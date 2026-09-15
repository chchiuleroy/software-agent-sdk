"""Integration tests for the approval-workflow router — against a REAL
Postgres database, not a mock.

Why real, not mocked: the whole point of this pass (v11 §11 step 2,
"conditional-update 邏輯") is that the state transition, its side-effect
row, and its idempotency record land or fail together in one DB
transaction, and that a conditional ``UPDATE ... WHERE status =
<expected>`` is what actually catches a stale/concurrent status change —
a mocked ``AsyncSession`` can only prove "the router called
``session.execute()`` with some statement", never that the statement
means what this file's tests assume it means. See ``tests/conftest.py``'s
``db_session`` fixture for the SAVEPOINT-based isolation that lets every
test below call the router's own ``session.commit()`` for real while
still rolling back cleanly at teardown.

Requires ``CGA_DATABASE_URL`` to point at a live Postgres with this
service's schema already migrated (``alembic upgrade head``) — see the
project's own session notes for how a throwaway local instance was stood
up for this pass. Not wired into CI by this commit; that's a separate,
explicit decision for whoever sets up the "real" test database per
README's "部署前置條件" section.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from central_governance_api.approvals.digest import compute_display_digest
from central_governance_api.auth.dependencies import get_oidc_resolver
from central_governance_api.auth.oidc import OIDCPrincipalResolver
from central_governance_api.db import get_db_session
from central_governance_api.main import create_app
from central_governance_api.models import IdempotencyRecord, PendingApprovalRecord

from .conftest import ISSUER
from .test_app_auth import _sign


@pytest.fixture
async def client(settings, public_jwks, signing_key, db_session):
    app = create_app(settings)
    resolver = OIDCPrincipalResolver(
        settings, preloaded_keys=public_jwks, never_refresh_keys=True
    )
    app.dependency_overrides[get_oidc_resolver] = lambda: resolver

    async def _db_session_override():
        yield db_session

    app.dependency_overrides[get_db_session] = _db_session_override
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


def _auth(token: str, idempotency_key: str | None = None) -> dict[str, str]:
    headers = {"Authorization": f"Bearer {token}"}
    if idempotency_key is not None:
        headers["Idempotency-Key"] = idempotency_key
    return headers


def _create_body(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "request_id": str(uuid.uuid4()),
        "origin_device_id": "device-1",
        "conversation_id": "conv-1",
        "action_event_id": "event-1",
        "tool_call_id": None,
        "action_type": "terminal_command",
        "tool_name": "bash",
        "policy_revision": "v1",
        "action_summary": "echo hello",
        "action_payload": {"command": "echo hello"},
        "digest_salt": None,
    }
    base.update({k: v for k, v in overrides.items() if k != "action_payload_digest"})
    correct_digest = compute_display_digest(
        action_type=base["action_type"],
        tool_name=base["tool_name"],
        policy_revision=base["policy_revision"],
        action_summary=base["action_summary"],
        action_payload=base["action_payload"],
        digest_salt=base["digest_salt"],
    )
    base["action_payload_digest"] = overrides.get(
        "action_payload_digest", correct_digest
    )
    return base


async def _create_approval(
    client,
    signing_key,
    *,
    sub: str = "alice",
    idempotency_key: str | None = None,
    **body_overrides,
) -> dict[str, Any]:
    token = _sign(signing_key, sub=sub, roles=["agent.operator"])
    resp = await client.post(
        "/api/v1/approvals",
        json=_create_body(**body_overrides),
        headers=_auth(token, idempotency_key or f"create-{uuid.uuid4()}"),
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


# --- CREATE ------------------------------------------------------------


async def test_create_approval_persists_a_real_row(client, signing_key, db_session):
    """Proves the endpoint actually writes to Postgres (not just returns
    a plausible-looking response) and that server-generated defaults
    (created_at, id) come back populated — the specific SQLAlchemy async
    eager-defaults behavior a mock can't verify."""
    created = await _create_approval(client, signing_key, sub="alice")

    assert created["status"] == "pending"
    assert created["created_at"] is not None
    assert created["expires_at"] is not None

    row = await db_session.get(PendingApprovalRecord, uuid.UUID(created["id"]))
    assert row is not None
    assert row.requester_subject == f"{ISSUER}#alice"
    assert row.status == "pending"


async def test_create_approval_digest_mismatch_is_400(client, signing_key):
    token = _sign(signing_key, sub="alice", roles=["agent.operator"])
    body = _create_body(action_payload_digest="not-a-real-digest")
    resp = await client.post(
        "/api/v1/approvals",
        json=body,
        headers=_auth(token, "idem-1"),
    )
    assert resp.status_code == 400
    assert resp.json()["error_code"] == "digest_mismatch"


async def test_create_approval_requires_operator_or_admin_role(client, signing_key):
    token = _sign(signing_key, sub="alice", roles=["agent.approver"])
    resp = await client.post(
        "/api/v1/approvals",
        json=_create_body(),
        headers=_auth(token, "idem-1"),
    )
    assert resp.status_code == 403
    assert resp.json()["error_code"] == "authorization_denied"


async def test_create_approval_idempotent_retry_replays_same_response(
    client, signing_key, db_session
):
    token = _sign(signing_key, sub="alice", roles=["agent.operator"])
    body = _create_body()

    first = await client.post(
        "/api/v1/approvals", json=body, headers=_auth(token, "idem-retry")
    )
    second = await client.post(
        "/api/v1/approvals", json=body, headers=_auth(token, "idem-retry")
    )
    assert first.status_code == 201
    assert second.status_code == 201
    assert first.json() == second.json()

    # Exactly one row exists — the retry replayed, it did not insert twice.
    result = await db_session.execute(
        select(PendingApprovalRecord).where(
            PendingApprovalRecord.request_id == body["request_id"]
        )
    )
    assert len(result.scalars().all()) == 1


async def test_create_approval_idempotency_key_reused_with_different_body_is_422(
    client, signing_key
):
    """The collision has to be on the SAME resource_id (== request_id for
    CREATE — see idempotency.py's module docstring) with a different
    fingerprint; two different request_ids sharing an Idempotency-Key
    value are just two unrelated resources by this endpoint's own scoping
    rule, not a collision (an earlier version of this test asserted that
    wrongly — caught by actually running it against real Postgres)."""
    token = _sign(signing_key, sub="alice", roles=["agent.operator"])
    shared_request_id = str(uuid.uuid4())
    await client.post(
        "/api/v1/approvals",
        json=_create_body(request_id=shared_request_id, action_summary="echo one"),
        headers=_auth(token, "shared-key"),
    )
    resp = await client.post(
        "/api/v1/approvals",
        json=_create_body(request_id=shared_request_id, action_summary="echo two"),
        headers=_auth(token, "shared-key"),
    )
    assert resp.status_code == 422
    assert resp.json()["error_code"] == "idempotency_key_reused"


async def test_create_approval_missing_idempotency_key_is_422(client, signing_key):
    token = _sign(signing_key, sub="alice", roles=["agent.operator"])
    resp = await client.post(
        "/api/v1/approvals",
        json=_create_body(),
        headers={"Authorization": f"Bearer {token}"},
    )
    # FastAPI's own missing-required-header validation, not this
    # service's idempotency logic — still worth pinning down as 4xx.
    assert resp.status_code == 422


# --- Full lifecycle ----------------------------------------------------


async def test_full_lifecycle_accept_claim_report_success(client, signing_key):
    created = await _create_approval(client, signing_key, sub="alice")
    approval_id = created["id"]

    approver_token = _sign(signing_key, sub="carol", roles=["agent.approver"])
    decide = await client.post(
        f"/api/v1/approvals/{approval_id}/decide",
        json={"decision": "accept"},
        headers=_auth(approver_token, "decide-1"),
    )
    assert decide.status_code == 200, decide.text
    assert decide.json()["status"] == "accepted"

    requester_token = _sign(signing_key, sub="alice", roles=["agent.operator"])
    claim = await client.post(
        f"/api/v1/approvals/{approval_id}/claim",
        headers=_auth(requester_token, "claim-1"),
    )
    assert claim.status_code == 200, claim.text
    claim_body = claim.json()
    assert claim_body["status"] == "executing"
    assert claim_body["action_payload_digest"] == created["action_payload_digest"]
    attempt_id = claim_body["execution_attempt_id"]

    report = await client.post(
        f"/api/v1/approvals/{approval_id}/report-result",
        json={"execution_attempt_id": attempt_id, "outcome": "success"},
        headers=_auth(requester_token, "report-1"),
    )
    assert report.status_code == 200, report.text
    assert report.json()["status"] == "applied"


async def test_self_approval_denied(client, signing_key):
    created = await _create_approval(client, signing_key, sub="alice")
    approval_id = created["id"]

    self_token = _sign(signing_key, sub="alice", roles=["agent.approver"])
    resp = await client.post(
        f"/api/v1/approvals/{approval_id}/decide",
        json={"decision": "accept"},
        headers=_auth(self_token, "decide-self"),
    )
    assert resp.status_code == 403
    assert resp.json()["error_code"] == "authorization_denied"


async def test_decide_reject(client, signing_key):
    created = await _create_approval(client, signing_key, sub="alice")
    approver_token = _sign(signing_key, sub="carol", roles=["agent.approver"])
    resp = await client.post(
        f"/api/v1/approvals/{created['id']}/decide",
        json={"decision": "reject"},
        headers=_auth(approver_token, "decide-reject"),
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "rejected"


async def test_claim_before_decision_is_409(client, signing_key):
    created = await _create_approval(client, signing_key, sub="alice")
    requester_token = _sign(signing_key, sub="alice", roles=["agent.operator"])
    resp = await client.post(
        f"/api/v1/approvals/{created['id']}/claim",
        headers=_auth(requester_token, "claim-early"),
    )
    assert resp.status_code == 409
    assert resp.json()["error_code"] == "illegal_transition"


async def test_report_result_wrong_attempt_id_is_409(client, signing_key):
    created = await _create_approval(client, signing_key, sub="alice")
    approval_id = created["id"]
    approver_token = _sign(signing_key, sub="carol", roles=["agent.approver"])
    await client.post(
        f"/api/v1/approvals/{approval_id}/decide",
        json={"decision": "accept"},
        headers=_auth(approver_token, "decide-2"),
    )
    requester_token = _sign(signing_key, sub="alice", roles=["agent.operator"])
    await client.post(
        f"/api/v1/approvals/{approval_id}/claim",
        headers=_auth(requester_token, "claim-2"),
    )

    resp = await client.post(
        f"/api/v1/approvals/{approval_id}/report-result",
        json={"execution_attempt_id": str(uuid.uuid4()), "outcome": "success"},
        headers=_auth(requester_token, "report-wrong-attempt"),
    )
    assert resp.status_code == 409
    assert resp.json()["error_code"] == "execution_attempt_mismatch"


async def test_pre_claim_abort_lands_on_cancelled(client, signing_key):
    created = await _create_approval(client, signing_key, sub="alice")
    approval_id = created["id"]
    approver_token = _sign(signing_key, sub="carol", roles=["agent.approver"])
    await client.post(
        f"/api/v1/approvals/{approval_id}/decide",
        json={"decision": "accept"},
        headers=_auth(approver_token, "decide-3"),
    )
    requester_token = _sign(signing_key, sub="alice", roles=["agent.operator"])
    resp = await client.post(
        f"/api/v1/approvals/{approval_id}/report-result",
        json={},
        headers=_auth(requester_token, "abort-1"),
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "cancelled"


async def test_cancel_pending_then_second_cancel_is_409(client, signing_key):
    """The second call re-reads the record fresh (via `_load_record`) and
    sees the already-committed 'cancelled' status from the first call, so
    it's caught by the pure state-machine precheck
    (`IllegalTransitionError`) before any SQL runs — NOT by the
    conditional UPDATE's own WHERE-clause race guard
    (`ConcurrentModificationError`), because there is no staleness here:
    this test's two requests run sequentially on the same session, each
    doing its own fresh read. `ConcurrentModificationError` specifically
    requires the record to change *between* a request's own precheck read
    and its UPDATE — genuine cross-transaction concurrency, not
    reproducible against this file's SAVEPOINT-isolated single session
    (see module docstring). Confirmed by first getting this test's
    expectation wrong: it originally asserted 'concurrent_modification'
    here and failed against real Postgres, which is exactly the kind of
    mistake a mocked session would never have caught either."""
    created = await _create_approval(client, signing_key, sub="alice")
    requester_token = _sign(signing_key, sub="alice", roles=["agent.operator"])

    first = await client.post(
        f"/api/v1/approvals/{created['id']}/cancel",
        headers=_auth(requester_token, "cancel-1"),
    )
    assert first.status_code == 200
    assert first.json()["status"] == "cancelled"

    second = await client.post(
        f"/api/v1/approvals/{created['id']}/cancel",
        headers=_auth(requester_token, "cancel-2"),
    )
    assert second.status_code == 409
    assert second.json()["error_code"] == "illegal_transition"


async def test_reconciliation_finding_requires_terminal_status(client, signing_key):
    created = await _create_approval(client, signing_key, sub="alice")
    requester_token = _sign(signing_key, sub="alice", roles=["agent.operator"])
    resp = await client.post(
        f"/api/v1/approvals/{created['id']}/reconciliation-findings",
        json={"finding_type": "requester_assertion", "note": "still pending"},
        headers=_auth(requester_token, "finding-1"),
    )
    assert resp.status_code == 409
    assert resp.json()["error_code"] == "record_not_terminal"


async def test_reconciliation_finding_after_rejection(client, signing_key, db_session):
    created = await _create_approval(client, signing_key, sub="alice")
    approval_id = created["id"]
    approver_token = _sign(signing_key, sub="carol", roles=["agent.approver"])
    await client.post(
        f"/api/v1/approvals/{approval_id}/decide",
        json={"decision": "reject"},
        headers=_auth(approver_token, "decide-4"),
    )

    admin_token = _sign(signing_key, sub="dave", roles=["governance.admin"])
    resp = await client.post(
        f"/api/v1/approvals/{approval_id}/reconciliation-findings",
        json={
            "finding_type": "admin_verified",
            "conclusion": "confirmed_not_executed",
            "note": "confirmed via audit log",
        },
        headers=_auth(admin_token, "finding-admin-1"),
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["finding_type"] == "admin_verified"


async def test_reconciliation_late_report_denied_for_admin(client, signing_key):
    created = await _create_approval(client, signing_key, sub="alice")
    approval_id = created["id"]
    approver_token = _sign(signing_key, sub="carol", roles=["agent.approver"])
    await client.post(
        f"/api/v1/approvals/{approval_id}/decide",
        json={"decision": "reject"},
        headers=_auth(approver_token, "decide-5"),
    )

    admin_token = _sign(signing_key, sub="dave", roles=["governance.admin"])
    resp = await client.post(
        f"/api/v1/approvals/{approval_id}/reconciliation-findings",
        json={"finding_type": "late_report", "note": "admin trying to file one"},
        headers=_auth(admin_token, "finding-late-1"),
    )
    assert resp.status_code == 403
    assert resp.json()["error_code"] == "authorization_denied"


async def test_idempotency_record_written_in_same_transaction_as_mutation(
    client, signing_key, db_session
):
    """A weaker but still meaningful proxy for "same transaction": after
    a successful decide, both the status change AND its IdempotencyRecord
    must be visible together within this test's own session — if the
    router's commit had somehow only applied one of the two, this would
    catch that."""
    created = await _create_approval(client, signing_key, sub="alice")
    approval_id = created["id"]
    approver_token = _sign(signing_key, sub="carol", roles=["agent.approver"])
    await client.post(
        f"/api/v1/approvals/{approval_id}/decide",
        json={"decision": "accept"},
        headers=_auth(approver_token, "decide-idem-check"),
    )

    row = await db_session.get(PendingApprovalRecord, uuid.UUID(approval_id))
    assert row.status == "accepted"

    idem_row = await db_session.scalar(
        select(IdempotencyRecord).where(
            IdempotencyRecord.scope_resource_id == approval_id,
            IdempotencyRecord.idempotency_key == "decide-idem-check",
        )
    )
    assert idem_row is not None
    assert idem_row.response_snapshot["status"] == "accepted"
