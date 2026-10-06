"""Execution-commitment binding (see ``approvals/digest.py``).

A device may register an opaque keyed hash of the action it will execute when
it creates the approval. It is covered by the create-time digest (so it is
fixed before the approver decides), must be presented again to claim, and is
compared with what the device attests at report-result.

Each test states the reason: this service cannot recompute the commitment, so
every guarantee below is "the value the device holds equals the value it
registered before the human decided", never "the commitment is true".

Real Postgres, like ``test_approvals_router.py`` (same fixtures).
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select

from central_governance_api.approvals.digest import (
    compute_display_digest,
    verify_display_digest,
)
from central_governance_api.auth.dependencies import get_oidc_resolver
from central_governance_api.auth.oidc import OIDCPrincipalResolver
from central_governance_api.db import create_engine, create_session_factory
from central_governance_api.main import create_app
from central_governance_api.models import (
    AdminAuditEvent,
    ApprovalDecision,
    IdempotencyRecord,
    PendingApprovalRecord,
)

from .test_app_auth import _sign
from .test_approvals_router import _auth, _create_body, client  # noqa: F401


COMMITMENT = "ab" * 32  # 64 lowercase hex characters
OTHER = "cd" * 32


def _body_with_commitment(commitment: str | None = COMMITMENT, **overrides: Any):
    body = _create_body(**overrides)
    if commitment is not None:
        body["execution_commitment"] = commitment
        body["action_payload_digest"] = compute_display_digest(
            action_type=body["action_type"],
            tool_name=body["tool_name"],
            policy_revision=body["policy_revision"],
            action_summary=body["action_summary"],
            action_payload=body["action_payload"],
            digest_salt=body["digest_salt"],
            execution_commitment=commitment,
        )
    return body


async def _create(client, signing_key, body) -> dict[str, Any]:  # noqa: F811
    token = _sign(signing_key, sub="alice", roles=["agent.operator"])
    resp = await client.post(
        "/api/v1/approvals",
        json=body,
        headers=_auth(token, f"create-{uuid.uuid4()}"),
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


async def _accept(client, signing_key, approval_id: str) -> None:  # noqa: F811
    approver = _sign(signing_key, sub="carol", roles=["agent.approver"])
    resp = await client.post(
        f"/api/v1/approvals/{approval_id}/decide",
        json={"decision": "accept"},
        headers=_auth(approver, f"decide-{uuid.uuid4()}"),
    )
    assert resp.status_code == 200, resp.text


async def _claim(client, signing_key, approval_id: str, json=None):  # noqa: F811
    token = _sign(signing_key, sub="alice", roles=["agent.operator"])
    return await client.post(
        f"/api/v1/approvals/{approval_id}/claim",
        json=json,
        headers=_auth(token, f"claim-{uuid.uuid4()}"),
    )


async def _report(client, signing_key, approval_id: str, **fields):  # noqa: F811
    token = _sign(signing_key, sub="alice", roles=["agent.operator"])
    return await client.post(
        f"/api/v1/approvals/{approval_id}/report-result",
        json=fields,
        headers=_auth(token, f"report-{uuid.uuid4()}"),
    )


# --- digest -----------------------------------------------------------------


def test_digest_without_a_commitment_is_unchanged():
    # Records created before this field existed, and devices that do not send
    # one, must keep hashing exactly as they did: the commitment key is added
    # to the canonical form only when present.
    args = dict(
        action_type="t",
        tool_name="n",
        policy_revision="v1",
        action_summary="s",
        action_payload={"a": 1},
        digest_salt=None,
    )
    assert compute_display_digest(**args) == compute_display_digest(
        **args, execution_commitment=None
    )
    assert compute_display_digest(**args) != compute_display_digest(
        **args, execution_commitment=COMMITMENT
    )


def test_digest_covers_the_commitment():
    args = dict(
        action_type="t",
        tool_name="n",
        policy_revision="v1",
        action_summary="s",
        action_payload={"a": 1},
        digest_salt=None,
    )
    digest = compute_display_digest(**args, execution_commitment=COMMITMENT)
    assert verify_display_digest(
        **args, execution_commitment=COMMITMENT, expected_digest=digest
    )
    assert not verify_display_digest(
        **args, execution_commitment=OTHER, expected_digest=digest
    )
    assert not verify_display_digest(**args, expected_digest=digest)


# --- create -----------------------------------------------------------------


async def test_create_stores_the_commitment(client, signing_key, db_session):  # noqa: F811
    created = await _create(client, signing_key, _body_with_commitment())

    row = await db_session.get(PendingApprovalRecord, uuid.UUID(created["id"]))
    assert row.execution_commitment == COMMITMENT
    assert row.executed_commitment is None
    assert row.commitment_verified is None


async def test_create_with_a_swapped_commitment_is_a_digest_mismatch(
    client,  # noqa: F811
    signing_key,
):
    # The device cannot register one commitment and sign the digest over
    # another: the digest covers it, and this service recomputes the digest.
    body = _body_with_commitment()
    body["execution_commitment"] = OTHER

    token = _sign(signing_key, sub="alice", roles=["agent.operator"])
    resp = await client.post(
        "/api/v1/approvals", json=body, headers=_auth(token, "swap-1")
    )

    assert resp.status_code == 400
    assert resp.json()["error_code"] == "digest_mismatch"


async def test_create_rejects_a_commitment_that_is_not_hex(client, signing_key):  # noqa: F811
    body = _body_with_commitment()
    body["execution_commitment"] = "not hex"

    token = _sign(signing_key, sub="alice", roles=["agent.operator"])
    resp = await client.post(
        "/api/v1/approvals", json=body, headers=_auth(token, "bad-format")
    )

    assert resp.status_code == 422


# --- claim ------------------------------------------------------------------


async def test_claim_with_the_registered_commitment_gets_a_lease(client, signing_key):  # noqa: F811
    created = await _create(client, signing_key, _body_with_commitment())
    await _accept(client, signing_key, created["id"])

    resp = await _claim(
        client, signing_key, created["id"], {"execution_commitment": COMMITMENT}
    )

    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "executing"


async def test_claim_with_a_different_commitment_is_refused_and_audited(
    client,  # noqa: F811
    signing_key,
    db_session,
):
    # The case this exists for: the device's stored approval record no longer
    # matches what was registered before the human decided. No lease is handed
    # out, the record stays claimable, and the refusal is evidence.
    created = await _create(client, signing_key, _body_with_commitment())
    await _accept(client, signing_key, created["id"])

    resp = await _claim(
        client, signing_key, created["id"], {"execution_commitment": OTHER}
    )

    assert resp.status_code == 409
    assert resp.json()["error_code"] == "execution_commitment_mismatch"
    assert COMMITMENT not in resp.text and OTHER not in resp.text
    row = await db_session.get(PendingApprovalRecord, uuid.UUID(created["id"]))
    await db_session.refresh(row)
    assert row.status == "accepted"
    assert row.execution_attempt_id is None
    events = (
        (
            await db_session.execute(
                select(AdminAuditEvent).where(
                    AdminAuditEvent.approval_request_id == row.id,
                    AdminAuditEvent.event_type == "approval_claim_commitment_mismatch",
                )
            )
        )
        .scalars()
        .all()
    )
    assert len(events) == 1
    assert events[0].payload == {"presented": True}


@pytest.mark.parametrize("body", [None, {}], ids=["no-body", "empty-body"])
async def test_claim_without_a_commitment_is_refused_when_one_was_registered(
    client,  # noqa: F811
    signing_key,
    body,
):
    # Fail closed: omitting the value must not be a way around the check.
    created = await _create(client, signing_key, _body_with_commitment())
    await _accept(client, signing_key, created["id"])

    resp = await _claim(client, signing_key, created["id"], body)

    assert resp.status_code == 409
    assert resp.json()["error_code"] == "execution_commitment_mismatch"


async def test_claim_of_a_legacy_record_still_works_without_a_body(client, signing_key):  # noqa: F811
    # A record created without a commitment (every device that predates it)
    # is claimed exactly as before: nothing to check.
    created = await _create(client, signing_key, _create_body())
    await _accept(client, signing_key, created["id"])

    resp = await _claim(client, signing_key, created["id"])

    assert resp.status_code == 200, resp.text


async def test_claim_of_a_legacy_record_ignores_a_presented_commitment(
    client,  # noqa: F811
    signing_key,
):
    created = await _create(client, signing_key, _create_body())
    await _accept(client, signing_key, created["id"])

    resp = await _claim(
        client, signing_key, created["id"], {"execution_commitment": OTHER}
    )

    assert resp.status_code == 200, resp.text


# --- report-result ----------------------------------------------------------


async def _claimed(client, signing_key, commitment=COMMITMENT):  # noqa: F811
    created = await _create(client, signing_key, _body_with_commitment(commitment))
    await _accept(client, signing_key, created["id"])
    body = {"execution_commitment": commitment} if commitment is not None else None
    claim = await _claim(client, signing_key, created["id"], body)
    assert claim.status_code == 200, claim.text
    return created["id"], claim.json()["execution_attempt_id"]


async def test_matching_attestation_is_recorded_as_verified(
    client,  # noqa: F811
    signing_key,
    db_session,
):
    approval_id, attempt = await _claimed(client, signing_key)

    resp = await _report(
        client,
        signing_key,
        approval_id,
        execution_attempt_id=attempt,
        outcome="success",
        executed_commitment=COMMITMENT,
    )

    assert resp.status_code == 200, resp.text
    row = await db_session.get(PendingApprovalRecord, uuid.UUID(approval_id))
    await db_session.refresh(row)
    assert row.executed_commitment == COMMITMENT
    assert row.commitment_verified is True


async def test_mismatching_attestation_is_recorded_not_rejected(
    client,  # noqa: F811
    signing_key,
    db_session,
):
    # The action already ran, so the outcome must still be accepted — a
    # refused report would erase the one record that execution happened. The
    # divergence is marked and audited instead.
    approval_id, attempt = await _claimed(client, signing_key)

    resp = await _report(
        client,
        signing_key,
        approval_id,
        execution_attempt_id=attempt,
        outcome="success",
        executed_commitment=OTHER,
    )

    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "applied"
    row = await db_session.get(PendingApprovalRecord, uuid.UUID(approval_id))
    await db_session.refresh(row)
    assert row.commitment_verified is False
    assert row.executed_commitment == OTHER
    events = (
        (
            await db_session.execute(
                select(AdminAuditEvent).where(
                    AdminAuditEvent.approval_request_id == row.id,
                    AdminAuditEvent.event_type
                    == "approval_executed_commitment_mismatch",
                )
            )
        )
        .scalars()
        .all()
    )
    assert len(events) == 1


async def test_report_without_an_attestation_leaves_verification_unknown(
    client,  # noqa: F811
    signing_key,
    db_session,
):
    # NULL means "not attested", which is not the same as "verified" or "did
    # not match": a crash can lose the device's marker, and that must stay
    # visible as unknown rather than being read as a pass.
    approval_id, attempt = await _claimed(client, signing_key)

    resp = await _report(
        client,
        signing_key,
        approval_id,
        execution_attempt_id=attempt,
        outcome="success",
    )

    assert resp.status_code == 200, resp.text
    row = await db_session.get(PendingApprovalRecord, uuid.UUID(approval_id))
    await db_session.refresh(row)
    assert row.executed_commitment is None
    assert row.commitment_verified is None


async def test_attestation_on_a_pre_claim_abort_is_rejected(client, signing_key):  # noqa: F811
    created = await _create(client, signing_key, _body_with_commitment())
    await _accept(client, signing_key, created["id"])

    resp = await _report(
        client, signing_key, created["id"], executed_commitment=COMMITMENT
    )

    assert resp.status_code == 422


async def test_attestation_for_a_legacy_record_is_stored_but_not_compared(
    client,  # noqa: F811
    signing_key,
    db_session,
):
    approval_id, attempt = await _claimed(client, signing_key, commitment=None)

    resp = await _report(
        client,
        signing_key,
        approval_id,
        execution_attempt_id=attempt,
        outcome="success",
        executed_commitment=COMMITMENT,
    )

    assert resp.status_code == 200, resp.text
    row = await db_session.get(PendingApprovalRecord, uuid.UUID(approval_id))
    await db_session.refresh(row)
    assert row.commitment_verified is None


async def test_refused_claim_audit_row_survives_the_error_path(
    settings, public_jwks, signing_key
):
    """The router raises right after writing the audit row, and a request that
    ends in an exception is rolled back when its session closes. So the row
    only exists if the router commits it first. The shared ``db_session`` the
    other tests use never rolls back on an exception, so it cannot show this:
    this test runs the app with its own sessions, as in production."""
    engine = create_engine(settings)
    factory = create_session_factory(engine)
    app = create_app(settings)
    app.state.db_session_factory = factory
    resolver = OIDCPrincipalResolver(
        settings, preloaded_keys=public_jwks, never_refresh_keys=True
    )
    app.dependency_overrides[get_oidc_resolver] = lambda: resolver
    approval_id = None
    body = _body_with_commitment()
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as real_client:
            created = await _create(real_client, signing_key, body)
            approval_id = uuid.UUID(created["id"])
            await _accept(real_client, signing_key, created["id"])

            resp = await _claim(
                real_client,
                signing_key,
                created["id"],
                {"execution_commitment": OTHER},
            )
            assert resp.status_code == 409

        async with factory() as fresh:
            events = (
                (
                    await fresh.execute(
                        select(AdminAuditEvent).where(
                            AdminAuditEvent.approval_request_id == approval_id,
                            AdminAuditEvent.event_type
                            == "approval_claim_commitment_mismatch",
                        )
                    )
                )
                .scalars()
                .all()
            )
            assert len(events) == 1
    finally:
        # These tests really commit, so remove what they wrote.
        if approval_id is not None:
            async with factory() as cleanup:
                await cleanup.execute(
                    delete(AdminAuditEvent).where(
                        AdminAuditEvent.approval_request_id == approval_id
                    )
                )
                await cleanup.execute(
                    delete(ApprovalDecision).where(
                        ApprovalDecision.approval_request_id == approval_id
                    )
                )
                await cleanup.execute(
                    delete(PendingApprovalRecord).where(
                        PendingApprovalRecord.id == approval_id
                    )
                )
                await cleanup.execute(
                    delete(IdempotencyRecord).where(
                        IdempotencyRecord.scope_resource_id.in_(
                            [str(approval_id), body["request_id"]]
                        )
                    )
                )
                await cleanup.commit()
        await engine.dispose()
