"""POST /api/v1/approvals/{id}/attention-resolutions: the audit-only record of what an
operator did with a record that needed attention (item 1.11, option B).

What matters: only the owner's operator may write it, it records exactly what was
sent plus the fact that the name is self-declared, it changes nothing about the
approval, a retry of the same call writes once, and it shows up in the audit trail.
"""

from __future__ import annotations

import asyncio
import uuid

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, func, select

from central_governance_api.auth.dependencies import get_oidc_resolver
from central_governance_api.auth.oidc import OIDCPrincipalResolver
from central_governance_api.db import get_db_session
from central_governance_api.main import create_app
from central_governance_api.models import AdminAuditEvent, PendingApprovalRecord

from .conftest import ISSUER
from .test_app_auth import _sign
from .test_approvals_router import _auth, _create_approval
from .test_finding_limit_concurrency import (
    _failed_unknown_record_with_findings,
    _remove,
)
from .test_finding_limit_concurrency import real_client as _real_client_fixture


real_client = _real_client_fixture  # the same fixture, under its own name here


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


def _url(approval_id: str) -> str:
    return f"/api/v1/approvals/{approval_id}/attention-resolutions"


BODY = {"action": "retry", "reason": "report_failed", "operator": "alice-ops"}


async def _events(db_session, approval_id: str) -> list[AdminAuditEvent]:
    result = await db_session.execute(
        select(AdminAuditEvent).where(
            AdminAuditEvent.approval_request_id == uuid.UUID(approval_id),
            AdminAuditEvent.event_type == "attention_resolved",
        )
    )
    return list(result.scalars())


async def _post(client, signing_key, approval_id, body, key, sub="alice", roles=None):
    token = _sign(signing_key, sub=sub, roles=roles or ["agent.operator"])
    return await client.post(_url(approval_id), json=body, headers=_auth(token, key))


async def test_the_owners_operator_writes_one_audit_event_with_what_was_sent(
    client, signing_key, db_session
):
    created = await _create_approval(client, signing_key, sub="alice")
    resp = await _post(client, signing_key, created["id"], BODY, "att-1")
    assert resp.status_code == 201, resp.text
    assert resp.json()["event_type"] == "attention_resolved"
    assert resp.json()["approval_request_id"] == created["id"]

    (event,) = await _events(db_session, created["id"])
    assert event.actor_sub == "alice"
    assert event.origin_device_id == "device-1"
    assert event.payload == {
        "action": "retry",
        "reason": "report_failed",
        "operator": "alice-ops",
        "operator_self_declared": True,
    }


@pytest.mark.parametrize("action", ["retry", "dismiss", "abandon"])
async def test_each_action_is_recorded_under_its_own_name(
    client, signing_key, db_session, action
):
    created = await _create_approval(client, signing_key, sub="alice")
    resp = await _post(
        client, signing_key, created["id"], {**BODY, "action": action}, f"att-{action}"
    )
    assert resp.status_code == 201, resp.text
    (event,) = await _events(db_session, created["id"])
    assert event.payload["action"] == action


async def test_a_dismiss_may_carry_the_outcome_and_nothing_else_may(
    client, signing_key, db_session
):
    created = await _create_approval(client, signing_key, sub="alice")
    ok = await _post(
        client,
        signing_key,
        created["id"],
        {**BODY, "action": "dismiss", "outcome": "confirmed_not_executed"},
        "att-outcome",
    )
    assert ok.status_code == 201, ok.text
    (event,) = await _events(db_session, created["id"])
    assert event.payload["outcome"] == "confirmed_not_executed"
    for action in ("retry", "abandon"):
        bad = await _post(
            client,
            signing_key,
            created["id"],
            {**BODY, "action": action, "outcome": "inconclusive"},
            f"att-bad-{action}",
        )
        assert bad.status_code == 422, (action, bad.text)


async def test_it_changes_nothing_about_the_approval(client, signing_key, db_session):
    created = await _create_approval(client, signing_key, sub="alice")
    before = await db_session.get(PendingApprovalRecord, uuid.UUID(created["id"]))
    status_before = before.status
    await _post(client, signing_key, created["id"], BODY, "att-nochange")
    await db_session.refresh(before)
    assert before.status == status_before == "pending"


@pytest.mark.parametrize(
    "sub, roles",
    [
        ("mallory", ["agent.operator"]),  # another operator
        ("alice", ["agent.approver"]),  # the owner, without the operator role
        ("root", ["governance.admin"]),  # an admin cannot speak for the device
        ("alice", ["governance.admin"]),
        ("root", ["governance.superadmin"]),
        ("nobody", []),
    ],
)
async def test_only_the_owners_operator_may_write_it(
    client, signing_key, db_session, sub, roles
):
    created = await _create_approval(client, signing_key, sub="alice")
    resp = await _post(
        client,
        signing_key,
        created["id"],
        BODY,
        f"att-deny-{sub}",
        sub=sub,
        roles=roles,
    )
    assert resp.status_code == 403, (sub, roles, resp.text)
    assert await _events(db_session, created["id"]) == []


async def test_an_unknown_approval_is_404(client, signing_key):
    resp = await _post(client, signing_key, str(uuid.uuid4()), BODY, "att-404")
    assert resp.status_code == 404
    assert resp.json()["error_code"] == "record_not_found"


async def test_the_same_call_twice_writes_once_and_answers_the_same(
    client, signing_key, db_session
):
    created = await _create_approval(client, signing_key, sub="alice")
    first = await _post(client, signing_key, created["id"], BODY, "att-replay")
    second = await _post(client, signing_key, created["id"], BODY, "att-replay")
    assert first.status_code == second.status_code == 201
    assert first.json() == second.json()
    assert len(await _events(db_session, created["id"])) == 1


async def test_a_different_body_under_the_same_key_is_refused(
    client, signing_key, db_session
):
    created = await _create_approval(client, signing_key, sub="alice")
    await _post(client, signing_key, created["id"], BODY, "att-reuse")
    other = await _post(
        client, signing_key, created["id"], {**BODY, "action": "abandon"}, "att-reuse"
    )
    assert other.status_code == 422
    assert other.json()["error_code"] == "idempotency_key_reused"
    assert len(await _events(db_session, created["id"])) == 1


async def test_a_second_resolution_with_a_new_key_is_a_second_event(
    client, signing_key, db_session
):
    """Retry then dismiss are two things that happened: both are kept."""
    created = await _create_approval(client, signing_key, sub="alice")
    await _post(client, signing_key, created["id"], BODY, "att-seq-1")
    await _post(
        client, signing_key, created["id"], {**BODY, "action": "dismiss"}, "att-seq-2"
    )
    actions = sorted(
        e.payload["action"] for e in await _events(db_session, created["id"])
    )
    assert actions == ["dismiss", "retry"]


@pytest.mark.parametrize(
    "patch",
    [
        {"action": "approve"},
        {"action": ""},
        {"reason": ""},
        {"reason": "has space"},
        {"reason": "x" * 65},
        {"operator": ""},
        {"operator": " padded "},
        {"operator": "tab\there"},
        {"operator": "x" * 65},
        {"operator": "new\nline"},
        {"outcome": "executed"},
        {"resolution_note": "must not be sent"},
        {"operator_self_declared": False},
    ],
)
async def test_a_malformed_body_is_422_and_stores_nothing(
    client, signing_key, db_session, patch
):
    created = await _create_approval(client, signing_key, sub="alice")
    resp = await _post(
        client,
        signing_key,
        created["id"],
        {**BODY, **patch},
        f"att-bad-{abs(hash(str(patch)))}",
    )
    assert resp.status_code == 422, (patch, resp.text)
    assert await _events(db_session, created["id"]) == []


async def test_the_server_decides_the_self_declared_flag_not_the_caller(
    client, signing_key, db_session
):
    created = await _create_approval(client, signing_key, sub="alice")
    forged = await _post(
        client,
        signing_key,
        created["id"],
        {**BODY, "operator_self_declared": False},
        "att-forge",
    )
    assert forged.status_code == 422  # unknown field refused, so it cannot be set
    ok = await _post(client, signing_key, created["id"], BODY, "att-flag")
    assert ok.status_code == 201
    (event,) = await _events(db_session, created["id"])
    assert event.payload["operator_self_declared"] is True


async def test_the_event_is_listed_by_the_audit_trail(client, signing_key, db_session):
    created = await _create_approval(client, signing_key, sub="alice")
    await _post(client, signing_key, created["id"], BODY, "att-listed")
    admin = _sign(signing_key, sub="dave", roles=["governance.admin"])
    resp = await client.get(
        "/api/v1/audit-events",
        params={
            "event_type": "attention_resolved",
            "approval_request_id": created["id"],
        },
        headers=_auth(admin),
    )
    assert resp.status_code == 200, resp.text
    (item,) = resp.json()["items"]
    assert item["payload"]["operator"] == "alice-ops"
    assert item["payload"]["operator_self_declared"] is True
    assert item["actor_subject"].endswith("#alice")


async def test_one_audit_row_per_call_even_across_many_calls(
    client, signing_key, db_session
):
    created = await _create_approval(client, signing_key, sub="alice")
    for n in range(3):
        await _post(client, signing_key, created["id"], BODY, f"att-many-{n}")
    count = await db_session.scalar(
        select(func.count(AdminAuditEvent.id)).where(
            AdminAuditEvent.event_type == "attention_resolved",
            AdminAuditEvent.approval_request_id == uuid.UUID(created["id"]),
        )
    )
    assert count == 3


# --- an approval holds at most this many attention events -------------------


async def _add_events(db_session, approval_id: str, n: int) -> None:
    for i in range(n):
        db_session.add(
            AdminAuditEvent(
                event_type="attention_resolved",
                actor_issuer=ISSUER,
                actor_sub="alice",
                approval_request_id=uuid.UUID(approval_id),
                payload={"action": "retry", "operator": f"o{i}"},
            )
        )
    await db_session.flush()


async def test_an_approval_holds_at_most_100_attention_events(
    client, signing_key, db_session
):
    created = await _create_approval(client, signing_key, sub="alice")
    await _add_events(db_session, created["id"], 99)

    last = await _post(client, signing_key, created["id"], BODY, "cap-last")
    assert last.status_code == 201, last.text
    over = await _post(client, signing_key, created["id"], BODY, "cap-over")
    assert over.status_code == 409
    assert over.json()["error_code"] == "too_many_attention_events"
    assert len(await _events(db_session, created["id"])) == 100


async def test_the_limit_is_per_approval_and_counts_only_attention_events(
    client, signing_key, db_session
):
    full = await _create_approval(client, signing_key, sub="alice")
    other = await _create_approval(client, signing_key, sub="alice")
    await _add_events(db_session, full["id"], 100)
    # other kinds of audit events on the same approval do not use up the places
    for _ in range(100):
        db_session.add(
            AdminAuditEvent(
                event_type="approval_cancelled",
                actor_issuer=ISSUER,
                actor_sub="alice",
                approval_request_id=uuid.UUID(other["id"]),
            )
        )
    await db_session.flush()

    ok = await _post(client, signing_key, other["id"], BODY, "cap-other")
    refused = await _post(client, signing_key, full["id"], BODY, "cap-full")
    assert ok.status_code == 201, ok.text
    assert refused.status_code == 409


async def test_a_refused_call_for_the_limit_is_not_remembered_as_an_answer(
    client, signing_key, db_session
):
    created = await _create_approval(client, signing_key, sub="alice")
    await _add_events(db_session, created["id"], 100)
    for _ in range(2):
        resp = await _post(client, signing_key, created["id"], BODY, "cap-same-key")
        assert resp.status_code == 409
    assert len(await _events(db_session, created["id"])) == 100


async def test_a_success_replays_after_the_approval_is_full(
    client, signing_key, db_session
):
    created = await _create_approval(client, signing_key, sub="alice")
    first = await _post(client, signing_key, created["id"], BODY, "cap-replay")
    await _add_events(db_session, created["id"], 100)
    again = await _post(client, signing_key, created["id"], BODY, "cap-replay")
    assert first.status_code == again.status_code == 201
    assert first.json() == again.json()


async def test_an_attention_event_waits_for_whoever_holds_the_approvals_row(
    real_client, signing_key
):
    """Counting happens under a lock on the approval's row; the foreign-key insert of
    an audit event takes a weaker lock itself, so the holder uses FOR NO KEY UPDATE,
    which only the explicit lock conflicts with."""
    http, factory = real_client
    record_id = await _failed_unknown_record_with_findings(factory, 0)
    token = _sign(signing_key, sub="alice", roles=["agent.operator"])
    try:
        async with factory() as holder:
            await holder.execute(
                select(PendingApprovalRecord.id)
                .where(PendingApprovalRecord.id == record_id)
                .with_for_update(key_share=True)
            )
            request = asyncio.ensure_future(
                http.post(
                    f"/api/v1/approvals/{record_id}/attention-resolutions",
                    json=BODY,
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Idempotency-Key": f"attn-lock-{record_id}",
                    },
                )
            )
            done, _pending = await asyncio.wait({request}, timeout=1.5)
            assert not done, "the request finished while the row was locked"
            await holder.rollback()
        response = await asyncio.wait_for(request, timeout=10)
        assert response.status_code == 201, response.text
    finally:
        async with factory() as session:
            await session.execute(
                delete(AdminAuditEvent).where(
                    AdminAuditEvent.approval_request_id == record_id
                )
            )
            await session.commit()
        await _remove(factory, record_id)


async def test_simultaneous_attention_events_cannot_pass_the_limit(
    real_client, signing_key
):
    http, factory = real_client
    record_id = await _failed_unknown_record_with_findings(factory, 0)
    async with factory() as session:
        for i in range(96):
            session.add(
                AdminAuditEvent(
                    event_type="attention_resolved",
                    actor_issuer=ISSUER,
                    actor_sub="alice",
                    approval_request_id=record_id,
                    payload={"action": "retry", "operator": f"o{i}"},
                )
            )
        await session.commit()
    token = _sign(signing_key, sub="alice", roles=["agent.operator"])
    try:

        async def post(n: int):
            return await http.post(
                f"/api/v1/approvals/{record_id}/attention-resolutions",
                json=BODY,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Idempotency-Key": f"attn-race-{record_id}-{n}",
                },
            )

        statuses = sorted(
            r.status_code for r in await asyncio.gather(*(post(n) for n in range(10)))
        )
        async with factory() as session:
            stored = await session.scalar(
                select(func.count(AdminAuditEvent.id)).where(
                    AdminAuditEvent.approval_request_id == record_id
                )
            )
        assert stored == 100
        assert statuses == [201] * 4 + [409] * 6, statuses
    finally:
        async with factory() as session:
            await session.execute(
                delete(AdminAuditEvent).where(
                    AdminAuditEvent.approval_request_id == record_id
                )
            )
            await session.commit()
        await _remove(factory, record_id)
