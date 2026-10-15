"""The per-approval limit on findings holds when requests arrive at the same time.

Against a REAL (non-SAVEPOINT) engine with one fresh session per request: the shared
SAVEPOINT session in the other test files runs everything on one connection, so it
cannot make two requests overlap. Rows are committed for real and removed in the
test's own ``finally``.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, func, select

from central_governance_api.approvals.schemas import MAX_FINDINGS_PER_APPROVAL
from central_governance_api.auth.dependencies import get_oidc_resolver
from central_governance_api.auth.oidc import OIDCPrincipalResolver
from central_governance_api.db import (
    create_engine,
    create_session_factory,
    get_db_session,
)
from central_governance_api.main import create_app
from central_governance_api.models import (
    IdempotencyRecord,
    PendingApprovalRecord,
    ReconciliationFinding,
)

from .conftest import ISSUER
from .test_app_auth import _sign


@pytest.fixture
async def real_client(settings, public_jwks):
    engine = create_engine(settings)
    try:
        async with engine.connect():
            pass
    except Exception as exc:
        await engine.dispose()
        pytest.skip(f"no reachable test Postgres: {exc}")
    app = create_app(settings)
    resolver = OIDCPrincipalResolver(
        settings, preloaded_keys=public_jwks, never_refresh_keys=True
    )
    app.dependency_overrides[get_oidc_resolver] = lambda: resolver
    factory = create_session_factory(engine)

    async def _override():
        async with factory() as session:
            yield session

    app.dependency_overrides[get_db_session] = _override
    transport = ASGITransport(app=app)
    try:
        async with AsyncClient(transport=transport, base_url="http://test") as http:
            yield http, factory
    finally:
        await engine.dispose()


async def _failed_unknown_record_with_findings(factory, how_many: int) -> uuid.UUID:
    record_id = uuid.uuid4()
    async with factory() as session:
        session.add(
            PendingApprovalRecord(
                id=record_id,
                request_id=f"limit-race-{record_id}",
                requester_issuer=ISSUER,
                requester_sub="alice",
                origin_device_id="d",
                conversation_id="c",
                action_event_id="e",
                action_type="terminal_command",
                tool_name="bash",
                policy_revision="v1",
                action_summary="s",
                action_payload={},
                action_payload_digest="x",
                status="failed_unknown",
                expires_at=datetime.now(UTC) + timedelta(days=1),
            )
        )
        await session.flush()
        for n in range(how_many):
            session.add(
                ReconciliationFinding(
                    approval_request_id=record_id,
                    finding_type="requester_assertion",
                    note=f"n{n}",
                    verifier_issuer=ISSUER,
                    verifier_sub="alice",
                )
            )
        await session.commit()
    return record_id


async def _remove(factory, record_id: uuid.UUID) -> None:
    async with factory() as session:
        await session.execute(
            delete(ReconciliationFinding).where(
                ReconciliationFinding.approval_request_id == record_id
            )
        )
        await session.execute(
            delete(IdempotencyRecord).where(
                IdempotencyRecord.scope_resource_id == str(record_id)
            )
        )
        await session.execute(
            delete(PendingApprovalRecord).where(PendingApprovalRecord.id == record_id)
        )
        await session.commit()


async def test_simultaneous_findings_cannot_pass_the_limit(real_client, signing_key):
    """Five places left, twelve requests at once: exactly five are taken and the
    approval ends with exactly the limit (a count-then-insert without a lock lets
    them all through)."""
    http, factory = real_client
    record_id = await _failed_unknown_record_with_findings(
        factory, MAX_FINDINGS_PER_APPROVAL - 5
    )
    token = _sign(signing_key, sub="alice", roles=["agent.operator"])
    try:

        async def post(n: int):
            return await http.post(
                f"/api/v1/approvals/{record_id}/reconciliation-findings",
                json={"finding_type": "requester_assertion", "note": f"race {n}"},
                headers={
                    "Authorization": f"Bearer {token}",
                    "Idempotency-Key": f"race-{record_id}-{n}",
                },
            )

        responses = await asyncio.gather(*(post(n) for n in range(12)))
        statuses = sorted(r.status_code for r in responses)
        async with factory() as session:
            stored = await session.scalar(
                select(func.count(ReconciliationFinding.id)).where(
                    ReconciliationFinding.approval_request_id == record_id
                )
            )
        assert stored == MAX_FINDINGS_PER_APPROVAL
        assert statuses == [201] * 5 + [409] * 7, statuses
    finally:
        await _remove(factory, record_id)


async def test_a_finding_waits_for_whoever_holds_the_approvals_row(
    real_client, signing_key
):
    """What makes the limit exact is that counting happens under a lock on the
    approval's row. Hold that lock from another connection: the request must not
    finish until it is released (a request that counted without the lock would
    answer at once). The race test above only sometimes catches a missing lock;
    this one always does."""
    http, factory = real_client
    record_id = await _failed_unknown_record_with_findings(factory, 3)
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
                    f"/api/v1/approvals/{record_id}/reconciliation-findings",
                    json={"finding_type": "requester_assertion", "note": "waits"},
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Idempotency-Key": f"lock-{record_id}",
                    },
                )
            )
            done, _pending = await asyncio.wait({request}, timeout=1.5)
            assert not done, "the request finished while the row was locked"
            await holder.rollback()
        response = await asyncio.wait_for(request, timeout=10)
        assert response.status_code == 201, response.text
    finally:
        await _remove(factory, record_id)
