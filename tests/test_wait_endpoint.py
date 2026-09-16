"""Tests for ``GET /api/v1/approvals/{id}/wait`` (v11 §11 step 3) — real
Postgres, same rationale as every other integration test file in this
project.

Most of these use the shared SAVEPOINT-isolated ``db_session`` fixture
(same ``client`` fixture as ``test_approvals_router.py``), which is enough
to prove the fast paths that never actually need to LISTEN for anything:
"already differs from known_status" and "already terminal" both return
without touching ``approvals/notify.py``'s wait loop at all, and the
"nothing changes before the timeout" path only needs a real (but short)
wall-clock wait against a real Postgres connection — it never needs a
second connection's commit to be visible.

The one thing that structurally needs a second, genuinely independent
connection is proving the actual point of this endpoint: that a decision
made by a completely separate request wakes a blocked ``/wait`` call via
NOTIFY well before its timeout, rather than only ever timing out. The
shared SAVEPOINT-isolated session can't produce that (see
``tests/conftest.py``'s ``db_session`` fixture docstring, and
``test_devices_router.py``'s ``test_register_quota_race_is_prevented_by_advisory_lock``
for the established precedent this file's one such test follows): a
SAVEPOINT release is never a real Postgres COMMIT, and Postgres only ever
delivers a queued NOTIFY at a real COMMIT.
"""

from __future__ import annotations

import asyncio
import uuid
from unittest import mock

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession

from central_governance_api.auth.dependencies import get_oidc_resolver
from central_governance_api.auth.oidc import OIDCPrincipalResolver
from central_governance_api.db import (
    create_engine,
    create_session_factory,
    get_db_session,
)
from central_governance_api.main import create_app
from central_governance_api.models import (
    ApprovalDecision,
    IdempotencyRecord,
    PendingApprovalRecord,
)

from .conftest import _TEST_DATABASE_URL
from .test_app_auth import _sign
from .test_approvals_router import _auth, _create_approval


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


@pytest.fixture
async def real_client(settings, public_jwks):
    """A client backed by a REAL (non-SAVEPOINT) engine, one fresh session
    per request — needed by any test whose code path calls
    ``session.commit()`` more than once. Only ``/wait``'s actual-wait
    branch does that (``wait_for_status_change``'s ``_refresh_and_release``
    helper commits after every read specifically so it doesn't hold a
    pooled connection for the whole wait — see ``approvals/notify.py``'s
    code-review High fix); every write endpoint elsewhere in this service
    still commits exactly once per request.

    The shared SAVEPOINT-isolated ``client``/``db_session`` fixture can't
    support a second commit within one test: releasing a SAVEPOINT and
    then having the ORM open a new one later in the same test raises
    ``sqlalchemy.exc.MissingGreenlet`` — a limitation of that fixture's
    isolation strategy (discovered writing this file), not a bug in the
    endpoint, which this fixture's own passing tests prove works
    correctly against a real engine. Mirrors
    ``test_devices_router.py``'s
    ``test_register_quota_race_is_prevented_by_advisory_lock`` for the
    "own real engine, skip gracefully if unreachable" pattern.

    Yields ``(http_client, engine)`` — tests that commit real rows need
    the ``engine`` back to clean them up in their own ``finally`` block
    before this fixture disposes it.
    """
    engine = create_engine(settings)
    try:
        async with engine.connect():
            pass
    except Exception as exc:
        await engine.dispose()
        pytest.skip(f"no reachable test Postgres at {_TEST_DATABASE_URL!r}: {exc}")

    app = create_app(settings)
    resolver = OIDCPrincipalResolver(
        settings, preloaded_keys=public_jwks, never_refresh_keys=True
    )
    app.dependency_overrides[get_oidc_resolver] = lambda: resolver

    session_factory = create_session_factory(engine)

    async def _real_db_session_override():
        # A fresh, genuinely independent session/connection per request —
        # what makes a write here a real COMMIT (and therefore a real
        # NOTIFY), not a SAVEPOINT release.
        async with session_factory() as session:
            yield session

    app.dependency_overrides[get_db_session] = _real_db_session_override

    transport = ASGITransport(app=app)
    try:
        async with AsyncClient(transport=transport, base_url="http://test") as http:
            yield http, engine
    finally:
        await engine.dispose()


# --- fast paths (shared SAVEPOINT-isolated session; see module docstring) ---


async def test_wait_returns_immediately_when_status_already_changed(
    client, signing_key, db_session
):
    created = await _create_approval(client, signing_key, sub="alice")
    approval_id = created["id"]
    approver_token = _sign(signing_key, sub="carol", roles=["agent.approver"])
    await client.post(
        f"/api/v1/approvals/{approval_id}/decide",
        json={"decision": "accept"},
        headers=_auth(approver_token, "decide-for-wait-test"),
    )

    owner_token = _sign(signing_key, sub="alice", roles=["agent.operator"])
    started = asyncio.get_running_loop().time()
    resp = await client.get(
        f"/api/v1/approvals/{approval_id}/wait",
        params={"known_status": "pending", "timeout_seconds": 25},
        headers=_auth(owner_token),
    )
    elapsed = asyncio.get_running_loop().time() - started

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "accepted"
    assert body["changed"] is True
    # No LISTEN/NOTIFY loop was needed for this answer at all — must not
    # have blocked anywhere near the 25s timeout budget.
    assert elapsed < 5


async def test_wait_returns_immediately_for_already_terminal_known_status(
    client, signing_key
):
    created = await _create_approval(client, signing_key, sub="alice")
    approval_id = created["id"]
    approver_token = _sign(signing_key, sub="carol", roles=["agent.approver"])
    await client.post(
        f"/api/v1/approvals/{approval_id}/decide",
        json={"decision": "reject"},
        headers=_auth(approver_token, "reject-for-wait-test"),
    )

    owner_token = _sign(signing_key, sub="alice", roles=["agent.operator"])
    started = asyncio.get_running_loop().time()
    resp = await client.get(
        f"/api/v1/approvals/{approval_id}/wait",
        params={"known_status": "rejected", "timeout_seconds": 25},
        headers=_auth(owner_token),
    )
    elapsed = asyncio.get_running_loop().time() - started

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "rejected"
    assert body["changed"] is False
    # `rejected` is terminal — must short-circuit rather than wait out the
    # full timeout for a status that can never change again.
    assert elapsed < 5


async def test_wait_times_out_when_nothing_changes(real_client, signing_key):
    """Needs ``real_client`` (real engine), not the shared SAVEPOINT
    session: this is the one fast-path test that actually reaches
    ``wait_for_status_change``'s timeout branch, which now commits TWICE
    (initial refresh, then the code-review-Medium final refresh before
    giving up) — see ``real_client``'s own docstring for why a second
    commit needs a real engine."""
    client, engine = real_client
    sub = f"wait-timeout-{uuid.uuid4()}"
    created = await _create_approval(client, signing_key, sub=sub)
    approval_id = created["id"]

    try:
        owner_token = _sign(signing_key, sub=sub, roles=["agent.operator"])
        started = asyncio.get_running_loop().time()
        resp = await client.get(
            f"/api/v1/approvals/{approval_id}/wait",
            params={"known_status": "pending", "timeout_seconds": 1},
            headers=_auth(owner_token),
        )
        elapsed = asyncio.get_running_loop().time() - started

        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["status"] == "pending"
        assert body["changed"] is False
        assert elapsed >= 1
    finally:
        async with engine.begin() as conn:
            await conn.execute(
                delete(PendingApprovalRecord).where(
                    PendingApprovalRecord.id == uuid.UUID(approval_id)
                )
            )
            await conn.execute(
                delete(IdempotencyRecord).where(
                    IdempotencyRecord.scope_principal_sub == sub
                )
            )


async def test_wait_requires_authorization(client, signing_key):
    created = await _create_approval(client, signing_key, sub="alice")
    approval_id = created["id"]

    stranger_token = _sign(signing_key, sub="mallory", roles=["agent.operator"])
    resp = await client.get(
        f"/api/v1/approvals/{approval_id}/wait",
        params={"known_status": "pending"},
        headers=_auth(stranger_token),
    )
    assert resp.status_code == 403
    assert resp.json()["error_code"] == "authorization_denied"


async def test_wait_allows_any_approver_not_just_the_owner(real_client, signing_key):
    """Design decision (approvals/authorize.py, WAIT branch): any
    agent.approver may wait on any record, not just its owner — an
    approver checking whether someone else already decided it is exactly
    as legitimate a caller as the requester itself.

    Needs ``real_client``, same reason as ``test_wait_times_out_when_nothing_changes``:
    this also runs the timeout branch (two commits)."""
    client, engine = real_client
    sub = f"wait-approver-{uuid.uuid4()}"
    created = await _create_approval(client, signing_key, sub=sub)
    approval_id = created["id"]

    try:
        approver_token = _sign(signing_key, sub="carol", roles=["agent.approver"])
        resp = await client.get(
            f"/api/v1/approvals/{approval_id}/wait",
            params={"known_status": "pending", "timeout_seconds": 1},
            headers=_auth(approver_token),
        )
        assert resp.status_code == 200, resp.text
        assert resp.json()["changed"] is False
    finally:
        async with engine.begin() as conn:
            await conn.execute(
                delete(PendingApprovalRecord).where(
                    PendingApprovalRecord.id == uuid.UUID(approval_id)
                )
            )
            await conn.execute(
                delete(IdempotencyRecord).where(
                    IdempotencyRecord.scope_principal_sub == sub
                )
            )


async def test_wait_404_for_unknown_id(client, signing_key):
    token = _sign(signing_key, sub="alice", roles=["agent.operator"])
    resp = await client.get(
        f"/api/v1/approvals/{uuid.uuid4()}/wait",
        params={"known_status": "pending"},
        headers=_auth(token),
    )
    assert resp.status_code == 404


async def test_wait_rejects_unknown_status_value(client, signing_key):
    created = await _create_approval(client, signing_key, sub="alice")
    token = _sign(signing_key, sub="alice", roles=["agent.operator"])
    resp = await client.get(
        f"/api/v1/approvals/{created['id']}/wait",
        params={"known_status": "not_a_real_status"},
        headers=_auth(token),
    )
    assert resp.status_code == 422


# --- the one genuinely cross-connection test -----------------------------


async def test_wait_wakes_immediately_when_another_connection_decides(
    real_client, signing_key
):
    """The actual point of this endpoint: a decision committed by a
    completely separate request/connection must wake a blocked ``/wait``
    call promptly via NOTIFY, not leave it to time out. Needs
    ``real_client`` (real engine, one session per request) rather than the
    shared SAVEPOINT-isolated ``db_session`` fixture, same rationale as
    ``test_devices_router.py``'s
    ``test_register_quota_race_is_prevented_by_advisory_lock``: a
    SAVEPOINT release is never a real Postgres COMMIT, and Postgres only
    ever delivers a queued NOTIFY at a real COMMIT.

    Code-review Medium: an earlier version of this test only slept 0.5s
    before calling ``decide``, hoping that was long enough for the
    ``/wait`` call to finish registering its LISTEN and confirm the
    status was still unchanged. That's true in practice but not
    guaranteed by the test itself — on a slow enough run, ``decide``
    could complete before that point, in which case ``wait_for_status_change``'s
    own initial post-LISTEN read would already see ``accepted`` and return
    immediately WITHOUT ever reaching the ``asyncio.wait_for(woken.get())``
    loop this test exists to prove. The test would still pass, but for the
    wrong reason — proving only "a cross-connection change is eventually
    observed", not "NOTIFY actually woke a blocked waiter". Fixed the same
    way ``test_register_quota_race_same_idempotency_key_replays_not_429``
    fixed the analogous problem for the advisory-lock test: monkeypatch a
    real call boundary (here, ``AsyncSession.refresh`` — the one call
    ``wait_for_status_change`` makes right before either returning
    immediately or entering the blocking loop, and the only place in this
    whole request that calls it at all; ``decide`` never does) so
    ``decide`` provably waits until the waiter has passed that point
    before running at all.
    """
    http, engine = real_client
    principal_sub = f"wait-wake-{uuid.uuid4()}"
    approval_id: str | None = None
    try:
        requester_token = _sign(
            signing_key, sub=principal_sub, roles=["agent.operator"]
        )
        approver_token = _sign(
            signing_key, sub="wait-wake-approver", roles=["agent.approver"]
        )
        created = await _create_approval(http, signing_key, sub=principal_sub)
        approval_id = created["id"]

        listener_ready = asyncio.Event()
        original_refresh = AsyncSession.refresh

        async def _refresh_and_signal(self, *args, **kwargs):
            result = await original_refresh(self, *args, **kwargs)
            listener_ready.set()
            return result

        async def _wait() -> tuple[int, dict]:
            with mock.patch.object(AsyncSession, "refresh", _refresh_and_signal):
                resp = await http.get(
                    f"/api/v1/approvals/{approval_id}/wait",
                    params={"known_status": "pending", "timeout_seconds": 20},
                    headers=_auth(requester_token),
                )
            return resp.status_code, resp.json()

        async def _decide_once_waiter_is_listening() -> None:
            await asyncio.wait_for(listener_ready.wait(), timeout=10)
            resp = await http.post(
                f"/api/v1/approvals/{approval_id}/decide",
                json={"decision": "accept"},
                headers=_auth(approver_token, "decide-during-wait"),
            )
            assert resp.status_code == 200, resp.text

        started = asyncio.get_running_loop().time()
        (wait_status, wait_body), _ = await asyncio.gather(
            _wait(), _decide_once_waiter_is_listening()
        )
        elapsed = asyncio.get_running_loop().time() - started

        assert wait_status == 200, wait_body
        assert wait_body["changed"] is True
        assert wait_body["status"] == "accepted"
        # `decide` provably could not even start until the waiter had
        # already passed its own pre-loop refresh (listener_ready), so
        # this elapsed time is specifically "how long the NOTIFY-driven
        # wake took", not "how long until some race happened to resolve
        # in our favor" — generous bound to absorb CI/local scheduling
        # jitter without the test becoming flaky, still nowhere near the
        # 20s timeout.
        assert elapsed < 10, (
            f"wait took {elapsed:.2f}s — looks like it fell through to "
            "the timeout instead of waking on NOTIFY"
        )
    finally:
        if approval_id is not None:
            async with engine.begin() as conn:
                await conn.execute(
                    delete(ApprovalDecision).where(
                        ApprovalDecision.approval_request_id == uuid.UUID(approval_id)
                    )
                )
                await conn.execute(
                    delete(PendingApprovalRecord).where(
                        PendingApprovalRecord.id == uuid.UUID(approval_id)
                    )
                )
                await conn.execute(
                    delete(IdempotencyRecord).where(
                        IdempotencyRecord.scope_principal_sub == principal_sub
                    )
                )
        await engine.dispose()
