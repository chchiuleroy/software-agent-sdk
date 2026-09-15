"""Integration tests for the device-inventory router — against a REAL
Postgres database, same rationale as ``test_approvals_router.py``: the
per-owner UNIQUE constraint on ``(owner_issuer, owner_sub, device_id)``,
the denylist's role in blocking re-registration, the registration quota,
and the conditional revoke UPDATE are exactly the kind of thing a mocked
session can't prove.

Not covered here, same limitation as ``test_approvals_router.py``'s own
module docstring: the ``check_replay_or_raise`` race-recovery branches in
both ``register_device``'s ``except IntegrityError`` and
``revoke_device``'s zero-rows-updated branch (code-review High) need a
genuine concurrent request racing against itself to exercise — this
file's SAVEPOINT-isolated single session structurally can't produce that
(see ``tests/conftest.py``'s ``db_session`` fixture docstring).

One exception to that limitation: the quota-race test below
(``test_register_quota_race_is_prevented_by_advisory_lock``, code-review
Medium) opens its own real engine/session-factory against the same test
database instead of using the shared SAVEPOINT-isolated fixture,
specifically so it CAN produce genuine concurrent commits — proving the
quota check's advisory lock actually serializes concurrent registrations
needs that, a single session cannot fake it.
"""

from __future__ import annotations

import asyncio
import uuid
from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select

from central_governance_api.auth.dependencies import get_oidc_resolver
from central_governance_api.auth.oidc import OIDCPrincipalResolver
from central_governance_api.config import Settings
from central_governance_api.db import (
    create_engine,
    create_session_factory,
    get_db_session,
)
from central_governance_api.main import create_app
from central_governance_api.models import (
    AdminAuditEvent,
    DeviceDenylistEntry,
    DeviceRegistration,
    IdempotencyRecord,
)

from .conftest import _TEST_DATABASE_URL, AUDIENCE, ISSUER, JWKS_URL
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


async def _register(
    client,
    signing_key,
    *,
    sub: str = "alice",
    roles: list[str] | None = None,
    device_id: str | None = None,
) -> dict[str, Any]:
    token = _sign(signing_key, sub=sub, roles=roles or ["agent.operator"])
    device_id = device_id or f"device-{uuid.uuid4()}"
    resp = await client.post(
        "/api/v1/devices/register",
        json={"device_id": device_id},
        headers=_auth(token, f"register-{uuid.uuid4()}"),
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


async def _revoke(client, token: str, registration_id: str, idempotency_key: str):
    return await client.post(
        f"/api/v1/devices/{registration_id}/revoke",
        headers=_auth(token, idempotency_key),
    )


# --- REGISTER ------------------------------------------------------------


async def test_register_persists_a_real_row(client, signing_key):
    body = await _register(client, signing_key, sub="alice")
    assert body["owner_subject"].endswith("#alice")
    assert body["registered_at"] is not None


async def test_register_succeeds_with_no_recognized_role(client, signing_key):
    """Device inventory isn't a security control (models.py's own
    docstring on DeviceRegistration) — self-registration has no privilege
    to gate, so a principal with zero known roles can still do it."""
    body = await _register(client, signing_key, sub="norole", roles=[])
    assert body["owner_subject"].endswith("#norole")


async def test_register_duplicate_device_id_same_owner_is_409(client, signing_key):
    device_id = f"dupe-{uuid.uuid4()}"
    await _register(client, signing_key, sub="alice", device_id=device_id)

    token = _sign(signing_key, sub="alice", roles=["agent.operator"])
    resp = await client.post(
        "/api/v1/devices/register",
        json={"device_id": device_id},
        headers=_auth(token, f"register-{uuid.uuid4()}"),
    )
    assert resp.status_code == 409
    assert resp.json()["error_code"] == "device_already_registered"


async def test_register_same_device_id_different_owner_succeeds(client, signing_key):
    """Code-review finding, Roy's decision 2026-09-15: device_id
    uniqueness is scoped per-owner, not global — two principals choosing
    the same human-meaningful name (e.g. "laptop") must not collide."""
    device_id = f"shared-name-{uuid.uuid4()}"
    alice_device = await _register(
        client, signing_key, sub="alice", device_id=device_id
    )
    bob_device = await _register(client, signing_key, sub="bob", device_id=device_id)

    assert alice_device["device_id"] == bob_device["device_id"] == device_id
    assert alice_device["id"] != bob_device["id"]
    assert alice_device["owner_subject"] != bob_device["owner_subject"]


async def test_register_idempotent_retry_replays(client, signing_key):
    token = _sign(signing_key, sub="alice", roles=["agent.operator"])
    device_id = f"idem-{uuid.uuid4()}"
    first = await client.post(
        "/api/v1/devices/register",
        json={"device_id": device_id},
        headers=_auth(token, "retry-key"),
    )
    second = await client.post(
        "/api/v1/devices/register",
        json={"device_id": device_id},
        headers=_auth(token, "retry-key"),
    )
    assert first.status_code == 201
    assert second.status_code == 201
    assert first.json() == second.json()


async def test_register_quota_exceeded_is_429(db_session, public_jwks, signing_key):
    """Code-review finding, Roy's decision 2026-09-15: a per-principal
    quota bounds total registrations (revoked ones count too — see
    DeviceRegistration's docstring) now that per-owner uniqueness alone
    doesn't stop one account from unbounded row growth. Uses its own app
    instance with a tiny quota rather than the shared `client` fixture,
    which doesn't parametrize `device_registration_quota`.
    """
    low_quota_settings = Settings(
        oidc_issuer=ISSUER,
        oidc_jwks_url=JWKS_URL,
        oidc_audience=AUDIENCE,
        database_url="postgresql+asyncpg://unused:unused@localhost/unused",
        device_registration_quota=2,
    )
    app = create_app(low_quota_settings)
    resolver = OIDCPrincipalResolver(
        low_quota_settings, preloaded_keys=public_jwks, never_refresh_keys=True
    )
    app.dependency_overrides[get_oidc_resolver] = lambda: resolver

    async def _db_session_override():
        yield db_session

    app.dependency_overrides[get_db_session] = _db_session_override
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        token = _sign(signing_key, sub="quota-alice", roles=["agent.operator"])
        for _ in range(2):
            resp = await client.post(
                "/api/v1/devices/register",
                json={"device_id": f"device-{uuid.uuid4()}"},
                headers=_auth(token, f"register-{uuid.uuid4()}"),
            )
            assert resp.status_code == 201, resp.text

        third = await client.post(
            "/api/v1/devices/register",
            json={"device_id": f"device-{uuid.uuid4()}"},
            headers=_auth(token, f"register-{uuid.uuid4()}"),
        )
        assert third.status_code == 429
        assert third.json()["error_code"] == "device_quota_exceeded"


async def test_register_quota_isolated_per_owner(db_session, public_jwks, signing_key):
    """Code-review Low: the sequential happy-path test above only proves
    ONE owner's quota is enforced — it doesn't prove a different owner is
    unaffected by it. Both principals share the same deployment (and thus
    the same `device_registration_quota` setting), so this pins that the
    quota is per-(issuer, sub), not a pool shared across every caller."""
    low_quota_settings = Settings(
        oidc_issuer=ISSUER,
        oidc_jwks_url=JWKS_URL,
        oidc_audience=AUDIENCE,
        database_url="postgresql+asyncpg://unused:unused@localhost/unused",
        device_registration_quota=2,
    )
    app = create_app(low_quota_settings)
    resolver = OIDCPrincipalResolver(
        low_quota_settings, preloaded_keys=public_jwks, never_refresh_keys=True
    )
    app.dependency_overrides[get_oidc_resolver] = lambda: resolver

    async def _db_session_override():
        yield db_session

    app.dependency_overrides[get_db_session] = _db_session_override
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        alice_token = _sign(
            signing_key, sub="quota-isolated-alice", roles=["agent.operator"]
        )
        bob_token = _sign(
            signing_key, sub="quota-isolated-bob", roles=["agent.operator"]
        )

        for _ in range(2):
            resp = await client.post(
                "/api/v1/devices/register",
                json={"device_id": f"device-{uuid.uuid4()}"},
                headers=_auth(alice_token, f"register-{uuid.uuid4()}"),
            )
            assert resp.status_code == 201, resp.text

        alice_third = await client.post(
            "/api/v1/devices/register",
            json={"device_id": f"device-{uuid.uuid4()}"},
            headers=_auth(alice_token, f"register-{uuid.uuid4()}"),
        )
        assert alice_third.status_code == 429

        bob_first = await client.post(
            "/api/v1/devices/register",
            json={"device_id": f"device-{uuid.uuid4()}"},
            headers=_auth(bob_token, f"register-{uuid.uuid4()}"),
        )
        assert bob_first.status_code == 201, bob_first.text


async def test_register_quota_still_counts_revoked_devices(
    db_session, public_jwks, signing_key
):
    """Code-review Low: config.py's own docstring on
    `device_registration_quota` says revoked rows still count toward it
    (revocation doesn't free the slot — see DeviceRegistration's
    docstring on why), but nothing actually tested that claim."""
    low_quota_settings = Settings(
        oidc_issuer=ISSUER,
        oidc_jwks_url=JWKS_URL,
        oidc_audience=AUDIENCE,
        database_url="postgresql+asyncpg://unused:unused@localhost/unused",
        device_registration_quota=1,
    )
    app = create_app(low_quota_settings)
    resolver = OIDCPrincipalResolver(
        low_quota_settings, preloaded_keys=public_jwks, never_refresh_keys=True
    )
    app.dependency_overrides[get_oidc_resolver] = lambda: resolver

    async def _db_session_override():
        yield db_session

    app.dependency_overrides[get_db_session] = _db_session_override
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        token = _sign(signing_key, sub="quota-revoked-alice", roles=["agent.operator"])
        first = await client.post(
            "/api/v1/devices/register",
            json={"device_id": f"device-{uuid.uuid4()}"},
            headers=_auth(token, f"register-{uuid.uuid4()}"),
        )
        assert first.status_code == 201, first.text

        revoke_resp = await _revoke(
            client, token, first.json()["id"], "revoke-for-quota-test"
        )
        assert revoke_resp.status_code == 200, revoke_resp.text

        second = await client.post(
            "/api/v1/devices/register",
            json={"device_id": f"device-{uuid.uuid4()}"},
            headers=_auth(token, f"register-{uuid.uuid4()}"),
        )
        assert second.status_code == 429
        assert second.json()["error_code"] == "device_quota_exceeded"


async def test_register_quota_race_is_prevented_by_advisory_lock(
    public_jwks, signing_key
):
    """Code-review Medium: a bare ``SELECT count(*)`` followed by a
    separate INSERT is not atomic under PostgreSQL's default Read
    Committed isolation — concurrent registrations with different
    device_id values could all read the same count, all pass the quota
    check, and all insert, overshooting the quota by more than "slightly".
    Fixed with a transaction-scoped advisory lock keyed on (issuer, sub)
    in ``register_device`` (see ``devices.py``'s ``_quota_lock_key``) so
    concurrent registrations for the same principal serialize instead of
    racing.

    Proving this needs a GENUINE concurrent commit, which the shared
    ``db_session`` fixture's SAVEPOINT-isolated single session
    structurally cannot produce — a single AsyncSession/connection can't
    run two requests "at the same time" no matter how it's awaited (see
    that fixture's own docstring). This test instead builds its own real
    engine/session-factory against the same test database (each request
    gets its own real connection from the pool, like production), fires a
    batch of genuinely concurrent registrations via ``asyncio.gather``,
    and cleans up the rows it committed afterward — the shared fixture's
    rollback-at-teardown can't clean these up since they were never part
    of its transaction. Skips gracefully (not the shared `db_session`
    fixture, so it checks connectivity itself) if no test Postgres is
    reachable, same convention as every other test in this module.
    """
    quota = 5
    concurrent_requests = 12
    principal_sub = f"quota-race-{uuid.uuid4()}"
    low_quota_settings = Settings(
        oidc_issuer=ISSUER,
        oidc_jwks_url=JWKS_URL,
        oidc_audience=AUDIENCE,
        database_url=_TEST_DATABASE_URL,
        device_registration_quota=quota,
    )
    engine = create_engine(low_quota_settings)
    try:
        async with engine.connect():
            pass
    except Exception as exc:
        await engine.dispose()
        pytest.skip(f"no reachable test Postgres at {_TEST_DATABASE_URL!r}: {exc}")

    app = create_app(low_quota_settings)
    resolver = OIDCPrincipalResolver(
        low_quota_settings, preloaded_keys=public_jwks, never_refresh_keys=True
    )
    app.dependency_overrides[get_oidc_resolver] = lambda: resolver

    session_factory = create_session_factory(engine)

    async def _real_db_session_override():
        # A fresh, genuinely independent session (and, from the pool, a
        # genuinely independent connection) per request — this is what
        # makes the requests below actually race, unlike the shared
        # SAVEPOINT-isolated `db_session` fixture used everywhere else.
        async with session_factory() as session:
            yield session

    app.dependency_overrides[get_db_session] = _real_db_session_override

    try:
        token = _sign(signing_key, sub=principal_sub, roles=["agent.operator"])
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:

            async def _one_register() -> int:
                resp = await client.post(
                    "/api/v1/devices/register",
                    json={"device_id": f"device-{uuid.uuid4()}"},
                    headers=_auth(token, f"register-{uuid.uuid4()}"),
                )
                return resp.status_code

            statuses = await asyncio.gather(
                *(_one_register() for _ in range(concurrent_requests))
            )

        succeeded = statuses.count(201)
        rejected = statuses.count(429)
        assert succeeded + rejected == concurrent_requests, statuses
        assert succeeded == quota, (
            f"advisory lock did not prevent quota overshoot: {succeeded} "
            f"registrations succeeded against a quota of {quota} "
            f"(statuses={statuses})"
        )
    finally:
        async with engine.begin() as conn:
            await conn.execute(
                delete(DeviceRegistration).where(
                    DeviceRegistration.owner_issuer == ISSUER,
                    DeviceRegistration.owner_sub == principal_sub,
                )
            )
            await conn.execute(
                delete(IdempotencyRecord).where(
                    IdempotencyRecord.scope_principal_issuer == ISSUER,
                    IdempotencyRecord.scope_principal_sub == principal_sub,
                )
            )
        await engine.dispose()


# --- REVOKE ----------------------------------------------------------------


async def test_revoke_by_owner_succeeds(client, signing_key, db_session):
    body = await _register(client, signing_key, sub="alice")
    token = _sign(signing_key, sub="alice", roles=["agent.operator"])
    resp = await _revoke(client, token, body["id"], "revoke-1")
    assert resp.status_code == 200, resp.text
    assert resp.json()["revoked_by_subject"].endswith("#alice")

    denylisted = await db_session.scalar(
        select(DeviceDenylistEntry).where(
            DeviceDenylistEntry.device_id == body["device_id"]
        )
    )
    assert denylisted is not None

    audit = await db_session.scalar(
        select(AdminAuditEvent).where(
            AdminAuditEvent.origin_device_id == body["device_id"],
            AdminAuditEvent.event_type == "device_revoked",
        )
    )
    assert audit is not None
    assert audit.actor_sub == "alice"


async def test_revoke_by_admin_on_someone_elses_device_succeeds(client, signing_key):
    body = await _register(client, signing_key, sub="alice")
    admin_token = _sign(signing_key, sub="dave", roles=["governance.admin"])
    resp = await _revoke(client, admin_token, body["id"], "revoke-admin")
    assert resp.status_code == 200
    assert resp.json()["revoked_by_subject"].endswith("#dave")


async def test_revoke_by_non_owner_non_admin_is_masked_as_404(client, signing_key):
    """Code-review Low: a non-owner, non-admin caller must not be able to
    tell "this registration doesn't exist" apart from "it exists but
    isn't yours" — both have to come back as the same 404, or an
    authenticated principal could enumerate the device inventory by
    probing IDs."""
    body = await _register(client, signing_key, sub="alice")
    other_token = _sign(signing_key, sub="bob", roles=["agent.operator"])
    resp = await _revoke(client, other_token, body["id"], "revoke-denied")
    unknown_resp = await _revoke(
        client, other_token, str(uuid.uuid4()), "revoke-unknown"
    )
    assert resp.status_code == unknown_resp.status_code == 404
    assert (
        resp.json()["error_code"]
        == unknown_resp.json()["error_code"]
        == ("device_not_found")
    )


async def test_revoke_unknown_registration_is_404(client, signing_key):
    token = _sign(signing_key, sub="alice", roles=["agent.operator"])
    resp = await _revoke(client, token, str(uuid.uuid4()), "revoke-404")
    assert resp.status_code == 404
    assert resp.json()["error_code"] == "device_not_found"


async def test_revoke_same_sub_different_issuer_is_not_owner(
    client, signing_key, db_session
):
    """Code-review Low: every other test in this file authenticates
    through this deployment's single trusted OIDC issuer (v11 §3: "not
    multi-tenant"), so none of them could catch a regression to comparing
    ownership on `sub` alone — OIDC only guarantees `sub` uniqueness
    *within* one issuer. This inserts a registration row owned by a
    DIFFERENT issuer directly (the resolver only ever trusts one issuer,
    so an HTTP-driven registration can't produce a second-issuer row on
    its own) and confirms a same-sub principal from the trusted issuer is
    still treated as a non-owner — masked as 404, same as any other
    non-owner (see the enumeration-defense test above)."""
    foreign = DeviceRegistration(
        owner_issuer="https://keycloak.example.invalid/realms/other-tenant",
        owner_sub="alice",
        device_id=f"foreign-issuer-{uuid.uuid4()}",
    )
    db_session.add(foreign)
    await db_session.flush()

    token = _sign(signing_key, sub="alice", roles=["agent.operator"])
    resp = await _revoke(client, token, str(foreign.id), "revoke-foreign-issuer")
    assert resp.status_code == 404
    assert resp.json()["error_code"] == "device_not_found"


async def test_revoke_malformed_registration_id_is_422(client, signing_key):
    """``registration_id`` is a path-level UUID now (not the caller-chosen
    ``device_id`` string — see module docstring) — FastAPI/Pydantic reject
    a non-UUID value before this router ever sees the request."""
    token = _sign(signing_key, sub="alice", roles=["agent.operator"])
    resp = await _revoke(client, token, "not-a-uuid", "revoke-malformed")
    assert resp.status_code == 422


async def test_revoke_twice_is_409_on_second_call(client, signing_key):
    body = await _register(client, signing_key, sub="alice")
    token = _sign(signing_key, sub="alice", roles=["agent.operator"])
    first = await _revoke(client, token, body["id"], "revoke-twice-1")
    second = await _revoke(client, token, body["id"], "revoke-twice-2")
    assert first.status_code == 200
    assert second.status_code == 409
    assert second.json()["error_code"] == "device_already_revoked"


async def test_register_after_revoke_is_denied_not_silently_reactivated(
    client, signing_key
):
    """The denylist's whole reason for existing (models.DeviceDenylistEntry's
    docstring) — a revoked (owner, device_id) pair must not quietly come
    back via a fresh register call."""
    body = await _register(client, signing_key, sub="alice")
    token = _sign(signing_key, sub="alice", roles=["agent.operator"])
    revoke_resp = await _revoke(client, token, body["id"], "revoke-before-reregister")
    assert revoke_resp.status_code == 200, revoke_resp.text

    resp = await client.post(
        "/api/v1/devices/register",
        json={"device_id": body["device_id"]},
        headers=_auth(token, "reregister-attempt"),
    )
    assert resp.status_code == 409
    assert resp.json()["error_code"] == "device_revoked"


# --- device_id format validation (code-review Medium) -----------------------


@pytest.mark.parametrize(
    "device_id",
    [
        "",
        "   ",
        "has a space",
        "has/a/slash",
        "has?a=query",
        "has#a-fragment",
        "a" * 65,  # one over the max
    ],
)
async def test_register_rejects_malformed_device_id(client, signing_key, device_id):
    """Empty, path-unsafe, or over-length device_id must be rejected at
    the request-validation boundary — otherwise it could be written by
    register but never cleanly displayed/audited, and (device_id being
    per-owner unique and never deleted, see DeviceRegistration's
    docstring) would permanently occupy that owner's namespace slot."""
    token = _sign(signing_key, sub="alice", roles=["agent.operator"])
    resp = await client.post(
        "/api/v1/devices/register",
        json={"device_id": device_id},
        headers=_auth(token, f"malformed-{uuid.uuid4()}"),
    )
    assert resp.status_code == 422
