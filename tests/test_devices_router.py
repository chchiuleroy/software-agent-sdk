"""Integration tests for the device-inventory router — against a REAL
Postgres database, same rationale as ``test_approvals_router.py``: the
UNIQUE constraint on ``device_id``, the denylist's role in blocking
re-registration, and the conditional revoke UPDATE are exactly the kind
of thing a mocked session can't prove.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from central_governance_api.auth.dependencies import get_oidc_resolver
from central_governance_api.auth.oidc import OIDCPrincipalResolver
from central_governance_api.db import get_db_session
from central_governance_api.main import create_app
from central_governance_api.models import AdminAuditEvent, DeviceDenylistEntry

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


async def test_register_duplicate_device_id_is_409(client, signing_key):
    device_id = f"dupe-{uuid.uuid4()}"
    await _register(client, signing_key, sub="alice", device_id=device_id)

    token = _sign(signing_key, sub="bob", roles=["agent.operator"])
    resp = await client.post(
        "/api/v1/devices/register",
        json={"device_id": device_id},
        headers=_auth(token, f"register-{uuid.uuid4()}"),
    )
    assert resp.status_code == 409
    assert resp.json()["error_code"] == "device_already_registered"


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


# --- REVOKE ----------------------------------------------------------------


async def test_revoke_by_owner_succeeds(client, signing_key, db_session):
    body = await _register(client, signing_key, sub="alice")
    token = _sign(signing_key, sub="alice", roles=["agent.operator"])
    resp = await client.post(
        f"/api/v1/devices/{body['device_id']}/revoke",
        headers=_auth(token, "revoke-1"),
    )
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
    assert audit.actor_subject.endswith("#alice")


async def test_revoke_by_admin_on_someone_elses_device_succeeds(client, signing_key):
    body = await _register(client, signing_key, sub="alice")
    admin_token = _sign(signing_key, sub="dave", roles=["governance.admin"])
    resp = await client.post(
        f"/api/v1/devices/{body['device_id']}/revoke",
        headers=_auth(admin_token, "revoke-admin"),
    )
    assert resp.status_code == 200
    assert resp.json()["revoked_by_subject"].endswith("#dave")


async def test_revoke_by_non_owner_non_admin_is_403(client, signing_key):
    body = await _register(client, signing_key, sub="alice")
    other_token = _sign(signing_key, sub="bob", roles=["agent.operator"])
    resp = await client.post(
        f"/api/v1/devices/{body['device_id']}/revoke",
        headers=_auth(other_token, "revoke-denied"),
    )
    assert resp.status_code == 403
    assert resp.json()["error_code"] == "authorization_denied"


async def test_revoke_unknown_device_is_404(client, signing_key):
    token = _sign(signing_key, sub="alice", roles=["agent.operator"])
    resp = await client.post(
        "/api/v1/devices/does-not-exist/revoke",
        headers=_auth(token, "revoke-404"),
    )
    assert resp.status_code == 404
    assert resp.json()["error_code"] == "device_not_found"


async def test_revoke_twice_is_409_on_second_call(client, signing_key):
    body = await _register(client, signing_key, sub="alice")
    token = _sign(signing_key, sub="alice", roles=["agent.operator"])
    first = await client.post(
        f"/api/v1/devices/{body['device_id']}/revoke",
        headers=_auth(token, "revoke-twice-1"),
    )
    second = await client.post(
        f"/api/v1/devices/{body['device_id']}/revoke",
        headers=_auth(token, "revoke-twice-2"),
    )
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
    await client.post(
        f"/api/v1/devices/{body['device_id']}/revoke",
        headers=_auth(token, "revoke-before-reregister"),
    )

    resp = await client.post(
        "/api/v1/devices/register",
        json={"device_id": body["device_id"]},
        headers=_auth(token, "reregister-attempt"),
    )
    assert resp.status_code == 409
    assert resp.json()["error_code"] == "device_revoked"
