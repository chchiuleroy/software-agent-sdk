"""Device binding on approval CREATE/CLAIM (``device_binding_enforced``).

Identity model B (2026-10-02): each agent-server is a *device* identity, its
Keycloak service account. Device binding is what makes that identity mean
something to central — with it on, ``origin_device_id`` must be an active
device registered by the very principal calling, so revoking a device
actually stops it. These tests run the real router against a real Postgres
(same setup as ``test_approvals_router.py``).

Each test encodes why it matters; none just checks that a status code
changed.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from central_governance_api.auth.dependencies import get_oidc_resolver
from central_governance_api.auth.oidc import OIDCPrincipalResolver
from central_governance_api.config import Settings
from central_governance_api.db import get_db_session
from central_governance_api.main import create_app
from central_governance_api.models import PendingApprovalRecord

from .conftest import _TEST_DATABASE_URL, AUDIENCE, ISSUER, JWKS_URL
from .test_app_auth import _sign
from .test_approvals_router import _auth, _create_approval, _create_body
from .test_devices_router import _register, _revoke


@pytest.fixture
def settings() -> Settings:
    """Overrides conftest's ``settings`` for this module only: binding ON."""
    return Settings(
        oidc_issuer=ISSUER,
        oidc_jwks_url=JWKS_URL,
        oidc_audience=AUDIENCE,
        database_url=_TEST_DATABASE_URL,
        device_binding_enforced=True,
    )


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


def _requester_token(signing_key, sub: str = "alice") -> str:
    return _sign(signing_key, sub=sub, roles=["agent.operator"])


async def _post_create(client, signing_key, *, sub: str, device_id: str):
    return await client.post(
        "/api/v1/approvals",
        json=_create_body(origin_device_id=device_id),
        headers=_auth(_requester_token(signing_key, sub), f"create-{uuid.uuid4()}"),
    )


def test_binding_is_off_by_default():
    """Opt-in on purpose: a freshly deployed central must not start refusing
    every agent-server whose device id was never registered. If this flips
    to True, every existing deployment breaks silently at its next request."""
    assert (
        Settings(
            oidc_issuer=ISSUER,
            oidc_jwks_url=JWKS_URL,
            oidc_audience=AUDIENCE,
            database_url=_TEST_DATABASE_URL,
        ).device_binding_enforced
        is False
    )


async def test_create_with_unregistered_device_is_403_and_writes_nothing(
    client, signing_key, db_session
):
    """The point of binding: a caller can't just assert any origin_device_id.
    Also proves the refusal happens BEFORE a row is written."""
    request_id = str(uuid.uuid4())
    resp = await client.post(
        "/api/v1/approvals",
        json=_create_body(request_id=request_id, origin_device_id="never-registered"),
        headers=_auth(_requester_token(signing_key), f"create-{uuid.uuid4()}"),
    )

    assert resp.status_code == 403
    assert resp.json()["error_code"] == "device_not_bound"
    rows = (
        await db_session.execute(
            select(PendingApprovalRecord).where(
                PendingApprovalRecord.request_id == request_id
            )
        )
    ).all()
    assert rows == []


async def test_create_with_own_registered_device_succeeds(client, signing_key):
    registered = await _register(client, signing_key, sub="alice")

    resp = await _post_create(
        client, signing_key, sub="alice", device_id=registered["device_id"]
    )

    assert resp.status_code == 201, resp.text


async def test_another_principals_registration_does_not_count(client, signing_key):
    """Ownership is part of the check: alice registering 'laptop' must not let
    bob create approvals claiming to come from 'laptop'. Without the owner
    filter this passes, and the binding would prove nothing."""
    device_id = f"laptop-{uuid.uuid4()}"
    await _register(client, signing_key, sub="alice", device_id=device_id)

    resp = await _post_create(client, signing_key, sub="bob", device_id=device_id)

    assert resp.status_code == 403
    assert resp.json()["error_code"] == "device_not_bound"


async def test_revoked_device_can_no_longer_create(client, signing_key):
    """Revocation must actually bite, or the inventory is decoration."""
    registered = await _register(client, signing_key, sub="alice")
    revoke = await _revoke(
        client,
        _requester_token(signing_key, "alice"),
        registered["id"],
        f"revoke-{uuid.uuid4()}",
    )
    assert revoke.status_code == 200, revoke.text

    resp = await _post_create(
        client, signing_key, sub="alice", device_id=registered["device_id"]
    )

    assert resp.status_code == 403
    assert resp.json()["error_code"] == "device_not_bound"


async def test_claim_after_revocation_is_refused_and_leaves_record_accepted(
    client, signing_key, db_session
):
    """The check at CLAIM, not only at CREATE: the device can be revoked while
    the request waits for a decision, and claim is what lets the action run."""
    registered = await _register(client, signing_key, sub="alice")
    created = await _create_approval(
        client, signing_key, sub="alice", origin_device_id=registered["device_id"]
    )
    approver = _sign(signing_key, sub="carol", roles=["agent.approver"])
    decided = await client.post(
        f"/api/v1/approvals/{created['id']}/decide",
        json={"decision": "accept"},
        headers=_auth(approver, f"decide-{uuid.uuid4()}"),
    )
    assert decided.status_code == 200, decided.text

    revoke = await _revoke(
        client,
        _requester_token(signing_key, "alice"),
        registered["id"],
        f"revoke-{uuid.uuid4()}",
    )
    assert revoke.status_code == 200, revoke.text

    claim = await client.post(
        f"/api/v1/approvals/{created['id']}/claim",
        headers=_auth(_requester_token(signing_key, "alice"), f"claim-{uuid.uuid4()}"),
    )

    assert claim.status_code == 403
    assert claim.json()["error_code"] == "device_not_bound"
    row = await db_session.get(PendingApprovalRecord, uuid.UUID(created["id"]))
    await db_session.refresh(row)
    assert row.status == "accepted"
