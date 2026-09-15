"""Integration tests for the audit-events read endpoint — against a REAL
Postgres database. No idempotency/conditional-update machinery to prove
here (it's a GET), so the real-DB rationale is narrower than the other
two router test files: mainly the ``governance.admin``-only gate and
pagination actually querying real rows rather than a fixture.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import ASGITransport, AsyncClient

from central_governance_api.auth.dependencies import get_oidc_resolver
from central_governance_api.auth.oidc import OIDCPrincipalResolver
from central_governance_api.db import get_db_session
from central_governance_api.main import create_app

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


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _register_and_revoke(client, signing_key, sub: str) -> str:
    token = _sign(signing_key, sub=sub, roles=["agent.operator"])
    device_id = f"device-{uuid.uuid4()}"
    await client.post(
        "/api/v1/devices/register",
        json={"device_id": device_id},
        headers={**_auth(token), "Idempotency-Key": f"reg-{uuid.uuid4()}"},
    )
    await client.post(
        f"/api/v1/devices/{device_id}/revoke",
        headers={**_auth(token), "Idempotency-Key": f"rev-{uuid.uuid4()}"},
    )
    return device_id


async def test_audit_events_requires_admin_role(client, signing_key):
    token = _sign(signing_key, sub="alice", roles=["agent.operator"])
    resp = await client.get("/api/v1/audit-events", headers=_auth(token))
    assert resp.status_code == 403


async def test_audit_events_lists_device_revocation(client, signing_key):
    device_id = await _register_and_revoke(client, signing_key, sub="alice")

    admin_token = _sign(signing_key, sub="dave", roles=["governance.admin"])
    resp = await client.get(
        "/api/v1/audit-events",
        params={"event_type": "device_revoked"},
        headers=_auth(admin_token),
    )
    assert resp.status_code == 200
    body = resp.json()
    matching = [item for item in body["items"] if item["origin_device_id"] == device_id]
    assert len(matching) == 1
    assert matching[0]["actor_subject"].endswith("#alice")


async def test_audit_events_pagination_walks_every_page_exactly_once(
    client, signing_key
):
    """Code-review Low pointed out the original version of this test only
    checked the first page's `next_offset` value, never actually followed
    it — so it couldn't have caught an off-by-one in the second page or a
    final page that wrongly still claims there's more. This version walks
    pages until `next_offset` is null and checks the total, not just one
    page's shape."""
    admin_token = _sign(signing_key, sub="dave", roles=["governance.admin"])
    for _ in range(3):
        await _register_and_revoke(client, signing_key, sub="alice")

    seen_ids: list[str] = []
    offset = 0
    for _ in range(10):  # hard cap so a pagination bug can't infinite-loop the test
        resp = await client.get(
            "/api/v1/audit-events",
            params={"event_type": "device_revoked", "limit": 2, "offset": offset},
            headers=_auth(admin_token),
        )
        assert resp.status_code == 200
        body = resp.json()
        seen_ids.extend(item["id"] for item in body["items"])
        if body["next_offset"] is None:
            break
        offset = body["next_offset"]
    else:
        pytest.fail("pagination did not terminate within 10 pages")

    assert len(seen_ids) == 3
    assert len(set(seen_ids)) == 3  # no page repeated an item
