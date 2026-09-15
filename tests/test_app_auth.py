"""Tests for the Bearer/FastAPI adapter layer (auth/dependencies.py) —
the RFC 6750 error-code mapping and the `/whoami` smoke-test endpoint.
Uses `app.dependency_overrides` to swap in a resolver seeded with a
synthetic JWKS, matching the house style found in the sibling
agent-server's own test suite (per repo exploration for this task).
"""

from __future__ import annotations

import time

import pytest
from httpx import ASGITransport, AsyncClient
from joserfc import jwt

from central_governance_api.auth.dependencies import get_oidc_resolver
from central_governance_api.auth.oidc import OIDCPrincipalResolver
from central_governance_api.main import create_app

from .conftest import AUDIENCE, ISSUER


def _sign(signing_key, **claim_overrides) -> str:
    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "sub": "user-123",
        "aud": AUDIENCE,
        "exp": now + 3600,
        "iat": now,
        "roles": ["agent.operator"],
    }
    claims.update(claim_overrides)
    header = {"alg": "RS256", "kid": "test-key-1"}
    return jwt.encode(header, claims, signing_key)


@pytest.fixture
async def client(settings, public_jwks, signing_key):
    app = create_app(settings)
    resolver = OIDCPrincipalResolver(
        settings, preloaded_keys=public_jwks, never_refresh_keys=True
    )
    app.dependency_overrides[get_oidc_resolver] = lambda: resolver
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


async def test_healthz_needs_no_auth(client):
    resp = await client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


async def test_whoami_without_authorization_header_is_401_with_challenge(client):
    resp = await client.get("/api/v1/whoami")
    assert resp.status_code == 401
    assert resp.headers["www-authenticate"].startswith("Bearer")


async def test_whoami_with_malformed_header_is_400(client):
    resp = await client.get(
        "/api/v1/whoami", headers={"Authorization": "NotBearer abc"}
    )
    assert resp.status_code == 400


async def test_whoami_with_invalid_token_is_401(client):
    resp = await client.get(
        "/api/v1/whoami", headers={"Authorization": "Bearer garbage-not-a-jwt"}
    )
    assert resp.status_code == 401
    assert resp.headers["www-authenticate"].startswith("Bearer")


async def test_whoami_error_body_does_not_leak_verification_internals(client):
    resp = await client.get(
        "/api/v1/whoami", headers={"Authorization": "Bearer garbage-not-a-jwt"}
    )
    assert resp.status_code == 401
    # v11: don't forward the resolver's internal failure reason to the caller
    assert "joserfc" not in resp.text.lower()
    assert "traceback" not in resp.text.lower()


async def test_whoami_with_valid_token_returns_principal(client, signing_key):
    token = _sign(signing_key)
    resp = await client.get(
        "/api/v1/whoami", headers={"Authorization": f"Bearer {token}"}
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["subject"] == f"{ISSUER}#user-123"
    assert body["roles"] == ["agent.operator"]
