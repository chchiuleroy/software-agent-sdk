"""``CGA_REQUIRE_EXECUTION_COMMITMENT``: without it a device that omits the
commitment silently falls back to the unprotected path, so the deployment can
decide to refuse such a create outright. Default off; applies to new records.
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
from .test_approvals_router import _auth, _create_body
from .test_execution_commitment import _body_with_commitment


def _settings(required: bool) -> Settings:
    return Settings(
        oidc_issuer=ISSUER,
        oidc_jwks_url=JWKS_URL,
        oidc_audience=AUDIENCE,
        database_url=_TEST_DATABASE_URL,
        require_execution_commitment=required,
    )


@pytest.fixture(params=[True, False], ids=["required", "optional"])
async def mode_client(request, public_jwks, db_session):
    required: bool = request.param
    app = create_app(_settings(required))
    resolver = OIDCPrincipalResolver(
        _settings(required), preloaded_keys=public_jwks, never_refresh_keys=True
    )
    app.dependency_overrides[get_oidc_resolver] = lambda: resolver

    async def _db_session_override():
        yield db_session

    app.dependency_overrides[get_db_session] = _db_session_override
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as c:
        yield required, c


def test_requiring_a_commitment_is_off_by_default():
    # Turning this on by default would make every agent-server that does not
    # send one fail at its next create.
    assert _settings(False).require_execution_commitment is False
    assert (
        Settings(
            oidc_issuer=ISSUER,
            oidc_jwks_url=JWKS_URL,
            oidc_audience=AUDIENCE,
            database_url=_TEST_DATABASE_URL,
        ).require_execution_commitment
        is False
    )


async def test_create_without_a_commitment(mode_client, signing_key, db_session):
    required, client = mode_client
    body = _create_body()
    token = _sign(signing_key, sub="alice", roles=["agent.operator"])

    resp = await client.post(
        "/api/v1/approvals", json=body, headers=_auth(token, f"c-{uuid.uuid4()}")
    )

    rows = (
        await db_session.execute(
            select(PendingApprovalRecord).where(
                PendingApprovalRecord.request_id == body["request_id"]
            )
        )
    ).all()
    if required:
        # Refused, and nothing was written.
        assert resp.status_code == 400
        assert resp.json()["error_code"] == "execution_commitment_required"
        assert rows == []
    else:
        assert resp.status_code == 201
        assert len(rows) == 1


async def test_create_with_a_commitment_is_accepted_either_way(
    mode_client, signing_key
):
    _, client = mode_client
    token = _sign(signing_key, sub="alice", roles=["agent.operator"])

    resp = await client.post(
        "/api/v1/approvals",
        json=_body_with_commitment(),
        headers=_auth(token, f"c-{uuid.uuid4()}"),
    )

    assert resp.status_code == 201, resp.text
