from __future__ import annotations

import pytest
from joserfc import jwk

from central_governance_api.config import Settings


ISSUER = "https://keycloak.example.invalid/realms/roy-governance"
JWKS_URL = f"{ISSUER}/protocol/openid-connect/certs"
AUDIENCE = "central-governance-api"


@pytest.fixture(scope="module")
def signing_key() -> jwk.RSAKey:
    return jwk.RSAKey.generate_key(2048, parameters={"kid": "test-key-1"})


@pytest.fixture
def public_jwks(signing_key: jwk.RSAKey) -> jwk.KeySetSerialization:
    return {"keys": [signing_key.as_dict(private=False)]}


@pytest.fixture
def settings() -> Settings:
    return Settings(
        oidc_issuer=ISSUER,
        oidc_jwks_url=JWKS_URL,
        oidc_audience=AUDIENCE,
        database_url="postgresql+asyncpg://cga:cga@localhost:5432/central_governance_test",
    )
