from __future__ import annotations

import os
from collections.abc import AsyncGenerator

import pytest
from joserfc import jwk
from sqlalchemy.ext.asyncio import AsyncSession

from central_governance_api.config import Settings
from central_governance_api.db import create_engine


ISSUER = "https://keycloak.example.invalid/realms/roy-governance"
JWKS_URL = f"{ISSUER}/protocol/openid-connect/certs"
AUDIENCE = "central-governance-api"

# Same env var + same fallback env.py's Alembic config uses (see
# alembic/env.py's comment) — one DB URL convention for both migrations
# and tests, and a session running its own throwaway Postgres instance
# for router-layer verification (see approvals router tests) only needs
# to export this once rather than edit this file.
_TEST_DATABASE_URL = os.environ.get(
    "CGA_DATABASE_URL",
    "postgresql+asyncpg://cga:cga@localhost:5432/central_governance_test",
)


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
        database_url=_TEST_DATABASE_URL,
    )


@pytest.fixture
async def db_session(settings: Settings) -> AsyncGenerator[AsyncSession]:
    """A real AsyncSession against ``_TEST_DATABASE_URL`` — router tests
    that need to verify actual conditional-UPDATE/transaction behavior use
    this rather than a mock, since that behavior is exactly what a mock
    can't prove.

    Isolation note: router endpoints are expected to call
    ``session.commit()`` themselves (that's what makes a conditional
    UPDATE's effect durable within a request) — a plain ``session.rollback()``
    at teardown would do nothing once that's already happened. So this
    fixture opens the *connection's* transaction first and binds the
    session to it with ``join_transaction_mode="create_savepoint"``: every
    ``session.commit()`` the application code calls only releases a
    SAVEPOINT nested inside that outer transaction, which is never itself
    committed — only rolled back here at teardown. This is the standard
    SQLAlchemy 2.0 pattern for exercising real commit-calling application
    code in tests without any test polluting another.
    """
    engine = create_engine(settings)
    try:
        connection_cm = engine.connect()
        connection = await connection_cm.__aenter__()
    except Exception as exc:
        # No live test Postgres configured/reachable — skip rather than
        # error, so the plain `uv run pytest tests/` documented in
        # README still passes for anyone who hasn't stood up a test DB
        # yet (this project's "official" test DB setup is still Roy's
        # call per README's "部署前置條件"). Exporting CGA_DATABASE_URL
        # before running pytest opts into the real integration tests.
        await engine.dispose()
        pytest.skip(f"no reachable test Postgres at {_TEST_DATABASE_URL!r}: {exc}")
    try:
        await connection.begin()
        session = AsyncSession(
            bind=connection, join_transaction_mode="create_savepoint"
        )
        try:
            yield session
        finally:
            await session.close()
            await connection.rollback()
    finally:
        await connection_cm.__aexit__(None, None, None)
        await engine.dispose()
