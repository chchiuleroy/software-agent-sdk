"""App factory + uvicorn entrypoint for the central governance API.

Step 1 of v11 §11's implementation order: this wires up the FastAPI app,
the OIDC principal resolver, and the DB engine/session factory. The
approval-workflow endpoints themselves (create/decide/claim/report-result/
wait/cancel/reconciliation-findings/devices/register/audit-events) are
step 2+ — not in this skeleton.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from central_governance_api.auth.oidc import OIDCPrincipalResolver
from central_governance_api.config import Settings, get_settings
from central_governance_api.db import create_engine, create_session_factory
from central_governance_api.routers.health import router as health_router


logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
    settings: Settings = app.state.settings
    app.state.oidc_resolver = OIDCPrincipalResolver(settings)

    engine = create_engine(settings)
    app.state.db_engine = engine
    app.state.db_session_factory = create_session_factory(engine)

    logger.info("central-governance-api startup complete")
    try:
        yield
    finally:
        await engine.dispose()


def create_app(settings: Settings | None = None) -> FastAPI:
    app = FastAPI(
        title="OHS Central Governance API",
        version="0.1.0",
        lifespan=lifespan,
    )
    app.state.settings = settings or get_settings()
    app.include_router(health_router)
    return app


def main() -> None:
    """CLI entrypoint (``central-governance-api`` script). Deliberately
    builds the app here rather than exposing a module-level ``app = ...``
    — ``Settings`` has no defaults for the OIDC fields (a misconfigured
    issuer/audience must fail loudly, not silently fall back to a
    placeholder), so importing this module for ``create_app`` alone (e.g.
    from tests, with their own explicit ``Settings``) must not require
    those env vars to be set.
    """
    import uvicorn

    uvicorn.run(create_app(), host="127.0.0.1", port=8899)
