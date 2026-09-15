"""App factory + uvicorn entrypoint for the central governance API.

Step 1 of v11 §11's implementation order wired up the FastAPI app, the
OIDC principal resolver, and the DB engine/session factory. Step 2 adds
the approval-workflow router (``routers/approvals.py``: create/decide/
claim/report-result/cancel/reconciliation-findings), the device inventory
router (``routers/devices.py``: register/revoke), the audit-events read
router (``routers/audit.py``), and the FastAPI exception handlers that
map their pure-logic error types to HTTP responses — still not in this
file: ``/wait`` (step 3, LISTEN/NOTIFY).
"""

from __future__ import annotations

import logging
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from central_governance_api.approvals.authorize import AuthorizationDeniedError
from central_governance_api.approvals.errors import (
    ConcurrentModificationError,
    DigestMismatchError,
    ExecutionAttemptMismatchError,
    RecordNotFoundError,
    RecordNotTerminalError,
)
from central_governance_api.approvals.idempotency import IdempotencyKeyReusedError
from central_governance_api.approvals.state_machine import IllegalTransitionError
from central_governance_api.auth.oidc import OIDCPrincipalResolver
from central_governance_api.config import Settings, get_settings
from central_governance_api.db import create_engine, create_session_factory
from central_governance_api.routers.approvals import router as approvals_router
from central_governance_api.routers.audit import router as audit_router
from central_governance_api.routers.devices import (
    DeviceAlreadyRegisteredError,
    DeviceAlreadyRevokedError,
    DeviceAuthorizationDeniedError,
    DeviceNotFoundError,
    DeviceRevokedError,
)
from central_governance_api.routers.devices import router as devices_router
from central_governance_api.routers.health import router as health_router


logger = logging.getLogger(__name__)

# error type -> (HTTP status, "error_code" body field). One central table
# rather than a try/except in every route handler — mirrors the sibling
# openhands-sdk-governed repo's SelfApprovalDeniedError -> 403 pattern
# (see errors.py's module docstring). The message shown to the caller is
# always str(exc) — every exception type above was written with a
# safe-to-show __str__ specifically so this table doesn't need a second,
# separate "public message" per error type.
_ERROR_STATUS: dict[type[Exception], tuple[int, str]] = {
    AuthorizationDeniedError: (403, "authorization_denied"),
    IllegalTransitionError: (409, "illegal_transition"),
    ConcurrentModificationError: (409, "concurrent_modification"),
    ExecutionAttemptMismatchError: (409, "execution_attempt_mismatch"),
    RecordNotTerminalError: (409, "record_not_terminal"),
    RecordNotFoundError: (404, "record_not_found"),
    DigestMismatchError: (400, "digest_mismatch"),
    IdempotencyKeyReusedError: (422, "idempotency_key_reused"),
    DeviceNotFoundError: (404, "device_not_found"),
    DeviceAuthorizationDeniedError: (403, "authorization_denied"),
    DeviceAlreadyRegisteredError: (409, "device_already_registered"),
    DeviceRevokedError: (409, "device_revoked"),
    DeviceAlreadyRevokedError: (409, "device_already_revoked"),
}


def _install_exception_handlers(app: FastAPI) -> None:
    for exc_type, (status_code, error_code) in _ERROR_STATUS.items():

        def _handler(
            _request: Request,
            exc: Exception,
            *,
            _status_code: int = status_code,
            _error_code: str = error_code,
        ) -> JSONResponse:
            return JSONResponse(
                status_code=_status_code,
                content={"error_code": _error_code, "detail": str(exc)},
            )

        app.add_exception_handler(exc_type, _handler)


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
    app.include_router(approvals_router)
    app.include_router(devices_router)
    app.include_router(audit_router)
    _install_exception_handlers(app)
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
