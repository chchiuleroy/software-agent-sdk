"""Unauthenticated liveness endpoint, and an authenticated `/whoami` used
to manually smoke-test the OIDC adapter end-to-end against a real
Keycloak token before any business endpoints exist.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends

from central_governance_api.auth.dependencies import get_current_principal
from central_governance_api.auth.oidc import Principal


router = APIRouter(tags=["health"])


@router.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/api/v1/whoami")
async def whoami(
    principal: Principal = Depends(get_current_principal),
) -> dict[str, object]:
    return {
        "subject": principal.subject,
        "display_name": principal.display_name,
        "roles": sorted(principal.roles),
    }
