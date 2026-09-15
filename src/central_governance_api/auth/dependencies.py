"""FastAPI dependency layer wrapping ``OIDCPrincipalResolver``.

``oidc.py``'s resolver only knows how to turn a raw token string into a
``Principal`` or raise ``PrincipalResolutionError`` — it has no idea what an
``Authorization`` header or an HTTP response is. This module is exactly the
adapter layer the v11 design (§3 "OIDCPrincipalResolver 重用範圍") says has
to be written new regardless of whether the underlying verifier is reused
or rewritten.

RFC 6750 error mapping (v11 round-10 fix — the design doc originally said
"map everything to 400", round 10 corrected that):
- No ``Authorization`` header at all → 401 with a ``WWW-Authenticate``
  challenge header, no detail.
- Header present but not ``Bearer <token>`` shaped → 400 (malformed
  request, not an authentication attempt at all).
- Token present but fails verification (expired, bad signature, wrong
  issuer/audience, malformed claims...) → 401 with challenge, no detail
  (v11: don't leak *why* verification failed to the caller).
- Token verifies but the caller lacks a required role → 403 (raised by
  ``require_role``, not this module).
"""

from __future__ import annotations

from collections.abc import Callable

from fastapi import Depends, Request
from fastapi.exceptions import HTTPException

from central_governance_api.auth.oidc import (
    OIDCPrincipalResolver,
    Principal,
    PrincipalResolutionError,
)


_WWW_AUTHENTICATE_CHALLENGE = 'Bearer realm="central-governance-api"'


def _unauthenticated(*, detail: str) -> HTTPException:
    return HTTPException(
        status_code=401,
        detail=detail,
        headers={"WWW-Authenticate": _WWW_AUTHENTICATE_CHALLENGE},
    )


def get_oidc_resolver(request: Request) -> OIDCPrincipalResolver:
    """Reads the resolver constructed once at app startup (see main.py's
    lifespan) off ``app.state`` — not rebuilt per request, since it owns a
    JWKS cache that must persist across requests to be useful at all.
    """
    resolver = getattr(request.app.state, "oidc_resolver", None)
    if resolver is None:
        raise RuntimeError(
            "OIDCPrincipalResolver not initialized on app.state — "
            "check the app lifespan wiring in main.py"
        )
    return resolver


async def get_current_principal(
    request: Request,
    resolver: OIDCPrincipalResolver = Depends(get_oidc_resolver),
) -> Principal:
    auth_header = request.headers.get("Authorization")
    if auth_header is None:
        raise _unauthenticated(detail="Missing Authorization header")

    scheme, _, token = auth_header.partition(" ")
    if scheme.lower() != "bearer" or not token:
        # Malformed request, not a failed auth attempt — per RFC 6750 this
        # is the one case that's a plain 400, not a 401 challenge.
        raise HTTPException(
            status_code=400,
            detail="Authorization header must be 'Bearer <token>'",
        )

    try:
        return await resolver.resolve(token)
    except PrincipalResolutionError:
        # Never forward the resolver's exception message to the client —
        # it can contain verification internals (which claim failed,
        # which key was tried). Log it server-side only, if desired; the
        # response is deliberately generic.
        raise _unauthenticated(detail="Invalid or expired token") from None


def require_role(role: str) -> Callable[[Principal], Principal]:
    """FastAPI dependency factory: ``Depends(require_role("agent.approver"))``.

    Must be layered on top of ``get_current_principal`` (which already ran
    as part of resolving the ``Principal`` argument) — this only adds the
    403 authorization check for callers who *are* authenticated but lack
    the required role.
    """

    def _check(principal: Principal = Depends(get_current_principal)) -> Principal:
        if role not in principal.roles:
            raise HTTPException(
                status_code=403,
                detail=f"Requires role '{role}'",
            )
        return principal

    return _check
