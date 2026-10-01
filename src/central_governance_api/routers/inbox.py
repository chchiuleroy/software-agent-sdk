"""Browser approvals inbox: a static page that lists the requests an approver
may decide and sends the decision.

Why a page served by this API rather than a feature of the desktop app: the
approver is a different person from the requester and need not run the desktop
app; the page works unchanged whether this service runs on localhost or on a
shared server; being same-origin it needs no CORS for the API calls.

The page logs in with Authorization Code + PKCE against the Keycloak realm
(``Settings.inbox_oidc_client_id``), keeps the access token in memory only,
and calls the existing ``GET /api/v1/approvals/pending`` and
``POST /api/v1/approvals/{id}/decide``. Everything here is public static
content: authorization is entirely the bearer token on those API calls.

Request content (commands, paths, the agent's own summary) is untrusted, so
the page renders it with ``textContent`` only, and the CSP below forbids
inline scripts/styles and any other script origin as a second line of defence.
"""

from __future__ import annotations

from functools import cache
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, Response

from central_governance_api.config import Settings, get_settings_dependency


router = APIRouter(prefix="/inbox", tags=["inbox"])

_STATIC_DIR = Path(__file__).resolve().parent.parent / "inbox_static"


@cache
def _read_static(name: str) -> str:
    return (_STATIC_DIR / name).read_text(encoding="utf-8")


def _issuer_origin(issuer: str) -> str | None:
    """``scheme://host[:port]`` of the issuer, or None if it is not http(s):
    the page must be allowed to call the IdP (discovery, token endpoint) and
    nothing else outside its own origin."""
    parts = urlsplit(issuer)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        return None
    return f"{parts.scheme}://{parts.netloc}"


def _security_headers(settings: Settings) -> dict[str, str]:
    connect = ["'self'"]
    origin = _issuer_origin(settings.oidc_issuer)
    if origin:
        connect.append(origin)
    csp = "; ".join(
        [
            "default-src 'none'",
            "script-src 'self'",
            "style-src 'self'",
            f"connect-src {' '.join(connect)}",
            "img-src 'self'",
            "base-uri 'none'",
            "form-action 'none'",
            "frame-ancestors 'none'",
        ]
    )
    return {
        "Content-Security-Policy": csp,
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Cross-Origin-Opener-Policy": "same-origin",
        # The page and its assets are tiny; never let a stale copy of the
        # script that handles tokens be served from a cache.
        "Cache-Control": "no-store",
    }


def _enabled(
    settings: Settings = Depends(get_settings_dependency),
) -> Settings:
    if not settings.inbox_oidc_client_id:
        raise HTTPException(status_code=404)
    return settings


@router.get("", response_class=HTMLResponse)
async def inbox_page(settings: Settings = Depends(_enabled)) -> Response:
    return HTMLResponse(_read_static("index.html"), headers=_security_headers(settings))


@router.get("/inbox.js")
async def inbox_script(settings: Settings = Depends(_enabled)) -> Response:
    return Response(
        _read_static("inbox.js"),
        media_type="text/javascript",
        headers=_security_headers(settings),
    )


@router.get("/inbox.css")
async def inbox_style(settings: Settings = Depends(_enabled)) -> Response:
    return Response(
        _read_static("inbox.css"),
        media_type="text/css",
        headers=_security_headers(settings),
    )


@router.get("/config.json")
async def inbox_config(settings: Settings = Depends(_enabled)) -> Response:
    # Both values are public by nature (a public client id and the issuer URL).
    return JSONResponse(
        {
            "issuer": settings.oidc_issuer,
            "client_id": settings.inbox_oidc_client_id,
        },
        headers=_security_headers(settings),
    )
