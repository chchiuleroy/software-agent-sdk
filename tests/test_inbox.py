"""The browser approvals inbox: gating, security headers, and a guard that the
script never builds HTML from request content (which is attacker-influenced:
the agent chooses its own command line and summary)."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from central_governance_api.config import Settings
from central_governance_api.main import create_app

from .conftest import AUDIENCE, ISSUER, JWKS_URL


_PATHS = ["/inbox", "/inbox/inbox.js", "/inbox/inbox.css", "/inbox/config.json"]
_STATIC = (
    Path(__file__).resolve().parent.parent
    / "src"
    / "central_governance_api"
    / "inbox_static"
)


def _client(client_id: str | None) -> AsyncClient:
    settings = Settings(
        oidc_issuer=ISSUER,
        oidc_jwks_url=JWKS_URL,
        oidc_audience=AUDIENCE,
        inbox_oidc_client_id=client_id,
    )
    return AsyncClient(
        transport=ASGITransport(app=create_app(settings)), base_url="http://test"
    )


@pytest.mark.parametrize("path", _PATHS)
async def test_inbox_is_disabled_until_a_client_id_is_configured(path):
    async with _client(None) as client:
        assert (await client.get(path)).status_code == 404


async def test_disabled_inbox_is_indistinguishable_from_an_unknown_path():
    # Deliberately no inbox headers on the disabled 404: it must not reveal
    # that the feature exists, so it has to look like any other missing route.
    async with _client(None) as client:
        disabled = await client.get("/inbox")
        unknown = await client.get("/no-such-route")
    assert disabled.status_code == unknown.status_code == 404
    assert disabled.content == unknown.content
    assert dict(disabled.headers) == dict(unknown.headers)


@pytest.mark.parametrize("path", _PATHS)
async def test_enabled_inbox_serves_every_path_with_hardening_headers(path):
    async with _client("approvals-inbox") as client:
        resp = await client.get(path)
    assert resp.status_code == 200
    csp = resp.headers["content-security-policy"]
    # Scripts and styles only from this origin; nothing inline, so an
    # injected <script> or style="" is inert even if escaping were bypassed.
    assert "script-src 'self'" in csp
    assert "style-src 'self'" in csp
    assert "unsafe-inline" not in csp
    assert "unsafe-eval" not in csp
    assert "default-src 'none'" in csp
    assert "frame-ancestors 'none'" in csp
    # The token endpoint lives on the issuer's origin; nothing else may be called.
    assert "connect-src 'self' https://keycloak.example.invalid" in csp
    assert resp.headers["x-content-type-options"] == "nosniff"
    assert resp.headers["x-frame-options"] == "DENY"
    assert resp.headers["referrer-policy"] == "no-referrer"
    assert resp.headers["cache-control"] == "no-store"


async def test_content_types_and_config():
    async with _client("approvals-inbox") as client:
        page = await client.get("/inbox")
        script = await client.get("/inbox/inbox.js")
        style = await client.get("/inbox/inbox.css")
        config = await client.get("/inbox/config.json")
    assert page.headers["content-type"].startswith("text/html")
    # Browsers refuse module scripts served with a non-JavaScript type.
    assert script.headers["content-type"].startswith("text/javascript")
    assert style.headers["content-type"].startswith("text/css")
    assert config.json() == {"issuer": ISSUER, "client_id": "approvals-inbox"}


def test_page_has_no_inline_script_or_handler():
    html = (_STATIC / "index.html").read_text(encoding="utf-8")
    assert not re.search(r"<script(?![^>]*\bsrc=)", html)
    assert not re.search(r"\son[a-z]+\s*=", html)
    assert "style=" not in html


# Each of these turns a string into markup or code. Request content must only
# ever reach the page through textContent / createTextNode.
_FORBIDDEN_JS = [
    "innerHTML",
    "outerHTML",
    "insertAdjacentHTML",
    "document.write",
    "createContextualFragment",
    "srcdoc",
    "eval(",
    "new Function",
    "localStorage",  # the token must not outlive the tab
]


@pytest.mark.parametrize("needle", _FORBIDDEN_JS)
def test_script_never_uses_an_html_or_code_injection_api(needle):
    source = _STATIC.joinpath("inbox.js").read_text(encoding="utf-8")
    # Strip // comments: the header comment names some of these on purpose.
    code = re.sub(r"//[^\n]*", "", source)
    assert needle not in code
