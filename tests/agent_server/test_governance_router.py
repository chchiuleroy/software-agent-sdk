"""Tests for GET /api/governance/status (read-only GUI status)."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

from fastapi.testclient import TestClient
from pydantic import SecretStr

from openhands.agent_server import governance_router as router_mod
from openhands.agent_server.api import create_app
from openhands.agent_server.config import Config
from openhands.agent_server.dependencies import get_conversation_service


URL = "/api/governance/status"


class _FakeClient:
    def __init__(self, result=None, delay: float = 0.0):
        self.result = result or {
            "reachable": True,
            "credentials_ok": True,
            "error": None,
        }
        self.delay = delay
        self.calls = 0

    async def check_health(self):
        self.calls += 1
        await asyncio.sleep(self.delay)
        return self.result


def _client(config: Config, governance_client) -> TestClient:
    app = create_app(config)
    app.dependency_overrides[get_conversation_service] = lambda: SimpleNamespace(
        governance_client=governance_client
    )
    return TestClient(app)


def _team_config(**overrides) -> Config:
    return Config(governance_deployment_mode="team", **overrides)


def test_personal_mode_reports_personal_and_never_probes():
    fake = _FakeClient()
    body = _client(Config(), fake).get(URL).json()

    assert body == {
        "deployment_mode": "personal",
        "missing_settings": [],
        "central_api": None,
    }
    assert fake.calls == 0


def test_team_mode_healthy():
    body = _client(_team_config(), _FakeClient()).get(URL).json()

    assert body["deployment_mode"] == "team"
    assert body["central_api"]["reachable"] is True
    assert body["central_api"]["credentials_ok"] is True
    assert body["central_api"]["error"] is None


def test_team_mode_without_client_lists_missing_settings():
    # Why this matters: this is exactly the "silently hangs" configuration;
    # the GUI must be able to name what is missing.
    body = _client(_team_config(), None).get(URL).json()

    assert body["central_api"]["reachable"] is None
    assert "not configured" in body["central_api"]["error"]
    assert "OH_GOVERNANCE_CENTRAL_API_BASE_URL" in body["missing_settings"]
    assert "OH_GOVERNANCE_CLIENT_SECRET" in body["missing_settings"]


def test_team_mode_missing_settings_excludes_configured_ones():
    config = _team_config(governance_bridge_token=SecretStr("tok"))
    body = _client(config, None).get(URL).json()

    assert "OH_GOVERNANCE_BRIDGE_TOKEN" not in body["missing_settings"]
    # The value is never echoed.
    assert "tok" not in str(body)


def test_team_mode_failed_probe_is_passed_through():
    fake = _FakeClient(
        {
            "reachable": True,
            "credentials_ok": False,
            "error": "token request failed (HTTP 401)",
        }
    )
    body = _client(_team_config(), fake).get(URL).json()

    assert body["central_api"]["credentials_ok"] is False
    assert body["central_api"]["error"] == "token request failed (HTTP 401)"


def test_team_mode_hung_probe_times_out(monkeypatch):
    monkeypatch.setattr(router_mod, "_PROBE_TIMEOUT_SECONDS", 0.05)
    body = _client(_team_config(), _FakeClient(delay=5)).get(URL).json()

    assert body["central_api"]["reachable"] is False
    assert "timed out" in body["central_api"]["error"]


def test_status_requires_session_api_key_when_configured():
    # The status names which settings are missing; it must not be a public
    # endpoint on an authenticated server.
    config = _team_config(session_api_keys=["k1"])
    client = _client(config, _FakeClient())

    assert client.get(URL).status_code == 401
    assert client.get(URL, headers={"X-Session-API-Key": "k1"}).status_code == 200
