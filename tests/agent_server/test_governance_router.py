"""Tests for GET /api/governance/status (read-only GUI status) and
GET /api/governance/attention (conversations parked in NEEDS_ATTENTION)."""

from __future__ import annotations

import asyncio
import uuid
from types import SimpleNamespace

from fastapi.testclient import TestClient
from pydantic import SecretStr

from openhands.agent_server import governance_router as router_mod
from openhands.agent_server.api import create_app
from openhands.agent_server.config import Config
from openhands.agent_server.dependencies import get_conversation_service
from openhands.agent_server.governance_outbox import (
    OUTBOX_FILENAME,
    NeedsAttentionReason,
    OutboxRecord,
    mark_needs_attention,
)


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


# ----------------------------- GET /attention -----------------------------

ATTENTION_URL = "/api/governance/attention"


def _attention_client(config: Config, conversations_dir) -> TestClient:
    app = create_app(config)
    app.dependency_overrides[get_conversation_service] = lambda: SimpleNamespace(
        conversations_dir=conversations_dir, governance_client=None
    )
    return TestClient(app)


def _park_a_conversation(conversations_dir) -> str:
    directory = conversations_dir / uuid.uuid4().hex
    directory.mkdir()
    record = OutboxRecord(
        request_id="req-1",
        conversation_id=directory.name,
        action_event_id="event-1",
        tool_call_id="call-1",
        tool_name="bash",
        action_type="terminal_command",
        policy_revision="v1",
        action_summary="echo hi",
        action_payload={"command": "echo hi"},
        digest_salt=None,
        action_payload_digest="deadbeef",
        execution_commitment="commitment-hash",
        origin_device_id="device-1",
        central_approval_id="approval-1",
    )
    mark_needs_attention(
        record, NeedsAttentionReason.CLAIM_FAILED, error_code="not_found"
    )
    (directory / OUTBOX_FILENAME).write_text(record.to_json(), encoding="utf-8")
    return str(uuid.UUID(hex=directory.name))


def test_attention_lists_parked_conversations_in_team_mode(tmp_path):
    conversation_id = _park_a_conversation(tmp_path)

    body = _attention_client(_team_config(), tmp_path).get(ATTENTION_URL).json()

    assert body == [
        {
            "conversation_id": conversation_id,
            "reason": "claim_failed",
            "last_error_code": "not_found",
            "central_approval_id": "approval-1",
            "request_id": "req-1",
            "attempt_count": 1,
            "last_attempt_at": body[0]["last_attempt_at"],
            "allowed_actions": ["retry", "abandon", "dismiss"],
        }
    ]
    assert body[0]["last_attempt_at"] is not None


def test_attention_is_empty_when_nothing_is_parked(tmp_path):
    assert _attention_client(_team_config(), tmp_path).get(ATTENTION_URL).json() == []


def test_attention_is_empty_in_personal_mode_even_if_a_file_exists(tmp_path):
    # Personal mode has no outbox; a leftover file must not be reported as work.
    _park_a_conversation(tmp_path)

    assert _attention_client(Config(), tmp_path).get(ATTENTION_URL).json() == []


def test_attention_requires_session_api_key_when_configured(tmp_path):
    # It names conversations and approval ids, so it is not a public endpoint.
    _park_a_conversation(tmp_path)
    client = _attention_client(_team_config(session_api_keys=["k1"]), tmp_path)

    assert client.get(ATTENTION_URL).status_code == 401
    ok = client.get(ATTENTION_URL, headers={"X-Session-API-Key": "k1"})
    assert ok.status_code == 200
    assert len(ok.json()) == 1
