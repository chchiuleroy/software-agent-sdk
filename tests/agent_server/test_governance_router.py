"""Tests for GET /api/governance/status (read-only GUI status) and
GET /api/governance/attention (conversations parked in NEEDS_ATTENTION)."""

from __future__ import annotations

import asyncio
import uuid
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from openhands.agent_server import governance_router as router_mod
from openhands.agent_server.api import create_app
from openhands.agent_server.config import Config
from openhands.agent_server.dependencies import get_conversation_service
from openhands.agent_server.governance_attention import ResolveError, ResolveResponse
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
        "device_registration": None,
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

    assert len(body) == 1
    # The time is "when it was parked": present, but not a fixed value.
    assert body[0].pop("last_attempt_at") is not None
    assert body == [
        {
            "conversation_id": conversation_id,
            "reason": "claim_failed",
            "last_error_code": "not_found",
            "central_approval_id": "approval-1",
            "request_id": "req-1",
            "attempt_count": 1,
            "allowed_actions": ["retry", "abandon", "dismiss"],
            "allowed_outcomes": [],
        }
    ]


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


# ----------------------- POST /attention/{id}/resolve -----------------------

RESOLVE_URL = "/api/governance/attention/{}/resolve"


class _FakeEventService:
    def __init__(self, error: ResolveError | None = None):
        self.error = error
        self.outcomes: list = []
        self.calls: list[tuple[str, str, str | None, str]] = []

    async def resolve_needs_attention(
        self, action, *, expected_request_id, note, operator, outcome=None
    ):
        self.calls.append((action.value, expected_request_id, note, operator))
        self.outcomes.append(outcome)
        if self.error is not None:
            raise self.error
        return ResolveResponse(
            conversation_id=str(CONVERSATION_ID),
            action=action,
            request_id=expected_request_id,
            new_state="resolved_manually",
            central_step="not_applicable",
            conversation_still_waiting=False,
        )


CONVERSATION_ID = uuid.uuid4()


def _resolve_client(config: Config, event_service) -> tuple[TestClient, list]:
    """The router must go through ConversationService.resolve_needs_attention (which
    holds the conversation's lifecycle lock), not get_event_service() and then
    resolve on it: this stand-in has no get_event_service, so the old two-step
    flow fails these tests."""
    asked: list = []

    async def _resolve(
        conversation_id, action, *, expected_request_id, note, operator, outcome=None
    ):
        asked.append(conversation_id)
        if event_service is None:
            return None
        return await event_service.resolve_needs_attention(
            action,
            expected_request_id=expected_request_id,
            note=note,
            operator=operator,
            outcome=outcome,
        )

    app = create_app(config)
    app.dependency_overrides[get_conversation_service] = lambda: SimpleNamespace(
        resolve_needs_attention=_resolve
    )
    return TestClient(app), asked


def _dismiss(**overrides):
    body = {
        "action": "dismiss",
        "expected_request_id": "req-1",
        "note": "why",
        "operator": "ada",
    }
    body.update(overrides)
    return body


def test_resolve_passes_the_request_through_and_returns_the_outcome():
    service = _FakeEventService()
    client, asked = _resolve_client(_team_config(), service)

    response = client.post(RESOLVE_URL.format(CONVERSATION_ID), json=_dismiss())

    assert response.status_code == 200
    assert response.json() == {
        "conversation_id": str(CONVERSATION_ID),
        "action": "dismiss",
        "request_id": "req-1",
        "new_state": "resolved_manually",
        "central_step": "not_applicable",
        "conversation_still_waiting": False,
    }
    # the operator reaches the service as declared (stripped of padding)
    assert service.calls == [("dismiss", "req-1", "why", "ada")]
    assert asked == [CONVERSATION_ID]


def test_resolve_unknown_conversation_is_404():
    client, _ = _resolve_client(_team_config(), None)

    response = client.post(RESOLVE_URL.format(CONVERSATION_ID), json=_dismiss())

    assert response.status_code == 404
    assert response.json()["detail"]["error_code"] == "not_found"


@pytest.mark.parametrize(
    ("error_code", "status"),
    [
        ("not_found", 404),
        ("not_team_mode", 404),
        ("state_changed", 409),
        ("request_id_mismatch", 409),
        ("action_not_allowed", 409),
        ("retry_not_possible", 409),
        ("conversation_inactive", 409),
        ("unreadable_outbox", 409),
        # 424, not 5xx: the app blanks the body of every 5xx response
        ("central_failed", 424),
        ("central_client_unavailable", 424),
    ],
)
def test_resolve_error_codes_map_to_statuses(error_code, status):
    service = _FakeEventService(
        ResolveError(error_code, "explained", allowed_actions=["retry", "dismiss"])
    )
    client, _ = _resolve_client(_team_config(), service)

    response = client.post(RESOLVE_URL.format(CONVERSATION_ID), json=_dismiss())

    assert response.status_code == status
    detail = response.json()["detail"]
    assert detail["error_code"] == error_code
    assert detail["detail"] == "explained"
    assert detail["allowed_actions"] == ["retry", "dismiss"]


@pytest.mark.parametrize(
    "body",
    [
        _dismiss(note=None),  # dismiss needs a note
        _dismiss(note="   "),
        _dismiss(action="purge"),
        _dismiss(expected_request_id=""),
        {"action": "retry"},  # no expected_request_id
        {"action": "retry", "expected_request_id": "req-1"},  # no operator
        _dismiss(operator=""),
        _dismiss(operator="ada\nforged log line"),
    ],
)
def test_resolve_rejects_a_malformed_request_before_touching_anything(body):
    service = _FakeEventService()
    client, asked = _resolve_client(_team_config(), service)

    response = client.post(RESOLVE_URL.format(CONVERSATION_ID), json=body)

    assert response.status_code == 422
    assert service.calls == []
    assert asked == []


def test_resolve_rejects_a_conversation_id_that_is_not_a_uuid():
    client, asked = _resolve_client(_team_config(), _FakeEventService())

    assert client.post(RESOLVE_URL.format("nope"), json=_dismiss()).status_code == 422
    assert asked == []


def test_resolve_is_refused_outside_team_mode_without_looking_the_conversation_up():
    service = _FakeEventService()
    client, asked = _resolve_client(Config(), service)

    response = client.post(RESOLVE_URL.format(CONVERSATION_ID), json=_dismiss())

    assert response.status_code == 404
    assert response.json()["detail"]["error_code"] == "not_team_mode"
    assert asked == [] and service.calls == []


def test_resolve_requires_session_api_key_when_configured():
    # It can cancel approvals and reject actions, so it is the opposite of public.
    service = _FakeEventService()
    client, _ = _resolve_client(_team_config(session_api_keys=["k1"]), service)
    url = RESOLVE_URL.format(CONVERSATION_ID)

    assert client.post(url, json=_dismiss()).status_code == 401
    assert service.calls == []
    ok = client.post(url, json=_dismiss(), headers={"X-Session-API-Key": "k1"})
    assert ok.status_code == 200
