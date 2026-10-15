"""Registering this server's ``origin_device_id`` with central at startup.

The client call, the answer-to-state table, the retry loop, the service
lifecycle and the status endpoint. The real central (binding enforced, a real
409) is exercised by governance/e2e/e2e_device_autoregister.py.
"""

import asyncio
from types import SimpleNamespace
from typing import Literal
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from openhands.agent_server import governance_device_registration as registration
from openhands.agent_server.api import create_app
from openhands.agent_server.config import Config
from openhands.agent_server.conversation_service import ConversationService
from openhands.agent_server.dependencies import get_conversation_service
from openhands.agent_server.governance_client import (
    GovernanceClient,
    GovernancePermanentError,
    GovernanceTransientError,
)


def _permanent(code, status=409):
    return GovernancePermanentError("m", error_code=code, status_code=status)


def _client(*outcomes):
    """A fake client whose register_device returns/raises each outcome in turn."""
    client = MagicMock()
    client.register_device = AsyncMock(side_effect=list(outcomes))
    return client


# --- the client call ---


async def test_register_device_sends_the_id_and_a_fresh_idempotency_key_each_attempt():
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == "http://idp.example/token":
            return httpx.Response(200, json={"access_token": "t", "expires_in": 3600})
        seen.append(request)
        return httpx.Response(201, json={"id": "r1", "device_id": "device-1"})

    client = GovernanceClient(
        base_url="http://central.example",
        token_url="http://idp.example/token",
        client_id="c",
        client_secret="s",
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    status = registration.DeviceRegistrationStatus()
    await registration.register_once(client, "device-1", status)
    await registration.register_once(client, "device-1", status)

    request = seen[0]
    assert str(request.url) == "http://central.example/api/v1/devices/register"
    assert request.read() == b'{"device_id":"device-1"}'
    # Why: central replays a stored answer for a repeated key before it looks at
    # the denylist, so a fixed key would report a revoked device as registered
    # after a restart (found by e2e_device_autoregister.py).
    keys = [r.headers["Idempotency-Key"] for r in seen]
    assert len(keys) == 2 and keys[0] != keys[1]
    assert all(k.startswith("device-register-") for k in keys)
    await client.aclose()


# --- one attempt: what each answer means ---


async def test_a_new_registration_is_registered():
    status = registration.DeviceRegistrationStatus()
    assert await registration.register_once(_client({}), "d", status) is True
    assert status == registration.DeviceRegistrationStatus("registered", None)


async def test_already_registered_counts_as_registered_and_is_not_retried():
    # Why: this is the answer every restart gets. Treating it as an error would
    # report a healthy device as broken after the first restart.
    client = _client(_permanent("device_already_registered"))
    status = registration.DeviceRegistrationStatus()
    assert await registration.register_once(client, "d", status) is True
    assert status.state == "registered"
    assert client.register_device.await_count == 1


async def test_a_revoked_device_stays_revoked_and_is_not_retried():
    # Why: restarting the server must not undo a revocation. No retry, and no
    # state that could be mistaken for a working registration.
    client = _client(_permanent("device_revoked"))
    status = registration.DeviceRegistrationStatus()
    assert await registration.register_once(client, "d", status) is True
    assert status == registration.DeviceRegistrationStatus("revoked", "device_revoked")
    assert client.register_device.await_count == 1


@pytest.mark.parametrize(
    ("error", "expected_code"),
    [
        (_permanent("device_quota_exceeded", 429), "device_quota_exceeded"),
        (_permanent("authorization_denied", 403), "authorization_denied"),
        (_permanent(None, 401), "http_401"),
    ],
)
async def test_other_permanent_answers_fail_without_retry(error, expected_code):
    # Why: these need a configuration change and a restart; retrying forever
    # would only hammer central and hide the reason.
    client = _client(error)
    status = registration.DeviceRegistrationStatus()
    assert await registration.register_once(client, "d", status) is True
    assert status == registration.DeviceRegistrationStatus("failed", expected_code)
    assert client.register_device.await_count == 1


async def test_a_transient_failure_stays_pending_and_asks_for_a_retry():
    client = _client(GovernanceTransientError("m", error_code=None, status_code=503))
    status = registration.DeviceRegistrationStatus()
    assert await registration.register_once(client, "d", status) is False
    assert status.state == "pending"
    assert status.error_code == "GovernanceTransientError"


@pytest.mark.parametrize("status", [408, 429])
async def test_a_rate_limit_that_is_not_one_of_centrals_answers_is_retried(status):
    # Why: the IdP's token endpoint answers 429/408 as a "permanent" error with no
    # error_code; a short rate limit must not end the registration for good.
    client = _client(_permanent(None, status))
    result = registration.DeviceRegistrationStatus()
    assert await registration.register_once(client, "d", result) is False
    assert result.state == "pending"
    assert result.error_code == f"http_{status}"


async def test_a_coded_429_from_central_is_still_final():
    # Why: central's quota answer is also a 429; it must not be mistaken for a
    # rate limit and retried for ever.
    client = _client(_permanent("device_quota_exceeded", 429))
    result = registration.DeviceRegistrationStatus()
    assert await registration.register_once(client, "d", result) is True
    assert result.state == "failed"


async def test_an_unexpected_exception_ends_in_failed_not_in_a_dead_task():
    # Why: an escaped exception would kill the background task and leave the
    # state "pending" for ever, which reads as "still trying".
    client = _client(RuntimeError("secret detail must not be kept"))
    status = registration.DeviceRegistrationStatus()
    assert await registration.register_once(client, "d", status) is True
    assert status == registration.DeviceRegistrationStatus("failed", "RuntimeError")


# --- the retry loop ---


async def test_the_loop_retries_with_a_growing_capped_delay_until_it_works(monkeypatch):
    transient = GovernanceTransientError("m", error_code=None, status_code=503)
    client = _client(*([transient] * 6), {})
    delays = []

    async def fake_sleep(seconds):
        delays.append(seconds)

    monkeypatch.setattr(registration, "asyncio", SimpleNamespace(sleep=fake_sleep))
    status = registration.DeviceRegistrationStatus()
    await registration.run(client, "d", status)

    assert status.state == "registered"
    assert client.register_device.await_count == 7
    assert delays == [5.0, 10.0, 20.0, 40.0, 60.0, 60.0]


async def test_the_loop_stops_at_a_final_answer(monkeypatch):
    client = _client(_permanent("device_revoked"))
    sleep = AsyncMock()
    monkeypatch.setattr(registration, "asyncio", SimpleNamespace(sleep=sleep))
    status = registration.DeviceRegistrationStatus()
    await registration.run(client, "d", status)
    assert client.register_device.await_count == 1
    sleep.assert_not_awaited()


# --- service lifecycle ---


def _fake_client(**register_kwargs) -> MagicMock:
    client = MagicMock()
    client.aclose = AsyncMock()
    client.register_device = AsyncMock(**register_kwargs)
    return client


def _service(
    tmp_path,
    client: MagicMock | None,
    *,
    mode: Literal["personal", "team"] = "team",
    device_id: str = "device-1",
) -> ConversationService:
    return ConversationService(
        conversations_dir=tmp_path,
        governance_deployment_mode=mode,
        governance_client=client,
        governance_origin_device_id=device_id,
    )


async def test_a_team_service_registers_its_device_at_startup(tmp_path):
    client = _fake_client(return_value={})
    service = _service(tmp_path, client)
    async with service:
        assert service._device_registration_task is not None
        await service._device_registration_task
        assert service.device_registration.state == "registered"
    client.register_device.assert_awaited_once()
    assert client.register_device.await_args.args == ("device-1",)


@pytest.mark.parametrize(
    ("kwargs", "expected_state"),
    [
        ({"device_id": registration.UNSET_DEVICE_ID}, "not_configured"),
        ({"mode": "personal"}, "pending"),
    ],
    ids=["placeholder-id", "personal-mode"],
)
async def test_nothing_is_registered_when_there_is_nothing_to_register(
    tmp_path, kwargs, expected_state
):
    # Why: the placeholder is not an identity; registering it would turn it into
    # a legitimate-looking device for every unconfigured server.
    client = _fake_client(return_value={})
    service = _service(tmp_path, client, **kwargs)
    async with service:
        assert service._device_registration_task is None
        assert service.device_registration.state == expected_state
    client.register_device.assert_not_awaited()


async def test_a_service_without_a_client_registers_nothing(tmp_path):
    service = _service(tmp_path, None)
    async with service:
        assert service._device_registration_task is None


async def test_leaving_the_service_stops_a_registration_that_is_still_retrying(
    tmp_path,
):
    # Why: a retry loop that outlives its service leaks a task per restart of the
    # service (the personal-to-team switch builds a new one).
    client = _fake_client(
        side_effect=GovernanceTransientError("m", error_code=None, status_code=503)
    )
    service = _service(tmp_path, client)
    async with service:
        task = service._device_registration_task
        assert task is not None
        await asyncio.sleep(0.05)
        assert not task.done()
    assert task.cancelled()
    assert service._device_registration_task is None


def test_the_service_takes_the_device_id_from_config_and_falls_back_to_the_placeholder(
    tmp_path,
):
    def config(**overrides):
        return Config(
            conversations_path=tmp_path,
            governance_deployment_mode="team",
            governance_central_api_base_url="https://central.example",
            governance_central_api_token_url="https://idp.example/token",
            governance_client_id="agent-server",
            governance_client_secret=SecretStr("s3cr3t"),
            **overrides,
        )

    assert (
        ConversationService.get_instance(
            config(governance_origin_device_id="device-1")
        ).governance_origin_device_id
        == "device-1"
    )
    assert (
        ConversationService.get_instance(config()).governance_origin_device_id
        == registration.UNSET_DEVICE_ID
    )


# --- status endpoint ---


class _Probe:
    async def check_health(self):
        return {"reachable": True, "credentials_ok": True, "error": None}


def _status(config, **service_attrs):
    app = create_app(config)
    app.dependency_overrides[get_conversation_service] = lambda: SimpleNamespace(
        **service_attrs
    )
    return TestClient(app).get("/api/governance/status").json()


@pytest.mark.parametrize(
    "state, code",
    [("registered", None), ("revoked", "device_revoked"), ("failed", "http_401")],
)
def test_status_shows_how_the_registration_went(state, code):
    # Why: a revoked or refused id is otherwise visible only as 403s later.
    body = _status(
        Config(governance_deployment_mode="team"),
        governance_client=_Probe(),
        device_registration=registration.DeviceRegistrationStatus(state, code),
    )
    assert body["device_registration"] == {"state": state, "error_code": code}


def test_status_has_no_registration_in_personal_mode():
    body = _status(Config(), governance_client=None)
    assert body["device_registration"] is None
