"""The agent-server side of department tool permissions: fetching and keeping
the list fresh, the config flag, and the ConversationService lifecycle.

The refusal inside EventService is tested next to its siblings in
test_event_service.py. The module state is process-wide, so every test resets
it.
"""

import asyncio
import time
from unittest.mock import AsyncMock, MagicMock

import pytest
from pydantic import SecretStr

from openhands.agent_server import governance_tool_permissions as refresher
from openhands.agent_server.config import Config
from openhands.agent_server.conversation_service import ConversationService
from openhands.agent_server.governance_client import (
    GovernancePermanentError,
    GovernanceTransientError,
)
from openhands.sdk.security import roy_tool_permissions as permissions


@pytest.fixture(autouse=True)
def _reset_state():
    permissions.reset()
    yield
    permissions.reset()


def _answer(**overrides):
    base = {
        "department_id": "d1",
        "department_name": "Finance",
        "tools": ["file_editor", "grep"],
        "revision": "abc123",
        "max_age_seconds": 600,
    }
    base.update(overrides)
    return base


def _client(answer=None, error=None):
    client = MagicMock()
    client.tool_permissions = AsyncMock(
        return_value=answer if answer is not None else _answer(), side_effect=error
    )
    return client


# --- one refresh -------------------------------------------------------------


async def test_a_good_answer_becomes_the_current_snapshot():
    permissions.set_enforcing(True)
    assert await refresher.refresh_once(_client()) is True
    snapshot = permissions.get_snapshot()
    assert snapshot is not None
    assert snapshot.tools == frozenset({"file_editor", "grep"})
    assert snapshot.revision == "abc123"
    assert snapshot.max_age_seconds == 600.0
    assert permissions.is_permitted("grep") is True
    assert permissions.is_permitted("terminal") is False


@pytest.mark.parametrize(
    "bad",
    [
        {"tools": "terminal"},
        {"tools": [1, 2]},
        {"max_age_seconds": 0},
        {"max_age_seconds": -5},
        {"max_age_seconds": True},
        {"max_age_seconds": "600"},
        {"revision": None},
    ],
)
async def test_a_malformed_answer_is_ignored_not_trusted(bad):
    # Why: a half-understood answer must not become a snapshot. In particular
    # a zero or boolean max age would otherwise mean "never expires".
    permissions.set_enforcing(True)
    assert await refresher.refresh_once(_client(_answer(**bad))) is False
    assert permissions.get_snapshot() is None


@pytest.mark.parametrize(
    "error",
    [
        GovernanceTransientError("down", error_code=None, status_code=None),
        GovernancePermanentError("nope", error_code="x", status_code=403),
    ],
)
async def test_a_failed_refresh_keeps_the_old_list_to_age_out(error):
    # Why: the failed call must neither raise into the loop nor wipe or
    # extend the old list; it simply ages out.
    permissions.set_enforcing(True)
    await refresher.refresh_once(_client())
    before = permissions.get_snapshot()
    assert await refresher.refresh_once(_client(error=error)) is False
    assert permissions.get_snapshot() is before


async def test_a_later_answer_replaces_the_list_so_a_revocation_lands():
    permissions.set_enforcing(True)
    await refresher.refresh_once(_client())
    assert permissions.is_permitted("grep") is True
    await refresher.refresh_once(_client(_answer(tools=["file_editor"])))
    assert permissions.is_permitted("grep") is False


# --- start / stop ---------------------------------------------------------------


async def _eventually(predicate, timeout=2.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        await asyncio.sleep(0.01)
    raise AssertionError("condition not reached")


async def test_start_turns_enforcement_on_and_fetches_then_stop_turns_it_off():
    client = _client()
    refresher.start(client)
    try:
        assert permissions.is_enforcing() is True
        await _eventually(lambda: permissions.get_snapshot() is not None)
    finally:
        await refresher.stop()
    assert permissions.is_enforcing() is False
    assert permissions.get_snapshot() is None


async def test_holds_are_counted_so_one_stop_does_not_switch_it_off_for_the_other():
    # Why: more than one ConversationService can come and go in a process (the
    # personal-to-team switch builds a new one); the first to leave must not
    # strip enforcement from the one still running.
    client = _client()
    refresher.start(client)
    refresher.start(client)
    await _eventually(lambda: permissions.get_snapshot() is not None)
    await refresher.stop()
    assert permissions.is_enforcing() is True
    await refresher.stop()
    assert permissions.is_enforcing() is False


# --- config flag and service lifecycle ---------------------------------------------


def test_enforcement_is_off_by_default():
    # Why: a team server whose service account has no department yet must not
    # be locked out on upgrade.
    assert Config().governance_enforce_tool_permissions is False


def _team_config(tmp_path, **overrides):
    return Config(
        conversations_path=tmp_path,
        governance_deployment_mode="team",
        governance_central_api_base_url="https://central.example",
        governance_central_api_token_url="https://idp.example/token",
        governance_client_id="agent-server",
        governance_client_secret=SecretStr("s3cr3t"),
        governance_origin_device_id="device-1",
        **overrides,
    )


def test_the_service_snapshots_the_flag_from_config(tmp_path):
    on = ConversationService.get_instance(
        _team_config(tmp_path, governance_enforce_tool_permissions=True)
    )
    off = ConversationService.get_instance(_team_config(tmp_path))
    assert on.governance_enforce_tool_permissions is True
    assert off.governance_enforce_tool_permissions is False


@pytest.mark.parametrize(
    "mode,flag,expected_started",
    [
        ("team", True, True),
        ("team", False, False),
        ("personal", True, False),
    ],
)
async def test_the_service_starts_the_refresher_only_in_team_mode_with_the_flag(
    tmp_path, monkeypatch, mode, flag, expected_started
):
    started: list = []
    stopped: list = []
    monkeypatch.setattr(refresher, "start", lambda client: started.append(client))

    async def _stop():
        stopped.append(True)

    monkeypatch.setattr(refresher, "stop", _stop)
    service = ConversationService(
        conversations_dir=tmp_path,
        governance_deployment_mode=mode,
        governance_client=MagicMock(aclose=AsyncMock()),
        governance_enforce_tool_permissions=flag,
    )
    async with service:
        assert bool(started) is expected_started
    assert bool(stopped) is expected_started
