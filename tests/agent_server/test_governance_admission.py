"""The agent-server side of the admission list: fetching and keeping it fresh, the
config flag, and the ConversationService lifecycle.

Nothing consults the list yet (the gates are the next step); this tests that the list
is fetched, understood or ignored, kept fresh and dropped, and that the flag turns it
on only in team mode. The module state is process-wide, so every test resets it.
"""

import asyncio
import time
from unittest.mock import AsyncMock, MagicMock

import pytest
from pydantic import SecretStr

from openhands.agent_server import governance_admission as refresher
from openhands.agent_server.config import Config
from openhands.agent_server.conversation_service import ConversationService
from openhands.agent_server.governance_client import (
    GovernancePermanentError,
    GovernanceTransientError,
)
from openhands.sdk.security import roy_admission as admission


@pytest.fixture(autouse=True)
def _reset_state():
    admission.reset()
    yield
    admission.reset()


TOOL_A = "sha256:" + "a" * 64
TOOL_B = "sha256:" + "b" * 64
SERVER = "sha256:" + "1" * 64
SKILL = "sha256:" + "2" * 64
PLUGIN = "sha256:" + "3" * 64


def _answer(**overrides):
    base = {
        "department_id": "d1",
        "items": [
            {
                "kind": "mcp_server",
                "fingerprint": SERVER,
                "tool_fingerprints": [TOOL_A, TOOL_B],
            },
            {"kind": "skill", "fingerprint": SKILL, "tool_fingerprints": []},
            {"kind": "plugin", "fingerprint": PLUGIN, "tool_fingerprints": []},
        ],
        "revision": "rev1",
        "max_age_seconds": 60,
    }
    base.update(overrides)
    return base


def _client(answer=None, error=None):
    client = MagicMock()
    client.admitted_items = AsyncMock(
        return_value=answer if answer is not None else _answer(), side_effect=error
    )
    return client


# --- one refresh -------------------------------------------------------------


async def test_a_good_answer_becomes_the_current_snapshot_kind_by_kind():
    admission.set_enforcing(True)
    assert await refresher.refresh_once(_client()) is True
    snapshot = admission.get_snapshot()
    assert snapshot is not None
    assert snapshot.mcp_tool_fingerprints == frozenset({TOOL_A, TOOL_B})
    assert snapshot.skill_fingerprints == frozenset({SKILL})
    assert snapshot.plugin_fingerprints == frozenset({PLUGIN})
    assert snapshot.revision == "rev1" and snapshot.max_age_seconds == 60.0
    # an MCP server's own fingerprint is not a tool: only its tools are admitted
    assert admission.is_mcp_tool_admitted(TOOL_A) is True
    assert admission.is_mcp_tool_admitted(SERVER) is False
    assert admission.is_skill_admitted(SKILL) is True
    assert admission.is_skill_admitted(TOOL_A) is False


async def test_an_item_of_a_kind_this_code_does_not_know_admits_nothing():
    # Why: a newer central must not make an older device admit something by accident.
    answer = _answer(
        items=[{"kind": "robot", "fingerprint": SKILL, "tool_fingerprints": [TOOL_A]}]
    )
    admission.set_enforcing(True)
    assert await refresher.refresh_once(_client(answer)) is True
    assert admission.is_mcp_tool_admitted(TOOL_A) is False
    assert admission.is_skill_admitted(SKILL) is False


@pytest.mark.parametrize(
    "bad",
    [
        {"items": "everything"},
        {"items": [1, 2]},
        {"items": [{"kind": "skill"}]},
        {
            "items": [
                {"kind": "skill", "fingerprint": "not-a-hash", "tool_fingerprints": []}
            ]
        },
        {"items": [{"kind": "skill", "fingerprint": SKILL, "tool_fingerprints": "x"}]},
        {
            "items": [
                {"kind": "mcp_server", "fingerprint": SERVER, "tool_fingerprints": [5]}
            ]
        },
        {"max_age_seconds": 0},
        {"max_age_seconds": -5},
        {"max_age_seconds": True},
        {"max_age_seconds": "60"},
        {"revision": None},
    ],
)
async def test_a_malformed_answer_is_ignored_not_trusted(bad):
    # Why: a half-understood answer must not become a snapshot. A zero or boolean max
    # age would otherwise mean "never expires", and a half-read item list could admit
    # more than central said.
    admission.set_enforcing(True)
    assert await refresher.refresh_once(_client(_answer(**bad))) is False
    assert admission.get_snapshot() is None


@pytest.mark.parametrize(
    "error",
    [
        GovernanceTransientError("down", error_code=None, status_code=None),
        GovernancePermanentError("nope", error_code="x", status_code=403),
    ],
)
async def test_a_failed_refresh_keeps_the_old_list_to_age_out(error):
    # Why: the failed call must neither raise into the loop nor wipe or extend the old
    # list; it simply ages out.
    admission.set_enforcing(True)
    await refresher.refresh_once(_client())
    before = admission.get_snapshot()
    assert await refresher.refresh_once(_client(error=error)) is False
    assert admission.get_snapshot() is before


async def test_a_later_answer_replaces_the_list_so_a_revocation_lands():
    admission.set_enforcing(True)
    await refresher.refresh_once(_client())
    assert admission.is_skill_admitted(SKILL) is True
    await refresher.refresh_once(_client(_answer(items=[])))
    assert admission.is_skill_admitted(SKILL) is False


# --- start / stop ---------------------------------------------------------------


async def _eventually(predicate, timeout=2.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        await asyncio.sleep(0.01)
    raise AssertionError("condition not reached")


async def test_start_turns_enforcement_on_and_fetches_then_stop_turns_it_off():
    refresher.start(_client())
    try:
        assert admission.is_enforcing() is True
        await _eventually(lambda: admission.get_snapshot() is not None)
    finally:
        await refresher.stop()
    assert admission.is_enforcing() is False
    assert admission.get_snapshot() is None


async def test_holds_are_counted_so_one_stop_does_not_switch_it_off_for_the_other():
    # Why: more than one ConversationService can come and go in a process; the first
    # to leave must not strip enforcement from the one still running.
    client = _client()
    refresher.start(client)
    refresher.start(client)
    await _eventually(lambda: admission.get_snapshot() is not None)
    await refresher.stop()
    assert admission.is_enforcing() is True
    await refresher.stop()
    assert admission.is_enforcing() is False


# --- config flag and service lifecycle ---------------------------------------------


def test_enforcement_is_off_by_default():
    # Why: there is no grace period, so it must be a deliberate step taken after the
    # items already in use have been approved.
    assert Config().governance_enforce_admission is False


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
        _team_config(tmp_path, governance_enforce_admission=True)
    )
    off = ConversationService.get_instance(_team_config(tmp_path))
    assert on.governance_enforce_admission is True
    assert off.governance_enforce_admission is False


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
        governance_client=AsyncMock(),
        governance_enforce_admission=flag,
    )
    async with service:
        assert bool(started) is expected_started
    assert bool(stopped) is expected_started
