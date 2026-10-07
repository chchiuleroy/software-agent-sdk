"""Shared fixtures for the agent-server tests."""

from __future__ import annotations

import sys
from collections.abc import Iterator

import pytest


@pytest.fixture(autouse=True)
def _clear_team_mode_subagent_guard() -> Iterator[None]:
    """Switch the team-mode sub-agent guard back off after every test.

    ``create_app()`` and ``_build_initialized_config()`` switch the guard on by
    setting a process-wide default handler in ``openhands-tools`` and never undo
    it, so a test that builds a team-mode config would otherwise leak a
    refusing handler into every later test that runs in the same process. The
    reference count of holds on the guard is module state too.
    Looks at ``sys.modules`` first so tests that never touched it pay nothing.
    """
    yield
    if "openhands.agent_server.governance_subagents" in sys.modules:
        from openhands.agent_server import governance_subagents

        governance_subagents._holds = 0
    if "openhands.tools.task.manager" in sys.modules:
        from openhands.tools.task.manager import set_default_confirmation_handler

        set_default_confirmation_handler(None)
