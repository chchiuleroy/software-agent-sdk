"""Which conversations a (re)started agent-server picks up again by itself.

Before: only those whose saved status was RUNNING. A conversation with an open
governance record (the approval waits for a decision, or was accepted but not yet
claimed or run) was left unloaded after a restart, so its relay never ran and an
approved action sat there until somebody opened the conversation. Found by killing a
real agent-server process: governance/e2e/e2e_kill_restart.py (case K3).
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, patch
from uuid import UUID, uuid4

import pytest

from openhands.agent_server.conversation_service import ConversationService
from openhands.agent_server.governance_outbox import OUTBOX_FILENAME, OutboxState
from openhands.agent_server.models import StartConversationRequest
from openhands.sdk import LLM, Agent
from openhands.sdk.security.confirmation_policy import NeverConfirm
from openhands.sdk.workspace import LocalWorkspace


def _write_outbox(conversations_dir: Path, conversation_id: UUID, state: str) -> None:
    directory = conversations_dir / conversation_id.hex
    directory.mkdir(parents=True, exist_ok=True)
    (directory / OUTBOX_FILENAME).write_text(json.dumps({"state": state}))


def test_only_open_governance_records_are_listed(tmp_path):
    open_ids = {uuid4(), uuid4()}
    finished = uuid4()
    cases = [
        (next(iter(open_ids)), OutboxState.CREATED.value),
        (finished, OutboxState.RESULT_REPORTED.value),
    ]
    for conversation_id, state in cases:
        _write_outbox(tmp_path, conversation_id, state)
    other_open = [i for i in open_ids if i != cases[0][0]][0]
    _write_outbox(tmp_path, other_open, OutboxState.NEEDS_ATTENTION.value)
    # a record nobody can read, one with a state this code does not know, a
    # directory that is not a conversation, and a conversation with no record
    broken = uuid4()
    (tmp_path / broken.hex).mkdir()
    (tmp_path / broken.hex / OUTBOX_FILENAME).write_text("{not json")
    _write_outbox(tmp_path, uuid4(), "a_state_from_the_future")
    (tmp_path / "not-a-conversation").mkdir()
    (tmp_path / "not-a-conversation" / OUTBOX_FILENAME).write_text(
        json.dumps({"state": "created"})
    )
    (tmp_path / uuid4().hex).mkdir()

    service = ConversationService(conversations_dir=tmp_path)

    assert set(service._open_governance_outbox_ids_sync()) == open_ids


@pytest.mark.parametrize(
    "mode,state,expect_loaded",
    [
        ("team", OutboxState.CREATED.value, True),
        ("team", OutboxState.CLAIMED.value, True),
        ("team", OutboxState.EXECUTION_STARTED.value, True),
        ("team", OutboxState.RESULT_REPORTED.value, False),
        ("personal", OutboxState.CREATED.value, False),
    ],
)
@pytest.mark.asyncio
async def test_a_restart_loads_a_conversation_with_an_open_governance_record(
    tmp_path, mode, state, expect_loaded
):
    """Team mode only: a conversation that is idle on disk but whose governance record
    is open is loaded at startup (so its relay and decision wait run); a finished
    record, or personal mode, leaves it lazy as before."""
    conversations_dir = tmp_path / "conversations"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    request = StartConversationRequest(
        agent=Agent(llm=LLM(model="gpt-4o", usage_id="test-llm"), tools=[]),
        workspace=LocalWorkspace(working_dir=str(workspace_dir)),
        confirmation_policy=NeverConfirm(),
    )
    async with ConversationService(conversations_dir=conversations_dir) as first:
        info, _ = await first.start_conversation(request)
    _write_outbox(conversations_dir, info.id, state)

    loaded: list[UUID] = []

    async def record_load(self, conversation_id):
        loaded.append(conversation_id)
        return AsyncMock()

    with patch.object(ConversationService, "_get_or_load_event_service", record_load):
        async with ConversationService(
            conversations_dir=conversations_dir, governance_deployment_mode=mode
        ):
            pass

    assert (info.id in loaded) is expect_loaded
