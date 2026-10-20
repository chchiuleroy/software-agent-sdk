"""After a crash, an approved action is executed at most once.

Every other crash-recovery test in this package replaces ``LocalConversation`` with a
mock. These do not, on purpose: the guarantee lives in what a *real* restart finds on
disk (the persisted conversation status, the event log, the outbox record) and in how
``EventService.start()`` and ``run()`` treat it. Only the network is fake (the
``GovernanceClient``) and the agent's tool executor is wrapped in a counting spy; the
LLM is not allowed to be called.

Each test builds the scene a crash would leave behind with a first EventService,
"crashes" it (its tasks are cancelled, nothing is closed, its lease is left behind but
expired), then starts a second one on the same directory and looks at what happened.

What stops a second execution is three things working together (see
governance/recovery/design.md): ``run()`` refuses while the persisted status is
RUNNING; ``start()`` flips RUNNING to ERROR and writes the ``AgentErrorEvent`` that
pairs with the interrupted action in one synchronous stretch, with no ``await`` in
between; and the binding check wants exactly one pending action. The execution lease
(300 seconds by default) is not one of them: a restart inside that window still holds a
valid lease.
"""

from __future__ import annotations

import asyncio
import contextlib
import inspect
import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from uuid import uuid4

import pytest

from openhands.agent_server.event_service import EventService
from openhands.agent_server.governance_outbox import OutboxRecord, OutboxState
from openhands.agent_server.models import StoredConversation
from openhands.sdk import LLM, Agent
from openhands.sdk.conversation.state import ConversationExecutionStatus
from openhands.sdk.event import ActionEvent, AgentErrorEvent, ObservationEvent
from openhands.sdk.llm import MessageToolCall, TextContent
from openhands.sdk.security.confirmation_policy import ConfirmRisky
from openhands.sdk.security.roy_action_binding import compute_execution_commitment
from openhands.sdk.workspace import LocalWorkspace
from openhands.tools.terminal.definition import TerminalAction, TerminalObservation


LEASE_FILE = "owner_lease.json"
ATTEMPT_ID = "attempt-1"
APPROVAL_ID = "approval-1"


def _pending_action() -> ActionEvent:
    return ActionEvent(
        source="agent",
        thought=[TextContent(text="running a command")],
        action=TerminalAction(command="echo hi"),
        tool_name="terminal",
        tool_call_id="call_1",
        tool_call=MessageToolCall(
            id="call_1",
            name="terminal",
            arguments=json.dumps({"command": "echo hi"}),
            origin="completion",
        ),
        llm_response_id="r1",
    )


@dataclass
class _Scene:
    """What the first process left on disk."""

    stored: StoredConversation
    agent: Agent
    conversations_dir: Path
    conversation_dir: Path


async def _build_scene(
    tmp_path: Path,
    *,
    status: ConversationExecutionStatus,
    outbox_state: OutboxState,
    tool_finished: bool = False,
) -> _Scene:
    """Run a real EventService in personal mode (no relay loop), put one approved
    action, the conversation status and the outbox record on disk, then crash it."""
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    stored = StoredConversation(
        id=uuid4(),
        workspace=LocalWorkspace(working_dir=str(workspace)),
        confirmation_policy=ConfirmRisky(),
        initial_message=None,
        metrics=None,
        created_at=datetime(2025, 1, 1, tzinfo=UTC),
        updated_at=datetime(2025, 1, 1, tzinfo=UTC),
    )
    agent = Agent(llm=LLM(model="gpt-4o", usage_id="crash-test"), tools=[])
    conversations_dir = tmp_path / "conversations"

    first = EventService(
        stored=stored, agent=agent, conversations_dir=conversations_dir
    )
    await first.start()
    conversation = first._conversation
    assert conversation is not None
    action = _pending_action()
    conversation._on_event(action)
    if tool_finished:
        conversation._on_event(
            ObservationEvent(
                source="environment",
                observation=TerminalObservation.from_text(
                    text="hi", command="echo hi", exit_code=0
                ),
                action_id=action.id,
                tool_name="terminal",
                tool_call_id="call_1",
            )
        )
    with conversation._state:
        conversation._state.execution_status = status
    await first.governance_outbox.create_record(
        OutboxRecord(
            request_id="req-1",
            conversation_id=str(stored.id),
            action_event_id=action.id,
            tool_call_id=action.tool_call_id,
            tool_name=action.tool_name,
            action_type="tool_call",
            policy_revision="agent-server-mvp-v1",
            action_summary="s",
            action_payload={},
            digest_salt="salt",
            action_payload_digest="digest",
            execution_commitment=compute_execution_commitment(action, str(stored.id)),
            origin_device_id="device-1",
            state=outbox_state,
            central_approval_id=APPROVAL_ID,
            execution_attempt_id=ATTEMPT_ID,
            # Valid for minutes: a quick restart must not be saved by lease expiry.
            executing_lease_expires_at=(
                datetime.now(UTC) + timedelta(minutes=5)
            ).isoformat(),
        )
    )

    # The crash: no close(), no release of the lease. Its tasks stop, and the lease
    # it holds is expired so that the next instance may take the conversation over.
    for task in (first._lease_task, first._outbox_relay_task):
        if task is not None:
            task.cancel()
    lease_path = first.conversation_dir / LEASE_FILE
    lease = json.loads(lease_path.read_text())
    lease["expires_at"] = 0
    lease_path.write_text(json.dumps(lease))
    return _Scene(stored, agent, conversations_dir, first.conversation_dir)


class _Restarted:
    def __init__(self, service: EventService, client: AsyncMock, executed: list[str]):
        self.service = service
        self.client = client
        self.executed = executed

    def report_outcomes(self) -> list[str]:
        return [
            call.kwargs.get("outcome")
            for call in self.client.report_result.call_args_list
        ]


async def _wait_until(condition: Callable[[], bool], seconds: float = 10.0) -> None:
    deadline = asyncio.get_running_loop().time() + seconds
    while not condition():
        if asyncio.get_running_loop().time() > deadline:
            raise AssertionError("timed out waiting for the restarted service")
        await asyncio.sleep(0.02)


@contextlib.asynccontextmanager
async def _restart(scene: _Scene):
    """A second EventService on the same directory, in team mode. The tool executor is
    wrapped to count calls (it still runs), and the LLM may not be called."""
    executed: list[str] = []
    original = Agent._execute_action_event

    def counting_executor(self, conversation, action_event):
        executed.append(action_event.tool_call_id)
        return original(self, conversation, action_event)

    def llm_must_not_run(*args, **kwargs):
        raise AssertionError("the LLM must not be called during crash recovery")

    client = AsyncMock()
    service = EventService(
        stored=scene.stored,
        agent=scene.agent,
        conversations_dir=scene.conversations_dir,
        governance_deployment_mode="team",
        governance_origin_device_id="device-1",
        governance_client=client,
    )
    try:
        with (
            patch.object(Agent, "_execute_action_event", counting_executor),
            patch("openhands.sdk.llm.llm.LLM.completion", llm_must_not_run),
        ):
            await service.start()
            yield _Restarted(service, client, executed)
    finally:
        tasks = [
            service._lease_task,
            service._outbox_relay_task,
            service._claim_redispatch_task,
            service._run_task,
        ]
        for task in tasks:
            if task is not None and not task.done():
                task.cancel()
        for task in tasks:
            if task is not None:
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await task


def _outbox_state(service: EventService) -> OutboxState:
    record = service.governance_outbox.load()
    assert record is not None, "the outbox record disappeared"
    return record.state


async def _settle(restarted: _Restarted, *, until_reported: bool) -> None:
    """Wait for everything the restart set in motion, then give a late execution a
    short, bounded chance to show up (the thing being asserted is that none does)."""
    task = restarted.service._claim_redispatch_task
    if task is not None:
        await task
    if until_reported:
        await _wait_until(
            lambda: _outbox_state(restarted.service) == OutboxState.RESULT_REPORTED
        )
    await asyncio.sleep(0.3)


async def _relay_cycles(restarted: _Restarted, cycles: int = 2) -> None:
    """Drive the periodic outbox relay by hand. The real loop first fires after 30
    seconds (``GOVERNANCE_OUTBOX_RELAY_INTERVAL_SECONDS``), far beyond what a test
    can wait, and it re-dispatches ``CLAIMED`` records through the same path as
    ``start()``: a second execution would show up here, not in the first moments."""
    for _ in range(cycles):
        await restarted.service._relay_outbox_once()
        task = restarted.service._claim_redispatch_task
        if task is not None:
            await task
        await asyncio.sleep(0.3)


def _events(service: EventService) -> list:
    assert service._conversation is not None
    return list(service._conversation.state.events)


# --- the action had not started: the redispatch is its first execution ----------


@pytest.mark.asyncio
async def test_a_claim_without_a_started_run_is_executed_exactly_once(tmp_path):
    """Crash after the claim was persisted and before run() was dispatched: the
    conversation still waits for confirmation. The redispatch is the first and only
    execution, not a replay. This is also what stops anyone "fixing" the cases below
    by removing the redispatch: this one would then never run.

    Then the best-effort EXECUTION_STARTED marker is undone (as if its write had been
    lost) and the relay is driven by hand: it re-dispatches the CLAIMED record by the
    same path as start(), and the finished action must not run again."""
    scene = await _build_scene(
        tmp_path,
        status=ConversationExecutionStatus.WAITING_FOR_CONFIRMATION,
        outbox_state=OutboxState.CLAIMED,
    )
    async with _restart(scene) as restarted:
        await _wait_until(lambda: bool(restarted.executed))
        await asyncio.sleep(0.3)
        assert restarted.executed == ["call_1"]

        def marker_lost(record: OutboxRecord) -> OutboxRecord:
            record.state = OutboxState.CLAIMED
            return record

        await restarted.service.governance_outbox.mutate(marker_lost)
        await _relay_cycles(restarted)

        assert restarted.executed == ["call_1"]


@pytest.mark.asyncio
async def test_running_is_on_disk_while_the_approved_tool_executes(tmp_path):
    """The status RUNNING must already be in base_state.json when the tool starts.

    Everything in "the action had started: never again" below rests on a process that
    dies mid-tool leaving RUNNING on disk (the restart finds it and writes the
    AgentErrorEvent). run() assigns RUNNING and runs the tool inside one ``with
    state:`` block, where saves are deferred until the block exits, so without an
    explicit flush the disk said WAITING_FOR_CONFIRMATION for the whole execution
    (found by killing a real agent-server process: governance/e2e/e2e_kill_restart.py).
    The tool executor reads the file at the moment it is called."""
    scene = await _build_scene(
        tmp_path,
        status=ConversationExecutionStatus.WAITING_FOR_CONFIRMATION,
        outbox_state=OutboxState.CLAIMED,
    )
    seen: list[str] = []
    original = Agent._execute_action_event

    def reading_executor(self, conversation, action_event):
        payload = json.loads((scene.conversation_dir / "base_state.json").read_text())
        seen.append(payload["execution_status"])
        return original(self, conversation, action_event)

    with patch.object(Agent, "_execute_action_event", reading_executor):
        async with _restart(scene) as restarted:
            await _wait_until(lambda: bool(seen))
            await asyncio.sleep(0.3)
            assert restarted.executed == ["call_1"]

    assert seen == [ConversationExecutionStatus.RUNNING.value]


# --- the action had started: never again ---------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "outbox_state",
    [OutboxState.CLAIMED, OutboxState.EXECUTION_STARTED],
    ids=["progress-marker-never-landed", "progress-marker-landed"],
)
async def test_an_interrupted_execution_is_not_executed_again(tmp_path, outbox_state):
    """Crash after run() set the persisted status RUNNING, which is written before the
    tool executes. Whether or not the outbox's best-effort EXECUTION_STARTED marker
    made it to disk, the restart must not run the tool a second time, and must tell
    central the truth: it cannot know whether the first run finished."""
    scene = await _build_scene(
        tmp_path,
        status=ConversationExecutionStatus.RUNNING,
        outbox_state=outbox_state,
    )
    async with _restart(scene) as restarted:
        await _settle(restarted, until_reported=True)
        await _relay_cycles(restarted)

        assert restarted.executed == []
        assert restarted.report_outcomes() == ["failure_unknown"]
        assert any(isinstance(e, AgentErrorEvent) for e in _events(restarted.service))


# --- the one stretch that must not yield ----------------------------------------


def _fake_service(status, on_event):
    state = SimpleNamespace(events=[_pending_action()], execution_status=status)
    conversation = SimpleNamespace(state=state, _on_event=on_event)
    return SimpleNamespace(_conversation=conversation), state


def test_the_status_flip_and_the_paired_error_cannot_be_separated_by_an_await():
    """The recovery step is a plain function: Python does not let one ``await``, so no
    other task can run between the status change and the AgentErrorEvent. This used to
    be a comment on ``start()``; making it ``async`` again fails here."""
    assert not inspect.iscoroutinefunction(EventService._fail_interrupted_tool_call)


def test_the_error_is_written_before_the_status_leaves_running():
    """If writing the AgentErrorEvent raises, the status must still be RUNNING: the next
    start() tries again. The other order leaves ERROR with an unpaired action, which a
    later run() could execute."""
    seen: list = []

    def record(event):
        seen.append((type(event).__name__, state.execution_status))

    service, state = _fake_service(ConversationExecutionStatus.RUNNING, record)
    EventService._fail_interrupted_tool_call(service)
    assert seen == [("AgentErrorEvent", ConversationExecutionStatus.RUNNING)]
    assert state.execution_status == ConversationExecutionStatus.ERROR

    def boom(event):
        raise RuntimeError("disk full")

    service, state = _fake_service(ConversationExecutionStatus.RUNNING, boom)
    with pytest.raises(RuntimeError):
        EventService._fail_interrupted_tool_call(service)
    assert state.execution_status == ConversationExecutionStatus.RUNNING


# --- the action had finished: report what really happened -----------------------


@pytest.mark.asyncio
async def test_a_finished_action_is_reported_as_it_happened_not_as_unknown(tmp_path):
    """Crash after the tool finished and its observation was persisted, before the
    result reached central. Recovery reports the real outcome and does not execute
    anything: telling central "unknown" here would be false."""
    scene = await _build_scene(
        tmp_path,
        status=ConversationExecutionStatus.RUNNING,
        outbox_state=OutboxState.EXECUTION_STARTED,
        tool_finished=True,
    )
    async with _restart(scene) as restarted:
        await _settle(restarted, until_reported=True)
        await _relay_cycles(restarted)

        assert restarted.executed == []
        assert restarted.report_outcomes() == ["success"]
