"""Tests for the user_approval audit wiring in LocalConversation itself.

record_user_approval_event() is called from reject_pending_actions(), run()
and arun() (conversation/impl/local_conversation.py) rather than from the
agent server's respond_to_confirmation() — see roy_admin_audit.py's module
docstring for why. This file covers those SDK-layer call sites; the writer
function itself (JSONL shape, fail-open behavior) is covered directly in
test_roy_admin_audit.py.
"""

import asyncio
import json

import pytest
from litellm import ChatCompletionMessageToolCall
from litellm.types.utils import Function
from pydantic import SecretStr

from openhands.sdk.agent import Agent
from openhands.sdk.conversation import Conversation, LocalConversation
from openhands.sdk.conversation.state import ConversationExecutionStatus
from openhands.sdk.event import ActionEvent
from openhands.sdk.llm import LLM, MessageToolCall, TextContent
from openhands.sdk.tool.schema import Action


class _StubAction(Action):
    command: str


def _pending_action_event(
    call_id: str = "call_1", command: str = "test_command"
) -> ActionEvent:
    litellm_tool_call = ChatCompletionMessageToolCall(
        id=call_id,
        type="function",
        function=Function(name="test_tool", arguments=f'{{"command": "{command}"}}'),
    )
    return ActionEvent(
        source="agent",
        thought=[TextContent(text="thought")],
        action=_StubAction(command=command),
        tool_name="test_tool",
        tool_call_id=call_id,
        tool_call=MessageToolCall.from_chat_tool_call(litellm_tool_call),
        llm_response_id="response_1",
    )


def _conversation(tmp_path) -> LocalConversation:
    llm = LLM(model="gpt-4o", api_key=SecretStr("x"), usage_id="test")
    agent = Agent(llm=llm, tools=[])
    return Conversation(agent=agent, workspace=str(tmp_path))


def _read_user_approval_records(audit_dir) -> list[dict]:
    path = audit_dir / "user_approval.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_reject_pending_actions_writes_user_approval_audit(monkeypatch, tmp_path):
    audit_dir = tmp_path / "audit"
    monkeypatch.setenv("ROY_GOVERNANCE_AUDIT_DIR", str(audit_dir))
    conversation = _conversation(tmp_path)
    conversation._on_event(_pending_action_event())

    conversation.reject_pending_actions("looked risky")

    records = _read_user_approval_records(audit_dir)
    assert len(records) == 1
    assert records[0]["accepted"] is False
    assert records[0]["reason"] == "looked risky"
    assert records[0]["tool_names"] == ["test_tool"]
    assert records[0]["tool_call_ids"] == ["call_1"]


def test_reject_pairs_same_tool_name_multiple_calls_by_call_id(monkeypatch, tmp_path):
    # Two pending calls to the same tool must stay distinguishable by
    # tool_call_id — a record that only kept tool_names couldn't tell them
    # apart.
    audit_dir = tmp_path / "audit"
    monkeypatch.setenv("ROY_GOVERNANCE_AUDIT_DIR", str(audit_dir))
    conversation = _conversation(tmp_path)
    conversation._on_event(_pending_action_event(call_id="call_1", command="ls"))
    conversation._on_event(_pending_action_event(call_id="call_2", command="rm -rf /"))

    conversation.reject_pending_actions("looked risky")

    records = _read_user_approval_records(audit_dir)
    assert len(records) == 1
    assert records[0]["tool_names"] == ["test_tool", "test_tool"]
    assert records[0]["tool_call_ids"] == ["call_1", "call_2"]


def test_reject_with_nothing_pending_writes_no_audit(monkeypatch, tmp_path):
    # No pending action exists — reject_pending_actions() is a no-op, and
    # nothing was actually rejected, so no record should be written.
    audit_dir = tmp_path / "audit"
    monkeypatch.setenv("ROY_GOVERNANCE_AUDIT_DIR", str(audit_dir))
    conversation = _conversation(tmp_path)

    conversation.reject_pending_actions("nothing to reject")

    assert _read_user_approval_records(audit_dir) == []


def test_run_accept_writes_user_approval_audit(monkeypatch, tmp_path):
    audit_dir = tmp_path / "audit"
    monkeypatch.setenv("ROY_GOVERNANCE_AUDIT_DIR", str(audit_dir))
    conversation = _conversation(tmp_path)
    conversation._on_event(_pending_action_event())
    with conversation.state:
        conversation.state.execution_status = (
            ConversationExecutionStatus.WAITING_FOR_CONFIRMATION
        )

    def _finish_step(*args, **kwargs):
        with conversation.state:
            conversation.state.execution_status = ConversationExecutionStatus.FINISHED

    monkeypatch.setattr(type(conversation.agent), "step", _finish_step)

    conversation.run()

    records = _read_user_approval_records(audit_dir)
    assert len(records) == 1
    assert records[0]["accepted"] is True
    assert records[0]["reason"] is None
    assert records[0]["tool_names"] == ["test_tool"]
    assert records[0]["tool_call_ids"] == ["call_1"]


def test_run_accept_pairs_same_tool_name_multiple_calls_by_call_id(
    monkeypatch, tmp_path
):
    audit_dir = tmp_path / "audit"
    monkeypatch.setenv("ROY_GOVERNANCE_AUDIT_DIR", str(audit_dir))
    conversation = _conversation(tmp_path)
    conversation._on_event(_pending_action_event(call_id="call_1", command="ls"))
    conversation._on_event(_pending_action_event(call_id="call_2", command="rm -rf /"))
    with conversation.state:
        conversation.state.execution_status = (
            ConversationExecutionStatus.WAITING_FOR_CONFIRMATION
        )

    def _finish_step(*args, **kwargs):
        with conversation.state:
            conversation.state.execution_status = ConversationExecutionStatus.FINISHED

    monkeypatch.setattr(type(conversation.agent), "step", _finish_step)

    conversation.run()

    records = _read_user_approval_records(audit_dir)
    assert len(records) == 1
    assert records[0]["tool_names"] == ["test_tool", "test_tool"]
    assert records[0]["tool_call_ids"] == ["call_1", "call_2"]


def test_run_when_not_waiting_for_confirmation_writes_no_audit(monkeypatch, tmp_path):
    # A plain run() (not resuming from WAITING_FOR_CONFIRMATION) is not an
    # approval decision and must not be recorded as one.
    audit_dir = tmp_path / "audit"
    monkeypatch.setenv("ROY_GOVERNANCE_AUDIT_DIR", str(audit_dir))
    conversation = _conversation(tmp_path)

    def _finish_step(*args, **kwargs):
        with conversation.state:
            conversation.state.execution_status = ConversationExecutionStatus.FINISHED

    monkeypatch.setattr(type(conversation.agent), "step", _finish_step)

    conversation.run()

    assert _read_user_approval_records(audit_dir) == []


def test_arun_accept_writes_user_approval_audit(monkeypatch, tmp_path):
    audit_dir = tmp_path / "audit"
    monkeypatch.setenv("ROY_GOVERNANCE_AUDIT_DIR", str(audit_dir))
    conversation = _conversation(tmp_path)
    conversation._on_event(_pending_action_event())
    with conversation.state:
        conversation.state.execution_status = (
            ConversationExecutionStatus.WAITING_FOR_CONFIRMATION
        )

    async def _finish_astep(*args, **kwargs):
        with conversation.state:
            conversation.state.execution_status = ConversationExecutionStatus.FINISHED

    monkeypatch.setattr(type(conversation.agent), "astep", _finish_astep)

    asyncio.run(conversation.arun())

    records = _read_user_approval_records(audit_dir)
    assert len(records) == 1
    assert records[0]["accepted"] is True
    assert records[0]["tool_names"] == ["test_tool"]
    assert records[0]["tool_call_ids"] == ["call_1"]


def test_arun_cancel_during_audit_drain_does_not_lose_queued_write(
    monkeypatch, tmp_path
):
    """Regression test for a review finding: without asyncio.shield(),
    cancelling arun() while its `finally` block is still draining a
    scheduled-but-not-yet-started audit write discards that write entirely
    (a queued, not-yet-running executor call really is cancellable, unlike
    one already running). Uses a single-worker executor to deterministically
    keep the write queued rather than started at the moment of cancellation,
    instead of relying on timing to win a genuine race.
    """
    import concurrent.futures
    import threading
    import time

    audit_dir = tmp_path / "audit"
    monkeypatch.setenv("ROY_GOVERNANCE_AUDIT_DIR", str(audit_dir))
    conversation = _conversation(tmp_path)
    conversation._on_event(_pending_action_event())
    with conversation.state:
        conversation.state.execution_status = (
            ConversationExecutionStatus.WAITING_FOR_CONFIRMATION
        )

    async def _finish_astep(*args, **kwargs):
        with conversation.state:
            conversation.state.execution_status = ConversationExecutionStatus.FINISHED

    monkeypatch.setattr(type(conversation.agent), "astep", _finish_astep)

    blocker_started = threading.Event()
    blocker_release = threading.Event()

    def _blocker():
        blocker_started.set()
        blocker_release.wait(timeout=5)

    async def _drive():
        single_worker = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        asyncio.get_running_loop().set_default_executor(single_worker)

        def _fake_ensure_agent_ready(self):
            # arun() reaches this via `await asyncio.to_thread(...)`, so it
            # runs ON the single worker. Submitting the blocker directly to
            # that same executor from here (still occupying its only
            # worker) guarantees the blocker is queued and picked up next —
            # before arun() can resume on the event loop and schedule the
            # audit write — with no race: both submissions happen on the
            # same worker thread, strictly ordered, no timing to get lucky
            # on.
            single_worker.submit(_blocker)

        monkeypatch.setattr(
            type(conversation), "_ensure_agent_ready", _fake_ensure_agent_ready
        )

        task = asyncio.ensure_future(conversation.arun())
        # Deterministically wait for the blocker to actually start (proves
        # the worker is now occupied — ensure_agent_ready's round trip
        # already completed, since it had to run and return before the
        # worker could pick up the queued blocker next), then yield a few
        # times so the event loop can resume arun()'s task and let it run
        # its remaining synchronous work (scheduling the audit write and
        # reaching the finally block's shielded await, which will now hang
        # behind the blocker) — this is a tighter, principled bound than a
        # wall-clock sleep guessing how long that takes. Polls
        # blocker_started.is_set() directly (not via asyncio.to_thread,
        # which would submit to the same single_worker this is trying to
        # observe and could itself get stuck queued behind arun()'s own
        # to_thread(_ensure_agent_ready) call).
        deadline = time.monotonic() + 5.0
        while not blocker_started.is_set():
            assert time.monotonic() < deadline, "blocker never started"
            await asyncio.sleep(0.005)
        for _ in range(10):
            await asyncio.sleep(0)

        task.cancel()
        await task  # must complete normally — see the finally-block comment
        assert conversation._arun_task is None

        blocker_release.set()
        # Deterministically wait for the now-unblocked write to actually
        # finish, rather than guessing with a sleep: shutdown(wait=True)
        # blocks until every submitted callable (blocker, then the write)
        # has completed. Called directly (not via to_thread) — this test
        # coroutine runs on the event loop's own thread, not one of
        # single_worker's, so blocking it briefly here is safe (to_thread
        # would submit this call to single_worker itself, which then tries
        # to join its own only worker thread and raises).
        single_worker.shutdown(wait=True)

    asyncio.run(_drive())

    records = _read_user_approval_records(audit_dir)
    assert len(records) == 1
    assert records[0]["accepted"] is True


def test_run_self_approval_blocked_when_requester_equals_approver(
    monkeypatch, tmp_path
):
    audit_dir = tmp_path / "audit"
    monkeypatch.setenv("ROY_GOVERNANCE_AUDIT_DIR", str(audit_dir))
    monkeypatch.setenv("ROY_GOVERNANCE_IDENTITY", "roy")
    conversation = _conversation(tmp_path)
    conversation._on_event(_pending_action_event())
    with conversation.state:
        conversation.state.execution_status = (
            ConversationExecutionStatus.WAITING_FOR_CONFIRMATION
        )

    step_calls = []
    monkeypatch.setattr(
        type(conversation.agent), "step", lambda *a, **k: step_calls.append(1)
    )

    with pytest.raises(ValueError, match="self-approval not allowed"):
        conversation.run(approver_identity="roy")

    # Blocked before the transition: still waiting, agent never stepped, and
    # no audit record — a blocked attempt is not a decision that happened.
    assert (
        conversation.state.execution_status
        == ConversationExecutionStatus.WAITING_FOR_CONFIRMATION
    )
    assert step_calls == []
    assert _read_user_approval_records(audit_dir) == []
    # Review finding: the check runs before the try/finally that normally
    # resets _cancel_token — must not leave a stale token behind from a run
    # that never actually started.
    assert conversation._cancel_token is None


def test_run_allows_when_approver_identity_differs_from_requester(
    monkeypatch, tmp_path
):
    audit_dir = tmp_path / "audit"
    monkeypatch.setenv("ROY_GOVERNANCE_AUDIT_DIR", str(audit_dir))
    monkeypatch.setenv("ROY_GOVERNANCE_IDENTITY", "roy")
    conversation = _conversation(tmp_path)
    conversation._on_event(_pending_action_event())
    with conversation.state:
        conversation.state.execution_status = (
            ConversationExecutionStatus.WAITING_FOR_CONFIRMATION
        )

    def _finish_step(*args, **kwargs):
        with conversation.state:
            conversation.state.execution_status = ConversationExecutionStatus.FINISHED

    monkeypatch.setattr(type(conversation.agent), "step", _finish_step)

    conversation.run(approver_identity="test-approver")

    records = _read_user_approval_records(audit_dir)
    assert len(records) == 1
    assert records[0]["accepted"] is True
    assert records[0]["requester_identity"] == "roy"
    assert records[0]["approver_identity"] == "test-approver"


def test_run_accept_with_approver_identity_but_no_requester_set_is_unaffected(
    monkeypatch, tmp_path
):
    # ROY_GOVERNANCE_IDENTITY intentionally left unset — today's default.
    # Even a caller that happens to pass approver_identity must not be
    # blocked, since there's no requester identity to compare it against.
    audit_dir = tmp_path / "audit"
    monkeypatch.setenv("ROY_GOVERNANCE_AUDIT_DIR", str(audit_dir))
    conversation = _conversation(tmp_path)
    conversation._on_event(_pending_action_event())
    with conversation.state:
        conversation.state.execution_status = (
            ConversationExecutionStatus.WAITING_FOR_CONFIRMATION
        )

    def _finish_step(*args, **kwargs):
        with conversation.state:
            conversation.state.execution_status = ConversationExecutionStatus.FINISHED

    monkeypatch.setattr(type(conversation.agent), "step", _finish_step)

    conversation.run(approver_identity="roy")

    records = _read_user_approval_records(audit_dir)
    assert len(records) == 1
    assert records[0]["accepted"] is True
    assert records[0]["requester_identity"] is None
    assert records[0]["approver_identity"] == "roy"


def test_arun_self_approval_blocked_when_requester_equals_approver(
    monkeypatch, tmp_path
):
    audit_dir = tmp_path / "audit"
    monkeypatch.setenv("ROY_GOVERNANCE_AUDIT_DIR", str(audit_dir))
    monkeypatch.setenv("ROY_GOVERNANCE_IDENTITY", "roy")
    conversation = _conversation(tmp_path)
    conversation._on_event(_pending_action_event())
    with conversation.state:
        conversation.state.execution_status = (
            ConversationExecutionStatus.WAITING_FOR_CONFIRMATION
        )

    astep_calls = []

    async def _track_astep(*args, **kwargs):
        astep_calls.append(1)

    monkeypatch.setattr(type(conversation.agent), "astep", _track_astep)

    with pytest.raises(ValueError, match="self-approval not allowed"):
        asyncio.run(conversation.arun(approver_identity="roy"))

    assert (
        conversation.state.execution_status
        == ConversationExecutionStatus.WAITING_FOR_CONFIRMATION
    )
    assert astep_calls == []
    assert _read_user_approval_records(audit_dir) == []
    # Review finding: same as the sync run() case, but arun() also sets
    # _arun_task before this check runs — both must be reset, not just the
    # cancel token, or interrupt()/diagnostics would see a stale in-flight
    # task that never actually started.
    assert conversation._cancel_token is None
    assert conversation._arun_task is None


def test_reject_pending_actions_records_identities_without_blocking_self_reject(
    monkeypatch, tmp_path
):
    # Rejecting your own pending action isn't a privilege escalation, so
    # reject_pending_actions() must never raise here even though
    # requester == approver — unlike run()/arun() above.
    audit_dir = tmp_path / "audit"
    monkeypatch.setenv("ROY_GOVERNANCE_AUDIT_DIR", str(audit_dir))
    monkeypatch.setenv("ROY_GOVERNANCE_IDENTITY", "roy")
    conversation = _conversation(tmp_path)
    conversation._on_event(_pending_action_event())

    conversation.reject_pending_actions("looked risky", approver_identity="roy")

    records = _read_user_approval_records(audit_dir)
    assert len(records) == 1
    assert records[0]["accepted"] is False
    assert records[0]["requester_identity"] == "roy"
    assert records[0]["approver_identity"] == "roy"
