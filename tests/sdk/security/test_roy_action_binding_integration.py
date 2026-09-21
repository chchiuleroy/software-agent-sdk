"""Integration tests: run()/arun() actually call check_action_binding() at
the right point — under the same conversation state lock that is about to
flip execution status to RUNNING, before any state mutation, so a mismatch
never needs to be undone. Mirrors test_roy_user_approval_audit.py's
self-approval integration tests.
"""

import asyncio

import pytest
from litellm import ChatCompletionMessageToolCall
from litellm.types.utils import Function
from pydantic import SecretStr

from openhands.sdk.agent import Agent
from openhands.sdk.conversation import Conversation, LocalConversation
from openhands.sdk.conversation.state import ConversationExecutionStatus
from openhands.sdk.event import ActionEvent
from openhands.sdk.llm import LLM, MessageToolCall, TextContent
from openhands.sdk.security.roy_action_binding import (
    ActionBinding,
    ActionBindingMismatchError,
    ActionCountMismatchError,
    compute_execution_commitment,
)
from openhands.sdk.tool.schema import Action


class _BindingIntegrationStubAction(Action):
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
        action=_BindingIntegrationStubAction(command=command),
        tool_name="test_tool",
        tool_call_id=call_id,
        tool_call=MessageToolCall.from_chat_tool_call(litellm_tool_call),
        llm_response_id="response_1",
    )


def _conversation(tmp_path) -> LocalConversation:
    llm = LLM(model="gpt-4o", api_key=SecretStr("x"), usage_id="test")
    agent = Agent(llm=llm, tools=[])
    return Conversation(agent=agent, workspace=str(tmp_path))


def _waiting_conversation(tmp_path, action: ActionEvent) -> LocalConversation:
    conversation = _conversation(tmp_path)
    conversation._on_event(action)
    with conversation.state:
        conversation.state.execution_status = (
            ConversationExecutionStatus.WAITING_FOR_CONFIRMATION
        )
    return conversation


def test_run_matching_binding_executes_normally(tmp_path, monkeypatch):
    action = _pending_action_event()
    conversation = _waiting_conversation(tmp_path, action)
    binding = ActionBinding(
        central_approval_id="approval-1",
        action_event_id=action.id,
        execution_commitment=compute_execution_commitment(
            action, str(conversation.state.id)
        ),
    )

    def _finish_step(*args, **kwargs):
        with conversation.state:
            conversation.state.execution_status = ConversationExecutionStatus.FINISHED

    monkeypatch.setattr(type(conversation.agent), "step", _finish_step)

    conversation.run(expected_binding=binding)

    assert conversation.state.execution_status == ConversationExecutionStatus.FINISHED


def test_run_mismatched_binding_blocked_before_running(tmp_path, monkeypatch):
    original = _pending_action_event(call_id="call_1")
    conversation = _waiting_conversation(tmp_path, original)
    stale_binding = ActionBinding(
        central_approval_id="approval-1",
        action_event_id="some-other-event-id",
        execution_commitment="irrelevant",
    )

    step_calls = []
    monkeypatch.setattr(
        type(conversation.agent), "step", lambda *a, **k: step_calls.append(1)
    )

    with pytest.raises(ActionBindingMismatchError):
        conversation.run(expected_binding=stale_binding)

    # Blocked before the transition: still waiting, agent never stepped —
    # a blocked binding check is not a decision that happened, and must not
    # fall into the generic exception handler that would set ERROR (see
    # roy_action_binding.py's placement in local_conversation.py).
    assert (
        conversation.state.execution_status
        == ConversationExecutionStatus.WAITING_FOR_CONFIRMATION
    )
    assert step_calls == []


def test_run_wrong_pending_action_count_blocked(tmp_path, monkeypatch):
    action = _pending_action_event(call_id="call_1")
    other = _pending_action_event(call_id="call_2")
    conversation = _conversation(tmp_path)
    conversation._on_event(action)
    conversation._on_event(other)
    with conversation.state:
        conversation.state.execution_status = (
            ConversationExecutionStatus.WAITING_FOR_CONFIRMATION
        )
    binding = ActionBinding(
        central_approval_id="approval-1",
        action_event_id=action.id,
        execution_commitment=compute_execution_commitment(
            action, str(conversation.state.id)
        ),
    )

    step_calls = []
    monkeypatch.setattr(
        type(conversation.agent), "step", lambda *a, **k: step_calls.append(1)
    )

    with pytest.raises(ActionCountMismatchError):
        conversation.run(expected_binding=binding)

    assert (
        conversation.state.execution_status
        == ConversationExecutionStatus.WAITING_FOR_CONFIRMATION
    )
    assert step_calls == []


def test_run_without_expected_binding_is_unaffected(tmp_path, monkeypatch):
    # Personal mode / today's behavior: omitting expected_binding entirely
    # must behave exactly as before this feature existed.
    action = _pending_action_event()
    conversation = _waiting_conversation(tmp_path, action)

    def _finish_step(*args, **kwargs):
        with conversation.state:
            conversation.state.execution_status = ConversationExecutionStatus.FINISHED

    monkeypatch.setattr(type(conversation.agent), "step", _finish_step)

    conversation.run()

    assert conversation.state.execution_status == ConversationExecutionStatus.FINISHED


def test_arun_matching_binding_executes_normally(tmp_path, monkeypatch):
    action = _pending_action_event()
    conversation = _waiting_conversation(tmp_path, action)
    binding = ActionBinding(
        central_approval_id="approval-1",
        action_event_id=action.id,
        execution_commitment=compute_execution_commitment(
            action, str(conversation.state.id)
        ),
    )

    async def _finish_astep(*args, **kwargs):
        with conversation.state:
            conversation.state.execution_status = ConversationExecutionStatus.FINISHED

    monkeypatch.setattr(type(conversation.agent), "astep", _finish_astep)

    asyncio.run(conversation.arun(expected_binding=binding))

    assert conversation.state.execution_status == ConversationExecutionStatus.FINISHED


def test_arun_mismatched_binding_blocked_before_running(tmp_path, monkeypatch):
    original = _pending_action_event(call_id="call_1")
    conversation = _waiting_conversation(tmp_path, original)
    stale_binding = ActionBinding(
        central_approval_id="approval-1",
        action_event_id="some-other-event-id",
        execution_commitment="irrelevant",
    )

    astep_calls = []

    async def _record_astep(*args, **kwargs):
        astep_calls.append(1)

    monkeypatch.setattr(type(conversation.agent), "astep", _record_astep)

    with pytest.raises(ActionBindingMismatchError):
        asyncio.run(conversation.arun(expected_binding=stale_binding))

    assert (
        conversation.state.execution_status
        == ConversationExecutionStatus.WAITING_FOR_CONFIRMATION
    )
    assert astep_calls == []


def test_run_raising_on_governed_reject_does_not_mask_the_binding_error(
    tmp_path, monkeypatch
):
    """A raising on_governed_reject callback (e.g. run_coroutine_threadsafe
    failing because the event loop is closing) must never replace the
    original ActionBindingMismatchError — EventService.run()'s dispatch
    depends on catching that exact exception type to route to the
    dedicated handler instead of the generic catch-all that would force
    ERROR."""
    original = _pending_action_event(call_id="call_1")
    conversation = _waiting_conversation(tmp_path, original)
    stale_binding = ActionBinding(
        central_approval_id="approval-1",
        action_event_id="some-other-event-id",
        execution_commitment="irrelevant",
    )

    def _raising_reject(exc: BaseException) -> None:
        raise RuntimeError("event loop is closing")

    with pytest.raises(ActionBindingMismatchError):
        conversation.run(
            expected_binding=stale_binding, on_governed_reject=_raising_reject
        )


def test_run_raising_on_governed_start_does_not_fail_the_run(tmp_path, monkeypatch):
    """A raising on_governed_start callback fires after RUNNING is already
    assigned — if it propagated, it would reach run()'s outer generic
    exception handler and get mistaken for a genuine run failure, forcing
    ERROR status even though the binding check actually passed."""
    action = _pending_action_event()
    conversation = _waiting_conversation(tmp_path, action)
    binding = ActionBinding(
        central_approval_id="approval-1",
        action_event_id=action.id,
        execution_commitment=compute_execution_commitment(
            action, str(conversation.state.id)
        ),
    )

    def _finish_step(*args, **kwargs):
        with conversation.state:
            conversation.state.execution_status = ConversationExecutionStatus.FINISHED

    monkeypatch.setattr(type(conversation.agent), "step", _finish_step)

    def _raising_start() -> None:
        raise RuntimeError("boom")

    conversation.run(expected_binding=binding, on_governed_start=_raising_start)

    assert conversation.state.execution_status == ConversationExecutionStatus.FINISHED
