"""Unit tests for roy_action_binding.py's pure functions.

Integration coverage (run()/arun() actually calling check_action_binding at
the right point, under the same lock as the RUNNING transition) lives in
test_roy_action_binding_integration.py, next to the equivalent self-approval
integration tests it mirrors.
"""

from datetime import UTC, datetime, timedelta

import pytest
from litellm import ChatCompletionMessageToolCall
from litellm.types.utils import Function

from openhands.sdk.event import ActionEvent
from openhands.sdk.llm import MessageToolCall, TextContent
from openhands.sdk.security.roy_action_binding import (
    ActionBinding,
    ActionBindingMismatchError,
    ActionCountMismatchError,
    ExecutionLeaseExpiredError,
    check_action_binding,
    compute_execution_commitment,
)
from openhands.sdk.tool.schema import Action


class _BindingUnitStubAction(Action):
    command: str


def _action_event(call_id: str = "call_1", command: str = "ls") -> ActionEvent:
    litellm_tool_call = ChatCompletionMessageToolCall(
        id=call_id,
        type="function",
        function=Function(name="test_tool", arguments=f'{{"command": "{command}"}}'),
    )
    return ActionEvent(
        source="agent",
        thought=[TextContent(text="thought")],
        action=_BindingUnitStubAction(command=command),
        tool_name="test_tool",
        tool_call_id=call_id,
        tool_call=MessageToolCall.from_chat_tool_call(litellm_tool_call),
        llm_response_id="response_1",
    )


def _binding_for(action: ActionEvent, conversation_id: str = "conv-1") -> ActionBinding:
    return ActionBinding(
        central_approval_id="approval-1",
        action_event_id=action.id,
        execution_commitment=compute_execution_commitment(action, conversation_id),
    )


def test_commitment_is_stable_for_identical_action():
    action = _action_event()
    assert compute_execution_commitment(
        action, "conv-1"
    ) == compute_execution_commitment(action, "conv-1")


def test_commitment_differs_when_args_change():
    a = _action_event(command="ls")
    b = _action_event(command="rm -rf /")
    assert compute_execution_commitment(a, "conv-1") != compute_execution_commitment(
        b, "conv-1"
    )


def test_commitment_differs_across_conversations():
    action = _action_event()
    assert compute_execution_commitment(
        action, "conv-1"
    ) != compute_execution_commitment(action, "conv-2")


def test_fingerprint_stable_for_same_binding_fields():
    action = _action_event()
    binding = _binding_for(action)
    same = ActionBinding(
        central_approval_id=binding.central_approval_id,
        action_event_id=binding.action_event_id,
        execution_commitment=binding.execution_commitment,
    )
    assert binding.fingerprint() == same.fingerprint()


def test_fingerprint_differs_for_different_approval_id():
    action = _action_event()
    binding = _binding_for(action)
    different = ActionBinding(
        central_approval_id="approval-2",
        action_event_id=binding.action_event_id,
        execution_commitment=binding.execution_commitment,
    )
    assert binding.fingerprint() != different.fingerprint()


def test_check_is_noop_when_expected_is_none():
    # Personal mode / today's behavior: no binding to check against at all.
    check_action_binding(None, [], "conv-1")
    check_action_binding(None, [_action_event(), _action_event(call_id="call_2")], "c")


def test_check_passes_when_action_matches():
    action = _action_event()
    binding = _binding_for(action)
    check_action_binding(binding, [action], "conv-1")


def test_check_raises_action_count_mismatch_when_zero_pending():
    action = _action_event()
    binding = _binding_for(action)
    with pytest.raises(ActionCountMismatchError):
        check_action_binding(binding, [], "conv-1")


def test_check_raises_action_count_mismatch_when_multiple_pending():
    action = _action_event()
    binding = _binding_for(action)
    other = _action_event(call_id="call_2")
    with pytest.raises(ActionCountMismatchError):
        check_action_binding(binding, [action, other], "conv-1")


def test_check_raises_binding_mismatch_when_action_replaced():
    original = _action_event(call_id="call_1")
    binding = _binding_for(original)
    replacement = _action_event(call_id="call_2")
    with pytest.raises(ActionBindingMismatchError, match="replaced"):
        check_action_binding(binding, [replacement], "conv-1")


def test_check_raises_binding_mismatch_when_content_changed():
    # Same action_event_id (same call_id) but the tool args mutated
    # underneath — must still be caught by the commitment recompute even
    # though the identity check alone wouldn't catch it. Force matching IDs
    # by reusing the original event's id.
    original = _action_event(call_id="call_1", command="ls")
    binding = _binding_for(original)
    mutated = _action_event(call_id="call_1", command="rm -rf /")
    object.__setattr__(mutated, "id", original.id)
    with pytest.raises(ActionBindingMismatchError, match="content changed"):
        check_action_binding(binding, [mutated], "conv-1")


def test_check_raises_when_lease_expired():
    action = _action_event()
    binding = ActionBinding(
        central_approval_id="approval-1",
        action_event_id=action.id,
        execution_commitment=compute_execution_commitment(action, "conv-1"),
        executing_lease_expires_at=datetime.now(UTC) - timedelta(seconds=1),
    )
    with pytest.raises(ExecutionLeaseExpiredError):
        check_action_binding(binding, [action], "conv-1")


def test_check_passes_when_lease_not_yet_expired():
    action = _action_event()
    binding = ActionBinding(
        central_approval_id="approval-1",
        action_event_id=action.id,
        execution_commitment=compute_execution_commitment(action, "conv-1"),
        executing_lease_expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )
    check_action_binding(binding, [action], "conv-1")
