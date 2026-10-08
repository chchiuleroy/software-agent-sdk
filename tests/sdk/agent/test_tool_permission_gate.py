"""The department tool-permission gate at the point a tool actually runs.

The analyzer and EventService checks only spare an approver a pointless
question; this gate is what holds when the conversation never asks anyone
(NeverConfirm, no analyzer, a sub-agent that did not inherit one). The tests
use a real Agent step with a mocked LLM and the DEFAULT confirmation policy,
because that is exactly the setup in which a check that lives in the
confirmation path would be skipped.
"""

import time
from collections.abc import Sequence
from typing import TYPE_CHECKING, Self
from unittest.mock import patch

import pytest
from litellm import ChatCompletionMessageToolCall
from litellm.types.utils import (
    Choices,
    Function,
    Message as LiteLLMMessage,
    ModelResponse,
)
from pydantic import SecretStr

from openhands.sdk.agent import Agent
from openhands.sdk.conversation import Conversation
from openhands.sdk.event import AgentErrorEvent, ObservationEvent
from openhands.sdk.llm import LLM, Message, TextContent
from openhands.sdk.security import roy_tool_permissions as permissions
from openhands.sdk.security.confirmation_policy import NeverConfirm
from openhands.sdk.security.roy_tool_permissions import ToolPermissionSnapshot
from openhands.sdk.tool import Action, Observation, Tool, ToolExecutor, register_tool
from openhands.sdk.tool.tool import ToolDefinition


if TYPE_CHECKING:
    from openhands.sdk.conversation.state import ConversationState


_RAN: list[str] = []


class _GateAction(Action):
    value: str = ""


class _GateObservation(Observation):
    result: str = ""


class _GateExecutor(ToolExecutor[_GateAction, _GateObservation]):
    def __call__(self, action: _GateAction, conversation=None) -> _GateObservation:
        _RAN.append(action.value)
        return _GateObservation(result=action.value)


class _GateTool(ToolDefinition[_GateAction, _GateObservation]):
    name = "gate_tool"

    @classmethod
    def create(cls, conv_state: "ConversationState | None" = None) -> Sequence[Self]:
        return [
            cls(
                description="Records that it ran",
                action_type=_GateAction,
                observation_type=_GateObservation,
                executor=_GateExecutor(),
            )
        ]


register_tool("GateTool", _GateTool)


def _response() -> ModelResponse:
    return ModelResponse(
        id="mock-response-1",
        choices=[
            Choices(
                index=0,
                message=LiteLLMMessage(
                    role="assistant",
                    content="using the tool",
                    tool_calls=[
                        ChatCompletionMessageToolCall(
                            id="call_1",
                            type="function",
                            function=Function(
                                name="gate_tool", arguments='{"value": "hi"}'
                            ),
                        )
                    ],
                ),
                finish_reason="tool_calls",
            )
        ],
        created=0,
        model="test-model",
        object="chat.completion",
    )


@pytest.fixture(autouse=True)
def _reset_state():
    permissions.reset()
    _RAN.clear()
    yield
    permissions.reset()


def _run_one_step():
    llm = LLM(
        usage_id="test-llm",
        model="test-model",
        api_key=SecretStr("test-key"),
        base_url="http://test",
    )
    agent = Agent(llm=llm, tools=[Tool(name="GateTool")])
    conversation = Conversation(agent=agent, callbacks=[])
    # The default: nobody is ever asked. This is what the gate must hold under.
    assert isinstance(conversation.state.confirmation_policy, NeverConfirm)
    assert conversation.state.security_analyzer is None
    events: list = []
    with patch(
        "openhands.sdk.llm.llm.litellm_completion",
        side_effect=lambda messages, **kw: _response(),
    ):
        conversation.send_message(
            Message(role="user", content=[TextContent(text="use the tool")])
        )
        agent.step(conversation, on_event=events.append)
    return events


def _allow(*tools: str) -> None:
    permissions.set_enforcing(True)
    permissions.set_snapshot(
        ToolPermissionSnapshot(
            tools=frozenset(tools),
            revision="r1",
            department_name="Finance",
            max_age_seconds=600.0,
            fetched_at=time.monotonic(),
        )
    )


def test_a_tool_outside_the_department_does_not_run_even_when_nobody_is_asked():
    # Why: this is the case a confirmation-path check cannot cover. The tool's
    # executor must not be reached at all.
    _allow("grep")
    events = _run_one_step()
    assert _RAN == []
    errors = [e for e in events if isinstance(e, AgentErrorEvent)]
    assert len(errors) == 1
    assert "not permitted" in errors[0].error
    assert not [e for e in events if isinstance(e, ObservationEvent)]


def test_a_permitted_tool_runs_normally():
    _allow("gate_tool")
    events = _run_one_step()
    assert _RAN == ["hi"]
    assert [e for e in events if isinstance(e, ObservationEvent)]


def test_enforcement_on_but_nothing_fetched_refuses_the_tool():
    permissions.set_enforcing(True)
    _run_one_step()
    assert _RAN == []


def test_nothing_changes_while_enforcement_is_off():
    # Why: personal mode and an opted-out team server behave as before.
    events = _run_one_step()
    assert _RAN == ["hi"]
    assert not [e for e in events if isinstance(e, AgentErrorEvent)]
