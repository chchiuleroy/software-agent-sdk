"""Team mode must refuse a sub-agent's pending actions instead of auto-approving.

``TaskManager._run_until_finished`` resumes a sub-agent that stopped at
WAITING_FOR_CONFIRMATION with ``handler is None or handler(...)``. Nothing in
the repo passes a handler (it is a callable, so it cannot ride in a JSON
``Tool(params=...)``), so every pending sub-agent action was run with neither
central approval nor user confirmation. The agent-server fixes this for team
mode only, by setting the tools package's process-wide default handler to one
that always refuses. Personal mode keeps the upstream behaviour.

Each place a sub-agent is resumed is tested on its own, because a fix that
covers the ``task`` tool but not the others leaves the gap open: the
``workflow`` tool builds a fresh ``TaskManager`` per call, and
``DelegateExecutor`` has its own copy of the loop.
"""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException
from pydantic import SecretStr

from openhands.agent_server.api import create_app
from openhands.agent_server.config import Config
from openhands.agent_server.governance_subagents import (
    MAX_REFUSALS_PER_RUN,
    install_team_mode_subagent_guard,
    refuse_subagent_pending_actions,
    release_team_mode_subagent_guard,
)
from openhands.agent_server.init_router import InitRequest, InitService
from openhands.sdk import Agent
from openhands.sdk.conversation.impl.local_conversation import LocalConversation
from openhands.sdk.conversation.state import ConversationExecutionStatus
from openhands.sdk.llm import Message, MessageToolCall, TextContent
from openhands.sdk.security.confirmation_policy import AlwaysConfirm
from openhands.sdk.testing import TestLLM
from openhands.sdk.tool import Tool
from openhands.tools.delegate.impl import DelegateExecutor
from openhands.tools.file_editor import FileEditorTool
from openhands.tools.task.manager import (
    RefusalLimitExceeded,
    Task,
    TaskManager,
    TaskStatus,
    get_default_confirmation_handler,
    get_default_max_refusals,
)
from openhands.tools.workflow.impl import WorkflowContext


TEAM = Config(governance_deployment_mode="team")
PERSONAL = Config(governance_deployment_mode="personal")


def _waiting_conversation():
    """A sub-agent conversation that stops once for confirmation.

    It stays WAITING until its pending actions are rejected, so approving them
    shows up as a bare ``run()`` while it is still WAITING.
    """
    conversation = MagicMock()
    conversation.state.execution_status = (
        ConversationExecutionStatus.WAITING_FOR_CONFIRMATION
    )
    conversation.status_at_each_run = []
    runs = {"n": 0}

    def _run() -> None:
        runs["n"] += 1
        conversation.status_at_each_run.append(conversation.state.execution_status)
        if runs["n"] > 3:  # a failing test must not hang the suite
            conversation.state.execution_status = ConversationExecutionStatus.FINISHED

    def _reject(_reason: str) -> None:
        conversation.state.execution_status = ConversationExecutionStatus.FINISHED

    conversation.run.side_effect = _run
    conversation.reject_pending_actions.side_effect = _reject
    return conversation


def _resume(runner, conversation) -> None:
    """Run a sub-agent through ``_run_until_finished`` with one pending action."""
    with (
        patch(
            "openhands.tools.task.manager.ConversationState.get_unmatched_actions",
            return_value=[MagicMock(name="pending-action")],
        ),
        patch(
            "openhands.tools.delegate.impl.ConversationState.get_unmatched_actions",
            return_value=[MagicMock(name="pending-action")],
        ),
    ):
        runner("task-1", conversation)


def _runners():
    """Every place that resumes a sub-agent, built with no handler of its own."""
    return {
        "task": TaskManager()._run_until_finished,
        "workflow": WorkflowContext(
            parent_conversation=MagicMock(), max_concurrency=1
        )._manager._run_until_finished,  # type: ignore[attr-defined]
        "delegate": DelegateExecutor()._run_until_finished,
    }


@pytest.mark.parametrize("which", ["task", "workflow", "delegate"])
def test_personal_mode_still_auto_approves_pending_subagent_actions(which):
    """Pins the unchanged upstream behaviour outside team mode."""
    install_team_mode_subagent_guard(PERSONAL)
    conversation = _waiting_conversation()

    _resume(_runners()[which], conversation)

    conversation.reject_pending_actions.assert_not_called()
    assert (
        ConversationExecutionStatus.WAITING_FOR_CONFIRMATION
        in (conversation.status_at_each_run[1:])
    )


@pytest.mark.parametrize("which", ["task", "workflow", "delegate"])
def test_team_mode_refuses_pending_subagent_actions_instead_of_running_them(which):
    install_team_mode_subagent_guard(TEAM)
    conversation = _waiting_conversation()

    _resume(_runners()[which], conversation)

    conversation.reject_pending_actions.assert_called_once()
    # Every run() after the sub-agent's own first start came after the
    # rejection had resolved the pending actions: nothing ran while pending.
    assert (
        ConversationExecutionStatus.WAITING_FOR_CONFIRMATION
        not in (conversation.status_at_each_run[1:])
    )
    assert conversation.status_at_each_run[0] == (
        ConversationExecutionStatus.WAITING_FOR_CONFIRMATION
    )


def test_a_manager_built_before_the_guard_still_follows_it():
    """The handler is read when a sub-agent stops, not when the manager is built:
    a persisted conversation's tools can be resolved before the mode settles."""
    manager = TaskManager()
    install_team_mode_subagent_guard(TEAM)
    conversation = _waiting_conversation()

    _resume(manager._run_until_finished, conversation)

    conversation.reject_pending_actions.assert_called_once()


def test_a_handler_given_to_the_manager_wins_over_the_default():
    install_team_mode_subagent_guard(TEAM)
    seen: list[str] = []

    def approve(task_id: str, _pending: list) -> bool:
        seen.append(task_id)
        return True

    manager = TaskManager(confirmation_handler=approve)
    conversation = _waiting_conversation()

    _resume(manager._run_until_finished, conversation)

    # The manager's own handler decided, not the refusing default.
    assert seen and set(seen) == {"task-1"}
    conversation.reject_pending_actions.assert_not_called()


def test_refusing_handler_says_no():
    assert refuse_subagent_pending_actions("task-9", [MagicMock()]) is False


def test_install_is_a_noop_outside_team_mode():
    install_team_mode_subagent_guard(PERSONAL)

    assert get_default_confirmation_handler() is None


def test_install_in_team_mode_sets_the_refusing_default_and_is_repeatable():
    install_team_mode_subagent_guard(TEAM)
    install_team_mode_subagent_guard(TEAM)

    assert get_default_confirmation_handler() is refuse_subagent_pending_actions
    assert get_default_max_refusals() == MAX_REFUSALS_PER_RUN


def test_create_app_installs_the_guard_for_a_team_config_handed_in_directly():
    """The path that does not go through load_config()."""
    create_app(Config(governance_deployment_mode="team"))

    assert get_default_confirmation_handler() is refuse_subagent_pending_actions


def test_create_app_that_fails_to_build_leaves_no_hold_behind():
    """The guard is switched on last, so a team app that never came up cannot
    leave a hold that a personal app built next in the same process inherits."""
    with patch(
        "openhands.agent_server.api._add_api_routes",
        side_effect=RuntimeError("routes failed to register"),
    ):
        with pytest.raises(RuntimeError):
            create_app(Config(governance_deployment_mode="team"))

    assert get_default_confirmation_handler() is None
    create_app(Config(governance_deployment_mode="personal"))
    assert get_default_confirmation_handler() is None


def test_create_app_leaves_a_personal_config_alone():
    create_app(Config(governance_deployment_mode="personal"))

    assert get_default_confirmation_handler() is None


def _central_fields() -> dict:
    return {
        "governance_central_api_base_url": "https://central.example",
        "governance_central_api_token_url": "https://idp.example/token",
        "governance_client_id": "agent-server",
        "governance_client_secret": SecretStr("s3cr3t"),
    }


def _team_init_request() -> InitRequest:
    return InitRequest(
        governance_deployment_mode="team",
        governance_bridge_token=SecretStr("bridge-secret"),
    )


def _dormant_service(tmp_path):
    base = Config(
        deferred_init=True,
        conversations_path=tmp_path / "convs",
        bash_events_dir=tmp_path / "bash",
        **_central_fields(),
    )
    app = SimpleNamespace(state=SimpleNamespace(config=base))
    return InitService(app, base_config=base)  # type: ignore[arg-type]


def _reset_service_singletons() -> None:
    from openhands.agent_server import bash_service, conversation_service

    conversation_service._conversation_service = None
    bash_service._bash_event_service = None


@pytest.mark.asyncio
async def test_init_that_flips_a_personal_server_to_team_installs_the_guard(tmp_path):
    """A warm-pool server starts personal and only becomes team at /api/init,
    which builds its Config with model_copy and so never reaches create_app()."""
    _reset_service_singletons()
    service = _dormant_service(tmp_path)
    assert get_default_confirmation_handler() is None

    await service.initialize(_team_init_request())
    try:
        assert service.state == "ready"
        assert get_default_confirmation_handler() is refuse_subagent_pending_actions
        assert get_default_max_refusals() == MAX_REFUSALS_PER_RUN
    finally:
        await service.teardown()
        _reset_service_singletons()


@pytest.mark.asyncio
async def test_a_personal_init_does_not_turn_the_guard_on(tmp_path):
    _reset_service_singletons()
    service = _dormant_service(tmp_path)

    await service.initialize(InitRequest())
    try:
        assert get_default_confirmation_handler() is None
    finally:
        await service.teardown()
        _reset_service_singletons()


@pytest.mark.asyncio
async def test_a_failed_team_init_takes_the_guard_back_so_a_personal_retry_is_clean(
    tmp_path,
):
    service = _dormant_service(tmp_path)

    with patch(
        "openhands.agent_server.init_router.build_telemetry_sink",
        side_effect=RuntimeError("boom after the config was built"),
    ):
        with pytest.raises(HTTPException):
            await service.initialize(_team_init_request())

    assert service.state == "dormant"
    assert get_default_confirmation_handler() is None
    assert get_default_max_refusals() is None


@pytest.mark.asyncio
async def test_a_cancelled_team_init_takes_the_guard_back_too(tmp_path):
    """CancelledError is a BaseException, so an `except Exception` alone would
    let the guard stay on for a server that never became ready."""
    service = _dormant_service(tmp_path)

    with patch(
        "openhands.agent_server.init_router.build_telemetry_sink",
        side_effect=asyncio.CancelledError(),
    ):
        with pytest.raises(asyncio.CancelledError):
            await service.initialize(_team_init_request())

    assert get_default_confirmation_handler() is None
    assert get_default_max_refusals() is None


@pytest.mark.asyncio
async def test_a_failed_init_does_not_clear_a_guard_another_server_holds(tmp_path):
    """Two servers in one process: the failing one gives back only its own hold,
    so the other, still running, keeps its guard."""
    assert install_team_mode_subagent_guard(TEAM) is True  # a live team server
    service = _dormant_service(tmp_path)

    with patch(
        "openhands.agent_server.init_router.build_telemetry_sink",
        side_effect=RuntimeError("boom"),
    ):
        with pytest.raises(HTTPException):
            await service.initialize(_team_init_request())

    assert get_default_confirmation_handler() is refuse_subagent_pending_actions
    assert get_default_max_refusals() == MAX_REFUSALS_PER_RUN


def test_the_guard_stays_on_until_every_hold_is_released():
    assert install_team_mode_subagent_guard(TEAM) is True
    assert install_team_mode_subagent_guard(TEAM) is True

    release_team_mode_subagent_guard()
    assert get_default_confirmation_handler() is refuse_subagent_pending_actions

    release_team_mode_subagent_guard()
    assert get_default_confirmation_handler() is None


def test_releasing_more_often_than_installed_does_not_break_the_next_install():
    release_team_mode_subagent_guard()
    release_team_mode_subagent_guard()

    install_team_mode_subagent_guard(TEAM)
    assert get_default_confirmation_handler() is refuse_subagent_pending_actions
    release_team_mode_subagent_guard()
    assert get_default_confirmation_handler() is None


def test_a_personal_install_takes_no_hold():
    assert install_team_mode_subagent_guard(PERSONAL) is False
    install_team_mode_subagent_guard(TEAM)

    release_team_mode_subagent_guard()  # the only hold is the team one

    assert get_default_confirmation_handler() is None


def _scripted_agent_that_keeps_proposing_the_same_action(n: int):
    """A real agent whose LLM proposes the same confirmation-needing action n times."""
    llm = TestLLM.from_messages(
        [
            Message(
                role="assistant",
                content=[TextContent(text="")],
                tool_calls=[
                    MessageToolCall(
                        id=f"call_{i}",
                        name=FileEditorTool.name,
                        arguments=json.dumps({"command": "view", "path": "/tmp"}),
                        origin="completion",
                    )
                ],
            )
            for i in range(n)
        ]
    )
    return llm, Agent(llm=llm, tools=[Tool(name=FileEditorTool.name)])


def test_a_sub_agent_that_re_proposes_every_time_is_stopped_not_looped(tmp_path):
    """Review finding: with an automatic refusal and no bound, the resume loop
    never ended on its own (measured: 200 refusals in a row, stuck detection on
    or off). Real LocalConversation, scripted LLM, the real loop."""
    install_team_mode_subagent_guard(TEAM)
    llm, agent = _scripted_agent_that_keeps_proposing_the_same_action(50)
    conversation = LocalConversation(agent=agent, workspace=tmp_path, visualizer=None)
    conversation.set_confirmation_policy(AlwaysConfirm())
    conversation.send_message("do the thing")

    with pytest.raises(RefusalLimitExceeded):
        TaskManager()._run_until_finished("loop-task", conversation)

    # One LLM call per proposal: the first, plus one after each refusal, and the
    # last of those is the one the limit stops. Far fewer than the 50 scripted.
    assert llm._call_count == MAX_REFUSALS_PER_RUN + 1


def test_task_manager_turns_the_limit_into_a_failed_task_the_parent_can_read(
    tmp_path,
):
    install_team_mode_subagent_guard(TEAM)
    _llm, agent = _scripted_agent_that_keeps_proposing_the_same_action(50)
    conversation = LocalConversation(agent=agent, workspace=tmp_path, visualizer=None)
    conversation.set_confirmation_policy(AlwaysConfirm())
    manager = TaskManager()
    parent = MagicMock()
    parent._visualizer = None  # else its name becomes a MagicMock "sender"
    manager.attach_parent(parent)
    task = Task(
        id="failing-task",
        status=TaskStatus.RUNNING,
        conversation_id=conversation.id,
        conversation=conversation,
    )

    result = manager._run_task(task, "do the thing")

    assert result.status == TaskStatus.ERROR
    assert result.error is not None
    assert "need confirmation" in result.error
    assert str(MAX_REFUSALS_PER_RUN) in result.error
