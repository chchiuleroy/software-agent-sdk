"""The default confirmation handler, and the bound on how often it may refuse.

A sub-agent that stops for confirmation is resumed by a loop that has no limit
of its own. With a handler that refuses automatically nobody ever stops it, so
the default handler can carry a refusal limit. The count has to belong to one
run: task ids come from ``len(self._tasks) + 1`` per manager, so two managers
(and every ``WorkflowContext`` call builds a new one) both hand out
``task_00000001``.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from openhands.sdk.conversation.state import ConversationExecutionStatus
from openhands.tools.task.manager import (
    ConfirmationGate,
    RefusalLimitExceeded,
    TaskManager,
    get_default_confirmation_handler,
    get_default_max_refusals,
    set_default_confirmation_handler,
)


@pytest.fixture(autouse=True)
def _no_default_handler_left_behind():
    yield
    set_default_confirmation_handler(None)


def _refuse(_task_id, _pending) -> bool:
    return False


def _pending() -> list:
    return [MagicMock(name="pending-action")]


def test_without_any_handler_a_sub_agent_is_let_through():
    """The upstream behaviour: nothing configured, nothing refused."""
    assert ConfirmationGate(None).allows("task_00000001", _pending()) is True


def test_the_default_handler_decides_when_the_manager_has_none():
    set_default_confirmation_handler(_refuse)

    assert ConfirmationGate(None).allows("task_00000001", _pending()) is False


def test_a_handler_given_to_the_manager_beats_the_default():
    set_default_confirmation_handler(_refuse, max_refusals=1)

    assert ConfirmationGate(lambda _t, _p: True).allows("t", _pending()) is True


def test_refusals_up_to_the_limit_are_plain_refusals():
    set_default_confirmation_handler(_refuse, max_refusals=3)
    gate = ConfirmationGate(None)

    assert [gate.allows("t", _pending()) for _ in range(3)] == [False] * 3


def test_the_refusal_after_the_limit_raises():
    set_default_confirmation_handler(_refuse, max_refusals=3)
    gate = ConfirmationGate(None)
    for _ in range(3):
        gate.allows("t", _pending())

    with pytest.raises(RefusalLimitExceeded, match="3 refusals"):
        gate.allows("t", _pending())


def test_runs_that_share_a_task_id_do_not_share_a_refusal_count():
    """The collision this design avoids: every manager's first task is
    ``task_00000001``, so a count keyed by task id would add up refusals from
    unrelated sub-agents and trip a run that had barely been refused."""
    set_default_confirmation_handler(_refuse, max_refusals=3)

    for _run in range(5):  # 15 refusals in all, never more than 3 in one run
        gate = ConfirmationGate(None)
        for _ in range(3):
            assert gate.allows("task_00000001", _pending()) is False


def test_a_handler_given_to_the_manager_is_never_limited():
    set_default_confirmation_handler(_refuse, max_refusals=1)
    gate = ConfirmationGate(_refuse)

    assert [gate.allows("t", _pending()) for _ in range(20)] == [False] * 20


def test_no_limit_means_the_default_handler_refuses_for_ever():
    set_default_confirmation_handler(_refuse)
    gate = ConfirmationGate(None)

    assert [gate.allows("t", _pending()) for _ in range(50)] == [False] * 50
    assert get_default_max_refusals() is None


def test_clearing_the_default_handler_clears_its_limit_too():
    set_default_confirmation_handler(_refuse, max_refusals=3)
    set_default_confirmation_handler(None)

    assert get_default_confirmation_handler() is None
    assert get_default_max_refusals() is None


def test_a_limit_without_a_handler_is_not_kept():
    """No handler means no limit: the pair is set or cleared together, so a
    caller that clears the handler cannot leave a limit behind for the next one."""
    set_default_confirmation_handler(None, max_refusals=3)

    assert get_default_confirmation_handler() is None
    assert get_default_max_refusals() is None


class _FakeSubAgent:
    """Waits for confirmation until its pending actions have been rejected
    ``refusals_needed`` times, then finishes."""

    def __init__(self, refusals_needed: int) -> None:
        self._left = refusals_needed
        self._runs = 0
        self.state = SimpleNamespace(
            execution_status=ConversationExecutionStatus.WAITING_FOR_CONFIRMATION,
            events=[],
        )

    def run(self) -> None:
        # Resuming it while its actions are still pending is the bug under
        # test; fail loudly instead of looping for ever.
        self._runs += 1
        assert self._runs <= 20, "resumed without its pending actions rejected"

    def reject_pending_actions(self, _reason: str) -> None:
        self._left -= 1
        if self._left <= 0:
            self.state.execution_status = ConversationExecutionStatus.FINISHED


def test_each_task_manager_run_gets_its_own_gate():
    """Two runs of the same manager, three refusals each, with a limit of three:
    the second run must not inherit the first run's count."""
    set_default_confirmation_handler(_refuse, max_refusals=3)
    manager = TaskManager()

    for _run in range(2):
        with patch(
            "openhands.tools.task.manager.ConversationState.get_unmatched_actions",
            return_value=_pending(),
        ):
            manager._run_until_finished(
                "task_00000001",
                _FakeSubAgent(refusals_needed=3),  # type: ignore[arg-type]
            )


def test_a_run_that_is_refused_past_the_limit_raises_out_of_the_manager():
    set_default_confirmation_handler(_refuse, max_refusals=3)

    with (
        patch(
            "openhands.tools.task.manager.ConversationState.get_unmatched_actions",
            return_value=_pending(),
        ),
        pytest.raises(RefusalLimitExceeded),
    ):
        TaskManager()._run_until_finished(
            "task_00000001",
            _FakeSubAgent(refusals_needed=99),  # type: ignore[arg-type]
        )


def test_a_handler_given_to_the_manager_that_refuses_still_rejects_then_resumes():
    """The upstream loop, unchanged for a manager that has its own handler: a
    refusal rejects the pending actions and resumes the sub-agent, however often,
    with no limit and no exception."""
    set_default_confirmation_handler(_refuse, max_refusals=1)  # must not apply
    agent = _FakeSubAgent(refusals_needed=10)

    with patch(
        "openhands.tools.task.manager.ConversationState.get_unmatched_actions",
        return_value=_pending(),
    ):
        TaskManager(confirmation_handler=_refuse)._run_until_finished(
            "task_00000001",
            agent,  # type: ignore[arg-type]
        )

    assert agent.state.execution_status == ConversationExecutionStatus.FINISHED
