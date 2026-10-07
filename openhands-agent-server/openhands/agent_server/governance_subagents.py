"""Refuse a sub-agent's pending actions in team mode instead of auto-approving.

``TaskManager._run_until_finished`` (openhands-tools) resumes a sub-agent that
stopped at WAITING_FOR_CONFIRMATION when ``handler is None or handler(...)``.
The handler is a callable, so it cannot be passed through the JSON
``Tool(params=...)`` the agent-server builds tools from, and nothing else
passes one: it is always ``None``. Every pending sub-agent action was
therefore run with neither central approval nor user confirmation, which
sidesteps the approval that the parent conversation's own actions need.

``openhands-tools`` has no notion of team mode (``governance_deployment_mode``
is an agent-server setting), so the decision is made here and handed over
through the tools package's process-wide default handler. That one seam covers
every place a sub-agent is resumed: the ``task`` tool, the ``workflow`` tool
(which builds its own ``TaskManager`` per call, out of reach of any tool-level
hook) and ``DelegateExecutor``. Personal mode is not touched and keeps the
upstream behaviour.

Refusing needs a bound. After a refusal the resume loop just resumes the
sub-agent, and nothing in it limits how often that repeats. In a one-off run (a
real ``LocalConversation`` driven by a scripted LLM that re-proposed the same
action every time) 200 refusals in a row were never cut off, with stuck
detection on or off; the run ended only when the script ran out. With a human
handler a person eventually stops it; with an automatic refusal nobody does,
so each round would be a paid LLM call with no end. The limit is passed to the
tools seam along with the handler; past it the run raises
``RefusalLimitExceeded``, which ``TaskManager`` turns into a failed task whose
message the parent agent receives.

The guard is process-wide, like the environment that sets
``governance_deployment_mode``. It is held by reference count so that two
servers in one process (an embedding host, tests) cannot switch each other's
guard off: each team-mode server takes a hold and the guard goes only when the
last hold is released. A server that gives up on a failed initialisation
releases just its own hold.

Scope and limits:

* This only refuses. Sending the sub-agent's action to central for approval
  is a separate design question (see the role-permission item in todo.md).
* ``TaskManager`` answers a refusal with the fixed text "User rejected the
  actions"; in team mode nobody was asked, and that text is not changed here.
* ``MAX_REFUSALS_PER_RUN`` is a judgement call, not a measured value.
* One mode per process is the supported shape. A personal-mode server created
  in a process that already holds a team guard inherits it.
* Not covered: a caller that resumes a conversation by calling
  ``LocalConversation.run()`` itself, such as the SDK's ``run_goal()`` or an
  application embedding the SDK. ``LocalConversation.run()`` runs pending
  actions on its second call by design. Nothing in this repository calls
  ``run_goal()``; the agent-server's own goal loop goes through
  ``EventService.run()``.
"""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING

from openhands.sdk.logger import get_logger
from openhands.tools.task.manager import set_default_confirmation_handler


if TYPE_CHECKING:
    from openhands.agent_server.config import Config
    from openhands.sdk.event import ActionEvent


logger = get_logger(__name__)

# How many times one run of one sub-agent may have its pending actions refused
# before the run is failed. Enough for it to try a few alternatives, small enough
# to bound cost.
MAX_REFUSALS_PER_RUN = 5

_holds = 0
_holds_lock = threading.Lock()


def refuse_subagent_pending_actions(
    task_id: str,
    pending_actions: list[ActionEvent],
) -> bool:
    """A sub-agent confirmation handler that always refuses."""
    logger.warning(
        "Refusing %d pending sub-agent action(s) for task %s: team mode does "
        "not auto-approve them and has no central approval path for them.",
        len(pending_actions),
        task_id,
    )
    return False


def install_team_mode_subagent_guard(config: Config) -> bool:
    """Take a hold on the team-mode sub-agent guard if the server is in team mode.

    Returns ``True`` if a hold was taken, which the caller must release with
    ``release_team_mode_subagent_guard()`` if it later gives up (a startup that
    stays up never releases). Returns ``False`` and does nothing outside team
    mode. Call it from every place that settles the server's mode:
    ``create_app`` for a server that starts in team mode, and the deferred-init
    flip from personal to team.
    """
    global _holds
    if config.governance_deployment_mode != "team":
        return False
    with _holds_lock:
        _holds += 1
        set_default_confirmation_handler(
            refuse_subagent_pending_actions, max_refusals=MAX_REFUSALS_PER_RUN
        )
    return True


def release_team_mode_subagent_guard() -> None:
    """Give back a hold taken by ``install_team_mode_subagent_guard``.

    The guard is switched off only when no hold is left.
    """
    global _holds
    with _holds_lock:
        _holds = max(0, _holds - 1)
        if _holds == 0:
            set_default_confirmation_handler(None)
