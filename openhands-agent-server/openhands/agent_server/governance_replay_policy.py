"""Which recovery behaviour an action gets after a crash (item 1.16, replay column).

Today every governed action is executed at most once: a tool call that a crash
interrupted gets a non-retryable ``AgentErrorEvent`` and is never run again (see
``governance/recovery/design.md``). Nothing in the agent-server consults this module;
there is no action class that may be replayed, so there is nothing to decide yet. It
exists so that the rule is written down and pinned by tests BEFORE the first
replayable class is added, instead of being invented under the pressure of adding it.

The rule is the one in design.md section 6, and it only ever tightens:

* a replay happens only if the policy stored with the approval AND the policy the
  tool declares now are BOTH ``replay_safe``;
* a tool that today declares ``at_most_once`` vetoes a stored ``replay_safe``;
* a tool that today declares ``replay_safe`` cannot upgrade a stored ``at_most_once``;
* a missing, unrecognised or malformed value on either side counts as
  ``at_most_once`` (the safe side), never as "no opinion".
"""

from __future__ import annotations

from enum import StrEnum


class ReplayPolicy(StrEnum):
    AT_MOST_ONCE = "at_most_once"
    REPLAY_SAFE = "replay_safe"


def parse_replay_policy(value: object) -> ReplayPolicy:
    """The policy a stored or declared value stands for; anything that is not exactly
    the string ``replay_safe`` is ``at_most_once``."""
    if isinstance(value, str) and value == ReplayPolicy.REPLAY_SAFE.value:
        return ReplayPolicy.REPLAY_SAFE
    return ReplayPolicy.AT_MOST_ONCE


def effective_replay_policy(stored: object, declared: object) -> ReplayPolicy:
    """What recovery may do with an interrupted action: ``REPLAY_SAFE`` only if both
    the stored and the currently declared policy say so."""
    if (
        parse_replay_policy(stored) is ReplayPolicy.REPLAY_SAFE
        and parse_replay_policy(declared) is ReplayPolicy.REPLAY_SAFE
    ):
        return ReplayPolicy.REPLAY_SAFE
    return ReplayPolicy.AT_MOST_ONCE
