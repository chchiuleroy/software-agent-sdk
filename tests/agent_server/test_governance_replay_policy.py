"""The replay-policy rule (governance_replay_policy.py): it may only tighten.

Each case is a way the rule could quietly loosen. The first two rows are the only
combination that allows a replay, and the rest must all stay at most once.
"""

from __future__ import annotations

import itertools

import pytest

from openhands.agent_server.governance_replay_policy import (
    ReplayPolicy,
    effective_replay_policy,
    parse_replay_policy,
)


SAFE = "replay_safe"
ONCE = "at_most_once"
# values a stored record or a tool declaration could carry that are not the policy
JUNK = [None, "", "REPLAY_SAFE", " replay_safe", "replay_safe ", "yes", True, 1, [SAFE]]


def test_only_both_sides_safe_allows_a_replay():
    assert effective_replay_policy(SAFE, SAFE) is ReplayPolicy.REPLAY_SAFE


@pytest.mark.parametrize(
    "stored,declared",
    [(SAFE, ONCE), (ONCE, SAFE), (ONCE, ONCE)],
)
def test_one_side_at_most_once_means_at_most_once(stored, declared):
    assert effective_replay_policy(stored, declared) is ReplayPolicy.AT_MOST_ONCE


def test_a_tool_that_declares_safe_now_cannot_upgrade_what_was_stored():
    """The reverse of the veto: a later, looser declaration must not widen an
    approval that was issued as at-most-once."""
    assert effective_replay_policy(ONCE, SAFE) is ReplayPolicy.AT_MOST_ONCE


@pytest.mark.parametrize("junk", JUNK)
def test_anything_unrecognised_counts_as_at_most_once(junk):
    assert parse_replay_policy(junk) is ReplayPolicy.AT_MOST_ONCE
    assert effective_replay_policy(junk, SAFE) is ReplayPolicy.AT_MOST_ONCE
    assert effective_replay_policy(SAFE, junk) is ReplayPolicy.AT_MOST_ONCE


def test_no_pair_but_both_safe_ever_replays():
    values = [SAFE, ONCE, *JUNK]
    allowed = [
        (s, d)
        for s, d in itertools.product(values, values)
        if effective_replay_policy(s, d) is ReplayPolicy.REPLAY_SAFE
    ]
    assert allowed == [(SAFE, SAFE)]
