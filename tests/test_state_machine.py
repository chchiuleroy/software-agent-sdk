"""Exhaustive tests for the pure approval state machine (no DB, no HTTP).

Each test encodes *why* a transition is legal or illegal, not just that
`next_status()` returns some value — per this project's testing
convention (see CLAUDE.md "測試要驗證『為什麼』，不只是『有沒有』"): a
test that only pins down current behavior without saying why it matters
would keep passing even if the business rule it's supposed to protect
silently regressed.
"""

from __future__ import annotations

import pytest

from central_governance_api.approvals.state_machine import (
    TERMINAL_STATUSES,
    ApprovalEvent,
    ApprovalStatus,
    IllegalTransitionError,
    is_terminal,
    legal_events,
    next_status,
)
from central_governance_api.models import APPROVAL_STATUSES


def test_status_enum_matches_db_schema_exactly():
    """The DB CHECK constraint (models.APPROVAL_STATUSES) and this pure
    enum must never drift apart — if they do, either the DB will reject a
    status this module thinks is valid, or this module will reject one
    the DB would happily store, and the mismatch would only surface at
    runtime against a real database.
    """
    assert {s.value for s in ApprovalStatus} == set(APPROVAL_STATUSES)


@pytest.mark.parametrize(
    ("current", "event", "expected"),
    [
        (ApprovalStatus.PENDING, ApprovalEvent.DECIDE_ACCEPT, ApprovalStatus.ACCEPTED),
        (ApprovalStatus.PENDING, ApprovalEvent.DECIDE_REJECT, ApprovalStatus.REJECTED),
        (ApprovalStatus.PENDING, ApprovalEvent.CANCEL, ApprovalStatus.CANCELLED),
        (ApprovalStatus.PENDING, ApprovalEvent.EXPIRE, ApprovalStatus.EXPIRED),
        (ApprovalStatus.ACCEPTED, ApprovalEvent.CLAIM, ApprovalStatus.EXECUTING),
        (
            ApprovalStatus.ACCEPTED,
            ApprovalEvent.REPORT_PRE_CLAIM_ABORT,
            ApprovalStatus.CANCELLED,
        ),
        (ApprovalStatus.ACCEPTED, ApprovalEvent.EXPIRE, ApprovalStatus.EXPIRED),
        (
            ApprovalStatus.EXECUTING,
            ApprovalEvent.REPORT_SUCCESS,
            ApprovalStatus.APPLIED,
        ),
        (
            ApprovalStatus.EXECUTING,
            ApprovalEvent.REPORT_FAILURE_DEFINITE,
            ApprovalStatus.FAILED_DEFINITE,
        ),
        (
            ApprovalStatus.EXECUTING,
            ApprovalEvent.REPORT_FAILURE_UNKNOWN,
            ApprovalStatus.FAILED_UNKNOWN,
        ),
        (ApprovalStatus.EXECUTING, ApprovalEvent.EXPIRE, ApprovalStatus.FAILED_UNKNOWN),
    ],
)
def test_legal_transitions(current, event, expected):
    assert next_status(current, event) == expected


def test_claimed_but_never_reported_fails_closed_not_silently_lost():
    """This is the one transition directly attested by the wiki record
    (v10: "crash 後無法確認就 fail closed") rather than reasoned by
    analogy — a lease that expires mid-execution must land on
    FAILED_UNKNOWN, never silently stay EXECUTING or jump straight to a
    definite outcome nobody actually confirmed.
    """
    assert (
        next_status(ApprovalStatus.EXECUTING, ApprovalEvent.EXPIRE)
        == ApprovalStatus.FAILED_UNKNOWN
    )


@pytest.mark.parametrize(
    ("current", "event"),
    [
        # Can't decide twice.
        (ApprovalStatus.ACCEPTED, ApprovalEvent.DECIDE_ACCEPT),
        (ApprovalStatus.REJECTED, ApprovalEvent.DECIDE_ACCEPT),
        # Can't claim before a decision.
        (ApprovalStatus.PENDING, ApprovalEvent.CLAIM),
        # Can't claim twice (already executing).
        (ApprovalStatus.EXECUTING, ApprovalEvent.CLAIM),
        # Can't report a result before claiming.
        (ApprovalStatus.PENDING, ApprovalEvent.REPORT_SUCCESS),
        (ApprovalStatus.ACCEPTED, ApprovalEvent.REPORT_SUCCESS),
        # Pre-claim abort only makes sense before a claim exists.
        (ApprovalStatus.EXECUTING, ApprovalEvent.REPORT_PRE_CLAIM_ABORT),
        (ApprovalStatus.PENDING, ApprovalEvent.REPORT_PRE_CLAIM_ABORT),
        # Cancel is only legal pre-decision (see authorize.py module
        # docstring: post-acceptance abandonment goes through the
        # pre-claim-abort report-result event instead, not cancel — one
        # semantic action should not have two competing endpoints).
        (ApprovalStatus.ACCEPTED, ApprovalEvent.CANCEL),
        (ApprovalStatus.EXECUTING, ApprovalEvent.CANCEL),
    ],
)
def test_illegal_transitions_raise(current, event):
    with pytest.raises(IllegalTransitionError) as exc_info:
        next_status(current, event)
    assert exc_info.value.current is current
    assert exc_info.value.event is event


_SORTED_TERMINAL_STATUSES = sorted(TERMINAL_STATUSES, key=lambda s: s.value)


@pytest.mark.parametrize("status", _SORTED_TERMINAL_STATUSES)
def test_terminal_statuses_accept_no_further_events(status):
    """A terminal status is exactly the set of statuses with zero legal
    outgoing events — this is the property routers rely on to decide
    "may a ReconciliationFinding still be filed" without a separate,
    independently-maintained terminal-status check.
    """
    assert is_terminal(status)
    assert legal_events(status) == frozenset()
    for event in ApprovalEvent:
        with pytest.raises(IllegalTransitionError):
            next_status(status, event)


@pytest.mark.parametrize(
    ("status", "expected_events"),
    [
        (
            ApprovalStatus.PENDING,
            frozenset(
                {
                    ApprovalEvent.DECIDE_ACCEPT,
                    ApprovalEvent.DECIDE_REJECT,
                    ApprovalEvent.CANCEL,
                    ApprovalEvent.EXPIRE,
                }
            ),
        ),
        (
            ApprovalStatus.ACCEPTED,
            frozenset(
                {
                    ApprovalEvent.CLAIM,
                    ApprovalEvent.REPORT_PRE_CLAIM_ABORT,
                    ApprovalEvent.EXPIRE,
                }
            ),
        ),
        (
            ApprovalStatus.EXECUTING,
            frozenset(
                {
                    ApprovalEvent.REPORT_SUCCESS,
                    ApprovalEvent.REPORT_FAILURE_DEFINITE,
                    ApprovalEvent.REPORT_FAILURE_UNKNOWN,
                    ApprovalEvent.EXPIRE,
                }
            ),
        ),
    ],
)
def test_non_terminal_statuses_have_exactly_the_expected_legal_events(
    status, expected_events
):
    """Exact-set, not just non-empty — review caught that the original
    version of this test (`legal_events(status) != frozenset()`) would
    keep passing even if an illegal transition were accidentally added
    (e.g. `PENDING + REPORT_FAILURE_UNKNOWN`), since the *count* of legal
    events isn't what a stray entry changes in an interesting way, and
    the parametrized `test_legal_transitions` above only lists the
    transitions this module intends to be legal, so it can't catch an
    extra one that wasn't supposed to exist. Comparing to the exact
    expected set is the only way an unintended addition to `_TRANSITIONS`
    actually fails a test.
    """
    assert not is_terminal(status)
    assert legal_events(status) == expected_events


def test_every_status_is_reachable_as_a_target():
    """Catches a status that was added to the enum/DB schema but never
    wired into any transition — such a status could only ever be reached
    by a direct DB write, never through the approval workflow itself.
    """
    reachable_targets = {target for target in _all_targets()} | {
        ApprovalStatus.PENDING
    }  # the row's own initial status at INSERT
    assert reachable_targets == set(ApprovalStatus)


def _all_targets():
    for status in ApprovalStatus:
        for event in legal_events(status):
            yield next_status(status, event)
