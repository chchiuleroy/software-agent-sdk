"""The admission state table. The point of each test is a guarantee someone could break
by editing one line of the table."""

from __future__ import annotations

import pytest

from central_governance_api.admission.errors import AdmissionInvalidTransitionError
from central_governance_api.admission.state import (
    STATUSES,
    Event,
    Status,
    allowed_events,
    target,
)


def test_every_status_the_database_allows_is_in_the_machine():
    from central_governance_api.models import ADMISSION_STATUSES

    assert set(STATUSES) == set(ADMISSION_STATUSES) == {s.value for s in Status}


def test_nothing_but_a_checked_item_can_be_approved():
    # Why: this is "checked first, then allowed". An edit that lets an item reach
    # approved from pending, rejected, check_failed or revoked removes the check.
    for status in Status:
        if status is Status.CHECKED:
            assert target(status, Event.APPROVE) is Status.APPROVED
        else:
            with pytest.raises(AdmissionInvalidTransitionError):
                target(status, Event.APPROVE)


def test_no_event_leads_to_approved_except_approve():
    from central_governance_api.admission import state

    leading = {e for (_, e), t in state._TRANSITIONS.items() if t is Status.APPROVED}
    assert leading == {Event.APPROVE}


@pytest.mark.parametrize(
    "status", [Status.REJECTED, Status.CHECK_FAILED, Status.REVOKED]
)
def test_a_failed_or_revoked_item_has_no_override_only_a_rerun(status):
    # Why (Roy 2026-10-20): "checked, no security concern, then allowed"; a failed
    # check is not something a person can wave through.
    assert Event.APPROVE not in allowed_events(status)
    assert target(status, Event.RERUN) is Status.PENDING


def test_only_an_approved_item_can_be_revoked():
    for status in Status:
        if status is Status.APPROVED:
            assert target(status, Event.REVOKE) is Status.REVOKED
        else:
            with pytest.raises(AdmissionInvalidTransitionError):
                target(status, Event.REVOKE)


def test_an_approved_item_cannot_simply_be_rejected_or_rerun():
    # Why: taking approval away is a revoke, a deliberate and separately audited act.
    for event in (Event.REJECT, Event.RERUN, Event.APPROVE):
        with pytest.raises(AdmissionInvalidTransitionError):
            target(Status.APPROVED, event)


def test_the_checks_lead_from_checking_to_exactly_three_outcomes():
    assert target(Status.PENDING, Event.START_CHECK) is Status.CHECKING
    assert target(Status.CHECKING, Event.CHECK_REJECTED) is Status.REJECTED
    assert target(Status.CHECKING, Event.CHECK_FAILED) is Status.CHECK_FAILED
    assert target(Status.CHECKING, Event.CHECK_PASSED) is Status.CHECKED
    for event in (Event.CHECK_REJECTED, Event.CHECK_FAILED, Event.CHECK_PASSED):
        for status in Status:
            if status is not Status.CHECKING:
                with pytest.raises(AdmissionInvalidTransitionError):
                    target(status, event)
