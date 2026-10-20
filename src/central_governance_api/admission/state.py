"""The admission item state machine, as a table (same style as
``approvals/state_machine.py``). Pure: no I/O.

    pending -> checking -> rejected | check_failed | checked
    checked -> approved (a person, not the submitter)
    approved -> revoked
    anything that is not approved and not yet decided can be rejected by a person;
    rejected, check_failed, checked and revoked go back to pending by an explicit rerun.

There is no transition that leads to ``approved`` from anything but ``checked``, and
none from ``rejected``, ``check_failed`` or ``revoked``: those have no override, only a
rerun of the checks (Roy, 2026-10-20). ``START_CHECK``, ``CHECK_*`` are the system's
events; the check pipeline that sends them arrives in a later step, so no endpoint
sends them yet.
"""

from __future__ import annotations

from enum import StrEnum

from central_governance_api.admission.errors import AdmissionInvalidTransitionError


class Status(StrEnum):
    PENDING = "pending"
    CHECKING = "checking"
    REJECTED = "rejected"
    CHECK_FAILED = "check_failed"
    CHECKED = "checked"
    APPROVED = "approved"
    REVOKED = "revoked"


class Event(StrEnum):
    START_CHECK = "start_check"
    CHECK_REJECTED = "check_rejected"
    CHECK_FAILED = "check_failed"
    CHECK_PASSED = "check_passed"
    APPROVE = "approve"
    REJECT = "reject"
    REVOKE = "revoke"
    RERUN = "rerun"


STATUSES = tuple(s.value for s in Status)

_TRANSITIONS: dict[tuple[Status, Event], Status] = {
    (Status.PENDING, Event.START_CHECK): Status.CHECKING,
    (Status.CHECKING, Event.CHECK_REJECTED): Status.REJECTED,
    (Status.CHECKING, Event.CHECK_FAILED): Status.CHECK_FAILED,
    (Status.CHECKING, Event.CHECK_PASSED): Status.CHECKED,
    (Status.CHECKED, Event.APPROVE): Status.APPROVED,
    (Status.PENDING, Event.REJECT): Status.REJECTED,
    (Status.CHECKING, Event.REJECT): Status.REJECTED,
    (Status.CHECKED, Event.REJECT): Status.REJECTED,
    (Status.CHECK_FAILED, Event.REJECT): Status.REJECTED,
    (Status.APPROVED, Event.REVOKE): Status.REVOKED,
    (Status.REJECTED, Event.RERUN): Status.PENDING,
    (Status.CHECK_FAILED, Event.RERUN): Status.PENDING,
    (Status.CHECKED, Event.RERUN): Status.PENDING,
    (Status.REVOKED, Event.RERUN): Status.PENDING,
}


def target(status: Status, event: Event) -> Status:
    try:
        return _TRANSITIONS[(status, event)]
    except KeyError:
        raise AdmissionInvalidTransitionError() from None


def allowed_events(status: Status) -> tuple[Event, ...]:
    return tuple(e for (s, e) in _TRANSITIONS if s is status)
