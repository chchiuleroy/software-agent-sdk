"""Pure state-transition logic for ``PendingApprovalRecord.status``.

v11 §11 step 2 (first half — "conditional-update 邏輯"'s state-machine
half). This module has no DB/HTTP dependency by design: every legal
transition is a plain function of ``(current_status, event)``, so the
whole machine can be exhaustively unit-tested without a running Postgres.
The actual conditional update (``UPDATE ... WHERE status = <expected>``
inside one DB transaction) that *applies* a transition lives in the
router layer, which calls :func:`next_status` first to know what to write
and to reject the request before touching the DB at all if the event
isn't legal from the row's last-known status — the DB's own
``WHERE status = <expected>`` is still the real race guard (this function
can be stale by the time the UPDATE runs; that's fine, the UPDATE
affecting 0 rows is what actually catches a concurrent transition, not
this check).

Two transitions here are DESIGN DECISIONS reconstructed from the wiki
narrative of the v11 design review, not copied verbatim from the design
document itself (the document lived in a prior session's scratchpad and
was never committed) — flagged individually below for the next code
review to confirm against what v11 actually specified:

- ``ACCEPTED + REPORT_PRE_CLAIM_ABORT -> CANCELLED``: v11 round 10 added a
  ``report-result`` variant that omits ``execution_attempt_id`` for the
  case where the caller gives up on an accepted-but-never-claimed action
  (this specifically resolved a contradiction: the design used to require
  every ``report-result`` call to carry an attempt id, which is
  impossible before ``claim`` ever happens). The wiki record confirms the
  *existence* of this event and why it exists, not which status it lands
  on. ``CANCELLED`` was chosen here as the closest existing terminal
  status to "the requester deliberately gave up before anything ran".
- ``ACCEPTED + EXPIRE -> EXPIRED``: no direct textual support found;
  reasoned by analogy with ``PENDING + EXPIRE -> EXPIRED`` (an
  execution_deadline lapsing before claim is the same kind of "the clock
  ran out with nothing having started" event as expires_at lapsing before
  a decision).

``EXECUTING + EXPIRE -> FAILED_UNKNOWN`` (lease expiry with no report) is
NOT a guess — it directly matches the wiki's v10 record: "crash 後無法確
認就 fail closed", i.e. a claimed-but-never-reported attempt must fail
closed to unknown, not silently vanish.
"""

from __future__ import annotations

from enum import StrEnum


class ApprovalStatus(StrEnum):
    """Mirrors ``models.APPROVAL_STATUSES`` — kept as a distinct enum here
    (rather than importing the DB module) so this module has zero
    SQLAlchemy dependency; a test asserts the two stay in sync.
    """

    PENDING = "pending"
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    EXECUTING = "executing"
    APPLIED = "applied"
    FAILED_DEFINITE = "failed_definite"
    FAILED_UNKNOWN = "failed_unknown"
    EXPIRED = "expired"
    CANCELLED = "cancelled"


TERMINAL_STATUSES: frozenset[ApprovalStatus] = frozenset(
    {
        ApprovalStatus.REJECTED,
        ApprovalStatus.APPLIED,
        ApprovalStatus.FAILED_DEFINITE,
        ApprovalStatus.FAILED_UNKNOWN,
        ApprovalStatus.EXPIRED,
        ApprovalStatus.CANCELLED,
    }
)
"""Once in one of these, the row's ``status`` never changes again — only
``ReconciliationFinding`` rows may accumulate on top (evidence, not a new
state transition; see ``models.ReconciliationFinding``'s docstring)."""


class ApprovalEvent(StrEnum):
    DECIDE_ACCEPT = "decide_accept"
    DECIDE_REJECT = "decide_reject"
    CANCEL = "cancel"
    CLAIM = "claim"
    REPORT_PRE_CLAIM_ABORT = "report_pre_claim_abort"
    REPORT_SUCCESS = "report_success"
    REPORT_FAILURE_DEFINITE = "report_failure_definite"
    REPORT_FAILURE_UNKNOWN = "report_failure_unknown"
    EXPIRE = "expire"
    """Background sweep only — no client-facing endpoint raises this
    directly. Step 3 (LISTEN/NOTIFY) or a simple periodic sweep is
    responsible for finding rows past ``expires_at``/``execution_deadline``/
    ``executing_lease_expires_at`` and applying this event; this module
    only defines what happens when it does.

    Review note: this single event stands in for three *different* deadline
    columns depending on ``current`` (PENDING → ``expires_at``, ACCEPTED →
    ``execution_deadline``, EXECUTING → ``executing_lease_expires_at``).
    That's fine for this pure module — it only needs to know "the clock ran
    out", not which clock — but whoever implements the conditional UPDATE
    for this event MUST include the matching deadline-has-passed predicate
    in the SQL ``WHERE`` clause (alongside ``WHERE status = <expected>``),
    not just call :func:`next_status` and trust it: this function has no
    idea what time it is and cannot validate that the deadline has actually
    passed."""


class IllegalTransitionError(Exception):
    """Raised when ``event`` is not valid from ``current``.

    Callers (routers) should map this to HTTP 409 Conflict, not 400 — it
    means the record's state doesn't support this request right now (e.g.
    someone already decided it, or claimed it), not that the request body
    itself was malformed.
    """

    def __init__(self, *, current: ApprovalStatus, event: ApprovalEvent) -> None:
        self.current = current
        self.event = event
        super().__init__(
            f"event {event.value!r} is not valid from status {current.value!r}"
        )


_TRANSITIONS: dict[tuple[ApprovalStatus, ApprovalEvent], ApprovalStatus] = {
    (ApprovalStatus.PENDING, ApprovalEvent.DECIDE_ACCEPT): ApprovalStatus.ACCEPTED,
    (ApprovalStatus.PENDING, ApprovalEvent.DECIDE_REJECT): ApprovalStatus.REJECTED,
    (ApprovalStatus.PENDING, ApprovalEvent.CANCEL): ApprovalStatus.CANCELLED,
    (ApprovalStatus.PENDING, ApprovalEvent.EXPIRE): ApprovalStatus.EXPIRED,
    (ApprovalStatus.ACCEPTED, ApprovalEvent.CLAIM): ApprovalStatus.EXECUTING,
    # Lands on the same terminal status as PENDING+CANCEL. Review note:
    # this is an acceptable choice (CANCELLED is a more honest label than
    # FAILED_DEFINITE for "nothing was ever attempted"), but because the
    # two events share a target status, whoever writes the audit/decision
    # record for this transition MUST persist which event actually fired
    # (REPORT_PRE_CLAIM_ABORT vs. plain pre-decision CANCEL) — this module
    # only tracks the current status, not transition history, so losing
    # that distinction at the DB-write layer would be unrecoverable later.
    (
        ApprovalStatus.ACCEPTED,
        ApprovalEvent.REPORT_PRE_CLAIM_ABORT,
    ): ApprovalStatus.CANCELLED,
    (ApprovalStatus.ACCEPTED, ApprovalEvent.EXPIRE): ApprovalStatus.EXPIRED,
    (ApprovalStatus.EXECUTING, ApprovalEvent.REPORT_SUCCESS): ApprovalStatus.APPLIED,
    (
        ApprovalStatus.EXECUTING,
        ApprovalEvent.REPORT_FAILURE_DEFINITE,
    ): ApprovalStatus.FAILED_DEFINITE,
    (
        ApprovalStatus.EXECUTING,
        ApprovalEvent.REPORT_FAILURE_UNKNOWN,
    ): ApprovalStatus.FAILED_UNKNOWN,
    (ApprovalStatus.EXECUTING, ApprovalEvent.EXPIRE): ApprovalStatus.FAILED_UNKNOWN,
}
"""Deliberately NOT a mapping of ``current -> {allowed events}`` — keying
directly on ``(current, event)`` makes an illegal combination a plain
``KeyError`` in :func:`next_status`, so there is no separate "is this
event even applicable" branch that could drift out of sync with this
table."""


def next_status(current: ApprovalStatus, event: ApprovalEvent) -> ApprovalStatus:
    """The status ``current`` transitions to when ``event`` occurs, or
    raises :class:`IllegalTransitionError` if that combination isn't a
    legal transition (including: ``current`` is already terminal)."""
    try:
        return _TRANSITIONS[(current, event)]
    except KeyError:
        raise IllegalTransitionError(current=current, event=event) from None


def is_terminal(status: ApprovalStatus) -> bool:
    return status in TERMINAL_STATUSES


def legal_events(current: ApprovalStatus) -> frozenset[ApprovalEvent]:
    """Every event that is legal from ``current`` — used by routers to
    produce a useful 409 error body (what *would* have worked) and by
    tests to assert terminal statuses truly have none."""
    return frozenset(event for (status, event) in _TRANSITIONS if status is current)
