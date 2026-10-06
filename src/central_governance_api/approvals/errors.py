"""Router-facing error types for the approval workflow, on top of the
ones :mod:`state_machine` and :mod:`authorize` already define. Kept
separate from those two modules so they stay zero-SQLAlchemy/zero-HTTP —
these exist specifically because a router needs them; nothing pure does.

All of these, plus ``IllegalTransitionError``, ``AuthorizationDeniedError``,
and ``IdempotencyKeyReusedError``, are registered as FastAPI exception
handlers in ``main.py`` rather than caught with try/except in every route
handler — mirrors the sibling ``openhands-sdk-governed`` repo's
``SelfApprovalDeniedError -> 403`` pattern (see wiki
``project_openhands_governance_platform.md``, "Identity-aware
self-approval 落地實作").
"""

from __future__ import annotations

import uuid


class RecordNotFoundError(Exception):
    """No ``PendingApprovalRecord`` with this id. Maps to HTTP 404."""

    def __init__(self, *, approval_id: uuid.UUID) -> None:
        self.approval_id = approval_id
        super().__init__(f"no approval request with id {approval_id}")


class DigestMismatchError(Exception):
    """CREATE only: the client-submitted ``action_payload_digest`` doesn't
    match what :func:`digest.compute_display_digest` derives from the
    other submitted fields — see ``digest.py``'s module docstring for why
    this check exists and why it only runs at create time. Maps to HTTP
    400: the request body itself is internally inconsistent, not a
    conflict with server state.
    """


class ExecutionCommitmentMismatchError(Exception):
    """CLAIM only: the record was created with an ``execution_commitment`` and
    the claiming device did not present the same one (or none). No lease is
    handed out. Maps to HTTP 409. The message never includes either value."""

    def __init__(self, *, approval_id: uuid.UUID) -> None:
        self.approval_id = approval_id
        super().__init__(
            f"execution commitment for approval {approval_id} was not presented "
            "or does not match the one registered when it was created"
        )


class ExecutionAttemptMismatchError(Exception):
    """REPORT_RESULT (execution-result shape only): the caller supplied an
    ``execution_attempt_id`` that doesn't match the record's current
    lease. Maps to HTTP 409 — same "request doesn't match current
    resource state" family as
    :class:`~central_governance_api.approvals.state_machine.IllegalTransitionError`,
    kept as a distinct type because the cause is different (a stale/wrong
    attempt id, not an out-of-order status transition) and a caller
    debugging a 409 benefits from knowing which.
    """

    def __init__(
        self,
        *,
        approval_id: uuid.UUID,
        submitted: uuid.UUID,
        expected: uuid.UUID | None,
    ) -> None:
        self.approval_id = approval_id
        self.submitted = submitted
        self.expected = expected
        super().__init__(
            f"approval {approval_id}: submitted execution_attempt_id "
            f"{submitted} does not match the record's current lease "
            f"({expected!r})"
        )


class ConcurrentModificationError(Exception):
    """The conditional ``UPDATE ... WHERE status = <expected>`` affected
    zero rows — the record's status (or, for report-result, its
    execution_attempt_id) changed between this request's own read and its
    write. This is the actual concurrency guard; every state-machine/
    authorize check that ran earlier in the same request was necessarily
    against a read that can be stale by the time the UPDATE executes.
    Maps to HTTP 409, same family as ``IllegalTransitionError`` but kept
    distinct because the cause here is a genuine race rather than a
    request that was already invalid when it arrived.
    """

    def __init__(self, *, approval_id: uuid.UUID) -> None:
        self.approval_id = approval_id
        super().__init__(
            f"approval {approval_id} was modified concurrently — retry "
            "against its current state"
        )


class RecordNotTerminalError(Exception):
    """RECONCILIATION-FINDINGS only: a finding is evidence about a
    *resolved* outcome (see ``models.ReconciliationFinding``'s docstring)
    — a record still mid-flight (PENDING/ACCEPTED/EXECUTING) has no
    resolved outcome yet to reconcile. Maps to HTTP 409.

    Narrower than one of code-review's suggestions: ``late_report``
    findings arguably should be restricted further still, to records that
    specifically reached ``failed_unknown`` (the whole reason that finding
    type exists), and arguably should have to reference the record's
    actual ``execution_attempt_id``. Neither extra constraint is enforced
    here — this error only checks "is the record terminal at all",
    flagged as a known gap rather than silently narrowed without a trace.
    """

    def __init__(self, *, approval_id: uuid.UUID, current_status: str) -> None:
        self.approval_id = approval_id
        self.current_status = current_status
        super().__init__(
            f"approval {approval_id} is not yet resolved "
            f"(status={current_status!r}) — no outcome to reconcile"
        )
