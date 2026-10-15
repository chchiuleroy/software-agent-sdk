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


class ExecutionCommitmentRequiredError(Exception):
    """CREATE only, when ``require_execution_commitment`` is on: the request
    carried no ``execution_commitment``. Maps to HTTP 400 — the request does
    not meet this deployment's policy; nothing was written."""

    def __init__(self) -> None:
        super().__init__(
            "this deployment requires an execution_commitment on every new "
            "approval request"
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

    This only checks "is the record terminal at all". ``late_report`` is
    narrower still — see :class:`LateReportNotApplicableError`.
    """

    def __init__(self, *, approval_id: uuid.UUID, current_status: str) -> None:
        self.approval_id = approval_id
        self.current_status = current_status
        super().__init__(
            f"approval {approval_id} is not yet resolved "
            f"(status={current_status!r}) — no outcome to reconcile"
        )


class EvidenceTooLargeError(Exception):
    """RECONCILIATION-FINDINGS only: the evidence, as the database prints its jsonb,
    is longer than the limit. Maps to HTTP 422. The message is safe to show."""

    def __init__(self, *, size: int, limit: int) -> None:
        self.size = size
        self.limit = limit
        super().__init__(
            f"evidence is {size} characters as stored; at most {limit} are accepted"
        )


class TooManyFindingsError(Exception):
    """RECONCILIATION-FINDINGS only: one approval may hold at most
    ``MAX_FINDINGS_PER_APPROVAL`` findings (the table is append-only, so without a
    limit a requester could add them without end). The count is read under a lock on
    the approval's row, so concurrent findings for one approval are counted one at a
    time and the limit is exact. Maps to HTTP 409. The message is safe to show."""

    def __init__(self, *, approval_id: uuid.UUID, limit: int) -> None:
        self.approval_id = approval_id
        self.limit = limit
        super().__init__(
            f"approval {approval_id} already has {limit} findings; no more are accepted"
        )


class TooManyAttentionEventsError(Exception):
    """ATTENTION-RESOLUTIONS only: one approval may hold at most
    ``MAX_ATTENTION_EVENTS_PER_APPROVAL`` attention_resolved events. The count is read
    under a lock on the approval's row, so the limit is exact. Maps to HTTP 409. The
    message is safe to show."""

    def __init__(self, *, approval_id: uuid.UUID, limit: int) -> None:
        self.approval_id = approval_id
        self.limit = limit
        super().__init__(
            f"approval {approval_id} already has {limit} attention events; "
            "no more are accepted"
        )


class SelfVerificationNotAllowedError(Exception):
    """RECONCILIATION-FINDINGS only: an ``admin_verified`` finding says an
    administrator checked what really happened. The principal who made the request
    cannot be that independent check on its own request, so the finding is refused
    when the verifier is the requester (same issuer and subject). Maps to HTTP 409.
    The message is safe to show: it carries only the approval id."""

    def __init__(self, *, approval_id: uuid.UUID) -> None:
        self.approval_id = approval_id
        super().__init__(
            f"approval {approval_id} was requested by this same principal; "
            "an admin_verified finding must come from someone else"
        )


class LateReportNotApplicableError(Exception):
    """RECONCILIATION-FINDINGS only: a ``late_report`` is the requester's
    own device reporting the real outcome of an attempt after central
    already failed it closed, so it is only meaningful on a record that
    reached ``failed_unknown``. On any other terminal status (``applied``,
    ``failed_definite``, ``rejected`` ...) the device either already
    reported or never ran anything, and a late report would plant
    misleading evidence in the audit trail. Maps to HTTP 409."""

    def __init__(self, *, approval_id: uuid.UUID, current_status: str) -> None:
        self.approval_id = approval_id
        self.current_status = current_status
        super().__init__(
            f"approval {approval_id} has status {current_status!r}; a "
            "late_report only applies to a failed_unknown record"
        )
