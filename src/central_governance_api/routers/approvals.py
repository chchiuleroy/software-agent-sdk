"""Approval-workflow HTTP endpoints.

v11 §11 step 2, second half — wires ``approvals/state_machine.py`` and
``approvals/authorize.py`` (already committed, code-reviewed) to real
conditional-update SQL against ``PendingApprovalRecord``, plus digest
verification (``approvals/digest.py``) and idempotency enforcement
(``approvals/idempotency.py``). Step 3 (LISTEN/NOTIFY, ``/wait``) is
layered on top below, in the same file.

Endpoint scope this router covers, matching todo.md's step-2 description:
create, decide, claim, report-result (both shapes), cancel,
reconciliation-findings — the harder state-machine/digest/idempotency
wiring. Devices register/revoke and audit-events (read) live in
``routers/devices.py``/``routers/audit.py`` (simpler, lower-risk,
deliberately built in a separate follow-up pass). Step 3 adds
``GET .../wait`` at the bottom of this file (same resource, so it lives
here rather than a separate router — see its own docstring) plus a
``notify_status_changed`` call after every conditional UPDATE above that
actually changes ``status`` (decide/claim/report-result/cancel — CREATE
has no prior waiter since the id doesn't exist yet, and
reconciliation-findings never changes ``status`` at all, see
``models.ReconciliationFinding``'s docstring) so a blocked ``/wait``
caller wakes up immediately instead of only via its own timeout.

Pattern shared by every write endpoint below:

1. Require the ``Idempotency-Key`` header.
2. Check for a replay (``approvals.idempotency``) — on a genuine retry
   with the same key + body, return the stored response; nothing below
   this point runs again.
3. Load the record (skip for CREATE, nothing exists yet) — 404 if missing.
4. Authorize (``approvals.authorize``) against the record as last read.
5. Ask the state machine (``approvals.state_machine``) whether the
   requested event is legal from that last-read status — a precise,
   friendly ``IllegalTransitionError`` before any SQL runs.
6. Issue ONE conditional ``UPDATE ... WHERE status = <expected>
   RETURNING id`` — the actual atomicity guarantee. Step 5's check can be
   stale by the time this runs; zero rows back means someone else moved
   the record first, mapped to ``ConcurrentModificationError``.
7. Insert whatever side-effect row the action implies (``ApprovalDecision``,
   ``AdminAuditEvent``, ``ReconciliationFinding``) in the SAME transaction.
8. Stage the idempotency record, in the SAME transaction.
9. Commit once, via ``idempotency.commit_or_replay`` rather than a bare
   ``session.commit()`` — the single commit is what makes steps 6-8 land
   or fail together (the actual meaning of "conditional-update 邏輯...同
   一 DB transaction" from todo.md's step-2 description), and the helper
   additionally catches the specific case where a concurrent retry with
   the same idempotency key already committed first, replaying its
   response instead of surfacing the resulting ``IntegrityError`` as a
   500 (see that function's own docstring — added after code review
   caught that step 2's idempotency module documented this recovery path
   without any router actually implementing it; originally a private
   helper duplicated here, moved into ``approvals/idempotency.py`` once
   ``routers/devices.py`` needed the identical logic).
"""

from __future__ import annotations

import hmac
import uuid
from datetime import timedelta
from typing import Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy import or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from central_governance_api.accounts.tool_permissions import ensure_tool_permitted
from central_governance_api.approvals.authorize import (
    ApprovalAction,
    ApprovalOwnership,
    authorize_create,
    authorize_list_pending,
    authorize_on_record,
)
from central_governance_api.approvals.digest import verify_display_digest
from central_governance_api.approvals.errors import (
    ConcurrentModificationError,
    DigestMismatchError,
    ExecutionAttemptMismatchError,
    ExecutionCommitmentMismatchError,
    ExecutionCommitmentRequiredError,
    RecordNotFoundError,
    RecordNotTerminalError,
)
from central_governance_api.approvals.idempotency import (
    commit_or_replay,
    find_replayed_response,
    fingerprint_request,
    record_response,
)
from central_governance_api.approvals.notify import (
    notify_status_changed,
    wait_for_status_change,
)
from central_governance_api.approvals.schemas import (
    ApprovalSummary,
    CancelResponse,
    ClaimRequest,
    ClaimResponse,
    CreateApprovalRequest,
    DecideRequest,
    DecideResponse,
    PendingApprovalItem,
    PendingApprovalListResponse,
    ReconciliationFindingRequest,
    ReconciliationFindingResponse,
    ReportResultRequest,
    ReportResultResponse,
    WaitResponse,
)
from central_governance_api.approvals.state_machine import (
    ApprovalEvent,
    ApprovalStatus,
    is_terminal,
    next_status,
)
from central_governance_api.auth.dependencies import get_current_principal
from central_governance_api.auth.oidc import Principal
from central_governance_api.clock import now_utc
from central_governance_api.config import Settings, get_settings_dependency
from central_governance_api.db import get_db_session
from central_governance_api.http_params import IdempotencyKeyHeader
from central_governance_api.models import (
    AdminAuditEvent,
    ApprovalDecision,
    PendingApprovalRecord,
    ReconciliationFinding,
)
from central_governance_api.routers.devices import ensure_device_bound


router = APIRouter(prefix="/api/v1/approvals", tags=["approvals"])

_FINDING_TYPE_ACTIONS: dict[str, ApprovalAction] = {
    "requester_assertion": ApprovalAction.RECONCILE_AS_REQUESTER,
    "admin_verified": ApprovalAction.RECONCILE_AS_ADMIN,
    "late_report": ApprovalAction.RECONCILE_LATE_REPORT,
}
_DECIDE_EVENTS: dict[str, ApprovalEvent] = {
    "accept": ApprovalEvent.DECIDE_ACCEPT,
    "reject": ApprovalEvent.DECIDE_REJECT,
}
_OUTCOME_EVENTS: dict[str, ApprovalEvent] = {
    "success": ApprovalEvent.REPORT_SUCCESS,
    "failure_definite": ApprovalEvent.REPORT_FAILURE_DEFINITE,
    "failure_unknown": ApprovalEvent.REPORT_FAILURE_UNKNOWN,
}
# DecideRequest.decision is the wire-level verb ("accept"/"reject");
# ApprovalDecision.decision is stored as the past-participle value the
# DB's own CHECK constraint expects ("accepted"/"rejected" —
# models.py: `decision IN ('accepted', 'rejected')`). Caught by the real-
# Postgres integration tests, not by ruff/pyright/unit tests — a mocked
# session would never have hit the DB's CHECK constraint at all.
_DECISION_DB_VALUES: dict[str, str] = {"accept": "accepted", "reject": "rejected"}


async def _load_record(
    session: AsyncSession, approval_id: uuid.UUID
) -> PendingApprovalRecord:
    record = await session.get(PendingApprovalRecord, approval_id)
    if record is None:
        raise RecordNotFoundError(approval_id=approval_id)
    return record


def _ownership(record: PendingApprovalRecord) -> ApprovalOwnership:
    return ApprovalOwnership(
        requester_issuer=record.requester_issuer, requester_sub=record.requester_sub
    )


# --- CREATE --------------------------------------------------------------

_CREATE_ENDPOINT = "POST /approvals"


@router.post("", response_model=ApprovalSummary, status_code=201)
async def create_approval(
    body: CreateApprovalRequest,
    idempotency_key: IdempotencyKeyHeader,
    principal: Principal = Depends(get_current_principal),
    session: AsyncSession = Depends(get_db_session),
    settings: Settings = Depends(get_settings_dependency),
) -> ApprovalSummary:
    fingerprint = fingerprint_request(body.model_dump(mode="json"))
    replayed = await find_replayed_response(
        session,
        principal_issuer=principal.issuer,
        principal_sub=principal.sub,
        endpoint=_CREATE_ENDPOINT,
        resource_id=body.request_id,
        idempotency_key=idempotency_key,
        request_fingerprint=fingerprint,
    )
    if replayed is not None:
        # A replay must not outlive a revocation: the stored answer is what a
        # device would act on.
        await ensure_tool_permitted(
            session,
            principal,
            body.tool_name,
            enforced=settings.enforce_tool_permissions,
        )
        return ApprovalSummary.model_validate(replayed)

    authorize_create(principal)
    await ensure_device_bound(
        session,
        principal,
        body.origin_device_id,
        enforced=settings.device_binding_enforced,
    )
    await ensure_tool_permitted(
        session, principal, body.tool_name, enforced=settings.enforce_tool_permissions
    )

    if settings.require_execution_commitment and body.execution_commitment is None:
        raise ExecutionCommitmentRequiredError()

    if not verify_display_digest(
        action_type=body.action_type,
        tool_name=body.tool_name,
        policy_revision=body.policy_revision,
        action_summary=body.action_summary,
        action_payload=body.action_payload,
        digest_salt=body.digest_salt,
        expected_digest=body.action_payload_digest,
        execution_commitment=body.execution_commitment,
    ):
        raise DigestMismatchError(
            "action_payload_digest does not match a digest computed from "
            "the submitted action_type/tool_name/policy_revision/"
            "action_summary/action_payload/digest_salt"
        )

    now = now_utc()
    record = PendingApprovalRecord(
        request_id=body.request_id,
        requester_issuer=principal.issuer,
        requester_sub=principal.sub,
        origin_device_id=body.origin_device_id,
        conversation_id=body.conversation_id,
        action_event_id=body.action_event_id,
        tool_call_id=body.tool_call_id,
        action_type=body.action_type,
        tool_name=body.tool_name,
        policy_revision=body.policy_revision,
        action_summary=body.action_summary,
        action_payload=body.action_payload,
        digest_salt=body.digest_salt,
        action_payload_digest=body.action_payload_digest,
        execution_commitment=body.execution_commitment,
        status=ApprovalStatus.PENDING.value,
        expires_at=now + timedelta(seconds=settings.approval_decision_ttl_seconds),
    )
    session.add(record)
    await session.flush()  # populate record.id/created_at (server defaults)

    response = ApprovalSummary(
        id=record.id,
        request_id=record.request_id,
        status=record.status,
        created_at=record.created_at,
        expires_at=record.expires_at,
        action_payload_digest=record.action_payload_digest,
    )
    record_response(
        session,
        principal_issuer=principal.issuer,
        principal_sub=principal.sub,
        endpoint=_CREATE_ENDPOINT,
        resource_id=body.request_id,
        idempotency_key=idempotency_key,
        request_fingerprint=fingerprint,
        response=response.model_dump(mode="json"),
    )
    replayed = await commit_or_replay(
        session,
        principal_issuer=principal.issuer,
        principal_sub=principal.sub,
        endpoint=_CREATE_ENDPOINT,
        resource_id=body.request_id,
        idempotency_key=idempotency_key,
        request_fingerprint=fingerprint,
    )
    if replayed is not None:
        return ApprovalSummary.model_validate(replayed)
    return response


# --- LIST PENDING (approver inbox) ---------------------------------------

_PENDING_DEFAULT_LIMIT = 50
_PENDING_MAX_LIMIT = 100


@router.get("/pending", response_model=PendingApprovalListResponse)
async def list_pending_approvals(
    limit: int = Query(default=_PENDING_DEFAULT_LIMIT, ge=1, le=_PENDING_MAX_LIMIT),
    principal: Principal = Depends(get_current_principal),
    session: AsyncSession = Depends(get_db_session),
) -> PendingApprovalListResponse:
    """Requests this principal could decide right now: still ``pending``,
    not past ``expires_at`` (decide would refuse those even before the expiry
    sweep flips their status), and not the caller's own (self-approval is
    denied for every role, so listing them would only offer a button that
    can never work). Read-only: no idempotency key, nothing written.
    """
    authorize_list_pending(principal)

    stmt = (
        select(PendingApprovalRecord)
        .where(
            PendingApprovalRecord.status == ApprovalStatus.PENDING.value,
            PendingApprovalRecord.expires_at > now_utc(),
            # (issuer, sub) is the identity key, not either column alone.
            or_(
                PendingApprovalRecord.requester_issuer != principal.issuer,
                PendingApprovalRecord.requester_sub != principal.sub,
            ),
        )
        .order_by(
            PendingApprovalRecord.created_at.asc(), PendingApprovalRecord.id.asc()
        )
        .limit(limit + 1)
    )
    rows = list((await session.execute(stmt)).scalars())
    has_more = len(rows) > limit
    items = [
        PendingApprovalItem(
            id=row.id,
            request_id=row.request_id,
            requester_issuer=row.requester_issuer,
            requester_sub=row.requester_sub,
            origin_device_id=row.origin_device_id,
            conversation_id=row.conversation_id,
            action_type=row.action_type,
            tool_name=row.tool_name,
            risk_level=row.risk_level,
            action_summary=row.action_summary,
            action_payload=row.action_payload,
            action_payload_digest=row.action_payload_digest,
            created_at=row.created_at,
            expires_at=row.expires_at,
        )
        for row in rows[:limit]
    ]
    return PendingApprovalListResponse(items=items, has_more=has_more)


# --- DECIDE ----------------------------------------------------------------

_DECIDE_ENDPOINT = "POST /approvals/{id}/decide"


@router.post("/{approval_id}/decide", response_model=DecideResponse)
async def decide_approval(
    approval_id: uuid.UUID,
    body: DecideRequest,
    idempotency_key: IdempotencyKeyHeader,
    principal: Principal = Depends(get_current_principal),
    session: AsyncSession = Depends(get_db_session),
    settings: Settings = Depends(get_settings_dependency),
) -> DecideResponse:
    resource_id = str(approval_id)
    fingerprint = fingerprint_request(body.model_dump(mode="json"))
    replayed = await find_replayed_response(
        session,
        principal_issuer=principal.issuer,
        principal_sub=principal.sub,
        endpoint=_DECIDE_ENDPOINT,
        resource_id=resource_id,
        idempotency_key=idempotency_key,
        request_fingerprint=fingerprint,
    )
    if replayed is not None:
        return DecideResponse.model_validate(replayed)

    record = await _load_record(session, approval_id)
    authorize_on_record(principal, ApprovalAction.DECIDE, _ownership(record))

    event = _DECIDE_EVENTS[body.decision]
    current = ApprovalStatus(record.status)
    target = next_status(current, event)

    now = now_utc()
    values: dict[str, Any] = {"status": target.value}
    if event is ApprovalEvent.DECIDE_ACCEPT:
        values["execution_deadline"] = now + timedelta(
            seconds=settings.approval_execution_window_seconds
        )

    result = await session.execute(
        update(PendingApprovalRecord)
        .where(
            PendingApprovalRecord.id == approval_id,
            PendingApprovalRecord.status == current.value,
            # Code-review High: without this, a request whose decision
            # deadline already lapsed can still be decided as long as the
            # background expiry sweep (step 3) hasn't gotten to it yet —
            # `expires_at` would be a purely advisory field, not an actual
            # boundary. `decide` is only ever legal from PENDING (the
            # state machine guarantees that), so `expires_at` — the
            # PENDING deadline — is always the right column to check here.
            PendingApprovalRecord.expires_at > now,
        )
        .values(**values)
        .returning(PendingApprovalRecord.id)
    )
    if result.scalar_one_or_none() is None:
        raise ConcurrentModificationError(approval_id=approval_id)

    await notify_status_changed(session, approval_id=approval_id, status=target.value)

    session.add(
        ApprovalDecision(
            approval_request_id=approval_id,
            decision=_DECISION_DB_VALUES[body.decision],
            decision_actor_issuer=principal.issuer,
            decision_actor_sub=principal.sub,
        )
    )

    response = DecideResponse(id=approval_id, status=target.value, decided_at=now)
    record_response(
        session,
        principal_issuer=principal.issuer,
        principal_sub=principal.sub,
        endpoint=_DECIDE_ENDPOINT,
        resource_id=resource_id,
        idempotency_key=idempotency_key,
        request_fingerprint=fingerprint,
        response=response.model_dump(mode="json"),
    )
    replayed = await commit_or_replay(
        session,
        principal_issuer=principal.issuer,
        principal_sub=principal.sub,
        endpoint=_DECIDE_ENDPOINT,
        resource_id=resource_id,
        idempotency_key=idempotency_key,
        request_fingerprint=fingerprint,
    )
    if replayed is not None:
        return DecideResponse.model_validate(replayed)
    return response


# --- CLAIM -----------------------------------------------------------------

_CLAIM_ENDPOINT = "POST /approvals/{id}/claim"


@router.post("/{approval_id}/claim", response_model=ClaimResponse)
async def claim_approval(
    approval_id: uuid.UUID,
    idempotency_key: IdempotencyKeyHeader,
    body: ClaimRequest | None = None,
    principal: Principal = Depends(get_current_principal),
    session: AsyncSession = Depends(get_db_session),
    settings: Settings = Depends(get_settings_dependency),
) -> ClaimResponse:
    resource_id = str(approval_id)
    # A bodyless claim (every device that predates the commitment) keeps the
    # fingerprint it always had.
    fingerprint = fingerprint_request(
        body.model_dump(mode="json") if body is not None else {}
    )
    replayed = await find_replayed_response(
        session,
        principal_issuer=principal.issuer,
        principal_sub=principal.sub,
        endpoint=_CLAIM_ENDPOINT,
        resource_id=resource_id,
        idempotency_key=idempotency_key,
        request_fingerprint=fingerprint,
    )
    if replayed is not None:
        # Same reason as at create, and more so: the stored ClaimResponse is
        # the execution lease. If the response to the first claim was lost
        # and the permission has been revoked since, the retry must not hand
        # the lease back.
        replayed_record = await _load_record(session, approval_id)
        await ensure_tool_permitted(
            session,
            principal,
            replayed_record.tool_name,
            enforced=settings.enforce_tool_permissions,
        )
        return ClaimResponse.model_validate(replayed)

    record = await _load_record(session, approval_id)
    authorize_on_record(principal, ApprovalAction.CLAIM, _ownership(record))
    # Re-checked at claim time (not only at create): the device may have been
    # revoked while the request waited for a decision, and claim is the step
    # that actually lets the action execute.
    await ensure_device_bound(
        session,
        principal,
        record.origin_device_id,
        enforced=settings.device_binding_enforced,
    )
    # Also at claim: a permission revoked while the request waited for a
    # decision must stop the action from executing.
    await ensure_tool_permitted(
        session, principal, record.tool_name, enforced=settings.enforce_tool_permissions
    )

    current = ApprovalStatus(record.status)
    next_status(current, ApprovalEvent.CLAIM)  # raises if illegal from here

    if record.execution_commitment is not None:
        presented = body.execution_commitment if body is not None else None
        if presented is None or not hmac.compare_digest(
            presented, record.execution_commitment
        ):
            # Persist the evidence BEFORE raising: the error path rolls the
            # request's transaction back, and a refused claim is exactly the
            # event an audit needs to see. No lease is handed out.
            session.add(
                AdminAuditEvent(
                    event_type="approval_claim_commitment_mismatch",
                    actor_issuer=principal.issuer,
                    actor_sub=principal.sub,
                    origin_device_id=record.origin_device_id,
                    approval_request_id=approval_id,
                    payload={"presented": presented is not None},
                )
            )
            await session.commit()
            raise ExecutionCommitmentMismatchError(approval_id=approval_id)

    now = now_utc()
    attempt_id = uuid.uuid4()
    lease_expires = now + timedelta(seconds=settings.approval_execution_lease_seconds)

    result = await session.execute(
        update(PendingApprovalRecord)
        .where(
            PendingApprovalRecord.id == approval_id,
            PendingApprovalRecord.status == ApprovalStatus.ACCEPTED.value,
            # Strict, no `OR execution_deadline IS NULL` escape hatch
            # (code-review Low): every ACCEPTED row this router produces
            # always has a deadline (see `decide_approval` above), so an
            # accepted-with-no-deadline row can only mean corrupted data,
            # a manual DB edit, or a future migration bug — treating that
            # as "never expires" would be the fail-open reading; `> now`
            # against a NULL column evaluates to NULL (falsy in SQL WHERE),
            # so this fails closed instead, matching the rest of this
            # router's stance on unexpected state.
            PendingApprovalRecord.execution_deadline > now,
        )
        .values(
            status=ApprovalStatus.EXECUTING.value,
            execution_attempt_id=attempt_id,
            executing_lease_expires_at=lease_expires,
        )
        .returning(PendingApprovalRecord.id)
    )
    if result.scalar_one_or_none() is None:
        # Deliberately not distinguished from a plain status race here —
        # "wrong status" and "deadline already passed while still
        # ACCEPTED" both mean the same thing to the caller: this claim
        # cannot proceed, retry is pointless without a fresh decision.
        raise ConcurrentModificationError(approval_id=approval_id)

    await notify_status_changed(
        session, approval_id=approval_id, status=ApprovalStatus.EXECUTING.value
    )

    response = ClaimResponse(
        id=approval_id,
        status=ApprovalStatus.EXECUTING.value,
        execution_attempt_id=attempt_id,
        executing_lease_expires_at=lease_expires,
        action_payload_digest=record.action_payload_digest,
    )
    record_response(
        session,
        principal_issuer=principal.issuer,
        principal_sub=principal.sub,
        endpoint=_CLAIM_ENDPOINT,
        resource_id=resource_id,
        idempotency_key=idempotency_key,
        request_fingerprint=fingerprint,
        response=response.model_dump(mode="json"),
    )
    replayed = await commit_or_replay(
        session,
        principal_issuer=principal.issuer,
        principal_sub=principal.sub,
        endpoint=_CLAIM_ENDPOINT,
        resource_id=resource_id,
        idempotency_key=idempotency_key,
        request_fingerprint=fingerprint,
    )
    if replayed is not None:
        return ClaimResponse.model_validate(replayed)
    return response


# --- REPORT-RESULT -----------------------------------------------------------

_REPORT_RESULT_ENDPOINT = "POST /approvals/{id}/report-result"


@router.post("/{approval_id}/report-result", response_model=ReportResultResponse)
async def report_result(
    approval_id: uuid.UUID,
    body: ReportResultRequest,
    idempotency_key: IdempotencyKeyHeader,
    principal: Principal = Depends(get_current_principal),
    session: AsyncSession = Depends(get_db_session),
) -> ReportResultResponse:
    resource_id = str(approval_id)
    fingerprint = fingerprint_request(body.model_dump(mode="json"))
    replayed = await find_replayed_response(
        session,
        principal_issuer=principal.issuer,
        principal_sub=principal.sub,
        endpoint=_REPORT_RESULT_ENDPOINT,
        resource_id=resource_id,
        idempotency_key=idempotency_key,
        request_fingerprint=fingerprint,
    )
    if replayed is not None:
        return ReportResultResponse.model_validate(replayed)

    record = await _load_record(session, approval_id)
    authorize_on_record(principal, ApprovalAction.REPORT_RESULT, _ownership(record))

    current = ApprovalStatus(record.status)
    now = now_utc()

    if body.is_pre_claim_abort:
        event = ApprovalEvent.REPORT_PRE_CLAIM_ABORT
        expected_status = ApprovalStatus.ACCEPTED
    else:
        assert body.execution_attempt_id is not None
        assert body.outcome is not None
        if record.execution_attempt_id != body.execution_attempt_id:
            raise ExecutionAttemptMismatchError(
                approval_id=approval_id,
                submitted=body.execution_attempt_id,
                expected=record.execution_attempt_id,
            )
        event = _OUTCOME_EVENTS[body.outcome]
        expected_status = ApprovalStatus.EXECUTING

    target = next_status(current, event)

    where_clauses = [
        PendingApprovalRecord.id == approval_id,
        PendingApprovalRecord.status == expected_status.value,
    ]
    if not body.is_pre_claim_abort:
        where_clauses.append(
            PendingApprovalRecord.execution_attempt_id == body.execution_attempt_id
        )
        # Code-review High: without this, a result reported after the
        # execution lease already expired could still land on APPLIED or
        # FAILED_DEFINITE — a *definite* outcome for an attempt this
        # service should already be treating as unconfirmed. This is
        # exactly the "crash 後無法確認就 fail closed" invariant from the
        # v10 design record (see state_machine.py's EXECUTING+EXPIRE
        # transition) — it has to be enforced here too, not only by the
        # (not-yet-implemented, step 3) background sweep, or a report
        # that arrives just after expiry but before the sweep runs would
        # silently bypass fail-closed.
        where_clauses.append(PendingApprovalRecord.executing_lease_expires_at > now)

    update_values: dict[str, Any] = {"status": target.value}
    commitment_mismatch = False
    if body.executed_commitment is not None:
        # Evidence only: the action has already run, so a mismatch cannot
        # change the outcome being reported. It is recorded, never rejected.
        update_values["executed_commitment"] = body.executed_commitment
        if record.execution_commitment is not None:
            verified = hmac.compare_digest(
                body.executed_commitment, record.execution_commitment
            )
            update_values["commitment_matched"] = verified
            commitment_mismatch = not verified

    result = await session.execute(
        update(PendingApprovalRecord)
        .where(*where_clauses)
        .values(**update_values)
        .returning(PendingApprovalRecord.id)
    )
    if result.scalar_one_or_none() is None:
        raise ConcurrentModificationError(approval_id=approval_id)

    await notify_status_changed(session, approval_id=approval_id, status=target.value)

    if commitment_mismatch:
        session.add(
            AdminAuditEvent(
                event_type="approval_executed_commitment_mismatch",
                actor_issuer=principal.issuer,
                actor_sub=principal.sub,
                origin_device_id=record.origin_device_id,
                approval_request_id=approval_id,
                payload={"outcome": body.outcome},
            )
        )

    if body.is_pre_claim_abort:
        # Code-review Medium: pre-claim abort and a plain pre-decision
        # CANCEL land on the same terminal status (see state_machine.py's
        # comment on this transition) — without recording which event
        # actually fired, that distinction is lost the moment this
        # commits. An AdminAuditEvent row (the only generic, already-
        # existing audit sink for "something happened to this request"
        # outside the accept/reject-specific ApprovalDecision table) is
        # the cheap fix that doesn't require a schema change.
        session.add(
            AdminAuditEvent(
                event_type="approval_pre_claim_abort",
                actor_issuer=principal.issuer,
                actor_sub=principal.sub,
                approval_request_id=approval_id,
            )
        )

    response = ReportResultResponse(id=approval_id, status=target.value)
    record_response(
        session,
        principal_issuer=principal.issuer,
        principal_sub=principal.sub,
        endpoint=_REPORT_RESULT_ENDPOINT,
        resource_id=resource_id,
        idempotency_key=idempotency_key,
        request_fingerprint=fingerprint,
        response=response.model_dump(mode="json"),
    )
    replayed = await commit_or_replay(
        session,
        principal_issuer=principal.issuer,
        principal_sub=principal.sub,
        endpoint=_REPORT_RESULT_ENDPOINT,
        resource_id=resource_id,
        idempotency_key=idempotency_key,
        request_fingerprint=fingerprint,
    )
    if replayed is not None:
        return ReportResultResponse.model_validate(replayed)
    return response


# --- CANCEL ------------------------------------------------------------------

_CANCEL_ENDPOINT = "POST /approvals/{id}/cancel"


@router.post("/{approval_id}/cancel", response_model=CancelResponse)
async def cancel_approval(
    approval_id: uuid.UUID,
    idempotency_key: IdempotencyKeyHeader,
    principal: Principal = Depends(get_current_principal),
    session: AsyncSession = Depends(get_db_session),
) -> CancelResponse:
    resource_id = str(approval_id)
    fingerprint = fingerprint_request({})
    replayed = await find_replayed_response(
        session,
        principal_issuer=principal.issuer,
        principal_sub=principal.sub,
        endpoint=_CANCEL_ENDPOINT,
        resource_id=resource_id,
        idempotency_key=idempotency_key,
        request_fingerprint=fingerprint,
    )
    if replayed is not None:
        return CancelResponse.model_validate(replayed)

    record = await _load_record(session, approval_id)
    authorize_on_record(principal, ApprovalAction.CANCEL, _ownership(record))

    current = ApprovalStatus(record.status)
    target = next_status(current, ApprovalEvent.CANCEL)

    result = await session.execute(
        update(PendingApprovalRecord)
        .where(
            PendingApprovalRecord.id == approval_id,
            PendingApprovalRecord.status == current.value,
        )
        .values(status=target.value)
        .returning(PendingApprovalRecord.id)
    )
    if result.scalar_one_or_none() is None:
        raise ConcurrentModificationError(approval_id=approval_id)

    await notify_status_changed(session, approval_id=approval_id, status=target.value)

    # See report_result's pre-claim-abort branch for why this exists:
    # both events land on CANCELLED, so an audit row is what lets the
    # two be told apart afterward.
    session.add(
        AdminAuditEvent(
            event_type="approval_cancelled",
            actor_issuer=principal.issuer,
            actor_sub=principal.sub,
            approval_request_id=approval_id,
        )
    )

    response = CancelResponse(id=approval_id, status=target.value)
    record_response(
        session,
        principal_issuer=principal.issuer,
        principal_sub=principal.sub,
        endpoint=_CANCEL_ENDPOINT,
        resource_id=resource_id,
        idempotency_key=idempotency_key,
        request_fingerprint=fingerprint,
        response=response.model_dump(mode="json"),
    )
    replayed = await commit_or_replay(
        session,
        principal_issuer=principal.issuer,
        principal_sub=principal.sub,
        endpoint=_CANCEL_ENDPOINT,
        resource_id=resource_id,
        idempotency_key=idempotency_key,
        request_fingerprint=fingerprint,
    )
    if replayed is not None:
        return CancelResponse.model_validate(replayed)
    return response


# --- RECONCILIATION FINDINGS -------------------------------------------------

_RECONCILE_ENDPOINT = "POST /approvals/{id}/reconciliation-findings"


@router.post(
    "/{approval_id}/reconciliation-findings",
    response_model=ReconciliationFindingResponse,
    status_code=201,
)
async def create_reconciliation_finding(
    approval_id: uuid.UUID,
    body: ReconciliationFindingRequest,
    idempotency_key: IdempotencyKeyHeader,
    principal: Principal = Depends(get_current_principal),
    session: AsyncSession = Depends(get_db_session),
) -> ReconciliationFindingResponse:
    resource_id = str(approval_id)
    fingerprint = fingerprint_request(body.model_dump(mode="json"))
    replayed = await find_replayed_response(
        session,
        principal_issuer=principal.issuer,
        principal_sub=principal.sub,
        endpoint=_RECONCILE_ENDPOINT,
        resource_id=resource_id,
        idempotency_key=idempotency_key,
        request_fingerprint=fingerprint,
    )
    if replayed is not None:
        return ReconciliationFindingResponse.model_validate(replayed)

    record = await _load_record(session, approval_id)
    action = _FINDING_TYPE_ACTIONS[body.finding_type]
    authorize_on_record(principal, action, _ownership(record))

    current = ApprovalStatus(record.status)
    if not is_terminal(current):
        raise RecordNotTerminalError(
            approval_id=approval_id, current_status=current.value
        )

    finding = ReconciliationFinding(
        approval_request_id=approval_id,
        finding_type=body.finding_type,
        conclusion=body.conclusion,
        note=body.note,
        verifier_issuer=principal.issuer,
        verifier_sub=principal.sub,
        evidence=body.evidence,
    )
    session.add(finding)
    await session.flush()  # populate finding.id/created_at

    response = ReconciliationFindingResponse(
        id=finding.id,
        approval_request_id=approval_id,
        finding_type=finding.finding_type,
        created_at=finding.created_at,
    )
    record_response(
        session,
        principal_issuer=principal.issuer,
        principal_sub=principal.sub,
        endpoint=_RECONCILE_ENDPOINT,
        resource_id=resource_id,
        idempotency_key=idempotency_key,
        request_fingerprint=fingerprint,
        response=response.model_dump(mode="json"),
    )
    replayed = await commit_or_replay(
        session,
        principal_issuer=principal.issuer,
        principal_sub=principal.sub,
        endpoint=_RECONCILE_ENDPOINT,
        resource_id=resource_id,
        idempotency_key=idempotency_key,
        request_fingerprint=fingerprint,
    )
    if replayed is not None:
        return ReconciliationFindingResponse.model_validate(replayed)
    return response


# --- WAIT (v11 §11 step 3) ---------------------------------------------------


@router.get("/{approval_id}/wait", response_model=WaitResponse)
async def wait_for_approval(
    approval_id: uuid.UUID,
    known_status: ApprovalStatus,
    timeout_seconds: int | None = Query(default=None, ge=1),
    principal: Principal = Depends(get_current_principal),
    session: AsyncSession = Depends(get_db_session),
    settings: Settings = Depends(get_settings_dependency),
) -> WaitResponse:
    """Long-poll: blocks until ``approval_id``'s status differs from the
    caller-supplied ``known_status``, or ``timeout_seconds`` elapses,
    whichever comes first. Backed by PostgreSQL LISTEN/NOTIFY
    (``approvals/notify.py``) rather than a fixed-interval poll loop, so
    the primary intended caller — the requester's own agent-server, after
    CREATE, waiting to learn when its request is decided so it can proceed
    to CLAIM — doesn't have to trade "check often" against "load the
    API/DB heavily".

    Not one of this router's Idempotency-Key-guarded write endpoints: a
    GET that only ever reads is already safe to call repeatedly with no
    special handling, and a long-poll client is *expected* to call this
    again immediately after every timeout — an idempotency key would add
    friction for no benefit here.

    ``known_status`` is required, not inferred server-side: the caller is
    always the one who last observed some status (from CREATE's response,
    or a previous ``/wait`` call) and is asking "tell me when it's no
    longer that" — there is no other way to phrase "wait for a change"
    without a baseline to compare against.
    """
    record = await _load_record(session, approval_id)
    authorize_on_record(principal, ApprovalAction.WAIT, _ownership(record))

    current = ApprovalStatus(record.status)
    if current != known_status:
        # True regardless of how stale this particular read is — some
        # change away from known_status already happened by now, full
        # stop. No need to touch LISTEN/NOTIFY at all for this answer.
        return WaitResponse(id=approval_id, status=record.status, changed=True)
    if is_terminal(current):
        # known_status already matches a terminal status, which by
        # definition (state_machine.TERMINAL_STATUSES) never changes
        # again — waiting would just burn the full timeout for nothing.
        return WaitResponse(id=approval_id, status=record.status, changed=False)

    effective_timeout = min(
        timeout_seconds
        if timeout_seconds is not None
        else settings.wait_default_timeout_seconds,
        settings.wait_max_timeout_seconds,
    )
    changed = await wait_for_status_change(
        session,
        record,
        database_url=settings.database_url,
        known_status=known_status.value,
        timeout_seconds=effective_timeout,
    )
    return WaitResponse(id=approval_id, status=record.status, changed=changed)
