"""Approval-workflow HTTP endpoints.

v11 §11 step 2, second half — wires ``approvals/state_machine.py`` and
``approvals/authorize.py`` (already committed, code-reviewed) to real
conditional-update SQL against ``PendingApprovalRecord``, plus digest
verification (``approvals/digest.py``) and idempotency enforcement
(``approvals/idempotency.py``).

Endpoint scope this pass covers, matching todo.md's step-2 description:
create, decide, claim, report-result (both shapes), cancel,
reconciliation-findings. NOT in this pass: devices register/revoke,
audit-events (read), and ``/wait`` (step 3, LISTEN/NOTIFY) — simpler,
lower-risk endpoints deliberately left for a follow-up rather than grown
in the same pass as the harder state-machine/digest/idempotency wiring.

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
   ``ReconciliationFinding``) in the SAME transaction.
8. Stage the idempotency record, in the SAME transaction.
9. ``session.commit()`` once. The single commit is what makes steps 6-8
   land or fail together — this is the actual meaning of "conditional-
   update 邏輯...同一 DB transaction" from todo.md's step-2 description.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, Header, Request
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from central_governance_api.approvals.authorize import (
    ApprovalAction,
    ApprovalOwnership,
    authorize_create,
    authorize_on_record,
)
from central_governance_api.approvals.digest import verify_display_digest
from central_governance_api.approvals.errors import (
    ConcurrentModificationError,
    DigestMismatchError,
    ExecutionAttemptMismatchError,
    RecordNotFoundError,
    RecordNotTerminalError,
)
from central_governance_api.approvals.idempotency import (
    find_replayed_response,
    fingerprint_request,
    record_response,
)
from central_governance_api.approvals.schemas import (
    ApprovalSummary,
    CancelResponse,
    ClaimResponse,
    CreateApprovalRequest,
    DecideRequest,
    DecideResponse,
    ReconciliationFindingRequest,
    ReconciliationFindingResponse,
    ReportResultRequest,
    ReportResultResponse,
)
from central_governance_api.approvals.state_machine import (
    ApprovalEvent,
    ApprovalStatus,
    is_terminal,
    next_status,
)
from central_governance_api.auth.dependencies import get_current_principal
from central_governance_api.auth.oidc import Principal
from central_governance_api.config import Settings
from central_governance_api.db import get_db_session
from central_governance_api.models import (
    ApprovalDecision,
    PendingApprovalRecord,
    ReconciliationFinding,
)


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


def _get_settings(request: Request) -> Settings:
    return request.app.state.settings


def _now() -> datetime:
    # App-clock timestamps throughout this router, not DB-server `now()`
    # — a reasoned simplification (see config.py's TTL field docstrings),
    # not something v11 specifies. Fine while the API process and its
    # Postgres are co-located; a multi-app-server deployment would need
    # this to move server-side to avoid clock-skew-induced early/late
    # expiry.
    return datetime.now(UTC)


async def _load_record(
    session: AsyncSession, approval_id: uuid.UUID
) -> PendingApprovalRecord:
    record = await session.get(PendingApprovalRecord, approval_id)
    if record is None:
        raise RecordNotFoundError(approval_id=approval_id)
    return record


def _ownership(record: PendingApprovalRecord) -> ApprovalOwnership:
    return ApprovalOwnership(requester_subject=record.requester_subject)


# --- CREATE --------------------------------------------------------------

_CREATE_ENDPOINT = "POST /approvals"


@router.post("", response_model=ApprovalSummary, status_code=201)
async def create_approval(
    body: CreateApprovalRequest,
    idempotency_key: str = Header(alias="Idempotency-Key"),
    principal: Principal = Depends(get_current_principal),
    session: AsyncSession = Depends(get_db_session),
    settings: Settings = Depends(_get_settings),
) -> ApprovalSummary:
    fingerprint = fingerprint_request(body.model_dump(mode="json"))
    replayed = await find_replayed_response(
        session,
        principal_subject=principal.subject,
        endpoint=_CREATE_ENDPOINT,
        resource_id=body.request_id,
        idempotency_key=idempotency_key,
        request_fingerprint=fingerprint,
    )
    if replayed is not None:
        return ApprovalSummary.model_validate(replayed)

    authorize_create(principal)

    if not verify_display_digest(
        action_type=body.action_type,
        tool_name=body.tool_name,
        policy_revision=body.policy_revision,
        action_summary=body.action_summary,
        action_payload=body.action_payload,
        digest_salt=body.digest_salt,
        expected_digest=body.action_payload_digest,
    ):
        raise DigestMismatchError(
            "action_payload_digest does not match a digest computed from "
            "the submitted action_type/tool_name/policy_revision/"
            "action_summary/action_payload/digest_salt"
        )

    now = _now()
    record = PendingApprovalRecord(
        request_id=body.request_id,
        requester_subject=principal.subject,
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
        principal_subject=principal.subject,
        endpoint=_CREATE_ENDPOINT,
        resource_id=body.request_id,
        idempotency_key=idempotency_key,
        request_fingerprint=fingerprint,
        response=response.model_dump(mode="json"),
    )
    await session.commit()
    return response


# --- DECIDE ----------------------------------------------------------------

_DECIDE_ENDPOINT = "POST /approvals/{id}/decide"


@router.post("/{approval_id}/decide", response_model=DecideResponse)
async def decide_approval(
    approval_id: uuid.UUID,
    body: DecideRequest,
    idempotency_key: str = Header(alias="Idempotency-Key"),
    principal: Principal = Depends(get_current_principal),
    session: AsyncSession = Depends(get_db_session),
    settings: Settings = Depends(_get_settings),
) -> DecideResponse:
    resource_id = str(approval_id)
    fingerprint = fingerprint_request(body.model_dump(mode="json"))
    replayed = await find_replayed_response(
        session,
        principal_subject=principal.subject,
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

    now = _now()
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
        )
        .values(**values)
        .returning(PendingApprovalRecord.id)
    )
    if result.scalar_one_or_none() is None:
        raise ConcurrentModificationError(approval_id=approval_id)

    session.add(
        ApprovalDecision(
            approval_request_id=approval_id,
            decision=_DECISION_DB_VALUES[body.decision],
            decision_actor_subject=principal.subject,
        )
    )

    response = DecideResponse(id=approval_id, status=target.value, decided_at=now)
    record_response(
        session,
        principal_subject=principal.subject,
        endpoint=_DECIDE_ENDPOINT,
        resource_id=resource_id,
        idempotency_key=idempotency_key,
        request_fingerprint=fingerprint,
        response=response.model_dump(mode="json"),
    )
    await session.commit()
    return response


# --- CLAIM -----------------------------------------------------------------

_CLAIM_ENDPOINT = "POST /approvals/{id}/claim"


@router.post("/{approval_id}/claim", response_model=ClaimResponse)
async def claim_approval(
    approval_id: uuid.UUID,
    idempotency_key: str = Header(alias="Idempotency-Key"),
    principal: Principal = Depends(get_current_principal),
    session: AsyncSession = Depends(get_db_session),
    settings: Settings = Depends(_get_settings),
) -> ClaimResponse:
    resource_id = str(approval_id)
    fingerprint = fingerprint_request({})  # no request body to fingerprint
    replayed = await find_replayed_response(
        session,
        principal_subject=principal.subject,
        endpoint=_CLAIM_ENDPOINT,
        resource_id=resource_id,
        idempotency_key=idempotency_key,
        request_fingerprint=fingerprint,
    )
    if replayed is not None:
        return ClaimResponse.model_validate(replayed)

    record = await _load_record(session, approval_id)
    authorize_on_record(principal, ApprovalAction.CLAIM, _ownership(record))

    current = ApprovalStatus(record.status)
    next_status(current, ApprovalEvent.CLAIM)  # raises if illegal from here

    now = _now()
    attempt_id = uuid.uuid4()
    lease_expires = now + timedelta(seconds=settings.approval_execution_lease_seconds)

    result = await session.execute(
        update(PendingApprovalRecord)
        .where(
            PendingApprovalRecord.id == approval_id,
            PendingApprovalRecord.status == ApprovalStatus.ACCEPTED.value,
            (
                PendingApprovalRecord.execution_deadline.is_(None)
                | (PendingApprovalRecord.execution_deadline > now)
            ),
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

    response = ClaimResponse(
        id=approval_id,
        status=ApprovalStatus.EXECUTING.value,
        execution_attempt_id=attempt_id,
        executing_lease_expires_at=lease_expires,
        action_payload_digest=record.action_payload_digest,
    )
    record_response(
        session,
        principal_subject=principal.subject,
        endpoint=_CLAIM_ENDPOINT,
        resource_id=resource_id,
        idempotency_key=idempotency_key,
        request_fingerprint=fingerprint,
        response=response.model_dump(mode="json"),
    )
    await session.commit()
    return response


# --- REPORT-RESULT -----------------------------------------------------------

_REPORT_RESULT_ENDPOINT = "POST /approvals/{id}/report-result"


@router.post("/{approval_id}/report-result", response_model=ReportResultResponse)
async def report_result(
    approval_id: uuid.UUID,
    body: ReportResultRequest,
    idempotency_key: str = Header(alias="Idempotency-Key"),
    principal: Principal = Depends(get_current_principal),
    session: AsyncSession = Depends(get_db_session),
) -> ReportResultResponse:
    resource_id = str(approval_id)
    fingerprint = fingerprint_request(body.model_dump(mode="json"))
    replayed = await find_replayed_response(
        session,
        principal_subject=principal.subject,
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

    result = await session.execute(
        update(PendingApprovalRecord)
        .where(*where_clauses)
        .values(status=target.value)
        .returning(PendingApprovalRecord.id)
    )
    if result.scalar_one_or_none() is None:
        raise ConcurrentModificationError(approval_id=approval_id)

    response = ReportResultResponse(id=approval_id, status=target.value)
    record_response(
        session,
        principal_subject=principal.subject,
        endpoint=_REPORT_RESULT_ENDPOINT,
        resource_id=resource_id,
        idempotency_key=idempotency_key,
        request_fingerprint=fingerprint,
        response=response.model_dump(mode="json"),
    )
    await session.commit()
    return response


# --- CANCEL ------------------------------------------------------------------

_CANCEL_ENDPOINT = "POST /approvals/{id}/cancel"


@router.post("/{approval_id}/cancel", response_model=CancelResponse)
async def cancel_approval(
    approval_id: uuid.UUID,
    idempotency_key: str = Header(alias="Idempotency-Key"),
    principal: Principal = Depends(get_current_principal),
    session: AsyncSession = Depends(get_db_session),
) -> CancelResponse:
    resource_id = str(approval_id)
    fingerprint = fingerprint_request({})
    replayed = await find_replayed_response(
        session,
        principal_subject=principal.subject,
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

    response = CancelResponse(id=approval_id, status=target.value)
    record_response(
        session,
        principal_subject=principal.subject,
        endpoint=_CANCEL_ENDPOINT,
        resource_id=resource_id,
        idempotency_key=idempotency_key,
        request_fingerprint=fingerprint,
        response=response.model_dump(mode="json"),
    )
    await session.commit()
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
    idempotency_key: str = Header(alias="Idempotency-Key"),
    principal: Principal = Depends(get_current_principal),
    session: AsyncSession = Depends(get_db_session),
) -> ReconciliationFindingResponse:
    resource_id = str(approval_id)
    fingerprint = fingerprint_request(body.model_dump(mode="json"))
    replayed = await find_replayed_response(
        session,
        principal_subject=principal.subject,
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
        verifier_subject=principal.subject,
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
        principal_subject=principal.subject,
        endpoint=_RECONCILE_ENDPOINT,
        resource_id=resource_id,
        idempotency_key=idempotency_key,
        request_fingerprint=fingerprint,
        response=response.model_dump(mode="json"),
    )
    await session.commit()
    return response
