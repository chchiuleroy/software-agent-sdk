"""Reconciliation queue: the approvals an administrator may need to verify by hand.

A request ends ``failed_unknown`` when its execution lease ran out without a report: the
action may or may not have happened. The device can later say what it saw (a
``late_report``) and the requester can state it (``requester_assertion``); both are
evidence from the requester's side. An ``admin_verified`` finding (filed through
``POST /api/v1/approvals/{id}/reconciliation-findings``) is the independent check, and
this endpoint is how an administrator finds the records that need one.

Read only. Lists ``failed_unknown`` records, newest first, with the findings each one
already has. A finding is evidence and never changes a record's status, so a
record stays in this list after it has been verified; ``admin_verified`` filters
on that.

Role: ``governance.admin`` only. ``governance.superadmin`` is deliberately not a
superset (see ``auth/oidc.py``), and the action this list leads to needs
``governance.admin`` anyway.

Paging is keyset on ``(created_at, id)`` of the approval, the same opaque cursor as the
audit trail (see ``routers/audit.py`` for what that does and does not promise).
Note that ``created_at`` is when the request was made, not when it became
``failed_unknown``.

Everything in ``note`` and ``evidence`` is text a requester or an administrator wrote;
treat it as untrusted wherever it is shown.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import exists, literal, select, tuple_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from central_governance_api.approvals.state_machine import ApprovalStatus
from central_governance_api.auth.dependencies import get_current_principal
from central_governance_api.auth.oidc import Principal
from central_governance_api.db import get_db_session
from central_governance_api.models import PendingApprovalRecord, ReconciliationFinding
from central_governance_api.routers.audit import (
    OffsetNotSupportedError,
    decode_cursor,
    encode_cursor,
)


router = APIRouter(prefix="/api/v1/reconciliation-queue", tags=["reconciliation"])

_MAX_LIMIT = 200
_DEFAULT_LIMIT = 50


def _require_admin(principal: Principal = Depends(get_current_principal)) -> Principal:
    if "governance.admin" not in principal.roles:
        raise HTTPException(status_code=403, detail="Requires role 'governance.admin'")
    return principal


class FindingSummary(BaseModel):
    id: uuid.UUID
    finding_type: str
    conclusion: str | None
    note: str
    verifier: str
    evidence: dict[str, Any] | None
    created_at: datetime


class QueueItem(BaseModel):
    id: uuid.UUID
    request_id: str
    status: str
    requester: str
    origin_device_id: str
    conversation_id: str
    tool_name: str
    action_summary: str
    action_payload: dict[str, Any]
    created_at: datetime
    admin_verified: bool
    findings: list[FindingSummary]


class QueueResponse(BaseModel):
    items: list[QueueItem]
    next_cursor: str | None


def _item(record: PendingApprovalRecord) -> QueueItem:
    findings = sorted(
        record.reconciliation_findings, key=lambda f: (f.created_at, f.id)
    )
    return QueueItem(
        id=record.id,
        request_id=record.request_id,
        status=record.status,
        requester=f"{record.requester_issuer}#{record.requester_sub}",
        origin_device_id=record.origin_device_id,
        conversation_id=record.conversation_id,
        tool_name=record.tool_name,
        action_summary=record.action_summary,
        action_payload=record.action_payload,
        created_at=record.created_at,
        admin_verified=any(f.finding_type == "admin_verified" for f in findings),
        findings=[
            FindingSummary(
                id=f.id,
                finding_type=f.finding_type,
                conclusion=f.conclusion,
                note=f.note,
                verifier=f"{f.verifier_issuer}#{f.verifier_sub}",
                evidence=f.evidence,
                created_at=f.created_at,
            )
            for f in findings
        ],
    )


@router.get("", response_model=QueueResponse, dependencies=[Depends(_require_admin)])
async def list_reconciliation_queue(
    session: AsyncSession = Depends(get_db_session),
    admin_verified: bool | None = Query(
        default=None,
        description="true: only records that already have an admin_verified finding; "
        "false: only those that do not; omitted: both",
    ),
    limit: int = Query(default=_DEFAULT_LIMIT, ge=1, le=_MAX_LIMIT),
    cursor: str | None = Query(default=None),
    offset: int | None = Query(default=None),
) -> QueueResponse:
    if offset is not None:
        raise OffsetNotSupportedError

    stmt = (
        select(PendingApprovalRecord)
        .where(PendingApprovalRecord.status == ApprovalStatus.FAILED_UNKNOWN.value)
        .options(selectinload(PendingApprovalRecord.reconciliation_findings))
        .order_by(
            PendingApprovalRecord.created_at.desc(), PendingApprovalRecord.id.desc()
        )
    )
    if cursor is not None:
        after_time, after_id = decode_cursor(cursor)
        stmt = stmt.where(
            tuple_(PendingApprovalRecord.created_at, PendingApprovalRecord.id)
            < tuple_(
                literal(after_time, type_=PendingApprovalRecord.created_at.type),
                literal(after_id, type_=PendingApprovalRecord.id.type),
            )
        )
    if admin_verified is not None:
        has_verified = exists().where(
            ReconciliationFinding.approval_request_id == PendingApprovalRecord.id,
            ReconciliationFinding.finding_type == "admin_verified",
        )
        stmt = stmt.where(has_verified if admin_verified else ~has_verified)

    # One extra row tells whether a next page exists without a COUNT(*).
    rows = list((await session.execute(stmt.limit(limit + 1))).scalars())
    has_more = len(rows) > limit
    rows = rows[:limit]
    return QueueResponse(
        items=[_item(row) for row in rows],
        next_cursor=(
            encode_cursor(rows[-1].created_at, rows[-1].id) if has_more else None
        ),
    )
