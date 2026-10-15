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

The size of one answer is bounded, which the number of findings on a record is not
(a requester may keep filing them): each record shows its newest
``_MAX_FINDINGS`` findings with ``findings_total`` saying how many exist, a ``note``
is cut at ``_NOTE_CHARS`` (``note_truncated``), and an ``evidence`` document longer
than ``_EVIDENCE_CHARS`` as JSON text is left out (``evidence_truncated``). The cutting
happens in the database, so the oversized values are never loaded. Whether a record is
``admin_verified`` always looks at ALL its findings, not only the ones shown.

Everything in ``note`` and ``evidence`` is text a requester or an administrator wrote;
treat it as untrusted wherever it is shown.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import Text, case, cast, exists, func, literal, select, tuple_
from sqlalchemy.ext.asyncio import AsyncSession

from central_governance_api.approvals.schemas import (
    FINDING_EVIDENCE_MAX_CHARS,
    FINDING_NOTE_MAX_CHARS,
)
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
_MAX_FINDINGS = 20
# the same limits the write side enforces (approvals/schemas.py), so a note or an
# evidence document accepted today is never cut here; older, longer ones still are
_NOTE_CHARS = FINDING_NOTE_MAX_CHARS
_EVIDENCE_CHARS = FINDING_EVIDENCE_MAX_CHARS


def _require_admin(principal: Principal = Depends(get_current_principal)) -> Principal:
    if "governance.admin" not in principal.roles:
        raise HTTPException(status_code=403, detail="Requires role 'governance.admin'")
    return principal


class FindingSummary(BaseModel):
    id: uuid.UUID
    finding_type: str
    conclusion: str | None
    note: str
    note_truncated: bool
    verifier: str
    evidence: dict[str, Any] | None
    evidence_truncated: bool
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
    findings_total: int
    findings: list[FindingSummary]


class QueueResponse(BaseModel):
    items: list[QueueItem]
    next_cursor: str | None


async def _findings_of(
    session: AsyncSession, approval_ids: list[uuid.UUID]
) -> tuple[dict[uuid.UUID, list[FindingSummary]], dict[uuid.UUID, int], set[uuid.UUID]]:
    """The newest ``_MAX_FINDINGS`` findings of each given approval (oldest first),
    how many findings each has in all, and which have an ``admin_verified`` one."""
    if not approval_ids:
        return {}, {}, set()
    too_long = func.length(cast(ReconciliationFinding.evidence, Text)) > _EVIDENCE_CHARS
    ranked = (
        select(
            ReconciliationFinding.id,
            ReconciliationFinding.approval_request_id,
            ReconciliationFinding.finding_type,
            ReconciliationFinding.conclusion,
            func.left(ReconciliationFinding.note, _NOTE_CHARS + 1).label("note"),
            ReconciliationFinding.verifier_issuer,
            ReconciliationFinding.verifier_sub,
            case((too_long, None), else_=ReconciliationFinding.evidence).label(
                "evidence"
            ),
            func.coalesce(too_long, False).label("evidence_truncated"),
            ReconciliationFinding.created_at,
            func.row_number()
            .over(
                partition_by=ReconciliationFinding.approval_request_id,
                order_by=(
                    ReconciliationFinding.created_at.desc(),
                    ReconciliationFinding.id.desc(),
                ),
            )
            .label("rank"),
        )
        .where(ReconciliationFinding.approval_request_id.in_(approval_ids))
        .subquery()
    )
    shown = await session.execute(
        select(ranked)
        .where(ranked.c.rank <= _MAX_FINDINGS)
        .order_by(ranked.c.created_at, ranked.c.id)
    )
    by_approval: dict[uuid.UUID, list[FindingSummary]] = {}
    for row in shown:
        by_approval.setdefault(row.approval_request_id, []).append(
            FindingSummary(
                id=row.id,
                finding_type=row.finding_type,
                conclusion=row.conclusion,
                note=row.note[:_NOTE_CHARS],
                note_truncated=len(row.note) > _NOTE_CHARS,
                verifier=f"{row.verifier_issuer}#{row.verifier_sub}",
                evidence=row.evidence,
                evidence_truncated=bool(row.evidence_truncated),
                created_at=row.created_at,
            )
        )
    counted = await session.execute(
        select(
            ReconciliationFinding.approval_request_id,
            func.count(ReconciliationFinding.id),
        )
        .where(ReconciliationFinding.approval_request_id.in_(approval_ids))
        .group_by(ReconciliationFinding.approval_request_id)
    )
    totals = {approval_id: count for approval_id, count in counted}
    verified_rows = await session.execute(
        select(ReconciliationFinding.approval_request_id)
        .where(
            ReconciliationFinding.approval_request_id.in_(approval_ids),
            ReconciliationFinding.finding_type == "admin_verified",
        )
        .distinct()
    )
    return by_approval, totals, set(verified_rows.scalars())


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
    findings, totals, verified = await _findings_of(session, [r.id for r in rows])
    return QueueResponse(
        items=[
            QueueItem(
                id=r.id,
                request_id=r.request_id,
                status=r.status,
                requester=f"{r.requester_issuer}#{r.requester_sub}",
                origin_device_id=r.origin_device_id,
                conversation_id=r.conversation_id,
                tool_name=r.tool_name,
                action_summary=r.action_summary,
                action_payload=r.action_payload,
                created_at=r.created_at,
                admin_verified=r.id in verified,
                findings_total=totals.get(r.id, 0),
                findings=findings.get(r.id, []),
            )
            for r in rows
        ],
        next_cursor=(
            encode_cursor(rows[-1].created_at, rows[-1].id) if has_more else None
        ),
    )
