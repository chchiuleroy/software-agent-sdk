"""Audit-events read endpoint.

v11 §3: read access to the admin audit trail (`AdminAuditEvent` — device
revocations, pre-claim aborts, plain cancels; see `routers/approvals.py`
and `routers/devices.py` for what writes into it) is `governance.admin`
only, matching the RBAC matrix's `RECONCILE_AS_ADMIN`-style restriction
on anything that inspects rather than acts within its own scope. No
idempotency handling here — a GET has no side effects to make idempotent.

Code-review Low, disclosed rather than fixed here: pagination is plain
offset/limit, ordered newest-first. That's an inherent trade-off, not a
counting bug in this file (the "fetch limit+1 to detect a next page"
logic itself is correct) — a caller paging through results while new
audit events keep arriving can see an item shift between pages (repeated
or skipped) because "page 2" is just "skip N rows from a result set
that's still growing at the front". A stable walk under concurrent writes
would need cursor-based pagination keyed on `(occurred_at, id)` instead;
not built here since nothing in this pass actually needs that guarantee.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from central_governance_api.auth.dependencies import require_role
from central_governance_api.db import get_db_session
from central_governance_api.models import AdminAuditEvent


router = APIRouter(prefix="/api/v1/audit-events", tags=["audit"])

_MAX_LIMIT = 200
_DEFAULT_LIMIT = 50


class AuditEventResponse(BaseModel):
    id: uuid.UUID
    event_type: str
    actor_subject: str
    origin_device_id: str | None
    approval_request_id: uuid.UUID | None
    occurred_at: datetime
    payload: dict[str, Any]


class AuditEventListResponse(BaseModel):
    items: list[AuditEventResponse]
    next_offset: int | None


@router.get(
    "",
    response_model=AuditEventListResponse,
    dependencies=[Depends(require_role("governance.admin"))],
)
async def list_audit_events(
    session: AsyncSession = Depends(get_db_session),
    event_type: str | None = Query(default=None),
    approval_request_id: uuid.UUID | None = Query(default=None),
    limit: int = Query(default=_DEFAULT_LIMIT, ge=1, le=_MAX_LIMIT),
    offset: int = Query(default=0, ge=0),
) -> AuditEventListResponse:
    stmt = select(AdminAuditEvent).order_by(
        AdminAuditEvent.occurred_at.desc(), AdminAuditEvent.id.desc()
    )
    if event_type is not None:
        stmt = stmt.where(AdminAuditEvent.event_type == event_type)
    if approval_request_id is not None:
        stmt = stmt.where(AdminAuditEvent.approval_request_id == approval_request_id)

    # Fetch one extra row to know whether a next page exists without a
    # separate COUNT(*) query.
    rows = list((await session.execute(stmt.offset(offset).limit(limit + 1))).scalars())
    has_more = len(rows) > limit
    rows = rows[:limit]

    items = [
        AuditEventResponse(
            id=row.id,
            event_type=row.event_type,
            actor_subject=row.actor_subject,
            origin_device_id=row.origin_device_id,
            approval_request_id=row.approval_request_id,
            occurred_at=row.occurred_at,
            payload=row.payload,
        )
        for row in rows
    ]
    return AuditEventListResponse(
        items=items, next_offset=(offset + limit) if has_more else None
    )
