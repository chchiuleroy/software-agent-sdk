"""Audit-events read endpoint.

v11 §3: read access to the admin audit trail (`AdminAuditEvent` — device
revocations, pre-claim aborts, plain cancels, department changes; see
`routers/approvals.py`, `routers/devices.py` and `routers/admin_accounts.py` for what
writes into it) is limited to ``governance.admin`` and ``governance.superadmin``
(the latter added 2026-10-14 for the console's Audit screen; it is NOT a superset of
``governance.admin`` anywhere else). No idempotency handling here — a GET has no side
effects to make idempotent.

This table is the one authoritative audit source (Roy, 2026-10-14). The JSONL files
the agent-server writes locally (policy/analyzer changes, local approvals) are
diagnostics of that device and are not ingested here: they would be a device's own
claim about itself, which this service cannot verify.

Paging is keyset, newest first, keyed on ``(occurred_at, id)``. The cursor is an
opaque position, not a secret: it is unsigned, and forging one only chooses a start
point inside data the caller may already read. It does not carry the filters, so
changing a filter between two pages gives "rows after that position that match the
new filter".

Known limit, disclosed rather than fixed: ``occurred_at`` is the database's
transaction start time (``now()``), not the commit time. A long transaction can
therefore commit a row whose ``occurred_at`` is older than rows already served, and a
walk that has passed that position will not see it; a fresh walk will.
"""

from __future__ import annotations

import base64
import binascii
import json
import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import literal, select, tuple_
from sqlalchemy.ext.asyncio import AsyncSession

from central_governance_api.auth.dependencies import get_current_principal
from central_governance_api.auth.oidc import Principal
from central_governance_api.db import get_db_session
from central_governance_api.models import AdminAuditEvent


router = APIRouter(prefix="/api/v1/audit-events", tags=["audit"])

_MAX_LIMIT = 200
_DEFAULT_LIMIT = 50
_MAX_CURSOR_LENGTH = 512
_CURSOR_VERSION = 1
_AUDIT_READER_ROLES = frozenset({"governance.admin", "governance.superadmin"})


class InvalidCursorError(Exception):
    """Maps to HTTP 400. The message is safe to show: it never echoes the cursor."""

    def __init__(self) -> None:
        super().__init__("cursor is not a position this service issued")


class OffsetNotSupportedError(Exception):
    """Maps to HTTP 400. ``offset`` paging was replaced by ``cursor``; ignoring the
    parameter would silently return the first page again."""

    def __init__(self) -> None:
        super().__init__("offset paging was removed; follow next_cursor instead")


def encode_cursor(occurred_at: datetime, event_id: uuid.UUID) -> str:
    raw = json.dumps(
        {"v": _CURSOR_VERSION, "t": occurred_at.isoformat(), "i": str(event_id)},
        separators=(",", ":"),
    )
    return base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")


def decode_cursor(cursor: str) -> tuple[datetime, uuid.UUID]:
    try:
        if not cursor or len(cursor) > _MAX_CURSOR_LENGTH:
            raise InvalidCursorError
        padded = cursor + "=" * (-len(cursor) % 4)
        body = json.loads(base64.urlsafe_b64decode(padded.encode()))
        if (
            not isinstance(body, dict)
            or set(body) != {"v", "t", "i"}
            or type(body["v"]) is not int
            or body["v"] != _CURSOR_VERSION
            or not isinstance(body["t"], str)
            or not isinstance(body["i"], str)
        ):
            raise InvalidCursorError
        occurred_at = datetime.fromisoformat(body["t"])
        if occurred_at.tzinfo is None:
            # A naive time would be read in the session's zone: never what we issued.
            raise InvalidCursorError
        return occurred_at, uuid.UUID(body["i"])
    except InvalidCursorError:
        raise
    except (ValueError, TypeError, binascii.Error, UnicodeDecodeError) as exc:
        raise InvalidCursorError from exc


def _require_audit_reader(
    principal: Principal = Depends(get_current_principal),
) -> Principal:
    if _AUDIT_READER_ROLES.isdisjoint(principal.roles):
        raise HTTPException(
            status_code=403,
            detail="Requires role 'governance.admin' or 'governance.superadmin'",
        )
    return principal


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
    next_cursor: str | None


@router.get(
    "",
    response_model=AuditEventListResponse,
    dependencies=[Depends(_require_audit_reader)],
)
async def list_audit_events(
    session: AsyncSession = Depends(get_db_session),
    event_type: str | None = Query(default=None),
    approval_request_id: uuid.UUID | None = Query(default=None),
    limit: int = Query(default=_DEFAULT_LIMIT, ge=1, le=_MAX_LIMIT),
    cursor: str | None = Query(default=None),
    offset: int | None = Query(default=None),
) -> AuditEventListResponse:
    if offset is not None:
        raise OffsetNotSupportedError

    stmt = select(AdminAuditEvent).order_by(
        AdminAuditEvent.occurred_at.desc(), AdminAuditEvent.id.desc()
    )
    if cursor is not None:
        after_time, after_id = decode_cursor(cursor)
        stmt = stmt.where(
            tuple_(AdminAuditEvent.occurred_at, AdminAuditEvent.id)
            < tuple_(
                literal(after_time, type_=AdminAuditEvent.occurred_at.type),
                literal(after_id, type_=AdminAuditEvent.id.type),
            )
        )
    if event_type is not None:
        stmt = stmt.where(AdminAuditEvent.event_type == event_type)
    if approval_request_id is not None:
        stmt = stmt.where(AdminAuditEvent.approval_request_id == approval_request_id)

    # Fetch one extra row to know whether a next page exists without a
    # separate COUNT(*) query.
    rows = list((await session.execute(stmt.limit(limit + 1))).scalars())
    has_more = len(rows) > limit
    rows = rows[:limit]

    items = [
        AuditEventResponse(
            id=row.id,
            event_type=row.event_type,
            actor_subject=f"{row.actor_issuer}#{row.actor_sub}",
            origin_device_id=row.origin_device_id,
            approval_request_id=row.approval_request_id,
            occurred_at=row.occurred_at,
            payload=row.payload,
        )
        for row in rows
    ]
    return AuditEventListResponse(
        items=items,
        next_cursor=(
            encode_cursor(rows[-1].occurred_at, rows[-1].id) if has_more else None
        ),
    )
