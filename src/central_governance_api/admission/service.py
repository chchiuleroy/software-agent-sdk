"""Database work of the admission registry (step C1). The routers stay thin.

Rules that matter here and are tested:

* the fingerprint is computed by central from the submitted content, never taken from
  the caller;
* an item can only become ``approved`` from ``checked``, by a person who is not the
  submitter, and only if its stored content still hashes to its fingerprint;
* every state change takes the item's row lock, so two decisions on one item run one
  after the other, and writes an audit event in the same transaction.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
import uuid
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from central_governance_api.accounts.errors import (
    DepartmentNotFoundError,
    SelfApprovalNotAllowedError,
)
from central_governance_api.accounts.tool_permissions import tool_permissions_for
from central_governance_api.admission import fingerprint as fp
from central_governance_api.admission.errors import (
    AdmissionContentChangedError,
    AdmissionContentInvalidError,
    AdmissionContentTooLargeError,
    AdmissionDepartmentNotAllowedError,
    AdmissionItemNotFoundError,
    AdmissionNoDepartmentError,
    AdmissionRateLimitedError,
)
from central_governance_api.admission.state import Event, Status, target
from central_governance_api.admission.unpack import UnpackedFile, unpack_zip
from central_governance_api.auth.oidc import Principal
from central_governance_api.clock import now_utc
from central_governance_api.config import Settings
from central_governance_api.models import (
    AdminAuditEvent,
    AdmissionFirstUse,
    AdmissionItem,
    AdmissionItemContent,
    AdmissionItemTool,
    Department,
)


_TOOL_NAME_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
_MAX_DESCRIPTION_CHARS = 20_000
FINGERPRINT_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

_OPEN = (Status.PENDING.value, Status.CHECKING.value, Status.CHECKED.value)


def _audit(
    principal: Principal, event_type: str, payload: dict[str, Any]
) -> AdminAuditEvent:
    return AdminAuditEvent(
        event_type=event_type,
        actor_issuer=principal.issuer,
        actor_sub=principal.sub,
        payload=payload,
    )


@dataclass(frozen=True)
class SubmitResult:
    item: AdmissionItem
    created: bool


@dataclass(frozen=True)
class ToolDescriptor:
    name: str
    description: str | None
    input_schema: dict[str, Any]


# --- content -> fingerprint ---------------------------------------------------


def _mcp_content(
    tools: list[ToolDescriptor], settings: Settings
) -> tuple[str, list[tuple[ToolDescriptor, str]]]:
    if not tools:
        raise AdmissionContentInvalidError("an MCP server needs at least one tool")
    if len(tools) > settings.admission_max_tools:
        raise AdmissionContentTooLargeError()
    names = [t.name for t in tools]
    if len(names) != len(set(names)):
        raise AdmissionContentInvalidError("two tools have the same name")
    pairs: list[tuple[ToolDescriptor, str]] = []
    for tool in tools:
        if not _TOOL_NAME_RE.match(tool.name):
            raise AdmissionContentInvalidError(
                "tool names must match [A-Za-z0-9_.:-]{1,128}"
            )
        if (
            tool.description is not None
            and len(tool.description) > _MAX_DESCRIPTION_CHARS
        ):
            raise AdmissionContentTooLargeError()
        try:
            pairs.append(
                (
                    tool,
                    fp.mcp_tool_fingerprint(
                        tool.name, tool.description, tool.input_schema
                    ),
                )
            )
        except (TypeError, ValueError):
            raise AdmissionContentInvalidError(
                "a tool schema is not plain JSON"
            ) from None
    return fp.mcp_server_fingerprint(f for _, f in pairs), pairs


def _archive_bytes(archive_b64: str, settings: Settings) -> bytes:
    # a base64 text is 4/3 of the bytes it holds; refuse before decoding anything big
    if len(archive_b64) > (settings.admission_max_archive_bytes * 4) // 3 + 8:
        raise AdmissionContentTooLargeError()
    try:
        data = base64.b64decode(archive_b64, validate=True)
    except (binascii.Error, ValueError):
        raise AdmissionContentInvalidError("the archive is not valid base64") from None
    if len(data) > settings.admission_max_archive_bytes:
        raise AdmissionContentTooLargeError()
    return data


def unpack_for(data: bytes, settings: Settings) -> list[UnpackedFile]:
    return unpack_zip(
        data,
        max_files=settings.admission_max_files,
        max_uncompressed_bytes=settings.admission_max_uncompressed_bytes,
    )


def archive_fingerprint(files: list[UnpackedFile]) -> str:
    return fp.manifest_fingerprint((f.path, f.sha256) for f in files)


# --- submit -------------------------------------------------------------------


async def _resolve_department(
    session: AsyncSession, principal: Principal, department_id: uuid.UUID | None
) -> uuid.UUID:
    if department_id is not None:
        if "governance.superadmin" not in principal.roles:
            raise AdmissionDepartmentNotAllowedError()
        found = (
            await session.execute(
                select(Department.id).where(Department.id == department_id)
            )
        ).first()
        if found is None:
            raise DepartmentNotFoundError()
        return department_id
    own = (await tool_permissions_for(session, principal)).department_id
    if own is None:
        raise AdmissionNoDepartmentError()
    return own


async def _existing(
    session: AsyncSession, kind: str, department_id: uuid.UUID, fingerprint: str
) -> AdmissionItem | None:
    return (
        await session.execute(
            select(AdmissionItem).where(
                AdmissionItem.kind == kind,
                AdmissionItem.department_id == department_id,
                AdmissionItem.fingerprint == fingerprint,
            )
        )
    ).scalar_one_or_none()


async def _enforce_limits(
    session: AsyncSession, principal: Principal, settings: Settings
) -> None:
    mine = (
        AdmissionItem.submitted_by_issuer == principal.issuer,
        AdmissionItem.submitted_by_sub == principal.sub,
    )
    recent = await session.scalar(
        select(func.count())
        .select_from(AdmissionItem)
        .where(*mine, AdmissionItem.created_at >= now_utc() - timedelta(hours=1))
    )
    if (recent or 0) >= settings.admission_max_submissions_per_hour:
        raise AdmissionRateLimitedError()
    waiting = await session.scalar(
        select(func.count())
        .select_from(AdmissionItem)
        .where(*mine, AdmissionItem.status.in_(_OPEN))
    )
    if (waiting or 0) >= settings.admission_max_open_per_user:
        raise AdmissionRateLimitedError()


async def submit(
    session: AsyncSession,
    principal: Principal,
    settings: Settings,
    *,
    kind: str,
    name: str,
    source: str,
    department_id: uuid.UUID | None,
    tools: list[ToolDescriptor] | None,
    archive_b64: str | None,
) -> SubmitResult:
    """Register a submission. Submitting only asks: the item starts ``pending``.
    The same content for the same department is one item: a second submission returns
    the first (and spends none of the submitter's limits)."""
    department = await _resolve_department(session, principal, department_id)
    tool_pairs: list[tuple[ToolDescriptor, str]] = []
    body: bytes | None = None
    if kind == "mcp_server":
        if archive_b64 is not None or tools is None:
            raise AdmissionContentInvalidError("an MCP server is submitted as tools")
        fingerprint, tool_pairs = _mcp_content(tools, settings)
    else:
        if tools is not None or archive_b64 is None:
            raise AdmissionContentInvalidError(
                "a skill or plugin is submitted as a zip"
            )
        body = _archive_bytes(archive_b64, settings)
        fingerprint = archive_fingerprint(unpack_for(body, settings))

    # One submission at a time per submitter, until this transaction ends: the two
    # limits below are "count, then insert", which two parallel requests of one user
    # would both pass. The lock is taken after the (CPU-heavy) unpacking, not before.
    await session.execute(
        text("select pg_advisory_xact_lock(hashtextextended(:key, 0))"),
        {"key": f"admission-submit:{principal.issuer}#{principal.sub}"},
    )
    found = await _existing(session, kind, department, fingerprint)
    if found is not None:
        return SubmitResult(found, created=False)
    await _enforce_limits(session, principal, settings)

    item = AdmissionItem(
        kind=kind,
        name=name,
        source=source,
        fingerprint=fingerprint,
        department_id=department,
        submitted_by_issuer=principal.issuer,
        submitted_by_sub=principal.sub,
        status=Status.PENDING.value,
    )
    try:
        session.add(item)
        await session.flush()
    except IntegrityError:
        # a concurrent identical submission won the race: hand back its item
        await session.rollback()
        winner = await _existing(session, kind, department, fingerprint)
        if winner is None:
            raise
        return SubmitResult(winner, created=False)
    if body is not None:
        session.add(
            AdmissionItemContent(item_id=item.id, content_type="zip", body=body)
        )
    for tool, tool_fp in tool_pairs:
        session.add(
            AdmissionItemTool(
                item_id=item.id,
                tool_name=tool.name,
                description=tool.description,
                input_schema=tool.input_schema,
                tool_fingerprint=tool_fp,
            )
        )
    session.add(
        _audit(
            principal,
            "admission_submitted",
            {
                "item_id": str(item.id),
                "kind": kind,
                "fingerprint": fingerprint,
                "department_id": str(department),
            },
        )
    )
    await session.commit()
    await session.refresh(item)
    return SubmitResult(item, created=True)


# --- decisions ----------------------------------------------------------------

_AUDIT_NAME = {
    Event.APPROVE: "admission_approved",
    Event.REJECT: "admission_rejected",
    Event.REVOKE: "admission_revoked",
    Event.RERUN: "admission_check_requested",
}


async def _recompute_fingerprint(
    session: AsyncSession, item: AdmissionItem, settings: Settings
) -> str:
    if item.kind == "mcp_server":
        rows = (
            await session.execute(
                select(AdmissionItemTool).where(AdmissionItemTool.item_id == item.id)
            )
        ).scalars()
        try:
            return fp.mcp_server_fingerprint(
                fp.mcp_tool_fingerprint(r.tool_name, r.description, r.input_schema)
                for r in rows
            )
        except (TypeError, ValueError):
            raise AdmissionContentChangedError() from None
    content = (
        await session.execute(
            select(AdmissionItemContent).where(AdmissionItemContent.item_id == item.id)
        )
    ).scalar_one_or_none()
    if content is None:
        raise AdmissionContentChangedError()
    try:
        return archive_fingerprint(unpack_for(content.body, settings))
    except (AdmissionContentInvalidError, AdmissionContentTooLargeError):
        raise AdmissionContentChangedError() from None


async def decide(
    session: AsyncSession,
    principal: Principal,
    settings: Settings,
    item_id: uuid.UUID,
    event: Event,
    reason: str | None = None,
) -> AdmissionItem:
    """Apply one human decision (approve, reject, revoke, rerun) to an item."""
    item = (
        await session.execute(
            select(AdmissionItem).where(AdmissionItem.id == item_id).with_for_update()
        )
    ).scalar_one_or_none()
    if item is None:
        raise AdmissionItemNotFoundError()
    new_status = target(Status(item.status), event)  # InvalidTransition if not allowed
    if event is Event.APPROVE:
        if (principal.issuer, principal.sub) == (
            item.submitted_by_issuer,
            item.submitted_by_sub,
        ):
            raise SelfApprovalNotAllowedError()
        if await _recompute_fingerprint(session, item, settings) != item.fingerprint:
            raise AdmissionContentChangedError()
    before = item.status
    item.status = new_status.value
    item.updated_at = now_utc()
    if event is Event.RERUN:
        item.status_reason = None
        item.decided_by_issuer = item.decided_by_sub = item.decided_at = None
    else:
        item.status_reason = reason if event in (Event.REJECT, Event.REVOKE) else None
        item.decided_by_issuer = principal.issuer
        item.decided_by_sub = principal.sub
        item.decided_at = item.updated_at
    session.add(
        _audit(
            principal,
            _AUDIT_NAME[event],
            {
                "item_id": str(item.id),
                "kind": item.kind,
                "fingerprint": item.fingerprint,
                "department_id": str(item.department_id),
                "from": before,
                "to": item.status,
            },
        )
    )
    await session.commit()
    await session.refresh(item)
    return item


# --- what a device reads --------------------------------------------------------


@dataclass(frozen=True)
class AdmittedItem:
    kind: str
    fingerprint: str
    tool_fingerprints: tuple[str, ...]


@dataclass(frozen=True)
class AdmittedSnapshot:
    department_id: uuid.UUID | None
    items: tuple[AdmittedItem, ...]

    @property
    def revision(self) -> str:
        raw = f"{self.department_id}|" + "\n".join(
            f"{i.kind}:{i.fingerprint}" for i in self.items
        )
        return hashlib.sha256(raw.encode()).hexdigest()[:16]


async def admitted_for(session: AsyncSession, principal: Principal) -> AdmittedSnapshot:
    """The approved items of the caller's department. No department, no items."""
    department = (await tool_permissions_for(session, principal)).department_id
    if department is None:
        return AdmittedSnapshot(None, ())
    items = (
        (
            await session.execute(
                select(AdmissionItem)
                .where(
                    AdmissionItem.department_id == department,
                    AdmissionItem.status == Status.APPROVED.value,
                )
                .order_by(AdmissionItem.kind, AdmissionItem.fingerprint)
            )
        )
        .scalars()
        .all()
    )
    tools: dict[uuid.UUID, list[str]] = {}
    mcp_ids = [i.id for i in items if i.kind == "mcp_server"]
    if mcp_ids:
        rows = await session.execute(
            select(AdmissionItemTool.item_id, AdmissionItemTool.tool_fingerprint)
            .where(AdmissionItemTool.item_id.in_(mcp_ids))
            .order_by(AdmissionItemTool.tool_fingerprint)
        )
        for item_id, tool_fp in rows:
            tools.setdefault(item_id, []).append(tool_fp)
    return AdmittedSnapshot(
        department,
        tuple(
            AdmittedItem(i.kind, i.fingerprint, tuple(tools.get(i.id, ())))
            for i in items
        ),
    )


_FIRST_USE_EVENTS = ("admission_first_use", "admission_first_use_mismatch")


async def _enforce_first_use_rate(
    session: AsyncSession, principal: Principal, settings: Settings
) -> None:
    recent = await session.scalar(
        select(func.count())
        .select_from(AdminAuditEvent)
        .where(
            AdminAuditEvent.event_type.in_(_FIRST_USE_EVENTS),
            AdminAuditEvent.actor_issuer == principal.issuer,
            AdminAuditEvent.actor_sub == principal.sub,
            AdminAuditEvent.occurred_at >= now_utc() - timedelta(minutes=1),
        )
    )
    if (recent or 0) >= settings.admission_first_use_per_minute:
        raise AdmissionRateLimitedError()


async def record_first_use(
    session: AsyncSession,
    principal: Principal,
    settings: Settings,
    *,
    kind: str,
    fingerprint: str,
    local_fingerprint: str,
) -> str:
    """A device is about to load ``fingerprint`` for the first time. Returns what the
    device must act on: ``approved`` is the only answer that lets it load; every other
    answer (``unknown``, ``mismatch``, ``revoked``, ``rejected`` ...) means do not.

    A mismatch (the device's own bytes hash to something else) does NOT change the
    item: it says something about that one device's copy, not about the approved
    content, and letting one device flag an item would let one compromised device block
    everyone. It is recorded and audited so it can be looked at.

    Every call writes an audit event, so one identity is limited per minute; the same
    report repeated (same device, fingerprint and answer) adds no second row."""
    await _enforce_first_use_rate(session, principal, settings)
    department = (await tool_permissions_for(session, principal)).department_id
    item = (
        await _existing(session, kind, department, fingerprint)
        if department is not None
        else None
    )
    if local_fingerprint != fingerprint:
        result = "mismatch"
    elif item is None:
        result = "unknown"
    else:
        result = item.status
    if item is not None:
        already = await session.scalar(
            select(func.count())
            .select_from(AdmissionFirstUse)
            .where(
                AdmissionFirstUse.item_id == item.id,
                AdmissionFirstUse.device_issuer == principal.issuer,
                AdmissionFirstUse.device_sub == principal.sub,
                AdmissionFirstUse.fingerprint == fingerprint,
                AdmissionFirstUse.result == result,
            )
        )
        if not already:
            session.add(
                AdmissionFirstUse(
                    item_id=item.id,
                    device_issuer=principal.issuer,
                    device_sub=principal.sub,
                    fingerprint=fingerprint,
                    result=result,
                )
            )
    payload = {
        "item_id": str(item.id) if item is not None else None,
        "kind": kind,
        "fingerprint": fingerprint,
        "local_fingerprint": local_fingerprint,
        "result": result,
    }
    if result == "mismatch":
        session.add(_audit(principal, "admission_first_use_mismatch", payload))
    else:
        session.add(_audit(principal, "admission_first_use", payload))
    await session.commit()
    return result
