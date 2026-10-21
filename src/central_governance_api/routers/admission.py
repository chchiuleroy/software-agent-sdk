"""Admission registry endpoints (step C1 of OHS_admission_design_gate2.md).

* any logged-in user submits an MCP server / skill / plugin and sees their own
  submissions (``/api/v1/admission/items``, ``/api/v1/me/admission/items``);
* a device (an agent-server's service account) reads the approved items of its
  department (``/api/v1/me/admitted-items``) and reports the first time it loads one
  (``/api/v1/me/admission/first-use``);
* a superadmin lists, reads and decides (``/api/v1/admin/admission/items``).

Submitting only asks. With no check pipeline yet (C5, C6) nothing can reach ``checked``
through these endpoints, so ``approve`` always answers 409: fail closed by construction.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Query, Response
from pydantic import BaseModel, Field, StringConstraints
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from central_governance_api.admission import service
from central_governance_api.admission.errors import AdmissionItemNotFoundError
from central_governance_api.admission.service import ToolDescriptor
from central_governance_api.admission.state import Event
from central_governance_api.auth.dependencies import (
    get_current_principal,
    require_role,
)
from central_governance_api.auth.oidc import Principal
from central_governance_api.config import Settings, get_settings_dependency
from central_governance_api.db import get_db_session
from central_governance_api.models import (
    AdmissionItem,
    AdmissionItemContent,
    AdmissionItemTool,
)
from central_governance_api.schemas_base import RequestModel


submit_router = APIRouter(prefix="/api/v1/admission", tags=["admission"])
me_router = APIRouter(prefix="/api/v1/me", tags=["me"])
admin_router = APIRouter(prefix="/api/v1/admin/admission", tags=["admission"])

_require_superadmin = require_role("governance.superadmin")
# What an agent-server's service account is: the two device endpoints below answer
# only to it, not to every logged-in person.
_require_operator = require_role("agent.operator")

_MAX_LIMIT = 200
_DEFAULT_LIMIT = 50

Kind = Literal["mcp_server", "skill", "plugin"]
AdmissionStatus = Literal[
    "pending",
    "checking",
    "rejected",
    "check_failed",
    "checked",
    "approved",
    "revoked",
]
Fingerprint = Annotated[str, StringConstraints(pattern=service.FINGERPRINT_RE.pattern)]


class ToolBody(RequestModel):
    name: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    description: str | None = None
    input_schema: dict[str, Any]


class SubmitRequest(RequestModel):
    kind: Kind
    name: Annotated[str, StringConstraints(min_length=1, max_length=200)]
    source: Annotated[str, StringConstraints(min_length=1, max_length=1024)]
    department_id: uuid.UUID | None = None
    tools: list[ToolBody] | None = None
    archive_b64: str | None = None


class DecisionRequest(RequestModel):
    reason: Annotated[str, StringConstraints(max_length=1000)] | None = None


class ItemSummary(BaseModel):
    id: uuid.UUID
    kind: str
    name: str
    source: str
    fingerprint: str
    department_id: uuid.UUID
    status: str
    status_reason: str | None
    created_at: datetime
    updated_at: datetime
    decided_at: datetime | None


class SubmitResponse(ItemSummary):
    created: bool


class AdminItemSummary(ItemSummary):
    submitted_by_sub: str
    decided_by_sub: str | None


class ToolDetail(BaseModel):
    name: str
    description: str | None
    input_schema: dict[str, Any]
    tool_fingerprint: str


class FileDetail(BaseModel):
    path: str
    sha256: str
    size: int


class AdminItemDetail(AdminItemSummary):
    tools: list[ToolDetail] = Field(default_factory=list)
    files: list[FileDetail] = Field(default_factory=list)


class AdmittedItemResponse(BaseModel):
    kind: str
    fingerprint: str
    tool_fingerprints: list[str]


class AdmittedItemsResponse(BaseModel):
    department_id: uuid.UUID | None
    items: list[AdmittedItemResponse]
    revision: str
    max_age_seconds: int


class FirstUseRequest(RequestModel):
    kind: Kind
    fingerprint: Fingerprint
    local_fingerprint: Annotated[str, StringConstraints(min_length=1, max_length=200)]


class FirstUseResponse(BaseModel):
    status: str


def _summary(item: AdmissionItem) -> dict[str, Any]:
    return {
        "id": item.id,
        "kind": item.kind,
        "name": item.name,
        "source": item.source,
        "fingerprint": item.fingerprint,
        "department_id": item.department_id,
        "status": item.status,
        "status_reason": item.status_reason,
        "created_at": item.created_at,
        "updated_at": item.updated_at,
        "decided_at": item.decided_at,
    }


def _admin_summary(item: AdmissionItem) -> dict[str, Any]:
    return {
        **_summary(item),
        "submitted_by_sub": item.submitted_by_sub,
        "decided_by_sub": item.decided_by_sub,
    }


# --- submit and own items -----------------------------------------------------


@submit_router.post("/items", response_model=SubmitResponse, status_code=201)
async def submit_item(
    body: SubmitRequest,
    response: Response,
    principal: Principal = Depends(get_current_principal),
    session: AsyncSession = Depends(get_db_session),
    settings: Settings = Depends(get_settings_dependency),
) -> dict[str, Any]:
    """Ask for an item to be allowed. The same content for the same department is one
    item: a repeat returns the first with 200 and ``created: false``."""
    result = await service.submit(
        session,
        principal,
        settings,
        kind=body.kind,
        name=body.name,
        source=body.source,
        department_id=body.department_id,
        tools=None
        if body.tools is None
        else [
            ToolDescriptor(t.name, t.description, t.input_schema) for t in body.tools
        ],
        archive_b64=body.archive_b64,
    )
    summary = {**_summary(result.item), "created": result.created}
    if not result.created:
        response.status_code = 200
        if (result.item.submitted_by_issuer, result.item.submitted_by_sub) != (
            principal.issuer,
            principal.sub,
        ):
            # The same content was submitted by somebody else in this department:
            # say it exists and where it stands, but not what they called it, where
            # it came from, or why it was decided as it was.
            summary.update(name=body.name, source=body.source, status_reason=None)
    return summary


@me_router.get("/admission/items", response_model=list[ItemSummary])
async def my_items(
    principal: Principal = Depends(get_current_principal),
    session: AsyncSession = Depends(get_db_session),
    limit: int = Query(default=_DEFAULT_LIMIT, ge=1, le=_MAX_LIMIT),
) -> list[dict[str, Any]]:
    rows = await session.execute(
        select(AdmissionItem)
        .where(
            AdmissionItem.submitted_by_issuer == principal.issuer,
            AdmissionItem.submitted_by_sub == principal.sub,
        )
        .order_by(AdmissionItem.created_at.desc(), AdmissionItem.id)
        .limit(limit)
    )
    return [_summary(i) for i in rows.scalars()]


# --- what a device reads --------------------------------------------------------


@me_router.get("/admitted-items", response_model=AdmittedItemsResponse)
async def my_admitted_items(
    principal: Principal = Depends(_require_operator),
    session: AsyncSession = Depends(get_db_session),
    settings: Settings = Depends(get_settings_dependency),
) -> dict[str, Any]:
    snapshot = await service.admitted_for(session, principal)
    return {
        "department_id": snapshot.department_id,
        "items": [
            {
                "kind": i.kind,
                "fingerprint": i.fingerprint,
                "tool_fingerprints": list(i.tool_fingerprints),
            }
            for i in snapshot.items
        ],
        "revision": snapshot.revision,
        "max_age_seconds": settings.admission_max_age_seconds,
    }


@me_router.post("/admission/first-use", response_model=FirstUseResponse)
async def first_use(
    body: FirstUseRequest,
    principal: Principal = Depends(_require_operator),
    session: AsyncSession = Depends(get_db_session),
    settings: Settings = Depends(get_settings_dependency),
) -> dict[str, str]:
    """A device is about to load an item for the first time. Only ``approved`` lets
    it."""
    status = await service.record_first_use(
        session,
        principal,
        settings,
        kind=body.kind,
        fingerprint=body.fingerprint,
        local_fingerprint=body.local_fingerprint,
    )
    return {"status": status}


# --- superadmin -----------------------------------------------------------------


@admin_router.get("/items", response_model=list[AdminItemSummary])
async def list_items(
    _principal: Principal = Depends(_require_superadmin),
    session: AsyncSession = Depends(get_db_session),
    status: AdmissionStatus | None = Query(default=None),
    kind: Kind | None = Query(default=None),
    limit: int = Query(default=_DEFAULT_LIMIT, ge=1, le=_MAX_LIMIT),
) -> list[dict[str, Any]]:
    """Newest first. No paging cursor yet (the review screen, item 2.8, adds one)."""
    stmt = select(AdmissionItem)
    if status is not None:
        stmt = stmt.where(AdmissionItem.status == status)
    if kind is not None:
        stmt = stmt.where(AdmissionItem.kind == kind)
    rows = await session.execute(
        stmt.order_by(AdmissionItem.created_at.desc(), AdmissionItem.id).limit(limit)
    )
    return [_admin_summary(i) for i in rows.scalars()]


@admin_router.get("/items/{item_id}", response_model=AdminItemDetail)
async def get_item(
    item_id: uuid.UUID,
    _principal: Principal = Depends(_require_superadmin),
    session: AsyncSession = Depends(get_db_session),
    settings: Settings = Depends(get_settings_dependency),
) -> dict[str, Any]:
    """The item with its content, whole: tool descriptions are not shortened, files are
    listed with their hashes. The content is untrusted text; a screen must show it as
    text only."""
    item = (
        await session.execute(select(AdmissionItem).where(AdmissionItem.id == item_id))
    ).scalar_one_or_none()
    if item is None:
        raise AdmissionItemNotFoundError()
    detail: dict[str, Any] = {**_admin_summary(item), "tools": [], "files": []}
    if item.kind == "mcp_server":
        tools = await session.execute(
            select(AdmissionItemTool)
            .where(AdmissionItemTool.item_id == item.id)
            .order_by(AdmissionItemTool.tool_name)
        )
        detail["tools"] = [
            {
                "name": t.tool_name,
                "description": t.description,
                "input_schema": t.input_schema,
                "tool_fingerprint": t.tool_fingerprint,
            }
            for t in tools.scalars()
        ]
    else:
        content = (
            await session.execute(
                select(AdmissionItemContent).where(
                    AdmissionItemContent.item_id == item.id
                )
            )
        ).scalar_one_or_none()
        if content is not None:
            detail["files"] = [
                {"path": f.path, "sha256": f.sha256, "size": f.size}
                for f in sorted(
                    service.unpack_for(content.body, settings), key=lambda f: f.path
                )
            ]
    return detail


async def _decide(
    event: Event,
    item_id: uuid.UUID,
    reason: str | None,
    principal: Principal,
    session: AsyncSession,
    settings: Settings,
) -> dict[str, Any]:
    item = await service.decide(session, principal, settings, item_id, event, reason)
    return _admin_summary(item)


@admin_router.post("/items/{item_id}/approve", response_model=AdminItemSummary)
async def approve_item(
    item_id: uuid.UUID,
    principal: Principal = Depends(_require_superadmin),
    session: AsyncSession = Depends(get_db_session),
    settings: Settings = Depends(get_settings_dependency),
) -> dict[str, Any]:
    """Only a ``checked`` item, never by its own submitter, only while its stored
    content still hashes to its fingerprint."""
    return await _decide(Event.APPROVE, item_id, None, principal, session, settings)


@admin_router.post("/items/{item_id}/reject", response_model=AdminItemSummary)
async def reject_item(
    item_id: uuid.UUID,
    body: DecisionRequest,
    principal: Principal = Depends(_require_superadmin),
    session: AsyncSession = Depends(get_db_session),
    settings: Settings = Depends(get_settings_dependency),
) -> dict[str, Any]:
    return await _decide(
        Event.REJECT, item_id, body.reason, principal, session, settings
    )


@admin_router.post("/items/{item_id}/revoke", response_model=AdminItemSummary)
async def revoke_item(
    item_id: uuid.UUID,
    body: DecisionRequest,
    principal: Principal = Depends(_require_superadmin),
    session: AsyncSession = Depends(get_db_session),
    settings: Settings = Depends(get_settings_dependency),
) -> dict[str, Any]:
    """Takes effect for a device within ``admission_max_age_seconds`` (its list), and
    at once for a first use (that asks central). It does not undo calls already made."""
    return await _decide(
        Event.REVOKE, item_id, body.reason, principal, session, settings
    )


@admin_router.post("/items/{item_id}/rerun-check", response_model=AdminItemSummary)
async def rerun_check(
    item_id: uuid.UUID,
    principal: Principal = Depends(_require_superadmin),
    session: AsyncSession = Depends(get_db_session),
    settings: Settings = Depends(get_settings_dependency),
) -> dict[str, Any]:
    """Back to ``pending`` so the checks run again. There is no way to approve past a
    failed check; this is the only way back."""
    return await _decide(Event.RERUN, item_id, None, principal, session, settings)
