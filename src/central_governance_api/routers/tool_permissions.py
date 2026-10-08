"""Department tool permissions.

Superadmin endpoints set which tools a department may use and which
service-account identity (an agent-server's client) belongs to it. Any
authenticated caller can read its own answer from
``GET /api/v1/me/tool-permissions``; an agent-server fetches that, caches it
for at most ``max_age_seconds`` and treats every tool as not permitted after
that (see the device side in openhands-agent-server).

The list is an allow-list: a tool nobody listed is not permitted, and tool
names are free text (central does not know which tools exist on devices), so a
typo grants nothing.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Response
from pydantic import BaseModel, StringConstraints, field_validator
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from central_governance_api.accounts.errors import (
    DepartmentNotFoundError,
    PrincipalAlreadyAssignedError,
    PrincipalAssignmentNotFoundError,
)
from central_governance_api.accounts.tool_permissions import tool_permissions_for
from central_governance_api.auth.dependencies import (
    get_current_principal,
    require_role,
)
from central_governance_api.auth.oidc import Principal
from central_governance_api.config import Settings, get_settings_dependency
from central_governance_api.db import get_db_session
from central_governance_api.models import (
    AdminAuditEvent,
    Department,
    DepartmentPrincipal,
    DepartmentToolPermission,
)
from central_governance_api.schemas_base import RequestModel


admin_router = APIRouter(prefix="/api/v1/admin", tags=["tool-permissions"])
me_router = APIRouter(prefix="/api/v1/me", tags=["me"])

_require_superadmin = require_role("governance.superadmin")

_TOOL_NAME_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
_MAX_TOOLS = 200


class SetToolsRequest(RequestModel):
    tools: list[str]

    @field_validator("tools")
    @classmethod
    def _check_tools(cls, v: list[str]) -> list[str]:
        if len(v) > _MAX_TOOLS:
            raise ValueError(f"at most {_MAX_TOOLS} tools")
        for name in v:
            if not _TOOL_NAME_RE.match(name):
                raise ValueError("tool names must match [A-Za-z0-9_.:-]{1,128}")
        return sorted(set(v))


class ToolsResponse(BaseModel):
    department_id: uuid.UUID
    tools: list[str]


class AssignPrincipalRequest(RequestModel):
    sub: Annotated[str, StringConstraints(min_length=1, max_length=255)]
    issuer: Annotated[str, StringConstraints(min_length=1, max_length=512)] | None = (
        None
    )


class PrincipalAssignmentResponse(BaseModel):
    id: uuid.UUID
    department_id: uuid.UUID
    issuer: str
    sub: str
    assigned_at: datetime


class MyToolPermissionsResponse(BaseModel):
    department_id: uuid.UUID | None
    department_name: str | None
    tools: list[str]
    revision: str
    max_age_seconds: int


async def _require_department(session: AsyncSession, department_id: uuid.UUID) -> None:
    found = (
        await session.execute(
            select(Department.id).where(Department.id == department_id)
        )
    ).first()
    if found is None:
        raise DepartmentNotFoundError()


async def _current_tools(session: AsyncSession, department_id: uuid.UUID) -> list[str]:
    rows = await session.execute(
        select(DepartmentToolPermission.tool_name)
        .where(DepartmentToolPermission.department_id == department_id)
        .order_by(DepartmentToolPermission.tool_name)
    )
    return list(rows.scalars())


@admin_router.get("/departments/{department_id}/tools", response_model=ToolsResponse)
async def get_department_tools(
    department_id: uuid.UUID,
    _principal: Principal = Depends(_require_superadmin),
    session: AsyncSession = Depends(get_db_session),
) -> ToolsResponse:
    await _require_department(session, department_id)
    return ToolsResponse(
        department_id=department_id, tools=await _current_tools(session, department_id)
    )


@admin_router.put("/departments/{department_id}/tools", response_model=ToolsResponse)
async def set_department_tools(
    department_id: uuid.UUID,
    body: SetToolsRequest,
    principal: Principal = Depends(_require_superadmin),
    session: AsyncSession = Depends(get_db_session),
) -> ToolsResponse:
    """Replace the whole set. A no-op (nothing added or removed) writes no
    audit event."""
    await _require_department(session, department_id)
    before = set(await _current_tools(session, department_id))
    after = set(body.tools)
    added, removed = sorted(after - before), sorted(before - after)
    if removed:
        await session.execute(
            delete(DepartmentToolPermission).where(
                DepartmentToolPermission.department_id == department_id,
                DepartmentToolPermission.tool_name.in_(removed),
            )
        )
    for name in added:
        session.add(
            DepartmentToolPermission(
                department_id=department_id,
                tool_name=name,
                granted_by_issuer=principal.issuer,
                granted_by_sub=principal.sub,
            )
        )
    if added or removed:
        session.add(
            AdminAuditEvent(
                event_type="department_tools_set",
                actor_issuer=principal.issuer,
                actor_sub=principal.sub,
                payload={
                    "department_id": str(department_id),
                    "added": added,
                    "removed": removed,
                },
            )
        )
    await session.commit()
    return ToolsResponse(department_id=department_id, tools=sorted(after))


@admin_router.get(
    "/departments/{department_id}/principals",
    response_model=list[PrincipalAssignmentResponse],
)
async def list_department_principals(
    department_id: uuid.UUID,
    _principal: Principal = Depends(_require_superadmin),
    session: AsyncSession = Depends(get_db_session),
) -> list[DepartmentPrincipal]:
    await _require_department(session, department_id)
    rows = await session.execute(
        select(DepartmentPrincipal)
        .where(DepartmentPrincipal.department_id == department_id)
        .order_by(DepartmentPrincipal.assigned_at, DepartmentPrincipal.id)
    )
    return list(rows.scalars())


@admin_router.post(
    "/departments/{department_id}/principals",
    response_model=PrincipalAssignmentResponse,
    status_code=201,
)
async def assign_principal(
    department_id: uuid.UUID,
    body: AssignPrincipalRequest,
    principal: Principal = Depends(_require_superadmin),
    session: AsyncSession = Depends(get_db_session),
    settings: Settings = Depends(get_settings_dependency),
) -> PrincipalAssignmentResponse:
    await _require_department(session, department_id)
    assignment = DepartmentPrincipal(
        department_id=department_id,
        issuer=body.issuer or settings.oidc_issuer,
        sub=body.sub,
        assigned_by_issuer=principal.issuer,
        assigned_by_sub=principal.sub,
    )
    try:
        session.add(assignment)
        await session.flush()
    except IntegrityError:
        await session.rollback()
        raise PrincipalAlreadyAssignedError() from None
    await session.refresh(assignment)  # server-default assigned_at
    session.add(
        AdminAuditEvent(
            event_type="department_principal_assigned",
            actor_issuer=principal.issuer,
            actor_sub=principal.sub,
            payload={
                "department_id": str(department_id),
                "issuer": assignment.issuer,
                "sub": assignment.sub,
            },
        )
    )
    response = PrincipalAssignmentResponse.model_validate(
        assignment, from_attributes=True
    )
    await session.commit()
    return response


@admin_router.delete(
    "/departments/{department_id}/principals/{assignment_id}", status_code=204
)
async def unassign_principal(
    department_id: uuid.UUID,
    assignment_id: uuid.UUID,
    principal: Principal = Depends(_require_superadmin),
    session: AsyncSession = Depends(get_db_session),
) -> Response:
    removed = (
        await session.execute(
            delete(DepartmentPrincipal)
            .where(
                DepartmentPrincipal.id == assignment_id,
                DepartmentPrincipal.department_id == department_id,
            )
            .returning(DepartmentPrincipal.issuer, DepartmentPrincipal.sub)
        )
    ).first()
    if removed is None:
        raise PrincipalAssignmentNotFoundError()
    session.add(
        AdminAuditEvent(
            event_type="department_principal_unassigned",
            actor_issuer=principal.issuer,
            actor_sub=principal.sub,
            payload={
                "department_id": str(department_id),
                "issuer": removed.issuer,
                "sub": removed.sub,
            },
        )
    )
    await session.commit()
    return Response(status_code=204)


@me_router.get("/tool-permissions", response_model=MyToolPermissionsResponse)
async def my_tool_permissions(
    principal: Principal = Depends(get_current_principal),
    session: AsyncSession = Depends(get_db_session),
    settings: Settings = Depends(get_settings_dependency),
) -> MyToolPermissionsResponse:
    permissions = await tool_permissions_for(session, principal)
    return MyToolPermissionsResponse(
        department_id=permissions.department_id,
        department_name=permissions.department_name,
        tools=list(permissions.tools),
        revision=permissions.revision,
        max_age_seconds=settings.tool_permission_max_age_seconds,
    )
