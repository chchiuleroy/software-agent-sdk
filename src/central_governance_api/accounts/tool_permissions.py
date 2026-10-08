"""Lookup of "which tools may this caller's department use".

Two ways a caller reaches a department, tried in this order:

1. ``department_principals`` — a superadmin assigned this exact service
   account (an agent-server's own client). This is what a device uses: central
   sees the agent-server's token, not the human's.
2. the membership bound to this login by the first-login flow
   (``routers/me.py``) — a human calling directly.

No match means no department and therefore no permitted tools (allow-list).
A disabled department keeps working: disabling only stops new approvals from
placing people in it.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from central_governance_api.accounts.errors import ToolNotPermittedError
from central_governance_api.auth.oidc import Principal
from central_governance_api.models import (
    AccountMembership,
    Department,
    DepartmentPrincipal,
    DepartmentToolPermission,
)


@dataclass(frozen=True)
class ToolPermissions:
    department_id: uuid.UUID | None
    department_name: str | None
    tools: tuple[str, ...]

    @property
    def revision(self) -> str:
        """Changes whenever the department or its tool set changes, so a
        device can tell a fresh answer from a stale one."""
        raw = f"{self.department_id}|" + "\n".join(self.tools)
        return hashlib.sha256(raw.encode()).hexdigest()[:16]


async def _department_for(
    session: AsyncSession, principal: Principal
) -> Department | None:
    assigned = (
        await session.execute(
            select(Department)
            .join(
                DepartmentPrincipal, DepartmentPrincipal.department_id == Department.id
            )
            .where(
                DepartmentPrincipal.issuer == principal.issuer,
                DepartmentPrincipal.sub == principal.sub,
            )
        )
    ).scalar_one_or_none()
    if assigned is not None:
        return assigned
    return (
        await session.execute(
            select(Department)
            .join(AccountMembership, AccountMembership.department_id == Department.id)
            .where(
                AccountMembership.bound_issuer == principal.issuer,
                AccountMembership.bound_sub == principal.sub,
            )
        )
    ).scalar_one_or_none()


async def tool_permissions_for(
    session: AsyncSession, principal: Principal
) -> ToolPermissions:
    department = await _department_for(session, principal)
    if department is None:
        return ToolPermissions(None, None, ())
    names = (
        await session.execute(
            select(DepartmentToolPermission.tool_name)
            .where(DepartmentToolPermission.department_id == department.id)
            .order_by(DepartmentToolPermission.tool_name)
        )
    ).scalars()
    return ToolPermissions(department.id, department.name, tuple(names))


async def ensure_tool_permitted(
    session: AsyncSession, principal: Principal, tool_name: str, *, enforced: bool
) -> None:
    """Raise :class:`ToolNotPermittedError` unless the caller's department may
    use ``tool_name``. A no-op while ``enforced`` is False, so turning the
    feature on is a deliberate step after service accounts are assigned."""
    if not enforced:
        return
    permissions = await tool_permissions_for(session, principal)
    if tool_name not in permissions.tools:
        raise ToolNotPermittedError()
