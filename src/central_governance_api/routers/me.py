"""``GET /api/v1/me``: who the caller is, and which department they belong to.

This is also where an approved account is bound to a login. A superadmin
approves an application and creates the Keycloak account by hand; the first
time that person calls this endpoint with a token whose e-mail is the
approved one *and verified by the IdP*, the membership is bound to that
token's ``(issuer, sub)`` — exactly once. From then on the identity key is
``(issuer, sub)``; the e-mail grants nothing, so a recycled or re-registered
address cannot inherit the department.

P1 only records the department. Nothing else in the service consults it yet
(that is the department tool-permission work that follows).
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from central_governance_api.auth.dependencies import get_current_principal
from central_governance_api.auth.oidc import Principal
from central_governance_api.clock import now_utc
from central_governance_api.db import get_db_session
from central_governance_api.models import AccountMembership, AdminAuditEvent, Department


router = APIRouter(prefix="/api/v1", tags=["me"])


class MembershipInfo(BaseModel):
    department_id: uuid.UUID
    department_name: str


class MeResponse(BaseModel):
    issuer: str
    sub: str
    display_name: str
    roles: list[str]
    email: str | None
    email_verified: bool
    membership: MembershipInfo | None


async def _bound_membership(
    session: AsyncSession, principal: Principal
) -> MembershipInfo | None:
    row = (
        await session.execute(
            select(Department.id, Department.name)
            .join(AccountMembership, AccountMembership.department_id == Department.id)
            .where(
                AccountMembership.bound_issuer == principal.issuer,
                AccountMembership.bound_sub == principal.sub,
            )
        )
    ).first()
    return (
        MembershipInfo(department_id=row.id, department_name=row.name) if row else None
    )


@router.get("/me", response_model=MeResponse)
async def me(
    principal: Principal = Depends(get_current_principal),
    session: AsyncSession = Depends(get_db_session),
) -> MeResponse:
    membership = await _bound_membership(session, principal)

    if membership is None and principal.email and principal.email_verified:
        try:
            bound = (
                await session.execute(
                    update(AccountMembership)
                    .where(
                        AccountMembership.email == principal.email,
                        AccountMembership.bound_sub.is_(None),
                    )
                    .values(
                        bound_issuer=principal.issuer,
                        bound_sub=principal.sub,
                        bound_at=now_utc(),
                    )
                    .returning(AccountMembership.id, AccountMembership.email)
                )
            ).first()
            if bound is not None:
                session.add(
                    AdminAuditEvent(
                        event_type="membership_bound",
                        actor_issuer=principal.issuer,
                        actor_sub=principal.sub,
                        payload={
                            "membership_id": str(bound.id),
                            "email": bound.email,
                        },
                    )
                )
            await session.commit()
        except IntegrityError:
            # This identity got bound to another membership in the meantime.
            await session.rollback()
        membership = await _bound_membership(session, principal)

    return MeResponse(
        issuer=principal.issuer,
        sub=principal.sub,
        display_name=principal.display_name,
        roles=sorted(principal.roles),
        email=principal.email,
        email_verified=principal.email_verified,
        membership=membership,
    )
