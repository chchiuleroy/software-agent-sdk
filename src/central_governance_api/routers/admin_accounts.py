"""Superadmin endpoints: departments, review of account requests, and the
list of approved accounts that have not logged in yet.

Everything here needs ``governance.superadmin``, which is deliberately not a
superset of ``governance.admin`` (see ``auth/oidc.py``). Every state change
is a conditional UPDATE plus an ``AdminAuditEvent`` in the same commit, the
same shape as the approval endpoints; a replayed decision therefore answers
409 instead of repeating its effect (no Idempotency-Key: the transition
itself is the guard).

Approving does not create the Keycloak account: a superadmin does that by
hand (Roy's decision). It only records the department and creates the
membership the first login will bind to (see ``routers/me.py``).
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from central_governance_api.accounts.errors import (
    AccountRequestNotFoundError,
    AccountRequestNotPendingError,
    DepartmentDisabledError,
    DepartmentExistsError,
    DepartmentNotFoundError,
    SelfApprovalNotAllowedError,
)
from central_governance_api.accounts.schemas import (
    AccountRequestSummary,
    ApproveAccountRequest,
    CreateDepartmentRequest,
    DepartmentResponse,
    MembershipSummary,
    RejectAccountRequest,
)
from central_governance_api.auth.dependencies import require_role
from central_governance_api.auth.oidc import Principal
from central_governance_api.clock import now_utc
from central_governance_api.db import get_db_session
from central_governance_api.models import (
    ACCOUNT_REQUEST_STATUSES,
    AccountMembership,
    AccountRequest,
    AdminAuditEvent,
    Department,
)


router = APIRouter(prefix="/api/v1/admin", tags=["admin-accounts"])

_require_superadmin = require_role("governance.superadmin")

_MAX_LIMIT = 200
_DEFAULT_LIMIT = 100


def _audit(
    principal: Principal, event_type: str, payload: dict[str, str]
) -> AdminAuditEvent:
    return AdminAuditEvent(
        event_type=event_type,
        actor_issuer=principal.issuer,
        actor_sub=principal.sub,
        payload=payload,
    )


# --- departments --------------------------------------------------------


@router.get("/departments", response_model=list[DepartmentResponse])
async def list_departments(
    _principal: Principal = Depends(_require_superadmin),
    session: AsyncSession = Depends(get_db_session),
) -> list[Department]:
    rows = await session.execute(select(Department).order_by(Department.name))
    return list(rows.scalars())


@router.post("/departments", response_model=DepartmentResponse, status_code=201)
async def create_department(
    body: CreateDepartmentRequest,
    principal: Principal = Depends(_require_superadmin),
    session: AsyncSession = Depends(get_db_session),
) -> DepartmentResponse:
    department = Department(name=body.name)
    try:
        session.add(department)
        await session.flush()
    except IntegrityError:
        await session.rollback()
        raise DepartmentExistsError() from None
    await session.refresh(department)  # server-default created_at
    session.add(
        _audit(
            principal,
            "department_created",
            {"department_id": str(department.id), "name": department.name},
        )
    )
    response = DepartmentResponse.model_validate(department, from_attributes=True)
    await session.commit()
    return response


@router.post("/departments/{department_id}/disable", response_model=DepartmentResponse)
async def disable_department(
    department_id: uuid.UUID,
    principal: Principal = Depends(_require_superadmin),
    session: AsyncSession = Depends(get_db_session),
) -> DepartmentResponse:
    updated = (
        await session.execute(
            update(Department)
            .where(Department.id == department_id, Department.disabled_at.is_(None))
            .values(disabled_at=now_utc())
            .returning(
                Department.id,
                Department.name,
                Department.created_at,
                Department.disabled_at,
            )
        )
    ).first()
    if updated is None:
        exists = (
            await session.execute(
                select(Department.id).where(Department.id == department_id)
            )
        ).first()
        if exists is None:
            raise DepartmentNotFoundError()
        raise DepartmentDisabledError()
    session.add(
        _audit(
            principal,
            "department_disabled",
            {"department_id": str(department_id), "name": updated.name},
        )
    )
    await session.commit()
    return DepartmentResponse(
        id=updated.id,
        name=updated.name,
        created_at=updated.created_at,
        disabled_at=updated.disabled_at,
    )


# --- account requests ---------------------------------------------------


@router.get("/account-requests", response_model=list[AccountRequestSummary])
async def list_account_requests(
    status: str = Query(default="pending_review"),
    limit: int = Query(default=_DEFAULT_LIMIT, ge=1, le=_MAX_LIMIT),
    _principal: Principal = Depends(_require_superadmin),
    session: AsyncSession = Depends(get_db_session),
) -> list[AccountRequest]:
    if status not in ACCOUNT_REQUEST_STATUSES:
        # An unknown status is a caller mistake, not "no results".
        raise HTTPException(status_code=422, detail="unknown status")
    rows = await session.execute(
        select(AccountRequest)
        .where(AccountRequest.status == status)
        .order_by(AccountRequest.created_at, AccountRequest.id)
        .limit(limit)
    )
    return list(rows.scalars())


async def _check_exists_and_not_self(
    session: AsyncSession, request_id: uuid.UUID, principal: Principal
) -> str:
    row = (
        await session.execute(
            select(AccountRequest.email, AccountRequest.status).where(
                AccountRequest.id == request_id
            )
        )
    ).first()
    if row is None:
        raise AccountRequestNotFoundError()
    # The caller's own addresses: the token's e-mail claim (if any) plus the
    # e-mail of the membership bound to this login. The second covers a token
    # that carries no e-mail claim; an operator created outside this flow with
    # neither is not detectable here.
    own = (
        await session.execute(
            select(AccountMembership.email).where(
                AccountMembership.bound_issuer == principal.issuer,
                AccountMembership.bound_sub == principal.sub,
            )
        )
    ).scalars()
    own_emails = set(own)
    if principal.email is not None:
        own_emails.add(principal.email)
    if row.email in own_emails:
        raise SelfApprovalNotAllowedError()
    return row.email


@router.post(
    "/account-requests/{request_id}/approve", response_model=AccountRequestSummary
)
async def approve_account_request(
    request_id: uuid.UUID,
    body: ApproveAccountRequest,
    principal: Principal = Depends(_require_superadmin),
    session: AsyncSession = Depends(get_db_session),
) -> AccountRequest:
    await _check_exists_and_not_self(session, request_id, principal)
    department = (
        await session.execute(
            # FOR SHARE: a concurrent disable needs a row write lock, so it
            # waits for this approval instead of slipping in after the check.
            select(Department)
            .where(Department.id == body.department_id)
            .with_for_update(read=True)
        )
    ).scalar_one_or_none()
    if department is None:
        raise DepartmentNotFoundError()
    if department.disabled_at is not None:
        raise DepartmentDisabledError()

    now = now_utc()
    decided = (
        await session.execute(
            update(AccountRequest)
            .where(
                AccountRequest.id == request_id,
                AccountRequest.status == "pending_review",
            )
            .values(
                status="approved",
                decided_by_issuer=principal.issuer,
                decided_by_sub=principal.sub,
                decided_at=now,
                approved_department_id=department.id,
            )
            .returning(AccountRequest.email)
        )
    ).first()
    if decided is None:
        raise AccountRequestNotPendingError()
    try:
        session.add(
            AccountMembership(
                email=decided.email,
                department_id=department.id,
                account_request_id=request_id,
            )
        )
        await session.flush()
    except IntegrityError:
        # An account for this address already exists (a race the submit
        # path normally prevents); nothing was decided.
        await session.rollback()
        raise AccountRequestNotPendingError() from None
    session.add(
        _audit(
            principal,
            "account_request_approved",
            {
                "account_request_id": str(request_id),
                "email": decided.email,
                "department_id": str(department.id),
            },
        )
    )
    await session.commit()
    return (
        await session.execute(
            select(AccountRequest).where(AccountRequest.id == request_id)
        )
    ).scalar_one()


@router.post(
    "/account-requests/{request_id}/reject", response_model=AccountRequestSummary
)
async def reject_account_request(
    request_id: uuid.UUID,
    body: RejectAccountRequest,
    principal: Principal = Depends(_require_superadmin),
    session: AsyncSession = Depends(get_db_session),
) -> AccountRequest:
    await _check_exists_and_not_self(session, request_id, principal)
    decided = (
        await session.execute(
            update(AccountRequest)
            .where(
                AccountRequest.id == request_id,
                AccountRequest.status == "pending_review",
            )
            .values(
                status="rejected",
                decided_by_issuer=principal.issuer,
                decided_by_sub=principal.sub,
                decided_at=now_utc(),
                decision_reason=body.reason,
            )
            .returning(AccountRequest.email)
        )
    ).first()
    if decided is None:
        raise AccountRequestNotPendingError()
    session.add(
        _audit(
            principal,
            "account_request_rejected",
            {"account_request_id": str(request_id), "email": decided.email},
        )
    )
    await session.commit()
    return (
        await session.execute(
            select(AccountRequest).where(AccountRequest.id == request_id)
        )
    ).scalar_one()


# --- memberships --------------------------------------------------------


@router.get("/memberships", response_model=list[MembershipSummary])
async def list_memberships(
    unbound: bool = Query(default=False),
    limit: int = Query(default=_DEFAULT_LIMIT, ge=1, le=_MAX_LIMIT),
    _principal: Principal = Depends(_require_superadmin),
    session: AsyncSession = Depends(get_db_session),
) -> list[AccountMembership]:
    """``unbound=true`` is the reminder list: approved, but nobody has logged
    in with that address yet (the Keycloak account may not exist)."""
    query = select(AccountMembership)
    if unbound:
        query = query.where(AccountMembership.bound_sub.is_(None))
    rows = await session.execute(
        query.order_by(AccountMembership.created_at, AccountMembership.id).limit(limit)
    )
    return list(rows.scalars())
