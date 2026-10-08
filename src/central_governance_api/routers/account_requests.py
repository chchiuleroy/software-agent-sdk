"""Public account-request endpoints: submit an application, prove the
e-mail address with an emailed code.

These two routes are unauthenticated on purpose (the applicant has no
account yet), so the whole router is invisible (404) unless
``Settings.account_requests_enabled`` is set, and every failure the caller
can trigger is a fixed, non-revealing message (see ``accounts/errors.py``).
Review and approval are in ``routers/admin_accounts.py``.

Design: docs/account-requests-departments-design-v1.md. One deviation from
that document: verify takes ``{email, code}`` rather than a request id in the
path, so no id ever has to be returned to an unauthenticated caller (an id
would let a third party who knows an address burn its attempt budget).
"""

from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import delete, func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from central_governance_api.accounts.codes import (
    code_hmac,
    codes_match,
    generate_code,
)
from central_governance_api.accounts.errors import (
    AccountRequestRateLimitedError,
    EmailDomainNotAllowedError,
    InvalidVerificationCodeError,
    MailUnavailableError,
)
from central_governance_api.accounts.schemas import (
    AccountRequestAccepted,
    AccountRequestVerified,
    CreateAccountRequest,
    VerifyAccountRequest,
)
from central_governance_api.clock import now_utc
from central_governance_api.config import Settings, get_settings_dependency
from central_governance_api.db import get_db_session
from central_governance_api.mailer import MailerError
from central_governance_api.models import AccountMembership, AccountRequest


router = APIRouter(prefix="/api/v1/account-requests", tags=["account-requests"])

# Arbitrary constant keying the advisory lock that serializes submissions.
_SUBMIT_LOCK_KEY = 0x4F485341


def require_enabled(settings: Settings = Depends(get_settings_dependency)) -> Settings:
    if not settings.account_requests_enabled:
        raise HTTPException(status_code=404)
    return settings


def _hmac_key(settings: Settings) -> str:
    key = settings.account_request_hmac_key
    # Settings validates this when the feature is enabled; assert for pyright.
    assert key is not None
    return key.get_secret_value()


@router.post("", response_model=AccountRequestAccepted, status_code=202)
async def create_account_request(
    body: CreateAccountRequest,
    request: Request,
    session: AsyncSession = Depends(get_db_session),
    settings: Settings = Depends(require_enabled),
) -> AccountRequestAccepted:
    mailer = getattr(request.app.state, "mailer", None)
    if mailer is None:
        raise MailUnavailableError()

    domain = body.email.rsplit("@", 1)[1]
    if domain not in settings.account_email_domains:
        raise EmailDomainNotAllowedError()

    # One transaction-scoped lock serializes the quota check and the insert
    # below; without it concurrent submissions for different addresses all
    # read the same unfilled count and overshoot the global limit. Released
    # at commit/rollback. Fine at this service's scale (a handful of
    # applications an hour); revisit if the limit is ever raised a lot.
    await session.execute(select(func.pg_advisory_xact_lock(_SUBMIT_LOCK_KEY)))

    now = now_utc()
    per_email = (
        await session.execute(
            select(func.count())
            .select_from(AccountRequest)
            .where(
                AccountRequest.email == body.email,
                AccountRequest.created_at >= now - timedelta(days=1),
            )
        )
    ).scalar_one()
    overall = (
        await session.execute(
            select(func.count())
            .select_from(AccountRequest)
            .where(AccountRequest.created_at >= now - timedelta(hours=1))
        )
    ).scalar_one()
    if (
        per_email >= settings.account_requests_per_email_per_day
        or overall >= settings.account_requests_global_per_hour
    ):
        raise AccountRequestRateLimitedError()

    # An address that already has an account or an application under review
    # gets the same reply as a fresh one and no e-mail. It also spends the
    # same quota (a counted, already-expired row), so exhausting the limit
    # cannot be used to tell known addresses from unknown ones. Residual:
    # skipping the SMTP round trip is still a timing difference.
    has_membership = (
        await session.execute(
            select(AccountMembership.id).where(AccountMembership.email == body.email)
        )
    ).first()
    in_review = (
        await session.execute(
            select(AccountRequest.id).where(
                AccountRequest.email == body.email,
                AccountRequest.status == "pending_review",
            )
        )
    ).first()
    if has_membership is not None or in_review is not None:
        session.add(
            AccountRequest(
                email=body.email,
                display_name=body.display_name,
                requested_department=body.requested_department,
                reason="",
                status="expired",
                code_attempts=0,
            )
        )
        await session.commit()
        return AccountRequestAccepted()

    code = generate_code()
    row = AccountRequest(
        email=body.email,
        display_name=body.display_name,
        requested_department=body.requested_department,
        reason=body.reason,
        status="pending_verification",
        code_hmac=code_hmac(key=_hmac_key(settings), email=body.email, code=code),
        code_expires_at=now + timedelta(seconds=settings.account_code_ttl_seconds),
        code_attempts=0,
    )
    try:
        # A newer submission supersedes an unverified older one; the partial
        # unique index keeps this safe if two submissions race.
        await session.execute(
            update(AccountRequest)
            .where(
                AccountRequest.email == body.email,
                AccountRequest.status == "pending_verification",
            )
            .values(status="expired")
        )
        session.add(row)
        await session.flush()
        request_id = row.id
        await session.commit()
    except IntegrityError:
        await session.rollback()
        return AccountRequestAccepted()

    try:
        await mailer.send(
            to=body.email,
            subject="OHS 帳號申請驗證碼",
            body=(
                f"您的 OHS 帳號申請驗證碼：{code}\n"
                f"有效時間 {settings.account_code_ttl_seconds // 60} 分鐘。\n"
                "若這不是您本人提出的申請，請忽略此信。"
            ),
        )
    except MailerError:
        # Do not leave an application nobody can verify, and do not charge
        # the applicant's daily quota for our relay being down.
        await session.execute(
            delete(AccountRequest).where(
                AccountRequest.id == request_id,
                AccountRequest.status == "pending_verification",
            )
        )
        await session.commit()
        raise MailUnavailableError() from None
    return AccountRequestAccepted()


async def _expire(session: AsyncSession, request_id) -> None:
    await session.execute(
        update(AccountRequest)
        .where(
            AccountRequest.id == request_id,
            AccountRequest.status == "pending_verification",
        )
        .values(status="expired")
    )
    await session.commit()


@router.post("/verify", response_model=AccountRequestVerified)
async def verify_account_request(
    body: VerifyAccountRequest,
    session: AsyncSession = Depends(get_db_session),
    settings: Settings = Depends(require_enabled),
) -> AccountRequestVerified:
    now = now_utc()
    row = (
        await session.execute(
            select(AccountRequest.id, AccountRequest.code_expires_at).where(
                AccountRequest.email == body.email,
                AccountRequest.status == "pending_verification",
            )
        )
    ).first()
    if row is None:
        raise InvalidVerificationCodeError()
    if row.code_expires_at is None or row.code_expires_at <= now:
        await _expire(session, row.id)
        raise InvalidVerificationCodeError()

    # Count the attempt first, atomically and only while the budget lasts:
    # two concurrent guesses cannot both slip under the limit, and a wrong
    # guess is counted even though we then raise.
    bumped = (
        await session.execute(
            update(AccountRequest)
            .where(
                AccountRequest.id == row.id,
                AccountRequest.status == "pending_verification",
                AccountRequest.code_attempts < settings.account_code_max_attempts,
            )
            .values(code_attempts=AccountRequest.code_attempts + 1)
            .returning(AccountRequest.code_hmac, AccountRequest.code_attempts)
        )
    ).first()
    await session.commit()
    if bumped is None:
        await _expire(session, row.id)
        raise InvalidVerificationCodeError()

    candidate = code_hmac(key=_hmac_key(settings), email=body.email, code=body.code)
    if bumped.code_hmac is None or not codes_match(bumped.code_hmac, candidate):
        if bumped.code_attempts >= settings.account_code_max_attempts:
            await _expire(session, row.id)
        raise InvalidVerificationCodeError()

    result = await session.execute(
        update(AccountRequest)
        .where(
            AccountRequest.id == row.id,
            AccountRequest.status == "pending_verification",
        )
        .values(
            status="pending_review",
            email_verified_at=now,
            code_hmac=None,
            code_expires_at=None,
        )
    )
    await session.commit()
    if result.rowcount != 1:  # pyright: ignore[reportAttributeAccessIssue]
        raise InvalidVerificationCodeError()
    return AccountRequestVerified()
