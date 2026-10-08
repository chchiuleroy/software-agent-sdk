"""Public account-request flow: submit, e-mail code, hand over to review.

These routes are unauthenticated, so most tests here pin a *refusal* and say
why it matters. Real Postgres (the ``db_session`` fixture), fake mailer.
"""

from __future__ import annotations

import re
from datetime import timedelta
from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient
from pydantic import SecretStr
from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError

from central_governance_api.clock import now_utc
from central_governance_api.config import Settings
from central_governance_api.db import get_db_session
from central_governance_api.mailer import MailerError
from central_governance_api.main import create_app
from central_governance_api.models import (
    AccountMembership,
    AccountRequest,
    Department,
)

from .conftest import _TEST_DATABASE_URL, AUDIENCE, ISSUER, JWKS_URL


class FakeMailer:
    def __init__(self) -> None:
        self.sent: list[tuple[str, str]] = []
        self.fail = False

    async def send(self, *, to: str, subject: str, body: str) -> None:
        if self.fail:
            raise MailerError("SMTPException")
        self.sent.append((to, body))

    def last_code(self) -> str:
        match = re.search(r"：([A-Z2-9]{8})\n", self.sent[-1][1])
        assert match, self.sent[-1][1]
        return match.group(1)


def _settings(**overrides) -> Settings:
    base: dict[str, Any] = dict(
        oidc_issuer=ISSUER,
        oidc_jwks_url=JWKS_URL,
        oidc_audience=AUDIENCE,
        database_url=_TEST_DATABASE_URL,
        account_requests_enabled=True,
        account_email_domains=("corp.example",),
        account_request_hmac_key=SecretStr("k" * 40),
    )
    base.update(overrides)
    return Settings(**base)  # pyright: ignore[reportCallIssue]


async def _client(settings: Settings, db_session, mailer: FakeMailer | None):
    app = create_app(settings)
    app.state.mailer = mailer

    async def _db_session_override():
        yield db_session

    app.dependency_overrides[get_db_session] = _db_session_override
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


@pytest.fixture
def mailer() -> FakeMailer:
    return FakeMailer()


@pytest.fixture
async def client(db_session, mailer):
    async with await _client(_settings(), db_session, mailer) as c:
        yield c


def _body(email: str = "alice@corp.example", **extra) -> dict:
    return {
        "email": email,
        "display_name": "Alice",
        "requested_department": "Finance",
        **extra,
    }


async def _rows(db_session, email: str | None = None) -> list[AccountRequest]:
    query = select(AccountRequest)
    if email is not None:
        query = query.where(AccountRequest.email == email)
    return list((await db_session.execute(query)).scalars())


# --- gating -----------------------------------------------------------------


async def test_routes_are_404_unless_explicitly_enabled(db_session, mailer):
    # Why: these routes take no credentials; exposing them is a deployment
    # decision, so the default must be "not there at all".
    async with await _client(
        _settings(account_requests_enabled=False), db_session, mailer
    ) as c:
        assert (
            await c.post("/api/v1/account-requests", json=_body())
        ).status_code == 404
        verify = await c.post(
            "/api/v1/account-requests/verify",
            json={"email": "alice@corp.example", "code": "ABCDEFGH"},
        )
        assert verify.status_code == 404
    assert await _rows(db_session) == []


async def test_no_smtp_means_503_and_nothing_is_stored(db_session):
    # Why: an application nobody can verify must not be accepted.
    async with await _client(_settings(), db_session, None) as c:
        resp = await c.post("/api/v1/account-requests", json=_body())
    assert resp.status_code == 503
    assert resp.json()["error_code"] == "mail_unavailable"
    assert await _rows(db_session) == []


def test_enabling_requires_a_strong_hmac_key():
    # Why: with a guessable key the stored code hash could be brute-forced.
    with pytest.raises(ValueError):
        _settings(account_request_hmac_key=None)
    with pytest.raises(ValueError):
        _settings(account_request_hmac_key=SecretStr("short"))


def test_domain_list_must_be_bare_lowercase_domains():
    for bad in ("@corp.example", "Corp.Example", " corp.example"):
        with pytest.raises(ValueError):
            _settings(account_email_domains=(bad,))


# --- submit -----------------------------------------------------------------


async def test_foreign_domain_is_refused_without_mail_or_row(
    client, db_session, mailer
):
    # Why: this is the company-domain gate Roy asked for.
    resp = await client.post("/api/v1/account-requests", json=_body("x@evil.example"))
    assert resp.status_code == 422
    assert resp.json()["error_code"] == "email_domain_not_allowed"
    assert mailer.sent == []
    assert await _rows(db_session) == []


async def test_empty_domain_list_refuses_everyone(db_session, mailer):
    # Why: a forgotten setting must fail closed, not open.
    async with await _client(
        _settings(account_email_domains=()), db_session, mailer
    ) as c:
        resp = await c.post("/api/v1/account-requests", json=_body())
    assert resp.status_code == 422


async def test_malformed_email_is_rejected(client):
    resp = await client.post("/api/v1/account-requests", json=_body("not-an-email"))
    assert resp.status_code == 422


async def test_submit_stores_hash_not_code_and_mails_the_code(
    client, db_session, mailer
):
    resp = await client.post(
        "/api/v1/account-requests", json=_body(" Alice@Corp.Example ")
    )
    assert resp.status_code == 202
    assert resp.json() == {"status": "verification_sent"}
    (row,) = await _rows(db_session)
    assert row.email == "alice@corp.example"
    assert row.status == "pending_verification"
    code = mailer.last_code()
    # Why: a database read alone must not reveal a live code.
    assert row.code_hmac is not None and len(row.code_hmac) == 64
    assert code not in row.code_hmac
    assert mailer.sent[0][0] == "alice@corp.example"


async def test_mail_failure_removes_the_row_and_frees_the_quota(
    client, db_session, mailer
):
    # Why: our relay being down must not burn the applicant's daily quota or
    # leave an application nobody can verify.
    mailer.fail = True
    resp = await client.post("/api/v1/account-requests", json=_body())
    assert resp.status_code == 503
    assert await _rows(db_session) == []
    mailer.fail = False
    assert (
        await client.post("/api/v1/account-requests", json=_body())
    ).status_code == 202


async def test_resubmitting_supersedes_the_unverified_application(
    client, db_session, mailer
):
    await client.post("/api/v1/account-requests", json=_body())
    old_code = mailer.last_code()
    await client.post("/api/v1/account-requests", json=_body())
    new_code = mailer.last_code()
    rows = await _rows(db_session, "alice@corp.example")
    assert sorted(r.status for r in rows) == ["expired", "pending_verification"]
    # Why: only the newest code may work; an old mail must not stay live.
    assert old_code != new_code
    bad = await client.post(
        "/api/v1/account-requests/verify",
        json={"email": "alice@corp.example", "code": old_code},
    )
    assert bad.status_code == 400


async def test_two_open_applications_for_one_email_are_impossible(db_session):
    # Why: the partial unique index is what makes supersede-then-insert safe
    # when two submissions race.
    for _ in range(2):
        db_session.add(
            AccountRequest(
                email="race@corp.example",
                display_name="R",
                requested_department="D",
                reason="",
                status="pending_verification",
                code_attempts=0,
            )
        )
    with pytest.raises(IntegrityError):
        async with db_session.begin_nested():
            await db_session.flush()


async def test_address_already_in_review_gets_the_same_reply_and_no_mail(
    client, db_session, mailer
):
    # Why: the response must not reveal whether an address is known.
    await client.post("/api/v1/account-requests", json=_body())
    await client.post(
        "/api/v1/account-requests/verify",
        json={"email": "alice@corp.example", "code": mailer.last_code()},
    )
    sent_before = len(mailer.sent)
    resp = await client.post("/api/v1/account-requests", json=_body())
    assert resp.status_code == 202
    assert resp.json() == {"status": "verification_sent"}
    assert len(mailer.sent) == sent_before
    assert len(await _rows(db_session, "alice@corp.example")) == 1


async def test_address_with_an_account_gets_the_same_reply_and_no_mail(
    client, db_session, mailer
):
    dept = Department(name="Finance")
    db_session.add(dept)
    done = AccountRequest(
        email="alice@corp.example",
        display_name="A",
        requested_department="Finance",
        reason="",
        status="approved",
        code_attempts=0,
    )
    db_session.add(done)
    await db_session.flush()
    db_session.add(
        AccountMembership(
            email="alice@corp.example",
            department_id=dept.id,
            account_request_id=done.id,
        )
    )
    await db_session.flush()
    resp = await client.post("/api/v1/account-requests", json=_body())
    assert resp.status_code == 202
    assert mailer.sent == []


async def test_per_email_daily_limit(db_session, mailer):
    # Why: stops one address being used to flood a mailbox with codes.
    settings = _settings(account_requests_per_email_per_day=2)
    async with await _client(settings, db_session, mailer) as c:
        assert (
            await c.post("/api/v1/account-requests", json=_body())
        ).status_code == 202
        assert (
            await c.post("/api/v1/account-requests", json=_body())
        ).status_code == 202
        third = await c.post("/api/v1/account-requests", json=_body())
    assert third.status_code == 429
    assert third.json()["error_code"] == "rate_limited"
    assert len(mailer.sent) == 2


async def test_global_hourly_limit_applies_across_addresses(db_session, mailer):
    # Why: the per-address cap alone does not bound a spray of many addresses.
    settings = _settings(account_requests_global_per_hour=2)
    async with await _client(settings, db_session, mailer) as c:
        for name in ("a", "b"):
            r = await c.post(
                "/api/v1/account-requests", json=_body(f"{name}@corp.example")
            )
            assert r.status_code == 202
        blocked = await c.post("/api/v1/account-requests", json=_body("c@corp.example"))
    assert blocked.status_code == 429


# --- verify -----------------------------------------------------------------


async def test_correct_code_moves_the_application_to_review(client, db_session, mailer):
    await client.post("/api/v1/account-requests", json=_body())
    resp = await client.post(
        "/api/v1/account-requests/verify",
        json={"email": "ALICE@corp.example", "code": mailer.last_code().lower()},
    )
    assert resp.status_code == 200
    assert resp.json() == {"status": "pending_review"}
    (row,) = await _rows(db_session)
    assert row.status == "pending_review"
    assert row.email_verified_at is not None
    # Why: the used code must not stay usable or recoverable.
    assert row.code_hmac is None


async def test_unknown_email_and_wrong_code_look_identical(client, mailer):
    # Why: otherwise verify becomes an oracle for which addresses have
    # pending applications.
    await client.post("/api/v1/account-requests", json=_body())
    wrong = await client.post(
        "/api/v1/account-requests/verify",
        json={"email": "alice@corp.example", "code": "AAAAAAAA"},
    )
    unknown = await client.post(
        "/api/v1/account-requests/verify",
        json={"email": "nobody@corp.example", "code": "AAAAAAAA"},
    )
    assert wrong.status_code == unknown.status_code == 400
    assert wrong.json() == unknown.json()


async def test_five_wrong_guesses_lock_the_application(client, db_session, mailer):
    # Why: an 8-character code is only safe because guesses are capped.
    await client.post("/api/v1/account-requests", json=_body())
    good = mailer.last_code()
    for _ in range(5):
        r = await client.post(
            "/api/v1/account-requests/verify",
            json={"email": "alice@corp.example", "code": "AAAAAAAA"},
        )
        assert r.status_code == 400
    late = await client.post(
        "/api/v1/account-requests/verify",
        json={"email": "alice@corp.example", "code": good},
    )
    assert late.status_code == 400
    (row,) = await _rows(db_session)
    assert row.status == "expired"


async def test_correct_code_on_the_fifth_try_still_works(client, mailer):
    # Why: pins the budget as exactly five tries, correct one included.
    await client.post("/api/v1/account-requests", json=_body())
    good = mailer.last_code()
    for _ in range(4):
        await client.post(
            "/api/v1/account-requests/verify",
            json={"email": "alice@corp.example", "code": "AAAAAAAA"},
        )
    ok = await client.post(
        "/api/v1/account-requests/verify",
        json={"email": "alice@corp.example", "code": good},
    )
    assert ok.status_code == 200


async def test_expired_code_is_refused(client, db_session, mailer):
    await client.post("/api/v1/account-requests", json=_body())
    code = mailer.last_code()
    await db_session.execute(
        update(AccountRequest).values(code_expires_at=now_utc() - timedelta(seconds=1))
    )
    resp = await client.post(
        "/api/v1/account-requests/verify",
        json={"email": "alice@corp.example", "code": code},
    )
    assert resp.status_code == 400
    (row,) = await _rows(db_session)
    assert row.status == "expired"


async def test_code_cannot_be_used_twice(client, mailer):
    await client.post("/api/v1/account-requests", json=_body())
    code = mailer.last_code()
    first = await client.post(
        "/api/v1/account-requests/verify",
        json={"email": "alice@corp.example", "code": code},
    )
    second = await client.post(
        "/api/v1/account-requests/verify",
        json={"email": "alice@corp.example", "code": code},
    )
    assert first.status_code == 200
    assert second.status_code == 400


async def test_failed_attempts_are_counted_even_though_the_request_errors(
    client, db_session, mailer
):
    # Why: if the counter rolled back with the error, guessing would be free.
    await client.post("/api/v1/account-requests", json=_body())
    await client.post(
        "/api/v1/account-requests/verify",
        json={"email": "alice@corp.example", "code": "AAAAAAAA"},
    )
    # A production session is closed (rolled back) when the request errors;
    # only what the handler committed may survive that.
    await db_session.rollback()
    attempts = (
        await db_session.execute(select(func.max(AccountRequest.code_attempts)))
    ).scalar_one()
    assert attempts == 1


async def test_exhausted_budget_refuses_even_the_correct_code(
    client, db_session, mailer
):
    # Why: the guard must hold on its own, not only because the fifth wrong
    # guess happens to expire the row (concurrent guesses could race past that).
    await client.post("/api/v1/account-requests", json=_body())
    good = mailer.last_code()
    await db_session.execute(update(AccountRequest).values(code_attempts=5))
    resp = await client.post(
        "/api/v1/account-requests/verify",
        json={"email": "alice@corp.example", "code": good},
    )
    assert resp.status_code == 400
