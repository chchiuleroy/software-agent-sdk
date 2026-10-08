"""GET /api/v1/me and the one-time first-login binding of an approved account."""

from __future__ import annotations

import asyncio

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select

from central_governance_api.auth.dependencies import get_oidc_resolver
from central_governance_api.auth.oidc import OIDCPrincipalResolver
from central_governance_api.db import (
    create_engine,
    create_session_factory,
    get_db_session,
)
from central_governance_api.main import create_app
from central_governance_api.models import (
    AccountMembership,
    AccountRequest,
    AdminAuditEvent,
    Department,
)

from .conftest import ISSUER
from .test_app_auth import _sign


@pytest.fixture
async def client(settings, public_jwks, db_session):
    app = create_app(settings)
    resolver = OIDCPrincipalResolver(
        settings, preloaded_keys=public_jwks, never_refresh_keys=True
    )
    app.dependency_overrides[get_oidc_resolver] = lambda: resolver

    async def _db_session_override():
        yield db_session

    app.dependency_overrides[get_db_session] = _db_session_override
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as c:
        yield c


async def _approved_membership(
    db_session, email: str = "alice@corp.example", dept_name: str = "Finance"
) -> None:
    dept = Department(name=dept_name)
    req = AccountRequest(
        email=email,
        display_name="Alice",
        requested_department=dept_name,
        reason="",
        status="approved",
        code_attempts=0,
    )
    db_session.add_all([dept, req])
    await db_session.flush()
    db_session.add(
        AccountMembership(email=email, department_id=dept.id, account_request_id=req.id)
    )
    await db_session.flush()


def _headers(signing_key, **claims) -> dict[str, str]:
    claims.setdefault("sub", "alice-sub")
    token = _sign(signing_key, roles=[], **claims)
    return {"Authorization": f"Bearer {token}"}


async def _me(client, signing_key, **claims):
    return await client.get("/api/v1/me", headers=_headers(signing_key, **claims))


async def test_first_login_with_the_verified_email_binds_the_account(
    client, db_session, signing_key
):
    await _approved_membership(db_session)
    resp = await _me(
        client, signing_key, email="alice@corp.example", email_verified=True
    )
    assert resp.status_code == 200
    assert resp.json()["membership"]["department_name"] == "Finance"
    member = (await db_session.execute(select(AccountMembership))).scalar_one()
    assert (member.bound_issuer, member.bound_sub) == (ISSUER, "alice-sub")
    assert member.bound_at is not None
    event = (await db_session.execute(select(AdminAuditEvent))).scalar_one()
    assert event.event_type == "membership_bound"
    assert event.actor_sub == "alice-sub"


async def test_email_claim_is_matched_case_insensitively(
    client, db_session, signing_key
):
    await _approved_membership(db_session)
    resp = await _me(
        client, signing_key, email="Alice@Corp.Example", email_verified=True
    )
    assert resp.json()["membership"] is not None


@pytest.mark.parametrize(
    "claims",
    [
        {"email": "alice@corp.example", "email_verified": False},
        {"email": "alice@corp.example"},
        {"email": "alice@corp.example", "email_verified": "true"},
        {"email": "other@corp.example", "email_verified": True},
        {},
    ],
)
async def test_no_binding_without_a_verified_matching_email(
    client, db_session, signing_key, claims
):
    # Why: binding grants a department; it must rest on an address the IdP
    # vouches for, never on an unverified or different one.
    await _approved_membership(db_session)
    resp = await _me(client, signing_key, **claims)
    assert resp.status_code == 200
    assert resp.json()["membership"] is None
    member = (await db_session.execute(select(AccountMembership))).scalar_one()
    assert member.bound_sub is None
    assert list((await db_session.execute(select(AdminAuditEvent))).scalars()) == []


async def test_a_second_identity_with_the_same_email_gets_nothing(
    client, db_session, signing_key
):
    # Why: this is the whole point of binding once. A recycled or
    # re-registered address must not inherit the department.
    await _approved_membership(db_session)
    first = await _me(
        client,
        signing_key,
        sub="first",
        email="alice@corp.example",
        email_verified=True,
    )
    second = await _me(
        client,
        signing_key,
        sub="second",
        email="alice@corp.example",
        email_verified=True,
    )
    assert first.json()["membership"] is not None
    assert second.json()["membership"] is None
    member = (await db_session.execute(select(AccountMembership))).scalar_one()
    assert member.bound_sub == "first"


async def test_a_bound_identity_keeps_its_department_after_its_email_changes(
    client, db_session, signing_key
):
    # Why: once bound, (issuer, sub) is the identity; the e-mail is irrelevant.
    await _approved_membership(db_session)
    await _me(client, signing_key, email="alice@corp.example", email_verified=True)
    again = await _me(client, signing_key)  # no e-mail claim at all
    assert again.json()["membership"]["department_name"] == "Finance"
    events = list((await db_session.execute(select(AdminAuditEvent))).scalars())
    assert len(events) == 1  # the repeat call bound nothing new


async def test_me_reports_identity_and_roles_for_anyone_authenticated(
    client, signing_key
):
    token = _sign(signing_key, sub="op", roles=["agent.operator"])
    resp = await client.get("/api/v1/me", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["sub"] == "op"
    assert body["roles"] == ["agent.operator"]
    assert body["membership"] is None


async def test_me_requires_authentication(client):
    assert (await client.get("/api/v1/me")).status_code == 401


async def test_concurrent_first_logins_bind_exactly_one_identity(
    settings, public_jwks, signing_key
):
    # Why: the conditional UPDATE (bound_sub IS NULL) is what stops two
    # simultaneous logins both claiming the account. Needs two real
    # connections, so this test commits real rows and cleans up after itself.
    engine = create_engine(settings)
    try:
        async with engine.connect():
            pass
    except Exception as exc:
        await engine.dispose()
        pytest.skip(f"no reachable test Postgres: {exc}")
    factory = create_session_factory(engine)
    email = "race-winner@corp.example"
    try:
        async with factory() as s:
            await _approved_membership(s, email=email, dept_name="RaceDept")
            await s.commit()

        app = create_app(settings)
        app.state.db_session_factory = factory
        resolver = OIDCPrincipalResolver(
            settings, preloaded_keys=public_jwks, never_refresh_keys=True
        )
        app.dependency_overrides[get_oidc_resolver] = lambda: resolver
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as c:
            responses = await asyncio.gather(
                *[
                    c.get(
                        "/api/v1/me",
                        headers=_headers(
                            signing_key,
                            sub=f"racer-{i}",
                            email=email,
                            email_verified=True,
                        ),
                    )
                    for i in range(2)
                ]
            )
        assert all(r.status_code == 200 for r in responses)
        winners = [r for r in responses if r.json()["membership"] is not None]
        assert len(winners) == 1
        async with factory() as s:
            member = (
                await s.execute(
                    select(AccountMembership).where(AccountMembership.email == email)
                )
            ).scalar_one()
            assert member.bound_sub in {"racer-0", "racer-1"}
    finally:
        async with factory() as s:
            await s.execute(
                delete(AdminAuditEvent).where(
                    AdminAuditEvent.actor_sub.in_(["racer-0", "racer-1"])
                )
            )
            await s.execute(
                delete(AccountMembership).where(AccountMembership.email == email)
            )
            await s.execute(delete(AccountRequest).where(AccountRequest.email == email))
            await s.execute(delete(Department).where(Department.name == "RaceDept"))
            await s.commit()
        await engine.dispose()


async def test_bound_lookup_uses_issuer_and_sub_together(db_session):
    # Why: `sub` is only unique per issuer. The HTTP path cannot show this
    # (the resolver accepts one issuer), so pin the lookup itself.
    from central_governance_api.auth.oidc import Principal
    from central_governance_api.routers.me import _bound_membership

    await _approved_membership(db_session)
    member = (await db_session.execute(select(AccountMembership))).scalar_one()
    member.bound_issuer, member.bound_sub = ISSUER, "same-sub"
    from datetime import UTC, datetime

    member.bound_at = datetime.now(UTC)
    await db_session.flush()

    def principal(issuer: str) -> Principal:
        return Principal(
            issuer=issuer,
            sub="same-sub",
            display_name="x",
            roles=frozenset(),
            azp=None,
        )

    assert await _bound_membership(db_session, principal(ISSUER)) is not None
    assert (
        await _bound_membership(db_session, principal("https://other.example")) is None
    )
