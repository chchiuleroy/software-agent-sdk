"""Superadmin endpoints: departments, reviewing account requests, the
unbound-membership reminder list. Real Postgres via ``db_session``.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from central_governance_api.auth.dependencies import get_oidc_resolver
from central_governance_api.auth.oidc import OIDCPrincipalResolver
from central_governance_api.db import get_db_session
from central_governance_api.main import create_app
from central_governance_api.models import (
    AccountMembership,
    AccountRequest,
    AdminAuditEvent,
    Department,
)

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


def _super(signing_key, **claims) -> dict[str, str]:
    token = _sign(
        signing_key,
        sub=claims.pop("sub", "root"),
        roles=claims.pop("roles", ["governance.superadmin"]),
        **claims,
    )
    return {"Authorization": f"Bearer {token}"}


async def _department(db_session, name: str = "Finance") -> Department:
    dept = Department(name=name)
    db_session.add(dept)
    await db_session.flush()
    await db_session.refresh(dept)
    return dept


async def _request(
    db_session, email: str = "alice@corp.example", status: str = "pending_review"
) -> AccountRequest:
    row = AccountRequest(
        email=email,
        display_name="Alice",
        requested_department="Finance",
        reason="needs access",
        status=status,
        code_attempts=0,
    )
    db_session.add(row)
    await db_session.flush()
    await db_session.refresh(row)
    return row


# --- who may call -----------------------------------------------------------

ADMIN_ROUTES = [
    ("GET", "/api/v1/admin/departments"),
    ("POST", "/api/v1/admin/departments"),
    ("GET", "/api/v1/admin/account-requests"),
    ("GET", "/api/v1/admin/memberships"),
]


@pytest.mark.parametrize("method,path", ADMIN_ROUTES)
@pytest.mark.parametrize(
    "roles", [[], ["governance.admin"], ["agent.approver"], ["agent.operator"]]
)
async def test_only_superadmin_may_use_admin_routes(
    client, signing_key, method, path, roles
):
    # Why: governance.admin runs approvals; it must not also run accounts.
    headers = _super(signing_key, roles=roles)
    resp = await client.request(method, path, headers=headers, json={"name": "X"})
    assert resp.status_code == 403


async def test_superadmin_gets_no_approval_powers(client, signing_key):
    # Why: the two role families must not leak into each other. The approvals
    # list needs agent.approver or governance.admin, never superadmin.
    resp = await client.get("/api/v1/approvals/pending", headers=_super(signing_key))
    assert resp.status_code == 403


async def test_unauthenticated_admin_call_is_401(client):
    assert (await client.get("/api/v1/admin/departments")).status_code == 401


# --- departments --------------------------------------------------------------


async def test_create_list_and_audit_a_department(client, db_session, signing_key):
    resp = await client.post(
        "/api/v1/admin/departments",
        json={"name": "  Legal "},
        headers=_super(signing_key),
    )
    assert resp.status_code == 201
    assert resp.json()["name"] == "Legal"
    listed = await client.get("/api/v1/admin/departments", headers=_super(signing_key))
    assert [d["name"] for d in listed.json()] == ["Legal"]
    events = list((await db_session.execute(select(AdminAuditEvent))).scalars())
    assert [e.event_type for e in events] == ["department_created"]
    assert events[0].actor_sub == "root"


async def test_duplicate_department_name_is_409(client, db_session, signing_key):
    await _department(db_session, "Finance")
    resp = await client.post(
        "/api/v1/admin/departments",
        json={"name": "Finance"},
        headers=_super(signing_key),
    )
    assert resp.status_code == 409
    assert resp.json()["error_code"] == "department_exists"


async def test_disable_department_once(client, db_session, signing_key):
    dept_id = (await _department(db_session)).id
    first = await client.post(
        f"/api/v1/admin/departments/{dept_id}/disable", headers=_super(signing_key)
    )
    second = await client.post(
        f"/api/v1/admin/departments/{dept_id}/disable", headers=_super(signing_key)
    )
    missing = await client.post(
        f"/api/v1/admin/departments/{uuid.uuid4()}/disable", headers=_super(signing_key)
    )
    assert first.status_code == 200 and first.json()["disabled_at"] is not None
    assert second.status_code == 409
    assert missing.status_code == 404


# --- review -------------------------------------------------------------------


async def test_list_defaults_to_requests_awaiting_review(
    client, db_session, signing_key
):
    await _request(db_session, "a@corp.example", "pending_review")
    await _request(db_session, "b@corp.example", "pending_verification")
    resp = await client.get(
        "/api/v1/admin/account-requests", headers=_super(signing_key)
    )
    assert [r["email"] for r in resp.json()] == ["a@corp.example"]
    bad = await client.get(
        "/api/v1/admin/account-requests?status=nope", headers=_super(signing_key)
    )
    assert bad.status_code == 422


async def test_approve_creates_membership_and_audit(client, db_session, signing_key):
    dept_id = (await _department(db_session)).id
    req_id = (await _request(db_session)).id
    resp = await client.post(
        f"/api/v1/admin/account-requests/{req_id}/approve",
        json={"department_id": str(dept_id)},
        headers=_super(signing_key),
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "approved"
    member = (await db_session.execute(select(AccountMembership))).scalar_one()
    # Why: the membership is what the first login binds to; it starts unbound.
    assert member.email == "alice@corp.example"
    assert member.department_id == dept_id
    assert member.bound_sub is None
    event = (await db_session.execute(select(AdminAuditEvent))).scalar_one()
    assert event.event_type == "account_request_approved"
    assert event.actor_sub == "root"
    assert event.payload["email"] == "alice@corp.example"


async def test_approving_twice_is_409_and_makes_one_membership(
    client, db_session, signing_key
):
    # Why: a retried approval must not create a second account.
    dept = await _department(db_session)
    req = await _request(db_session)
    url = f"/api/v1/admin/account-requests/{req.id}/approve"
    body = {"department_id": str(dept.id)}
    first = await client.post(url, json=body, headers=_super(signing_key))
    second = await client.post(url, json=body, headers=_super(signing_key))
    assert first.status_code == 200
    assert second.status_code == 409
    assert second.json()["error_code"] == "account_request_not_pending"
    members = list((await db_session.execute(select(AccountMembership))).scalars())
    assert len(members) == 1


async def test_cannot_approve_an_unverified_request(client, db_session, signing_key):
    # Why: review must only ever see addresses whose owner proved the code.
    dept = await _department(db_session)
    req = await _request(db_session, status="pending_verification")
    resp = await client.post(
        f"/api/v1/admin/account-requests/{req.id}/approve",
        json={"department_id": str(dept.id)},
        headers=_super(signing_key),
    )
    assert resp.status_code == 409
    assert list((await db_session.execute(select(AccountMembership))).scalars()) == []


async def test_cannot_approve_into_a_disabled_or_missing_department(
    client, db_session, signing_key
):
    dept_id = (await _department(db_session)).id
    req = await _request(db_session)
    url = f"/api/v1/admin/account-requests/{req.id}/approve"
    await client.post(
        f"/api/v1/admin/departments/{dept_id}/disable", headers=_super(signing_key)
    )
    disabled = await client.post(
        url, json={"department_id": str(dept_id)}, headers=_super(signing_key)
    )
    missing = await client.post(
        url, json={"department_id": str(uuid.uuid4())}, headers=_super(signing_key)
    )
    assert disabled.status_code == 409
    assert disabled.json()["error_code"] == "department_disabled"
    assert missing.status_code == 404
    await db_session.refresh(req)
    assert req.status == "pending_review"


async def test_superadmin_cannot_decide_their_own_request(
    client, db_session, signing_key
):
    # Why: nobody approves their own access.
    dept = await _department(db_session)
    req = await _request(db_session, "root@corp.example")
    headers = _super(signing_key, email="root@corp.example")
    approve = await client.post(
        f"/api/v1/admin/account-requests/{req.id}/approve",
        json={"department_id": str(dept.id)},
        headers=headers,
    )
    reject = await client.post(
        f"/api/v1/admin/account-requests/{req.id}/reject",
        json={"reason": "x"},
        headers=headers,
    )
    assert approve.status_code == reject.status_code == 403
    await db_session.refresh(req)
    assert req.status == "pending_review"


async def test_reject_records_reason_and_decider(client, db_session, signing_key):
    req = await _request(db_session)
    resp = await client.post(
        f"/api/v1/admin/account-requests/{req.id}/reject",
        json={"reason": "not a company address"},
        headers=_super(signing_key),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "rejected"
    assert body["decision_reason"] == "not a company address"
    await db_session.refresh(req)
    assert req.decided_by_sub == "root"
    assert list((await db_session.execute(select(AccountMembership))).scalars()) == []
    event = (await db_session.execute(select(AdminAuditEvent))).scalar_one()
    assert event.event_type == "account_request_rejected"


async def test_unknown_request_id_is_404(client, signing_key):
    resp = await client.post(
        f"/api/v1/admin/account-requests/{uuid.uuid4()}/reject",
        json={"reason": "x"},
        headers=_super(signing_key),
    )
    assert resp.status_code == 404


# --- unbound reminder list ------------------------------------------------------


async def test_unbound_memberships_are_the_reminder_list(
    client, db_session, signing_key
):
    dept = await _department(db_session)
    done = await _request(db_session, "bound@corp.example", "approved")
    todo = await _request(db_session, "todo@corp.example", "approved")
    from datetime import UTC, datetime

    db_session.add_all(
        [
            AccountMembership(
                email="bound@corp.example",
                department_id=dept.id,
                account_request_id=done.id,
                bound_issuer="https://idp",
                bound_sub="s1",
                bound_at=datetime.now(UTC),
            ),
            AccountMembership(
                email="todo@corp.example",
                department_id=dept.id,
                account_request_id=todo.id,
            ),
        ]
    )
    await db_session.flush()
    only_unbound = await client.get(
        "/api/v1/admin/memberships?unbound=true", headers=_super(signing_key)
    )
    everyone = await client.get(
        "/api/v1/admin/memberships", headers=_super(signing_key)
    )
    assert [m["email"] for m in only_unbound.json()] == ["todo@corp.example"]
    assert len(everyone.json()) == 2


@pytest.mark.parametrize("status", ["pending_verification", "approved", "expired"])
async def test_cannot_reject_a_request_that_is_not_awaiting_review(
    client, db_session, signing_key, status
):
    # Why: a decided or unverified application must not be overwritten by a
    # late or replayed reject (an approved one would end up approved AND
    # rejected, with a live membership).
    req = await _request(db_session, status=status)
    resp = await client.post(
        f"/api/v1/admin/account-requests/{req.id}/reject",
        json={"reason": "late"},
        headers=_super(signing_key),
    )
    assert resp.status_code == 409
    await db_session.refresh(req)
    assert req.status == status
    assert req.decision_reason is None
