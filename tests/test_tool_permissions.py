"""Department tool permissions: superadmin endpoints, the per-caller answer an
agent-server fetches, and enforcement at approval CREATE and CLAIM.

Real Postgres via ``db_session``. Each test says why it matters.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select

from central_governance_api.auth.dependencies import get_oidc_resolver
from central_governance_api.auth.oidc import OIDCPrincipalResolver
from central_governance_api.config import Settings
from central_governance_api.db import get_db_session
from central_governance_api.main import create_app
from central_governance_api.models import (
    AdminAuditEvent,
    Department,
    DepartmentPrincipal,
    DepartmentToolPermission,
    PendingApprovalRecord,
)

from .conftest import _TEST_DATABASE_URL, AUDIENCE, ISSUER, JWKS_URL
from .test_app_auth import _sign
from .test_approvals_router import _auth, _create_body


def _settings(**overrides) -> Settings:
    return Settings(
        oidc_issuer=ISSUER,
        oidc_jwks_url=JWKS_URL,
        oidc_audience=AUDIENCE,
        database_url=_TEST_DATABASE_URL,
        **overrides,
    )  # pyright: ignore[reportCallIssue]


async def _client(settings: Settings, public_jwks, db_session):
    app = create_app(settings)
    resolver = OIDCPrincipalResolver(
        settings, preloaded_keys=public_jwks, never_refresh_keys=True
    )
    app.dependency_overrides[get_oidc_resolver] = lambda: resolver

    async def _db_session_override():
        yield db_session

    app.dependency_overrides[get_db_session] = _db_session_override
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


@pytest.fixture
async def client(public_jwks, db_session):
    async with await _client(_settings(), public_jwks, db_session) as c:
        yield c


@pytest.fixture
async def enforcing_client(public_jwks, db_session):
    settings = _settings(enforce_tool_permissions=True)
    async with await _client(settings, public_jwks, db_session) as c:
        yield c


def _super(signing_key, **claims) -> dict[str, str]:
    token = _sign(signing_key, sub="root", roles=["governance.superadmin"], **claims)
    return {"Authorization": f"Bearer {token}"}


async def _department(db_session, name: str = "Finance") -> uuid.UUID:
    dept = Department(name=name)
    db_session.add(dept)
    await db_session.flush()
    return dept.id


async def _grant(db_session, department_id: uuid.UUID, *tools: str) -> None:
    for name in tools:
        db_session.add(
            DepartmentToolPermission(
                department_id=department_id,
                tool_name=name,
                granted_by_issuer=ISSUER,
                granted_by_sub="root",
            )
        )
    await db_session.flush()


async def _assign(db_session, department_id: uuid.UUID, sub: str) -> None:
    db_session.add(
        DepartmentPrincipal(
            department_id=department_id,
            issuer=ISSUER,
            sub=sub,
            assigned_by_issuer=ISSUER,
            assigned_by_sub="root",
        )
    )
    await db_session.flush()


# --- who may change permissions ---------------------------------------------


@pytest.mark.parametrize(
    "roles", [[], ["governance.admin"], ["agent.approver"], ["agent.operator"]]
)
async def test_only_superadmin_may_edit_permissions(client, signing_key, roles):
    # Why: tool permissions are the policy itself; the approval roles must not
    # be able to rewrite them.
    token = _sign(signing_key, sub="x", roles=roles)
    headers = {"Authorization": f"Bearer {token}"}
    dept = str(uuid.uuid4())
    for method, path, body in [
        ("PUT", f"/api/v1/admin/departments/{dept}/tools", {"tools": ["a"]}),
        ("GET", f"/api/v1/admin/departments/{dept}/tools", None),
        ("POST", f"/api/v1/admin/departments/{dept}/principals", {"sub": "s"}),
    ]:
        resp = await client.request(method, path, headers=headers, json=body)
        assert resp.status_code == 403, (method, path)


# --- setting the tool list ---------------------------------------------------


async def test_put_replaces_the_set_and_audits_the_difference(
    client, db_session, signing_key
):
    dept = await _department(db_session)
    await _grant(db_session, dept, "terminal", "file_editor")
    resp = await client.put(
        f"/api/v1/admin/departments/{dept}/tools",
        json={"tools": ["file_editor", "grep", "grep"]},
        headers=_super(signing_key),
    )
    assert resp.status_code == 200
    assert resp.json()["tools"] == ["file_editor", "grep"]
    stored = (
        await db_session.execute(
            select(DepartmentToolPermission.tool_name).order_by(
                DepartmentToolPermission.tool_name
            )
        )
    ).scalars()
    assert list(stored) == ["file_editor", "grep"]
    event = (await db_session.execute(select(AdminAuditEvent))).scalar_one()
    assert event.event_type == "department_tools_set"
    assert event.payload["added"] == ["grep"]
    assert event.payload["removed"] == ["terminal"]


async def test_put_with_no_change_writes_no_audit_event(
    client, db_session, signing_key
):
    dept = await _department(db_session)
    await _grant(db_session, dept, "terminal")
    resp = await client.put(
        f"/api/v1/admin/departments/{dept}/tools",
        json={"tools": ["terminal"]},
        headers=_super(signing_key),
    )
    assert resp.status_code == 200
    assert list((await db_session.execute(select(AdminAuditEvent))).scalars()) == []


@pytest.mark.parametrize("bad", ["has space", "", "a/b", "x" * 129, "tool;rm"])
async def test_bad_tool_names_are_rejected(client, db_session, signing_key, bad):
    dept = await _department(db_session)
    resp = await client.put(
        f"/api/v1/admin/departments/{dept}/tools",
        json={"tools": [bad]},
        headers=_super(signing_key),
    )
    assert resp.status_code == 422


async def test_too_many_tools_and_unknown_department(client, db_session, signing_key):
    dept = await _department(db_session)
    many = [f"t{i}" for i in range(201)]
    assert (
        await client.put(
            f"/api/v1/admin/departments/{dept}/tools",
            json={"tools": many},
            headers=_super(signing_key),
        )
    ).status_code == 422
    assert (
        await client.put(
            f"/api/v1/admin/departments/{uuid.uuid4()}/tools",
            json={"tools": []},
            headers=_super(signing_key),
        )
    ).status_code == 404


# --- assigning a service account to a department ----------------------------


async def test_assign_and_unassign_a_principal_with_audit(
    client, db_session, signing_key
):
    dept = await _department(db_session)
    created = await client.post(
        f"/api/v1/admin/departments/{dept}/principals",
        json={"sub": "svc-agent-1"},
        headers=_super(signing_key),
    )
    assert created.status_code == 201
    body = created.json()
    assert body["issuer"] == ISSUER  # defaults to the configured issuer
    listed = await client.get(
        f"/api/v1/admin/departments/{dept}/principals", headers=_super(signing_key)
    )
    assert [p["sub"] for p in listed.json()] == ["svc-agent-1"]
    gone = await client.delete(
        f"/api/v1/admin/departments/{dept}/principals/{body['id']}",
        headers=_super(signing_key),
    )
    assert gone.status_code == 204
    again = await client.delete(
        f"/api/v1/admin/departments/{dept}/principals/{body['id']}",
        headers=_super(signing_key),
    )
    assert again.status_code == 404
    events = [
        e.event_type
        for e in (await db_session.execute(select(AdminAuditEvent))).scalars()
    ]
    assert sorted(events) == [
        "department_principal_assigned",
        "department_principal_unassigned",
    ]


async def test_a_principal_belongs_to_one_department_only(
    client, db_session, signing_key
):
    # Why: if one service account could sit in two departments, "which tools
    # may it use" would depend on lookup order.
    a = await _department(db_session, "A")
    b = await _department(db_session, "B")
    first = await client.post(
        f"/api/v1/admin/departments/{a}/principals",
        json={"sub": "svc"},
        headers=_super(signing_key),
    )
    second = await client.post(
        f"/api/v1/admin/departments/{b}/principals",
        json={"sub": "svc"},
        headers=_super(signing_key),
    )
    assert first.status_code == 201
    assert second.status_code == 409
    assert second.json()["error_code"] == "principal_already_assigned"


# --- what a device fetches ----------------------------------------------------


async def test_my_permissions_follow_the_assigned_service_account(
    client, db_session, signing_key
):
    dept = await _department(db_session)
    await _grant(db_session, dept, "terminal", "grep")
    await _assign(db_session, dept, "svc-agent-1")
    token = _sign(signing_key, sub="svc-agent-1", roles=["agent.operator"])
    resp = await client.get(
        "/api/v1/me/tool-permissions", headers={"Authorization": f"Bearer {token}"}
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["department_name"] == "Finance"
    assert body["tools"] == ["grep", "terminal"]
    assert body["max_age_seconds"] == 600
    assert len(body["revision"]) == 16


async def test_revision_changes_when_the_tool_set_changes(
    client, db_session, signing_key
):
    # Why: a device uses the revision to tell fresh from stale.
    dept = await _department(db_session)
    await _assign(db_session, dept, "svc")
    token = _sign(signing_key, sub="svc", roles=[])
    headers = {"Authorization": f"Bearer {token}"}
    before = (await client.get("/api/v1/me/tool-permissions", headers=headers)).json()
    await _grant(db_session, dept, "terminal")
    after = (await client.get("/api/v1/me/tool-permissions", headers=headers)).json()
    assert before["revision"] != after["revision"]


async def test_a_caller_with_no_department_gets_nothing(client, signing_key):
    # Why: allow-list. No department must mean no tools, never "all tools".
    token = _sign(signing_key, sub="stranger", roles=["agent.operator"])
    resp = await client.get(
        "/api/v1/me/tool-permissions", headers={"Authorization": f"Bearer {token}"}
    )
    body = resp.json()
    assert body["department_id"] is None
    assert body["tools"] == []


async def test_my_permissions_requires_authentication(client):
    assert (await client.get("/api/v1/me/tool-permissions")).status_code == 401


# --- enforcement at create and claim -----------------------------------------


async def _create(client, signing_key, *, sub: str, tool: str):
    token = _sign(signing_key, sub=sub, roles=["agent.operator"])
    return await client.post(
        "/api/v1/approvals",
        json=_create_body(tool_name=tool),
        headers=_auth(token, f"create-{uuid.uuid4()}"),
    )


def test_enforcement_is_off_by_default():
    # Why: a freshly deployed central must not start refusing every
    # agent-server whose service account has no department yet.
    assert _settings().enforce_tool_permissions is False


async def test_nothing_changes_while_enforcement_is_off(
    client, db_session, signing_key
):
    resp = await _create(client, signing_key, sub="unassigned", tool="bash")
    assert resp.status_code == 201


async def test_create_is_refused_for_a_tool_outside_the_department(
    enforcing_client, db_session, signing_key
):
    dept = await _department(db_session)
    await _grant(db_session, dept, "grep")
    await _assign(db_session, dept, "svc")
    resp = await _create(enforcing_client, signing_key, sub="svc", tool="bash")
    assert resp.status_code == 403
    assert resp.json()["error_code"] == "tool_not_permitted"
    # Why: the refusal must come before anything is written.
    assert (
        list((await db_session.execute(select(PendingApprovalRecord))).scalars()) == []
    )
    assert "bash" not in resp.text


async def test_create_is_allowed_for_a_permitted_tool(
    enforcing_client, db_session, signing_key
):
    dept = await _department(db_session)
    await _grant(db_session, dept, "bash")
    await _assign(db_session, dept, "svc")
    resp = await _create(enforcing_client, signing_key, sub="svc", tool="bash")
    assert resp.status_code == 201


async def test_a_caller_without_a_department_is_refused_when_enforcing(
    enforcing_client, signing_key
):
    resp = await _create(enforcing_client, signing_key, sub="nobody", tool="bash")
    assert resp.status_code == 403


async def test_claim_is_refused_after_the_permission_is_revoked(
    enforcing_client, db_session, signing_key
):
    # Why: claim is the step that lets the action execute. A permission
    # revoked while the request waited for a decision must stop it here.
    dept = await _department(db_session)
    await _grant(db_session, dept, "bash")
    await _assign(db_session, dept, "svc")
    created = await _create(enforcing_client, signing_key, sub="svc", tool="bash")
    approval_id = created.json()["id"]
    approver = _sign(signing_key, sub="carol", roles=["agent.approver"])
    decided = await enforcing_client.post(
        f"/api/v1/approvals/{approval_id}/decide",
        json={"decision": "accept"},
        headers=_auth(approver, f"decide-{uuid.uuid4()}"),
    )
    assert decided.status_code == 200, decided.text

    await db_session.execute(delete(DepartmentToolPermission))  # revoke
    token = _sign(signing_key, sub="svc", roles=["agent.operator"])
    claim = await enforcing_client.post(
        f"/api/v1/approvals/{approval_id}/claim",
        headers=_auth(token, f"claim-{uuid.uuid4()}"),
    )
    assert claim.status_code == 403
    assert claim.json()["error_code"] == "tool_not_permitted"
