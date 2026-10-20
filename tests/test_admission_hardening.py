"""Findings of the review of step C1, each with the test that keeps it fixed:
request-body size, who may call the device endpoints and how often, the per-submitter
limits under real parallel requests, and what a repeated submission reveals.

Every test says why it matters.
"""

from __future__ import annotations

import asyncio
import uuid

import pytest
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import async_sessionmaker

from central_governance_api.admission import service
from central_governance_api.admission.errors import AdmissionRateLimitedError
from central_governance_api.auth.oidc import Principal
from central_governance_api.body_limit import BodySizeLimitMiddleware
from central_governance_api.db import create_engine
from central_governance_api.models import (
    AdminAuditEvent,
    AdmissionFirstUse,
    AdmissionItem,
    AdmissionItemContent,
    AdmissionItemTool,
    Department,
    DepartmentPrincipal,
)

from .test_admission_router import (
    SCHEMA,
    _as,
    _decide,
    _first_use,
    _mcp,
    _set_status,
    _staff,
    _submitted,
)
from .test_app_auth import _sign
from .test_tool_permissions import ISSUER, _client, _department, _settings


pytestmark = pytest.mark.asyncio


@pytest.fixture
async def client(public_jwks, db_session):
    async with await _client(_settings(), public_jwks, db_session) as c:
        yield c


@pytest.fixture
async def tiny_body_client(public_jwks, db_session):
    settings = _settings(admission_max_request_bytes=5_000)
    async with await _client(settings, public_jwks, db_session) as c:
        yield c


@pytest.fixture
async def first_use_limited_client(public_jwks, db_session):
    settings = _settings(admission_first_use_per_minute=3)
    async with await _client(settings, public_jwks, db_session) as c:
        yield c


# --- the request body is limited while it is read -----------------------------------


async def test_an_oversized_body_is_refused_before_it_is_parsed(
    tiny_body_client, db_session, signing_key
):
    # Why: FastAPI parses the whole JSON body before the endpoint runs, so the size
    # checks inside the endpoint come too late to protect memory.
    client = tiny_body_client
    dept = await _department(db_session)
    headers = await _staff(db_session, signing_key, dept, "ada")
    huge = _mcp(tools=[{"name": "t", "description": "x" * 20_000, "input_schema": {}}])
    refused = await client.post("/api/v1/admission/items", json=huge, headers=headers)
    assert refused.status_code == 413
    assert refused.json()["error_code"] == "admission_content_too_large"
    assert (await db_session.execute(select(AdmissionItem))).first() is None
    small = await client.post("/api/v1/admission/items", json=_mcp(), headers=headers)
    assert small.status_code == 201


async def test_other_routes_are_not_limited_by_it(
    tiny_body_client, db_session, signing_key
):
    client = tiny_body_client
    headers = _as(signing_key, "root", "governance.superadmin")
    # a body well over the limit on a route that is not listed still reaches its
    # handler (here: it fails validation, which is the handler's own answer, not 413)
    resp = await client.post(
        f"/api/v1/admin/admission/items/{uuid.uuid4()}/reject",
        json={"reason": "x" * 600},
        headers=headers,
    )
    assert resp.status_code != 413


async def _call(app, *, method, path, headers, chunks):
    """Drive an ASGI app by hand: ``chunks`` are the body messages."""
    sent: list[dict] = []
    pending = list(chunks)

    async def receive():
        if pending:
            data = pending.pop(0)
            return {"type": "http.request", "body": data, "more_body": bool(pending)}
        return {"type": "http.disconnect"}

    async def send(message):
        sent.append(message)

    scope = {
        "type": "http",
        "method": method,
        "path": path,
        "headers": [(k.encode(), v.encode()) for k, v in headers.items()],
    }
    await app(scope, receive, send)
    return sent


async def test_a_body_with_no_or_a_false_content_length_is_stopped_while_streaming():
    # Why: a chunked upload has no Content-Length, and a client can state a small one
    # and send more; counting the bytes as they arrive covers both.
    reads = 0

    async def app(scope, receive, send):
        nonlocal reads
        while True:
            message = await receive()
            if message["type"] != "http.request":
                break
            reads += 1
            if not message.get("more_body"):
                break
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    limited = BodySizeLimitMiddleware(app, limits={("POST", "/limited"): 100})
    chunks = [b"x" * 60, b"x" * 60, b"x" * 60]

    sent = await _call(
        limited, method="POST", path="/limited", headers={}, chunks=chunks
    )
    # the second chunk is stopped before the app ever sees it
    assert sent[0]["status"] == 413 and reads == 1
    liar = {"content-length": "10"}
    sent = await _call(
        limited, method="POST", path="/limited", headers=liar, chunks=chunks
    )
    assert sent[0]["status"] == 413
    declared = {"content-length": "5000"}
    reads = 0
    sent = await _call(
        limited, method="POST", path="/limited", headers=declared, chunks=chunks
    )
    assert sent[0]["status"] == 413 and reads == 0  # refused without reading a byte
    sent = await _call(
        limited, method="POST", path="/limited", headers={}, chunks=[b"x" * 50]
    )
    assert sent[0]["status"] == 200
    sent = await _call(
        limited, method="POST", path="/elsewhere", headers={}, chunks=chunks
    )
    assert sent[0]["status"] == 200


# --- the device endpoints are for devices, and are rate limited ---------------------


@pytest.mark.parametrize(
    "roles", [[], ["governance.admin"], ["agent.approver"], ["governance.superadmin"]]
)
async def test_only_a_device_identity_may_read_the_list_or_report_a_first_use(
    client, db_session, signing_key, roles
):
    # Why: these answer for a whole department; a person (an approver, an admin) has no
    # business enumerating approved fingerprints or writing first-use records.
    headers = {
        "Authorization": "Bearer " + _sign(signing_key, sub="someone", roles=roles)
    }
    fingerprint = "sha256:" + "a" * 64
    assert (
        await client.get("/api/v1/me/admitted-items", headers=headers)
    ).status_code == 403
    assert (await _first_use(client, headers, fingerprint)).status_code == 403
    assert (await db_session.execute(select(AdmissionFirstUse))).first() is None


async def test_first_use_reports_are_limited_per_identity_per_minute(
    first_use_limited_client, db_session, signing_key
):
    # Why: every report writes an audit event, so an endless loop of them would fill
    # the audit table. A device sends one per item, so the limit is far above need.
    client = first_use_limited_client
    dept, headers, _ = await _submitted(client, db_session, signing_key, "device-1")
    codes = []
    for i in range(5):
        resp = await _first_use(client, headers, "sha256:" + f"{i:064x}")
        codes.append(resp.status_code)
    assert codes == [200, 200, 200, 429, 429]
    assert resp.json()["error_code"] == "admission_rate_limited"
    other = await _staff(db_session, signing_key, dept, "device-2")
    assert (await _first_use(client, other, "sha256:" + "f" * 64)).status_code == 200


async def test_the_same_first_use_report_adds_one_row_not_many(
    client, db_session, signing_key
):
    _, headers, item = await _submitted(client, db_session, signing_key, "device-1")
    fingerprint = (
        await db_session.execute(select(AdmissionItem.fingerprint))
    ).scalar_one()
    await _set_status(db_session, item, "approved")
    for _ in range(4):
        assert (await _first_use(client, headers, fingerprint)).json() == {
            "status": "approved"
        }
    rows = await db_session.scalar(select(func.count()).select_from(AdmissionFirstUse))
    assert rows == 1


# --- what a repeated submission reveals ---------------------------------------------


async def test_a_repeat_by_someone_else_reveals_where_it_stands_but_nothing_they_wrote(
    client, db_session, signing_key
):
    # Why: the same content in the same department is one item, so a second submitter
    # learns of the first. That must not include the first person's name for it, its
    # source, or the reason it was decided as it was.
    dept = await _department(db_session)
    ada = await _staff(db_session, signing_key, dept, "ada")
    bob = await _staff(db_session, signing_key, dept, "bob")
    mine = _mcp("ada-private-name")
    mine["source"] = "https://internal.example.test/ada"
    first = (
        await client.post("/api/v1/admission/items", json=mine, headers=ada)
    ).json()
    rejected = await _decide(
        client, signing_key, first["id"], "reject", reason="ada's secret reason"
    )
    assert rejected.status_code == 200
    theirs = _mcp("bob-name")
    theirs["source"] = "https://bob.example.test"
    resp = await client.post("/api/v1/admission/items", json=theirs, headers=bob)
    body = resp.json()
    assert resp.status_code == 200 and body["created"] is False
    assert body["id"] == first["id"] and body["status"] == "rejected"
    assert (body["name"], body["source"], body["status_reason"]) == (
        "bob-name",
        "https://bob.example.test",
        None,
    )
    assert "ada" not in resp.text
    again = (
        await client.post("/api/v1/admission/items", json=mine, headers=ada)
    ).json()
    assert again["name"] == "ada-private-name"  # the submitter still sees their own


# --- the limits under real parallel requests ----------------------------------------


async def test_parallel_submissions_by_one_user_cannot_pass_the_waiting_limit(
    signing_key,
):
    """Eight different contents at once, limit one waiting item.

    Why: each limit is "count, then insert". Without something that makes one user's
    submissions take turns, all eight see an empty queue and all eight are created.
    This needs real, separate connections (the shared test session cannot make a real
    conflict), so it commits its own rows and removes them again."""
    engine = create_engine(_settings())
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    sub = f"parallel-{uuid.uuid4().hex[:8]}"
    settings = _settings(admission_max_open_per_user=1)
    principal = Principal(
        issuer=ISSUER,
        sub=sub,
        display_name="parallel",
        roles=frozenset({"agent.operator"}),
        azp=None,
    )
    try:
        async with sessions() as setup:
            department = Department(name=f"Parallel-{uuid.uuid4().hex[:6]}")
            setup.add(department)
            await setup.flush()
            setup.add(
                DepartmentPrincipal(
                    department_id=department.id,
                    issuer=ISSUER,
                    sub=sub,
                    assigned_by_issuer=ISSUER,
                    assigned_by_sub="root",
                )
            )
            await setup.commit()
            department_id = department.id
    except Exception as exc:  # no reachable test Postgres
        await engine.dispose()
        pytest.skip(f"no reachable test Postgres: {exc}")

    # Open all the connections first and hand them back to the pool. Otherwise they are
    # made one after another, the first request finishes before the others even have a
    # connection, and nothing runs in parallel (found by removing the lock: the test
    # still passed).
    warm = [await engine.connect() for _ in range(8)]
    for connection in warm:
        await connection.close()

    async def one(i: int):
        async with sessions() as session:
            tool = service.ToolDescriptor(f"tool{i}", None, SCHEMA)
            try:
                result = await service.submit(
                    session,
                    principal,
                    settings,
                    kind="mcp_server",
                    name=f"server{i}",
                    source="https://mcp.example.test",
                    department_id=None,
                    tools=[tool],
                    archive_b64=None,
                )
                return "created" if result.created else "existing"
            except AdmissionRateLimitedError:
                return "limited"

    try:
        outcomes = await asyncio.gather(*(one(i) for i in range(8)))
        assert sorted(outcomes) == ["created"] + ["limited"] * 7, outcomes
    finally:
        async with sessions() as cleanup:
            item_ids = (
                (
                    await cleanup.execute(
                        select(AdmissionItem.id).where(
                            AdmissionItem.submitted_by_sub == sub
                        )
                    )
                )
                .scalars()
                .all()
            )
            if item_ids:
                await cleanup.execute(
                    delete(AdmissionItemTool).where(
                        AdmissionItemTool.item_id.in_(item_ids)
                    )
                )
                await cleanup.execute(
                    delete(AdmissionItemContent).where(
                        AdmissionItemContent.item_id.in_(item_ids)
                    )
                )
                await cleanup.execute(
                    delete(AdmissionItem).where(AdmissionItem.id.in_(item_ids))
                )
            await cleanup.execute(
                delete(AdminAuditEvent).where(AdminAuditEvent.actor_sub == sub)
            )
            await cleanup.execute(
                delete(DepartmentPrincipal).where(DepartmentPrincipal.sub == sub)
            )
            await cleanup.execute(
                delete(Department).where(Department.id == department_id)
            )
            await cleanup.commit()
        await engine.dispose()
