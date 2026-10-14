"""Integration tests for the audit-events read endpoint — against a REAL
Postgres database. No idempotency/conditional-update machinery to prove
here (it's a GET), so the real-DB rationale is narrower than the other
two router test files: the role gate, and keyset paging actually querying
real rows (ties, microseconds, rows arriving mid-walk) rather than a fixture.
"""

from __future__ import annotations

import base64
import json
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text

from central_governance_api.auth.dependencies import get_oidc_resolver
from central_governance_api.auth.oidc import OIDCPrincipalResolver
from central_governance_api.db import get_db_session
from central_governance_api.main import create_app
from central_governance_api.models import AdminAuditEvent
from central_governance_api.routers.audit import decode_cursor, encode_cursor

from .test_app_auth import _sign


@pytest.fixture
async def client(settings, public_jwks, signing_key, db_session):
    app = create_app(settings)
    resolver = OIDCPrincipalResolver(
        settings, preloaded_keys=public_jwks, never_refresh_keys=True
    )
    app.dependency_overrides[get_oidc_resolver] = lambda: resolver

    async def _db_session_override():
        yield db_session

    app.dependency_overrides[get_db_session] = _db_session_override
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _register_and_revoke(client, signing_key, sub: str) -> str:
    """Returns the registration's own ``device_id`` (not its server ``id``
    — revoke needs the latter, since device_id uniqueness is per-owner
    now, not global; see routers/devices.py's module docstring)."""
    token = _sign(signing_key, sub=sub, roles=["agent.operator"])
    device_id = f"device-{uuid.uuid4()}"
    register_resp = await client.post(
        "/api/v1/devices/register",
        json={"device_id": device_id},
        headers={**_auth(token), "Idempotency-Key": f"reg-{uuid.uuid4()}"},
    )
    registration_id = register_resp.json()["id"]
    revoke_resp = await client.post(
        f"/api/v1/devices/{registration_id}/revoke",
        headers={**_auth(token), "Idempotency-Key": f"rev-{uuid.uuid4()}"},
    )
    assert revoke_resp.status_code == 200, revoke_resp.text
    return device_id


def _admin(signing_key) -> dict[str, str]:
    return _auth(_sign(signing_key, sub="dave", roles=["governance.admin"]))


def _unique_type() -> str:
    """A private event_type, so a test only ever looks at the rows it inserted."""
    return f"t-{uuid.uuid4().hex[:12]}"


T0 = datetime(2026, 10, 14, 12, 0, 0, tzinfo=UTC)


async def _insert(db_session, *, event_type: str, occurred_at: datetime):
    row = AdminAuditEvent(
        id=uuid.uuid4(),
        event_type=event_type,
        actor_issuer="https://issuer.test",
        actor_sub="seed",
        origin_device_id=None,
        approval_request_id=None,
        occurred_at=occurred_at,
        payload={},
    )
    db_session.add(row)
    await db_session.flush()
    return row


async def _get(client, signing_key, **params):
    return await client.get(
        "/api/v1/audit-events", params=params, headers=_admin(signing_key)
    )


async def _walk(client, signing_key, *, first_page=None, **params) -> list[str]:
    """Follow next_cursor to the end; returns every item id in order."""
    ids: list[str] = []
    body = first_page
    for _ in range(50):  # a paging bug must not loop forever
        if body is None:
            resp = await _get(client, signing_key, **params)
            assert resp.status_code == 200, resp.text
            body = resp.json()
        ids.extend(item["id"] for item in body["items"])
        if body["next_cursor"] is None:
            return ids
        params = {**params, "cursor": body["next_cursor"]}
        body = None
    pytest.fail("paging did not terminate within 50 pages")


# ------------------------------------------------------------------ role gate


@pytest.mark.parametrize(
    "roles,status",
    [
        (["governance.admin"], 200),
        (["governance.superadmin"], 200),
        (["agent.approver"], 403),
        (["agent.operator"], 403),
        ([], 403),
    ],
)
async def test_audit_events_role_gate(client, signing_key, roles, status):
    token = _sign(signing_key, sub="alice", roles=roles)
    resp = await client.get("/api/v1/audit-events", headers=_auth(token))
    assert resp.status_code == status


async def test_audit_events_requires_a_token(client):
    resp = await client.get("/api/v1/audit-events")
    assert resp.status_code == 401


# ------------------------------------------------------------------- content


async def test_audit_events_lists_device_revocation(client, signing_key):
    device_id = await _register_and_revoke(client, signing_key, sub="alice")

    resp = await _get(client, signing_key, event_type="device_revoked")
    assert resp.status_code == 200
    body = resp.json()
    matching = [item for item in body["items"] if item["origin_device_id"] == device_id]
    assert len(matching) == 1
    assert matching[0]["actor_subject"].endswith("#alice")


async def test_audit_events_empty_result_has_no_cursor(client, signing_key):
    resp = await _get(client, signing_key, event_type=_unique_type())
    assert resp.status_code == 200
    assert resp.json() == {"items": [], "next_cursor": None}


# -------------------------------------------------------------- keyset paging


async def test_rows_arriving_mid_walk_neither_repeat_nor_skip_existing_ones(
    client, signing_key, db_session
):
    """The reason cursors exist: with offset paging, two newer rows arriving after
    page 1 shift everything down and page 2 repeats rows already served. The walk
    must return exactly the rows that existed when it began, once each."""
    etype = _unique_type()
    original = [
        await _insert(
            db_session, event_type=etype, occurred_at=T0 + timedelta(seconds=i)
        )
        for i in range(7)
    ]
    first = await _get(client, signing_key, event_type=etype, limit=3)
    assert first.status_code == 200

    for i in (100, 101):  # newer than everything already served
        await _insert(
            db_session, event_type=etype, occurred_at=T0 + timedelta(seconds=i)
        )

    ids = await _walk(
        client, signing_key, first_page=first.json(), event_type=etype, limit=3
    )

    assert sorted(ids) == sorted(str(row.id) for row in original)
    assert len(ids) == len(set(ids)) == 7
    # and newest first
    expected_order = [
        str(row.id)
        for row in sorted(original, key=lambda r: r.occurred_at, reverse=True)
    ]
    assert ids == expected_order


async def test_page_boundary_inside_a_run_of_identical_timestamps(
    client, signing_key, db_session
):
    """Keying on occurred_at alone would drop the rest of a tie at the page edge;
    the id is what makes the position unique."""
    etype = _unique_type()
    rows = [
        await _insert(db_session, event_type=etype, occurred_at=T0) for _ in range(5)
    ]

    ids = await _walk(client, signing_key, event_type=etype, limit=2)

    assert sorted(ids) == sorted(str(row.id) for row in rows)
    assert len(ids) == len(set(ids)) == 5
    assert ids == sorted((str(row.id) for row in rows), reverse=True)


async def test_page_boundary_on_a_row_with_microseconds(
    client, signing_key, db_session
):
    """A cursor that loses sub-second precision would send the next page to a
    time earlier than the row it ended on and skip its close neighbours."""
    etype = _unique_type()
    rows = [
        await _insert(
            db_session, event_type=etype, occurred_at=T0.replace(microsecond=us)
        )
        for us in (123455, 123456, 123457)
    ]

    ids = await _walk(client, signing_key, event_type=etype, limit=1)

    assert ids == [str(row.id) for row in reversed(rows)]


async def test_filters_and_cursor_work_together(client, signing_key, db_session):
    a, b = _unique_type(), _unique_type()
    a_rows = []
    for i in range(4):
        a_rows.append(
            await _insert(
                db_session, event_type=a, occurred_at=T0 + timedelta(seconds=2 * i)
            )
        )
        await _insert(
            db_session, event_type=b, occurred_at=T0 + timedelta(seconds=2 * i + 1)
        )

    ids = await _walk(client, signing_key, event_type=a, limit=3)

    assert sorted(ids) == sorted(str(row.id) for row in a_rows)


# ------------------------------------------------------------ bad requests


def _raw_cursor(body) -> str:
    raw = body if isinstance(body, str) else json.dumps(body)
    return base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")


_GOOD = {"v": 1, "t": T0.isoformat(), "i": str(uuid.uuid4())}


@pytest.mark.parametrize(
    "cursor",
    [
        "!!!not base64!!!",
        _raw_cursor("not json"),
        _raw_cursor([1, 2, 3]),
        _raw_cursor({**_GOOD, "v": 2}),
        _raw_cursor({**_GOOD, "v": True}),
        _raw_cursor({"v": 1, "t": _GOOD["t"]}),
        _raw_cursor({**_GOOD, "extra": 1}),
        _raw_cursor({**_GOOD, "i": "not-a-uuid"}),
        _raw_cursor({**_GOOD, "t": "yesterday"}),
        _raw_cursor({**_GOOD, "t": "2026-10-14T12:00:00"}),  # no zone
        _raw_cursor({**_GOOD, "t": 20261014}),
        "A" * 600,
    ],
)
async def test_an_invalid_cursor_is_a_400_with_a_stable_code(
    client, signing_key, cursor
):
    resp = await _get(client, signing_key, cursor=cursor)
    assert resp.status_code == 400
    assert resp.json()["error_code"] == "invalid_cursor"


async def test_the_removed_offset_parameter_is_refused_not_ignored(client, signing_key):
    for value in (0, 50):
        resp = await _get(client, signing_key, offset=value)
        assert resp.status_code == 400
        assert resp.json()["error_code"] == "offset_not_supported"


def test_cursor_round_trips_exactly():
    when = datetime(2026, 10, 14, 12, 0, 0, 123456, tzinfo=UTC)
    event_id = uuid.uuid4()
    assert decode_cursor(encode_cursor(when, event_id)) == (when, event_id)


# --------------------------------------------------------------------- index


async def test_the_keyset_index_exists(db_session):
    """A small table never makes the planner use it, so check it is declared."""
    definition = (
        await db_session.execute(
            text(
                "select indexdef from pg_indexes "
                "where indexname = 'ix_admin_audit_events_occurred_at_id'"
            )
        )
    ).scalar_one()
    assert "occurred_at DESC, id DESC" in definition
