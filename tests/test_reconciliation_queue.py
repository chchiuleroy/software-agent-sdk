"""Integration tests for GET /api/v1/reconciliation-queue, against a REAL Postgres.

What matters here: only ``failed_unknown`` records are listed (the one state that
needs a person), the role gate is ``governance.admin`` and nothing else, a finding
never takes a record out of the list, the filter on ``admin_verified`` is a filter on
what is stored, and keyset paging walks every row once.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import update

from central_governance_api.auth.dependencies import get_oidc_resolver
from central_governance_api.auth.oidc import OIDCPrincipalResolver
from central_governance_api.db import get_db_session
from central_governance_api.main import create_app
from central_governance_api.models import (
    PendingApprovalRecord,
    ReconciliationFinding,
)

from .test_app_auth import _sign
from .test_approvals_router import (
    _approval_failed_unknown,
    _auth,
    _create_approval,
    _findings_for,
)


URL = "/api/v1/reconciliation-queue"


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


def _admin(signing_key) -> dict[str, str]:
    return _auth(_sign(signing_key, sub="dave", roles=["governance.admin"]))


async def _verify(client, signing_key, approval_id: str, key: str) -> None:
    resp = await client.post(
        f"/api/v1/approvals/{approval_id}/reconciliation-findings",
        json={
            "finding_type": "admin_verified",
            "conclusion": "confirmed_not_executed",
            "note": "checked the target system",
        },
        headers=_auth(_sign(signing_key, sub="dave", roles=["governance.admin"]), key),
    )
    assert resp.status_code == 201, resp.text


async def _set_created_at(db_session, approval_id: str, when: datetime) -> None:
    await db_session.execute(
        update(PendingApprovalRecord)
        .where(PendingApprovalRecord.id == uuid.UUID(approval_id))
        .values(created_at=when)
    )
    await db_session.flush()


@pytest.mark.parametrize(
    "roles",
    [
        ["agent.operator"],
        ["agent.approver"],
        ["governance.superadmin"],
        [],
    ],
)
async def test_only_governance_admin_may_read_the_queue(client, signing_key, roles):
    resp = await client.get(URL, headers=_auth(_sign(signing_key, roles=roles)))
    assert resp.status_code == 403


async def test_no_token_is_401(client):
    assert (await client.get(URL)).status_code in (401, 403)


async def test_only_failed_unknown_records_are_listed(client, signing_key, db_session):
    failed_id, _ = await _approval_failed_unknown(client, signing_key, db_session)
    await _create_approval(client, signing_key, sub="alice")  # stays pending
    rejected = await _create_approval(client, signing_key, sub="alice")
    await client.post(
        f"/api/v1/approvals/{rejected['id']}/decide",
        json={"decision": "reject"},
        headers=_auth(
            _sign(signing_key, sub="carol", roles=["agent.approver"]), "rj-1"
        ),
    )

    resp = await client.get(URL, headers=_admin(signing_key))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert [item["id"] for item in body["items"]] == [failed_id]
    assert body["items"][0]["status"] == "failed_unknown"
    assert body["next_cursor"] is None


async def test_an_item_shows_what_a_verifier_needs_and_not_the_digest_inputs(
    client, signing_key, db_session
):
    approval_id, _ = await _approval_failed_unknown(client, signing_key, db_session)
    item = (await client.get(URL, headers=_admin(signing_key))).json()["items"][0]
    assert set(item) == {
        "id",
        "request_id",
        "status",
        "requester",
        "origin_device_id",
        "conversation_id",
        "tool_name",
        "action_summary",
        "action_payload",
        "created_at",
        "admin_verified",
        "findings_total",
        "findings",
    }
    assert item["id"] == approval_id
    assert item["requester"].endswith("#alice")
    assert item["tool_name"] == "bash"
    assert item["admin_verified"] is False
    assert item["findings"] == []


async def test_findings_are_listed_and_a_verified_record_stays_in_the_queue(
    client, signing_key, db_session
):
    approval_id, _ = await _approval_failed_unknown(client, signing_key, db_session)
    alice = _sign(signing_key, sub="alice", roles=["agent.operator"])
    await client.post(
        f"/api/v1/approvals/{approval_id}/reconciliation-findings",
        json={
            "finding_type": "requester_assertion",
            "conclusion": "confirmed_executed",
            "note": "I saw it run",
            "evidence": {"operator": "alice"},
        },
        headers=_auth(alice, "assert-q-1"),
    )
    await _verify(client, signing_key, approval_id, "verify-q-1")
    # every request here runs inside one test transaction, so the database stamps both
    # findings with the same now(); give them the distinct times real requests get
    findings = {f.finding_type: f for f in await _findings_for(db_session, approval_id)}
    findings["requester_assertion"].created_at = datetime(2026, 10, 1, tzinfo=UTC)
    findings["admin_verified"].created_at = datetime(2026, 10, 2, tzinfo=UTC)
    await db_session.flush()

    body = (await client.get(URL, headers=_admin(signing_key))).json()
    assert [item["id"] for item in body["items"]] == [approval_id]
    item = body["items"][0]
    assert item["status"] == "failed_unknown"  # a finding is evidence, not a transition
    assert item["admin_verified"] is True
    kinds = [f["finding_type"] for f in item["findings"]]
    assert kinds == ["requester_assertion", "admin_verified"]
    assertion, verified = item["findings"]
    assert assertion["note"] == "I saw it run"
    assert assertion["evidence"] == {"operator": "alice"}
    assert assertion["verifier"].endswith("#alice")
    assert verified["conclusion"] == "confirmed_not_executed"
    assert verified["verifier"].endswith("#dave")


async def test_the_admin_verified_filter_follows_what_is_stored(
    client, signing_key, db_session
):
    verified_id, _ = await _approval_failed_unknown(client, signing_key, db_session)
    open_id, _ = await _approval_failed_unknown(client, signing_key, db_session)
    # a requester assertion alone does not count as the independent check
    alice = _sign(signing_key, sub="alice", roles=["agent.operator"])
    await client.post(
        f"/api/v1/approvals/{open_id}/reconciliation-findings",
        json={"finding_type": "requester_assertion", "note": "x"},
        headers=_auth(alice, "assert-q-2"),
    )
    await _verify(client, signing_key, verified_id, "verify-q-2")

    def ids(response):
        return {item["id"] for item in response.json()["items"]}

    admin = _admin(signing_key)
    assert ids(await client.get(URL, headers=admin)) == {verified_id, open_id}
    assert ids(
        await client.get(URL, params={"admin_verified": "true"}, headers=admin)
    ) == {verified_id}
    assert ids(
        await client.get(URL, params={"admin_verified": "false"}, headers=admin)
    ) == {open_id}


async def test_keyset_paging_walks_every_record_once_newest_first(
    client, signing_key, db_session
):
    base = datetime(2026, 10, 1, 12, 0, tzinfo=UTC)
    created = []
    for n in range(5):
        approval_id, _ = await _approval_failed_unknown(client, signing_key, db_session)
        await _set_created_at(db_session, approval_id, base + timedelta(minutes=n))
        created.append(approval_id)
    # two share one timestamp and the page boundary falls between them: the id breaks
    # the tie, and neither may be skipped
    await _set_created_at(db_session, created[1], base + timedelta(minutes=2))

    admin = _admin(signing_key)
    seen: list[str] = []
    cursor = None
    pages = 0
    while True:
        params = {"limit": 3, **({"cursor": cursor} if cursor else {})}
        body = (await client.get(URL, params=params, headers=admin)).json()
        seen += [item["id"] for item in body["items"]]
        pages += 1
        cursor = body["next_cursor"]
        if cursor is None:
            break
    assert pages == 2
    assert sorted(seen) == sorted(created)
    assert len(seen) == len(set(seen))
    times = [
        (await db_session.get(PendingApprovalRecord, uuid.UUID(i))).created_at
        for i in seen
    ]
    assert times == sorted(times, reverse=True)


async def test_the_last_full_page_has_no_cursor(client, signing_key, db_session):
    for _ in range(2):
        await _approval_failed_unknown(client, signing_key, db_session)
    body = (
        await client.get(URL, params={"limit": 2}, headers=_admin(signing_key))
    ).json()
    assert len(body["items"]) == 2
    assert body["next_cursor"] is None


async def test_offset_and_a_forged_cursor_are_400(client, signing_key):
    admin = _admin(signing_key)
    resp = await client.get(URL, params={"offset": 1}, headers=admin)
    assert resp.status_code == 400
    assert resp.json()["error_code"] == "offset_not_supported"
    resp = await client.get(URL, params={"cursor": "not-a-cursor"}, headers=admin)
    assert resp.status_code == 400
    assert resp.json()["error_code"] == "invalid_cursor"


@pytest.mark.parametrize("limit", [0, 201])
async def test_limit_is_bounded(client, signing_key, limit):
    resp = await client.get(URL, params={"limit": limit}, headers=_admin(signing_key))
    assert resp.status_code == 422


async def _add_findings(db_session, approval_id: str, rows: list[dict]) -> None:
    for row in rows:
        db_session.add(
            ReconciliationFinding(
                approval_request_id=uuid.UUID(approval_id),
                verifier_issuer="http://kc/realms/x",
                verifier_sub="svc-agent-1",
                **row,
            )
        )
    await db_session.flush()


async def test_a_record_with_many_findings_shows_the_newest_and_says_how_many(
    client, signing_key, db_session
):
    """A requester may keep filing findings: one answer must not grow with them."""
    approval_id, _ = await _approval_failed_unknown(client, signing_key, db_session)
    base = datetime(2026, 10, 1, tzinfo=UTC)
    await _add_findings(
        db_session,
        approval_id,
        [
            {
                "finding_type": "requester_assertion",
                "note": f"note {n}",
                "created_at": base + timedelta(minutes=n),
            }
            for n in range(25)
        ],
    )
    item = (await client.get(URL, headers=_admin(signing_key))).json()["items"][0]
    assert item["findings_total"] == 25
    notes = [f["note"] for f in item["findings"]]
    assert notes == [f"note {n}" for n in range(5, 25)]  # the newest 20, oldest first


async def test_admin_verified_looks_at_every_finding_not_only_the_ones_shown(
    client, signing_key, db_session
):
    approval_id, _ = await _approval_failed_unknown(client, signing_key, db_session)
    base = datetime(2026, 10, 1, tzinfo=UTC)
    await _add_findings(
        db_session,
        approval_id,
        [
            {
                "finding_type": "admin_verified",
                "conclusion": "inconclusive",
                "note": "oldest",
                "created_at": base,
            }
        ]
        + [
            {
                "finding_type": "requester_assertion",
                "note": f"later {n}",
                "created_at": base + timedelta(minutes=n + 1),
            }
            for n in range(25)
        ],
    )
    admin = _admin(signing_key)
    item = (await client.get(URL, headers=admin)).json()["items"][0]
    assert item["findings_total"] == 26
    assert "admin_verified" not in [f["finding_type"] for f in item["findings"]]
    assert item["admin_verified"] is True, "the verification is older than the 20 shown"
    only_open = await client.get(URL, params={"admin_verified": "false"}, headers=admin)
    assert only_open.json()["items"] == []


async def test_a_long_note_and_a_huge_evidence_are_cut_in_the_database(
    client, signing_key, db_session
):
    approval_id, _ = await _approval_failed_unknown(client, signing_key, db_session)
    base = datetime(2026, 10, 1, tzinfo=UTC)
    await _add_findings(
        db_session,
        approval_id,
        [
            {
                "finding_type": "requester_assertion",
                "note": "n" * 5000,
                "evidence": {"blob": "e" * 20000},
                "created_at": base,
            },
            {
                "finding_type": "late_report",
                "note": "n" * 2000,  # exactly the limit: not cut
                "evidence": {"ok": "small"},
                "created_at": base + timedelta(minutes=1),
            },
        ],
    )
    findings = (await client.get(URL, headers=_admin(signing_key))).json()["items"][0][
        "findings"
    ]
    long_one, exact = findings
    assert len(long_one["note"]) == 2000 and long_one["note_truncated"] is True
    assert long_one["evidence"] is None and long_one["evidence_truncated"] is True
    assert len(exact["note"]) == 2000 and exact["note_truncated"] is False
    assert exact["evidence"] == {"ok": "small"} and exact["evidence_truncated"] is False


async def test_a_finding_without_evidence_is_not_reported_as_cut(
    client, signing_key, db_session
):
    approval_id, _ = await _approval_failed_unknown(client, signing_key, db_session)
    await _add_findings(
        db_session,
        approval_id,
        [{"finding_type": "requester_assertion", "note": "x", "evidence": None}],
    )
    finding = (await client.get(URL, headers=_admin(signing_key))).json()["items"][0][
        "findings"
    ][0]
    assert finding["evidence"] is None and finding["evidence_truncated"] is False
