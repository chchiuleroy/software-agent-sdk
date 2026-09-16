"""Tests for the background expiry sweep (``approvals/sweep.py``) — real
Postgres, same rationale as the other integration test files: applying the
state machine's ``EXPIRE`` event via a conditional UPDATE is exactly the
kind of thing a mocked session can't prove.

Uses the shared SAVEPOINT-isolated ``db_session`` fixture, same as most of
this project's integration tests — ``sweep_expired_approvals()`` only
needs to prove it flips the right rows to the right status, entirely
visible within one transaction/session; unlike
``tests/test_wait_endpoint.py``'s NOTIFY-wakeup test, it doesn't need a
genuine concurrent commit. The ``pg_notify()`` calls
``sweep_expired_approvals()`` makes along the way run here too, but are
never actually delivered (this file's SAVEPOINT transaction is only ever
rolled back, never committed — see ``approvals/notify.py``'s module
docstring on why that's inert rather than wrong); real delivery is proven
once, in ``test_wait_endpoint.py``, not duplicated here.

Assertions below check each test's own record by id after a fresh
``session.refresh()`` rather than trusting ``sweep_expired_approvals()``'s
aggregate return count for exact equality — that count reflects a scan of
the WHOLE table, so a strict equality assertion would be fragile against
any other row's state (there are none as of this writing, but a per-row
check costs nothing and doesn't depend on that staying true).
"""

from __future__ import annotations

import uuid
from datetime import timedelta

from central_governance_api.approvals.state_machine import ApprovalStatus
from central_governance_api.approvals.sweep import sweep_expired_approvals
from central_governance_api.clock import now_utc
from central_governance_api.models import PendingApprovalRecord


def _make_record(**overrides: object) -> PendingApprovalRecord:
    base: dict[str, object] = dict(
        request_id=str(uuid.uuid4()),
        requester_issuer="https://issuer.example.invalid",
        requester_sub="alice",
        origin_device_id="device-1",
        conversation_id="conv-1",
        action_event_id="event-1",
        action_type="terminal_command",
        tool_name="bash",
        policy_revision="v1",
        action_summary="echo hi",
        action_payload={"command": "echo hi"},
        action_payload_digest="deadbeef",
        status=ApprovalStatus.PENDING.value,
        expires_at=now_utc() + timedelta(hours=1),
    )
    base.update(overrides)
    return PendingApprovalRecord(**base)  # pyright: ignore[reportArgumentType]


async def test_sweep_expires_lapsed_pending_row(db_session):
    record = _make_record(expires_at=now_utc() - timedelta(seconds=1))
    db_session.add(record)
    await db_session.flush()

    changed = await sweep_expired_approvals(db_session)

    await db_session.refresh(record)
    assert changed >= 1
    assert record.status == ApprovalStatus.EXPIRED.value


async def test_sweep_leaves_unexpired_pending_row_alone(db_session):
    record = _make_record(expires_at=now_utc() + timedelta(hours=1))
    db_session.add(record)
    await db_session.flush()

    await sweep_expired_approvals(db_session)

    await db_session.refresh(record)
    assert record.status == ApprovalStatus.PENDING.value


async def test_sweep_expires_lapsed_accepted_row(db_session):
    record = _make_record(
        status=ApprovalStatus.ACCEPTED.value,
        execution_deadline=now_utc() - timedelta(seconds=1),
    )
    db_session.add(record)
    await db_session.flush()

    changed = await sweep_expired_approvals(db_session)

    await db_session.refresh(record)
    assert changed >= 1
    assert record.status == ApprovalStatus.EXPIRED.value


async def test_sweep_fails_lapsed_executing_row_to_unknown(db_session):
    """Matches the v10 "crash 後無法確認就 fail closed" invariant
    (``state_machine.py``'s ``EXECUTING`` + ``EXPIRE`` transition
    docstring): a claimed-but-never-reported attempt must fail closed to
    ``failed_unknown``, not silently vanish or resolve to a definite
    outcome."""
    record = _make_record(
        status=ApprovalStatus.EXECUTING.value,
        execution_attempt_id=uuid.uuid4(),
        executing_lease_expires_at=now_utc() - timedelta(seconds=1),
    )
    db_session.add(record)
    await db_session.flush()

    changed = await sweep_expired_approvals(db_session)

    await db_session.refresh(record)
    assert changed >= 1
    assert record.status == ApprovalStatus.FAILED_UNKNOWN.value


async def test_sweep_ignores_row_with_no_deadline_set(db_session):
    """``execution_deadline``/``executing_lease_expires_at`` are nullable
    — a row that somehow reached ACCEPTED/EXECUTING with that column
    unset must never be swept (``deadline_column.is_not(None)`` in the
    WHERE clause, the same fail-closed stance ``claim_approval`` itself
    takes on an accepted-with-no-deadline row — see
    ``routers/approvals.py``)."""
    record = _make_record(status=ApprovalStatus.ACCEPTED.value, execution_deadline=None)
    db_session.add(record)
    await db_session.flush()

    await sweep_expired_approvals(db_session)

    await db_session.refresh(record)
    assert record.status == ApprovalStatus.ACCEPTED.value


async def test_sweep_processes_multiple_lapsed_rows_in_one_pass(db_session):
    records = [
        _make_record(expires_at=now_utc() - timedelta(seconds=1)) for _ in range(3)
    ]
    for record in records:
        db_session.add(record)
    await db_session.flush()

    await sweep_expired_approvals(db_session)

    for record in records:
        await db_session.refresh(record)
        assert record.status == ApprovalStatus.EXPIRED.value
