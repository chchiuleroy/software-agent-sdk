"""Tests for GovernanceOutbox's persistence, atomic-write, and state
transitions.
"""

from __future__ import annotations

from typing import Any

import pytest

from openhands.agent_server.governance_outbox import (
    GovernanceOutbox,
    OutboxRecord,
    OutboxState,
    record_attempt,
)


def _record(**overrides: Any) -> OutboxRecord:
    defaults: dict[str, Any] = dict(
        request_id="req-1",
        conversation_id="conv-1",
        action_event_id="event-1",
        tool_call_id="call-1",
        tool_name="bash",
        action_type="terminal_command",
        policy_revision="v1",
        action_summary="echo hi",
        action_payload={"command": "echo hi"},
        digest_salt=None,
        action_payload_digest="deadbeef",
        execution_commitment="commitment-hash",
        origin_device_id="agent-server-mvp",
    )
    defaults.update(overrides)
    return OutboxRecord(**defaults)


@pytest.mark.asyncio
async def test_create_and_load_round_trip(tmp_path):
    outbox = GovernanceOutbox(tmp_path)
    assert outbox.load() is None

    await outbox.create_record(_record())

    loaded = outbox.load()
    assert loaded is not None
    assert loaded.request_id == "req-1"
    assert loaded.state == OutboxState.PENDING_CREATE


@pytest.mark.asyncio
async def test_create_record_refuses_to_overwrite_existing(tmp_path):
    outbox = GovernanceOutbox(tmp_path)
    await outbox.create_record(_record())

    with pytest.raises(FileExistsError):
        await outbox.create_record(_record())


@pytest.mark.asyncio
async def test_mutate_without_existing_record_raises(tmp_path):
    outbox = GovernanceOutbox(tmp_path)
    with pytest.raises(FileNotFoundError):
        await outbox.mutate(lambda r: r)


@pytest.mark.asyncio
async def test_mutate_advances_state_and_persists(tmp_path):
    outbox = GovernanceOutbox(tmp_path)
    await outbox.create_record(_record())

    def _mark_created(record: OutboxRecord) -> OutboxRecord:
        record.state = OutboxState.CREATED
        record.central_approval_id = "approval-123"
        return record

    updated = await outbox.mutate(_mark_created)
    assert updated.state == OutboxState.CREATED
    assert updated.central_approval_id == "approval-123"

    # Persisted, not just returned in memory — a fresh load sees it too.
    reloaded = outbox.load()
    assert reloaded is not None
    assert reloaded.state == OutboxState.CREATED
    assert reloaded.central_approval_id == "approval-123"


@pytest.mark.asyncio
async def test_atomic_write_survives_across_instances(tmp_path):
    # Simulates a process restart: a fresh GovernanceOutbox pointed at the
    # same directory must see the same durable state.
    first = GovernanceOutbox(tmp_path)
    await first.create_record(_record())

    second = GovernanceOutbox(tmp_path)
    loaded = second.load()
    assert loaded is not None
    assert loaded.request_id == "req-1"


def test_record_attempt_bumps_count_and_timestamp():
    record = _record()
    assert record.attempt_count == 0
    assert record.last_attempt_at is None

    updated = record_attempt(record, new_state=OutboxState.CLAIM_INFLIGHT)

    assert updated.attempt_count == 1
    assert updated.last_attempt_at is not None
    assert updated.state == OutboxState.CLAIM_INFLIGHT


def test_record_attempt_without_state_change_only_bumps_bookkeeping():
    record = _record(state=OutboxState.CLAIMED)
    updated = record_attempt(record)
    assert updated.attempt_count == 1
    assert updated.state == OutboxState.CLAIMED


@pytest.mark.asyncio
async def test_no_leftover_temp_file_after_successful_write(tmp_path):
    outbox = GovernanceOutbox(tmp_path)
    await outbox.create_record(_record())

    leftover_temps = list(tmp_path.glob(".governance_outbox.json.*"))
    assert leftover_temps == []


@pytest.mark.asyncio
async def test_archive_and_clear_frees_the_active_path_for_a_new_record(tmp_path):
    """A conversation must be governable more than once in its lifetime —
    without this, the active governance_outbox.json path stays permanently
    occupied by the first (even if long-since-terminal) record."""
    outbox = GovernanceOutbox(tmp_path)
    await outbox.create_record(_record(action_event_id="event-1"))
    await outbox.mutate(
        lambda r: record_attempt(r, new_state=OutboxState.RESULT_REPORTED)
    )

    await outbox.archive_and_clear()

    assert outbox.load() is None
    # A new record for a *different* action can now be created.
    await outbox.create_record(_record(action_event_id="event-2"))
    reloaded = outbox.load()
    assert reloaded is not None
    assert reloaded.action_event_id == "event-2"


@pytest.mark.asyncio
async def test_archive_and_clear_keeps_the_old_record_on_disk(tmp_path):
    """The terminal record is an audit trail, not deleted — same
    convention as delete()'s own docstring."""
    outbox = GovernanceOutbox(tmp_path)
    record = _record(action_event_id="event-1")
    await outbox.create_record(record)

    await outbox.archive_and_clear()

    archived = list(tmp_path.glob(f".governance_outbox.{record.request_id}.*.json"))
    assert len(archived) == 1


@pytest.mark.asyncio
async def test_archive_and_clear_is_a_noop_when_nothing_exists(tmp_path):
    outbox = GovernanceOutbox(tmp_path)
    await outbox.archive_and_clear()  # must not raise
    assert outbox.load() is None
