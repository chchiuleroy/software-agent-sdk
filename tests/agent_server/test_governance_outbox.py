"""Tests for GovernanceOutbox's persistence, atomic-write, and state
transitions.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from openhands.agent_server.governance_outbox import (
    RETRIABLE_STATES,
    TERMINAL_STATES,
    UNRECOGNIZED_ERROR_CODE,
    GovernanceOutbox,
    NeedsAttentionReason,
    OutboxRecord,
    OutboxState,
    mark_needs_attention,
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


def test_mark_needs_attention_records_state_reason_and_code():
    record = _record(state=OutboxState.CLAIM_INFLIGHT)

    updated = mark_needs_attention(
        record, NeedsAttentionReason.CLAIM_FAILED, error_code="not_found"
    )

    assert updated.state == OutboxState.NEEDS_ATTENTION
    assert updated.needs_attention_reason == "claim_failed"
    assert updated.last_error_code == "not_found"
    assert updated.attempt_count == 1
    assert updated.last_attempt_at is not None


@pytest.mark.parametrize(
    "unsafe",
    [
        "oops token=sk-123 leaked",  # contains a space
        "line1\nline2",  # control character
        "x" * 65,  # over the length limit
        "",  # empty
        "中文",  # outside the identifier alphabet
    ],
)
def test_mark_needs_attention_never_persists_a_free_text_error_code(unsafe):
    """The code comes from a remote response body. Whatever the caller passes,
    only a short identifier-like label may reach the outbox file."""
    updated = mark_needs_attention(
        _record(), NeedsAttentionReason.REPORT_FAILED, error_code=unsafe
    )

    assert updated.last_error_code == UNRECOGNIZED_ERROR_CODE
    assert updated.needs_attention_reason == "report_failed"


@pytest.mark.parametrize(
    "safe", ["not_found", "status=executing", "RuntimeError", "a.b:c-d_1", "x" * 64]
)
def test_mark_needs_attention_keeps_a_well_formed_error_code(safe):
    updated = mark_needs_attention(
        _record(), NeedsAttentionReason.REPORT_FAILED, error_code=safe
    )

    assert updated.last_error_code == safe


def test_mark_needs_attention_replaces_a_previous_error_code():
    """A record that is parked again must not keep the earlier failure's code."""
    record = _record(last_error_code="stale-code")

    updated = mark_needs_attention(record, NeedsAttentionReason.REPORT_FAILED)

    assert updated.last_error_code is None


@pytest.mark.asyncio
async def test_needs_attention_reason_is_persisted_as_its_plain_string(tmp_path):
    """The reason values are the contract an operator API will expose, so the
    exact strings on disk matter, and they must survive a restart."""
    outbox = GovernanceOutbox(tmp_path)
    await outbox.create_record(_record())
    await outbox.mutate(
        lambda r: mark_needs_attention(
            r,
            NeedsAttentionReason.CENTRAL_STATUS_UNEXPECTED,
            error_code="status=applied",
        )
    )

    raw = json.loads((tmp_path / "governance_outbox.json").read_text(encoding="utf-8"))
    assert raw["state"] == "needs_attention"
    assert raw["needs_attention_reason"] == "central_status_unexpected"
    assert raw["last_error_code"] == "status=applied"

    reloaded = GovernanceOutbox(tmp_path).load()
    assert reloaded is not None
    assert (
        reloaded.needs_attention_reason
        == NeedsAttentionReason.CENTRAL_STATUS_UNEXPECTED
    )


def test_needs_attention_is_neither_retriable_nor_terminal():
    """Everything in the 1.11 design rests on this: relay never touches the
    state, and a new governed action is refused while a record sits in it.
    Changing either set changes that analysis, so make it a conscious edit."""
    assert OutboxState.NEEDS_ATTENTION not in RETRIABLE_STATES
    assert OutboxState.NEEDS_ATTENTION not in TERMINAL_STATES


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
