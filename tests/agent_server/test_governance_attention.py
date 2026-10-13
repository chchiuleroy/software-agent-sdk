"""Tests for the NEEDS_ATTENTION scan (``governance_attention``)."""

from __future__ import annotations

import json
import os
import subprocess
import uuid
from pathlib import Path
from typing import Any

import pytest

from openhands.agent_server import governance_attention as attention
from openhands.agent_server.governance_attention import (
    _ALLOWED_ACTIONS,
    UNREADABLE_OUTBOX,
    AttentionAction,
    AttentionItem,
    allowed_actions_for,
    scan_needs_attention,
)
from openhands.agent_server.governance_outbox import (
    OUTBOX_FILENAME,
    NeedsAttentionReason,
    OutboxRecord,
    OutboxState,
    mark_needs_attention,
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
        origin_device_id="device-1",
        central_approval_id="approval-1",
    )
    defaults.update(overrides)
    return OutboxRecord(**defaults)


def _parked(
    reason: NeedsAttentionReason | None = NeedsAttentionReason.CLAIM_FAILED,
    **overrides: Any,
) -> OutboxRecord:
    record = _record(**overrides)
    mark_needs_attention(
        record, reason or NeedsAttentionReason.CLAIM_FAILED, error_code="not_found"
    )
    if reason is None:  # a record parked before reasons were recorded
        record.needs_attention_reason = None
        record.last_error_code = None
    return record


def _write(root: Path, record: OutboxRecord, name: str | None = None) -> Path:
    directory = root / (name or uuid.uuid4().hex)
    directory.mkdir()
    (directory / OUTBOX_FILENAME).write_text(record.to_json(), encoding="utf-8")
    return directory


def test_missing_conversations_dir_is_empty(tmp_path):
    assert scan_needs_attention(tmp_path / "does-not-exist") == []


def test_lists_only_records_parked_in_needs_attention(tmp_path):
    parked = _write(tmp_path, _parked(request_id="req-parked"))
    for state in (
        OutboxState.PENDING_CREATE,
        OutboxState.CREATED,
        OutboxState.CLAIMED,
        OutboxState.RESULT_REPORTED,
        OutboxState.CANCELLED,
    ):
        _write(tmp_path, _record(state=state))

    items = scan_needs_attention(tmp_path)

    assert [i.request_id for i in items] == ["req-parked"]
    assert items[0].conversation_id == str(uuid.UUID(hex=parked.name))


def test_item_reports_what_identifies_the_problem(tmp_path):
    record = _parked(NeedsAttentionReason.REPORT_FAILED, request_id="req-9")
    record.last_error_code = "illegal_transition"
    record.attempt_count = 4
    record.last_attempt_at = "2026-10-13T00:00:00+00:00"
    _write(tmp_path, record)

    (item,) = scan_needs_attention(tmp_path)

    assert item.reason == "report_failed"
    assert item.last_error_code == "illegal_transition"
    assert item.central_approval_id == "approval-1"
    assert item.request_id == "req-9"
    assert item.attempt_count == 4
    assert item.last_attempt_at == "2026-10-13T00:00:00+00:00"
    assert item.allowed_actions == ["retry", "dismiss"]


def test_item_never_carries_the_action_payload(tmp_path):
    """The list is for deciding what to do, not for reading what the agent was
    about to run: payloads can hold commands, paths and secrets."""
    _write(
        tmp_path,
        _parked(
            action_payload={"command": "curl -H 'Authorization: Bearer SECRET-XYZ'"},
            action_summary="uses SECRET-XYZ",
        ),
    )

    (item,) = scan_needs_attention(tmp_path)

    assert set(item.model_dump()) == set(AttentionItem.model_fields)
    assert "SECRET-XYZ" not in item.model_dump_json()


def test_directory_name_that_is_not_a_uuid_is_shown_as_is(tmp_path):
    _write(tmp_path, _parked(), name="not-a-uuid")

    (item,) = scan_needs_attention(tmp_path)

    assert item.conversation_id == "not-a-uuid"


def test_most_recent_failure_first(tmp_path):
    # mark_needs_attention stamps "now", so set the time after parking.
    for request_id, when in (
        ("old", "2026-10-01T00:00:00"),
        ("new", "2026-10-13T00:00:00"),
        ("mid", "2026-10-07T00:00:00"),
    ):
        record = _parked(request_id=request_id)
        record.last_attempt_at = when
        _write(tmp_path, record)

    assert [i.request_id for i in scan_needs_attention(tmp_path)] == [
        "new",
        "mid",
        "old",
    ]


def test_skips_directories_without_an_outbox_and_stray_files(tmp_path):
    (tmp_path / uuid.uuid4().hex).mkdir()
    (tmp_path / "stray.txt").write_text("x", encoding="utf-8")

    assert scan_needs_attention(tmp_path) == []


def test_archived_outbox_files_are_not_listed(tmp_path):
    """An archived record is history. Only the active outbox file counts."""
    directory = tmp_path / uuid.uuid4().hex
    directory.mkdir()
    (directory / ".governance_outbox.req-1.archived.json").write_text(
        _parked().to_json(), encoding="utf-8"
    )

    assert scan_needs_attention(tmp_path) == []


# --------------------------- unreadable outboxes ---------------------------


@pytest.mark.parametrize(
    "content",
    [
        "{not json",
        "",
        "[]",
        json.dumps({"state": "needs_attention"}),  # required fields missing
        json.dumps(  # a state this version does not know (newer version, downgrade)
            {**json.loads(_parked().to_json()), "state": "resolved_from_the_future"}
        ),
        json.dumps(  # a field this version does not know
            {**json.loads(_parked().to_json()), "unknown_field": 1}
        ),
    ],
)
def test_unreadable_outbox_is_listed_not_skipped(tmp_path, content):
    """A damaged or too-new outbox may be exactly the stuck conversation; hiding
    it would defeat the point of the scan."""
    directory = tmp_path / uuid.uuid4().hex
    directory.mkdir()
    (directory / OUTBOX_FILENAME).write_text(content, encoding="utf-8")

    (item,) = scan_needs_attention(tmp_path)

    assert item.reason == UNREADABLE_OUTBOX
    assert item.allowed_actions == []
    assert item.request_id is None
    assert item.conversation_id == str(uuid.UUID(hex=directory.name))


def test_invalid_utf8_is_unreadable(tmp_path):
    directory = tmp_path / uuid.uuid4().hex
    directory.mkdir()
    (directory / OUTBOX_FILENAME).write_bytes(b"\xff\xfe\x00bad")

    (item,) = scan_needs_attention(tmp_path)

    assert item.reason == UNREADABLE_OUTBOX


def test_outbox_archived_during_the_scan_is_not_reported_as_unreadable(
    tmp_path, monkeypatch
):
    """Archiving renames the active file away. A scan that saw it exist a moment
    earlier must not turn that normal event into a damaged-file warning."""
    directory = _write(tmp_path, _parked())
    outbox_file = directory / OUTBOX_FILENAME
    real_read_text = Path.read_text

    def _vanish_before_the_read(self, *args, **kwargs):
        # By now exists() and stat() have both succeeded; the rename lands here.
        if self == outbox_file:
            outbox_file.unlink()
        return real_read_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", _vanish_before_the_read)

    assert scan_needs_attention(tmp_path) == []


def test_oversized_outbox_is_unreadable_without_being_parsed(tmp_path, monkeypatch):
    _write(tmp_path, _parked())
    monkeypatch.setattr(attention, "MAX_OUTBOX_BYTES", 10)

    (item,) = scan_needs_attention(tmp_path)

    assert item.reason == UNREADABLE_OUTBOX


def _symlink_or_skip(link: Path, target: Path, *, directory: bool) -> None:
    try:
        link.symlink_to(target, target_is_directory=directory)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks cannot be created in this environment")


def test_symlinked_outbox_file_is_not_followed(tmp_path):
    outside = tmp_path / "outside.json"
    outside.write_text(_parked().to_json(), encoding="utf-8")
    root = tmp_path / "conversations"
    root.mkdir()
    directory = root / uuid.uuid4().hex
    directory.mkdir()
    _symlink_or_skip(directory / OUTBOX_FILENAME, outside, directory=False)

    (item,) = scan_needs_attention(root)

    assert item.reason == UNREADABLE_OUTBOX


def test_symlinked_conversation_directory_is_not_followed(tmp_path):
    real = tmp_path / "elsewhere"
    real.mkdir()
    (real / OUTBOX_FILENAME).write_text(_parked().to_json(), encoding="utf-8")
    root = tmp_path / "conversations"
    root.mkdir()
    _symlink_or_skip(root / uuid.uuid4().hex, real, directory=True)

    assert scan_needs_attention(root) == []


def _pretend_symlink(monkeypatch, linked: Path) -> None:
    """Make ``linked`` report itself as a symlink. Creating a real one needs a
    privilege this machine may not grant, which would silently skip the checks
    above; this tests the decision, not the filesystem."""
    real = Path.is_symlink
    monkeypatch.setattr(Path, "is_symlink", lambda self: self == linked or real(self))


def test_outbox_file_that_reports_as_a_symlink_is_refused(tmp_path, monkeypatch):
    directory = _write(tmp_path, _parked())
    _pretend_symlink(monkeypatch, directory / OUTBOX_FILENAME)

    (item,) = scan_needs_attention(tmp_path)

    assert item.reason == UNREADABLE_OUTBOX


def test_conversation_directory_that_reports_as_a_symlink_is_skipped(
    tmp_path, monkeypatch
):
    directory = _write(tmp_path, _parked())
    _pretend_symlink(monkeypatch, directory)

    assert scan_needs_attention(tmp_path) == []


@pytest.mark.skipif(os.name != "nt", reason="junctions exist only on Windows")
def test_junctioned_conversation_directory_is_not_followed(tmp_path):
    """A junction needs no privilege to create, is not reported by is_symlink(),
    and is followed by is_dir() and read_text(), so it is the link that
    actually works against a Windows install."""
    real = tmp_path / "elsewhere"
    real.mkdir()
    (real / OUTBOX_FILENAME).write_text(_parked().to_json(), encoding="utf-8")
    root = tmp_path / "conversations"
    root.mkdir()
    link = root / uuid.uuid4().hex
    subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(link), str(real)],
        check=True,
        capture_output=True,
    )

    assert link.is_dir() and not link.is_symlink()  # the premise of the test
    assert scan_needs_attention(root) == []


# ------------------------------ action matrix ------------------------------


def test_every_reason_has_an_explicit_entry():
    """A reason added later must be given its actions on purpose, not fall back
    to the cautious default by accident."""
    assert set(_ALLOWED_ACTIONS) == set(NeedsAttentionReason)


@pytest.mark.parametrize(
    ("reason", "expected"),
    [
        (NeedsAttentionReason.CLAIM_FAILED, ["retry", "abandon", "dismiss"]),
        (NeedsAttentionReason.APPROVAL_CANCELLED_OR_EXPIRED, ["abandon", "dismiss"]),
        (NeedsAttentionReason.REPORT_FAILED, ["retry", "dismiss"]),
        (NeedsAttentionReason.RECONCILE_FAILED, ["retry", "dismiss"]),
        (NeedsAttentionReason.BINDING_REPORT_FAILED, ["retry", "dismiss"]),
        (NeedsAttentionReason.LATE_REPORT_REFUSED, ["dismiss"]),
        (NeedsAttentionReason.CENTRAL_STATUS_UNEXPECTED, ["dismiss"]),
    ],
)
def test_allowed_actions_per_reason(reason, expected):
    assert allowed_actions_for(reason.value) == expected


def test_abandon_is_only_offered_where_no_execution_attempt_exists():
    """The core safety rule: abandoning cancels at central and rejects the
    action locally, which is wrong for anything that may already have run."""
    never_ran = {
        NeedsAttentionReason.CLAIM_FAILED,
        NeedsAttentionReason.APPROVAL_CANCELLED_OR_EXPIRED,
    }
    for reason in NeedsAttentionReason:
        offered = AttentionAction.ABANDON.value in allowed_actions_for(reason.value)
        assert offered == (reason in never_ran), reason


@pytest.mark.parametrize("reason", [None, "", "from_a_newer_version"])
def test_missing_or_unknown_reason_only_allows_dismiss(reason):
    assert allowed_actions_for(reason) == ["dismiss"]


def test_record_parked_before_reasons_were_recorded_is_listed(tmp_path):
    _write(tmp_path, _parked(None))

    (item,) = scan_needs_attention(tmp_path)

    assert item.reason is None
    assert item.allowed_actions == ["dismiss"]
