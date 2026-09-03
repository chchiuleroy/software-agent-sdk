"""Tests for roy_admin_audit — the admin_audit/user_approval JSONL writers.

Covers the module directly (record_admin_audit_event/record_user_approval_
event write correctly-shaped JSONL and fail open on write errors). See
test_roy_governance_lock.py for set_confirmation_policy()/
set_security_analyzer() writing through this module (including the
only-on-actual-change behavior), and test_roy_user_approval_audit.py for
reject_pending_actions()/run()/arun() doing the same for user_approval.
"""

import json
import os

from openhands.sdk.security.roy_admin_audit import (
    record_admin_audit_event,
    record_user_approval_event,
)


def test_record_admin_audit_event_writes_expected_fields(monkeypatch, tmp_path):
    monkeypatch.setenv("ROY_GOVERNANCE_AUDIT_DIR", str(tmp_path))

    record_admin_audit_event(
        conversation_id="conv-1", field="confirmation_policy", value="NeverConfirm()"
    )

    record = json.loads(
        (tmp_path / "admin_audit.jsonl").read_text(encoding="utf-8").strip()
    )
    assert record["conversation_id"] == "conv-1"
    assert record["field"] == "confirmation_policy"
    assert record["value"] == "NeverConfirm()"
    assert "timestamp" in record


def test_record_user_approval_event_writes_expected_fields(monkeypatch, tmp_path):
    monkeypatch.setenv("ROY_GOVERNANCE_AUDIT_DIR", str(tmp_path))

    record_user_approval_event(
        conversation_id="conv-2",
        accepted=False,
        reason="looked risky",
        tool_names=["terminal", "file_editor"],
        tool_call_ids=["call_1", "call_2"],
    )

    record = json.loads(
        (tmp_path / "user_approval.jsonl").read_text(encoding="utf-8").strip()
    )
    assert record["conversation_id"] == "conv-2"
    assert record["accepted"] is False
    assert record["reason"] == "looked risky"
    assert record["tool_names"] == ["terminal", "file_editor"]
    assert record["tool_call_ids"] == ["call_1", "call_2"]


def test_admin_and_user_events_go_to_separate_files(monkeypatch, tmp_path):
    monkeypatch.setenv("ROY_GOVERNANCE_AUDIT_DIR", str(tmp_path))

    record_admin_audit_event(conversation_id="c", field="x", value="y")
    record_user_approval_event(
        conversation_id="c",
        accepted=True,
        reason=None,
        tool_names=[],
        tool_call_ids=[],
    )

    assert (tmp_path / "admin_audit.jsonl").exists()
    assert (tmp_path / "user_approval.jsonl").exists()


def test_appends_multiple_events_as_separate_lines(monkeypatch, tmp_path):
    monkeypatch.setenv("ROY_GOVERNANCE_AUDIT_DIR", str(tmp_path))

    record_admin_audit_event(conversation_id="c1", field="f", value="1")
    record_admin_audit_event(conversation_id="c2", field="f", value="2")

    lines = (tmp_path / "admin_audit.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["conversation_id"] == "c1"
    assert json.loads(lines[1])["conversation_id"] == "c2"


def test_unwritable_audit_dir_does_not_raise(monkeypatch):
    # Fail open: a broken audit path must never be the reason a governance
    # setting change or an approval decision fails.
    monkeypatch.setattr(
        os, "makedirs", lambda *a, **k: (_ for _ in ()).throw(OSError("nope"))
    )

    record_admin_audit_event(conversation_id="c", field="f", value="v")
    record_user_approval_event(
        conversation_id="c",
        accepted=True,
        reason=None,
        tool_names=[],
        tool_call_ids=[],
    )
