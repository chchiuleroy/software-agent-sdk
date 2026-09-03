"""Tests for the governance audit hook (roy_audit_hooks / roy_audit_hook_writer).

Covers: the module that builds/merges the governance-mandated SessionStart
hook (``build_governance_hook_config``), and the standalone writer script it
points at (``roy_audit_hook_writer.main``), which is what actually runs as a
subprocess when OpenHands fires the hook.
"""

import importlib
import json
import os
import subprocess
import sys

from openhands.sdk.hooks import HookConfig, HookDefinition, HookMatcher
from openhands.sdk.security import (
    roy_audit_hook_writer,
    roy_audit_hooks as roy_audit_hooks_module,
)
from openhands.sdk.security.roy_audit_hooks import (
    AUDIT_HOOK_NAME,
    build_governance_hook_config,
)


def _session_start_hook_names(hook_config: HookConfig) -> list[str]:
    return [
        hook.name for matcher in hook_config.session_start for hook in matcher.hooks
    ]


class _FakeStdin:
    """Minimal stand-in for sys.stdin exposing only .read()."""

    def __init__(self, text: str) -> None:
        self._text = text

    def read(self) -> str:
        return self._text


# --- build_governance_hook_config ------------------------------------------


def test_no_user_config_returns_audit_only() -> None:
    config = build_governance_hook_config(None)
    assert _session_start_hook_names(config) == [AUDIT_HOOK_NAME]


def test_merges_with_user_hook_config_without_dropping_it() -> None:
    user_config = HookConfig(
        pre_tool_use=[HookMatcher(hooks=[HookDefinition(command="echo hi")])]
    )
    merged = build_governance_hook_config(user_config)

    assert len(merged.pre_tool_use) == 1
    assert merged.pre_tool_use[0].hooks[0].command == "echo hi"
    assert _session_start_hook_names(merged) == [AUDIT_HOOK_NAME]


def test_idempotent_when_audit_hook_already_present() -> None:
    # Simulates the double-construction path: ConversationSettings
    # .create_request() already merges the audit hook into the payload,
    # then StartConversationRequest's own validator runs the same merge
    # again on that already-merged config.
    once = build_governance_hook_config(None)
    twice = build_governance_hook_config(once)

    # Not necessarily the same object (rebuilt each time), but must not
    # accumulate a second copy.
    assert _session_start_hook_names(twice) == [AUDIT_HOOK_NAME]


def test_idempotent_preserves_user_hooks_added_alongside_audit() -> None:
    user_config = HookConfig(
        pre_tool_use=[HookMatcher(hooks=[HookDefinition(command="echo hi")])]
    )
    merged_once = build_governance_hook_config(user_config)
    merged_twice = build_governance_hook_config(merged_once)

    assert len(merged_twice.pre_tool_use) == 1
    assert _session_start_hook_names(merged_twice) == [AUDIT_HOOK_NAME]


def test_same_named_fake_hook_is_replaced_not_trusted() -> None:
    # Regression test for a real finding from Codex review (2026-09-03):
    # the original idempotency check only looked at the hook *name*, so a
    # caller (or a malicious/buggy plugin) supplying its own hook under the
    # reserved AUDIT_HOOK_NAME with a different (e.g. no-op) command would
    # be mistaken for "the audit hook already ran" and the real audit hook
    # would never be added.
    fake_config = HookConfig(
        session_start=[
            HookMatcher(
                hooks=[HookDefinition(name=AUDIT_HOOK_NAME, command="echo noop")]
            )
        ]
    )

    result = build_governance_hook_config(fake_config)

    hooks = [h for m in result.session_start for h in m.hooks]
    assert len(hooks) == 1
    assert hooks[0].name == AUDIT_HOOK_NAME
    assert hooks[0].command != "echo noop"
    # The real regression coverage for "does the fake get replaced with a
    # working hook, not just a differently-named one" is the subprocess
    # test below (test_real_subprocess_rejects_hostile_workspace_shadowing
    # _openhands) — it actually runs the resulting command and checks
    # observable output, rather than comparing against internal state here.


def test_audit_dir_with_double_quote_falls_back_to_safe_default(monkeypatch) -> None:
    # Regression test for a real finding from Codex review (2026-09-03): an
    # audit dir value containing `"` could break out of the quoted command
    # string and inject arbitrary shell content, since the command is
    # executed with shell=True.
    monkeypatch.setenv("ROY_GOVERNANCE_AUDIT_DIR", '"; echo pwned; "')

    reloaded = importlib.reload(roy_audit_hooks_module)
    try:
        assert reloaded.DEFAULT_AUDIT_DIR == reloaded._DEFAULT_SAFE_AUDIT_DIR
    finally:
        monkeypatch.delenv("ROY_GOVERNANCE_AUDIT_DIR", raising=False)
        importlib.reload(roy_audit_hooks_module)


def test_audit_dir_with_command_substitution_falls_back_to_safe_default(
    monkeypatch,
) -> None:
    # Regression test for the follow-up finding from Codex review
    # (2026-09-03, second pass): the first fix only rejected a literal `"`,
    # but a POSIX shell expands `$(...)` / backticks / `$VAR` *inside*
    # double quotes too — a value like `$(touch pwned)` needs no quote
    # character at all to execute arbitrary commands under shell=True. The
    # allowlist-based validation must reject this even though it contains
    # no `"`.
    monkeypatch.setenv("ROY_GOVERNANCE_AUDIT_DIR", "$(touch /tmp/pwned)")

    reloaded = importlib.reload(roy_audit_hooks_module)
    try:
        assert reloaded.DEFAULT_AUDIT_DIR == reloaded._DEFAULT_SAFE_AUDIT_DIR
    finally:
        monkeypatch.delenv("ROY_GOVERNANCE_AUDIT_DIR", raising=False)
        importlib.reload(roy_audit_hooks_module)


def test_audit_dir_with_plausible_path_is_accepted(monkeypatch, tmp_path) -> None:
    # A normal, legitimate override should not be rejected by the
    # allowlist — only values containing shell-special characters should
    # fall back to the default.
    safe_value = str(tmp_path / "custom audit-dir_2")
    monkeypatch.setenv("ROY_GOVERNANCE_AUDIT_DIR", safe_value)

    reloaded = importlib.reload(roy_audit_hooks_module)
    try:
        assert reloaded.DEFAULT_AUDIT_DIR == safe_value
    finally:
        monkeypatch.delenv("ROY_GOVERNANCE_AUDIT_DIR", raising=False)
        importlib.reload(roy_audit_hooks_module)


# --- roy_audit_hook_writer.main ---------------------------------------------


def test_writes_jsonl_record_for_session_start_event(tmp_path, monkeypatch) -> None:
    event = {
        "event_type": "SessionStart",
        "session_id": "sess-123",
        "working_dir": str(tmp_path),
    }
    monkeypatch.setattr(sys, "stdin", _FakeStdin(json.dumps(event)))

    rc = roy_audit_hook_writer.main(["prog", str(tmp_path)])

    assert rc == 0
    log_file = tmp_path / "session_start.jsonl"
    assert log_file.exists()
    record = json.loads(log_file.read_text(encoding="utf-8").strip())
    assert record["event_type"] == "SessionStart"
    assert record["session_id"] == "sess-123"
    assert record["working_dir"] == str(tmp_path)
    assert "timestamp" in record


def test_appends_multiple_events_as_separate_lines(tmp_path, monkeypatch) -> None:
    for session_id in ("sess-1", "sess-2"):
        event = {"event_type": "SessionStart", "session_id": session_id}
        monkeypatch.setattr(sys, "stdin", _FakeStdin(json.dumps(event)))
        assert roy_audit_hook_writer.main(["prog", str(tmp_path)]) == 0

    lines = (tmp_path / "session_start.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["session_id"] == "sess-1"
    assert json.loads(lines[1])["session_id"] == "sess-2"


def test_malformed_stdin_does_not_crash_and_logs_as_unknown(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setattr(sys, "stdin", _FakeStdin("not json"))

    rc = roy_audit_hook_writer.main(["prog", str(tmp_path)])

    assert rc == 0
    record = json.loads(
        (tmp_path / "unknown.jsonl").read_text(encoding="utf-8").strip()
    )
    assert record["event_type"] == "unknown"


def test_unwritable_audit_dir_does_not_raise(monkeypatch) -> None:
    # A file where a directory is expected makes os.makedirs fail with
    # OSError. Audit logging must fail open — it must never be the reason
    # a conversation can't start.
    monkeypatch.setattr(
        os, "makedirs", lambda *a, **k: (_ for _ in ()).throw(OSError("nope"))
    )
    monkeypatch.setattr(sys, "stdin", _FakeStdin("{}"))

    rc = roy_audit_hook_writer.main(["prog", "/does/not/matter"])

    assert rc == 0


def test_real_subprocess_invocation_via_command_string(tmp_path) -> None:
    # End-to-end: exercises the *actual* command string
    # build_governance_hook_config() produces (subprocess.run with
    # shell=True, event JSON on stdin) rather than hand-building an
    # invocation, so a future change to _audit_command()'s shape is caught
    # here instead of silently testing a stale invocation style.
    command = roy_audit_hooks_module._audit_command().replace(
        roy_audit_hooks_module.DEFAULT_AUDIT_DIR, str(tmp_path)
    )
    event_json = json.dumps({"event_type": "SessionStart", "session_id": "s1"})

    result = subprocess.run(
        command,
        shell=True,
        input=event_json,
        capture_output=True,
        text=True,
        timeout=15,
    )

    assert result.returncode == 0, result.stderr
    assert (tmp_path / "session_start.jsonl").exists()


def test_real_subprocess_rejects_hostile_workspace_shadowing_openhands(
    tmp_path,
) -> None:
    # Regression test for the critical finding: run the *real* command
    # string with cwd set to a workspace that defines its own top-level
    # `openhands` package whose security.roy_audit_hook_writer would, under
    # `python -m`, shadow the real one and get imported+executed instead.
    # With the absolute-path invocation this must not happen — the hostile
    # package must never run.
    hostile_root = tmp_path / "hostile_workspace"
    hostile_pkg = hostile_root / "openhands" / "sdk" / "security"
    hostile_pkg.mkdir(parents=True)
    (hostile_root / "openhands" / "__init__.py").write_text("")
    (hostile_root / "openhands" / "sdk" / "__init__.py").write_text("")
    (hostile_pkg / "__init__.py").write_text("")
    pwned_marker = tmp_path / "pwned.txt"
    (hostile_pkg / "roy_audit_hook_writer.py").write_text(
        f"open(r'{pwned_marker}', 'w').close()\nimport sys; sys.exit(0)\n"
    )

    audit_dir = tmp_path / "audit"
    command = roy_audit_hooks_module._audit_command().replace(
        roy_audit_hooks_module.DEFAULT_AUDIT_DIR, str(audit_dir)
    )
    event_json = json.dumps({"event_type": "SessionStart", "session_id": "s1"})

    result = subprocess.run(
        command,
        shell=True,
        cwd=str(hostile_root),
        input=event_json,
        capture_output=True,
        text=True,
        timeout=15,
    )

    assert result.returncode == 0, result.stderr
    assert not pwned_marker.exists(), (
        "hostile workspace package was imported and executed instead of "
        "the real audit hook writer"
    )
    assert (audit_dir / "session_start.jsonl").exists()
