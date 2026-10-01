"""What a central approval shows its approver: a deterministic, bounded,
redacted projection of the pending action, computed locally.

Why not the LLM's ``summary`` or the raw arguments: ``ActionEvent.summary`` is
either an unverified claim (a prompt-injected LLM can describe ``curl | bash``
as "running tests") or, when the LLM left it empty, the SDK's auto-generated
"{tool}: {every raw argument}". Neither belongs in front of an approver, and
the second also sent commands, file contents and tokens to central.

Rules this module keeps:

- The projection is a pure function of the action: same action, same output.
- Output size is bounded by construction, whatever the input size.
- Redaction runs on the text BEFORE it is clipped, so a secret cut in half by
  a limit cannot slip past a pattern that needs the whole token.
- Whole commands/files are never sent: terminal gets a short preview, files get
  path + sizes + a short diff preview, unknown tools get argument NAMES only.
- The LLM's summary is kept but labelled untrusted (``agent_claim``).
"""

from __future__ import annotations

import difflib
import json
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from openhands.agent_server.governance_redaction import REDACTION_VERSION, redact
from openhands.sdk.event import ActionEvent


PROJECTION_VERSION = 1
# Part of the digest envelope: changes whenever what an approver sees changes.
POLICY_REVISION = "agent-server-display-v1"

MAX_COMMAND_PREVIEW_CHARS = 160
MAX_SUMMARY_CHARS = 200
MAX_CLAIM_CHARS = 200
MAX_PREVIEW_LINES = 30
MAX_PREVIEW_LINE_CHARS = 200
MAX_PATCH_FILES = 20
MAX_URL_CHARS = 300
MAX_QUERY_KEYS = 10
# Redaction/diff only ever need the head: everything past this is never shown.
_MAX_INPUT_CHARS = 100_000
_MAX_INPUT_LINES = 500

_ENV_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_PATCH_FILE_HEADER = re.compile(
    r"^\*\*\* (Add|Update|Delete) File: (.+)$", re.MULTILINE
)
_FRAMEWORK_ARG_KEYS = frozenset({"kind", "summary", "security_risk"})


@dataclass(frozen=True)
class DisplayProjection:
    summary: str
    payload: dict[str, Any]


class _Redactions:
    """Collects which rules fired anywhere in one projection."""

    def __init__(self) -> None:
        self._names: set[str] = set()

    def text(self, value: str) -> str:
        result = redact(value[:_MAX_INPUT_CHARS])
        self._names.update(result.applied)
        return result.text

    @property
    def names(self) -> list[str]:
        return sorted(self._names)


def _clip(text: str, limit: int) -> tuple[str, bool]:
    if len(text) <= limit:
        return text, False
    return text[:limit], True


def _one_line(text: str) -> str:
    return text.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "\\n")


def _lines_preview(text: str) -> tuple[list[str], bool]:
    """First MAX_PREVIEW_LINES lines, each clipped; ``truncated`` if anything
    was dropped."""
    lines = text.splitlines()
    truncated = len(lines) > MAX_PREVIEW_LINES
    clipped = []
    for line in lines[:MAX_PREVIEW_LINES]:
        shown, was_clipped = _clip(line, MAX_PREVIEW_LINE_CHARS)
        truncated = truncated or was_clipped
        clipped.append(shown)
    return clipped, truncated


def _text(value: Any) -> str:
    return value if isinstance(value, str) else ""


def _byte_len(value: str) -> int:
    return len(value.encode("utf-8"))


def _program(command: str) -> str:
    """The executable a command starts with, ignoring leading ``VAR=value``
    assignments (their values are not shown at all)."""
    for token in command.split():
        if _ENV_ASSIGNMENT.match(token):
            continue
        return token.replace("\\", "/").rsplit("/", 1)[-1][:64]
    return ""


def _project_terminal(act: Any, red: _Redactions) -> tuple[str, dict[str, Any]]:
    command = _text(getattr(act, "command", None))
    preview, truncated = _clip(_one_line(red.text(command)), MAX_COMMAND_PREVIEW_CHARS)
    payload = {
        "kind": "terminal",
        "program": red.text(_program(command)),
        "command_preview": preview,
        "command_length": len(command),
        "truncated": truncated,
        "is_input": bool(getattr(act, "is_input", False)),
    }
    return f"terminal: {preview}", payload


def _plus_lines(text: str) -> list[str]:
    return [f"+{line}" for line in text.splitlines()[:_MAX_INPUT_LINES]]


def _project_file_editor(act: Any, red: _Redactions) -> tuple[str, dict[str, Any]]:
    command = _text(getattr(act, "command", None))
    path = red.text(_text(getattr(act, "path", None)))
    payload: dict[str, Any] = {"kind": "file_edit", "command": command, "path": path}

    if command == "create":
        content = _text(getattr(act, "file_text", None))
        payload["file_text_bytes"] = _byte_len(content)
        payload["file_text_lines"] = len(content.splitlines())
        preview, truncated = _lines_preview("\n".join(_plus_lines(red.text(content))))
        payload["diff_preview"] = preview
        payload["diff_truncated"] = truncated
    elif command == "str_replace":
        old = _text(getattr(act, "old_str", None))
        new = _text(getattr(act, "new_str", None))
        payload["old_str_bytes"] = _byte_len(old)
        payload["new_str_bytes"] = _byte_len(new)
        diff = difflib.unified_diff(
            red.text(old).splitlines()[:_MAX_INPUT_LINES],
            red.text(new).splitlines()[:_MAX_INPUT_LINES],
            fromfile="old",
            tofile="new",
            lineterm="",
            n=1,
        )
        preview, truncated = _lines_preview("\n".join(diff))
        payload["diff_preview"] = preview
        payload["diff_truncated"] = truncated
    elif command == "insert":
        new = _text(getattr(act, "new_str", None))
        insert_line = getattr(act, "insert_line", None)
        if isinstance(insert_line, int) and not isinstance(insert_line, bool):
            payload["insert_line"] = insert_line
        payload["new_str_bytes"] = _byte_len(new)
        preview, truncated = _lines_preview("\n".join(_plus_lines(red.text(new))))
        payload["diff_preview"] = preview
        payload["diff_truncated"] = truncated

    summary, _ = _clip(f"file_editor {command} {path}", MAX_SUMMARY_CHARS)
    return summary, payload


def _project_apply_patch(act: Any, red: _Redactions) -> tuple[str, dict[str, Any]]:
    patch = _text(getattr(act, "patch", None))[:_MAX_INPUT_CHARS]
    files = [
        {"op": op.lower(), "path": red.text(path.strip())}
        for op, path in _PATCH_FILE_HEADER.findall(patch)
    ]
    body = [line for line in patch.splitlines() if not line.startswith("***")]
    preview, truncated = _lines_preview(red.text(patch))
    payload = {
        "kind": "patch",
        "files": files[:MAX_PATCH_FILES],
        "file_count": len(files),
        "added_lines": sum(1 for line in body if line.startswith("+")),
        "removed_lines": sum(1 for line in body if line.startswith("-")),
        "patch_bytes": _byte_len(_text(getattr(act, "patch", None))),
        "patch_preview": preview,
        "patch_truncated": truncated,
    }
    names = ", ".join(f["path"] for f in files[:3])
    summary, _ = _clip(f"apply_patch: {len(files)} file(s): {names}", MAX_SUMMARY_CHARS)
    return summary, payload


def _project_browser_navigate(act: Any, red: _Redactions) -> tuple[str, dict[str, Any]]:
    raw = _text(getattr(act, "url", None))[:_MAX_INPUT_CHARS]
    try:
        parts = urlsplit(raw)
        host = parts.hostname or ""
        if ":" in host:  # IPv6 literal: urlsplit strips the brackets
            host = f"[{host}]"
        netloc = f"{host}:{parts.port}" if parts.port else host
        query_keys = sorted({p.split("=", 1)[0] for p in parts.query.split("&") if p})
        # Never more than host, port and path — whatever the URL looks like.
        if parts.netloc:
            # http://h/p, or scheme-relative //h/p (userinfo dropped either way)
            base = f"{parts.scheme + ':' if parts.scheme else ''}//{netloc}{parts.path}"
        elif parts.scheme:
            # data:, javascript:, mailto:, ...: the content lives in the
            # "path", so show only how much there is.
            base = f"{parts.scheme}:[{len(raw) - len(parts.scheme) - 1} chars]"
            query_keys = []
        else:
            # Relative ("/cb?x=1") or a bare host ("site.example/a?x=1"):
            # urlsplit already split the query off the path.
            base = parts.path
    except ValueError:
        # Unparseable: show nothing derived from it rather than the raw text.
        base, query_keys = "", []
    url, truncated = _clip(red.text(base), MAX_URL_CHARS)
    payload = {
        "kind": "browser_navigate",
        "url": url,
        "url_truncated": truncated,
        # Names only: query values are where session ids and tokens live.
        "query_keys": [red.text(k) for k in query_keys[:MAX_QUERY_KEYS]],
        "new_tab": bool(getattr(act, "new_tab", False)),
    }
    return f"browser_navigate {url}", payload


def _project_generic(
    action: ActionEvent, red: _Redactions
) -> tuple[str, dict[str, Any]]:
    """Unknown tool (MCP, grep, ...): argument NAMES and total size only.
    A tool we have no projection for must not leak values by default."""
    act = action.action
    args = act.model_dump(mode="json") if act is not None else {}
    names = sorted(k for k in args if k not in _FRAMEWORK_ARG_KEYS)
    payload = {
        "kind": "generic",
        "arg_names": [red.text(n) for n in names],
        "args_size": len(json.dumps(args, default=str)),
    }
    summary, _ = _clip(
        f"{red.text(action.tool_name)} ({len(names)} argument(s))", MAX_SUMMARY_CHARS
    )
    return summary, payload


_PROJECTORS = {
    "terminal": _project_terminal,
    "file_editor": _project_file_editor,
    "apply_patch": _project_apply_patch,
    "browser_navigate": _project_browser_navigate,
}


def _agent_claim(action: ActionEvent, red: _Redactions) -> dict[str, Any] | None:
    summary = action.summary
    if not summary or summary.startswith(f"{action.tool_name}:"):
        # Absent, or the SDK's auto-generated "{tool}: {raw arguments}"
        # fallback — which is not the agent's claim, just the raw payload.
        # Any "<tool>:" prefix is dropped (the SDK always emits
        # "{tool.name}: {json}", but a claim is untrusted anyway, so being
        # conservative costs nothing).
        return None
    text, _ = _clip(_one_line(red.text(summary)), MAX_CLAIM_CHARS)
    return {"text": text, "trusted": False}


def build_display(action: ActionEvent) -> DisplayProjection:
    red = _Redactions()
    projector = _PROJECTORS.get(action.tool_name)
    if projector is not None and action.action is not None:
        summary, payload = projector(action.action, red)
    else:
        summary, payload = _project_generic(action, red)

    summary, _ = _clip(summary, MAX_SUMMARY_CHARS)
    payload = {
        "projection_version": PROJECTION_VERSION,
        "redaction_version": REDACTION_VERSION,
        "tool_name": action.tool_name,
        **payload,
    }
    claim = _agent_claim(action, red)
    if claim is not None:
        payload["agent_claim"] = claim
    # Collected last so it covers every field above, including the claim.
    payload["redactions"] = red.names
    return DisplayProjection(summary=summary, payload=payload)
