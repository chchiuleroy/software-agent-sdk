"""Process-level department tool permissions (team mode).

central-governance-api holds an allow-list of tools per department
(``docs/department-tool-permissions-design-v1.md`` in that repo). The
agent-server fetches this process's list and stores it here; the analyzer
(``roy_governance.RoyPathPayloadSecurityAnalyzer``) asks :func:`is_permitted`
for every action.

Why a module-level snapshot rather than a per-conversation field: sub-agents
run in the same process as their parent, so they see the same snapshot and
inherit the parent's permissions with no extra code, and the analyzer is
synchronous, so it can only read state that something else already fetched.

Fail-closed rules, all deliberate:

* enforcement off (the default, and always in personal mode): everything is
  permitted and the analyzer behaves exactly as before;
* enforcement on, nothing fetched yet, or the fetched list is older than the
  ``max_age_seconds`` central sent: nothing is permitted except
  :data:`ALWAYS_PERMITTED`;
* a tool nobody listed is not permitted.

``ALWAYS_PERMITTED`` is only the two built-ins with no side effect at all.
``invoke_skill``, ``switch_llm`` and ``vision_inspect`` read files, change the
model or load content, so they need an explicit grant like any other tool.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass


ALWAYS_PERMITTED = frozenset({"finish", "think"})


@dataclass(frozen=True)
class ToolPermissionSnapshot:
    tools: frozenset[str]
    revision: str
    department_name: str | None
    max_age_seconds: float
    fetched_at: float  # time.monotonic()

    def is_fresh(self, now: float) -> bool:
        return now - self.fetched_at <= self.max_age_seconds


_lock = threading.Lock()
_enforcing = False
_snapshot: ToolPermissionSnapshot | None = None


def set_enforcing(enabled: bool) -> None:
    global _enforcing
    with _lock:
        _enforcing = enabled


def is_enforcing() -> bool:
    return _enforcing


def set_snapshot(snapshot: ToolPermissionSnapshot | None) -> None:
    global _snapshot
    with _lock:
        _snapshot = snapshot


def get_snapshot() -> ToolPermissionSnapshot | None:
    return _snapshot


def reset() -> None:
    """Back to the default (not enforcing, nothing fetched). For shutdown and
    for tests."""
    set_enforcing(False)
    set_snapshot(None)


def is_permitted(tool_name: str, *, now: float | None = None) -> bool:
    if not _enforcing:
        return True
    if tool_name in ALWAYS_PERMITTED:
        return True
    snapshot = _snapshot
    if snapshot is None:
        return False
    if not snapshot.is_fresh(time.monotonic() if now is None else now):
        return False
    return tool_name in snapshot.tools


def denial_reason(tool_name: str, *, now: float | None = None) -> str | None:
    """Why ``tool_name`` is not permitted, for the message the agent sees, or
    ``None`` if it is permitted. Names no department and no other tool."""
    if is_permitted(tool_name, now=now):
        return None
    snapshot = _snapshot
    if snapshot is None or not snapshot.is_fresh(
        time.monotonic() if now is None else now
    ):
        return (
            "Refused by governance policy: this agent-server has no current "
            "list of the tools its department may use, so it cannot allow "
            "this tool right now."
        )
    return (
        "Refused by governance policy: this tool is not permitted for this "
        "agent-server's department. Use a permitted tool, or ask an "
        "administrator to grant this one."
    )
