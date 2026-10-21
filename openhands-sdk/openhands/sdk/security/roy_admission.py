"""Process-level admission snapshot for MCP tools, skills and plugins (team mode).

central-governance-api keeps a registry of what may be used (the admission registry,
``OHS_admission_design_gate2.md``). The agent-server fetches this process's answer and
stores it here; the gates that load an MCP tool, a skill or a plugin ask this module
whether its content fingerprint is on the list.

Same shape and the same fail-closed rules as ``roy_tool_permissions`` (read that
module's reasoning: a module-level snapshot because sub-agents run in the same process
and the gates are synchronous):

* enforcement off (the default, and always in personal mode): everything is admitted
  and nothing behaves differently from before;
* enforcement on and nothing fetched yet, or the fetched list is older than the
  ``max_age_seconds`` central sent: NOTHING is admitted;
* a fingerprint nobody listed is not admitted. The three kinds are separate lists: a
  skill's fingerprint never admits an MCP tool.

This module only answers questions. It does not fetch (``governance_admission`` in the
agent-server does) and it does not load or refuse anything (the gates do, a later step).
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass


@dataclass(frozen=True)
class AdmissionSnapshot:
    mcp_tool_fingerprints: frozenset[str]
    skill_fingerprints: frozenset[str]
    plugin_fingerprints: frozenset[str]
    revision: str
    max_age_seconds: float
    fetched_at: float  # time.monotonic()

    def is_fresh(self, now: float) -> bool:
        return now - self.fetched_at <= self.max_age_seconds


_lock = threading.Lock()
_enforcing = False
_snapshot: AdmissionSnapshot | None = None


def set_enforcing(enabled: bool) -> None:
    global _enforcing
    with _lock:
        _enforcing = enabled


def is_enforcing() -> bool:
    return _enforcing


def set_snapshot(snapshot: AdmissionSnapshot | None) -> None:
    global _snapshot
    with _lock:
        _snapshot = snapshot


def get_snapshot() -> AdmissionSnapshot | None:
    return _snapshot


def reset() -> None:
    """Back to the default (not enforcing, nothing fetched). For shutdown and for
    tests."""
    set_enforcing(False)
    set_snapshot(None)


def _usable_snapshot(now: float | None) -> AdmissionSnapshot | None:
    """The current snapshot if there is one and it is still fresh, else None."""
    snapshot = _snapshot
    if snapshot is None:
        return None
    if not snapshot.is_fresh(time.monotonic() if now is None else now):
        return None
    return snapshot


def has_current_list(*, now: float | None = None) -> bool:
    """Whether a decision can be made at all: not enforcing counts as yes (everything
    is admitted); enforcing needs a fresh list."""
    return (not _enforcing) or _usable_snapshot(now) is not None


def is_mcp_tool_admitted(fingerprint: str, *, now: float | None = None) -> bool:
    if not _enforcing:
        return True
    snapshot = _usable_snapshot(now)
    return snapshot is not None and fingerprint in snapshot.mcp_tool_fingerprints


def is_skill_admitted(fingerprint: str, *, now: float | None = None) -> bool:
    if not _enforcing:
        return True
    snapshot = _usable_snapshot(now)
    return snapshot is not None and fingerprint in snapshot.skill_fingerprints


def is_plugin_admitted(fingerprint: str, *, now: float | None = None) -> bool:
    if not _enforcing:
        return True
    snapshot = _usable_snapshot(now)
    return snapshot is not None and fingerprint in snapshot.plugin_fingerprints
