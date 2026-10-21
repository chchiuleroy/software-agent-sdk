"""Keeps the process's admission snapshot fresh (team mode).

Fetches ``GET /api/v1/me/admitted-items`` from central-governance-api on a timer and
stores the answer in ``openhands.sdk.security.roy_admission``. See that module for the
fail-closed rules; the short version: if this task cannot refresh before the list's
``max_age_seconds`` runs out, no MCP tool, skill or plugin is admitted any more, so a
device cut off from central loses what it was allowed instead of keeping a stale list.

Same structure as ``governance_tool_permissions`` (one refresher per process,
``start()``/``stop()`` reference-counted because more than one ``ConversationService``
can come and go in one process).

This is the foundation only (step C2a). Nothing consults the snapshot yet: the gates
that load an MCP tool, a skill or a plugin come in the next step.
"""

from __future__ import annotations

import asyncio
import math
import threading
import time
from contextlib import suppress
from typing import TypeGuard

from openhands.agent_server.governance_client import (
    GovernanceApiError,
    GovernanceClient,
)
from openhands.sdk.logger import get_logger
from openhands.sdk.security import roy_admission as admission


logger = get_logger(__name__)

# Never poll faster than this, whatever central's max age says.
MIN_REFRESH_INTERVAL_SECONDS = 5.0
# Retry quickly while there is nothing usable yet.
RETRY_INTERVAL_SECONDS = 5.0

_holds = 0
_holds_lock = threading.Lock()
_task: asyncio.Task[None] | None = None


def _is_fingerprint(value: object) -> TypeGuard[str]:
    return isinstance(value, str) and value.startswith("sha256:") and len(value) > 7


def _snapshot_from_answer(answer: dict) -> admission.AdmissionSnapshot:
    if not isinstance(answer, dict):
        raise ValueError("unexpected admitted-items answer from central")
    items = answer.get("items")
    max_age = answer.get("max_age_seconds")
    revision = answer.get("revision")
    if (
        not isinstance(items, list)
        or not isinstance(max_age, int | float)
        or isinstance(max_age, bool)
        # inf (JSON 1e309) would never expire; nan compares false with everything
        or not math.isfinite(max_age)
        or max_age <= 0
        or not isinstance(revision, str)
    ):
        raise ValueError("unexpected admitted-items answer from central")
    mcp_tools: set[str] = set()
    skills: set[str] = set()
    plugins: set[str] = set()
    for item in items:
        if not isinstance(item, dict):
            raise ValueError("unexpected admitted-items answer from central")
        kind = item.get("kind")
        if kind not in ("mcp_server", "skill", "plugin"):
            # A kind this code does not know admits nothing and is not an error: a
            # newer central may use fields this code has never seen.
            continue
        fingerprint = item.get("fingerprint")
        tool_fingerprints = item.get("tool_fingerprints")
        if not _is_fingerprint(fingerprint) or not isinstance(tool_fingerprints, list):
            raise ValueError("unexpected admitted-items answer from central")
        if kind == "mcp_server":
            if not all(_is_fingerprint(f) for f in tool_fingerprints):
                raise ValueError("unexpected admitted-items answer from central")
            mcp_tools.update(tool_fingerprints)
        elif kind == "skill":
            skills.add(fingerprint)
        elif kind == "plugin":
            plugins.add(fingerprint)
    return admission.AdmissionSnapshot(
        mcp_tool_fingerprints=frozenset(mcp_tools),
        skill_fingerprints=frozenset(skills),
        plugin_fingerprints=frozenset(plugins),
        revision=revision,
        max_age_seconds=float(max_age),
        fetched_at=time.monotonic(),
    )


async def refresh_once(client: GovernanceClient) -> bool:
    """Fetch and store one answer. Returns whether it worked. Never raises: a failure
    leaves the previous snapshot to age out on its own."""
    try:
        answer = await client.admitted_items()
        admission.set_snapshot(_snapshot_from_answer(answer))
    except (GovernanceApiError, ValueError) as exc:
        # Class name only: the message can carry response text.
        logger.warning(
            "admission list refresh failed (%s); the current list, if any, "
            "ages out on its own",
            type(exc).__name__,
        )
        return False
    return True


async def _run(client: GovernanceClient) -> None:
    while True:
        ok = await refresh_once(client)
        snapshot = admission.get_snapshot()
        if ok and snapshot is not None:
            delay = max(MIN_REFRESH_INTERVAL_SECONDS, snapshot.max_age_seconds / 3)
        else:
            delay = RETRY_INTERVAL_SECONDS
        await asyncio.sleep(delay)


def start(client: GovernanceClient) -> None:
    """Take a hold, turn enforcement on and start the refresher if it is not already
    running. Call from inside the running event loop."""
    global _holds, _task
    with _holds_lock:
        _holds += 1
        admission.set_enforcing(True)
        if _task is None or _task.done():
            _task = asyncio.get_running_loop().create_task(_run(client))


async def stop() -> None:
    """Give back a hold; with none left, stop refreshing and switch enforcement off
    and forget the snapshot."""
    global _holds, _task
    task = None
    with _holds_lock:
        _holds = max(0, _holds - 1)
        if _holds == 0:
            task, _task = _task, None
            admission.reset()
    if task is not None:
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task
