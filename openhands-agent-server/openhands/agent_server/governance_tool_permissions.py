"""Keeps the process's department tool permissions fresh (team mode).

Fetches ``GET /api/v1/me/tool-permissions`` from central-governance-api on a
timer and stores the answer in ``openhands.sdk.security.roy_tool_permissions``,
which the analyzer reads on every action. See that module for the fail-closed
rules; the short version: if this task cannot refresh before the list's
``max_age_seconds`` runs out, every tool except the pure built-ins stops being
permitted, so a device cut off from central loses its permissions rather than
keeping stale ones.

One refresher per process. ``start()``/``stop()`` are reference-counted the
same way the sub-agent guard is, because more than one ``ConversationService``
can come and go in one process (the personal-to-team switch builds a new one).
"""

from __future__ import annotations

import asyncio
import threading
import time
from contextlib import suppress

from openhands.agent_server.governance_client import (
    GovernanceApiError,
    GovernanceClient,
)
from openhands.sdk.logger import get_logger
from openhands.sdk.security import roy_tool_permissions as permissions


logger = get_logger(__name__)

# Never poll faster than this, whatever central's max age says.
MIN_REFRESH_INTERVAL_SECONDS = 5.0
# Retry quickly while there is nothing usable yet.
RETRY_INTERVAL_SECONDS = 5.0

_holds = 0
_holds_lock = threading.Lock()
_task: asyncio.Task[None] | None = None


def _snapshot_from_answer(answer: dict) -> permissions.ToolPermissionSnapshot:
    tools = answer.get("tools")
    max_age = answer.get("max_age_seconds")
    revision = answer.get("revision")
    if (
        not isinstance(tools, list)
        or not all(isinstance(t, str) for t in tools)
        or not isinstance(max_age, int | float)
        or isinstance(max_age, bool)
        or max_age <= 0
        or not isinstance(revision, str)
    ):
        raise ValueError("unexpected tool-permissions answer from central")
    name = answer.get("department_name")
    return permissions.ToolPermissionSnapshot(
        tools=frozenset(tools),
        revision=revision,
        department_name=name if isinstance(name, str) else None,
        max_age_seconds=float(max_age),
        fetched_at=time.monotonic(),
    )


async def refresh_once(client: GovernanceClient) -> bool:
    """Fetch and store one answer. Returns whether it worked. Never raises:
    a failure leaves the previous snapshot to age out on its own."""
    try:
        answer = await client.tool_permissions()
        permissions.set_snapshot(_snapshot_from_answer(answer))
    except (GovernanceApiError, ValueError) as exc:
        # Class name only: the message can carry response text.
        logger.warning(
            "tool permission refresh failed (%s); the current list, if any, "
            "ages out on its own",
            type(exc).__name__,
        )
        return False
    return True


async def _run(client: GovernanceClient) -> None:
    while True:
        ok = await refresh_once(client)
        snapshot = permissions.get_snapshot()
        if ok and snapshot is not None:
            delay = max(MIN_REFRESH_INTERVAL_SECONDS, snapshot.max_age_seconds / 3)
        else:
            delay = RETRY_INTERVAL_SECONDS
        await asyncio.sleep(delay)


def start(client: GovernanceClient) -> None:
    """Take a hold, turn enforcement on and start the refresher if it is not
    already running. Call from inside the running event loop."""
    global _holds, _task
    with _holds_lock:
        _holds += 1
        permissions.set_enforcing(True)
        if _task is None or _task.done():
            _task = asyncio.get_running_loop().create_task(_run(client))


async def stop() -> None:
    """Give back a hold; with none left, stop refreshing and switch
    enforcement off and forget the snapshot."""
    global _holds, _task
    task = None
    with _holds_lock:
        _holds = max(0, _holds - 1)
        if _holds == 0:
            task, _task = _task, None
            permissions.reset()
    if task is not None:
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task
