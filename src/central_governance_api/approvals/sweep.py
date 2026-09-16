"""Background sweep applying the state machine's ``EXPIRE`` event.

Why this exists: every write endpoint in ``routers/approvals.py``
defensively checks its own relevant deadline column in its conditional
UPDATE's ``WHERE`` clause (e.g. ``decide_approval``'s ``expires_at > now``,
``claim_approval``'s ``execution_deadline > now``, ``report_result``'s
``executing_lease_expires_at > now`` guards) — but those checks only ever
REJECT a stale write; nothing about them proactively flips a row's
``status`` once nobody calls any endpoint on it again. Without this sweep,
a ``pending`` row whose ``expires_at`` has lapsed just sits there forever
still showing ``pending``, and a ``GET .../wait`` caller blocked on it
would only ever learn that via its own timeout, never see it actually
resolve to ``expired``/``failed_unknown``. This sweep is what makes
``state_machine.py``'s ``ApprovalEvent.EXPIRE`` transitions — defined since
step 2, never actually applied by anything until now — really fire, and
(via ``approvals/notify.py``) wakes up anyone in ``/wait`` the moment it
does rather than making them wait out their own timeout too.

Runs as one ``asyncio`` task per app process (started/cancelled in
``main.py``'s lifespan), not a separate worker process or scheduling
dependency — v11/README repeatedly frame this service's current target as
"internal small-scale validation", and a single co-located loop is the
simplest thing that actually closes this gap. A multi-process deployment
of this service would need this promoted to a single-leader scheduler
(e.g. guarded by ``pg_advisory_lock``) so every process's sweep doesn't
race over the same rows — not attempted here (YAGNI): nothing about this
service's current deployment runs more than one process of it, and
running the same conditional-UPDATE-with-``RETURNING`` pattern the routers
already rely on for correctness means even an accidental second sweeper
would just see 0 rows for whatever the first one already claimed, not
double-apply anything — the multi-process gap is a wasted-work concern,
not a correctness one.
"""

from __future__ import annotations

import asyncio
import logging

from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import InstrumentedAttribute

from central_governance_api.approvals.notify import notify_status_changed
from central_governance_api.approvals.state_machine import (
    ApprovalEvent,
    ApprovalStatus,
    next_status,
)
from central_governance_api.clock import now_utc
from central_governance_api.models import PendingApprovalRecord


logger = logging.getLogger(__name__)

# (status a row must currently be in, the deadline column that governs
# it) — directly matches state_machine.ApprovalEvent.EXPIRE's own
# docstring: "this single event stands in for three different deadline
# columns depending on current". `next_status()` remains the single
# source of truth for which status each bucket actually lands on; this
# tuple only says which column to compare against `now`, deliberately not
# a duplicated raw-SQL CASE expression for that mapping.
_EXPIRY_CHECKS: tuple[tuple[ApprovalStatus, InstrumentedAttribute], ...] = (
    (ApprovalStatus.PENDING, PendingApprovalRecord.expires_at),
    (ApprovalStatus.ACCEPTED, PendingApprovalRecord.execution_deadline),
    (ApprovalStatus.EXECUTING, PendingApprovalRecord.executing_lease_expires_at),
)


async def sweep_expired_approvals(session: AsyncSession) -> int:
    """One pass over all three expiry buckets. Returns the number of rows
    changed (for logging and direct testing — see ``tests/test_sweep.py``).

    Each bucket is its own conditional UPDATE + commit rather than one
    combined statement: the three buckets land on different target
    statuses (PENDING/ACCEPTED both go to ``expired``, EXECUTING goes to
    ``failed_unknown`` — see ``state_machine.py``), and each expired row's
    NOTIFY payload needs its own specific new status, not a shared one.
    Same conditional-UPDATE-with-``RETURNING`` shape the write endpoints
    already use (``routers/approvals.py``'s module docstring, step 6) —
    this sweep is just another writer of the same row, racing safely
    against a concurrent client request the exact same way two client
    requests already race against each other.
    """
    now = now_utc()
    changed = 0
    for status, deadline_column in _EXPIRY_CHECKS:
        target = next_status(status, ApprovalEvent.EXPIRE)
        result = await session.execute(
            update(PendingApprovalRecord)
            .where(
                PendingApprovalRecord.status == status.value,
                deadline_column.is_not(None),
                deadline_column <= now,
            )
            .values(status=target.value)
            .returning(PendingApprovalRecord.id)
        )
        expired_ids = [row[0] for row in result.all()]
        for approval_id in expired_ids:
            await notify_status_changed(
                session, approval_id=approval_id, status=target.value
            )
        await session.commit()
        if expired_ids:
            changed += len(expired_ids)
            logger.info(
                "expiry sweep: %d row(s) %s -> %s",
                len(expired_ids),
                status.value,
                target.value,
            )
    return changed


async def run_expiry_sweep_forever(
    session_factory: async_sessionmaker[AsyncSession], *, interval_seconds: float
) -> None:
    """Loops until cancelled (app shutdown, see ``main.py``'s lifespan). A
    failed pass is logged and retried next interval rather than crashing
    the loop — a transient DB hiccup here shouldn't take down the whole
    sweep for the rest of the process's life, and the next pass will just
    catch whatever this one missed (every check is a plain "past its
    deadline right now" comparison, not a delta since last run).
    """
    while True:
        try:
            async with session_factory() as session:
                await sweep_expired_approvals(session)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("expiry sweep pass failed; will retry next interval")
        await asyncio.sleep(interval_seconds)
