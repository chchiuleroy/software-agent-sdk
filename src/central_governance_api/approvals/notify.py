"""PostgreSQL LISTEN/NOTIFY plumbing backing the ``/wait`` endpoint (v11
§11 step 3) and the expiry sweep (``approvals/sweep.py``) — the two
places that change ``PendingApprovalRecord.status`` outside a client's own
request/response cycle and therefore need to actively wake up anyone
blocked in ``GET .../wait``, not just rely on that caller's own timeout.

One shared channel (``APPROVAL_STATUS_CHANNEL``), not one channel per
approval id: Postgres channel names would need per-id quoting/sanitizing
to be dynamic, and this deployment's scale (v11/README: "internal
small-scale validation") makes a single channel's fan-out cost to every
listener (one extra JSON-decode-and-compare per unrelated notification)
negligible next to that complexity.

Design note on this whole module: the v11 design record's actual wire
contract for ``/wait`` never survived into this repo (only the wiki's
mention that a "LISTEN/commit 邊界" bug existed and was fixed in round-10
— not what the fix looked like). Everything below is derived directly
from Postgres's own documented NOTIFY semantics, not reconstructed from
lost prose, and is complete on its own terms: NOTIFY delivery is
transaction-scoped by Postgres itself (queued during a transaction,
delivered to listeners only at COMMIT, dropped entirely on ROLLBACK) —
this module's only obligation is to call ``pg_notify()`` inside the same
transaction as the status-changing UPDATE (never in a separate
transaction after the fact) and to register a listener before trusting
any "is it still unchanged" read, which :func:`wait_for_status_change`
does explicitly below.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from typing import TYPE_CHECKING

import asyncpg
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


if TYPE_CHECKING:
    from central_governance_api.models import PendingApprovalRecord


APPROVAL_STATUS_CHANNEL = "cga_approval_status_changed"


async def notify_status_changed(
    session: AsyncSession, *, approval_id: uuid.UUID, status: str
) -> None:
    """Queues a NOTIFY on :data:`APPROVAL_STATUS_CHANNEL` carrying
    ``{"id": ..., "status": ...}``. Must be called inside the SAME
    transaction as the conditional UPDATE that actually changed
    ``approval_id``'s status, before that transaction's ``commit()`` — see
    module docstring. Calling this and then rolling back the transaction
    is always safe (Postgres never delivers it); calling this in a
    transaction that never commits at all (e.g. this project's
    SAVEPOINT-isolated test fixture, ``tests/conftest.py``'s
    ``db_session``) is likewise inert, not an error.

    The payload only ever carries what a listener needs to decide whether
    to bother re-querying — never the action's content — so this function
    has no bearing on the digest/canonical-payload confidentiality
    boundary ``approvals/digest.py`` describes.
    """
    payload = json.dumps({"id": str(approval_id), "status": status})
    await session.execute(
        text("SELECT pg_notify(:channel, :payload)"),
        {"channel": APPROVAL_STATUS_CHANNEL, "payload": payload},
    )


def _asyncpg_dsn(database_url: str) -> str:
    """Translates this service's SQLAlchemy async DSN scheme
    (``postgresql+asyncpg://...``, what ``config.Settings.database_url``
    and ``db.create_engine`` expect) into the plain ``postgresql://...``
    scheme ``asyncpg.connect()`` wants directly. A second, separately
    configured DSN for this one connection would be one more setting to
    keep in sync with the real one for no benefit — this service has
    exactly one supported database (models.py's module docstring), so
    there is only ever one URL to translate.
    """
    prefix = "postgresql+asyncpg://"
    if not database_url.startswith(prefix):
        raise ValueError(
            f"expected a {prefix!r} URL for the dedicated LISTEN "
            f"connection, got: {database_url!r}"
        )
    return "postgresql://" + database_url[len(prefix) :]


async def wait_for_status_change(
    session: AsyncSession,
    record: PendingApprovalRecord,
    *,
    database_url: str,
    known_status: str,
    timeout_seconds: float,
) -> bool:
    """Blocks up to ``timeout_seconds`` for ``record``'s status to differ
    from ``known_status``. Refreshes ``record`` in place from the database
    (via ``session.refresh()``) and returns ``True`` if its status ended
    up different from ``known_status``, ``False`` if the timeout elapsed
    with no change.

    Race-safety: this function opens its own dedicated LISTEN connection
    and registers its notification callback BEFORE performing the read
    that decides whether to wait at all. Any UPDATE-plus-NOTIFY
    transaction (``notify_status_changed``) that commits from that point
    on is guaranteed to be either already reflected in that read (if it
    committed before the read ran) or captured as a queued notification
    this function will see while waiting (if it commits after) — a change
    can be neither missed nor required to retry-because-it-might-be-stale.

    Callers must NOT use a status read taken *before* calling this
    function to decide whether a wait is even necessary — only the read
    this function performs internally, immediately after LISTEN is
    registered, has that guarantee. (The one read a caller CAN safely make
    beforehand, without any LISTEN at all, is "the status I already have
    on hand differs from known_status" — true regardless of staleness,
    since it only asserts a change already happened by that point; see
    ``routers/approvals.py``'s ``wait_for_approval`` for exactly that
    short-circuit.)

    Uses a dedicated ``asyncpg`` connection opened directly against
    ``database_url`` — NOT a connection checked out of this service's
    pooled SQLAlchemy engine. asyncpg's LISTEN/NOTIFY callback API
    (``add_listener``) has no equivalent through SQLAlchemy's async
    engine, and holding a pooled connection idle for up to
    ``timeout_seconds`` per concurrent ``/wait`` caller would compete with
    the pool every other endpoint shares — which is exactly why every
    read of ``record`` below is immediately followed by
    ``session.commit()`` (code-review High: an earlier version of this
    function held ``session`` checked out from the pool for the entire
    wait, on top of the dedicated LISTEN connection, silently defeating
    this paragraph's own reasoning; a bare commit on a session with no
    pending writes is a safe no-op that only ends the transaction and
    returns the connection — see ``db.create_session_factory``'s
    ``expire_on_commit=False``, which is what makes it safe to keep
    reading ``record``'s already-loaded attributes afterward without
    another round trip). Known scope limit, consistent with this
    service's stated "internal small-scale validation" target
    (README.md / config.py): one dedicated LISTEN connection per
    concurrent ``/wait`` call scales to a handful of simultaneously-
    waiting principals, not a large fleet. A fan-out design (one shared,
    reconnecting LISTEN connection broadcasting in-process to many
    waiters) would remove that limit but adds a liveness/reconnect state
    machine this deployment doesn't need yet — not built here (YAGNI).

    That LISTEN connection dying silently mid-wait (network blip,
    Postgres restart) is likewise a known, accepted degradation rather
    than a correctness bug: every notification from that point on is
    missed, but the final read this function always performs before
    giving up (see below) is still authoritative, so the caller only ever
    sees reduced responsiveness (falls back to ``timeout_seconds``
    latency), never a wrong answer. Detecting the death early (asyncpg's
    ``add_termination_listener``) would restore responsiveness but isn't
    needed for correctness — not built here either (YAGNI, same
    reasoning as the fan-out design above).
    """
    dsn = _asyncpg_dsn(database_url)
    conn = await asyncpg.connect(dsn)
    try:
        woken: asyncio.Queue[str] = asyncio.Queue()

        def _on_notify(
            _connection: asyncpg.Connection, _pid: int, _channel: str, payload: str
        ) -> None:
            woken.put_nowait(payload)

        await conn.add_listener(APPROVAL_STATUS_CHANNEL, _on_notify)
        try:

            async def _refresh_and_release() -> bool:
                """Re-reads ``record`` from the database and immediately
                releases the SQLAlchemy pool connection that read checked
                out, rather than holding it for the whole span between
                reads (see this function's own docstring, code-review
                High). Returns whether ``record.status`` now differs from
                ``known_status`` — the only authoritative answer; a
                notification's payload is never trusted for this (see the
                loop below).
                """
                await session.refresh(record)
                await session.commit()
                return record.status != known_status

            # Safe now: any commit from this point on is captured above,
            # so this read (and every re-read below) can never miss a
            # change and never needs to be second-guessed just because it
            # might be stale by the time we act on it.
            if await _refresh_and_release():
                return True

            loop = asyncio.get_running_loop()
            deadline = loop.time() + timeout_seconds
            while True:
                remaining = deadline - loop.time()
                if remaining <= 0:
                    # Code-review Medium: check once more before giving
                    # up — a change that committed (and queued its
                    # NOTIFY) in the last instant before this deadline,
                    # whose callback just hasn't run yet, must still be
                    # reported rather than falsely claiming nothing
                    # happened. This same final read is also what keeps a
                    # silently-dead LISTEN connection correct rather than
                    # merely slow (see docstring).
                    return await _refresh_and_release()
                try:
                    await asyncio.wait_for(woken.get(), timeout=remaining)
                except TimeoutError:
                    return await _refresh_and_release()
                # A notification arrived — but never trust its payload as
                # the answer; it only means "something changed somewhere
                # on this shared channel" (could be a different approval
                # id entirely). Re-read the actual row, the only
                # authoritative source, and loop if this wake was
                # spurious for us specifically.
                if await _refresh_and_release():
                    return True
        finally:
            await conn.remove_listener(APPROVAL_STATUS_CHANNEL, _on_notify)
    finally:
        await conn.close()
