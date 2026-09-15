"""Idempotency enforcement for approval-workflow write endpoints.

v11 round-11 High (see ``models.IdempotencyRecord``'s docstring): every
write endpoint needs this, not just ``claim``. Scope is
``(principal, endpoint, resource_id, idempotency_key)``.

Callers are responsible for opening the single DB transaction that wraps
BOTH the idempotency check/write AND the actual state mutation — this
module deliberately takes an already-open ``AsyncSession`` rather than
ever opening its own, so it can never itself be the reason a mutation and
its idempotency record end up split across two transactions (this
project's approval-workflow design review repeatedly caught exactly that
split-transaction bug pattern in earlier iterations — see wiki
``project_openhands_governance_platform.md``, the R2-R4 admin_audit/
user_approval rounds).

Concurrency note: two concurrent requests carrying the *same* idempotency
key can both pass :func:`find_replayed_response` (both see no existing
record yet) and both proceed to attempt the underlying mutation. This
module does not itself prevent that race — the state machine's
conditional UPDATE (``WHERE status = <expected>``) does: only one of the
two mutations can actually apply, and the loser's own attempt to insert
an ``IdempotencyRecord`` afterward fails on the table's unique constraint
(``uq_idempotency_scope``), which the router maps to a replay-lookup
retry rather than a hard error. Idempotency here is about safe *retries*
of one logical request, not a general-purpose distributed lock.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from central_governance_api.models import IdempotencyRecord


class IdempotencyKeyReusedError(Exception):
    """The same ``(principal, endpoint, resource_id, idempotency_key)``
    was already used for a request with a DIFFERENT body — the client is
    reusing an idempotency key across two logically different requests,
    which this service can't safely resolve on its own (replaying the old
    response would silently ignore the new request; running the new
    request would defeat the key's purpose for the old one). Callers
    should map this to HTTP 422 Unprocessable Content.
    """

    def __init__(self, *, idempotency_key: str) -> None:
        self.idempotency_key = idempotency_key
        super().__init__(
            f"idempotency key {idempotency_key!r} was already used for a "
            "request with a different body"
        )


def fingerprint_request(payload: dict[str, Any]) -> str:
    """A stable hash of a request body, used only to detect idempotency-
    key reuse across different bodies — not a security-sensitive digest,
    so no salt: field order sensitivity is enough, nothing here needs to
    resist an adversary who already knows the plaintext body.
    """
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


async def find_replayed_response(
    session: AsyncSession,
    *,
    principal_issuer: str,
    principal_sub: str,
    endpoint: str,
    resource_id: str,
    idempotency_key: str,
    request_fingerprint: str,
) -> dict[str, Any] | None:
    """Returns the previously-stored response to replay verbatim, or
    ``None`` if this is a genuinely new request that must actually run.

    Raises :class:`IdempotencyKeyReusedError` if the key was already used
    for a request with a different body.

    Must be called inside the same transaction the caller will use to
    perform the actual mutation and (on success) call
    :func:`record_response` — this function only reads, so calling it
    alone does not by itself guarantee anything about transaction
    boundaries; that discipline is the router's responsibility.
    """
    existing = await session.scalar(
        select(IdempotencyRecord).where(
            IdempotencyRecord.scope_principal_issuer == principal_issuer,
            IdempotencyRecord.scope_principal_sub == principal_sub,
            IdempotencyRecord.scope_endpoint == endpoint,
            IdempotencyRecord.scope_resource_id == resource_id,
            IdempotencyRecord.idempotency_key == idempotency_key,
        )
    )
    if existing is None:
        return None
    if existing.request_fingerprint != request_fingerprint:
        raise IdempotencyKeyReusedError(idempotency_key=idempotency_key)
    return existing.response_snapshot


async def check_replay_or_raise(
    session: AsyncSession,
    *,
    principal_issuer: str,
    principal_sub: str,
    endpoint: str,
    resource_id: str,
    idempotency_key: str,
    request_fingerprint: str,
    conflict_error: Exception,
) -> dict[str, Any]:
    """Before concluding some failure signal (a unique-constraint
    violation on flush, a conditional UPDATE that matched zero rows) is a
    genuine business conflict, check whether it's actually this exact
    request racing against its own concurrent retry — in which case the
    retry's response should be replayed, not turned into an error.

    Code-review High (found reviewing ``routers/devices.py``, but the
    same shape applies wherever a router does a pre-commit existence/
    uniqueness check before ever reaching :func:`commit_or_replay`):
    two concurrent requests carrying the *same* idempotency key can both
    pass an initial :func:`find_replayed_response` call (neither has
    committed yet) and both attempt the same mutation. Under Postgres's
    default Read Committed isolation, the second one blocks on the first
    at the unique index / row lock, then — once the first commits —
    re-evaluates and fails (unique violation, or its own conditional
    UPDATE matching zero rows because the first request already changed
    the row). Without this check, that failure is indistinguishable from
    a genuinely different conflict (someone else's device_id, an already-
    revoked device from an unrelated request) and gets reported as one —
    exactly backwards for what an idempotency key is supposed to
    guarantee: a safe retry of one's own request should replay success,
    not surface as a conflict.

    Callers whose failure was an exception (e.g. ``IntegrityError`` from
    ``session.flush()``) must roll back before calling this, same as
    :func:`commit_or_replay` does — this function only reads.

    Returns the replay dict if this was that race; raises
    ``conflict_error`` (unmodified) if it wasn't — a genuinely different
    conflict the caller must still report as one.
    """
    replayed = await find_replayed_response(
        session,
        principal_issuer=principal_issuer,
        principal_sub=principal_sub,
        endpoint=endpoint,
        resource_id=resource_id,
        idempotency_key=idempotency_key,
        request_fingerprint=request_fingerprint,
    )
    if replayed is not None:
        return replayed
    raise conflict_error


def record_response(
    session: AsyncSession,
    *,
    principal_issuer: str,
    principal_sub: str,
    endpoint: str,
    resource_id: str,
    idempotency_key: str,
    request_fingerprint: str,
    response: dict[str, Any],
) -> None:
    """Stages the response that was just computed, so a retried request
    with the same key replays it instead of re-running the mutation. Not
    ``async`` — ``session.add()`` is synchronous; the caller's own
    ``session.commit()`` (or the transaction it's inside) is what
    actually persists this alongside the mutation itself. See module
    docstring on why that has to be the same transaction.
    """
    session.add(
        IdempotencyRecord(
            scope_principal_issuer=principal_issuer,
            scope_principal_sub=principal_sub,
            scope_endpoint=endpoint,
            scope_resource_id=resource_id,
            idempotency_key=idempotency_key,
            request_fingerprint=request_fingerprint,
            response_snapshot=response,
        )
    )


async def commit_or_replay(
    session: AsyncSession,
    *,
    principal_issuer: str,
    principal_sub: str,
    endpoint: str,
    resource_id: str,
    idempotency_key: str,
    request_fingerprint: str,
) -> dict[str, Any] | None:
    """Commits the transaction the caller built. If the commit fails
    specifically because a concurrent request already won the race to
    insert this same idempotency key (or, for an endpoint like CREATE
    whose ``resource_id`` is itself part of the request body, the same
    resource_id), rolls back and returns the winner's stored response so
    this request replays it instead of surfacing a raw 500 — this is the
    race-recovery mechanism described above in this module's own
    docstring.

    Moved here (originally a private helper duplicated inline in
    ``routers/approvals.py``) once a second router (``routers/devices.py``)
    needed the exact same commit/replay-on-conflict logic — every write
    endpoint in this service needs this, per the module docstring's
    opening line, so it belongs with the rest of the idempotency
    machinery rather than copied per router.

    Code-review note (carried over from the original version of this
    function): an earlier version of ``routers/approvals.py`` described
    this race-recovery mechanism in ``idempotency.py``'s docstring without
    implementing the catch-and-retry anywhere — every write endpoint just
    called ``session.commit()`` directly, so a genuine concurrent retry
    would have hit ``IdempotencyRecord``'s unique constraint and surfaced
    an unhandled ``IntegrityError`` (500), not a replay. Caught by code
    review, not by any test in this repo: the SAVEPOINT-isolated
    integration tests (see ``tests/conftest.py``) run everything through
    one session and can't produce a genuine concurrent commit, so this
    specific race-recovery branch remains unverified by an automated test.

    Returns the replay dict if a race was caught and resolved this way;
    ``None`` if the commit simply succeeded (the normal, non-racing path)
    and the caller should return the response it already built.
    """
    try:
        await session.commit()
    except IntegrityError:
        await session.rollback()
        replayed = await find_replayed_response(
            session,
            principal_issuer=principal_issuer,
            principal_sub=principal_sub,
            endpoint=endpoint,
            resource_id=resource_id,
            idempotency_key=idempotency_key,
            request_fingerprint=request_fingerprint,
        )
        if replayed is None:
            # Not the race this function exists to handle (e.g. a
            # genuinely different constraint violation) — surface it
            # rather than silently swallowing an unrelated failure.
            raise
        return replayed
    return None
