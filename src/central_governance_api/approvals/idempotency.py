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
    principal_subject: str,
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
            IdempotencyRecord.scope_principal == principal_subject,
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


def record_response(
    session: AsyncSession,
    *,
    principal_subject: str,
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
            scope_principal=principal_subject,
            scope_endpoint=endpoint,
            scope_resource_id=resource_id,
            idempotency_key=idempotency_key,
            request_fingerprint=request_fingerprint,
            response_snapshot=response,
        )
    )
