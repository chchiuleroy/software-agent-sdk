"""Per-conversation durable record of a single central-governance-api
approval workflow, for agent-server's ``governance_deployment_mode ==
"team"`` path.

MVP scope:

- **Single pending action only.** One outbox file per conversation,
  overwritten in place. A conversation with zero or more-than-one pending
  action under team mode is out of scope — the governance hook simply does
  not engage (see ``event_service.py``'s detection point), and
  ``ActionCountMismatchError`` (``roy_action_binding.py``) is the
  authoritative backstop if a race ever lets one through anyway.
- **Single agent-server process.** Writes go through an in-process
  ``asyncio.Lock`` (serializes the finally-hook and any relay/retry
  attempt against each other) plus the SDK's existing
  ``openhands.sdk.utils.files.atomic_write_text`` (same-directory temp
  file + fsync + ``os.replace()``, 0o600 permissions — already used
  elsewhere in this codebase for exactly this "never leave a torn file on
  disk" guarantee, not reinvented here). Multi-process coordination (e.g.
  leader election across replicas) is explicitly not handled.
- **No automatic device registration.** ``origin_device_id`` is a
  ``Config`` value the operator sets once (matching the already-registered
  Keycloak service-account clients from the MVP validation), not obtained
  via central-governance-api's ``POST /devices/register`` — deferred.

State machine (see this module's ``OutboxState``): every external call is
preceded by durably persisting *intent* (the exact idempotency key +
request body about to be sent), so a crash between "decided to call X" and
"got X's response" always resumes as "retry X with the same key" rather
than guessing.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from openhands.sdk.utils.files import atomic_write_text


class OutboxState(StrEnum):
    PENDING_CREATE = "pending_create"
    CREATED = "created"
    CLAIM_INFLIGHT = "claim_inflight"
    CLAIMED = "claimed"
    EXECUTION_STARTED = "execution_started"
    RESULT_PENDING = "result_pending"
    RESULT_REPORTED = "result_reported"
    RECONCILIATION_PENDING = "reconciliation_pending"
    RECONCILIATION_REPORTED = "reconciliation_reported"
    REJECTED_LOCALLY = "rejected_locally"
    CANCELLED = "cancelled"
    NEEDS_ATTENTION = "needs_attention"


# States a relay loop should keep retrying from — everything else is either
# a terminal success/cancel or NEEDS_ATTENTION (deliberately excluded: a
# permanent failure must not be auto-retried, see governance_client.py's
# GovernancePermanentError docstring).
RETRIABLE_STATES = frozenset(
    {
        OutboxState.PENDING_CREATE,
        OutboxState.CLAIM_INFLIGHT,
        OutboxState.RESULT_PENDING,
        OutboxState.RECONCILIATION_PENDING,
    }
)

TERMINAL_STATES = frozenset(
    {
        OutboxState.RESULT_REPORTED,
        OutboxState.RECONCILIATION_REPORTED,
        OutboxState.CANCELLED,
    }
)


@dataclass
class OutboxRecord:
    """One conversation's in-flight (or resolved) governance workflow."""

    request_id: str
    conversation_id: str
    action_event_id: str
    tool_call_id: str | None
    tool_name: str
    action_type: str
    policy_revision: str
    action_summary: str
    action_payload: dict[str, Any]
    digest_salt: str | None
    action_payload_digest: str
    execution_commitment: str
    origin_device_id: str
    state: OutboxState = OutboxState.PENDING_CREATE
    central_approval_id: str | None = None
    execution_attempt_id: str | None = None
    executing_lease_expires_at: str | None = None
    attempt_count: int = 0
    last_attempt_at: str | None = None
    last_error_code: str | None = None
    needs_attention_reason: str | None = None

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, sort_keys=True, default=str)

    @classmethod
    def from_json(cls, text: str) -> OutboxRecord:
        raw = json.loads(text)
        raw["state"] = OutboxState(raw["state"])
        return cls(**raw)


def _outbox_path(conversation_dir: Path) -> Path:
    return conversation_dir / "governance_outbox.json"


class GovernanceOutbox:
    """One instance per conversation. All mutation goes through
    ``mutate()``, which serializes access via an in-process lock (see
    module docstring's "single agent-server process" scope note) and
    always persists via atomic write."""

    def __init__(self, conversation_dir: Path) -> None:
        self._path = _outbox_path(conversation_dir)
        self._lock = asyncio.Lock()

    def load(self) -> OutboxRecord | None:
        if not self._path.exists():
            return None
        return OutboxRecord.from_json(self._path.read_text(encoding="utf-8"))

    async def create_record(self, record: OutboxRecord) -> None:
        async with self._lock:
            if self._path.exists():
                raise FileExistsError(
                    f"governance outbox already exists at {self._path}"
                )
            atomic_write_text(self._path, record.to_json())

    async def mutate(self, fn) -> OutboxRecord:
        """``fn(record) -> record`` — read-modify-write under the lock,
        atomic write on the way out. Raises ``FileNotFoundError`` if no
        record exists yet (callers should ``create_record`` first)."""
        async with self._lock:
            record = self.load()
            if record is None:
                raise FileNotFoundError(f"no governance outbox at {self._path}")
            updated = fn(record)
            atomic_write_text(self._path, updated.to_json())
            return updated

    def delete(self) -> None:
        """Only used by tests/cleanup — a resolved (terminal) outbox record
        is left on disk as an audit trail, not deleted in normal operation.
        """
        self._path.unlink(missing_ok=True)

    async def archive_and_clear(self) -> None:
        """Move a terminal record aside (keeping it on disk as an audit
        trail, per ``delete()``'s own convention above) so the active
        ``governance_outbox.json`` path is free for this conversation's
        *next* governed action. Without this, a conversation could only
        ever be governed once in its whole lifetime — every subsequent
        confirmation round would find the old (terminal) record and
        silently skip.

        Callers are responsible for confirming the current record is
        actually terminal before calling this — this method just moves
        whatever is currently there.
        """
        async with self._lock:
            record = self.load()
            if record is None:
                return
            archive_path = self._path.with_name(
                f".governance_outbox.{record.request_id}.archived.json"
            )
            self._path.replace(archive_path)


def record_attempt(
    record: OutboxRecord, *, new_state: OutboxState | None = None
) -> OutboxRecord:
    """Bumps the retry bookkeeping fields; optionally advances state.
    A small pure helper so every call site doesn't repeat this."""
    record.attempt_count += 1
    record.last_attempt_at = datetime.now(UTC).isoformat()
    if new_state is not None:
        record.state = new_state
    return record
