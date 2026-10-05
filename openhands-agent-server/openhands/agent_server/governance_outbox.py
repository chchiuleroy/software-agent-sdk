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

from openhands.sdk.security.roy_action_binding import (
    ActionBinding,
    ActionBindingMismatchError,
)
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
# GovernancePermanentError docstring). CLAIMED included: a crash between
# claim succeeding and self.run() ever being dispatched for it (or a
# local, non-central failure on a prior redispatch attempt — e.g.
# conversation_already_running from an unrelated race) must not leave the
# record stuck here until the central lease simply expires — see
# EventService._ensure_claim_redispatch_task()'s own docstring for the
# retry mechanism this enables. A record only ever leaves CLAIMED via a
# genuine outcome (EXECUTION_STARTED, or a report/reconciliation call
# that moves it to a terminal state or NEEDS_ATTENTION), so retrying here
# is always either a no-op (already moved on) or a real second attempt.
RETRIABLE_STATES = frozenset(
    {
        OutboxState.PENDING_CREATE,
        OutboxState.CLAIM_INFLIGHT,
        OutboxState.CLAIMED,
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
    # The outcome ("success" / "failure_definite" / "failure_unknown")
    # durably persisted *before* calling report_result(), so a crash
    # between "decided to report X" and "central acknowledged X" resumes
    # as "retry report_result with this exact outcome" — see this
    # module's own docstring's "every external call is preceded by
    # durably persisting intent" invariant. Only meaningful while
    # state == RESULT_PENDING; stale otherwise.
    pending_report_outcome: str | None = None

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


def check_governed_binding_required(
    record: OutboxRecord | None, expected: ActionBinding | None
) -> None:
    """Refuse a ``run()`` that is not tied to the governed approval covering
    the conversation's pending actions.

    ``EventService.run()`` treats ``expected_binding=None`` as a no-op by
    design (personal mode behaves as before), so any agent-server entry
    point that calls ``run()`` without a real binding — ``send_message
    (run=True)``, the goal loop, the ACP-rerun path in ``run()``'s own
    ``finally`` — would otherwise start a conversation that is waiting for
    confirmation without central approval. ``run_and_wait_for_start()``, the
    intended caller, always passes a real ``ActionBinding`` for the exact
    outbox record checked here.

    This check is only reached in team mode while the conversation is
    ``WAITING_FOR_CONFIRMATION``, i.e. while actions are pending. A call is
    let through only when a non-terminal record exists and ``expected``
    names that record's workflow. Everything else is refused:

    * No record: the pending actions are governed by no approval.
      ``maybe_register_governance_approval()`` registers only when exactly
      one action is pending, its create call may not have persisted the
      record yet, and the service may have restarted before registering.
    * Terminal record: the governed action it tracked is finished,
      cancelled or reconciled, so it covers none of the actions pending
      now. A later confirmation round that the hook does not register
      (several pending actions) leaves the old record in place.
    * ``PENDING_CREATE`` (no ``central_approval_id`` minted yet): no caller
      can hold a genuine binding for an approval that does not exist.

    Rejecting the pending actions (``reject_pending_actions()``) does not go
    through ``run()`` and still unblocks the conversation.

    Compares only ``central_approval_id`` and ``action_event_id`` — the two
    fields that identify *which* governed workflow is in flight — rather
    than recomputing the full ``ActionBinding.fingerprint()`` (which also
    folds in ``execution_attempt_id``/``executing_lease_expires_at``,
    populated only after claim). Detecting a stale/replayed claim-level
    fingerprint is ``run_and_wait_for_start()``'s own job; this check's only
    job is "does the caller know this conversation is currently gated on a
    specific central approval at all".

    Raises:
        ActionBindingMismatchError: there is no outbox record, the record is
            terminal, or ``expected`` is missing or names a different
            workflow.
    """
    if record is None:
        raise ActionBindingMismatchError(
            "conversation is waiting for confirmation but no governed "
            "approval is registered for its pending actions; run() cannot "
            "start it directly (reject the pending actions, or wait for an "
            "approval to be created and use run_and_wait_for_start())"
        )
    if record.state in TERMINAL_STATES:
        raise ActionBindingMismatchError(
            "conversation is waiting for confirmation but the governed "
            f"approval on record is already finished ({record.state.name}) "
            "and does not cover its pending actions; run() cannot start it "
            "directly (reject the pending actions, or wait for a new "
            "approval to be created and use run_and_wait_for_start())"
        )
    if (
        expected is None
        or expected.central_approval_id != record.central_approval_id
        or expected.action_event_id != record.action_event_id
    ):
        raise ActionBindingMismatchError(
            "conversation has a governed action pending central approval; "
            "run() must be called through run_and_wait_for_start() with a "
            "matching expected_binding, not directly"
        )
