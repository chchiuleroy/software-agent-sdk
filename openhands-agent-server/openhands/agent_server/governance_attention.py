"""Finding the conversations whose governance outbox is parked in NEEDS_ATTENTION.

A record only reaches ``OutboxState.NEEDS_ATTENTION`` after a failure the relay
will not retry, and while it sits there a conversation can no longer be
governed for any other action (see ``ops_notes/design_1_11_needs_attention.md``).
Nothing used to tell an operator it had happened. This module scans the
conversations directory for such records and says which follow-up actions are
safe for each, and holds the rules for acting on one (``resolve``): which
precondition must hold, and what each action does to the record.

The scan reads ``<conversations_dir>/<conversation id hex>/governance_outbox.json``
straight from disk, so it also finds conversations that are not loaded (the relay
only runs for loaded ones). Acting needs the loaded ``EventService``; this module
holds only the pure parts, so they can be tested without one.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator

from openhands.agent_server.governance_outbox import (
    OUTBOX_FILENAME,
    NeedsAttentionReason,
    OutboxRecord,
    OutboxState,
)


# Far above any real outbox record. A larger file is reported, not parsed.
MAX_OUTBOX_BYTES = 4 * 1024 * 1024

# Longest operator name accepted (after stripping); see ResolveRequest.operator.
MAX_OPERATOR_CHARS = 64

# Not a NeedsAttentionReason: it is only ever produced by this scan, never stored.
UNREADABLE_OUTBOX = "unreadable_outbox"


class AttentionAction(StrEnum):
    RETRY = "retry"
    ABANDON = "abandon"
    DISMISS = "dismiss"


# The rule behind this table: an action that may already have run is never
# offered ``abandon`` (it would cancel and reject something that executed). Only
# ``claim_failed`` and ``approval_cancelled_or_expired`` are known to have no
# execution attempt. ``retry`` only re-arms a step the relay already knows how to
# repeat with the same idempotency key; it is not offered where central has
# permanently refused the same call, or where central is already past it.
# A record whose reason is missing or unknown (parked before reasons were
# recorded, or by a newer version) may be anything, so it gets ``dismiss`` only.
_ALLOWED_ACTIONS: dict[NeedsAttentionReason, tuple[AttentionAction, ...]] = {
    NeedsAttentionReason.CLAIM_FAILED: (
        AttentionAction.RETRY,
        AttentionAction.ABANDON,
        AttentionAction.DISMISS,
    ),
    # No abandon: central may have claimed (only the reply was lost), so an
    # execution attempt may exist.
    NeedsAttentionReason.CLAIM_TRANSIENT: (
        AttentionAction.RETRY,
        AttentionAction.DISMISS,
    ),
    NeedsAttentionReason.CLAIM_RETRY_FAILED: (AttentionAction.DISMISS,),
    NeedsAttentionReason.APPROVAL_CANCELLED_OR_EXPIRED: (
        AttentionAction.ABANDON,
        AttentionAction.DISMISS,
    ),
    NeedsAttentionReason.REPORT_FAILED: (
        AttentionAction.RETRY,
        AttentionAction.DISMISS,
    ),
    NeedsAttentionReason.RECONCILE_FAILED: (
        AttentionAction.RETRY,
        AttentionAction.DISMISS,
    ),
    NeedsAttentionReason.BINDING_REPORT_FAILED: (
        AttentionAction.RETRY,
        AttentionAction.DISMISS,
    ),
    NeedsAttentionReason.LATE_REPORT_REFUSED: (AttentionAction.DISMISS,),
    NeedsAttentionReason.CENTRAL_STATUS_UNEXPECTED: (AttentionAction.DISMISS,),
}
_FALLBACK_ACTIONS: tuple[AttentionAction, ...] = (AttentionAction.DISMISS,)


def allowed_actions_for(reason: str | None) -> list[str]:
    """The actions an operator may take on a record parked for ``reason``."""
    try:
        known = NeedsAttentionReason(reason)
    except ValueError:  # None, or a reason this version does not know
        return [a.value for a in _FALLBACK_ACTIONS]
    return [a.value for a in _ALLOWED_ACTIONS[known]]


class AttentionItem(BaseModel):
    """One conversation whose outbox needs an operator. Deliberately carries no
    action payload or other record content, only what identifies the problem."""

    conversation_id: str
    reason: str | None = Field(
        description="Why it was parked; null if it was parked before reasons were "
        f"recorded. '{UNREADABLE_OUTBOX}' if the outbox file could not be read."
    )
    last_error_code: str | None
    central_approval_id: str | None
    request_id: str | None = Field(
        description="Identifies this workflow; a later action must quote it so it "
        "cannot be applied to a different one."
    )
    attempt_count: int
    last_attempt_at: str | None
    allowed_actions: list[str]


def _display_id(directory_name: str) -> str:
    """Conversation directories are named by the id's hex; the API shows the
    hyphenated form."""
    try:
        return str(uuid.UUID(hex=directory_name))
    except ValueError:
        return directory_name


def _unreadable(directory_name: str) -> AttentionItem:
    return AttentionItem(
        conversation_id=_display_id(directory_name),
        reason=UNREADABLE_OUTBOX,
        last_error_code=None,
        central_approval_id=None,
        request_id=None,
        attempt_count=0,
        last_attempt_at=None,
        allowed_actions=[],
    )


def _read_record(path: Path) -> OutboxRecord:
    """The record at ``path``; raises if it is unreadable or not a valid record.
    A symlink is refused rather than followed: the file is only ever written by
    an atomic replace, so a link there is not something this server created.

    This is best effort, not a security boundary: the link checks and the read
    are separate path lookups, so a process that can already write to the
    conversations directory (the same trust level as this server) could swap the
    path in between. It catches accidents and stale links, nothing more."""
    if path.is_symlink():
        raise OSError("outbox path is a symlink")
    if path.stat().st_size > MAX_OUTBOX_BYTES:
        raise ValueError("outbox file is too large")
    return OutboxRecord.from_json(path.read_text(encoding="utf-8"))


def scan_needs_attention(conversations_dir: Path) -> list[AttentionItem]:
    """Every conversation under ``conversations_dir`` whose outbox is in
    NEEDS_ATTENTION, plus every one whose outbox cannot be read (those are listed
    with reason ``unreadable_outbox`` and no actions, so a damaged file is never
    silently skipped). Most recent failure first."""
    try:
        entries = sorted(conversations_dir.iterdir())
    except FileNotFoundError:
        return []

    found: list[AttentionItem] = []
    for entry in entries:
        # A linked conversation directory is not followed (see _read_record).
        # A Windows junction is not reported by is_symlink() but is followed
        # just the same, so it is checked separately.
        if entry.is_symlink() or entry.is_junction() or not entry.is_dir():
            continue
        path = entry / OUTBOX_FILENAME
        if not path.exists() and not path.is_symlink():
            continue
        try:
            record = _read_record(path)
        except FileNotFoundError:
            # Present a moment ago, gone now: the conversation's outbox was
            # archived (a normal rename) between the check and the read.
            continue
        except (OSError, ValueError, KeyError, TypeError):
            found.append(_unreadable(entry.name))
            continue
        if record.state != OutboxState.NEEDS_ATTENTION:
            continue
        found.append(
            AttentionItem(
                conversation_id=_display_id(entry.name),
                reason=record.needs_attention_reason,
                last_error_code=record.last_error_code,
                central_approval_id=record.central_approval_id,
                request_id=record.request_id,
                attempt_count=record.attempt_count,
                last_attempt_at=record.last_attempt_at,
                allowed_actions=allowed_actions_for(record.needs_attention_reason),
            )
        )
    found.sort(key=lambda i: (i.last_attempt_at or "", i.conversation_id), reverse=True)
    return found


# ------------------------------- resolving -------------------------------


class ResolveError(Exception):
    """A resolve request that cannot, or must not, be applied. ``error_code`` is
    stable and meant for callers; ``detail`` is for a human."""

    def __init__(
        self,
        error_code: str,
        detail: str,
        *,
        allowed_actions: list[str] | None = None,
    ) -> None:
        super().__init__(detail)
        self.error_code = error_code
        self.detail = detail
        self.allowed_actions = allowed_actions


class ResolveRequest(BaseModel):
    action: AttentionAction
    expected_request_id: str = Field(
        min_length=1,
        max_length=256,
        description="The request_id from the listing. The action is refused if the "
        "record now belongs to a different workflow, so a stale view cannot act "
        "on something it never saw.",
    )
    note: str | None = Field(
        default=None,
        max_length=1000,
        description="Why. Required for dismiss; stored with the record.",
    )
    operator: str = Field(
        max_length=MAX_OPERATOR_CHARS * 4,
        description="Who is acting, as the operator declares it. Not authenticated: "
        "the server only knows the shared session API key, so anyone holding it "
        "can write any name. Stored with the record on abandon and dismiss, and "
        "logged for every action.",
    )

    @field_validator("operator")
    @classmethod
    def _operator_is_a_plain_name(cls, value: str) -> str:
        # Stripped first so padding cannot hide an empty name or push a real one
        # past the limit. Printable only: a name goes into the log and the record,
        # and a line break there could forge a log line.
        value = value.strip()
        if not value or len(value) > MAX_OPERATOR_CHARS:
            raise ValueError(f"operator must be 1 to {MAX_OPERATOR_CHARS} characters")
        if not value.isprintable():
            raise ValueError("operator must not contain control characters")
        return value

    @model_validator(mode="after")
    def _dismiss_needs_a_note(self) -> ResolveRequest:
        if self.note is not None:
            self.note = self.note.strip() or None
        if self.action is AttentionAction.DISMISS and self.note is None:
            raise ValueError("dismiss needs a note saying why")
        return self


class ResolveResponse(BaseModel):
    conversation_id: str
    action: AttentionAction
    request_id: str
    new_state: str
    central_step: Literal["not_applicable", "cancelled", "aborted", "already_terminal"]
    conversation_still_waiting: bool | None = Field(
        description="True if the conversation is still waiting for confirmation of "
        "this very action. The record no longer governs it, so it must be rejected "
        "(or abandoned) before the conversation can move on. None if unknown."
    )


def check_resolvable(
    record: OutboxRecord | None, action: AttentionAction, expected_request_id: str
) -> OutboxRecord:
    """The record, if ``action`` may be applied to it right now. Raised errors
    leave everything untouched, so this is also run again inside the locked
    read-modify-write that applies the action."""
    if record is None:
        raise ResolveError("not_found", "this conversation has no governance outbox")
    if record.state != OutboxState.NEEDS_ATTENTION:
        raise ResolveError(
            "state_changed",
            f"the record is {record.state.value}, no longer needs_attention",
        )
    if record.request_id != expected_request_id:
        raise ResolveError(
            "request_id_mismatch",
            "the record now belongs to a different workflow than the one named",
        )
    allowed = allowed_actions_for(record.needs_attention_reason)
    if action.value not in allowed:
        raise ResolveError(
            "action_not_allowed",
            f"{action.value} is not allowed for reason "
            f"{record.needs_attention_reason!r}",
            allowed_actions=allowed,
        )
    return record


def retry_target(record: OutboxRecord) -> tuple[OutboxState, str | None]:
    """Where a retry sends ``record`` so the relay repeats the step that failed,
    and the report outcome to set first (or None to keep the stored one). The
    relay asserts the fields it needs, so a record without them is refused here
    instead of being parked where the relay would crash on it."""
    reason = record.needs_attention_reason
    if record.central_approval_id is None:
        raise ResolveError(
            "retry_not_possible", "the record has no central approval id"
        )
    if reason in (
        NeedsAttentionReason.CLAIM_FAILED,
        NeedsAttentionReason.CLAIM_TRANSIENT,
    ):
        return OutboxState.CLAIM_INFLIGHT, None
    if record.execution_attempt_id is None:
        raise ResolveError(
            "retry_not_possible", "the record has no execution attempt to report on"
        )
    if reason in (
        NeedsAttentionReason.REPORT_FAILED,
        NeedsAttentionReason.RECONCILE_FAILED,
    ):
        if record.pending_report_outcome is None:
            raise ResolveError(
                "retry_not_possible", "the record has no stored outcome to report"
            )
        return OutboxState.RESULT_PENDING, None
    if reason == NeedsAttentionReason.BINDING_REPORT_FAILED:
        # The tool never ran; the failure that was being reported is definite.
        return OutboxState.RESULT_PENDING, "failure_definite"
    raise ResolveError("retry_not_possible", f"retry does not apply to {reason!r}")


def apply_retry(record: OutboxRecord, expected_request_id: str) -> OutboxRecord:
    """Re-arms the step that failed. Not an attempt, so the retry counters are
    left alone; the stale reason is cleared because the record is no longer
    parked (a new failure sets it again)."""
    check_resolvable(record, AttentionAction.RETRY, expected_request_id)
    state, outcome = retry_target(record)
    if outcome is not None:
        record.pending_report_outcome = outcome
    record.state = state
    record.needs_attention_reason = None
    record.last_error_code = None
    return record


def apply_close(
    record: OutboxRecord,
    action: AttentionAction,
    expected_request_id: str,
    note: str | None,
    operator: str,
) -> OutboxRecord:
    """Ends a parked record: ``abandon`` -> CANCELLED, ``dismiss`` ->
    RESOLVED_MANUALLY. The reason and error code stay as the history of why;
    ``operator`` is recorded as declared (see ``ResolveRequest.operator``)."""
    if action is AttentionAction.RETRY:
        raise ValueError("retry does not close a record")
    check_resolvable(record, action, expected_request_id)
    record.state = (
        OutboxState.CANCELLED
        if action is AttentionAction.ABANDON
        else OutboxState.RESOLVED_MANUALLY
    )
    record.resolution_note = note
    record.resolved_by = operator
    record.resolved_at = datetime.now(UTC).isoformat()
    return record
