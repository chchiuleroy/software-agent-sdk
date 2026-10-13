"""Finding the conversations whose governance outbox is parked in NEEDS_ATTENTION.

A record only reaches ``OutboxState.NEEDS_ATTENTION`` after a failure the relay
will not retry, and while it sits there a conversation can no longer be
governed for any other action (see ``ops_notes/design_1_11_needs_attention.md``).
Nothing used to tell an operator it had happened. This module scans the
conversations directory for such records and says which follow-up actions are
safe for each. It only reads: acting on a record is a separate step.

The scan reads ``<conversations_dir>/<conversation id hex>/governance_outbox.json``
straight from disk, so it also finds conversations that are not loaded (the relay
only runs for loaded ones).
"""

from __future__ import annotations

import uuid
from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, Field

from openhands.agent_server.governance_outbox import (
    OUTBOX_FILENAME,
    NeedsAttentionReason,
    OutboxRecord,
    OutboxState,
)


# Far above any real outbox record. A larger file is reported, not parsed.
MAX_OUTBOX_BYTES = 4 * 1024 * 1024

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
    an atomic replace, so a link there is not something this server created."""
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
