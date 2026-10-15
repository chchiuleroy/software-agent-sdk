"""Pydantic request/response models for the approval-workflow router.

Kept separate from ``routers/approvals.py`` purely for readability — these
have no behavior of their own beyond field validation.
"""

from __future__ import annotations

import json
import math
import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator

from central_governance_api.schemas_base import RequestModel


# A keyed SHA-256 (HMAC) in lowercase hex. Opaque to this service; the format is
# pinned only so the column and the audit payload never hold arbitrary text.
COMMITMENT_PATTERN = r"^[0-9a-f]{64}$"


class CreateApprovalRequest(RequestModel):
    """``request_id`` is client-generated (models.py: "client-generated
    before create, so the requester can compute its envelope digest before
    the record exists server-side") and doubles as this create endpoint's
    idempotency ``resource_id`` — see ``routers/approvals.py``.
    ``requester_subject`` is deliberately NOT a field here: it is always
    derived server-side from the authenticated principal, never taken from
    the request body (see ``authorize.authorize_create``'s docstring).
    """

    request_id: str = Field(max_length=64)
    origin_device_id: str = Field(max_length=64)
    conversation_id: str = Field(max_length=128)
    action_event_id: str = Field(max_length=128)
    tool_call_id: str | None = Field(default=None, max_length=128)
    action_type: str = Field(max_length=128)
    tool_name: str = Field(max_length=128)
    policy_revision: str = Field(max_length=64)
    action_summary: str
    action_payload: dict[str, Any]
    digest_salt: str | None = Field(default=None, max_length=64)
    action_payload_digest: str = Field(
        max_length=128,
        description="Client-computed; verified server-side against the "
        "other fields at create time — see approvals/digest.py.",
    )
    execution_commitment: str | None = Field(
        default=None,
        pattern=COMMITMENT_PATTERN,
        description="Optional keyed hash of the action the device will "
        "execute, covered by action_payload_digest — see approvals/digest.py.",
    )


class ApprovalSummary(BaseModel):
    id: uuid.UUID
    request_id: str
    status: str
    created_at: datetime
    expires_at: datetime
    action_payload_digest: str


class PendingApprovalItem(BaseModel):
    """What an approver needs to decide one request — and nothing more.

    Deliberately omitted: ``digest_salt`` (an input to the integrity digest,
    not something a decider needs), ``tool_call_id``/``action_event_id``/
    ``policy_revision`` (requester-side bookkeeping), and every execution
    field (a pending record has none yet).

    ``action_summary``/``action_payload`` are the *display* half of the
    envelope — the only view of the action this service ever stores (see
    models.py). Today the requester sends a placeholder there (gap #11), so
    this endpoint is only as informative as what was submitted.
    """

    id: uuid.UUID
    request_id: str
    requester_issuer: str
    requester_sub: str
    origin_device_id: str
    conversation_id: str
    action_type: str
    tool_name: str
    risk_level: str
    action_summary: str
    action_payload: dict[str, Any]
    action_payload_digest: str
    created_at: datetime
    expires_at: datetime


class PendingApprovalListResponse(BaseModel):
    """Oldest first (closest to expiring first). No offset/cursor on purpose:
    deciding a request removes it from this list, so offset paging would skip
    items; the client simply re-fetches after acting. ``has_more`` says
    whether the oldest ``limit`` items were all there was."""

    items: list[PendingApprovalItem]
    has_more: bool


class DecideRequest(RequestModel):
    decision: Literal["accept", "reject"]


class DecideResponse(BaseModel):
    id: uuid.UUID
    status: str
    decided_at: datetime


class ClaimRequest(RequestModel):
    """Optional body. A record that was created with an
    ``execution_commitment`` is only claimable by presenting the same value;
    a record without one ignores this body (and a bodyless claim keeps working
    for it)."""

    execution_commitment: str | None = Field(default=None, pattern=COMMITMENT_PATTERN)


class ClaimResponse(BaseModel):
    """Echoes ``action_payload_digest`` back so the claiming device — the
    only party that still holds the canonical payload (see digest.py) —
    can perform its own final local check before actually executing.
    """

    id: uuid.UUID
    status: str
    execution_attempt_id: uuid.UUID
    executing_lease_expires_at: datetime
    action_payload_digest: str


class ReportResultRequest(RequestModel):
    """Two shapes in one model (v10/v11: report-result splits into
    pre-claim abort vs. an execution result report specifically because
    a pre-claim abort has no attempt id to attach):

    - Pre-claim abort: ``execution_attempt_id`` and ``outcome`` both
      omitted. Only legal while the record is ACCEPTED (never claimed).
    - Execution result: both fields required together. Only legal while
      EXECUTING, and ``execution_attempt_id`` must match the record's
      current lease (see ``errors.ExecutionAttemptMismatchError``).

    The "both or neither" pairing is enforced here so a router handler
    never has to deal with the nonsensical partial states (an attempt id
    with no outcome, or an outcome with no attempt id to attach it to).
    """

    execution_attempt_id: uuid.UUID | None = None
    outcome: Literal["success", "failure_definite", "failure_unknown"] | None = None
    executed_commitment: str | None = Field(
        default=None,
        pattern=COMMITMENT_PATTERN,
        description="The device attests that, immediately before execution "
        "started, the action it was about to run matched this commitment. "
        "Execution results only; omit when the device could not attest.",
    )

    @model_validator(mode="after")
    def _both_or_neither(self) -> ReportResultRequest:
        has_attempt = self.execution_attempt_id is not None
        has_outcome = self.outcome is not None
        if has_attempt != has_outcome:
            raise ValueError(
                "execution_attempt_id and outcome must both be set "
                "(reporting an execution result) or both omitted "
                "(pre-claim abort) — not one without the other"
            )
        if self.executed_commitment is not None and not has_attempt:
            raise ValueError(
                "executed_commitment only belongs to an execution result, "
                "not a pre-claim abort"
            )
        return self

    @property
    def is_pre_claim_abort(self) -> bool:
        return self.execution_attempt_id is None


class ReportResultResponse(BaseModel):
    id: uuid.UUID
    status: str


class CancelResponse(BaseModel):
    id: uuid.UUID
    status: str


# What one reconciliation finding may carry. The queue endpoint
# (routers/reconciliation.py) shows a note up to the same length and an evidence
# document up to the same size, so nothing a caller is allowed to write is cut when an
# administrator reads it. The size of ``evidence`` that counts is the length of its
# jsonb as text, the way PostgreSQL itself prints it, which is what the read side
# measures: the router asks the database (a number such as 1e-100 is printed in full
# there, so no Python measure can be exact). The check below is only a cheap early
# refusal on a LOWER bound of that length; it never refuses something the database
# would accept.
FINDING_NOTE_MAX_CHARS = 2000
FINDING_EVIDENCE_MAX_CHARS = 8000
MAX_FINDINGS_PER_APPROVAL = 100


def _contains_non_finite(value: Any) -> bool:
    """NaN and the infinities parse from a request (Python's JSON reader accepts
    them) but jsonb cannot hold them."""
    if isinstance(value, float):
        return not math.isfinite(value)
    if isinstance(value, dict):
        return any(_contains_non_finite(v) for v in value.values())
    if isinstance(value, list):
        return any(_contains_non_finite(v) for v in value)
    return False


def _contains_nul(value: Any) -> bool:
    """PostgreSQL's jsonb cannot hold U+0000 in a key or a string."""
    if isinstance(value, str):
        return "\x00" in value
    if isinstance(value, dict):
        return any(_contains_nul(k) or _contains_nul(v) for k, v in value.items())
    if isinstance(value, list):
        return any(_contains_nul(v) for v in value)
    return False


class ReconciliationFindingRequest(RequestModel):
    finding_type: Literal["requester_assertion", "admin_verified", "late_report"]
    conclusion: (
        Literal["confirmed_not_executed", "confirmed_executed", "inconclusive"] | None
    ) = None
    note: str = Field(default="", max_length=FINDING_NOTE_MAX_CHARS)
    evidence: dict[str, Any] | None = None
    execution_attempt_id: uuid.UUID | None = Field(
        default=None,
        description="late_report only, and required there: the execution "
        "attempt this late report is about. Must match the record's own "
        "attempt, and is stored with the finding.",
    )

    @model_validator(mode="after")
    def _evidence_is_bounded(self) -> ReconciliationFindingRequest:
        if "\x00" in self.note:
            raise ValueError("note holds a NUL character, which cannot be stored")
        if self.evidence is not None:
            if _contains_non_finite(self.evidence):
                raise ValueError(
                    "evidence holds NaN or an infinity, which cannot be stored"
                )
            if _contains_nul(self.evidence):
                raise ValueError(
                    "evidence holds a NUL character, which cannot be stored"
                )
            size = len(
                json.dumps(self.evidence, ensure_ascii=False, separators=(", ", ": "))
            )
            if size > FINDING_EVIDENCE_MAX_CHARS:
                raise ValueError(
                    f"evidence is {size} characters as JSON; at most "
                    f"{FINDING_EVIDENCE_MAX_CHARS} are accepted"
                )
        return self

    @model_validator(mode="after")
    def _attempt_id_only_for_late_report(self) -> ReconciliationFindingRequest:
        is_late_report = self.finding_type == "late_report"
        if is_late_report and self.execution_attempt_id is None:
            raise ValueError("a late_report must carry execution_attempt_id")
        if not is_late_report and self.execution_attempt_id is not None:
            raise ValueError(
                "execution_attempt_id only belongs to a late_report, not to "
                f"a {self.finding_type} finding"
            )
        return self


# One approval holds at most this many attention_resolved events (an append-only
# audit table: without a limit its owner's operator could add them without end).
MAX_ATTENTION_EVENTS_PER_APPROVAL = 100


class AttentionResolutionRequest(RequestModel):
    """What an agent-server tells central after its operator dealt with a record that
    needed attention (retry, dismiss, abandon). Evidence of an operator's own account:
    ``operator`` is whatever name the operator typed, never authenticated, and central
    stores it as such. No free text from the operator is sent (the resolution note
    stays on the device)."""

    action: Literal["retry", "dismiss", "abandon"]
    reason: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    operator: str = Field(min_length=1, max_length=64)
    outcome: (
        Literal["confirmed_not_executed", "confirmed_executed", "inconclusive"] | None
    ) = None

    @model_validator(mode="after")
    def _checked(self) -> AttentionResolutionRequest:
        if not self.operator.isprintable() or self.operator != self.operator.strip():
            raise ValueError("operator must be visible characters, no edge spaces")
        if self.outcome is not None and self.action != "dismiss":
            raise ValueError("an outcome only goes with a dismiss")
        return self


class AttentionResolutionResponse(BaseModel):
    id: uuid.UUID
    approval_request_id: uuid.UUID
    event_type: str
    occurred_at: datetime


class ReconciliationFindingResponse(BaseModel):
    id: uuid.UUID
    approval_request_id: uuid.UUID
    finding_type: str
    created_at: datetime


class WaitResponse(BaseModel):
    """``changed=False`` means ``timeout_seconds`` elapsed with the status
    still equal to the caller's ``known_status`` — not an error, just "try
    again". ``changed=True`` means ``status`` is the caller's answer,
    whether that was learned immediately (already different on entry) or
    only after actually blocking on LISTEN/NOTIFY.
    """

    id: uuid.UUID
    status: str
    changed: bool
