"""Pydantic request/response models for the approval-workflow router.

Kept separate from ``routers/approvals.py`` purely for readability — these
have no behavior of their own beyond field validation.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator


class CreateApprovalRequest(BaseModel):
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


class ApprovalSummary(BaseModel):
    id: uuid.UUID
    request_id: str
    status: str
    created_at: datetime
    expires_at: datetime
    action_payload_digest: str


class DecideRequest(BaseModel):
    decision: Literal["accept", "reject"]


class DecideResponse(BaseModel):
    id: uuid.UUID
    status: str
    decided_at: datetime


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


class ReportResultRequest(BaseModel):
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


class ReconciliationFindingRequest(BaseModel):
    finding_type: Literal["requester_assertion", "admin_verified", "late_report"]
    conclusion: (
        Literal["confirmed_not_executed", "confirmed_executed", "inconclusive"] | None
    ) = None
    note: str = ""
    evidence: dict[str, Any] | None = None


class ReconciliationFindingResponse(BaseModel):
    id: uuid.UUID
    approval_request_id: uuid.UUID
    finding_type: str
    created_at: datetime
