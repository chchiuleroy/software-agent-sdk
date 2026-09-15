"""SQLAlchemy ORM models for the central governance API's PostgreSQL schema.

Mirrors the tables described in Phase 1 route-wiring design v11 (§4
``PendingApprovalRecord``, §5 transition table, §3 device inventory / audit
/ idempotency sections). This module only defines the schema — the
conditional-update transition logic (§5's table), digest verification, and
endpoint behavior are step 2 of v11 §11's implementation order, not this
skeleton pass.

Every table is Postgres-specific (native ``UUID``/``JSONB``) since this
service has exactly one supported backend, per the design.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


def _uuid_pk() -> Mapped[uuid.UUID]:
    return mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)


# --- v11 §4/§5: the approval workflow's core record --------------------

APPROVAL_STATUSES = (
    "pending",
    "accepted",
    "rejected",
    "executing",
    "applied",
    "failed_definite",
    "failed_unknown",
    "expired",
    "cancelled",
)


class PendingApprovalRecord(Base):
    """v11 §4. One row per HIGH-risk action submitted for approval."""

    __tablename__ = "pending_approval_records"

    id: Mapped[uuid.UUID] = _uuid_pk()

    # v11: client-generated before create, so the requester can compute
    # its envelope digest before the record exists server-side.
    request_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)

    tenant_scope: Mapped[str] = mapped_column(String(64), default="default")

    requester_subject: Mapped[str] = mapped_column(String(512), index=True)
    origin_device_id: Mapped[str] = mapped_column(String(64))

    conversation_id: Mapped[str] = mapped_column(String(128))
    action_event_id: Mapped[str] = mapped_column(String(128))
    tool_call_id: Mapped[str | None] = mapped_column(String(128), nullable=True)

    # v11 digest-envelope fields (execution_binding half)
    action_type: Mapped[str] = mapped_column(String(128))
    tool_name: Mapped[str] = mapped_column(String(128))
    policy_revision: Mapped[str] = mapped_column(String(64))

    # v11 digest-envelope fields (approval_display half) — this is the
    # ONLY view of the action content this service ever stores; canonical
    # payload never leaves the requester's machine (v11 §4).
    action_summary: Mapped[str] = mapped_column(Text)
    action_payload: Mapped[dict] = mapped_column(JSONB)

    # v11 round-11 known gap (已知實作時待辦 #2): salt needs a defined wire
    # field — added here now rather than left implicit. Nullable because
    # not every deployment necessarily needs it (v11: only "if canonical
    # payload may contain low-entropy secrets").
    digest_salt: Mapped[str | None] = mapped_column(String(64), nullable=True)
    action_payload_digest: Mapped[str] = mapped_column(String(128))

    risk_level: Mapped[str] = mapped_column(String(16), default="HIGH")

    status: Mapped[str] = mapped_column(String(32), default="pending", index=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    execution_deadline: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    executing_lease_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    execution_attempt_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )

    decision: Mapped[ApprovalDecision | None] = relationship(
        back_populates="approval_request", uselist=False
    )
    reconciliation_findings: Mapped[list[ReconciliationFinding]] = relationship(
        back_populates="approval_request"
    )

    __table_args__ = (
        CheckConstraint(
            f"status IN {APPROVAL_STATUSES!r}", name="ck_approval_status_valid"
        ),
        Index("ix_approval_requester_status", "requester_subject", "status"),
    )


class ApprovalDecision(Base):
    """v11 §4/§5. Independent, immutable — never overwrites the parent row's
    own status transition, which happens in the same DB transaction as this
    insert (enforced by application code in step 2, not by this schema).
    """

    __tablename__ = "approval_decisions"

    id: Mapped[uuid.UUID] = _uuid_pk()
    approval_request_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("pending_approval_records.id"),
        unique=True,
    )
    decision: Mapped[str] = mapped_column(String(16))  # "accepted" | "rejected"
    decision_actor_subject: Mapped[str] = mapped_column(String(512))
    decided_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    approval_request: Mapped[PendingApprovalRecord] = relationship(
        back_populates="decision"
    )

    __table_args__ = (
        CheckConstraint(
            "decision IN ('accepted', 'rejected')", name="ck_decision_value"
        ),
    )


# --- v11 §5: human reconciliation of failed_unknown / late reports -----

FINDING_TYPES = ("requester_assertion", "admin_verified", "late_report")
FINDING_CONCLUSIONS = ("confirmed_not_executed", "confirmed_executed", "inconclusive")


class ReconciliationFinding(Base):
    """v11 §5. Append-only per request_id — multiple findings may
    accumulate on one approval request; the parent's ``status`` never
    changes because of a finding (a finding is evidence, not a state
    transition).
    """

    __tablename__ = "reconciliation_findings"

    id: Mapped[uuid.UUID] = _uuid_pk()
    approval_request_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("pending_approval_records.id"), index=True
    )
    finding_type: Mapped[str] = mapped_column(String(32))
    conclusion: Mapped[str | None] = mapped_column(String(32), nullable=True)
    note: Mapped[str] = mapped_column(Text, default="")
    verifier_subject: Mapped[str] = mapped_column(String(512))
    evidence: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    approval_request: Mapped[PendingApprovalRecord] = relationship(
        back_populates="reconciliation_findings"
    )

    __table_args__ = (
        CheckConstraint(
            f"finding_type IN {FINDING_TYPES!r}", name="ck_finding_type_valid"
        ),
        CheckConstraint(
            f"conclusion IS NULL OR conclusion IN {FINDING_CONCLUSIONS!r}",
            name="ck_finding_conclusion_valid",
        ),
    )


# --- v11 §2: device inventory (explicitly NOT a security control) ------


class DeviceRegistration(Base):
    """v11 §2/§4. `origin_device_id` inventory — a registration hint, not a
    cryptographic device proof (see v11 §2's honesty note; this table's
    existence does not itself make claim/decide endpoints "device-bound").
    """

    __tablename__ = "device_registrations"

    id: Mapped[uuid.UUID] = _uuid_pk()
    owner_subject: Mapped[str] = mapped_column(String(512), index=True)
    device_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    registered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    revoked_by_subject: Mapped[str | None] = mapped_column(String(512), nullable=True)


class DeviceDenylistEntry(Base):
    """v11 §2: after revocation, (owner_subject, device_id) goes here so the
    same device_id can't just be immediately re-registered.
    """

    __tablename__ = "device_denylist_entries"

    id: Mapped[uuid.UUID] = _uuid_pk()
    owner_subject: Mapped[str] = mapped_column(String(512))
    device_id: Mapped[str] = mapped_column(String(64))
    denied_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    __table_args__ = (
        UniqueConstraint("owner_subject", "device_id", name="uq_denylist_owner_device"),
    )


# --- v11 §3: server-attributed audit (not tamper-evident) --------------


class AdminAuditEvent(Base):
    """v11 §3. `actor`/`occurred_at`/`origin_device_id` are always
    server-derived at write time from the verified Principal and the DB
    transaction clock — callers can never set these fields via request
    body (enforced in step-2 application code, not by this table alone).
    """

    __tablename__ = "admin_audit_events"

    id: Mapped[uuid.UUID] = _uuid_pk()
    event_type: Mapped[str] = mapped_column(String(64), index=True)
    actor_subject: Mapped[str] = mapped_column(String(512), index=True)
    origin_device_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    approval_request_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("pending_approval_records.id"),
        nullable=True,
    )
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    payload: Mapped[dict] = mapped_column(JSONB, default=dict)


# --- v11 §3 (round-11 finding): idempotency across all write endpoints --


class IdempotencyRecord(Base):
    """v11 round-11 High: every write endpoint (not just `claim`) needs an
    idempotency contract. Scope is `(principal, endpoint, resource_id,
    idempotency_key)` per round-11's specific correction — `resource_id`
    is the client-generated `request_id` for the create endpoint (no
    server resource exists yet at that point) or the approval request's
    server id for endpoints that act on an existing record.
    """

    __tablename__ = "idempotency_records"

    id: Mapped[uuid.UUID] = _uuid_pk()
    scope_principal: Mapped[str] = mapped_column(String(512))
    scope_endpoint: Mapped[str] = mapped_column(String(128))
    scope_resource_id: Mapped[str] = mapped_column(String(128))
    idempotency_key: Mapped[str] = mapped_column(String(128))
    request_fingerprint: Mapped[str] = mapped_column(String(128))
    response_snapshot: Mapped[dict] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    __table_args__ = (
        UniqueConstraint(
            "scope_principal",
            "scope_endpoint",
            "scope_resource_id",
            "idempotency_key",
            name="uq_idempotency_scope",
        ),
    )
