"""SQLAlchemy ORM models for the central governance API's PostgreSQL schema.

Mirrors the tables described in Phase 1 route-wiring design v11 (§4
``PendingApprovalRecord``, §5 transition table, §3 device inventory / audit
/ idempotency sections), now with v11 §11 step 2's conditional-update
logic and RBAC matrix implemented on top (see ``approvals/`` and
``routers/``).

Every table is Postgres-specific (native ``UUID``/``JSONB``) since this
service has exactly one supported backend, per the design.

Identity columns (code-review finding, fixed 2026-09-15): every place
this schema previously stored a single ``*_subject: String(512)`` column
(``Principal.subject``'s ``f"{issuer}#{sub}"`` concatenation) now stores
the issuer and sub as two separate columns instead. ``auth/oidc.py``'s
``Principal.subject`` docstring always said the concatenated string
shouldn't be used for security-relevant comparisons — only ``(issuer,
sub)`` as a tuple is the real identity key per OIDC — and this schema was
the one place that guidance wasn't actually followed. Rewritten directly
into the original migration (``alembic/versions/6bd53bd8f7a5_...``)
rather than layered as a follow-up migration, since nothing has been
deployed against this schema outside disposable local test clusters.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
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


# An OIDC issuer is a URL (can be long); `sub` is an IdP-opaque identifier,
# conventionally short. These two lengths are reused for every identity
# column pair in this module rather than picked ad hoc per table.
_ISSUER_LEN = 512
_SUB_LEN = 255


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

    requester_issuer: Mapped[str] = mapped_column(String(_ISSUER_LEN))
    requester_sub: Mapped[str] = mapped_column(String(_SUB_LEN))
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

    # Execution-commitment binding (see approvals/digest.py). All three are
    # NULL for a record whose device does not send one (nothing is checked
    # for those). ``execution_commitment`` is an opaque keyed hash the
    # device registered at create time, covered by ``action_payload_digest``
    # so it is fixed BEFORE the approver decides; this service cannot
    # recompute it (it never sees the action or the key). ``executed_commitment``
    # is what the device later attested at report-result;
    # ``commitment_matched`` (device-attested: it says the device's claim
    # equals the registered value, not that this service verified an
    # execution) is True/False when both exist and were
    # compared, NULL when the device did not attest.
    execution_commitment: Mapped[str | None] = mapped_column(String(64), nullable=True)
    executed_commitment: Mapped[str | None] = mapped_column(String(64), nullable=True)
    commitment_matched: Mapped[bool | None] = mapped_column(Boolean, nullable=True)

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
        Index(
            "ix_approval_requester_status",
            "requester_issuer",
            "requester_sub",
            "status",
        ),
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
    decision_actor_issuer: Mapped[str] = mapped_column(String(_ISSUER_LEN))
    decision_actor_sub: Mapped[str] = mapped_column(String(_SUB_LEN))
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
    verifier_issuer: Mapped[str] = mapped_column(String(_ISSUER_LEN))
    verifier_sub: Mapped[str] = mapped_column(String(_SUB_LEN))
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
    Since 2026-10-02 an operator can opt in (``config.device_binding_enforced``)
    to having approval CREATE/CLAIM require an active registration owned by
    the calling principal — still a registration check, not a device proof.

    ``device_id`` uniqueness is scoped per-owner (code-review finding,
    fixed 2026-09-15), not global: the original global-unique constraint
    let one principal's registration permanently claim a device_id string
    out of a namespace every other principal shared, and was already
    inconsistent with ``DeviceDenylistEntry``'s own per-owner design (see
    that table's docstring) — this fix makes the two agree rather than
    introducing new policy. It does not by itself bound how many devices
    one principal can register in total; see
    ``config.device_registration_quota`` / ``routers/devices.py`` for
    that half of the code-review finding.
    """

    __tablename__ = "device_registrations"

    id: Mapped[uuid.UUID] = _uuid_pk()
    owner_issuer: Mapped[str] = mapped_column(String(_ISSUER_LEN), index=True)
    owner_sub: Mapped[str] = mapped_column(String(_SUB_LEN), index=True)
    device_id: Mapped[str] = mapped_column(String(64), index=True)
    registered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    revoked_by_issuer: Mapped[str | None] = mapped_column(
        String(_ISSUER_LEN), nullable=True
    )
    revoked_by_sub: Mapped[str | None] = mapped_column(String(_SUB_LEN), nullable=True)

    __table_args__ = (
        UniqueConstraint(
            "owner_issuer",
            "owner_sub",
            "device_id",
            name="uq_device_registration_owner_device",
        ),
    )


class DeviceDenylistEntry(Base):
    """v11 §2: after revocation, (owner, device_id) goes here so the same
    device_id can't just be immediately re-registered by that same owner.
    """

    __tablename__ = "device_denylist_entries"

    id: Mapped[uuid.UUID] = _uuid_pk()
    owner_issuer: Mapped[str] = mapped_column(String(_ISSUER_LEN))
    owner_sub: Mapped[str] = mapped_column(String(_SUB_LEN))
    device_id: Mapped[str] = mapped_column(String(64))
    denied_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    __table_args__ = (
        UniqueConstraint(
            "owner_issuer",
            "owner_sub",
            "device_id",
            name="uq_denylist_owner_device",
        ),
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
    actor_issuer: Mapped[str] = mapped_column(String(_ISSUER_LEN), index=True)
    actor_sub: Mapped[str] = mapped_column(String(_SUB_LEN), index=True)
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
    scope_principal_issuer: Mapped[str] = mapped_column(String(_ISSUER_LEN))
    scope_principal_sub: Mapped[str] = mapped_column(String(_SUB_LEN))
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
            "scope_principal_issuer",
            "scope_principal_sub",
            "scope_endpoint",
            "scope_resource_id",
            "idempotency_key",
            name="uq_idempotency_scope",
        ),
    )


# --- Account requests / departments ---
# See docs/account-requests-departments-design-v1.md.

ACCOUNT_REQUEST_STATUSES = (
    "pending_verification",
    "pending_review",
    "approved",
    "rejected",
    "expired",
)


class Department(Base):
    """A department a superadmin can assign an approved account to.

    Created and disabled only by ``governance.superadmin``. Disabling keeps
    existing memberships intact; it only stops new approvals picking it.
    """

    __tablename__ = "departments"

    id: Mapped[uuid.UUID] = _uuid_pk()
    name: Mapped[str] = mapped_column(String(128), unique=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    disabled_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class AccountRequest(Base):
    """A publicly submitted request for an account.

    The submitter has no account yet, so there is no verified identity on
    create/verify and no ``AdminAuditEvent`` (its actor columns are
    required) — this row is the record. ``email`` is stored lower-cased and
    is unproven until ``email_verified_at`` is set. ``code_hmac`` is an
    HMAC of the emailed verification code, never the code itself.
    """

    __tablename__ = "account_requests"

    id: Mapped[uuid.UUID] = _uuid_pk()
    email: Mapped[str] = mapped_column(String(320), index=True)
    display_name: Mapped[str] = mapped_column(String(128))
    requested_department: Mapped[str] = mapped_column(String(128))
    reason: Mapped[str] = mapped_column(String(1000), default="")
    status: Mapped[str] = mapped_column(String(32), index=True)
    code_hmac: Mapped[str | None] = mapped_column(String(64), nullable=True)
    code_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    code_attempts: Mapped[int] = mapped_column(default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
    email_verified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    decided_by_issuer: Mapped[str | None] = mapped_column(
        String(_ISSUER_LEN), nullable=True
    )
    decided_by_sub: Mapped[str | None] = mapped_column(String(_SUB_LEN), nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    decision_reason: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    approved_department_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("departments.id"), nullable=True
    )

    __table_args__ = (
        CheckConstraint(
            "status IN ('pending_verification','pending_review','approved',"
            "'rejected','expired')",
            name="ck_account_request_status",
        ),
    )


class AccountMembership(Base):
    """An approved account. Created at approval time with the identity
    columns empty; the first login whose token carries this verified EMAIL
    binds ``(bound_issuer, bound_sub)`` exactly once. After that the identity
    key is ``(issuer, sub)`` and the EMAIL no longer grants anything.
    """

    __tablename__ = "account_memberships"

    id: Mapped[uuid.UUID] = _uuid_pk()
    email: Mapped[str] = mapped_column(String(320), unique=True)
    department_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("departments.id")
    )
    account_request_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("account_requests.id"), unique=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    bound_issuer: Mapped[str | None] = mapped_column(String(_ISSUER_LEN), nullable=True)
    bound_sub: Mapped[str | None] = mapped_column(String(_SUB_LEN), nullable=True)
    bound_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    __table_args__ = (
        CheckConstraint(
            "(bound_issuer IS NULL) = (bound_sub IS NULL) "
            "AND (bound_sub IS NULL) = (bound_at IS NULL)",
            name="ck_membership_binding_all_or_none",
        ),
        UniqueConstraint(
            "bound_issuer", "bound_sub", name="uq_membership_bound_identity"
        ),
    )
