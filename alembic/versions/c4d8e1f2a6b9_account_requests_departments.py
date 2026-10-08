"""account requests, departments, memberships

Revision ID: c4d8e1f2a6b9
Revises: a3c5e91b7d20
Create Date: 2026-10-08

Three new tables only; nothing existing is altered, so downgrade is a plain
drop in reverse dependency order. See
docs/account-requests-departments-design-v1.md.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op


revision: str = "c4d8e1f2a6b9"
down_revision: Union[str, Sequence[str], None] = "a3c5e91b7d20"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "departments",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(128), nullable=False, unique=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("disabled_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_table(
        "account_requests",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("email", sa.String(320), nullable=False),
        sa.Column("display_name", sa.String(128), nullable=False),
        sa.Column("requested_department", sa.String(128), nullable=False),
        sa.Column("reason", sa.String(1000), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("code_hmac", sa.String(64), nullable=True),
        sa.Column("code_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("code_attempts", sa.Integer(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("email_verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("decided_by_issuer", sa.String(512), nullable=True),
        sa.Column("decided_by_sub", sa.String(255), nullable=True),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("decision_reason", sa.String(1000), nullable=True),
        sa.Column(
            "approved_department_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("departments.id"),
            nullable=True,
        ),
        sa.CheckConstraint(
            "status IN ('pending_verification','pending_review','approved',"
            "'rejected','expired')",
            name="ck_account_request_status",
        ),
    )
    op.create_index("ix_account_requests_email", "account_requests", ["email"])
    op.create_index("ix_account_requests_status", "account_requests", ["status"])
    op.create_index(
        "ix_account_requests_created_at", "account_requests", ["created_at"]
    )
    op.create_table(
        "account_memberships",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("email", sa.String(320), nullable=False, unique=True),
        sa.Column(
            "department_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("departments.id"),
            nullable=False,
        ),
        sa.Column(
            "account_request_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("account_requests.id"),
            nullable=False,
            unique=True,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("bound_issuer", sa.String(512), nullable=True),
        sa.Column("bound_sub", sa.String(255), nullable=True),
        sa.Column("bound_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "(bound_issuer IS NULL) = (bound_sub IS NULL) "
            "AND (bound_sub IS NULL) = (bound_at IS NULL)",
            name="ck_membership_binding_all_or_none",
        ),
        sa.UniqueConstraint(
            "bound_issuer", "bound_sub", name="uq_membership_bound_identity"
        ),
    )


def downgrade() -> None:
    op.drop_table("account_memberships")
    op.drop_index("ix_account_requests_created_at", table_name="account_requests")
    op.drop_index("ix_account_requests_status", table_name="account_requests")
    op.drop_index("ix_account_requests_email", table_name="account_requests")
    op.drop_table("account_requests")
    op.drop_table("departments")
