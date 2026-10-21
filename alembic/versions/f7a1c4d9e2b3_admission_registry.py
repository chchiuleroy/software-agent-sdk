"""admission registry for MCP servers, skills and plugins

Revision ID: f7a1c4d9e2b3
Revises: e6f0b3c8d4a2
Create Date: 2026-10-20

Four new tables; nothing existing is altered, so downgrade is a plain drop. See
OHS_admission_design_gate2.md (step C1).
"""

from typing import Sequence, Union

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op


revision: str = "f7a1c4d9e2b3"
down_revision: Union[str, Sequence[str], None] = "e6f0b3c8d4a2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "admission_items",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("source", sa.String(1024), nullable=False),
        sa.Column("fingerprint", sa.String(80), nullable=False),
        sa.Column(
            "department_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("departments.id"),
            nullable=False,
        ),
        sa.Column("submitted_by_issuer", sa.String(512), nullable=False),
        sa.Column("submitted_by_sub", sa.String(255), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="pending"),
        sa.Column("status_reason", sa.String(1000), nullable=True),
        sa.Column("decided_by_issuer", sa.String(512), nullable=True),
        sa.Column("decided_by_sub", sa.String(255), nullable=True),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.CheckConstraint(
            "kind IN ('mcp_server', 'skill', 'plugin')", name="ck_admission_kind"
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'checking', 'rejected', 'check_failed', "
            "'checked', 'approved', 'revoked')",
            name="ck_admission_status",
        ),
        sa.UniqueConstraint(
            "kind", "department_id", "fingerprint", name="uq_admission_content"
        ),
    )
    op.create_index("ix_admission_items_status", "admission_items", ["status"])
    op.create_index(
        "ix_admission_items_submitter",
        "admission_items",
        ["submitted_by_issuer", "submitted_by_sub", "created_at"],
    )
    op.create_table(
        "admission_item_contents",
        sa.Column(
            "item_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("admission_items.id"),
            primary_key=True,
        ),
        sa.Column("content_type", sa.String(32), nullable=False),
        sa.Column("body", sa.LargeBinary(), nullable=False),
    )
    op.create_table(
        "admission_item_tools",
        sa.Column(
            "item_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("admission_items.id"),
            primary_key=True,
        ),
        sa.Column("tool_name", sa.String(200), primary_key=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("input_schema", postgresql.JSONB(), nullable=False),
        sa.Column("tool_fingerprint", sa.String(80), nullable=False),
    )
    op.create_table(
        "admission_first_uses",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "item_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("admission_items.id"),
            nullable=False,
        ),
        sa.Column("device_issuer", sa.String(512), nullable=False),
        sa.Column("device_sub", sa.String(255), nullable=False),
        sa.Column("fingerprint", sa.String(80), nullable=False),
        sa.Column("result", sa.String(16), nullable=False),
        sa.Column(
            "occurred_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index(
        "ix_admission_first_uses_item_id", "admission_first_uses", ["item_id"]
    )


def downgrade() -> None:
    op.drop_index("ix_admission_first_uses_item_id", table_name="admission_first_uses")
    op.drop_table("admission_first_uses")
    op.drop_table("admission_item_tools")
    op.drop_table("admission_item_contents")
    op.drop_index("ix_admission_items_submitter", table_name="admission_items")
    op.drop_index("ix_admission_items_status", table_name="admission_items")
    op.drop_table("admission_items")
