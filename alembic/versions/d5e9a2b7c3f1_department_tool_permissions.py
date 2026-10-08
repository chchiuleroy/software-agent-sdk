"""department tool permissions and service-account assignments

Revision ID: d5e9a2b7c3f1
Revises: c4d8e1f2a6b9
Create Date: 2026-10-08

Two new tables only; nothing existing is altered, so downgrade is a plain
drop. See docs/department-tool-permissions-design-v1.md.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op


revision: str = "d5e9a2b7c3f1"
down_revision: Union[str, Sequence[str], None] = "c4d8e1f2a6b9"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "department_tool_permissions",
        sa.Column(
            "department_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("departments.id"),
            primary_key=True,
        ),
        sa.Column("tool_name", sa.String(128), primary_key=True),
        sa.Column("granted_by_issuer", sa.String(512), nullable=False),
        sa.Column("granted_by_sub", sa.String(255), nullable=False),
        sa.Column(
            "granted_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_table(
        "department_principals",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "department_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("departments.id"),
            nullable=False,
        ),
        sa.Column("issuer", sa.String(512), nullable=False),
        sa.Column("sub", sa.String(255), nullable=False),
        sa.Column("assigned_by_issuer", sa.String(512), nullable=False),
        sa.Column("assigned_by_sub", sa.String(255), nullable=False),
        sa.Column(
            "assigned_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.UniqueConstraint("issuer", "sub", name="uq_department_principal_identity"),
    )
    op.create_index(
        "ix_department_principals_department_id",
        "department_principals",
        ["department_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_department_principals_department_id", table_name="department_principals"
    )
    op.drop_table("department_principals")
    op.drop_table("department_tool_permissions")
