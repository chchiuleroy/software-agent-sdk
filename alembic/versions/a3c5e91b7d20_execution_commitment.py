"""execution commitment binding columns

Revision ID: a3c5e91b7d20
Revises: 6bd53bd8f7a5
Create Date: 2026-10-06

Additive and nullable on purpose: a record created before this revision has
no commitment and keeps its old behaviour (nothing is checked at claim or
report time). See ``approvals/digest.py`` for what the columns mean.
"""

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op


revision: str = "a3c5e91b7d20"
down_revision: Union[str, Sequence[str], None] = "6bd53bd8f7a5"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "pending_approval_records",
        sa.Column("execution_commitment", sa.String(64), nullable=True),
    )
    op.add_column(
        "pending_approval_records",
        sa.Column("executed_commitment", sa.String(64), nullable=True),
    )
    op.add_column(
        "pending_approval_records",
        sa.Column("commitment_verified", sa.Boolean(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("pending_approval_records", "commitment_verified")
    op.drop_column("pending_approval_records", "executed_commitment")
    op.drop_column("pending_approval_records", "execution_commitment")
