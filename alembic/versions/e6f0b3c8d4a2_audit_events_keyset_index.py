"""index for keyset paging of admin_audit_events

Revision ID: e6f0b3c8d4a2
Revises: d5e9a2b7c3f1
Create Date: 2026-10-14

One index, nothing else: GET /api/v1/audit-events pages newest-first by
(occurred_at, id), which the existing per-column indexes cannot serve. Downgrade is a
plain drop.
"""

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op


# revision identifiers, used by Alembic.
revision: str = "e6f0b3c8d4a2"
down_revision: Union[str, Sequence[str], None] = "d5e9a2b7c3f1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_index(
        "ix_admin_audit_events_occurred_at_id",
        "admin_audit_events",
        [sa.text("occurred_at DESC"), sa.text("id DESC")],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_admin_audit_events_occurred_at_id", table_name="admin_audit_events"
    )
