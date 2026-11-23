"""health alerts: when an engine's (or the backup's) problem started, and when it was notified

Revision ID: 0008
Revises: 0007
Create Date: 2026-11-23
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0008"
down_revision: str | None = "0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TS = sa.DateTime(timezone=True)


def upgrade() -> None:
    op.add_column("engine_status", sa.Column("problem_since", TS))
    op.add_column("engine_status", sa.Column("alerted_at", TS))
    op.execute(
        "UPDATE engine_status SET problem_since = checked_at WHERE status IN ('warning', 'error')"
    )


def downgrade() -> None:
    op.drop_column("engine_status", "alerted_at")
    op.drop_column("engine_status", "problem_since")
