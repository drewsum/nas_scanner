"""reports and notifications: run version snapshots, alert bookkeeping, stored reports

Revision ID: 0007
Revises: 0006
Create Date: 2026-11-23
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0007"
down_revision: str | None = "0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TS = sa.DateTime(timezone=True)


def upgrade() -> None:
    op.add_column("scan_runs", sa.Column("versions", JSONB()))
    op.add_column("scan_runs", sa.Column("notified_at", TS))
    op.add_column("findings", sa.Column("alerted_at", TS))
    # What came before notifications existed is not news: no burst of old alerts on deploy.
    op.execute("UPDATE scan_runs SET notified_at = now() WHERE status NOT IN ('queued', 'running')")
    op.execute("UPDATE findings SET alerted_at = now()")
    op.create_table(
        "notifications",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("ok", sa.Boolean(), nullable=False),
        sa.Column("error", sa.Text()),
        sa.Column("created_at", TS, nullable=False),
    )
    op.create_index("notifications_created", "notifications", ["created_at"])
    op.create_table(
        "reports",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column(
            "run_id",
            sa.BigInteger(),
            sa.ForeignKey("scan_runs.id", ondelete="SET NULL"),
            unique=True,
        ),
        sa.Column("period_start", TS, nullable=False),
        sa.Column("period_end", TS, nullable=False),
        sa.Column("data", JSONB(), nullable=False),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("notified_at", TS),
    )


def downgrade() -> None:
    op.drop_table("reports")
    op.drop_index("notifications_created", table_name="notifications")
    op.drop_table("notifications")
    op.drop_column("findings", "alerted_at")
    op.drop_column("scan_runs", "notified_at")
    op.drop_column("scan_runs", "versions")
