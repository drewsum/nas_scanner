"""detections, engine status, scan modes

Revision ID: 0003
Revises: 0002
Create Date: 2026-11-22
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("files", sa.Column("scan_mode", sa.String(16)))
    op.add_column(
        "scan_runs", sa.Column("files_flagged", sa.BigInteger(), nullable=False, server_default="0")
    )
    op.add_column(
        "scan_runs", sa.Column("detections", sa.BigInteger(), nullable=False, server_default="0")
    )
    op.create_table(
        "detections",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column(
            "file_id",
            sa.BigInteger(),
            sa.ForeignKey("files.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("engine", sa.String(32), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("member", sa.Text(), nullable=False, server_default=""),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("details", JSONB()),
        sa.Column("run_id", sa.BigInteger(), sa.ForeignKey("scan_runs.id", ondelete="SET NULL")),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "severity IN ('info', 'suspicious', 'malicious')", name="detections_severity"
        ),
    )
    op.create_index(
        "detections_unique", "detections", ["file_id", "engine", "name", "member"], unique=True
    )
    op.create_index("detections_last_seen", "detections", ["last_seen"])
    op.create_table(
        "engine_status",
        sa.Column("name", sa.String(32), primary_key=True),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("version", sa.Text()),
        sa.Column("signatures_at", sa.DateTime(timezone=True)),
        sa.Column("details", JSONB()),
        sa.Column("checked_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("engine_status")
    op.drop_table("detections")
    op.drop_column("scan_runs", "detections")
    op.drop_column("scan_runs", "files_flagged")
    op.drop_column("files", "scan_mode")
