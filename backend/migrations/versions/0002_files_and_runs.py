"""file inventory and scan runs

Revision ID: 0002
Revises: 0001
Create Date: 2026-11-22
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "scan_runs",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("root", sa.Text(), nullable=False, server_default=""),
        sa.Column("trigger", sa.String(16), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="queued"),
        sa.Column(
            "requested_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.Column("updated_at", sa.DateTime(timezone=True)),
        sa.Column("resumed", sa.Integer(), nullable=False, server_default="0"),
        *[
            sa.Column(name, sa.BigInteger(), nullable=False, server_default="0")
            for name in (
                "files_seen",
                "files_new",
                "files_changed",
                "files_unchanged",
                "files_removed",
                "files_hashed",
                "bytes_seen",
                "bytes_hashed",
                "errors",
            )
        ],
        sa.Column("current_path", sa.Text()),
        sa.Column("last_error", sa.Text()),
        sa.Column("message", sa.Text()),
        sa.CheckConstraint("kind IN ('incremental', 'full', 'path')", name="scan_runs_kind"),
        sa.CheckConstraint(
            "status IN ('queued', 'running', 'completed', 'failed', 'cancelled')",
            name="scan_runs_status",
        ),
    )
    op.create_index(
        "scan_runs_one_active",
        "scan_runs",
        [sa.text("(true)")],
        unique=True,
        postgresql_where=sa.text("status IN ('queued', 'running')"),
    )

    op.create_table(
        "files",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("path", sa.Text(), nullable=False, unique=True),
        sa.Column("extension", sa.String(32)),
        sa.Column("size", sa.BigInteger(), nullable=False),
        sa.Column("mtime_ns", sa.BigInteger(), nullable=False),
        sa.Column("inode", sa.BigInteger(), nullable=False),
        sa.Column("device", sa.BigInteger(), nullable=False),
        sa.Column("mime", sa.String(255)),
        sa.Column("magic", sa.Text()),
        sa.Column("sha256", sa.String(64)),
        sa.Column("sha1", sa.String(40)),
        sa.Column("md5", sa.String(32)),
        sa.Column("status", sa.String(16), nullable=False, server_default="active"),
        sa.Column("error", sa.Text()),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_scanned", sa.DateTime(timezone=True)),
        sa.Column("removed_at", sa.DateTime(timezone=True)),
        sa.Column(
            "last_seen_run_id",
            sa.BigInteger(),
            sa.ForeignKey("scan_runs.id", ondelete="SET NULL"),
        ),
        sa.CheckConstraint("status IN ('active', 'removed', 'error')", name="files_status_valid"),
    )
    op.create_index("files_sha256", "files", ["sha256"])
    op.create_index("files_status", "files", ["status"])


def downgrade() -> None:
    op.drop_table("files")
    op.drop_table("scan_runs")
