"""threat intel: feed hashes, cached lookups, provider state

Revision ID: 0004
Revises: 0003
Create Date: 2026-11-23
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "files", sa.Column("intel_priority", sa.SmallInteger(), nullable=False, server_default="0")
    )
    op.add_column("files", sa.Column("intel_checked_at", sa.DateTime(timezone=True)))
    op.create_index("files_md5", "files", ["md5"])
    op.create_index("files_sha1", "files", ["sha1"])
    op.create_index(
        "files_intel_pending",
        "files",
        ["id"],
        postgresql_where=sa.text("intel_checked_at IS NULL AND status = 'active'"),
    )
    op.create_index(
        "files_intel_candidates",
        "files",
        ["sha256"],
        postgresql_where=sa.text("intel_priority > 0"),
    )

    op.create_table(
        "feed_hashes",
        sa.Column("hash", sa.LargeBinary(), primary_key=True),
        sa.Column("feed", sa.String(32), primary_key=True),
        sa.Column("name", sa.Text()),
        sa.Column("added_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("seen_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "hash_lookups",
        sa.Column("provider", sa.String(32), primary_key=True),
        sa.Column("sha256", sa.String(64), primary_key=True),
        sa.Column("verdict", sa.String(16), nullable=False),
        sa.Column("name", sa.Text()),
        sa.Column("description", sa.Text()),
        sa.Column("details", JSONB()),
        sa.Column("looked_up_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("hash_lookups_sha256", "hash_lookups", ["sha256"])
    op.create_table(
        "intel_providers",
        sa.Column("name", sa.String(32), primary_key=True),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("message", sa.Text(), nullable=False, server_default=""),
        sa.Column("last_success", sa.DateTime(timezone=True)),
        sa.Column("last_attempt", sa.DateTime(timezone=True)),
        sa.Column("last_error", sa.Text()),
        sa.Column("last_error_at", sa.DateTime(timezone=True)),
        sa.Column("paused_until", sa.DateTime(timezone=True)),
        sa.Column("day", sa.Date()),
        sa.Column("requests_today", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("daily_budget", sa.Integer()),
        sa.Column("per_minute", sa.Float()),
        sa.Column("entries", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("details", JSONB()),
        sa.Column("updated_at", sa.DateTime(timezone=True)),
    )


def downgrade() -> None:
    op.drop_table("intel_providers")
    op.drop_index("hash_lookups_sha256", table_name="hash_lookups")
    op.drop_table("hash_lookups")
    op.drop_table("feed_hashes")
    for name in ("files_intel_candidates", "files_intel_pending", "files_sha1", "files_md5"):
        op.drop_index(name, table_name="files")
    op.drop_column("files", "intel_checked_at")
    op.drop_column("files", "intel_priority")
