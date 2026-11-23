"""verdicts: findings, allowlist, and triggers that queue files for re-evaluation

Revision ID: 0005
Revises: 0004
Create Date: 2026-11-23
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Triggers rather than calls in each writer (crawler, intel matching, lookups, feed drops), so
# nothing that changes a file's evidence can forget to queue it. Updates only count when the
# severity changes: rescans touch last_seen on every detection.
TRIGGERS = """
CREATE FUNCTION nasscan_detection_changed() RETURNS trigger AS $$
BEGIN
    UPDATE files SET verdict_pending = true
    WHERE id = COALESCE(NEW.file_id, OLD.file_id) AND NOT verdict_pending;
    RETURN NULL;
END $$ LANGUAGE plpgsql;

CREATE TRIGGER detections_queue_verdict
AFTER INSERT OR DELETE ON detections
FOR EACH ROW EXECUTE FUNCTION nasscan_detection_changed();

CREATE TRIGGER detections_queue_verdict_on_severity
AFTER UPDATE OF severity ON detections
FOR EACH ROW WHEN (OLD.severity IS DISTINCT FROM NEW.severity)
EXECUTE FUNCTION nasscan_detection_changed();

CREATE FUNCTION nasscan_file_changed() RETURNS trigger AS $$
BEGIN
    NEW.verdict_pending := true;
    RETURN NEW;
END $$ LANGUAGE plpgsql;

CREATE TRIGGER files_queue_verdict
BEFORE UPDATE OF status, sha256 ON files
FOR EACH ROW WHEN (OLD.status IS DISTINCT FROM NEW.status
                   OR OLD.sha256 IS DISTINCT FROM NEW.sha256)
EXECUTE FUNCTION nasscan_file_changed();
"""


def upgrade() -> None:
    op.add_column(
        "files",
        sa.Column("verdict_pending", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.create_index(
        "files_verdict_pending", "files", ["id"], postgresql_where=sa.text("verdict_pending")
    )

    op.create_table(
        "findings",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column(
            "file_id",
            sa.BigInteger(),
            sa.ForeignKey("files.id", ondelete="CASCADE"),
            nullable=False,
            unique=True,
        ),
        sa.Column("sha256", sa.String(64)),
        sa.Column("verdict", sa.String(16), nullable=False),
        sa.Column("score", sa.Integer(), nullable=False),
        sa.Column("evidence", JSONB(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("resolution", sa.String(16)),
        sa.Column("note", sa.Text()),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("opened_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status_changed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("verdict_changed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True)),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("findings_status", "findings", ["status", "verdict"])

    op.create_table(
        "allowlist",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("note", sa.Text()),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )
    op.create_index("allowlist_unique", "allowlist", ["kind", "value"], unique=True)

    op.execute(TRIGGERS)
    # Everything M2 and M3 already found gets its first verdict.
    op.execute(
        "UPDATE files SET verdict_pending = true "
        "WHERE id IN (SELECT DISTINCT file_id FROM detections)"
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS files_queue_verdict ON files")
    op.execute("DROP TRIGGER IF EXISTS detections_queue_verdict_on_severity ON detections")
    op.execute("DROP TRIGGER IF EXISTS detections_queue_verdict ON detections")
    op.execute("DROP FUNCTION IF EXISTS nasscan_file_changed()")
    op.execute("DROP FUNCTION IF EXISTS nasscan_detection_changed()")
    op.drop_table("allowlist")
    op.drop_table("findings")
    op.drop_index("files_verdict_pending", table_name="files")
    op.drop_column("files", "verdict_pending")
