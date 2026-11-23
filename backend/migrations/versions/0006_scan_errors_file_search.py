"""web UI: errors per scan run, and a trigram index for path search

Revision ID: 0006
Revises: 0005
Create Date: 2026-11-23
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "scan_errors",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column(
            "run_id",
            sa.BigInteger(),
            sa.ForeignKey("scan_runs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("path", sa.Text(), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("scan_errors_run", "scan_errors", ["run_id", "id"])
    # pg_trgm ships with Postgres; the stack's database user owns the database.
    op.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm")
    op.create_index(
        "files_path_trgm",
        "files",
        ["path"],
        postgresql_using="gin",
        postgresql_ops={"path": "gin_trgm_ops"},
    )


def downgrade() -> None:
    op.drop_index("files_path_trgm", table_name="files")
    op.drop_index("scan_errors_run", table_name="scan_errors")
    op.drop_table("scan_errors")
