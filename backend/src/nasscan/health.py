"""Health rows in engine_status: each engine (ClamAV, YARA, ...) and the database backup.

A row remembers when its current problem started (``problem_since``), so a notification can
wait out a short blip, such as clamd still loading its signatures after a restart, and
``alerted_at`` marks a problem that has been reported, so its recovery can be too.
"""

from datetime import UTC, datetime

from sqlalchemy import case
from sqlalchemy.dialects.postgresql import insert

from nasscan.db import get_sessionmaker
from nasscan.db.models import EngineStatus

PROBLEMS = ("warning", "error")


def record(name: str, status: str, message: str, **fields) -> None:
    """Upsert one row. Keeps ``problem_since`` while the problem lasts and clears it when the
    row is healthy again."""
    now = datetime.now(UTC)
    values = {
        "name": name,
        "status": status,
        "message": message,
        "version": fields.get("version"),
        "signatures_at": fields.get("signatures_at"),
        "details": fields.get("details"),
        "checked_at": now,
        "problem_since": now if status in PROBLEMS else None,
    }
    stmt = insert(EngineStatus).values(**values)
    update = {k: stmt.excluded[k] for k in values if k not in ("name", "problem_since")}
    # The start of an ongoing problem, or NULL when healthy.
    update["problem_since"] = case(
        (
            stmt.excluded.status.in_(PROBLEMS),
            case(
                (EngineStatus.problem_since.is_(None), stmt.excluded.problem_since),
                else_=EngineStatus.problem_since,
            ),
        ),
        else_=None,
    )
    with get_sessionmaker()() as session:
        session.execute(stmt.on_conflict_do_update(index_elements=["name"], set_=update))
        session.commit()
