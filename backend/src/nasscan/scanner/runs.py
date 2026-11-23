"""The scan queue: runs are rows in scan_runs. At most one is queued or running at a time (a
partial unique index enforces it), so a scan requested while one is active is refused, or
replaced, rather than piling up."""

from datetime import UTC, datetime
from pathlib import PurePosixPath

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from nasscan.db.models import ACTIVE_RUN_STATUSES, ScanRun


class ScanBusyError(RuntimeError):
    def __init__(self, active: ScanRun) -> None:
        super().__init__(f"scan {active.id} ({active.kind}) is already {active.status}")
        self.active = active


def normalize_root(path: str) -> str:
    """A folder under the scan root as stored: relative, '/'-separated, no '..'."""
    parts = [p for p in PurePosixPath(path.replace("\\", "/")).parts if p not in ("/", ".")]
    if ".." in parts:
        raise ValueError("the folder must be inside the scan root")
    return "/".join(parts)


def active_run(session: Session) -> ScanRun | None:
    return session.scalar(select(ScanRun).where(ScanRun.status.in_(ACTIVE_RUN_STATUSES)))


def enqueue(session: Session, kind: str, trigger: str, root: str = "") -> ScanRun:
    """Queue a scan. A queued (not yet running) incremental scan gives way to a full one,
    which covers it; anything else already active raises ScanBusyError."""
    root = normalize_root(root) if kind == "path" else ""
    if kind == "path" and not root:
        kind = "full"
    active = active_run(session)
    if active is not None:
        if active.status == "queued" and active.kind == "incremental" and kind == "full":
            active.status = "cancelled"
            active.finished_at = datetime.now(UTC)
            active.message = "replaced by a full scan"
            session.flush()
        else:
            raise ScanBusyError(active)
    run = ScanRun(kind=kind, trigger=trigger, root=root, status="queued")
    session.add(run)
    try:
        session.commit()
    except IntegrityError:  # another process queued one in between
        session.rollback()
        raise ScanBusyError(active_run(session)) from None  # type: ignore[arg-type]
    return run


def requeue_interrupted(session: Session) -> list[int]:
    """Runs left "running" by a stopped scanner go back to the queue, to resume."""
    ids = list(
        session.scalars(
            update(ScanRun)
            .where(ScanRun.status == "running")
            .values(status="queued", resumed=ScanRun.resumed + 1)
            .returning(ScanRun.id)
        )
    )
    session.commit()
    return ids


def claim_next(session: Session) -> ScanRun | None:
    """Mark the queued run running and return it."""
    run = session.scalar(
        select(ScanRun).where(ScanRun.status == "queued").with_for_update(skip_locked=True)
    )
    if run is None:
        return None
    now = datetime.now(UTC)
    run.status = "running"
    run.started_at = run.started_at or now
    run.updated_at = now
    session.commit()
    return run
