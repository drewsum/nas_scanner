"""Scan runs: the list, one run's live progress, and starting or cancelling a scan."""

from datetime import UTC, datetime
from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from nasscan.api.deps import DB
from nasscan.db.models import ScanError, ScanRun
from nasscan.scanner.runs import ScanBusyError, enqueue

router = APIRouter(prefix="/api/runs", tags=["runs"])


class RunOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    kind: str
    root: str
    trigger: str
    status: str
    requested_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    updated_at: datetime | None
    resumed: int
    files_seen: int
    files_new: int
    files_changed: int
    files_unchanged: int
    files_removed: int
    files_hashed: int
    bytes_seen: int
    bytes_hashed: int
    errors: int
    files_flagged: int
    detections: int
    current_path: str | None
    last_error: str | None
    message: str | None


class ScanErrorOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    path: str
    message: str
    at: datetime


class RunRequest(BaseModel):
    kind: Literal["incremental", "full", "path"] = "incremental"
    # For kind "path": a folder relative to the scan root.
    path: str = Field(default="", max_length=4096)


def _get(db, run_id: int) -> ScanRun:
    run = db.get(ScanRun, run_id)
    if run is None:
        raise HTTPException(404, "no such scan")
    return run


@router.get("", response_model=list[RunOut])
def list_runs(db: DB, limit: Annotated[int, Query(ge=1, le=500)] = 50) -> list[ScanRun]:
    """Newest first."""
    return list(db.scalars(select(ScanRun).order_by(ScanRun.id.desc()).limit(limit)))


@router.get("/{run_id}", response_model=RunOut)
def read_run(run_id: int, db: DB) -> ScanRun:
    return _get(db, run_id)


@router.get("/{run_id}/errors", response_model=list[ScanErrorOut])
def run_errors(
    run_id: int, db: DB, limit: Annotated[int, Query(ge=1, le=1000)] = 500
) -> list[ScanError]:
    """What the run couldn't read, in order (the first 500 of a run are kept)."""
    _get(db, run_id)
    return list(
        db.scalars(
            select(ScanError).where(ScanError.run_id == run_id).order_by(ScanError.id).limit(limit)
        )
    )


@router.post("", response_model=RunOut, status_code=201)
def start_run(body: RunRequest, db: DB) -> ScanRun:
    """Queue a scan; the scanner picks it up within seconds. 409 while another is active."""
    try:
        return enqueue(db, body.kind, "manual", body.path)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    except ScanBusyError as exc:
        raise HTTPException(409, str(exc)) from exc


@router.post("/{run_id}/cancel", response_model=RunOut)
def cancel_run(run_id: int, db: DB) -> ScanRun:
    """Stop a queued or running scan. A running one stops after its current batch of files."""
    run = _get(db, run_id)
    if run.status not in ("queued", "running"):
        raise HTTPException(409, f"scan is already {run.status}")
    now = datetime.now(UTC)
    run.status, run.finished_at, run.updated_at = "cancelled", now, now
    run.message = "Cancelled."
    db.commit()
    return run
