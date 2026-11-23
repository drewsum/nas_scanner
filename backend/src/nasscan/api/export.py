"""Data export, as CSV or JSON downloads: findings, scan runs, and the whole file inventory
(streamed, so a few million files don't sit in memory)."""

import csv
import io
import json
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal

from fastapi import APIRouter
from fastapi.encoders import jsonable_encoder
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import text

from nasscan.db import get_sessionmaker

router = APIRouter(prefix="/api/export", tags=["export"])


@dataclass(frozen=True)
class Dataset:
    label: str
    sql: str


DATASETS = {
    "findings": Dataset(
        "Findings",
        "SELECT f.id, fl.path, fl.status AS file_status, f.sha256, f.verdict, f.score, f.status,"
        " f.resolution, f.note, f.evidence, f.first_seen, f.last_seen, f.opened_at,"
        " f.status_changed_at, f.resolved_at"
        " FROM findings f JOIN files fl ON fl.id = f.file_id ORDER BY f.id",
    ),
    "runs": Dataset(
        "Scan runs",
        "SELECT id, kind, root, trigger, status, requested_at, started_at, finished_at,"
        " files_seen, files_new, files_changed, files_unchanged, files_removed, files_hashed,"
        " bytes_seen, bytes_hashed, files_flagged, detections, errors, message"
        " FROM scan_runs ORDER BY id",
    ),
    "detections": Dataset(
        "Detections",
        "SELECT d.id, fl.path, d.engine, d.name, d.member, d.severity, d.description,"
        " d.first_seen, d.last_seen FROM detections d JOIN files fl ON fl.id = d.file_id"
        " ORDER BY d.id",
    ),
    "files": Dataset(
        "File inventory",
        "SELECT id, path, size, status, mime, sha256, sha1, md5, scan_mode, first_seen,"
        " last_seen, last_scanned, removed_at, error FROM files ORDER BY id",
    ),
    "allowlist": Dataset(
        "Allowlist", "SELECT id, kind, value, note, created_at FROM allowlist ORDER BY id"
    ),
}

Name = Literal["findings", "runs", "detections", "files", "allowlist"]


class DatasetOut(BaseModel):
    name: str
    label: str


@router.get("", response_model=list[DatasetOut])
def list_datasets() -> list[DatasetOut]:
    return [DatasetOut(name=name, label=d.label) for name, d in DATASETS.items()]


def _cell(value: object) -> object:
    if value is None:
        return ""
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict | list):
        return json.dumps(value, separators=(",", ":"))
    return value


def _stream(dataset: Dataset, fmt: str) -> Iterator[str]:
    """Rows straight from a server-side cursor, a chunk at a time."""
    with get_sessionmaker()() as session:
        result = session.execute(
            text(dataset.sql).execution_options(stream_results=True, yield_per=2000)
        )
        columns = list(result.keys())
        if fmt == "csv":
            buf = io.StringIO()
            writer = csv.writer(buf)
            writer.writerow(columns)
            for i, row in enumerate(result):
                writer.writerow([_cell(v) for v in row])
                if i % 2000 == 1999:
                    yield buf.getvalue()
                    buf.seek(0)
                    buf.truncate()
            yield buf.getvalue()
        else:
            yield "["
            for i, row in enumerate(result):
                item = jsonable_encoder(dict(zip(columns, row, strict=True)))
                yield ("," if i else "") + "\n" + json.dumps(item)
            yield "\n]\n"


@router.get("/{name}.{fmt}")
def export(name: Name, fmt: Literal["csv", "json"]) -> StreamingResponse:
    """One dataset as a CSV or JSON download."""
    stamp = datetime.now(UTC).strftime("%Y-%m-%d")
    filename = f"nasscan-{name}-{stamp}.{fmt}"
    media = "text/csv" if fmt == "csv" else "application/json"
    return StreamingResponse(
        _stream(DATASETS[name], fmt),
        media_type=media,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
