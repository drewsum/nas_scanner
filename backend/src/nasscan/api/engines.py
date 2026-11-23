"""Engine health and what the engines found."""

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Query
from pydantic import BaseModel, ConfigDict
from sqlalchemy import case, select

from nasscan.api.deps import DB
from nasscan.db.models import Detection, EngineStatus, File

router = APIRouter(prefix="/api", tags=["engines"])


class EngineOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    name: str
    status: str
    message: str
    version: str | None
    signatures_at: datetime | None
    details: dict | None
    checked_at: datetime


class DetectionOut(BaseModel):
    id: int
    file_id: int
    path: str
    file_status: str
    engine: str
    name: str
    member: str
    severity: str
    description: str | None
    details: dict | None
    first_seen: datetime
    last_seen: datetime


SEVERITY_ORDER = case(
    {"malicious": 0, "suspicious": 1, "info": 2}, value=Detection.severity, else_=3
)


@router.get("/engines", response_model=list[EngineOut])
def engines(db: DB) -> list[EngineStatus]:
    return list(db.scalars(select(EngineStatus).order_by(EngineStatus.name)))


@router.get("/detections", response_model=list[DetectionOut])
def detections(
    db: DB,
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
    severity: Annotated[str | None, Query(pattern="^(info|suspicious|malicious)$")] = None,
    include_removed: bool = False,
) -> list[DetectionOut]:
    """Most severe first, then newest."""
    stmt = select(Detection, File.path, File.status).join(File, File.id == Detection.file_id)
    if severity:
        stmt = stmt.where(Detection.severity == severity)
    if not include_removed:
        stmt = stmt.where(File.status != "removed")
    rows = db.execute(
        stmt.order_by(SEVERITY_ORDER, Detection.last_seen.desc(), Detection.id.desc()).limit(limit)
    ).all()
    return [
        DetectionOut(
            id=d.id,
            file_id=d.file_id,
            path=path,
            file_status=status,
            engine=d.engine,
            name=d.name,
            member=d.member,
            severity=d.severity,
            description=d.description,
            details=d.details,
            first_seen=d.first_seen,
            last_seen=d.last_seen,
        )
        for d, path, status in rows
    ]
