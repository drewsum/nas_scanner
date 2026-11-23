"""Findings (one verdict per flagged file), their triage, and the allowlist."""

import re
from datetime import UTC, datetime
from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException, Query, Response
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import case, func, select
from sqlalchemy.exc import IntegrityError

from nasscan import findings as store
from nasscan.api.deps import DB
from nasscan.config import get_settings
from nasscan.db.models import AllowlistEntry, File, Finding

router = APIRouter(prefix="/api", tags=["findings"])

SHA256 = re.compile(r"^[0-9a-f]{64}$")
# Groups for the list filter; "active" is what still needs attention or tracking.
STATUS_GROUPS = {
    "active": ("open", "acknowledged"),
    "open": ("open",),
    "acknowledged": ("acknowledged",),
    "ignored": ("ignored",),
    "allowlisted": ("allowlisted",),
    "resolved": ("resolved",),
}


class FindingOut(BaseModel):
    id: int
    file_id: int
    path: str
    file_status: str
    size: int
    mime: str | None
    sha256: str | None
    verdict: str
    score: int
    status: str
    resolution: str | None
    note: str | None
    evidence: list[dict]
    first_seen: datetime
    last_seen: datetime
    opened_at: datetime
    status_changed_at: datetime
    resolved_at: datetime | None


class SummaryOut(BaseModel):
    # status -> verdict -> count
    counts: dict[str, dict[str, int]]
    pending: int  # files waiting for a verdict


class StatusRequest(BaseModel):
    status: Literal["open", "acknowledged", "ignored"]
    note: str | None = Field(default=None, max_length=2000)


class AllowlistOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    kind: str
    value: str
    note: str | None
    created_at: datetime


class AllowlistRequest(BaseModel):
    kind: Literal["sha256", "path"]
    value: str = Field(min_length=1, max_length=1024)
    note: str | None = Field(default=None, max_length=2000)

    @field_validator("value")
    @classmethod
    def _clean(cls, value: str) -> str:
        return value.strip()


VERDICT_ORDER = case({"malicious": 0, "suspicious": 1}, value=Finding.verdict, else_=2)


def _out(finding: Finding, file: File) -> FindingOut:
    return FindingOut(
        id=finding.id,
        file_id=file.id,
        path=file.path,
        file_status=file.status,
        size=file.size,
        mime=file.mime,
        sha256=finding.sha256,
        verdict=finding.verdict,
        score=finding.score,
        status=finding.status,
        resolution=finding.resolution,
        note=finding.note,
        evidence=finding.evidence,
        first_seen=finding.first_seen,
        last_seen=finding.last_seen,
        opened_at=finding.opened_at,
        status_changed_at=finding.status_changed_at,
        resolved_at=finding.resolved_at,
    )


@router.get("/findings", response_model=list[FindingOut])
def list_findings(
    db: DB,
    status: Annotated[
        Literal["active", "open", "acknowledged", "ignored", "allowlisted", "resolved", "all"],
        Query(),
    ] = "active",
    verdict: Annotated[Literal["suspicious", "malicious"] | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=1000)] = 200,
) -> list[FindingOut]:
    """Malicious first, then highest score, then newest."""
    stmt = select(Finding, File).join(File, File.id == Finding.file_id)
    if status != "all":
        stmt = stmt.where(Finding.status.in_(STATUS_GROUPS[status]))
    if verdict:
        stmt = stmt.where(Finding.verdict == verdict)
    rows = db.execute(
        stmt.order_by(
            VERDICT_ORDER, Finding.score.desc(), Finding.opened_at.desc(), Finding.id.desc()
        ).limit(limit)
    ).all()
    return [_out(f, file) for f, file in rows]


@router.get("/findings/summary", response_model=SummaryOut)
def summary(db: DB) -> SummaryOut:
    counts: dict[str, dict[str, int]] = {}
    for status, verdict, n in db.execute(
        select(Finding.status, Finding.verdict, func.count()).group_by(
            Finding.status, Finding.verdict
        )
    ):
        counts.setdefault(status, {})[verdict] = n
    pending = db.scalar(select(func.count()).where(File.verdict_pending)) or 0
    return SummaryOut(counts=counts, pending=pending)


def _get(db, finding_id: int) -> tuple[Finding, File]:
    row = db.execute(
        select(Finding, File).join(File, File.id == Finding.file_id).where(Finding.id == finding_id)
    ).first()
    if row is None:
        raise HTTPException(404, "no such finding")
    return row[0], row[1]


@router.get("/findings/{finding_id}", response_model=FindingOut)
def read_finding(finding_id: int, db: DB) -> FindingOut:
    return _out(*_get(db, finding_id))


@router.post("/findings/{finding_id}/status", response_model=FindingOut)
def set_status(finding_id: int, body: StatusRequest, db: DB) -> FindingOut:
    """Acknowledge (keep listed, no more alerts), ignore (a false positive for this content),
    or reopen."""
    finding, file = _get(db, finding_id)
    try:
        store.set_status(finding, body.status, body.note, datetime.now(UTC))
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    db.commit()
    return _out(finding, file)


@router.get("/allowlist", response_model=list[AllowlistOut])
def list_allowlist(db: DB) -> list[AllowlistEntry]:
    return list(db.scalars(select(AllowlistEntry).order_by(AllowlistEntry.id.desc())))


@router.post("/allowlist", response_model=AllowlistOut, status_code=201)
def add_allowlist(body: AllowlistRequest, db: DB) -> AllowlistEntry:
    """Add a SHA-256 or a path glob (relative to the scan root; * also matches /). Matching
    findings become allowlisted straight away."""
    value = body.value
    if body.kind == "sha256":
        value = value.lower()
        if not SHA256.match(value):
            raise HTTPException(422, "not a SHA-256 (64 hex characters)")
    else:
        value = value.lstrip("/")
        if not value:
            raise HTTPException(422, "empty path pattern")
    entry = AllowlistEntry(kind=body.kind, value=value, note=(body.note or "").strip() or None)
    db.add(entry)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(409, "already on the allowlist") from exc
    _reevaluate(db)
    db.refresh(entry)
    return entry


@router.delete("/allowlist/{entry_id}", status_code=204)
def delete_allowlist(entry_id: int, db: DB) -> Response:
    entry = db.get(AllowlistEntry, entry_id)
    if entry is None:
        raise HTTPException(404, "no such allowlist entry")
    db.delete(entry)
    db.commit()
    _reevaluate(db)
    return Response(status_code=204)


def _reevaluate(db) -> None:
    """Flagged files are few, so the change applies before the response."""
    store.queue_all(db)
    db.commit()
    store.evaluate_all(db, get_settings())
