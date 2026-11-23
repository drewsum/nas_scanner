"""The file inventory: search by path or hash, one file's full story, and totals."""

import re
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import func, or_, select

from nasscan.api.deps import DB
from nasscan.db.models import Detection, FeedHash, File, Finding, HashLookup

router = APIRouter(prefix="/api/files", tags=["files"])

HEX_HASH = re.compile(r"^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$")


class FileRow(BaseModel):
    id: int
    path: str
    size: int
    status: str
    mime: str | None
    sha256: str | None
    last_scanned: datetime | None
    verdict: str | None  # of its finding, if it has one
    finding_status: str | None


class SearchOut(BaseModel):
    files: list[FileRow]
    match: str  # "hash" or "path"
    truncated: bool


class StatsOut(BaseModel):
    files: int  # on the NAS now
    bytes: int
    read_partly: int  # large media, start and end only
    unreadable: int
    removed: int
    with_detections: int
    last_scanned: datetime | None


class DetectionItem(BaseModel):
    engine: str
    name: str
    member: str
    severity: str
    description: str | None
    link: str | None
    first_seen: datetime
    last_seen: datetime


class LookupItem(BaseModel):
    provider: str
    verdict: str
    name: str | None
    looked_up_at: datetime


class FeedItem(BaseModel):
    feed: str
    name: str | None
    hash_type: str


class FindingRef(BaseModel):
    id: int
    verdict: str
    score: int
    status: str


class Event(BaseModel):
    at: datetime
    what: str


class FileDetail(BaseModel):
    id: int
    path: str
    extension: str | None
    size: int
    mtime: datetime
    status: str
    error: str | None
    mime: str | None
    magic: str | None
    sha256: str | None
    sha1: str | None
    md5: str | None
    scan_mode: str | None
    first_seen: datetime
    last_seen: datetime
    last_scanned: datetime | None
    removed_at: datetime | None
    last_seen_run_id: int | None
    finding: FindingRef | None
    detections: list[DetectionItem]
    lookups: list[LookupItem]
    feeds: list[FeedItem]
    history: list[Event]  # newest first


@router.get("", response_model=SearchOut)
def search(
    db: DB,
    q: Annotated[str, Query(min_length=1, max_length=1024)],
    include_removed: bool = False,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> SearchOut:
    """A whole MD5, SHA-1 or SHA-256 finds every copy of that content (removed ones too);
    anything else is a path substring, case-insensitive."""
    term = q.strip()
    stmt = select(File, Finding.verdict, Finding.status).outerjoin(
        Finding, Finding.file_id == File.id
    )
    if HEX_HASH.match(term.lower()):
        h = term.lower()
        stmt = stmt.where(or_(File.sha256 == h, File.sha1 == h, File.md5 == h))
        match = "hash"
    else:
        if len(term) < 2:
            raise HTTPException(422, "search for at least 2 characters")
        stmt = stmt.where(File.path.icontains(term, autoescape=True))
        if not include_removed:
            stmt = stmt.where(File.status != "removed")
        match = "path"
    rows = db.execute(stmt.order_by(File.path).limit(limit + 1)).all()
    return SearchOut(
        files=[
            FileRow(
                id=f.id,
                path=f.path,
                size=f.size,
                status=f.status,
                mime=f.mime,
                sha256=f.sha256,
                last_scanned=f.last_scanned,
                verdict=verdict,
                finding_status=status,
            )
            for f, verdict, status in rows[:limit]
        ],
        match=match,
        truncated=len(rows) > limit,
    )


@router.get("/stats", response_model=StatsOut)
def stats(db: DB) -> StatsOut:
    present = File.status != "removed"
    row = db.execute(
        select(
            func.count().filter(present),
            func.coalesce(func.sum(File.size).filter(present), 0),
            func.count().filter(present, File.scan_mode == "partial"),
            func.count().filter(File.status == "error"),
            func.count().filter(File.status == "removed"),
            func.max(File.last_scanned),
        )
    ).one()
    flagged = db.scalar(
        select(func.count(func.distinct(Detection.file_id)))
        .join(File, File.id == Detection.file_id)
        .where(present)
    )
    return StatsOut(
        files=row[0],
        bytes=int(row[1]),
        read_partly=row[2],
        unreadable=row[3],
        removed=row[4],
        with_detections=flagged or 0,
        last_scanned=row[5],
    )


def _history(f: File, detections: list[Detection], finding: Finding | None) -> list[Event]:
    """The file's story from what the inventory keeps (no row per file per scan: that would
    be millions a week)."""
    history = [Event(at=f.first_seen, what="First seen")]
    if f.last_scanned:
        how = " (start and end only)" if f.scan_mode == "partial" else ""
        history.append(Event(at=f.last_scanned, what=f"Last read and scanned{how}"))
    seen_in = f" (scan {f.last_seen_run_id})" if f.last_seen_run_id else ""
    history.append(Event(at=f.last_seen, what=f"Last seen{seen_in}"))
    if f.removed_at:
        history.append(Event(at=f.removed_at, what="Gone from the NAS"))
    for d in detections:
        history.append(Event(at=d.first_seen, what=f"{d.engine}: {d.name} ({d.severity})"))
    if finding:
        history.append(Event(at=finding.opened_at, what=f"Finding opened ({finding.verdict})"))
        if finding.status != "open" and finding.status_changed_at != finding.opened_at:
            history.append(Event(at=finding.status_changed_at, what=f"Finding {finding.status}"))
    history.sort(key=lambda e: e.at, reverse=True)
    return history


@router.get("/{file_id}", response_model=FileDetail)
def read_file(file_id: int, db: DB) -> FileDetail:
    f = db.get(File, file_id)
    if f is None:
        raise HTTPException(404, "no such file")
    finding = db.scalar(select(Finding).where(Finding.file_id == f.id))
    detections = list(
        db.scalars(
            select(Detection)
            .where(Detection.file_id == f.id)
            .order_by(Detection.first_seen, Detection.id)
        )
    )
    lookups = []
    if f.sha256:
        lookups = list(
            db.scalars(
                select(HashLookup)
                .where(HashLookup.sha256 == f.sha256)
                .order_by(HashLookup.provider)
            )
        )
    by_raw = {
        bytes.fromhex(value): kind
        for kind, value in (("sha256", f.sha256), ("sha1", f.sha1), ("md5", f.md5))
        if value
    }
    feeds = []
    if by_raw:
        feeds = [
            FeedItem(feed=feed, name=name, hash_type=by_raw[bytes(h)])
            for h, feed, name in db.execute(
                select(FeedHash.hash, FeedHash.feed, FeedHash.name).where(
                    FeedHash.hash.in_(list(by_raw))
                )
            )
        ]
    return FileDetail(
        id=f.id,
        path=f.path,
        extension=f.extension,
        size=f.size,
        mtime=datetime.fromtimestamp(f.mtime_ns / 1e9, UTC),
        status=f.status,
        error=f.error,
        mime=f.mime,
        magic=f.magic,
        sha256=f.sha256,
        sha1=f.sha1,
        md5=f.md5,
        scan_mode=f.scan_mode,
        first_seen=f.first_seen,
        last_seen=f.last_seen,
        last_scanned=f.last_scanned,
        removed_at=f.removed_at,
        last_seen_run_id=f.last_seen_run_id,
        finding=FindingRef(
            id=finding.id, verdict=finding.verdict, score=finding.score, status=finding.status
        )
        if finding
        else None,
        detections=[
            DetectionItem(
                engine=d.engine,
                name=d.name,
                member=d.member,
                severity=d.severity,
                description=d.description,
                link=(d.details or {}).get("link"),
                first_seen=d.first_seen,
                last_seen=d.last_seen,
            )
            for d in detections
        ],
        lookups=[
            LookupItem(
                provider=lk.provider,
                verdict=lk.verdict,
                name=lk.name,
                looked_up_at=lk.looked_up_at,
            )
            for lk in lookups
        ],
        feeds=feeds,
        history=_history(f, detections, finding),
    )
