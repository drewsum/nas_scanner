"""ORM models."""

from datetime import datetime

from sqlalchemy import (
    BigInteger,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class AppSecret(Base):
    """Secrets the app generates for itself, such as the session signing key."""

    __tablename__ = "app_secrets"

    name: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


# Scan kinds: new and changed files only; every file; every file under one folder.
RUN_KINDS = ("incremental", "full", "path")
# queued -> running -> completed | failed | cancelled. A run still "running" when the scanner
# restarts was interrupted, and goes back to queued to resume.
RUN_STATUSES = ("queued", "running", "completed", "failed", "cancelled")
ACTIVE_RUN_STATUSES = ("queued", "running")


class ScanRun(Base):
    __tablename__ = "scan_runs"
    __table_args__ = (
        # At most one run waits or runs at a time.
        Index(
            "scan_runs_one_active",
            text("(true)"),
            unique=True,
            postgresql_where=text("status IN ('queued', 'running')"),
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    kind: Mapped[str] = mapped_column(String(16))
    # Folder under the scan root, relative ("" for the whole root).
    root: Mapped[str] = mapped_column(Text, default="")
    trigger: Mapped[str] = mapped_column(String(16))  # schedule | manual
    status: Mapped[str] = mapped_column(String(16), default="queued")
    requested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Times the run was picked up again after a restart.
    resumed: Mapped[int] = mapped_column(Integer, default=0)

    files_seen: Mapped[int] = mapped_column(BigInteger, default=0)
    files_new: Mapped[int] = mapped_column(BigInteger, default=0)
    files_changed: Mapped[int] = mapped_column(BigInteger, default=0)
    files_unchanged: Mapped[int] = mapped_column(BigInteger, default=0)
    files_removed: Mapped[int] = mapped_column(BigInteger, default=0)
    files_hashed: Mapped[int] = mapped_column(BigInteger, default=0)
    bytes_seen: Mapped[int] = mapped_column(BigInteger, default=0)
    bytes_hashed: Mapped[int] = mapped_column(BigInteger, default=0)
    errors: Mapped[int] = mapped_column(BigInteger, default=0)
    # Files with at least one detection, and detections in all, found by this run.
    files_flagged: Mapped[int] = mapped_column(BigInteger, default=0)
    detections: Mapped[int] = mapped_column(BigInteger, default=0)
    current_path: Mapped[str | None] = mapped_column(Text)
    last_error: Mapped[str | None] = mapped_column(Text)
    message: Mapped[str | None] = mapped_column(Text)


# active: present at the last scan; removed: gone since; error: couldn't be read.
FILE_STATUSES = ("active", "removed", "error")


class File(Base):
    __tablename__ = "files"
    __table_args__ = (Index("files_sha256", "sha256"), Index("files_status", "status"))

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    # Relative to the scan root, '/'-separated. Names that aren't valid UTF-8 are stored with
    # backslash escapes for the odd bytes.
    path: Mapped[str] = mapped_column(Text, unique=True)
    extension: Mapped[str | None] = mapped_column(String(32))
    size: Mapped[int] = mapped_column(BigInteger)
    mtime_ns: Mapped[int] = mapped_column(BigInteger)
    inode: Mapped[int] = mapped_column(BigInteger)
    device: Mapped[int] = mapped_column(BigInteger)

    mime: Mapped[str | None] = mapped_column(String(255))
    magic: Mapped[str | None] = mapped_column(Text)
    sha256: Mapped[str | None] = mapped_column(String(64))
    sha1: Mapped[str | None] = mapped_column(String(40))
    md5: Mapped[str | None] = mapped_column(String(32))
    # How it was last read: "full", or "partial" (a large media file's start and end only,
    # so no hashes).
    scan_mode: Mapped[str | None] = mapped_column(String(16))

    status: Mapped[str] = mapped_column(String(16), default="active")
    error: Mapped[str | None] = mapped_column(Text)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    # When it was last read (hashed and typed; later, scanned by the engines).
    last_scanned: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    removed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen_run_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("scan_runs.id", ondelete="SET NULL")
    )


# How sure an engine is: info (worth knowing), suspicious, malicious.
SEVERITIES = ("info", "suspicious", "malicious")


class Detection(Base):
    """One engine's finding about one file, e.g. a ClamAV signature or a YARA rule. M4 turns
    these into a verdict per file."""

    __tablename__ = "detections"
    __table_args__ = (
        Index("detections_unique", "file_id", "engine", "name", "member", unique=True),
        Index("detections_last_seen", "last_seen"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    file_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("files.id", ondelete="CASCADE"))
    engine: Mapped[str] = mapped_column(String(32))
    name: Mapped[str] = mapped_column(Text)  # signature or rule name
    # Inside an archive-like file (a 3MF's texture, say): the member's name; '' for the file.
    member: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(16))
    description: Mapped[str | None] = mapped_column(Text)
    details: Mapped[dict | None] = mapped_column(JSONB)
    run_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("scan_runs.id", ondelete="SET NULL")
    )
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class EngineStatus(Base):
    """Each engine's health and signature age, refreshed by the scanner."""

    __tablename__ = "engine_status"

    name: Mapped[str] = mapped_column(String(32), primary_key=True)
    status: Mapped[str] = mapped_column(String(16))  # ok | warning | error | disabled
    message: Mapped[str] = mapped_column(Text)
    version: Mapped[str | None] = mapped_column(Text)
    signatures_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    details: Mapped[dict | None] = mapped_column(JSONB)
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
