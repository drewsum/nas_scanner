"""ORM models."""

from datetime import date, datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    Date,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    SmallInteger,
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
    # At the end of the run: engine versions and signature dates, feed sizes. For its report.
    versions: Mapped[dict | None] = mapped_column(JSONB)
    # When its digest (or failure notice) went out, or was found not to be needed.
    notified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


# active: present at the last scan; removed: gone since; error: couldn't be read.
FILE_STATUSES = ("active", "removed", "error")


class ScanError(Base):
    """A file or folder a scan couldn't read, kept for the run's detail page. A run keeps its
    first few hundred; ScanRun.errors counts them all."""

    __tablename__ = "scan_errors"
    __table_args__ = (Index("scan_errors_run", "run_id", "id"),)

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    run_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("scan_runs.id", ondelete="CASCADE"))
    path: Mapped[str] = mapped_column(Text)
    message: Mapped[str] = mapped_column(Text)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class File(Base):
    __tablename__ = "files"
    __table_args__ = (
        Index("files_sha256", "sha256"),
        Index("files_md5", "md5"),
        Index("files_sha1", "sha1"),
        Index("files_status", "status"),
        # Files whose threat-intel evidence needs (re)applying: new or changed content.
        Index(
            "files_intel_pending",
            "id",
            postgresql_where=text("intel_checked_at IS NULL AND status = 'active'"),
        ),
        Index("files_intel_candidates", "sha256", postgresql_where=text("intel_priority > 0")),
        Index("files_verdict_pending", "id", postgresql_where=text("verdict_pending")),
        # Path substring search (pg_trgm), for the file search page.
        Index(
            "files_path_trgm",
            "path",
            postgresql_using="gin",
            postgresql_ops={"path": "gin_trgm_ops"},
        ),
    )

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
    # How much a live threat-intel lookup is worth spending on this file (0: none); see
    # nasscan.intel.priority.
    intel_priority: Mapped[int] = mapped_column(SmallInteger, default=0)
    # When feed matches and cached lookups were last applied to it; cleared when the content
    # changes.
    intel_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Its verdict needs working out again. Set by database triggers whenever its detections,
    # status or content change, so every writer is covered; cleared by nasscan.findings.
    verdict_pending: Mapped[bool] = mapped_column(Boolean, default=False)


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
    """Each engine's health and signature age, refreshed by the scanner, and the database
    backup's (name ``backup``), written by the backup service."""

    __tablename__ = "engine_status"

    name: Mapped[str] = mapped_column(String(32), primary_key=True)
    status: Mapped[str] = mapped_column(String(16))  # ok | warning | error | disabled
    message: Mapped[str] = mapped_column(Text)
    version: Mapped[str | None] = mapped_column(Text)
    signatures_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    details: Mapped[dict | None] = mapped_column(JSONB)
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    # When the current warning or error started (NULL while healthy), and when it was notified.
    problem_since: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    alerted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class FeedHash(Base):
    """A hash listed by a downloaded threat feed (MalwareBazaar, VirusShare, ...)."""

    __tablename__ = "feed_hashes"

    # Raw bytes (16, 20 or 32 of them) to keep millions of rows small.
    hash: Mapped[bytes] = mapped_column(LargeBinary, primary_key=True)
    feed: Mapped[str] = mapped_column(String(32), primary_key=True)
    name: Mapped[str | None] = mapped_column(Text)  # malware family or signature, if given
    added_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


# What a provider said about a hash. malicious/suspicious/info become detections; known_good
# (NSRL and the like) keeps a hash away from the other providers.
VERDICTS = ("malicious", "suspicious", "info", "clean", "known_good", "not_found")


class HashLookup(Base):
    """Cached answer from one live provider about one SHA-256."""

    __tablename__ = "hash_lookups"
    __table_args__ = (Index("hash_lookups_sha256", "sha256"),)

    provider: Mapped[str] = mapped_column(String(32), primary_key=True)
    sha256: Mapped[str] = mapped_column(String(64), primary_key=True)
    verdict: Mapped[str] = mapped_column(String(16))
    name: Mapped[str | None] = mapped_column(Text)
    description: Mapped[str | None] = mapped_column(Text)
    details: Mapped[dict | None] = mapped_column(JSONB)
    looked_up_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class IntelProvider(Base):
    """Each feed's and lookup provider's state: health, freshness and quota use."""

    __tablename__ = "intel_providers"

    name: Mapped[str] = mapped_column(String(32), primary_key=True)
    kind: Mapped[str] = mapped_column(String(16))  # feed | lookup
    title: Mapped[str] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    status: Mapped[str] = mapped_column(String(16))  # ok | warning | error | disabled | idle
    message: Mapped[str] = mapped_column(Text, default="")
    last_success: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_attempt: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(Text)
    last_error_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # No requests before this (rate limited, key rejected, quota spent).
    paused_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Requests made on `day` (UTC) against the daily budget.
    day: Mapped[date | None] = mapped_column(Date)
    requests_today: Mapped[int] = mapped_column(Integer, default=0)
    daily_budget: Mapped[int | None] = mapped_column(Integer)
    per_minute: Mapped[float | None] = mapped_column()
    # Feeds: hashes held. Lookups: hashes answered in all.
    entries: Mapped[int] = mapped_column(BigInteger, default=0)
    details: Mapped[dict | None] = mapped_column(JSONB)
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


# A file's overall verdict, from all its detections (nasscan.verdict).
FILE_VERDICTS = ("clean", "suspicious", "malicious")
# open: needs a look. acknowledged: seen, keep it listed, don't alert again. ignored: a false
# positive for this content. allowlisted: matches an allowlist entry. resolved: the file is
# gone or came back clean. Only the first three are set by hand.
FINDING_STATUSES = ("open", "acknowledged", "ignored", "allowlisted", "resolved")
TRIAGE_STATUSES = ("open", "acknowledged", "ignored")


class Finding(Base):
    """One file judged suspicious or malicious, kept after it resolves for the history."""

    __tablename__ = "findings"
    __table_args__ = (Index("findings_status", "status", "verdict"),)

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    file_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("files.id", ondelete="CASCADE"), unique=True
    )
    # The content judged; a different hash later means new content, and triage starts over.
    sha256: Mapped[str | None] = mapped_column(String(64))
    verdict: Mapped[str] = mapped_column(String(16))
    score: Mapped[int] = mapped_column(Integer)
    # Every detection behind it, with the points each engine contributed.
    evidence: Mapped[list] = mapped_column(JSONB)
    status: Mapped[str] = mapped_column(String(16), default="open")
    # removed | clean, when resolved.
    resolution: Mapped[str | None] = mapped_column(String(16))
    note: Mapped[str | None] = mapped_column(Text)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    # Last evaluated as suspicious or malicious.
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    # When it last became open (new, reopened, or escalated): what alerts key on.
    opened_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    status_changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    verdict_changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    # When an alert last went out for it; it's due again once opened_at passes this.
    alerted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


ALLOWLIST_KINDS = ("sha256", "path")


class AllowlistEntry(Base):
    """Content (by SHA-256) or paths (by glob) never to raise a finding."""

    __tablename__ = "allowlist"
    __table_args__ = (Index("allowlist_unique", "kind", "value", unique=True),)

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    kind: Mapped[str] = mapped_column(String(16))
    # A lowercase SHA-256, or a glob relative to the scan root where * also matches /.
    value: Mapped[str] = mapped_column(Text)
    note: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Notification(Base):
    """Everything sent (or tried) through Apprise: alerts, digests, reports, tests."""

    __tablename__ = "notifications"
    __table_args__ = (Index("notifications_created", "created_at"),)

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    kind: Mapped[str] = mapped_column(String(16))  # alert | scan | weekly | test
    title: Mapped[str] = mapped_column(Text)
    body: Mapped[str] = mapped_column(Text)
    ok: Mapped[bool] = mapped_column(Boolean)
    error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class Report(Base):
    """A stored weekly report: its figures, rendered to HTML when viewed."""

    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    kind: Mapped[str] = mapped_column(String(16), default="weekly")
    # The scheduled full scan it followed, if any.
    run_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("scan_runs.id", ondelete="SET NULL"), unique=True
    )
    period_start: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    period_end: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    data: Mapped[dict] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    notified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
