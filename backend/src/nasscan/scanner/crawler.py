"""Executes one scan run: walk, compare with the inventory, read what needs reading, record.

Incremental runs read only new and changed files (size, mtime or inode differ from the
inventory). Full and folder runs read every file. Files the walk no longer finds are marked
removed, except under folders that couldn't be listed, and never when the scan root looks
unmounted, so a missing mount can't wipe the inventory.

Progress is committed batch by batch together with the files, and each file records the run
that last saw it. A run that is interrupted (the container stops) goes back to the queue,
and picks up where it was: files already seen by that run are skipped.
"""

import logging
import os
import threading
from collections.abc import Iterable, Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import PurePosixPath

from sqlalchemy import and_, case, delete, func, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session, sessionmaker

from nasscan.config import Settings
from nasscan.db.models import Detection, File, ScanError, ScanRun
from nasscan.intel.priority import priority_for
from nasscan.scanner.engines import LOCAL_ENGINE_NAMES, Pipeline, ScanResult
from nasscan.scanner.engines.base import FileContext
from nasscan.scanner.hashing import ReadResult, Stopped, Throttle, read_file
from nasscan.scanner.walker import Excluder, FoundFile, WalkError, walk

log = logging.getLogger(__name__)

# A batch is committed (with the run's progress) after this many files or bytes, whichever
# comes first, so progress keeps moving through folders of big movies too.
BATCH = 200
BATCH_BYTES = 1024**3
# With more unreadable folders than this, removals are skipped for the run altogether.
MAX_ERROR_DIRS = 500


class ScanFailedError(RuntimeError):
    pass


def extension(path: str) -> str | None:
    suffix = PurePosixPath(path).suffix.lower().lstrip(".")
    return suffix[:32] or None


def under(path: str, folder: str) -> bool:
    return not folder or path == folder or path.startswith(folder + "/")


@dataclass
class Scanned:
    """A file read and scanned, ready to record."""

    read: ReadResult
    result: ScanResult
    priority: int = 0  # for live threat-intel lookups


# Unreadable files and folders kept per run for its detail page.
MAX_SAVED_ERRORS = 500


@dataclass
class Counts:
    seen: int = 0
    new: int = 0
    changed: int = 0
    unchanged: int = 0
    hashed: int = 0
    bytes_seen: int = 0
    bytes_hashed: int = 0
    errors: int = 0
    flagged: int = 0
    detections: int = 0
    last_error: str | None = None
    error_dirs: list[str] = field(default_factory=list)
    # Files each engine couldn't scan (clamd down, no rules yet), and the last reason.
    engine_errors: dict[str, int] = field(default_factory=dict)
    engine_last_error: dict[str, str] = field(default_factory=dict)
    # Errors not yet written to scan_errors, and how many this execution has written.
    unsaved: list[tuple[str, str]] = field(default_factory=list)
    saved: int = 0

    def error(self, path: str, message: str) -> None:
        self.errors += 1
        self.last_error = f"{path}: {message}"[:2000]
        self.unsaved.append((path, message[:2000]))


def batches(items: Iterable[FoundFile], size: int, max_bytes: int) -> Iterator[list[FoundFile]]:
    chunk: list[FoundFile] = []
    total = 0
    for item in items:
        chunk.append(item)
        total += item.size
        if len(chunk) >= size or total >= max_bytes:
            yield chunk
            chunk, total = [], 0
    if chunk:
        yield chunk


class Crawler:
    def __init__(
        self,
        settings: Settings,
        sessions: sessionmaker[Session],
        stop: threading.Event | None = None,
        pipeline: Pipeline | None = None,
    ) -> None:
        self.settings = settings
        self.sessions = sessions
        self.stop = stop or threading.Event()
        self.throttle = Throttle(settings.max_read_mbps)
        self.exclude = Excluder(settings.exclude_patterns)
        self.pipeline = pipeline if pipeline is not None else Pipeline(settings)
        mb = 1024 * 1024
        self.read_options = {
            "memory_limit": settings.memory_read_mb * mb,
            "large_limit": settings.large_file_mb * mb,
            "piece": settings.partial_chunk_mb * mb,
            "full_media": settings.large_media_full_read,
        }
        self._base = Counts()

    # --- the run ---------------------------------------------------------------------------

    def execute(self, run_id: int) -> None:
        """Run to the end, or raise Stopped (left running, to resume) on shutdown or when the
        run is cancelled. Failures are recorded on the run."""
        with self.sessions() as session:
            run = session.get_one(ScanRun, run_id)
            kind, root = run.kind, run.root
            # A resumed run carries on from its totals so far.
            self._base = Counts(
                seen=run.files_seen,
                new=run.files_new,
                changed=run.files_changed,
                unchanged=run.files_unchanged,
                hashed=run.files_hashed,
                bytes_seen=run.bytes_seen,
                bytes_hashed=run.bytes_hashed,
                errors=run.errors,
                flagged=run.files_flagged,
                detections=run.detections,
                last_error=run.last_error,
            )
        log.info(
            "scan %d (%s%s) started; engines: %s",
            run_id,
            kind,
            f" of {root}" if root else "",
            ", ".join(self.pipeline.names) or "none",
        )
        try:
            self._check_root(root)
            counts = self._walk(run_id, kind, root)
            removed = self._mark_removed(run_id, root, counts)
        except Stopped:
            log.info("scan %d stopped; it resumes when the scanner starts again", run_id)
            raise
        except Exception as exc:
            log.exception("scan %d failed", run_id)
            self._finish(run_id, "failed", f"Failed: {exc}")
            return
        b = self._base
        message = (
            f"{b.seen + counts.seen} files: {b.new + counts.new} new, "
            f"{b.changed + counts.changed} changed, {removed} removed, "
            f"{b.hashed + counts.hashed} read, {b.flagged + counts.flagged} flagged, "
            f"{b.errors + counts.errors} errors."
        )
        for engine, n in sorted(counts.engine_errors.items()):
            message += f" {engine} skipped {n} files ({counts.engine_last_error[engine]})."
        self._finish(run_id, "completed", message)
        log.info("scan %d completed: %s", run_id, message)

    def _check_root(self, root: str) -> None:
        base = self.settings.scan_root
        target = os.path.join(base, root) if root else base
        if not os.path.isdir(target):
            raise ScanFailedError(f"{target} isn't a folder (is NASSCAN_SCAN_ROOT mounted?)")
        if not root and not os.listdir(base):
            raise ScanFailedError(f"{base} is empty (is NASSCAN_SCAN_ROOT mounted?)")

    def _walk(self, run_id: int, kind: str, root: str) -> Counts:
        counts = Counts()
        read_all = kind in ("full", "path")
        found = self._found_files(root, counts)
        with ThreadPoolExecutor(self.settings.scan_workers, "nasscan-read") as pool:
            for batch in batches(found, BATCH, BATCH_BYTES):
                if self.stop.is_set():
                    raise Stopped
                with self.sessions() as session:
                    if session.scalar(select(ScanRun.status).where(ScanRun.id == run_id)) != (
                        "running"
                    ):
                        raise Stopped  # cancelled
                    self._batch(session, pool, run_id, batch, read_all, counts)
                    self._progress(session, run_id, counts, batch[-1].path)
                    session.commit()
        return counts

    def _found_files(self, root: str, counts: Counts) -> Iterator[FoundFile]:
        for item in walk(self.settings.scan_root, root, self.exclude):
            if isinstance(item, WalkError):
                counts.error(item.path, item.message)
                log.warning("can't read %s: %s", item.path or "/", item.message)
                if item.is_dir:
                    if item.path == root:
                        raise ScanFailedError(f"can't list {root or 'the scan root'}")
                    counts.error_dirs.append(item.path)
                continue
            yield item

    def _batch(
        self,
        session: Session,
        pool: ThreadPoolExecutor,
        run_id: int,
        batch: list[FoundFile],
        read_all: bool,
        counts: Counts,
    ) -> None:
        now = datetime.now(UTC)
        known = {
            f.path: f
            for f in session.scalars(select(File).where(File.path.in_([b.path for b in batch])))
        }
        to_read: list[FoundFile] = []
        unchanged: list[int] = []
        for item in batch:
            row = known.get(item.path)
            if row is not None and row.last_seen_run_id == run_id:
                continue  # done before this run was interrupted
            counts.seen += 1
            counts.bytes_seen += item.size
            changed = row is not None and (
                row.size != item.size
                or row.mtime_ns != item.mtime_ns
                or row.inode != item.inode
                or row.status != "active"
                or row.last_scanned is None
            )
            if row is None:
                counts.new += 1
            elif changed:
                counts.changed += 1
            else:
                counts.unchanged += 1
            if row is None or changed or read_all:
                to_read.append(item)
            else:
                unchanged.append(row.id)

        if unchanged:
            session.execute(
                update(File)
                .where(File.id.in_(unchanged))
                .values(last_seen=now, last_seen_run_id=run_id)
            )
        for item, result in zip(to_read, pool.map(self._read, to_read), strict=True):
            if isinstance(result, Stopped):
                raise result
            if isinstance(result, Exception):
                message = getattr(result, "strerror", None) or str(result)
                counts.error(item.path, message)
                self._upsert(session, run_id, item, None, now, error=message)
            else:
                counts.hashed += 1
                counts.bytes_hashed += result.read.bytes_read
                for engine, reason in result.result.errors.items():
                    counts.engine_errors[engine] = counts.engine_errors.get(engine, 0) + 1
                    counts.engine_last_error[engine] = reason[:300]
                findings = result.result.findings
                if findings:
                    counts.flagged += 1
                    counts.detections += len(findings)
                file_id = self._upsert(session, run_id, item, result.read, now, result.priority)
                self._record_findings(session, run_id, file_id, result.result, now)

    def _read(self, item: FoundFile) -> Scanned | Exception:
        """Read one file and run the engines over it (in a worker thread)."""
        try:
            read = read_file(
                item.full_path,
                item.size,
                extension(item.path),
                throttle=self.throttle,
                stop=self.stop,
                **self.read_options,
            )
            ctx = FileContext(
                path=item.path,
                full_path=item.full_path,
                size=item.size,
                extension=extension(item.path),
                mime=read.mime,
                magic=read.magic,
                mode=read.mode,
                data=read.data,
                head=read.head,
                tail=read.tail,
                throttle=self.throttle,
            )
            result = self.pipeline.scan(ctx)
            ext = extension(item.path)
            return Scanned(read, result, priority_for(ext, read.mime, result.findings))
        except (Stopped, OSError) as exc:
            return exc

    def _record_findings(
        self, session: Session, run_id: int, file_id: int, result: ScanResult, now: datetime
    ) -> None:
        """Store this read's findings; drop earlier ones that didn't come back, except from
        engines that couldn't scan this time."""
        for f in result.findings:
            stmt = insert(Detection).values(
                file_id=file_id,
                engine=f.engine,
                name=f.name[:500],
                member=f.member[:1000],
                severity=f.severity,
                description=f.description[:2000],
                details=f.details,
                run_id=run_id,
                first_seen=now,
                last_seen=now,
            )
            session.execute(
                stmt.on_conflict_do_update(
                    index_elements=["file_id", "engine", "name", "member"],
                    set_={
                        k: stmt.excluded[k]
                        for k in ("severity", "description", "details", "run_id", "last_seen")
                    },
                )
            )
        stale = delete(Detection).where(
            Detection.file_id == file_id,
            Detection.last_seen < now,
            Detection.engine.in_(LOCAL_ENGINE_NAMES | set(self.pipeline.names)),
        )
        if result.errors:
            stale = stale.where(Detection.engine.not_in(list(result.errors)))
        session.execute(stale)

    def _upsert(
        self,
        session: Session,
        run_id: int,
        item: FoundFile,
        read: ReadResult | None,
        now: datetime,
        priority: int = 0,
        error: str | None = None,
    ) -> int:
        digest = read.digest if read else None
        values = {
            "path": item.path,
            "extension": extension(item.path),
            "size": item.size,
            "mtime_ns": item.mtime_ns,
            "inode": item.inode,
            "device": item.device,
            "mime": read.mime if read else None,
            "magic": read.magic if read else None,
            "sha256": digest.sha256 if digest else None,
            "sha1": digest.sha1 if digest else None,
            "md5": digest.md5 if digest else None,
            "scan_mode": ("partial" if read.digest is None else "full") if read else None,
            "status": "error" if error else "active",
            "error": error[:2000] if error else None,
            "first_seen": now,
            "last_seen": now,
            "last_scanned": now if read else None,
            "removed_at": None,
            "last_seen_run_id": run_id,
            "intel_priority": priority,
        }
        stmt = insert(File).values(**values)
        update_cols = {k: stmt.excluded[k] for k in values if k not in ("path", "first_seen")}
        if read:
            # New content: threat intel is applied again (and stale intel detections go).
            table = File.__table__.c
            update_cols["intel_checked_at"] = case(
                (table.sha256.is_distinct_from(stmt.excluded.sha256), None),
                else_=table.intel_checked_at,
            )
        else:
            # Keep when it was last read successfully, and what intel knew then.
            for col in ("last_scanned", "intel_priority", "sha256", "sha1", "md5"):
                update_cols.pop(col)
        return session.scalar(
            stmt.on_conflict_do_update(index_elements=["path"], set_=update_cols).returning(File.id)
        )

    def _progress(self, session: Session, run_id: int, counts: Counts, current: str | None) -> None:
        """Totals so far: what the run had when this execution began, plus this execution."""
        base = self._base
        if counts.unsaved:
            # A run keeps its first MAX_SAVED_ERRORS; the count covers the rest.
            room = max(0, MAX_SAVED_ERRORS - base.errors - counts.saved)
            now = datetime.now(UTC)
            rows = [
                {"run_id": run_id, "path": path, "message": message, "at": now}
                for path, message in counts.unsaved[:room]
            ]
            if rows:
                session.execute(insert(ScanError), rows)
            counts.saved += len(rows)
            counts.unsaved.clear()
        session.execute(
            update(ScanRun)
            .where(ScanRun.id == run_id)
            .values(
                files_seen=base.seen + counts.seen,
                files_new=base.new + counts.new,
                files_changed=base.changed + counts.changed,
                files_unchanged=base.unchanged + counts.unchanged,
                files_hashed=base.hashed + counts.hashed,
                bytes_seen=base.bytes_seen + counts.bytes_seen,
                bytes_hashed=base.bytes_hashed + counts.bytes_hashed,
                errors=base.errors + counts.errors,
                files_flagged=base.flagged + counts.flagged,
                detections=base.detections + counts.detections,
                last_error=counts.last_error or base.last_error,
                current_path=current,
                updated_at=datetime.now(UTC),
            )
        )

    # --- the end ---------------------------------------------------------------------------

    def _mark_removed(self, run_id: int, root: str, counts: Counts) -> int:
        with self.sessions() as session:
            # Final totals, including errors after the last batch.
            self._progress(session, run_id, counts, None)
            session.commit()
            run = session.get_one(ScanRun, run_id)
            if len(counts.error_dirs) > MAX_ERROR_DIRS:
                run.message = f"{len(counts.error_dirs)} unreadable folders: removals skipped"
                session.commit()
                return 0
            scope = [File.status != "removed", File.last_seen_run_id.is_distinct_from(run_id)]
            if root:
                scope.append(File.path.startswith(root + "/", autoescape=True))
            for folder in counts.error_dirs:
                scope.append(~File.path.startswith(folder + "/", autoescape=True))
            gone = session.scalar(select(func.count()).select_from(File).where(and_(*scope)))
            if gone and run.files_seen == 0:
                raise ScanFailedError(
                    f"found no files but {gone} were known; not marking them removed"
                )
            now = datetime.now(UTC)
            session.execute(
                update(File).where(and_(*scope)).values(status="removed", removed_at=now)
            )
            run.files_removed = gone or 0
            session.commit()
            return gone or 0

    def _finish(self, run_id: int, status: str, message: str) -> None:
        with self.sessions() as session:
            now = datetime.now(UTC)
            session.execute(
                update(ScanRun)
                .where(ScanRun.id == run_id)
                .values(
                    status=status,
                    finished_at=now,
                    updated_at=now,
                    current_path=None,
                    message=message,
                )
            )
            session.commit()
