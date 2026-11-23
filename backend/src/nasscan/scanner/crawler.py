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

from sqlalchemy import and_, func, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session, sessionmaker

from nasscan.config import Settings
from nasscan.db.models import File, ScanRun
from nasscan.scanner.hashing import FileDigest, Stopped, Throttle, digest_file
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
class Counts:
    seen: int = 0
    new: int = 0
    changed: int = 0
    unchanged: int = 0
    hashed: int = 0
    bytes_seen: int = 0
    bytes_hashed: int = 0
    errors: int = 0
    last_error: str | None = None
    error_dirs: list[str] = field(default_factory=list)

    def error(self, message: str) -> None:
        self.errors += 1
        self.last_error = message[:2000]


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
    ) -> None:
        self.settings = settings
        self.sessions = sessions
        self.stop = stop or threading.Event()
        self.throttle = Throttle(settings.max_read_mbps)
        self.exclude = Excluder(settings.exclude_patterns)
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
                last_error=run.last_error,
            )
        log.info("scan %d (%s%s) started", run_id, kind, f" of {root}" if root else "")
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
            f"{b.hashed + counts.hashed} read, {b.errors + counts.errors} errors."
        )
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
                counts.error(f"{item.path}: {item.message}")
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
                or row.sha256 is None
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
                counts.error(f"{item.path}: {message}")
                self._upsert(session, run_id, item, None, now, error=message)
            else:
                counts.hashed += 1
                counts.bytes_hashed += result.size
                self._upsert(session, run_id, item, result, now)

    def _read(self, item: FoundFile) -> FileDigest | Exception:
        try:
            return digest_file(item.full_path, self.throttle, self.stop)
        except (Stopped, OSError) as exc:
            return exc

    def _upsert(
        self,
        session: Session,
        run_id: int,
        item: FoundFile,
        digest: FileDigest | None,
        now: datetime,
        error: str | None = None,
    ) -> None:
        values = {
            "path": item.path,
            "extension": extension(item.path),
            "size": item.size,
            "mtime_ns": item.mtime_ns,
            "inode": item.inode,
            "device": item.device,
            "mime": digest.mime if digest else None,
            "magic": digest.magic if digest else None,
            "sha256": digest.sha256 if digest else None,
            "sha1": digest.sha1 if digest else None,
            "md5": digest.md5 if digest else None,
            "status": "error" if error else "active",
            "error": error[:2000] if error else None,
            "first_seen": now,
            "last_seen": now,
            "last_scanned": now if digest else None,
            "removed_at": None,
            "last_seen_run_id": run_id,
        }
        stmt = insert(File).values(**values)
        update_cols = {k: stmt.excluded[k] for k in values if k not in ("path", "first_seen")}
        if not digest:
            update_cols.pop("last_scanned")  # keep when it was last read successfully
        session.execute(stmt.on_conflict_do_update(index_elements=["path"], set_=update_cols))

    def _progress(self, session: Session, run_id: int, counts: Counts, current: str | None) -> None:
        """Totals so far: what the run had when this execution began, plus this execution."""
        base = self._base
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
