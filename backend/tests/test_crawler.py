"""Crawler runs against a real database and a temporary scan root."""

import os
import sys
import threading

import pytest
from sqlalchemy import select, text

from nasscan.cli import main
from nasscan.config import get_settings
from nasscan.db import get_sessionmaker
from nasscan.db.models import Detection, File, ScanError, ScanRun
from nasscan.scanner import crawler as crawler_mod
from nasscan.scanner.crawler import Crawler, batches
from nasscan.scanner.engines import Pipeline
from nasscan.scanner.engines.base import Engine, EngineUnavailableError, Finding
from nasscan.scanner.engines.heuristics import HeuristicsEngine
from nasscan.scanner.hashing import Stopped
from nasscan.scanner.runs import ScanBusyError, claim_next, enqueue, requeue_interrupted
from nasscan.scanner.walker import FoundFile

pytestmark = pytest.mark.db


@pytest.fixture
def scan_root(db_env, monkeypatch, tmp_path):
    main(["migrate"])
    with get_sessionmaker()() as s:
        s.execute(text("TRUNCATE files, scan_runs, engine_status RESTART IDENTITY CASCADE"))
        s.commit()
    root = tmp_path / "scan"
    root.mkdir()
    monkeypatch.setenv("NASSCAN_SCAN_ROOT", str(root))
    monkeypatch.setenv("NASSCAN_MAX_READ_MBPS", "0")
    get_settings.cache_clear()
    return root


def put(root, rel, data=b"data"):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)
    return p


def scan(kind="incremental", root="", stop=None, pipeline=None) -> ScanRun:
    sessions = get_sessionmaker()
    with sessions() as s:
        run_id = enqueue(s, kind, "manual", root).id
        claim_next(s)
    Crawler(get_settings(), sessions, stop, pipeline).execute(run_id)
    with sessions() as s:
        return s.get_one(ScanRun, run_id)


def files() -> dict[str, File]:
    with get_sessionmaker()() as s:
        return {f.path: f for f in s.scalars(select(File))}


def test_first_scan_inventories_everything(scan_root):
    put(scan_root, "docs/a.pdf", b"%PDF-1.4")
    put(scan_root, "movies/m.mkv", b"x" * 5000)
    put(scan_root, ".zfs/snapshot/s", b"skip me")
    run = scan()
    assert run.status == "completed", run.message
    assert (run.files_seen, run.files_new, run.files_hashed, run.bytes_hashed) == (2, 2, 2, 5008)
    assert set(run.versions) == {"engines", "intel"}  # recorded for the run's report
    f = files()
    assert set(f) == {"docs/a.pdf", "movies/m.mkv"}
    m = f["movies/m.mkv"]
    assert m.status == "active" and m.extension == "mkv" and len(m.sha256) == 64
    assert m.size == 5000 and m.last_scanned and m.last_seen_run_id == run.id


def test_incremental_reads_only_new_and_changed_files(scan_root):
    put(scan_root, "a", b"one")
    put(scan_root, "b", b"two")
    first = scan()
    before = files()

    put(scan_root, "b", b"two, longer")
    put(scan_root, "c", b"three")
    run = scan()
    assert (run.files_new, run.files_changed, run.files_unchanged) == (1, 1, 1)
    assert run.files_hashed == 2
    after = files()
    assert after["a"].sha256 == before["a"].sha256
    assert after["a"].last_scanned == before["a"].last_scanned  # not read again
    assert after["a"].last_seen_run_id == run.id != first.id
    assert after["b"].sha256 != before["b"].sha256

    again = scan()
    assert (again.files_unchanged, again.files_hashed) == (3, 0)


def test_mtime_change_alone_counts_as_changed(scan_root):
    p = put(scan_root, "a", b"same")
    scan()
    st = p.stat()
    os.utime(p, ns=(st.st_atime_ns, st.st_mtime_ns + 1_000_000_000))
    assert scan().files_changed == 1


def test_batches_end_at_a_count_or_a_size():
    def f(size):
        return FoundFile(path="p", full_path=b"p", size=size, mtime_ns=0, inode=0, device=0)

    sizes = [[len(b), sum(i.size for i in b)] for b in batches([f(1)] * 5, 2, 100)]
    assert sizes == [[2, 2], [2, 2], [1, 1]]
    sizes = [len(b) for b in batches([f(10), f(95), f(1), f(200), f(1)], 50, 100)]
    assert sizes == [2, 2, 1]


def test_full_scan_reads_everything(scan_root):
    put(scan_root, "a")
    put(scan_root, "b")
    scan()
    run = scan("full")
    assert (run.files_unchanged, run.files_hashed) == (2, 2)


def test_deleted_files_are_marked_removed_and_can_come_back(scan_root):
    put(scan_root, "keep")
    gone = put(scan_root, "dir/gone")
    scan()
    gone.unlink()
    run = scan()
    assert run.files_removed == 1
    f = files()["dir/gone"]
    assert f.status == "removed" and f.removed_at is not None
    assert scan().files_removed == 0  # already removed

    put(scan_root, "dir/gone")
    run = scan()
    assert run.files_changed == 1
    f = files()["dir/gone"]
    assert f.status == "active" and f.removed_at is None


def test_an_empty_scan_root_fails_without_removing_anything(scan_root):
    p = put(scan_root, "a")
    scan()
    p.unlink()  # as if the dataset weren't mounted
    run = scan()
    assert run.status == "failed" and "empty" in run.message
    assert files()["a"].status == "active"


def test_a_folder_scan_only_touches_that_folder(scan_root):
    put(scan_root, "a/x")
    put(scan_root, "b/y")
    scan()
    (scan_root / "b/y").unlink()
    put(scan_root, "a/new")
    run = scan("path", "a")
    assert run.kind == "path" and run.root == "a"
    assert (run.files_seen, run.files_new, run.files_removed) == (2, 1, 0)
    assert files()["b/y"].status == "active"  # outside the folder: left for a full scan


@pytest.mark.skipif(sys.platform == "win32" or os.geteuid() == 0, reason="needs POSIX non-root")
def test_files_under_unreadable_folders_are_not_marked_removed(scan_root):
    put(scan_root, "ok/f")
    put(scan_root, "locked/g")
    scan()
    (scan_root / "locked").chmod(0)
    try:
        run = scan()
    finally:
        (scan_root / "locked").chmod(0o755)
    assert run.status == "completed" and run.errors == 1 and run.files_removed == 0
    assert files()["locked/g"].status == "active"


def test_an_unreadable_file_is_recorded_as_an_error(scan_root, monkeypatch):
    put(scan_root, "good")
    put(scan_root, "bad")
    real = crawler_mod.read_file

    def flaky(path, *args, **kwargs):
        if str(path).endswith("bad") or path.endswith(b"bad"):
            raise PermissionError(13, "Permission denied")
        return real(path, *args, **kwargs)

    monkeypatch.setattr(crawler_mod, "read_file", flaky)
    run = scan()
    assert run.status == "completed" and run.errors == 1 and "bad" in run.last_error
    bad = files()["bad"]
    assert bad.status == "error" and bad.error == "Permission denied" and bad.sha256 is None
    with get_sessionmaker()() as s:
        logged = [(e.path, e.message) for e in s.scalars(select(ScanError))]
    assert logged == [("bad", "Permission denied")]
    monkeypatch.setattr(crawler_mod, "read_file", real)
    assert scan().files_changed == 1  # retried next time
    assert files()["bad"].status == "active"


def test_a_run_keeps_its_first_errors(scan_root, monkeypatch):
    for i in range(5):
        put(scan_root, f"bad{i}")
    monkeypatch.setattr(crawler_mod, "MAX_SAVED_ERRORS", 3)

    def broken(path, *args, **kwargs):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(crawler_mod, "read_file", broken)
    run = scan()
    with get_sessionmaker()() as s:
        assert len(list(s.scalars(select(ScanError)))) == 3
    assert run.errors == 5


def test_an_interrupted_run_resumes_where_it_stopped(scan_root, monkeypatch):
    for i in range(5):
        put(scan_root, f"f{i}", str(i).encode())
    monkeypatch.setattr(crawler_mod, "BATCH", 2)
    stop = threading.Event()
    real = crawler_mod.read_file
    reads = []

    def stop_during_second_batch(path, *args, **kwargs):
        reads.append(os.path.basename(os.fsdecode(path)))
        if len(reads) == 3:
            stop.set()  # the container is stopping: this read and its batch are abandoned
        return real(path, *args, **kwargs)

    monkeypatch.setattr(crawler_mod, "read_file", stop_during_second_batch)
    sessions = get_sessionmaker()
    with sessions() as s:
        run_id = enqueue(s, "incremental", "schedule").id
        claim_next(s)
    with pytest.raises(Stopped):
        Crawler(get_settings(), sessions, stop).execute(run_id)
    with sessions() as s:
        run = s.get_one(ScanRun, run_id)
        assert run.status == "running" and run.files_seen == 2

    with sessions() as s:  # the scanner starts again
        assert requeue_interrupted(s) == [run_id]
        assert claim_next(s).id == run_id
    Crawler(get_settings(), sessions).execute(run_id)
    with sessions() as s:
        run = s.get_one(ScanRun, run_id)
    assert run.status == "completed" and run.resumed == 1
    assert (run.files_seen, run.files_new, run.files_hashed) == (5, 5, 5)
    # The first batch was committed and isn't read again; the abandoned one is redone.
    assert set(reads) == {"f0", "f1", "f2", "f3", "f4"}
    assert reads.count("f0") == reads.count("f1") == 1


def test_a_cancelled_run_stops(scan_root, monkeypatch):
    for i in range(4):
        put(scan_root, f"f{i}")
    monkeypatch.setattr(crawler_mod, "BATCH", 1)
    sessions = get_sessionmaker()
    with sessions() as s:
        run_id = enqueue(s, "full", "manual").id
        claim_next(s)
        s.execute(text("UPDATE scan_runs SET status = 'cancelled' WHERE id = :i"), {"i": run_id})
        s.commit()
    with pytest.raises(Stopped):
        Crawler(get_settings(), sessions).execute(run_id)
    assert files() == {}


def test_only_one_scan_at_a_time(scan_root):
    with get_sessionmaker()() as s:
        queued = enqueue(s, "incremental", "schedule")
        with pytest.raises(ScanBusyError):
            enqueue(s, "incremental", "manual")
        # A full scan replaces a queued incremental one: it covers it.
        full = enqueue(s, "full", "schedule")
        s.refresh(queued)
        assert queued.status == "cancelled" and full.status == "queued"
        claim_next(s)
        with pytest.raises(ScanBusyError, match="running"):
            enqueue(s, "full", "manual")


def test_folder_paths_are_normalized_and_kept_inside_the_root(scan_root):
    with get_sessionmaker()() as s:
        run = enqueue(s, "path", "manual", "/movies//2024/")
        assert run.root == "movies/2024"
        s.execute(text("UPDATE scan_runs SET status = 'cancelled'"))
        s.commit()
        with pytest.raises(ValueError, match="inside"):
            enqueue(s, "path", "manual", "../etc")
        assert enqueue(s, "path", "manual", "/").kind == "full"


class Flagger(Engine):
    """Flags files whose content contains b'BAD'; can be switched off like a dead clamd."""

    name = "flagger"
    down = False

    def scan(self, c):
        if self.down:
            raise EngineUnavailableError("flagger is down")
        return [Finding("flagger", "bad", "malicious", "bad content")] * (b"BAD" in (c.data or b""))


def detections() -> list[tuple[str, str, str]]:
    with get_sessionmaker()() as s:
        rows = s.execute(
            select(File.path, Detection.engine, Detection.name)
            .join(File, File.id == Detection.file_id)
            .order_by(File.path, Detection.engine, Detection.name)
        ).all()
    return [tuple(r) for r in rows]


def test_findings_are_recorded_refreshed_and_dropped(scan_root):
    settings = get_settings()
    flagger = Flagger(settings)
    pipeline = Pipeline(settings, [flagger, HeuristicsEngine(settings)])
    put(scan_root, "Movies/x.mkv.exe", b"BAD stuff")
    put(scan_root, "clean.txt", b"fine")
    run = scan(pipeline=pipeline)
    assert (run.files_flagged, run.detections) == (1, 3)
    assert "1 flagged" in run.message
    assert detections() == [
        ("Movies/x.mkv.exe", "flagger", "bad"),
        ("Movies/x.mkv.exe", "heuristics", "double_extension"),
        ("Movies/x.mkv.exe", "heuristics", "executable_in_media_folder"),
    ]
    first_seen = files()["Movies/x.mkv.exe"].last_scanned

    # The engine is down during the next read: its earlier finding is kept.
    flagger.down = True
    put(scan_root, "Movies/x.mkv.exe", b"BAD stuff, edited")
    run = scan(pipeline=pipeline)
    assert "flagger skipped 1 files (flagger is down)" in run.message
    assert ("Movies/x.mkv.exe", "flagger", "bad") in detections()
    assert files()["Movies/x.mkv.exe"].last_scanned > first_seen

    # Back up, and the content is clean now: the finding goes.
    flagger.down = False
    put(scan_root, "Movies/x.mkv.exe", b"clean now")
    scan(pipeline=pipeline)
    assert [d[1] for d in detections()] == ["heuristics", "heuristics"]


def test_large_media_gets_a_partial_scan(scan_root, monkeypatch):
    from nasscan.scanner import hashing

    monkeypatch.setenv("NASSCAN_LARGE_FILE_MB", "16")
    monkeypatch.setenv("NASSCAN_PARTIAL_CHUNK_MB", "1")
    get_settings.cache_clear()
    monkeypatch.setattr(hashing, "detect_type", lambda head: ("video/mp4", "ISO Media"))
    put(scan_root, "movies/film.mp4", b"z" * (17 * 1024 * 1024))
    run = scan()
    f = files()["movies/film.mp4"]
    assert (f.scan_mode, f.sha256, f.mime) == ("partial", None, "video/mp4")
    assert run.bytes_hashed == 2 * 1024 * 1024
    assert scan().files_hashed == 0  # unchanged: not read again
