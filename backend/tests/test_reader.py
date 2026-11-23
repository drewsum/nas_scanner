"""read_file: one read per file, in memory, file or partial mode."""

import hashlib

import pytest

from nasscan.scanner import hashing
from nasscan.scanner.hashing import Stopped, Throttle, read_file

KB = 1024


def read(path, ext, **kw):
    opts = {"memory_limit": 10 * KB, "large_limit": 50 * KB, "piece": 4 * KB} | kw
    return read_file(path, path.stat().st_size, ext, **opts)


@pytest.fixture
def as_video(monkeypatch):
    monkeypatch.setattr(hashing, "detect_type", lambda head: ("video/x-matroska", "Matroska"))


def test_small_files_are_kept_in_memory(tmp_path):
    p = tmp_path / "a.txt"
    p.write_bytes(b"x" * 5000)
    r = read(p, "txt")
    assert r.mode == "memory" and r.data == p.read_bytes() and r.tail == b""
    assert r.digest.sha256 == hashlib.sha256(p.read_bytes()).hexdigest()
    assert r.bytes_read == 5000


def test_bigger_files_keep_head_and_tail(tmp_path, monkeypatch):
    monkeypatch.setattr(hashing, "CHUNK", 3 * KB)  # chunks that don't line up with pieces
    data = bytes(range(256)) * 100  # 25600 bytes
    p = tmp_path / "b.bin"
    p.write_bytes(data)
    r = read(p, "bin")
    assert r.mode == "file" and r.data is None
    assert r.head == data[: 4 * KB] and r.tail == data[-4 * KB :]
    assert r.digest.md5 == hashlib.md5(data).hexdigest()


def test_large_media_is_read_partially(tmp_path, as_video):
    data = b"H" * (8 * KB) + b"M" * (60 * KB) + b"T" * (8 * KB)
    p = tmp_path / "movie.mkv"
    p.write_bytes(data)
    r = read(p, "mkv")
    assert r.mode == "partial" and r.digest is None
    assert r.head == b"H" * (4 * KB) and r.tail == b"T" * (4 * KB)
    assert r.bytes_read == 8 * KB


def test_media_shortcut_needs_name_type_and_size(tmp_path, as_video, monkeypatch):
    big = b"z" * (60 * KB)
    p = tmp_path / "movie.exe"
    p.write_bytes(big)
    assert read(p, "exe").mode == "file"  # named otherwise: read whole
    q = tmp_path / "movie.mkv"
    q.write_bytes(big)
    assert read(q, "mkv", full_media=True).mode == "file"  # forced full read
    assert read(q, "mkv", large_limit=100 * KB).mode == "file"  # not large
    monkeypatch.setattr(hashing, "detect_type", lambda head: ("application/x-dosexec", "PE32"))
    assert read(q, "mkv").mode == "file"  # not really media: escalated to a full read


def test_reads_are_throttled_and_stoppable(tmp_path):
    p = tmp_path / "c.bin"
    p.write_bytes(b"x" * (3 * 1024 * 1024))
    used = []

    class Counting(Throttle):
        def consume(self, n):
            used.append(n)

    read(p, "bin", throttle=Counting(0))
    assert sum(used) == 3 * 1024 * 1024

    import threading

    stop = threading.Event()
    stop.set()
    with pytest.raises(Stopped):
        read(p, "bin", stop=stop)
