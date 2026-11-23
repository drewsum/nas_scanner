import os
import sys

import pytest

from nasscan.scanner.walker import Excluder, FoundFile, WalkError, storable, walk

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX filesystem features")


def make_tree(root, files):
    for rel, content in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(content)


def found(root, start="", patterns=()):
    return [i for i in walk(str(root), start, Excluder(list(patterns)))]


def paths(items):
    return [i.path for i in items if isinstance(i, FoundFile)]


def test_walks_every_regular_file_in_name_order(tmp_path):
    make_tree(tmp_path, {"b.txt": b"b", "a/x.bin": b"xx", "a/sub/y.mkv": b"y", "c/z": b""})
    items = found(tmp_path)
    assert paths(items) == ["b.txt", "a/x.bin", "a/sub/y.mkv", "c/z"]
    x = next(i for i in items if i.path == "a/x.bin")
    assert x.size == 2 and x.mtime_ns > 0 and os.path.exists(x.full_path)


def test_start_folder(tmp_path):
    make_tree(tmp_path, {"a/x": b"", "a/sub/y": b"", "b/z": b""})
    assert paths(found(tmp_path, "a/")) == ["a/x", "a/sub/y"]


def test_excludes_by_name_anywhere_and_by_path(tmp_path):
    make_tree(
        tmp_path,
        {
            "keep.txt": b"",
            ".zfs/snapshot/old.txt": b"",
            "deep/ix-apps/app.db": b"",
            "apps/nas_scanner/db/base": b"",
            "apps/other/f": b"",
            "media/a/cache/c": b"",
            "media/a/movie.mkv": b"",
            "x.Trash-1000/t": b"",
            ".Trash-1000/t": b"",
        },
    )
    patterns = [".zfs", "ix-apps", "apps/nas_scanner", "media/*/cache", ".Trash-*"]
    assert sorted(paths(found(tmp_path, patterns=patterns))) == [
        "apps/other/f",
        "keep.txt",
        "media/a/movie.mkv",
        "x.Trash-1000/t",
    ]


def test_excluder_matching():
    ex = Excluder([".zfs", "media/*/cache", "*.part"])
    assert ex.excluded(".zfs") and ex.excluded("a/b/.zfs")
    assert ex.excluded("media/x/cache") and not ex.excluded("media/x/y/cache")
    assert ex.excluded("dl/movie.mkv.part") and not ex.excluded("dl/movie.mkv")


@posix_only
def test_symlinks_and_special_files_are_skipped(tmp_path):
    make_tree(tmp_path, {"real/f.txt": b"data"})
    (tmp_path / "link.txt").symlink_to(tmp_path / "real/f.txt")
    (tmp_path / "linkdir").symlink_to(tmp_path / "real")
    os.mkfifo(tmp_path / "pipe")
    assert paths(found(tmp_path)) == ["real/f.txt"]


@posix_only
@pytest.mark.skipif(sys.platform != "win32" and os.geteuid() == 0, reason="root reads anything")
def test_unreadable_folder_is_reported_and_skipped(tmp_path):
    make_tree(tmp_path, {"ok/f": b"", "locked/g": b""})
    (tmp_path / "locked").chmod(0)
    try:
        items = found(tmp_path)
    finally:
        (tmp_path / "locked").chmod(0o755)
    assert paths(items) == ["ok/f"]
    errors = [i for i in items if isinstance(i, WalkError)]
    assert [(e.path, e.is_dir) for e in errors] == [("locked", True)]


@posix_only
def test_names_that_are_not_utf8_get_a_stable_display_path(tmp_path):
    raw = os.fsencode(str(tmp_path)) + b"/caf\xe9.txt"
    with open(raw, "wb") as f:
        f.write(b"x")
    (item,) = [i for i in found(tmp_path) if isinstance(i, FoundFile)]
    assert item.path == "caf\\xe9.txt"
    with open(item.full_path, "rb") as f:
        assert f.read() == b"x"


def test_missing_start_folder_is_an_error(tmp_path):
    items = found(tmp_path, "nope")
    assert len(items) == 1 and isinstance(items[0], WalkError) and items[0].is_dir


def test_deep_and_wide_trees_stream(tmp_path):
    deep = tmp_path
    for i in range(60):
        deep = deep / f"d{i}"
    deep.mkdir(parents=True)
    (deep / "leaf").write_bytes(b"")
    for i in range(300):
        (tmp_path / f"f{i:03}").write_bytes(b"")
    gen = walk(str(tmp_path))
    assert next(gen).path == "f000"  # a generator: files come out as folders are listed
    rest = paths(gen)
    assert len(rest) == 300 and rest[-1].endswith("/d59/leaf")


def test_out_of_range_timestamps_are_clamped_to_bigint():
    # Seen on a real NAS: a crash log whose mtime reads as the year 1601.
    assert storable(-11622159270858821800) == -(2**63)
    assert storable(2**64) == 2**63 - 1
    assert storable(1_700_000_000_000_000_000) == 1_700_000_000_000_000_000
