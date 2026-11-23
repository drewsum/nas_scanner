"""Walks the scan root, yielding regular files one at a time.

Streaming: the walk holds one directory listing per level of depth, never the whole tree.
Symlinks aren't followed (or reported), nor are other special files (FIFOs, sockets,
devices). Folders that can't be read are reported once and skipped, and the crawler leaves
the files it knew under them alone rather than marking them removed.
"""

import os
import stat
from collections.abc import Iterator
from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import PurePosixPath


@dataclass(frozen=True)
class FoundFile:
    path: str  # display path, relative to the root, '/'-separated
    full_path: bytes  # the real path, for opening
    size: int
    mtime_ns: int
    inode: int
    device: int


@dataclass(frozen=True)
class WalkError:
    path: str  # relative display path of the folder or file
    message: str
    is_dir: bool


# The database stores these in BIGINT columns. A corrupt timestamp (one seen in the wild
# reads as the year 1601) can be beyond that range, and one such file would fail the whole
# scan, so it's clamped to the nearest storable value.
INT64_MIN = -(2**63)
INT64_MAX = 2**63 - 1


def storable(n: int) -> int:
    """``n`` clamped into a signed 64-bit range."""
    return min(max(n, INT64_MIN), INT64_MAX)


def display(rel: bytes) -> str:
    """A filesystem path as text. Bytes that aren't UTF-8 become backslash escapes, so the
    result is always storable and the same path always gives the same text."""
    return rel.decode("utf-8", "backslashreplace")


class Excluder:
    """Matches relative paths against exclude patterns: a pattern without a slash matches a
    name at any depth, one with a slash matches the path from the root."""

    def __init__(self, patterns: list[str]) -> None:
        self.names = [p for p in patterns if "/" not in p]
        # Path patterns match segment by segment, so * never spans a slash.
        self.paths = [p.split("/") for p in patterns if "/" in p]

    def excluded(self, rel: str) -> bool:
        name = PurePosixPath(rel).name
        if any(fnmatchcase(name, p) for p in self.names):
            return True
        parts = rel.split("/")
        return any(len(parts) == len(p) and all(map(fnmatchcase, parts, p)) for p in self.paths)


def walk(
    root: str, start: str = "", exclude: Excluder | None = None
) -> Iterator[FoundFile | WalkError]:
    """Regular files under ``root``/``start``, depth first, plus a WalkError for each folder
    or file that couldn't be read."""
    exclude = exclude or Excluder([])
    base = os.fsencode(root).rstrip(b"/\\") or b"/"
    first = os.fsencode(start.strip("/"))
    stack: list[bytes] = [first]
    while stack:
        rel_dir = stack.pop()
        abs_dir = base + b"/" + rel_dir if rel_dir else base
        try:
            with os.scandir(abs_dir) as entries:
                listing = sorted(entries, key=lambda e: e.name)
        except OSError as exc:
            yield WalkError(display(rel_dir), exc.strerror or str(exc), is_dir=True)
            continue
        subdirs: list[bytes] = []
        for entry in listing:
            rel = rel_dir + b"/" + entry.name if rel_dir else entry.name
            text = display(rel)
            if exclude.excluded(text):
                continue
            try:
                st = entry.stat(follow_symlinks=False)
            except OSError as exc:
                yield WalkError(text, exc.strerror or str(exc), is_dir=False)
                continue
            if stat.S_ISDIR(st.st_mode):
                subdirs.append(rel)
            elif stat.S_ISREG(st.st_mode):
                yield FoundFile(
                    path=text,
                    full_path=entry.path,
                    size=st.st_size,
                    mtime_ns=storable(st.st_mtime_ns),
                    inode=st.st_ino,
                    device=st.st_dev,
                )
            # Symlinks, FIFOs, sockets and devices: skipped.
        # Pushed in reverse so the folders come off the stack in name order.
        stack.extend(reversed(subdirs))
