"""Reading files: SHA-256, SHA-1 and MD5 in one pass, the real type from libmagic, and a
read-rate limit shared by every worker."""

import hashlib
import logging
import sys
import threading
import time
from dataclasses import dataclass

log = logging.getLogger(__name__)

CHUNK = 1024 * 1024
# libmagic looks at the start of a file; this much of it is plenty.
MAGIC_BYTES = 64 * 1024


class Stopped(Exception):
    """The scanner is shutting down; the file wasn't finished."""


class Throttle:
    """Token bucket over bytes read, shared by all worker threads. 0 MB/s: unlimited."""

    def __init__(self, mb_per_second: float, clock=time.monotonic, sleep=time.sleep) -> None:
        self.rate = mb_per_second * 1024 * 1024
        self._clock, self._sleep = clock, sleep
        self._lock = threading.Lock()
        self._next = clock()  # when the bucket is next free

    def consume(self, n: int) -> None:
        if self.rate <= 0:
            return
        with self._lock:
            now = self._clock()
            start = max(now, self._next)
            self._next = start + n / self.rate
            wait = start - now
        if wait > 0:
            self._sleep(wait)


@dataclass(frozen=True)
class FileDigest:
    sha256: str
    sha1: str
    md5: str
    size: int  # bytes actually read
    mime: str | None
    magic: str | None


_local = threading.local()


_magic_lock = threading.Lock()
_magic_ok: bool | None = None


def _magic_available() -> bool:
    """Whether libmagic loads; decided once, by whichever worker thread asks first."""
    global _magic_ok
    with _magic_lock:
        if _magic_ok is None:
            if sys.platform == "win32":
                # python-magic can crash loading a stray magic DLL on Windows; the image and
                # CI run Linux, so a Windows dev box just goes without file types.
                _magic_ok = False
            else:
                try:
                    import magic  # noqa: F401
                except ImportError as exc:
                    log.warning("libmagic unavailable, file types won't be detected: %s", exc)
                    _magic_ok = False
                else:
                    _magic_ok = True
        return _magic_ok


def detect_type(head: bytes) -> tuple[str | None, str | None]:
    """(MIME type, description) of a file from its first bytes."""
    if not _magic_available():
        return None, None
    import magic

    # libmagic handles aren't thread-safe: one pair per thread.
    if not hasattr(_local, "mime"):
        _local.mime = magic.Magic(mime=True)
        _local.desc = magic.Magic()
    try:
        return _local.mime.from_buffer(head), _local.desc.from_buffer(head)[:2000]
    except Exception as exc:  # a malformed file mustn't stop the scan
        log.debug("libmagic failed: %s", exc)
        return None, None


def digest_file(
    path: bytes | str,
    throttle: Throttle | None = None,
    stop: threading.Event | None = None,
) -> FileDigest:
    """Read a file once, in chunks: memory stays at one chunk whatever its size."""
    sha256, sha1, md5 = hashlib.sha256(), hashlib.sha1(), hashlib.md5()
    head = b""
    size = 0
    with open(path, "rb", buffering=0) as f:
        while True:
            if stop is not None and stop.is_set():
                raise Stopped
            chunk = f.read(CHUNK)
            if not chunk:
                break
            if throttle:
                throttle.consume(len(chunk))
            if len(head) < MAGIC_BYTES:
                head += chunk[: MAGIC_BYTES - len(head)]
            sha256.update(chunk)
            sha1.update(chunk)
            md5.update(chunk)
            size += len(chunk)
    mime, desc = detect_type(head)
    return FileDigest(sha256.hexdigest(), sha1.hexdigest(), md5.hexdigest(), size, mime, desc)
