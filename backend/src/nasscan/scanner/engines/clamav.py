"""ClamAV, through the clamd service over TCP.

Files are streamed to clamd (INSTREAM) rather than scanned by path: the scanner has already
read them (the bytes are often still in memory), and clamd then needs no access to the NAS
data at all, so file permissions and mounts can't differ between the two containers. Files
bigger than NASSCAN_CLAMD_STREAM_MAX_MB, and large media read partially, are sent as their
head and tail.

Official signatures come from freshclam inside the clamd container, unofficial ones
(Sanesecurity, URLhaus, ...) from fangfrisch there (deploy/clamd).
"""

import logging
import re
import socket
import struct
import threading
import time
from collections.abc import Iterable
from datetime import datetime

from nasscan.config import Settings
from nasscan.scanner.engines.base import (
    FILE,
    Engine,
    EngineUnavailableError,
    FileContext,
    Finding,
)

log = logging.getLogger(__name__)

NAME = "clamav"
# clamd INSTREAM chunks; it takes any size up to StreamMaxLength in total.
SEND_CHUNK = 256 * 1024
# After clamd fails, files skip ClamAV for this long instead of each waiting for a timeout.
RETRY_SECONDS = 60.0
VERSION_RE = re.compile(r"^ClamAV ([^/]+)/(\d+)/(.+)$")


# Unofficial signature names that mean malware rather than phishing, spam or a bad URL.
MALWARE_WORDS = ("malware", "trojan", "virus", "worm", "exploit", "ransom", "backdoor",
                 "badmacro", "foxhole", "hackingteam", "rogue", "eicar")  # fmt: skip


class ClamdError(RuntimeError):
    pass


def severity_for(signature: str) -> str:
    """Official signatures are malicious. Unofficial sets (Sanesecurity and friends) mix
    malware with phishing, spam and URL lists: only their malware ones count as malicious.
    clamd reports one signature per file, the first that matched, so an unofficial name can
    stand for a file official signatures would call malware too."""
    if not signature.endswith(".UNOFFICIAL"):
        return "malicious"
    lowered = signature.lower()
    return "malicious" if any(w in lowered for w in MALWARE_WORDS) else "suspicious"


def parse_version(text: str) -> tuple[str, int | None, datetime | None]:
    """'ClamAV 1.4.1/27470/Sun Nov 22 08:30:00 2026' -> engine, database version, date."""
    m = VERSION_RE.match(text.strip())
    if not m:
        return text.strip(), None, None
    try:
        when = datetime.strptime(m.group(3).strip(), "%a %b %d %H:%M:%S %Y")
    except ValueError:
        when = None
    return m.group(1), int(m.group(2)), when


class ClamdClient:
    def __init__(self, host: str, port: int, timeout: float) -> None:
        self.host, self.port, self.timeout = host, port, timeout

    def _connect(self) -> socket.socket:
        try:
            return socket.create_connection((self.host, self.port), timeout=self.timeout)
        except OSError as exc:
            raise EngineUnavailableError(
                f"can't reach clamd at {self.host}:{self.port}: {exc}"
            ) from exc

    @staticmethod
    def _reply(sock: socket.socket) -> str:
        buf = bytearray()
        while not buf.endswith(b"\0"):
            block = sock.recv(4096)
            if not block:
                break
            buf += block
        return buf.rstrip(b"\0").decode("utf-8", "replace").strip()

    def command(self, cmd: str) -> str:
        with self._connect() as sock:
            sock.sendall(b"z" + cmd.encode() + b"\0")
            return self._reply(sock)

    def ping(self) -> bool:
        return self.command("PING") == "PONG"

    def version(self) -> str:
        return self.command("VERSION")

    def instream(self, chunks: Iterable[bytes]) -> str | None:
        """Scan a stream; the signature name if found, else None."""
        with self._connect() as sock:
            try:
                sock.sendall(b"zINSTREAM\0")
                for chunk in chunks:
                    for i in range(0, len(chunk), SEND_CHUNK):
                        part = chunk[i : i + SEND_CHUNK]
                        sock.sendall(struct.pack(">I", len(part)) + part)
                sock.sendall(struct.pack(">I", 0))
                reply = self._reply(sock)
            except OSError as exc:
                raise EngineUnavailableError(f"clamd connection failed: {exc}") from exc
        # "stream: OK", "stream: Win.Test.EICAR_HDB-1 FOUND", "... ERROR"
        body = reply.split(": ", 1)[-1]
        if body == "OK":
            return None
        if body.endswith(" FOUND"):
            return body[: -len(" FOUND")]
        raise ClamdError(reply)


class ClamavEngine(Engine):
    name = NAME

    def __init__(self, settings: Settings) -> None:
        super().__init__(settings)
        self.client = ClamdClient(
            settings.clamd_host or "", settings.clamd_port, settings.clamd_timeout
        )
        self.stream_max = settings.clamd_stream_max_mb * 1024 * 1024
        self._down_until = 0.0
        self._lock = threading.Lock()

    def enabled(self) -> bool:
        return bool(self.settings.clamd_host)

    def _streams(self, ctx: FileContext) -> list[tuple[str, Iterable[bytes]]]:
        if ctx.mode == FILE and ctx.size <= self.stream_max:
            return [("", ctx.stream())]
        if ctx.mode == FILE:
            return [("head", [ctx.head]), ("tail", [ctx.tail])]
        return [(part, [data]) for part, data in ctx.pieces()]

    def scan(self, ctx: FileContext) -> list[Finding]:
        with self._lock:
            if time.monotonic() < self._down_until:
                raise EngineUnavailableError("clamd was unreachable a moment ago")
        findings = []
        for part, chunks in self._streams(ctx):
            try:
                signature = self.client.instream(chunks)
            except EngineUnavailableError:
                with self._lock:
                    self._down_until = time.monotonic() + RETRY_SECONDS
                raise
            except ClamdError as exc:
                # E.g. a size limit: the file is fine, ClamAV just couldn't finish it.
                log.warning("clamd couldn't scan %s: %s", ctx.member or ctx.path, exc)
                continue
            if signature:
                unofficial = signature.endswith(".UNOFFICIAL")
                findings.append(
                    Finding(
                        engine=NAME,
                        name=signature,
                        severity=severity_for(signature),
                        description=f"ClamAV signature {signature}"
                        + (f" (in the file's {part})" if part else ""),
                        details={"signature": signature, "unofficial": unofficial, "part": part},
                        member=ctx.member,
                    )
                )
        return findings
