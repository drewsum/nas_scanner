"""What every scanning engine shares: the file being scanned and what an engine reports."""

import os
from abc import ABC, abstractmethod
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

from nasscan.config import Settings

# Reading modes. memory: the whole file is in ``data``. file: too big to hold, so engines
# read it from ``full_path`` themselves. partial: a large media file, of which only ``head``
# and ``tail`` were read.
MEMORY, FILE, PARTIAL = "memory", "file", "partial"


class EngineUnavailableError(RuntimeError):
    """The engine can't scan right now (clamd down, no rules yet); not the file's fault."""


@dataclass
class Embedded:
    """Content found inside a file (a 3MF member, say), to be scanned in its own right."""

    name: str
    data: bytes


@dataclass(frozen=True)
class Finding:
    engine: str
    name: str
    severity: str  # info | suspicious | malicious
    description: str
    details: dict = field(default_factory=dict)
    member: str = ""  # set for findings in embedded content


@dataclass
class FileContext:
    path: str  # relative display path
    full_path: bytes | None  # None for embedded content
    size: int
    extension: str | None
    mime: str | None
    magic: str | None
    mode: str
    data: bytes | None = None  # MEMORY
    # The first and last bytes read (up to NASSCAN_PARTIAL_CHUNK_MB each); in PARTIAL mode
    # that's all there is. Empty tail in MEMORY mode.
    head: bytes = b""
    tail: bytes = b""
    member: str = ""  # for embedded content: its name inside the parent
    # The scanner's read limit, applied when an engine reads the file again (FILE mode).
    throttle: Any = None
    # Content an engine found inside this file (3MF members), scanned after it.
    embedded: list["Embedded"] = field(default_factory=list)

    @property
    def name(self) -> str:
        return os.path.basename(self.member or self.path)

    def pieces(self) -> list[tuple[str, bytes]]:
        """What can be scanned without reading the file again."""
        if self.mode == MEMORY:
            return [("", self.data or b"")]
        if self.mode == PARTIAL:
            return [("head", self.head), ("tail", self.tail)]
        return []

    def stream(self, chunk: int = 1024 * 1024) -> Iterator[bytes]:
        """The whole content, in chunks: from memory, or read again from disk (FILE)."""
        if self.mode == MEMORY:
            yield self.data or b""
            return
        if self.mode == PARTIAL or self.full_path is None:
            raise ValueError("only head and tail of this file were read")
        with open(self.full_path, "rb") as f:
            while block := f.read(chunk):
                if self.throttle is not None:
                    self.throttle.consume(len(block))
                yield block


class Engine(ABC):
    name: str

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def enabled(self) -> bool:
        return True

    def applies(self, ctx: FileContext) -> bool:
        """Cheap check before scan(), from the name and type."""
        return True

    @abstractmethod
    def scan(self, ctx: FileContext) -> list[Finding]:
        """Findings for this file. Content inside it that the other engines should scan
        too goes into ``ctx.embedded``."""
