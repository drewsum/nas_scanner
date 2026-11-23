"""Heuristics from a file's name, real type and location: the tricks malware uses to get
opened (movie.mkv.exe, an executable named .pdf, a script in the Movies folder)."""

import re
from pathlib import PurePosixPath

from nasscan.config import Settings
from nasscan.scanner.engines.base import Engine, FileContext, Finding
from nasscan.scanner.engines.types import (
    BENIGN_EXTENSIONS,
    EXECUTABLE_EXTENSIONS,
    EXECUTABLE_MIMES,
    is_executable,
)

NAME = "heuristics"
# Unicode tricks that change how a name reads: right-to-left override and friends.
BIDI_CONTROLS = re.compile("[‪-‮⁦-⁩‎‏]")


def double_extension(name: str) -> Finding | None:
    """'movie.mkv.exe', 'invoice.pdf   .scr': a harmless-looking extension in front of one
    that runs."""
    parts = name.lower().split(".")
    if len(parts) < 3:
        return None
    inner, outer = parts[-2].strip(), parts[-1].strip()
    if inner in BENIGN_EXTENSIONS and outer in EXECUTABLE_EXTENSIONS:
        padded = parts[-2] != parts[-2].rstrip()
        return Finding(
            engine=NAME,
            name="double_extension",
            severity="suspicious",
            description=f"Named like a .{inner} file but is a .{outer}"
            + (" (padded with spaces to hide it)" if padded else ""),
            details={"inner": inner, "outer": outer, "padded": padded},
        )
    return None


def disguised_executable(name: str, extension: str | None, mime: str | None) -> Finding | None:
    """An executable whose name says media, image or document."""
    if mime in EXECUTABLE_MIMES and extension in BENIGN_EXTENSIONS:
        return Finding(
            engine=NAME,
            name="disguised_executable",
            severity="suspicious",
            description=f"A program ({mime}) named as a .{extension} file",
            details={"extension": extension, "mime": mime},
        )
    return None


def misplaced_executable(
    path: str, extension: str | None, mime: str | None, media_folders: set[str]
) -> Finding | None:
    """Executables, scripts and shortcuts in a folder for media or documents."""
    if not is_executable(extension, mime):
        return None
    folders = [p.lower() for p in PurePosixPath(path).parts[:-1]]
    hit = next((f for f in folders if f in media_folders), None)
    if hit is None:
        return None
    return Finding(
        engine=NAME,
        name="executable_in_media_folder",
        severity="suspicious",
        description=f"A program or script inside a '{hit}' folder",
        details={"folder": hit, "extension": extension, "mime": mime},
    )


def bidi_name(name: str) -> Finding | None:
    """Right-to-left override in a name: 'invoice‮gpj.exe' shows as 'invoiceexe.jpg'."""
    if not BIDI_CONTROLS.search(name):
        return None
    return Finding(
        engine=NAME,
        name="bidi_override_in_name",
        severity="suspicious",
        description="The name contains invisible characters that reverse how it reads",
        details={"name": name.encode("unicode_escape").decode()},
    )


class HeuristicsEngine(Engine):
    name = NAME

    def __init__(self, settings: Settings) -> None:
        super().__init__(settings)
        self.media_folders = settings.media_folder_names

    def scan(self, ctx: FileContext) -> list[Finding]:
        path = (ctx.member and f"{ctx.path}/{ctx.member}") or ctx.path
        candidates = [
            double_extension(ctx.name),
            disguised_executable(ctx.name, ctx.extension, ctx.mime),
            bidi_name(ctx.name),
            None if ctx.member else misplaced_executable(
                path, ctx.extension, ctx.mime, self.media_folders
            ),
        ]  # fmt: skip
        return [
            Finding(**{**f.__dict__, "member": ctx.member}) for f in candidates if f is not None
        ]
