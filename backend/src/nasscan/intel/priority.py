"""Which files are worth a live lookup, and in what order.

Free tiers allow a few hundred to a few thousand lookups a day, and a NAS holds millions of
files, nearly all of them photos, films and documents nobody has ever submitted anywhere.
So live providers only see files that can run code or hide it, plus anything the local
engines flagged. Everything with a hash is still matched against the downloaded feeds.
"""

from collections.abc import Iterable

from nasscan.scanner.engines.base import Finding
from nasscan.scanner.engines.types import (
    BENIGN_EXTENSIONS,
    EXECUTABLE_EXTENSIONS,
    EXECUTABLE_MIMES,
    OFFICE_EXTENSIONS,
)

SCRIPT_EXTENSIONS = {"bat", "cmd", "ps1", "psm1", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta",
                     "sh", "reg", "scf", "url", "lnk"}  # fmt: skip
MACRO_EXTENSIONS = {"docm", "dotm", "xlsm", "xltm", "xlam", "xlsb", "pptm", "potm", "ppsm",
                    "doc", "xls", "ppt", "rtf"}  # fmt: skip
ARCHIVE_EXTENSIONS = {"zip", "rar", "7z", "gz", "tgz", "bz2", "xz", "tar", "cab", "iso", "img",
                      "vhd", "vhdx", "dmg", "arj", "lzh", "ace", "z", "zst"}  # fmt: skip
ARCHIVE_MIMES = {"application/zip", "application/x-rar", "application/vnd.rar",
                 "application/x-7z-compressed", "application/gzip", "application/x-tar",
                 "application/x-xz", "application/x-bzip2", "application/vnd.ms-cab-compressed",
                 "application/x-iso9660-image", "application/x-cpio",
                 "application/zstd"}  # fmt: skip

# Higher goes first.
LOCALLY_MALICIOUS = 100
LOCALLY_SUSPICIOUS = 90
DISGUISED = 85
EXECUTABLE = 80
SCRIPT = 75
MACROS = 60
MACRO_FORMAT = 55
ARCHIVE = 50
LOCAL_INFO = 40
PDF = 20
NONE = 0


def priority_for(extension: str | None, mime: str | None, findings: Iterable[Finding] = ()) -> int:
    best = NONE
    for f in findings:
        if f.severity == "malicious":
            best = max(best, LOCALLY_MALICIOUS)
        elif f.engine == "heuristics":
            best = max(best, DISGUISED)  # a program posing as a film, say
        elif f.severity == "suspicious":
            best = max(best, LOCALLY_SUSPICIOUS)
        elif f.engine == "documents" and "macro" in (f.name + f.description).lower():
            best = max(best, MACROS)
        else:
            best = max(best, LOCAL_INFO)
    mime = mime or ""
    if mime in EXECUTABLE_MIMES or (extension in EXECUTABLE_EXTENSIONS and extension not in
                                    SCRIPT_EXTENSIONS):  # fmt: skip
        best = max(best, EXECUTABLE)
    elif extension in SCRIPT_EXTENSIONS:
        best = max(best, SCRIPT)
    if extension in MACRO_EXTENSIONS:
        best = max(best, MACRO_FORMAT)
    # Zip-based formats (3MF, DOCX, EPUB) are typed as zips; their name says what they are.
    known_format = extension in BENIGN_EXTENSIONS or extension in OFFICE_EXTENSIONS
    if extension in ARCHIVE_EXTENSIONS or (mime in ARCHIVE_MIMES and not known_format):
        best = max(best, ARCHIVE)
    if extension == "pdf" or mime == "application/pdf":
        best = max(best, PDF)
    return best
