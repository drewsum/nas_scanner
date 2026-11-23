"""Active content in documents: Office macros (oletools' olevba) and PDF features that run
code or open things (JavaScript, OpenAction, Launch, embedded files)."""

import logging
import os
import re
from collections import Counter

from nasscan.config import Settings
from nasscan.scanner.engines.base import MEMORY, Engine, FileContext, Finding
from nasscan.scanner.engines.types import OFFICE_EXTENSIONS, OFFICE_MIME_MARKERS

log = logging.getLogger(__name__)

NAME = "documents"
# PDF names that matter, as pdfid counts them.
PDF_KEYS = ("JavaScript", "JS", "OpenAction", "AA", "Launch", "EmbeddedFile", "RichMedia",
            "XFA", "SubmitForm", "ImportData")  # fmt: skip
PDF_NAME = re.compile(rb"/([A-Za-z0-9#]{2,40})")
HEX_ESCAPE = re.compile(rb"#([0-9A-Fa-f]{2})")
VBA_CODE = re.compile(rb"^\s*(Private |Public )?(Sub|Function)\s+\w+", re.I | re.M)
# PDFs bigger than this in FILE mode are read in pieces of this size (with overlap).
PDF_PIECE = 8 * 1024 * 1024


def is_office(ctx: FileContext) -> bool:
    mime = ctx.mime or ""
    return ctx.extension in OFFICE_EXTENSIONS or any(m in mime for m in OFFICE_MIME_MARKERS)


def is_pdf(ctx: FileContext) -> bool:
    return ctx.mime == "application/pdf" or ctx.extension == "pdf" or ctx.head[:5] == b"%PDF-"


def pdf_names(data: bytes) -> tuple[Counter, int]:
    """How often each interesting name appears, and how many were written with #xx escapes
    (an old trick to hide /JavaScript from naive scanners)."""
    counts: Counter = Counter()
    obfuscated = 0
    for raw in PDF_NAME.findall(data):
        name = raw
        if b"#" in raw:
            name = HEX_ESCAPE.sub(lambda m: bytes([int(m.group(1), 16)]), raw)
        text = name.decode("latin-1")
        if text in PDF_KEYS:
            counts[text] += 1
            obfuscated += name != raw
    return counts, obfuscated


def pdf_findings(counts: Counter, obfuscated: int) -> list[Finding]:
    found = {k: v for k, v in counts.items() if v}
    if not found:
        return []
    runs_code = bool(found.get("JavaScript") or found.get("JS"))
    auto = bool(found.get("OpenAction") or found.get("AA"))
    findings = []
    if found.get("Launch"):
        findings.append(
            Finding(
                NAME,
                "pdf_launch",
                "suspicious",
                "PDF can launch a program or file (/Launch)",
                found,
            )
        )
    if runs_code:
        findings.append(
            Finding(
                NAME,
                "pdf_javascript",
                "suspicious" if auto else "info",
                "PDF contains JavaScript" + (" that runs when it opens" if auto else ""),
                found,
            )
        )
    if found.get("EmbeddedFile"):
        findings.append(
            Finding(
                NAME,
                "pdf_embedded_file",
                "suspicious" if runs_code or auto else "info",
                "PDF carries embedded files",
                found,
            )
        )
    if obfuscated:
        findings.append(
            Finding(
                NAME,
                "pdf_obfuscated_names",
                "suspicious",
                "PDF hides keywords with #xx escapes",
                {**found, "obfuscated": obfuscated},
            )
        )
    return findings  # fmt: skip


class DocumentsEngine(Engine):
    name = NAME

    def __init__(self, settings: Settings) -> None:
        super().__init__(settings)
        self.memory_limit = settings.memory_read_mb * 1024 * 1024

    def applies(self, ctx: FileContext) -> bool:
        return is_office(ctx) or is_pdf(ctx)

    def scan(self, ctx: FileContext) -> list[Finding]:
        findings: list[Finding] = []
        if is_pdf(ctx):
            findings += self._pdf(ctx)
        elif is_office(ctx):
            findings += self._office(ctx)
        return [Finding(**{**f.__dict__, "member": ctx.member}) for f in findings]

    def _pdf(self, ctx: FileContext) -> list[Finding]:
        counts: Counter = Counter()
        obfuscated = 0
        pieces = [ctx.data or b""] if ctx.mode == MEMORY else self._pieces(ctx)
        for data in pieces:
            c, o = pdf_names(data)
            counts += c
            obfuscated += o
        return pdf_findings(counts, obfuscated)

    def _pieces(self, ctx: FileContext):
        carry = b""
        for block in ctx.stream(PDF_PIECE):
            yield carry + block
            carry = block[-64:]  # a name split between pieces is still seen

    def _office(self, ctx: FileContext) -> list[Finding]:
        from oletools.olevba import VBA_Parser

        if ctx.mode == MEMORY:
            parser = VBA_Parser(ctx.name, data=ctx.data)
        elif ctx.full_path is not None and ctx.size <= 4 * self.memory_limit:
            parser = VBA_Parser(os.fsdecode(ctx.full_path))
        else:
            return []  # a huge document, or one only partially read: leave it to the AV
        try:
            if parser.type == "Text" and not VBA_CODE.search(ctx.data or b""):
                return []  # olevba calls any plain text "macros"; real VBA has procedures
            if not parser.detect_vba_macros() and not getattr(parser, "contains_xlm_macros", 0):
                return []
            results = parser.analyze_macros() or []
        finally:
            parser.close()
        kinds: dict[str, list[str]] = {}
        for kind, keyword, _description in results:
            kinds.setdefault(kind, [])
            if keyword not in kinds[kind] and len(kinds[kind]) < 20:
                kinds[kind].append(str(keyword))
        details = {k.lower().replace(" ", "_").replace("-", "_"): v for k, v in kinds.items()}
        autoexec = "AutoExec" in kinds
        suspicious = "Suspicious" in kinds
        if autoexec and suspicious:
            return [
                Finding(
                    NAME,
                    "office_macro_autoexec_suspicious",
                    "suspicious",
                    "Office macros that run on open and use risky features "
                    f"({', '.join(kinds['Suspicious'][:5])})",
                    details,
                )
            ]
        if autoexec or suspicious:
            return [
                Finding(
                    NAME,
                    "office_macro_risky",
                    "suspicious",
                    "Office macros that " + ("run on open" if autoexec else "use risky features"),
                    details,
                )
            ]
        return [Finding(NAME, "office_macros", "info", "Document contains macros", details)]
