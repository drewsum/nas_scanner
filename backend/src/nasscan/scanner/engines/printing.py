"""3D-print files: 3MF and AMF (zip containers whose members are scanned like files), G-code
(commands that reach beyond printing) and STL (is it really an STL?)."""

import io
import os
import re
import struct
import zipfile

from nasscan.config import Settings
from nasscan.scanner.engines.base import MEMORY, PARTIAL, Embedded, Engine, FileContext, Finding
from nasscan.scanner.engines.types import EXECUTABLE_EXTENSIONS

NAME = "printing"
ZIP_EXTENSIONS = {"3mf", "amf"}
GCODE_EXTENSIONS = {"gcode", "gco", "g", "nc"}
# Signs of a program rather than print data, at the start of a member.
EXEC_MAGIC = (b"MZ", b"\x7fELF", b"#!", b"\xca\xfe\xba\xbe", b"\xcf\xfa\xed\xfe")
ZIP_BOMB_RATIO = 200
ZIP_BOMB_MIN = 100 * 1024 * 1024

# G-code worth a look. Klipper/RepRapFirmware/Marlin commands that run host programs, flash
# firmware or rewrite saved settings, and URLs.
GCODE_RULES = [
    ("gcode_shell_command", "suspicious", re.compile(rb"^\s*RUN_SHELL_COMMAND\b", re.I | re.M),
     "runs a shell command on the printer host"),
    ("gcode_firmware_update", "suspicious", re.compile(rb"^\s*M997\b", re.M),
     "starts a firmware update (M997)"),
    ("gcode_settings_write", "info", re.compile(rb"^\s*M50[02]\b", re.M),
     "saves or resets the printer's stored settings (M500/M502)"),
    ("gcode_url", "info", re.compile(rb"^[^;\n]*https?://", re.M | re.I),
     "contains a URL outside comments"),
    ("gcode_long_blob", "info", re.compile(rb"[A-Za-z0-9+/=]{2000,}"),
     "contains a long encoded blob"),
]  # fmt: skip


def check_stl(size: int, head: bytes) -> Finding | None:
    """Binary STL: 80-byte header, triangle count, 50 bytes per triangle. ASCII STL: starts
    with 'solid' and has facets. Anything else named .stl is flagged."""
    if size >= 84 and len(head) >= 84:
        (count,) = struct.unpack_from("<I", head, 80)
        if size == 84 + 50 * count:
            return None
    text = head[:4096].lstrip().lower()
    if text.startswith(b"solid") and (b"facet" in text or b"endsolid" in text or size < 4096):
        return None
    return Finding(NAME, "stl_invalid", "suspicious", "Named .stl but isn't a valid STL file",
                   {"size": size, "starts_with": head[:16].hex()})  # fmt: skip


def check_gcode(data: bytes) -> list[Finding]:
    if b"\0" in data[:65536]:
        return [Finding(NAME, "gcode_binary", "suspicious",
                        "Named as G-code but contains binary data", {})]  # fmt: skip
    findings = []
    for name, severity, pattern, what in GCODE_RULES:
        hits = pattern.findall(data)
        if hits:
            sample = [h.decode("latin-1", "replace").strip()[:120] for h in hits[:3]]
            findings.append(
                Finding(NAME, name, severity, f"G-code that {what}", {"count": len(hits),
                                                                      "sample": sample})
            )  # fmt: skip
    return findings


class PrintingEngine(Engine):
    name = NAME

    def __init__(self, settings: Settings) -> None:
        super().__init__(settings)
        self.embedded_max = settings.embedded_max_mb * 1024 * 1024
        self.memory_limit = settings.memory_read_mb * 1024 * 1024

    def applies(self, ctx: FileContext) -> bool:
        return ctx.extension in ZIP_EXTENSIONS | GCODE_EXTENSIONS | {"stl"}

    def scan(self, ctx: FileContext) -> list[Finding]:
        if ctx.extension == "stl":
            f = check_stl(ctx.size, ctx.data if ctx.mode == MEMORY else ctx.head)
            findings = [f] if f else []
        elif ctx.extension in GCODE_EXTENSIONS:
            findings = self._gcode(ctx)
        else:
            findings, members = self._container(ctx)
            if not ctx.member:  # members of members aren't unpacked
                ctx.embedded.extend(members)
        return [Finding(**{**f.__dict__, "member": ctx.member}) for f in findings]

    def _gcode(self, ctx: FileContext) -> list[Finding]:
        if ctx.mode == PARTIAL:
            return []
        if ctx.mode == MEMORY:
            return check_gcode(ctx.data or b"")
        findings: dict[str, Finding] = {}
        carry = b""
        for block in ctx.stream(4 * 1024 * 1024):
            cut = block.rfind(b"\n") + 1 or len(block)
            for f in check_gcode(carry + block[:cut]):
                findings.setdefault(f.name, f)
            carry = block[cut:]
        for f in check_gcode(carry):
            findings.setdefault(f.name, f)
        return list(findings.values())

    def _open_zip(self, ctx: FileContext) -> zipfile.ZipFile | None:
        if ctx.mode == MEMORY:
            source: io.BytesIO | str = io.BytesIO(ctx.data or b"")
        elif ctx.full_path is not None and ctx.mode != PARTIAL:
            source = os.fsdecode(ctx.full_path)
        else:
            return None
        try:
            return zipfile.ZipFile(source)
        except (zipfile.BadZipFile, OSError):
            return None

    def _container(self, ctx: FileContext) -> tuple[list[Finding], list[Embedded]]:
        z = self._open_zip(ctx)
        if z is None:
            if ctx.extension == "3mf":
                return [Finding(NAME, "3mf_not_zip", "suspicious",
                                "Named .3mf but isn't a 3MF (zip) package", {})], []  # fmt: skip
            return [], []  # AMF may be plain XML
        findings: list[Finding] = []
        members: list[Embedded] = []
        budget = self.embedded_max
        with z:
            infos = [i for i in z.infolist() if not i.is_dir()]
            total = sum(i.file_size for i in infos)
            packed = sum(i.compress_size for i in infos) or 1
            if total > ZIP_BOMB_MIN and total / packed > ZIP_BOMB_RATIO:
                return [
                    Finding(
                        NAME,
                        "zip_bomb",
                        "suspicious",
                        f"Expands {total // packed}x to {total} bytes",
                        {},
                    )
                ], []
            for info in infos:
                name = info.filename
                ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
                if ext in EXECUTABLE_EXTENSIONS:
                    findings.append(
                        Finding(
                            NAME,
                            "executable_in_print_file",
                            "suspicious",
                            f"Contains a program or script: {name}",
                            {"member": name},
                        )
                    )
                if info.file_size > min(budget, self.memory_limit):
                    continue
                try:
                    data = z.read(info)
                except (zipfile.BadZipFile, OSError, RuntimeError, NotImplementedError):
                    continue
                budget -= len(data)
                if data.startswith(EXEC_MAGIC) and ext not in EXECUTABLE_EXTENSIONS:
                    findings.append(
                        Finding(
                            NAME,
                            "executable_in_print_file",
                            "suspicious",
                            f"Contains a program disguised as {name}",
                            {"member": name},
                        )
                    )
                members.append(Embedded(name, data))
        return findings, members  # fmt: skip
