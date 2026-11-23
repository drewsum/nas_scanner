"""The local engines: heuristics, documents, 3D-print files, and the pipeline around them."""

import io
import struct
import zipfile

import pytest

from nasscan.config import Settings
from nasscan.scanner.engines import Pipeline
from nasscan.scanner.engines.base import (
    MEMORY,
    PARTIAL,
    Engine,
    EngineUnavailableError,
    FileContext,
    Finding,
)
from nasscan.scanner.engines.documents import DocumentsEngine, pdf_names
from nasscan.scanner.engines.heuristics import (
    HeuristicsEngine,
    bidi_name,
    disguised_executable,
    double_extension,
    misplaced_executable,
)
from nasscan.scanner.engines.printing import PrintingEngine, check_gcode, check_stl


def ctx(path, data=b"", mime=None, mode=MEMORY, **kw) -> FileContext:
    ext = path.rsplit(".", 1)[-1].lower() if "." in path.rsplit("/", 1)[-1] else None
    return FileContext(
        path=path,
        full_path=None,
        size=kw.pop("size", len(data)),
        extension=ext,
        mime=mime,
        magic=None,
        mode=mode,
        data=data if mode == MEMORY else None,
        head=kw.pop("head", data[:1024]),
        **kw,
    )


def names(findings):
    return sorted(f.name for f in findings)


# --- heuristics ------------------------------------------------------------------------------


def test_double_extension():
    assert double_extension("movie.mkv.exe").details == {
        "inner": "mkv",
        "outer": "exe",
        "padded": False,
    }
    assert double_extension("invoice.pdf      .scr").details["padded"] is True
    assert double_extension("Report.Final.PDF.js") is not None
    assert double_extension("archive.tar.gz") is None
    assert double_extension("setup.exe") is None
    assert double_extension("holiday.2024.mkv") is None


def test_disguised_executable():
    assert disguised_executable("x.mkv", "mkv", "application/x-dosexec") is not None
    assert disguised_executable("x.pdf", "pdf", "application/x-executable") is not None
    assert disguised_executable("x.exe", "exe", "application/x-dosexec") is None
    assert disguised_executable("x.mkv", "mkv", "video/x-matroska") is None


def test_misplaced_executable():
    folders = Settings().media_folder_names
    hit = misplaced_executable("Movies/Film (2020)/setup.exe", "exe", None, folders)
    assert hit is not None and hit.details["folder"] == "movies"
    assert misplaced_executable("Music/x/run.bat", "bat", None, folders) is not None
    assert misplaced_executable("Photos/IMG_1.jpg", "jpg", "image/jpeg", folders) is None
    assert misplaced_executable("Software/setup.exe", "exe", None, folders) is None
    # A program's own media folders don't count, but a software folder inside your media does.
    vscode = "home/me/.vscode-server/bin/abc/out/vs/terminal/browser/media/shellIntegration.ps1"
    assert misplaced_executable(vscode, "ps1", None, folders) is None
    assert misplaced_executable("dev/node_modules/x/images/run.js", "js", None, folders) is None
    assert misplaced_executable("Movies/node_modules/run.js", "js", None, folders) is not None
    # A program without a telling extension is still a program.
    assert misplaced_executable("tv/show/ep1", None, "application/x-dosexec", folders)


def test_bidi_override():
    assert bidi_name("invoice‮gpj.exe") is not None
    assert bidi_name("invoice.jpg") is None


def test_heuristics_engine_combines_rules():
    engine = HeuristicsEngine(Settings())
    found = engine.scan(ctx("Movies/new.mkv.exe", mime="application/x-dosexec"))
    assert names(found) == ["double_extension", "executable_in_media_folder"]
    assert engine.scan(ctx("Movies/new.mkv", mime="video/x-matroska")) == []


# --- documents -------------------------------------------------------------------------------

PDF_JS = b"%PDF-1.7\n1 0 obj << /OpenAction 2 0 R >> endobj\n2 0 obj << /S /JavaScript /JS (x) >>"


def test_pdf_names_and_obfuscation():
    counts, obfuscated = pdf_names(PDF_JS)
    assert counts["OpenAction"] == 1 and counts["JavaScript"] == 1 and counts["JS"] == 1
    assert obfuscated == 0
    counts, obfuscated = pdf_names(b"/J#61vaScript /OpenAction")
    assert counts["JavaScript"] == 1 and obfuscated == 1


def test_pdf_findings():
    engine = DocumentsEngine(Settings())
    found = engine.scan(ctx("a.pdf", PDF_JS, "application/pdf"))
    assert names(found) == ["pdf_javascript"] and found[0].severity == "suspicious"
    plain = engine.scan(ctx("b.pdf", b"%PDF-1.4\n/JavaScript (x)", "application/pdf"))
    assert plain[0].severity == "info"  # JavaScript that doesn't run on open
    launch = engine.scan(ctx("c.pdf", b"%PDF-1.4 /Launch /EmbeddedFile", "application/pdf"))
    assert names(launch) == ["pdf_embedded_file", "pdf_launch"]
    assert engine.scan(ctx("d.pdf", b"%PDF-1.4 /Type /Catalog", "application/pdf")) == []


VBA = b'Attribute VB_Name = "Module1"\r\nSub AutoOpen()\r\n  Shell "cmd.exe /c calc"\r\nEnd Sub\r\n'


def test_office_macros():
    engine = DocumentsEngine(Settings())
    found = engine.scan(ctx("invoice.docm", VBA))
    assert names(found) == ["office_macro_autoexec_suspicious"]
    assert "AutoOpen" in found[0].details["autoexec"]
    tame = engine.scan(ctx("x.doc", b'Attribute VB_Name = "M"\r\nSub Hello()\r\nEnd Sub\r\n'))
    assert names(tame) == ["office_macros"] and tame[0].severity == "info"
    assert engine.scan(ctx("notes.doc", b"just some text, no code")) == []
    assert not engine.applies(ctx("movie.mkv", b"x", "video/x-matroska"))


# --- 3D printing -----------------------------------------------------------------------------


def binary_stl(triangles: int) -> bytes:
    return b"\0" * 80 + struct.pack("<I", triangles) + b"\0" * (50 * triangles)


def test_stl_validation():
    data = binary_stl(3)
    assert check_stl(len(data), data) is None
    ascii_stl = b"solid cube\n facet normal 0 0 1\n outer loop\n"
    assert check_stl(10_000, ascii_stl) is None
    bad = b"MZ\x90\x00" + b"\0" * 200
    assert check_stl(len(bad), bad).name == "stl_invalid"
    truncated = binary_stl(3)[:-10]
    assert check_stl(len(truncated), truncated) is not None


def test_gcode_rules():
    gcode = (
        b"; generated by PrusaSlicer https://prusa3d.com\nG28\nG1 X10 Y10\n"
        b"RUN_SHELL_COMMAND CMD=backup\nM997\nM500\n"
    )
    found = {f.name: f for f in check_gcode(gcode)}
    assert set(found) == {"gcode_shell_command", "gcode_firmware_update", "gcode_settings_write"}
    assert found["gcode_shell_command"].severity == "suspicious"
    assert check_gcode(b"G28\nG1 X1\n; https://example.com in a comment\n") == []
    assert names(check_gcode(b"G1 X1 ; ok\nM118 http://x.example/a\n")) == ["gcode_url"]
    assert names(check_gcode(b"G28\n\0\0\x01binary")) == ["gcode_binary"]


def make_zip(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in members.items():
            z.writestr(name, data)
    return buf.getvalue()


def test_3mf_members_are_checked_and_handed_on():
    data = make_zip(
        {
            "3D/3dmodel.model": b"<model/>",
            "Metadata/run.bat": b"@echo off",
            "Metadata/thumbnail.png": b"MZ\x90\x00 not really a png",
        }
    )
    engine = PrintingEngine(Settings())
    c = ctx("prints/benchy.3mf", data)
    found = engine.scan(c)
    assert [f.details["member"] for f in found] == ["Metadata/run.bat", "Metadata/thumbnail.png"]
    assert {e.name for e in c.embedded} == set(zipfile.ZipFile(io.BytesIO(data)).namelist())


def test_3mf_that_isnt_a_zip():
    assert names(PrintingEngine(Settings()).scan(ctx("x.3mf", b"not a zip"))) == ["3mf_not_zip"]
    assert PrintingEngine(Settings()).scan(ctx("x.amf", b"<amf></amf>")) == []


def test_zip_bombs_are_flagged_not_unpacked(monkeypatch):
    from nasscan.scanner.engines import printing

    monkeypatch.setattr(printing, "ZIP_BOMB_MIN", 1024 * 1024)
    data = make_zip({"3D/3dmodel.model": b"\0" * (2 * 1024 * 1024)})
    c = ctx("bomb.3mf", data)
    assert names(PrintingEngine(Settings()).scan(c)) == ["zip_bomb"]
    assert c.embedded == []


# --- pipeline --------------------------------------------------------------------------------


class Marker(Engine):
    """Flags any content containing b'EVIL'."""

    name = "marker"

    def scan(self, c):
        data = c.data or c.head
        return [Finding("marker", "evil", "malicious", "evil", member=c.member)] * (b"EVIL" in data)


class Broken(Engine):
    name = "broken"

    def scan(self, c):
        raise EngineUnavailableError("down")


def test_pipeline_scans_embedded_members_and_collects_errors():
    s = Settings()
    pipeline = Pipeline(s, [Marker(s), PrintingEngine(s), Broken(s)])
    data = make_zip({"3D/3dmodel.model": b"<model/>", "Metadata/x.bin": b"..EVIL.."})
    result = pipeline.scan(ctx("p.3mf", data))
    assert [(f.name, f.member) for f in result.findings] == [("evil", "Metadata/x.bin")]
    assert result.errors == {"broken": "down"}


def test_pipeline_keeps_going_when_an_engine_crashes():
    class Crashing(Engine):
        name = "crashing"

        def scan(self, c):
            raise ValueError("bad file")

    s = Settings()
    result = Pipeline(s, [Crashing(s), Marker(s)]).scan(ctx("a.bin", b"EVIL"))
    assert names(result.findings) == ["evil"]
    assert "ValueError" in result.errors["crashing"]


def test_partial_contexts_only_offer_head_and_tail():
    c = ctx("big.mkv", mode=PARTIAL, head=b"H" * 10, tail=b"T" * 10, size=10**10)
    assert c.pieces() == [("head", b"H" * 10), ("tail", b"T" * 10)]
    with pytest.raises(ValueError):
        list(c.stream())
