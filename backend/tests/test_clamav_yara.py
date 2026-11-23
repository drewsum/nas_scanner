"""ClamAV (against a fake clamd speaking the real protocol) and YARA (rules compiled locally)."""

import io
import socket
import struct
import threading
import zipfile
from datetime import datetime

import pytest

from nasscan.config import Settings
from nasscan.scanner.engines.base import FILE, MEMORY, EngineUnavailableError, FileContext
from nasscan.scanner.engines.clamav import ClamavEngine, ClamdClient, parse_version
from nasscan.scanner.engines.clamav import severity_for as clam_severity
from nasscan.scanner.engines.yara_rules import RuleStore, YaraEngine
from nasscan.scanner.engines.yara_rules import severity_for as yara_severity

# Assembled at runtime so this file doesn't trip antivirus.
EICAR = ("X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!" + "$H+H*").encode()


class FakeClamd:
    """Answers PING, VERSION and INSTREAM like clamd; flags streams containing EICAR, or
    containing b'UNOFFICIAL' with an unofficial signature."""

    def __init__(self):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen()
        self.port = self.sock.getsockname()[1]
        self.streams: list[bytes] = []
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            with conn:
                cmd = b""
                while not cmd.endswith(b"\0"):
                    cmd += conn.recv(1)
                if cmd == b"zPING\0":
                    conn.sendall(b"PONG\0")
                elif cmd == b"zVERSION\0":
                    conn.sendall(b"ClamAV 1.4.1/27470/Sun Nov 22 08:30:00 2026\0")
                elif cmd == b"zINSTREAM\0":
                    data = b""
                    while True:
                        (n,) = struct.unpack(">I", self._recv(conn, 4))
                        if n == 0:
                            break
                        data += self._recv(conn, n)
                    self.streams.append(data)
                    if EICAR in data:
                        conn.sendall(b"stream: Win.Test.EICAR_HDB-1 FOUND\0")
                    elif b"UNOFFICIAL" in data:
                        conn.sendall(b"stream: Sanesecurity.Junk.1.UNOFFICIAL FOUND\0")
                    elif b"TOOBIG" in data:
                        conn.sendall(b"INSTREAM size limit exceeded. ERROR\0")
                    else:
                        conn.sendall(b"stream: OK\0")

    @staticmethod
    def _recv(conn, n):
        buf = b""
        while len(buf) < n:
            buf += conn.recv(n - len(buf))
        return buf

    def close(self):
        self.sock.close()


@pytest.fixture
def clamd():
    server = FakeClamd()
    yield server
    server.close()


def clam(port, **kw) -> ClamavEngine:
    return ClamavEngine(Settings(clamd_host="127.0.0.1", clamd_port=port, **kw))


def mem(path, data) -> FileContext:
    return FileContext(path, None, len(data), path.rsplit(".")[-1], None, None, MEMORY, data, data)


def test_signature_severity():
    assert clam_severity("Win.Test.EICAR_HDB-1") == "malicious"
    assert clam_severity("winnow.malware.test.eicar.com.UNOFFICIAL") == "malicious"
    assert clam_severity("Sanesecurity.Foxhole.JS_Zip_1.UNOFFICIAL") == "malicious"
    assert clam_severity("Sanesecurity.Phishing.Bank.123.UNOFFICIAL") == "suspicious"
    assert clam_severity("Sanesecurity.Junk.1.UNOFFICIAL") == "suspicious"


def test_version_parsing():
    assert parse_version("ClamAV 1.4.1/27470/Sun Nov 22 08:30:00 2026") == (
        "1.4.1",
        27470,
        datetime(2026, 11, 22, 8, 30),
    )
    assert parse_version("ClamAV 1.4.1") == ("ClamAV 1.4.1", None, None)


def test_client_commands(clamd):
    client = ClamdClient("127.0.0.1", clamd.port, 5)
    assert client.ping()
    assert client.version().startswith("ClamAV 1.4.1/")
    assert client.instream([b"hello"]) is None
    assert client.instream([b"pad" * 100_000, EICAR]) == "Win.Test.EICAR_HDB-1"
    assert clamd.streams[-1].endswith(EICAR)


def test_engine_reports_signatures(clamd):
    engine = clam(clamd.port)
    (f,) = engine.scan(mem("a.exe", EICAR))
    assert (f.name, f.severity, f.engine) == ("Win.Test.EICAR_HDB-1", "malicious", "clamav")
    (u,) = engine.scan(mem("b.eml", b"UNOFFICIAL"))
    assert u.severity == "suspicious" and u.details["unofficial"]
    assert engine.scan(mem("c.txt", b"fine")) == []
    assert engine.scan(mem("d.bin", b"TOOBIG")) == []  # clamd couldn't finish: not a finding


def test_big_files_are_streamed_whole_or_as_head_and_tail(clamd, tmp_path):
    p = tmp_path / "f.bin"
    p.write_bytes(b"A" * 3000 + EICAR)
    c = FileContext("f.bin", bytes(p), p.stat().st_size, "bin", None, None, FILE,
                    head=b"A" * 100, tail=EICAR)  # fmt: skip
    engine = clam(clamd.port)
    assert [f.name for f in engine.scan(c)] == ["Win.Test.EICAR_HDB-1"]
    assert clamd.streams[-1] == p.read_bytes()  # streamed from disk, whole

    engine.stream_max = 1000  # smaller than the file: head and tail only
    (f,) = engine.scan(c)
    assert f.details["part"] == "tail"
    assert clamd.streams[-2:] == [b"A" * 100, EICAR]


def test_unreachable_clamd_is_unavailable_and_backs_off():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()  # nothing listens here
    engine = clam(port, clamd_timeout=2)
    with pytest.raises(EngineUnavailableError, match="can't reach"):
        engine.scan(mem("a", b"x"))
    with pytest.raises(EngineUnavailableError, match="a moment ago"):
        engine.scan(mem("b", b"x"))


def test_disabled_without_a_host():
    assert not ClamavEngine(Settings()).enabled()


# --- YARA ------------------------------------------------------------------------------------

RULES = """
rule Test_Marker {
    meta:
        description = "test marker string"
        score = 85
    strings:
        $a = "NASSCAN-YARA-TEST"
    condition:
        $a
}
rule Uses_Externals {
    meta:
        score = 50
    condition:
        filename == "special.bin"
}
"""


def yara_settings(tmp_path, **kw) -> Settings:
    local = tmp_path / "rules"
    local.mkdir(exist_ok=True)
    (local / "mine.yar").write_text(RULES)
    (local / "broken.yar").write_text("rule broken { condition: nonsense( }")
    opts = {"data_dir": str(tmp_path / "data"), "yara_local_dir": str(local), "yara_sources": ""}
    return Settings(**(opts | kw))


def test_severity_from_score():
    assert yara_severity(85) == "malicious"
    assert yara_severity("70") == "suspicious"
    assert yara_severity(20) == "info"
    assert yara_severity(None) == "suspicious"


def test_local_rules_compile_and_bad_files_are_skipped(tmp_path):
    settings = yara_settings(tmp_path)
    report = RuleStore(settings).refresh()
    assert report.rules_files == 1
    assert [s.split(":")[0] for s in report.skipped] == ["local/broken"]
    assert not RuleStore(settings).due()

    engine = YaraEngine(settings)
    (f,) = engine.scan(mem("x.txt", b"...NASSCAN-YARA-TEST..."))
    assert (f.name, f.severity, f.details["source"]) == ("Test_Marker", "malicious", "local")
    assert f.description == "test marker string"
    (g,) = engine.scan(mem("special.bin", b"nothing"))  # matched on the filename external
    assert g.name == "Uses_Externals" and g.severity == "info"
    assert engine.scan(mem("y.txt", b"clean")) == []


def test_local_rule_changes_trigger_a_rebuild(tmp_path):
    settings = yara_settings(tmp_path)
    store = RuleStore(settings)
    store.refresh()
    assert not store.local_changed()
    new = tmp_path / "rules" / "extra.yar"
    new.write_text('rule Extra { strings: $a = "EXTRA-MARKER" condition: $a }')
    assert store.local_changed()  # a new file
    report = store.refresh(download=False)
    assert report.rules_files == 2 and not store.local_changed()
    assert [f.name for f in YaraEngine(settings).scan(mem("a", b"EXTRA-MARKER"))] == ["Extra"]
    new.unlink()
    assert store.local_changed()  # removed counts too


def test_files_on_disk_are_matched_by_path(tmp_path):
    settings = yara_settings(tmp_path)
    RuleStore(settings).refresh()
    p = tmp_path / "big.bin"
    p.write_bytes(b"\0" * 5000 + b"NASSCAN-YARA-TEST")
    c = FileContext("big.bin", bytes(p), p.stat().st_size, "bin", None, None, FILE,
                    head=b"\0" * 10, tail=b"\0" * 10)  # fmt: skip
    assert [f.name for f in YaraEngine(settings).scan(c)] == ["Test_Marker"]


def test_no_rules_means_unavailable(tmp_path):
    engine = YaraEngine(Settings(data_dir=str(tmp_path)))
    with pytest.raises(EngineUnavailableError):
        engine.scan(mem("a", b"x"))


def zip_of(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, text in files.items():
            z.writestr(name, text)
    return buf.getvalue()


def test_downloaded_sources(tmp_path, monkeypatch):
    settings = yara_settings(tmp_path, yara_sources="forge-core,signature-base,nope")
    downloads = {
        "forge-core": zip_of({"packages/core/yara-rules-core.yar": RULES.replace("Test_", "F_")}),
        "signature-base": zip_of(
            {
                "signature-base-master/yara/apt_x.yar": RULES.replace("Test_", "S_"),
                "signature-base-master/yara/needs_magic.yar": 'import "magic"\nrule m '
                '{ condition: magic.mime_type() == "x" }',
                "signature-base-master/other/not_rules.yar": "garbage",
            }
        ),
    }
    store = RuleStore(settings)
    from nasscan.scanner.engines import yara_rules

    monkeypatch.setattr(
        store, "_download", lambda url: downloads[next(k for k, v in yara_rules.SOURCES.items()
                                                      if v == url)]
    )  # fmt: skip
    report = store.refresh()
    assert report.sources == {"forge-core": "ok", "signature-base": "ok",
                              "nope": "unknown source", "local": "ok"}  # fmt: skip
    assert report.rules_files == 3  # forge, signature-base apt_x, local mine
    assert any(s.startswith("signature-base/needs_magic") for s in report.skipped)
    found = YaraEngine(settings).scan(mem("a.txt", b"NASSCAN-YARA-TEST"))
    assert sorted(f.name for f in found) == ["F_Marker", "S_Marker", "Test_Marker"]

    # A failed download keeps the copy from last time.
    def fail(url):
        raise OSError("network down")

    monkeypatch.setattr(store, "_download", fail)
    report = store.refresh()
    assert report.sources["forge-core"].startswith("download failed")
    assert report.rules_files == 3
