import threading

import pytest

from nasscan.scanner import hashing
from nasscan.scanner.hashing import Stopped, Throttle, digest_file

# The EICAR antivirus test file, assembled at runtime so this source file itself doesn't
# trip antivirus on a dev machine.
EICAR = ("X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!" + "$H+H*").encode()


def write(tmp_path, data: bytes, name="f"):
    p = tmp_path / name
    p.write_bytes(data)
    return p


def test_eicar_hashes(tmp_path):
    try:
        d = digest_file(write(tmp_path, EICAR))
    except OSError as exc:  # Windows Defender blocks reading it on a dev machine
        pytest.skip(f"local antivirus blocked the EICAR file: {exc}")
    assert d.size == 68
    assert d.sha256 == "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    assert d.sha1 == "3395856ce81f2b7382dee72602f798b642f14140"
    assert d.md5 == "44d88612fea8a8f36de82e1278abb02f"


def test_empty_file(tmp_path):
    d = digest_file(write(tmp_path, b""))
    assert d.size == 0
    assert d.sha256 == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert d.md5 == "d41d8cd98f00b204e9800998ecf8427e"


def test_files_larger_than_a_chunk(tmp_path, monkeypatch):
    import hashlib

    monkeypatch.setattr(hashing, "CHUNK", 1000)
    data = bytes(range(256)) * 50  # 12800 bytes: 13 chunks
    d = digest_file(write(tmp_path, data))
    assert d.size == len(data)
    assert d.sha256 == hashlib.sha256(data).hexdigest()
    assert d.sha1 == hashlib.sha1(data).hexdigest()


def test_stop_interrupts_a_read(tmp_path):
    stop = threading.Event()
    stop.set()
    with pytest.raises(Stopped):
        digest_file(write(tmp_path, b"x" * 10), stop=stop)


def test_magic_detects_the_real_type(tmp_path):
    if not hashing._magic_available():
        pytest.skip("libmagic not installed")
    # A PE executable header under a movie name.
    exe = write(tmp_path, b"MZ" + b"\x90" * 58 + b"\x80\x00\x00\x00" + b"\x00" * 200, "movie.mkv")
    d = digest_file(exe)
    assert d.mime in ("application/x-dosexec", "application/vnd.microsoft.portable-executable")
    pdf = digest_file(write(tmp_path, b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n", "doc.txt"))
    assert pdf.mime == "application/pdf" and "PDF" in pdf.magic


class FakeClock:
    def __init__(self):
        self.now = 0.0
        self.slept: list[float] = []

    def clock(self):
        return self.now

    def sleep(self, seconds):
        self.slept.append(seconds)
        self.now += seconds


def test_throttle_spaces_reads_to_the_rate():
    fake = FakeClock()
    t = Throttle(1, clock=fake.clock, sleep=fake.sleep)  # 1 MB/s
    mb = 1024 * 1024
    t.consume(mb)  # the first read goes straight away
    t.consume(mb)
    t.consume(mb // 2)
    assert fake.slept == [1.0, 1.0]
    assert fake.now == 2.0  # and the bucket is booked until 2.5


def test_throttle_zero_is_unlimited():
    fake = FakeClock()
    t = Throttle(0, clock=fake.clock, sleep=fake.sleep)
    for _ in range(5):
        t.consume(10**9)
    assert fake.slept == []
