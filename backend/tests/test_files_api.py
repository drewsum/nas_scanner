"""File search, totals and one file's detail, against a real database."""

import hashlib
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from nasscan import findings
from nasscan.api.app import create_app
from nasscan.cli import main
from nasscan.config import get_settings
from nasscan.db import get_sessionmaker
from nasscan.db.models import Detection, File, ScanError, ScanRun
from nasscan.intel import store

pytestmark = pytest.mark.db


@pytest.fixture
def client(db_env):
    main(["migrate"])
    with get_sessionmaker()() as s:
        s.execute(
            text("TRUNCATE files, scan_runs, feed_hashes, hash_lookups RESTART IDENTITY CASCADE")
        )
        s.commit()
    get_settings.cache_clear()
    with TestClient(create_app()) as c:
        yield c


def add(path, data=b"x", status="active", scan_mode="full"):
    now = datetime.now(UTC)
    with get_sessionmaker()() as s:
        f = File(
            path=path,
            size=len(data),
            mtime_ns=1_700_000_000 * 10**9,
            inode=1,
            device=1,
            sha256=hashlib.sha256(data).hexdigest(),
            sha1=hashlib.sha1(data).hexdigest(),
            md5=hashlib.md5(data).hexdigest(),
            status=status,
            scan_mode=scan_mode,
            first_seen=now,
            last_seen=now,
            last_scanned=now,
        )
        s.add(f)
        s.commit()
        return f.id, f.sha256, f.md5


def test_search_by_path_and_hash(client):
    _, sha, md5 = add("Movies/Film/setup.EXE", b"evil")
    add("Movies/Film/film.mkv", b"film")
    add("Old/setup.exe", b"evil", status="removed")
    add("100%_real.txt", b"pct")

    r = client.get("/api/files", params={"q": "setup.exe"}).json()
    assert (r["match"], [f["path"] for f in r["files"]]) == ("path", ["Movies/Film/setup.EXE"])
    r = client.get("/api/files", params={"q": "setup.exe", "include_removed": True}).json()
    assert len(r["files"]) == 2
    # Every copy of the content, removed ones too, by any of its hashes.
    for h in (sha, md5, sha.upper()):
        r = client.get("/api/files", params={"q": h}).json()
        assert r["match"] == "hash" and len(r["files"]) == 2
    # LIKE wildcards are literal.
    assert [f["path"] for f in client.get("/api/files?q=0%25_").json()["files"]] == [
        "100%_real.txt"
    ]
    assert client.get("/api/files?q=x").status_code == 422
    r = client.get("/api/files", params={"q": "fi", "limit": 1}).json()
    assert r["truncated"] and len(r["files"]) == 1


def test_stats(client):
    add("a", b"aa")
    add("b", b"bbbb", scan_mode="partial")
    add("c", b"c", status="removed")
    add("d", b"dd", status="error")
    s = client.get("/api/files/stats").json()
    assert (s["files"], s["bytes"], s["read_partly"], s["unreadable"], s["removed"]) == (
        3,
        8,
        1,
        1,
        1,
    )
    assert s["with_detections"] == 0 and s["last_scanned"]


def test_file_detail(client):
    fid, sha, md5 = add("Downloads/tool.exe", b"tool")
    now = datetime.now(UTC)
    sessions = get_sessionmaker()
    with sessions() as s:
        s.add(
            Detection(
                file_id=fid,
                engine="clamav",
                name="Win.Trojan.Test",
                member="",
                severity="malicious",
                description="ClamAV signature",
                details={"link": "https://example/report"},
                first_seen=now,
                last_seen=now,
            )
        )
        store.import_feed(s, "malwarebazaar-feed", [(bytes.fromhex(md5), "Fam")], True)
        s.commit()
        findings.evaluate_all(s, get_settings())

    d = client.get(f"/api/files/{fid}").json()
    assert d["path"] == "Downloads/tool.exe" and d["sha256"] == sha
    assert d["mtime"].startswith("2023-11-14")
    assert d["finding"]["verdict"] == "malicious"
    assert d["detections"][0]["link"] == "https://example/report"
    assert d["feeds"] == [{"feed": "malwarebazaar-feed", "name": "Fam", "hash_type": "md5"}]
    whats = [e["what"] for e in d["history"]]
    assert "First seen" in whats and "Finding opened (malicious)" in whats
    assert client.get("/api/files/999").status_code == 404
    # The findings list filters by path too.
    assert len(client.get("/api/findings?q=TOOL").json()) == 1
    assert client.get("/api/findings?q=nothing").json() == []


def test_run_errors(client):
    with get_sessionmaker()() as s:
        run = ScanRun(kind="full", root="", trigger="manual", status="completed")
        s.add(run)
        s.flush()
        s.add(
            ScanError(run_id=run.id, path="a/b", message="Permission denied", at=datetime.now(UTC))
        )
        s.commit()
        run_id = run.id
    assert client.get(f"/api/runs/{run_id}/errors").json()[0]["path"] == "a/b"
    assert client.get("/api/runs/999/errors").status_code == 404
