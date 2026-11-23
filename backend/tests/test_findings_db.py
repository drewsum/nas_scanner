"""Findings against a real database: the triggers that queue files, the lifecycle, the
allowlist, the API, and re-evaluation when threat intel changes."""

import hashlib
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete, select, text, update

from nasscan import findings
from nasscan.api.app import create_app
from nasscan.cli import main
from nasscan.config import get_settings
from nasscan.db import get_sessionmaker
from nasscan.db.models import AllowlistEntry, Detection, File, Finding
from nasscan.intel import store

pytestmark = pytest.mark.db


@pytest.fixture
def db(db_env):
    main(["migrate"])
    with get_sessionmaker()() as s:
        s.execute(
            text(
                "TRUNCATE files, scan_runs, feed_hashes, hash_lookups, allowlist "
                "RESTART IDENTITY CASCADE"
            )
        )
        s.commit()
    get_settings.cache_clear()
    return get_sessionmaker()


def add_file(sessions, path="Downloads/setup.exe", data=b"payload"):
    now = datetime.now(UTC)
    with sessions() as s:
        f = File(
            path=path,
            size=len(data),
            mtime_ns=1,
            inode=1,
            device=1,
            sha256=hashlib.sha256(data).hexdigest(),
            sha1=hashlib.sha1(data).hexdigest(),
            md5=hashlib.md5(data).hexdigest(),
            first_seen=now,
            last_seen=now,
            intel_checked_at=now,
        )
        s.add(f)
        s.commit()
        return f.id


def detect(sessions, file_id, engine="clamav", severity="malicious", name="Sig"):
    now = datetime.now(UTC)
    with sessions() as s:
        s.add(
            Detection(
                file_id=file_id,
                engine=engine,
                name=name,
                member="",
                severity=severity,
                description=f"{engine} says {name}",
                details={"link": "https://example/report"},
                first_seen=now,
                last_seen=now,
            )
        )
        s.commit()


def evaluate(sessions):
    with sessions() as s:
        return findings.evaluate_all(s, get_settings())


def finding(sessions, file_id) -> Finding | None:
    with sessions() as s:
        return s.scalar(select(Finding).where(Finding.file_id == file_id))


def pending(sessions, file_id) -> bool:
    with sessions() as s:
        return s.get_one(File, file_id).verdict_pending


def test_detections_queue_the_file_and_open_a_finding(db):
    fid = add_file(db)
    assert not pending(db, fid)
    detect(db, fid)
    assert pending(db, fid)
    assert evaluate(db) == 1
    assert not pending(db, fid)
    f = finding(db, fid)
    assert (f.verdict, f.score, f.status) == ("malicious", 100, "open")
    assert f.evidence[0]["link"] == "https://example/report"


def test_rescans_touching_last_seen_dont_requeue(db):
    fid = add_file(db)
    detect(db, fid)
    evaluate(db)
    with db() as s:
        s.execute(update(Detection).values(last_seen=datetime.now(UTC), description="again"))
        s.commit()
    assert not pending(db, fid)
    with db() as s:
        s.execute(update(Detection).values(severity="suspicious"))
        s.commit()
    assert pending(db, fid)
    evaluate(db)
    assert finding(db, fid).verdict == "suspicious"


def test_info_only_raises_no_finding(db):
    fid = add_file(db)
    detect(db, fid, "documents", "info")
    evaluate(db)
    assert finding(db, fid) is None
    assert not pending(db, fid)


def test_resolves_when_clean_and_reopens_when_flagged_again(db):
    fid = add_file(db)
    detect(db, fid)
    evaluate(db)
    with db() as s:
        s.execute(delete(Detection))
        s.commit()
    evaluate(db)
    f = finding(db, fid)
    assert (f.status, f.resolution) == ("resolved", "clean")
    detect(db, fid, "yara", "suspicious")
    evaluate(db)
    f2 = finding(db, fid)
    assert (f2.status, f2.verdict, f2.resolution) == ("open", "suspicious", None)
    assert f2.opened_at > f.opened_at
    assert f2.first_seen == f.first_seen


def test_resolves_when_the_file_is_removed(db):
    fid = add_file(db)
    detect(db, fid)
    evaluate(db)
    with db() as s:
        s.execute(update(File).values(status="removed"))
        s.commit()
    assert pending(db, fid)
    evaluate(db)
    f = finding(db, fid)
    assert (f.status, f.resolution) == ("resolved", "removed")


def test_acknowledged_stays_quiet_until_it_escalates(db):
    fid = add_file(db)
    detect(db, fid, "heuristics", "suspicious")
    evaluate(db)
    f = finding(db, fid)
    with db() as s:
        findings.set_status(
            s.get_one(Finding, f.id), "acknowledged", " seen it ", datetime.now(UTC)
        )
        s.commit()
    detect(db, fid, "yara", "info", "meh")  # still suspicious
    evaluate(db)
    f = finding(db, fid)
    assert (f.status, f.note) == ("acknowledged", "seen it")
    detect(db, fid, "clamav", "malicious")
    evaluate(db)
    f = finding(db, fid)
    assert (f.status, f.verdict) == ("open", "malicious")


def test_ignored_stays_ignored_until_the_content_changes(db):
    fid = add_file(db)
    detect(db, fid)
    evaluate(db)
    with db() as s:
        findings.set_status(s.scalar(select(Finding)), "ignored", None, datetime.now(UTC))
        s.commit()
    detect(db, fid, "yara", "malicious")
    evaluate(db)
    assert finding(db, fid).status == "ignored"
    with db() as s:
        s.execute(update(File).values(sha256="ab" * 32))
        s.commit()
    assert pending(db, fid)
    evaluate(db)
    f = finding(db, fid)
    assert (f.status, f.sha256) == ("open", "ab" * 32)


def test_known_good_hashes_score_lower(db):
    fid = add_file(db)
    with db() as s:
        sha = s.get_one(File, fid).sha256
        s.execute(
            text(
                "INSERT INTO hash_lookups VALUES "
                "('circl', :sha, 'known_good', NULL, NULL, NULL, now(), now())"
            ),
            {"sha": sha},
        )
        s.commit()
    detect(db, fid, "heuristics", "suspicious")
    evaluate(db)
    assert finding(db, fid) is None


def test_allowlist_by_hash_and_glob(db, monkeypatch):
    a = add_file(db, "Downloads/tool.exe", b"tool")
    b = add_file(db, "Games/mods/cheat.dll", b"cheat")
    detect(db, a)
    detect(db, b)
    evaluate(db)
    sha = finding(db, a).sha256
    with TestClient(create_app()) as client:
        r = client.post("/api/allowlist", json={"kind": "sha256", "value": sha.upper()})
        assert r.status_code == 201, r.text
        assert r.json()["value"] == sha
        assert finding(db, a).status == "allowlisted"
        assert finding(db, b).status == "open"

        assert (
            client.post("/api/allowlist", json={"kind": "sha256", "value": sha}).status_code == 409
        )
        assert (
            client.post("/api/allowlist", json={"kind": "sha256", "value": "zz"}).status_code == 422
        )

        r = client.post(
            "/api/allowlist", json={"kind": "path", "value": "/Games/*", "note": "mods"}
        )
        assert r.json()["value"] == "Games/*"
        assert finding(db, b).status == "allowlisted"
        listed = client.get("/api/findings").json()
        assert listed == []
        assert len(client.get("/api/findings?status=allowlisted").json()) == 2

        assert client.delete(f"/api/allowlist/{r.json()['id']}").status_code == 204
        assert finding(db, b).status == "open"
        assert [e["kind"] for e in client.get("/api/allowlist").json()] == ["sha256"]
    with db() as s:
        assert s.scalar(select(AllowlistEntry.kind)) == "sha256"


def test_findings_api(db):
    sus = add_file(db, "a/macro.docm", b"doc")
    bad = add_file(db, "b/evil.exe", b"evil")
    detect(db, sus, "documents", "suspicious", "vba-autoexec")
    detect(db, bad)
    evaluate(db)
    with TestClient(create_app()) as client:
        rows = client.get("/api/findings").json()
        assert [r["path"] for r in rows] == ["b/evil.exe", "a/macro.docm"]
        assert client.get("/api/findings?verdict=suspicious").json()[0]["path"] == "a/macro.docm"
        fid = rows[0]["id"]
        r = client.post(
            f"/api/findings/{fid}/status", json={"status": "acknowledged", "note": "ok"}
        )
        assert (r.json()["status"], r.json()["note"]) == ("acknowledged", "ok")
        assert len(client.get("/api/findings?status=open").json()) == 1
        assert client.get(f"/api/findings/{fid}").json()["evidence"][0]["engine"] == "clamav"
        assert client.get("/api/findings/999").status_code == 404
        r = client.post(f"/api/findings/{fid}/status", json={"status": "resolved"})
        assert r.status_code == 422
        s = client.get("/api/findings/summary").json()
        assert s == {
            "counts": {"acknowledged": {"malicious": 1}, "open": {"suspicious": 1}},
            "pending": 0,
        }


def test_cannot_triage_a_resolved_finding(db):
    fid = add_file(db)
    detect(db, fid)
    evaluate(db)
    with db() as s:
        s.execute(update(File).values(status="removed"))
        s.commit()
    evaluate(db)
    with TestClient(create_app()) as client:
        r = client.post(f"/api/findings/{finding(db, fid).id}/status", json={"status": "ignored"})
        assert r.status_code == 409


def test_a_feed_update_turns_into_a_finding_and_back(db):
    """Re-evaluation on updated intel: a feed newly listing a hash flags the file, and the
    feed dropping it resolves the finding."""
    fid = add_file(db, data=b"later known bad")
    with db() as s:
        sha = s.get_one(File, fid).sha256
    for listed in ([sha], ["00" * 32]):
        with db() as s:
            store.import_feed(
                s, "malwarebazaar-feed", [(bytes.fromhex(h), "Fam") for h in listed], True
            )
            while store.process_pending(s):
                pass
            s.commit()
        evaluate(db)
        f = finding(db, fid)
        if listed == [sha]:
            assert (f.status, f.verdict) == ("open", "malicious")
            assert f.evidence[0]["engine"] == "malwarebazaar-feed"
        else:
            assert (f.status, f.resolution) == ("resolved", "clean")


def test_queue_all_requeues_flagged_files(db):
    fid = add_file(db)
    plain = add_file(db, "x.txt", b"x")
    detect(db, fid)
    evaluate(db)
    with db() as s:
        assert findings.queue_all(s) == 1
        s.commit()
    assert pending(db, fid) and not pending(db, plain)
    assert evaluate(db) == 1
