"""Notifications (alerts, scan digests, the weekly report, the cap), reports and exports,
against a real database. Apprise is stubbed: nothing leaves the machine."""

import hashlib
import json
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, text

from nasscan import findings, notify, reports
from nasscan.api.app import create_app
from nasscan.cli import main
from nasscan.config import get_settings
from nasscan.db import get_sessionmaker
from nasscan.db.models import Detection, File, Finding, Notification, Report, ScanRun

pytestmark = pytest.mark.db


@pytest.fixture
def env(db_env, monkeypatch):
    main(["migrate"])
    with get_sessionmaker()() as s:
        s.execute(
            text(
                "TRUNCATE files, scan_runs, notifications, reports, engine_status "
                "RESTART IDENTITY CASCADE"
            )
        )
        s.commit()
    monkeypatch.setenv("NASSCAN_APPRISE_URLS", "json://localhost")
    monkeypatch.setenv("NASSCAN_PUBLIC_URL", "http://nas:8010/")
    get_settings.cache_clear()
    sent: list[dict] = []
    failing = {"on": False}

    def fake_notify(self, title, body, notify_type):
        if failing["on"]:
            return False
        sent.append({"title": title, "body": body, "type": notify_type})
        return True

    monkeypatch.setattr("apprise.Apprise.notify", lambda self, **kw: fake_notify(self, **kw))
    yield {"sent": sent, "failing": failing}
    get_settings.cache_clear()


def flag(path="Downloads/evil.exe", engine="clamav", severity="malicious", run_id=None) -> int:
    now = datetime.now(UTC)
    sessions = get_sessionmaker()
    with sessions() as s:
        data = path.encode()
        f = File(
            path=path,
            size=len(data),
            mtime_ns=1,
            inode=1,
            device=1,
            sha256=hashlib.sha256(data).hexdigest(),
            first_seen=now,
            last_seen=now,
        )
        s.add(f)
        s.flush()
        s.add(
            Detection(
                file_id=f.id,
                engine=engine,
                name="Sig",
                member="",
                severity=severity,
                description="",
                run_id=run_id,
                first_seen=now,
                last_seen=now,
            )
        )
        s.commit()
        findings.evaluate_all(s, get_settings())
        return f.id


def send(now=None) -> int:
    with get_sessionmaker()() as s:
        return notify.send_pending(
            s, get_settings(), notify.Notifier(get_settings()), now or datetime.now(UTC)
        )


def test_new_findings_alert_once_per_opening(env):
    flag()
    flag("Docs/macro.docm", "documents", "suspicious")
    assert send() == 1
    (msg,) = env["sent"]
    assert msg["title"] == "nasscan: 1 malicious, 1 suspicious files found"
    assert "Downloads/evil.exe — clamav (Sig)" in msg["body"]
    assert "http://nas:8010/#/findings" in msg["body"]
    assert send() == 0  # nothing new

    # Acknowledged findings stay quiet; reopening one alerts again.
    with get_sessionmaker()() as s:
        f = s.scalar(select(Finding).where(Finding.verdict == "malicious"))
        findings.set_status(f, "acknowledged", None, datetime.now(UTC))
        s.commit()
    assert send() == 0
    with get_sessionmaker()() as s:
        f = s.scalar(select(Finding).where(Finding.verdict == "malicious"))
        findings.set_status(f, "open", None, datetime.now(UTC))
        s.commit()
    assert send() == 1
    assert env["sent"][-1]["title"] == "nasscan: malicious file found"
    assert f"#/findings/{f.id}" in env["sent"][-1]["body"]


def test_min_verdict(env, monkeypatch):
    monkeypatch.setenv("NASSCAN_NOTIFY_MIN_VERDICT", "malicious")
    get_settings.cache_clear()
    flag("a.docm", "documents", "suspicious")
    assert send() == 0


def test_hourly_cap_and_failures(env, monkeypatch):
    monkeypatch.setenv("NASSCAN_NOTIFY_MAX_PER_HOUR", "1")
    get_settings.cache_clear()
    env["failing"]["on"] = True
    flag("a.exe")
    assert send() == 0
    with get_sessionmaker()() as s:
        (n,) = s.scalars(select(Notification)).all()
        assert not n.ok and "Apprise" in n.error
    env["failing"]["on"] = False
    assert send() == 0  # the failed try used the hour's one message
    later = datetime.now(UTC) + timedelta(hours=1, minutes=1)
    flag("b.exe")
    assert send(later) == 1
    assert "2 malicious" in env["sent"][0]["title"]  # a.exe waited and went out with b.exe


def test_scan_digests(env, monkeypatch):
    now = datetime.now(UTC)
    with get_sessionmaker()() as s:
        for status in ("completed", "failed"):
            s.add(
                ScanRun(
                    kind="incremental",
                    trigger="schedule",
                    status=status,
                    finished_at=now,
                    message="Failed: /scan is empty" if status == "failed" else "ok",
                )
            )
        s.commit()
    assert send() == 1  # only the failure, the digest is off
    assert env["sent"][0]["title"] == "nasscan: incremental scan failed"
    assert "/scan is empty" in env["sent"][0]["body"]
    assert send() == 0

    monkeypatch.setenv("NASSCAN_NOTIFY_DIGEST", "true")
    get_settings.cache_clear()
    with get_sessionmaker()() as s:
        s.add(ScanRun(kind="full", trigger="manual", status="completed", finished_at=now))
        s.commit()
    assert send() == 1
    assert env["sent"][-1]["title"] == "nasscan: full scan completed"


def test_weekly_report_made_after_the_scheduled_full_scan(env):
    now = datetime.now(UTC)
    with get_sessionmaker()() as s:
        run = ScanRun(
            kind="full",
            trigger="schedule",
            status="completed",
            started_at=now - timedelta(hours=2),
            finished_at=now - timedelta(minutes=1),
            files_seen=3,
            versions={"engines": [{"name": "clamav", "status": "ok", "version": "ClamAV 1.4"}]},
            notified_at=now,
        )
        manual = ScanRun(kind="full", trigger="manual", status="completed", finished_at=now)
        s.add_all([run, manual])
        s.commit()
        run_id = run.id
    flag("x/evil.exe", run_id=run_id)
    with get_sessionmaker()() as s:
        assert len(reports.make_due_reports(s)) == 1
        s.commit()
        assert reports.make_due_reports(s) == []  # once per scan, never for manual ones
        report = s.scalar(select(Report))
        assert report.run_id == run_id and report.data["opened"] == {"malicious": 1}
        html = reports.weekly_report_html(report, get_settings())
    assert "x/evil.exe" in html and "ClamAV 1.4" in html

    assert send() == 2  # the alert, then the report
    weekly = env["sent"][-1]
    assert weekly["title"].startswith("nasscan: weekly report to ")
    assert "Open now: 1." in weekly["body"] and "http://nas:8010/api/reports/1" in weekly["body"]


def test_report_and_notify_api(env):
    with get_sessionmaker()() as s:
        run = ScanRun(kind="full", trigger="manual", status="completed")
        s.add(run)
        s.commit()
        run_id = run.id
    flag("Games/<script>.exe", run_id=run_id)
    with TestClient(create_app()) as c:
        r = c.get(f"/api/runs/{run_id}/report")
        assert r.status_code == 200 and r.headers["content-type"].startswith("text/html")
        assert "Games/&lt;script&gt;.exe" in r.text  # escaped
        assert c.get("/api/runs/999/report").status_code == 404

        made = c.post("/api/reports").json()
        assert made["open_findings"] == 1 and made["notified_at"]
        assert [x["id"] for x in c.get("/api/reports").json()] == [made["id"]]
        assert "Weekly report" in c.get(f"/api/reports/{made['id']}").text
        assert c.get(f"/api/reports/{made['id']}/data").json()["files"] == 1

        status = c.get("/api/notify").json()
        assert status["configured"] and status["services"] == 1 and status["links"]
        assert c.post("/api/notify/test").json() == {"ok": True, "error": None}
        assert env["sent"][-1]["title"] == "nasscan: test notification"
        env["failing"]["on"] = True
        result = c.post("/api/notify/test").json()
        assert not result["ok"] and result["error"]
        assert [n["kind"] for n in c.get("/api/notify").json()["recent"]] == ["test", "test"]


def test_test_button_without_apprise(env, monkeypatch):
    monkeypatch.delenv("NASSCAN_APPRISE_URLS")
    get_settings.cache_clear()
    with TestClient(create_app()) as c:
        assert not c.get("/api/notify").json()["configured"]
        assert c.post("/api/notify/test").status_code == 409


def test_exports(env):
    flag('a,b/"quoted".exe')
    with TestClient(create_app()) as c:
        assert {d["name"] for d in c.get("/api/export").json()} >= {"findings", "files"}
        r = c.get("/api/export/findings.csv")
        assert r.headers["content-disposition"].startswith(
            'attachment; filename="nasscan-findings-'
        )
        lines = r.text.splitlines()
        assert lines[0].startswith("id,path,file_status,sha256,verdict")
        assert '"a,b/""quoted"".exe"' in lines[1]
        rows = c.get("/api/export/files.json").json()
        assert [x["path"] for x in rows] == ['a,b/"quoted".exe']
        assert json.loads(c.get("/api/export/runs.json").text) == []
        assert c.get("/api/export/nope.csv").status_code == 422


def test_runs_record_versions(env):
    with get_sessionmaker()() as s:
        s.execute(
            text(
                "INSERT INTO engine_status (name, status, message, version, checked_at) "
                "VALUES ('clamav', 'ok', '', 'ClamAV 1.4', now())"
            )
        )
        s.commit()
        snap = reports.snapshot_versions(s)
    assert snap["engines"][0]["version"] == "ClamAV 1.4"
