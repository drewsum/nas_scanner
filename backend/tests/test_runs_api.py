import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from nasscan.api.app import create_app
from nasscan.cli import main
from nasscan.db import get_sessionmaker

pytestmark = pytest.mark.db


@pytest.fixture
def client(db_env):
    main(["migrate"])
    with get_sessionmaker()() as s:
        s.execute(text("TRUNCATE files, scan_runs, engine_status RESTART IDENTITY CASCADE"))
        s.commit()
    return TestClient(create_app())


def test_start_list_read_and_cancel(client):
    res = client.post("/api/runs", json={"kind": "full"})
    assert res.status_code == 201
    run = res.json()
    assert run["kind"] == "full" and run["status"] == "queued" and run["trigger"] == "manual"

    assert client.post("/api/runs", json={}).status_code == 409  # one at a time
    assert [r["id"] for r in client.get("/api/runs").json()] == [run["id"]]
    assert client.get(f"/api/runs/{run['id']}").json()["files_seen"] == 0
    assert client.get("/api/runs/999").status_code == 404

    res = client.post(f"/api/runs/{run['id']}/cancel")
    assert res.json()["status"] == "cancelled"
    assert client.post(f"/api/runs/{run['id']}/cancel").status_code == 409


def test_folder_scan_validation(client):
    assert client.post("/api/runs", json={"kind": "path", "path": "../x"}).status_code == 422
    res = client.post("/api/runs", json={"kind": "path", "path": "media/tv"})
    assert res.json()["root"] == "media/tv"


def test_scan_cli_queues_a_run(client, capsys):
    main(["scan", "--path", "photos"])
    assert "Queued path scan" in capsys.readouterr().out
    with pytest.raises(SystemExit, match="already queued"):
        main(["scan"])


def test_engines_and_detections(client):
    from datetime import UTC, datetime

    from nasscan.db.models import Detection, EngineStatus, File

    now = datetime.now(UTC)
    with get_sessionmaker()() as s:
        f = File(path="a/x.exe", size=1, mtime_ns=1, inode=1, device=1, first_seen=now,
                 last_seen=now)  # fmt: skip
        gone = File(path="b/y.exe", size=1, mtime_ns=1, inode=2, device=1, first_seen=now,
                    last_seen=now, status="removed")  # fmt: skip
        s.add_all([f, gone])
        s.flush()
        for file_id, name, sev in [(f.id, "info_one", "info"), (f.id, "bad", "malicious"),
                                   (gone.id, "old", "malicious")]:  # fmt: skip
            s.add(Detection(file_id=file_id, engine="clamav", name=name, severity=sev,
                            first_seen=now, last_seen=now))  # fmt: skip
        s.add(EngineStatus(name="clamav", status="ok", message="fine", checked_at=now))
        s.commit()
    rows = client.get("/api/detections").json()
    assert [(r["path"], r["name"]) for r in rows] == [("a/x.exe", "bad"), ("a/x.exe", "info_one")]
    assert len(client.get("/api/detections?include_removed=true").json()) == 3
    assert [r["name"] for r in client.get("/api/detections?severity=info").json()] == ["info_one"]
    assert client.get("/api/engines").json()[0]["name"] == "clamav"
