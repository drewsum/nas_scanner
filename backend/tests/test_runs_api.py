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
        s.execute(text("TRUNCATE files, scan_runs RESTART IDENTITY CASCADE"))
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
