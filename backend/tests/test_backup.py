"""Backups and restore."""

import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.pool import NullPool

from nasscan.backup import (
    BackupError,
    dump_name,
    dump_time,
    dumps,
    make_dump,
    pg_connection,
    prune,
    restore,
    seconds_until_due,
)
from nasscan.cli import main
from nasscan.config import get_settings
from nasscan.db import get_engine

NOW = datetime(2026, 11, 15, 3, 0, tzinfo=UTC)


def touch_dumps(directory: Path, *hours_ago: int) -> list[Path]:
    paths = [directory / dump_name(NOW - timedelta(hours=h)) for h in hours_ago]
    for p in paths:
        p.write_bytes(b"dump")
    return paths


class FakePg:
    """Stands in for pg_dump/pg_restore: records calls, writes the --file it's given."""

    def __init__(self, returncode: int = 0, stderr: str = "") -> None:
        self.calls: list[tuple[list[str], dict]] = []
        self.returncode, self.stderr = returncode, stderr

    def __call__(self, args, env, **_) -> subprocess.CompletedProcess:
        self.calls.append((args, env))
        if "--file" in args:
            Path(args[args.index("--file") + 1]).write_bytes(b"PGDMP fake")
        return subprocess.CompletedProcess(args, self.returncode, "", self.stderr)


def test_dump_names_carry_their_time():
    name = dump_name(NOW)
    assert name == "nasscan-20261115T030000Z.dump"
    assert dump_time(Path(name)) == NOW
    assert dump_time(Path("notes.txt")) is None
    assert dump_time(Path("nasscan-garbage.dump")) is None


def test_a_dump_is_due_when_the_newest_is_older_than_the_interval(tmp_path):
    day = timedelta(hours=24)
    assert seconds_until_due(tmp_path, NOW, day) == 0  # none yet
    touch_dumps(tmp_path, 30, 2)
    assert seconds_until_due(tmp_path, NOW, day) == 22 * 3600
    assert seconds_until_due(tmp_path, NOW + timedelta(hours=23), day) == 0


def test_prune_keeps_the_newest_and_drops_unfinished(tmp_path):
    newest, middle, oldest = touch_dumps(tmp_path, 1, 25, 49)
    partial = tmp_path / (dump_name(NOW) + ".partial")
    partial.write_bytes(b"half")
    (tmp_path / "keep-me.txt").write_text("not a dump")
    assert set(prune(tmp_path, keep=2)) == {oldest, partial}
    assert dumps(tmp_path) == [newest, middle]
    assert (tmp_path / "keep-me.txt").exists()


def test_password_goes_in_the_environment_not_the_arguments():
    args, env = pg_connection(make_url("postgresql+psycopg://nasscan:s3cret@db:5432/nasscan"))
    assert args == ["--host", "db", "--port", "5432", "--username", "nasscan"]
    assert env["PGPASSWORD"] == "s3cret"
    assert "s3cret" not in " ".join(args)


def test_make_dump_renames_only_a_finished_dump(tmp_path, monkeypatch):
    monkeypatch.setenv("NASSCAN_BACKUP_DIR", str(tmp_path))
    monkeypatch.setenv("NASSCAN_DATABASE_URL", "postgresql+psycopg://u:pw@db:5432/nasscan")
    pg = FakePg()
    path = make_dump(get_settings(), NOW, pg)
    assert path == tmp_path / "nasscan-20261115T030000Z.dump"
    assert path.read_bytes() == b"PGDMP fake"
    args, env = pg.calls[0]
    assert Path(args[0]).name == "pg_dump" and "--format=custom" in args and args[-1] == "nasscan"
    assert env["PGPASSWORD"] == "pw"

    failing = FakePg(returncode=1, stderr="pg_dump: error: connection refused")
    with pytest.raises(BackupError, match="connection refused"):
        make_dump(get_settings(), NOW + timedelta(days=1), failing)
    assert dumps(tmp_path) == [path]
    assert not list(tmp_path.glob("*.partial"))


def test_restore_recreates_the_target_database(db_env):
    main(["migrate"])
    target = "nasscan_restore_test"
    pg = FakePg()
    dump = Path("x.dump")
    dump.write_bytes(b"PGDMP fake")
    assert restore(get_settings(), dump, target, pg) == target
    args, _ = pg.calls[0]
    assert Path(args[0]).name == "pg_restore" and args[-3:] == ["--dbname", target, "x.dump"]

    admin = create_engine(
        make_url(db_env.database_url).set(database="postgres"),
        poolclass=NullPool,
        isolation_level="AUTOCOMMIT",
    )
    try:
        with admin.connect() as conn:
            assert conn.scalar(text("SELECT 1 FROM pg_database WHERE datname = :d"), {"d": target})
            conn.execute(text(f"DROP DATABASE IF EXISTS {target}"))
    finally:
        admin.dispose()


def test_restore_refuses_while_the_app_is_connected(db_env):
    main(["migrate"])
    dump = Path("x.dump")
    dump.write_bytes(b"PGDMP fake")
    with get_engine().connect() as conn:  # stands in for the api
        conn.execute(text("SELECT 1"))
        with pytest.raises(BackupError, match="stop the api and scanner"):
            restore(get_settings(), dump, None, FakePg())
        assert conn.scalar(text("SELECT count(*) FROM alembic_version")) == 1


def test_restore_of_the_live_database_needs_yes(db_env):
    with pytest.raises(SystemExit, match="--yes"):
        main(["restore", "x.dump"])
