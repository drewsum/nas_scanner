from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from nasscan.config import Settings
from nasscan.scanner.schedule import FULL, INCREMENTAL, due_kind, next_run


def at(day: int, hour: int, minute: int = 0) -> datetime:
    # November 2026: the 22nd is a Sunday.
    return datetime(2026, 11, day, hour, minute, tzinfo=UTC)


def test_default_schedules():
    s = Settings()
    assert next_run(s.incremental_cron, at(20, 12)) == at(21, 2)
    assert next_run(s.full_cron, at(20, 12)) == at(22, 3)


def test_due_kind_fires_once_per_slot():
    s = Settings()
    assert due_kind(s, at(21, 1, 59), at(21, 2, 0)) == INCREMENTAL
    assert due_kind(s, at(21, 2, 0), at(21, 2, 1)) is None
    assert due_kind(s, at(21, 3), at(21, 4)) is None  # Saturday: no full scan


def test_full_wins_when_both_are_due():
    s = Settings()
    # Sunday 01:00 to 04:00 covers both the 02:00 incremental and the 03:00 full scan.
    assert due_kind(s, at(22, 1), at(22, 4)) == FULL
    assert due_kind(s, at(22, 1), at(22, 1) + timedelta(hours=1, minutes=30)) == INCREMENTAL


def test_invalid_cron_is_rejected(monkeypatch):
    monkeypatch.setenv("NASSCAN_FULL_CRON", "every sunday")
    with pytest.raises(ValidationError, match="cron"):
        Settings()


def test_blank_env_falls_back_to_default(monkeypatch):
    monkeypatch.setenv("NASSCAN_INCREMENTAL_CRON", "")
    assert Settings().incremental_cron == "0 2 * * *"
