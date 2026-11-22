"""Cron schedules for the nightly incremental scan and the weekly full scan."""

import logging
from datetime import datetime

from croniter import croniter

from nasscan.config import Settings
from nasscan.db import get_sessionmaker
from nasscan.scanner.base import Source
from nasscan.scanner.runs import ScanBusyError, enqueue

log = logging.getLogger(__name__)

INCREMENTAL = "incremental"
FULL = "full"


def next_run(cron: str, after: datetime) -> datetime:
    return croniter(cron, after).get_next(datetime)


def due_kind(settings: Settings, last_check: datetime, now: datetime) -> str | None:
    """The scan that came due in (last_check, now], if any. Full wins when both are due,
    since it covers everything an incremental scan would."""
    if next_run(settings.full_cron, last_check) <= now:
        return FULL
    if next_run(settings.incremental_cron, last_check) <= now:
        return INCREMENTAL
    return None


class ScheduleSource(Source):
    """Queues a scan when its cron time passes. If one is still running, the due scan is
    skipped (and logged): a full scan running past the next night covers it anyway."""

    name = "schedule"
    interval_seconds = 30.0

    def __init__(self, settings: Settings) -> None:
        super().__init__(settings)
        self._last_check = datetime.now().astimezone()

    async def run_once(self) -> None:
        now = datetime.now().astimezone()
        kind = due_kind(self.settings, self._last_check, now)
        self._last_check = now
        if kind:
            with get_sessionmaker()() as session:
                try:
                    run = enqueue(session, kind, "schedule")
                    log.info("queued %s scan %d", kind, run.id)
                except ScanBusyError as exc:
                    log.info("%s scan due but skipped: %s", kind, exc)
