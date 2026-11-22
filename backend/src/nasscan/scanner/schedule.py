"""Cron schedules for the nightly incremental scan and the weekly full scan."""

import logging
from datetime import datetime

from croniter import croniter

from nasscan.config import Settings
from nasscan.scanner.base import Source

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
    """Starts scans when their cron time passes. Scans themselves arrive in M1; until then
    a due scan is only logged."""

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
            log.info("%s scan due (scanning arrives in M1)", kind)
