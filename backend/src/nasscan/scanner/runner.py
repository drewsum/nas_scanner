"""Runs queued scans, one at a time, in a worker thread so the heartbeat and the schedule
keep going while a scan reads files for hours."""

import asyncio
import contextlib
import logging

from nasscan.config import Settings
from nasscan.db import get_sessionmaker
from nasscan.scanner.base import Source
from nasscan.scanner.crawler import Crawler
from nasscan.scanner.hashing import Stopped
from nasscan.scanner.runs import claim_next, requeue_interrupted

log = logging.getLogger(__name__)


class ScanRunnerSource(Source):
    name = "scans"
    interval_seconds = 10.0

    def __init__(self, settings: Settings) -> None:
        super().__init__(settings)
        self._requeued = False

    async def run_once(self) -> None:
        await asyncio.to_thread(self.run_pending)

    def run_pending(self) -> None:
        sessions = get_sessionmaker()
        if not self._requeued:
            with sessions() as session:
                ids = requeue_interrupted(session)
            if ids:
                log.info("resuming interrupted scan(s) %s", ids)
            self._requeued = True
        with sessions() as session:
            run = claim_next(session)
            run_id = run.id if run else None
        if run_id is None:
            return
        # Stopped: left "running" to resume at the next start, or it was cancelled.
        with contextlib.suppress(Stopped):
            Crawler(self.settings, sessions, self.stopping).execute(run_id)
