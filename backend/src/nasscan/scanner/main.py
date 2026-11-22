import asyncio
import contextlib
import logging
import signal
import time
from datetime import datetime
from pathlib import Path

from nasscan.config import Settings
from nasscan.scanner.base import Source
from nasscan.scanner.priority import lower_priority
from nasscan.scanner.runner import ScanRunnerSource
from nasscan.scanner.schedule import ScheduleSource, next_run

log = logging.getLogger(__name__)

# Background tasks register here as milestones land (M1 crawler, M2 engines, M3 feeds, ...).
SOURCE_TYPES: list[type[Source]] = [ScheduleSource, ScanRunnerSource]


async def _loop(source: Source, stop: asyncio.Event) -> None:
    try:
        while not stop.is_set():
            started = time.monotonic()
            try:
                await source.run_once()
            except Exception:
                log.exception("source %s failed", source.name)
            delay = max(0.0, source.interval_seconds - (time.monotonic() - started))
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(stop.wait(), timeout=delay)
    finally:
        try:
            await source.close()
        except Exception:
            log.exception("source %s failed to close", source.name)


async def _heartbeat(settings: Settings, stop: asyncio.Event) -> None:
    path = Path(settings.scanner_heartbeat_file)
    while not stop.is_set():
        path.write_text(str(time.time()))
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(stop.wait(), timeout=settings.scanner_tick_seconds)


async def run(settings: Settings) -> None:
    # Before any thread starts, so the scan workers inherit it.
    lower_priority(settings)
    sources = [cls(settings) for cls in SOURCE_TYPES]
    stop = asyncio.Event()

    def shutdown() -> None:
        stop.set()
        for s in sources:
            s.stopping.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError):  # Windows
            loop.add_signal_handler(sig, shutdown)

    now = datetime.now().astimezone()
    log.info(
        "next incremental scan %s, next full scan %s",
        next_run(settings.incremental_cron, now).isoformat(timespec="minutes"),
        next_run(settings.full_cron, now).isoformat(timespec="minutes"),
    )
    active = [s for s in sources if s.enabled()]
    for s in sources:
        log.info("source %s: %s", s.name, "enabled" if s in active else "disabled")

    async with asyncio.TaskGroup() as tg:
        tg.create_task(_heartbeat(settings, stop))
        for s in active:
            tg.create_task(_loop(s, stop))
    log.info("scanner stopped")
