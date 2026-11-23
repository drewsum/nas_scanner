"""The scanner's threat-intel background tasks.

- intel-feeds downloads the hash feeds when they're due.
- intel-match applies feed matches and cached lookups to new and changed files.
- lookup-<provider>, one per live provider, spends that provider's per-minute rate and daily
  budget on the most interesting hashes nobody has answered yet.
- intel-status records every provider's state (including the ones that are off) for the UI.
"""

import asyncio
import logging
import math
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx

from nasscan.config import Settings
from nasscan.db import get_sessionmaker
from nasscan.db.models import IntelProvider
from nasscan.intel import store
from nasscan.intel.base import USER_AGENT, Provider, ProviderError
from nasscan.intel.feeds import (
    Feed,
    FeedError,
    all_feeds,
    feed_listed,
    fetch,
    parse_hashes,
    text_lines,
)
from nasscan.intel.lookups import PROVIDER_TYPES
from nasscan.scanner.base import Source

log = logging.getLogger(__name__)

# A feed that failed is tried again after this long.
FEED_RETRY = timedelta(hours=1)


def gate_for(settings: Settings, provider: Provider) -> tuple[str | None, bool]:
    """(the known-good provider this one waits for, whether this one is it)."""
    if provider.known_good_source:
        return None, True
    for cls in PROVIDER_TYPES:
        if cls.known_good_source:
            other = cls(settings)
            if other.enabled():
                return other.name, False
    return None, False


class IntelMatchSource(Source):
    name = "intel-match"
    interval_seconds = 30.0

    async def run_once(self) -> None:
        await asyncio.to_thread(self._run)

    def _run(self) -> None:
        sessions = get_sessionmaker()
        total = 0
        while not self.stopping.is_set():
            with sessions() as session:
                done = store.process_pending(session)
                session.commit()
            total += done
            if done == 0:
                break
        if total:
            log.info("threat intel applied to %d new or changed files", total)


class FeedSource(Source):
    name = "intel-feeds"
    interval_seconds = 300.0

    def __init__(self, settings: Settings) -> None:
        super().__init__(settings)
        self.client = httpx.Client(
            timeout=httpx.Timeout(120.0, connect=15.0),
            headers={"User-Agent": USER_AGENT},
            follow_redirects=True,
        )

    async def run_once(self) -> None:
        await asyncio.to_thread(self._run)

    async def close(self) -> None:
        self.client.close()

    def _run(self) -> None:
        sessions = get_sessionmaker()
        for feed in all_feeds(self.settings):
            if self.stopping.is_set():
                return
            if not feed_listed(self.settings, feed) or feed.disabled_reason():
                with sessions() as session:
                    if store.drop_feed(session, feed.name):
                        log.info("feed %s is off; its hashes were dropped", feed.name)
                    session.commit()
                continue
            with sessions() as session:
                row = store.ensure_provider(session, feed.name, "feed", feed.title)
                due = self._due(feed, row)
                session.commit()
            if due:
                self.refresh(feed)

    @staticmethod
    def _due(feed: Feed, row: IntelProvider) -> bool:
        now = datetime.now(UTC)
        if row.last_attempt and row.last_attempt > now - FEED_RETRY:
            return False
        return row.last_success is None or row.last_success <= now - feed.refresh

    def refresh(self, feed: Feed) -> None:
        sessions = get_sessionmaker()
        with sessions() as session:
            row = store.ensure_provider(session, feed.name, "feed", feed.title)
            row.last_attempt = datetime.now(UTC)
            details = dict(row.details or {})
            session.commit()
        state = dict(details.get("state", {}))
        folder = Path(self.settings.data_dir) / "feeds"
        imported, added, removed, labels = 0, 0, 0, []
        try:
            downloads = feed.downloads(state, self.client)
            for download in downloads:
                if self.stopping.is_set():
                    return
                log.info("feed %s: downloading %s", feed.name, download.label)
                path = fetch(self.client, download, folder / f"{feed.name}.download")
                try:
                    with sessions() as session:
                        result = store.import_feed(
                            session, feed.name, parse_hashes(text_lines(path)), download.replace
                        )
                        session.commit()
                finally:
                    path.unlink(missing_ok=True)
                feed.after_import(state, download)
                imported += result.parsed
                added += result.added
                removed += result.removed
                labels.append(download.label)
                with sessions() as session:
                    row = store.ensure_provider(session, feed.name, "feed", feed.title)
                    row.entries = result.total
                    row.details = details | {"state": state}
                    session.commit()
                log.info(
                    "feed %s: %s held %d hashes, %d new, %d dropped; %d in all",
                    feed.name, download.label, result.parsed, result.added, result.removed,
                    result.total,
                )  # fmt: skip
        except (FeedError, store.EmptyFeedError, OSError, ValueError) as exc:
            log.warning("feed %s failed: %s", feed.name, exc)
            with sessions() as session:
                row = store.ensure_provider(session, feed.name, "feed", feed.title)
                now = datetime.now(UTC)
                row.status, row.last_error, row.last_error_at = "error", str(exc)[:2000], now
                row.message = f"Refresh failed: {str(exc)[:300]}"
                row.details = dict(row.details or {}) | {"state": state}
                row.updated_at = now
                session.commit()
            return
        with sessions() as session:
            row = store.ensure_provider(session, feed.name, "feed", feed.title)
            now = datetime.now(UTC)
            row.status, row.last_success, row.updated_at = "ok", now, now
            row.message = (
                f"{row.entries:,} hashes; last refresh read {imported:,} "
                f"({added:,} new, {removed:,} dropped)"
            )
            row.details = dict(row.details or {}) | {"downloads": labels, "state": state}
            session.commit()


class LookupSource(Source):
    """Spends one provider's quota. Runs once a minute, making up to its per-minute rate in
    requests, spaced evenly, within what's left of today's budget."""

    interval_seconds = 60.0

    def __init__(self, settings: Settings, provider: Provider) -> None:
        super().__init__(settings)
        self.provider = provider
        self.name = f"lookup-{provider.name}"

    def enabled(self) -> bool:
        return self.provider.enabled()

    async def run_once(self) -> None:
        await asyncio.to_thread(self.run_sync)

    async def close(self) -> None:
        self.provider.close()

    def run_sync(self) -> int:
        """Returns the number of requests made."""
        p = self.provider
        sessions = get_sessionmaker()
        gate, is_gate = gate_for(self.settings, p)
        spacing = 60.0 / p.per_minute
        with sessions() as session:
            row = store.ensure_provider(session, p.name, "lookup", p.title)
            now = datetime.now(UTC)
            store.roll_day(row, now.date())
            row.daily_budget, row.per_minute, row.enabled = p.daily_budget, p.per_minute, True
            paused = row.paused_until and row.paused_until > now
            # Under one request a minute: wait out the spacing since the last one.
            too_soon = (
                p.per_minute < 1
                and row.last_attempt is not None
                and row.last_attempt > now - timedelta(seconds=spacing)
            )
            left = p.daily_budget - row.requests_today
            if left <= 0 and not paused:
                row.status = "warning"
                row.message = (
                    f"Daily budget of {p.daily_budget} requests used; resumes at 00:00 UTC"
                )
            session.commit()
        if paused or too_soon or left <= 0:
            return 0
        made = 0
        for _ in range(min(max(1, math.floor(p.per_minute)), left)):
            with sessions() as session:
                batch = store.candidates(session, p.name, p.batch_size, gate=gate, is_gate=is_gate)
            if not batch:
                if made == 0:
                    self._idle(gate)
                break
            try:
                results = p.lookup(batch)
            except ProviderError as exc:
                self._failed(exc)
                return made + 1
            made += 1
            with sessions() as session:
                store.save_lookups(session, p.name, results, self.settings)
                store.apply_hashes(session, list(results))
                row = store.ensure_provider(session, p.name, "lookup", p.title)
                now = datetime.now(UTC)
                store.roll_day(row, now.date())
                row.requests_today += 1
                row.entries += len(results)
                row.last_attempt = row.last_success = row.updated_at = now
                row.status = "ok"
                hits = sum(r.verdict in ("malicious", "suspicious") for r in results.values())
                row.message = f"{row.requests_today}/{p.daily_budget} requests today" + (
                    f"; last batch flagged {hits}" if hits else ""
                )
                session.commit()
            if self.stopping.wait(spacing):
                break
        return made

    def _idle(self, gate: str | None) -> None:
        with get_sessionmaker()() as session:
            row = store.ensure_provider(session, self.provider.name, "lookup", self.provider.title)
            if row.status != "error" or (row.paused_until and row.paused_until < datetime.now(UTC)):
                row.status = "ok"
                row.message = (
                    f"{row.requests_today}/{self.provider.daily_budget} requests today; "
                    "nothing waiting"
                    + (f" (waits for {gate} to rule out known-good files)" if gate else "")
                )
            session.commit()

    def _failed(self, exc: ProviderError) -> None:
        log.warning("%s lookup failed: %s", self.provider.name, exc)
        with get_sessionmaker()() as session:
            row = store.ensure_provider(session, self.provider.name, "lookup", self.provider.title)
            now = datetime.now(UTC)
            store.roll_day(row, now.date())
            row.requests_today += 1
            row.status = "error"
            row.last_attempt = row.last_error_at = row.updated_at = now
            row.last_error = str(exc)[:2000]
            row.paused_until = now + exc.pause if exc.pause else None
            row.message = str(exc)[:300] + (
                f"; retrying after {row.paused_until:%H:%M} UTC" if exc.pause else ""
            )
            session.commit()


class IntelStatusSource(Source):
    """Records which providers and feeds are on, why the others are off, and how many hashes
    wait for each provider."""

    name = "intel-status"
    interval_seconds = 300.0

    async def run_once(self) -> None:
        await asyncio.to_thread(self.run_sync)

    def run_sync(self) -> None:
        sessions = get_sessionmaker()
        now = datetime.now(UTC)
        with sessions() as session:
            for feed in all_feeds(self.settings):
                row = store.ensure_provider(session, feed.name, "feed", feed.title)
                reason = (
                    "not listed in NASSCAN_INTEL_FEEDS"
                    if not feed_listed(self.settings, feed)
                    else feed.disabled_reason()
                )
                row.enabled = reason is None
                if reason:
                    row.status, row.message = "disabled", reason
                elif row.status in ("disabled", "idle"):
                    row.status, row.message = "idle", "Waiting for the first download"
                row.updated_at = row.updated_at or now
            for cls in PROVIDER_TYPES:
                p = cls(self.settings)
                try:
                    row = store.ensure_provider(session, p.name, "lookup", p.title)
                    reason = p.disabled_reason()
                    row.enabled = reason is None
                    row.daily_budget, row.per_minute = p.daily_budget, p.per_minute
                    store.roll_day(row, now.date())
                    if reason:
                        row.status, row.message = "disabled", reason
                        continue
                    if row.status in ("disabled", "idle"):
                        row.status, row.message = "idle", "Waiting for hashes to look up"
                    gate, is_gate = gate_for(self.settings, p)
                    row.details = dict(row.details or {}) | {
                        "pending": store.pending_count(session, p.name, gate=gate, is_gate=is_gate),
                        "link": p.link,
                        "batch_size": p.batch_size,
                    }
                finally:
                    p.close()  # never opened: status checks make no requests
            session.commit()


def intel_sources(settings: Settings) -> list[Source]:
    sources: list[Source] = [
        IntelStatusSource(settings),
        FeedSource(settings),
        IntelMatchSource(settings),
    ]
    sources += [LookupSource(settings, cls(settings)) for cls in PROVIDER_TYPES]
    return sources
