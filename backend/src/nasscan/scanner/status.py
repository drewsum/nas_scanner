"""Background tasks for the engines: the daily YARA rule refresh, and each engine's health and
signature age, recorded in engine_status for the UI."""

import asyncio
import logging
from datetime import UTC, datetime, timedelta

from nasscan.config import Settings
from nasscan.health import record
from nasscan.scanner.base import Source
from nasscan.scanner.engines.base import EngineUnavailableError
from nasscan.scanner.engines.clamav import ClamdClient, parse_version
from nasscan.scanner.engines.yara_rules import RuleStore

log = logging.getLogger(__name__)

# Signatures older than this mean updates have stopped.
STALE_AFTER = timedelta(days=3)


def check_clamav(settings: Settings) -> None:
    if not settings.clamd_host:
        record("clamav", "disabled", "NASSCAN_CLAMD_HOST isn't set")
        return
    client = ClamdClient(settings.clamd_host, settings.clamd_port, 10)
    try:
        engine, db_version, db_date = parse_version(client.version())
    except (EngineUnavailableError, OSError) as exc:
        record("clamav", "error", f"clamd isn't answering (it can take minutes to start): {exc}")
        return
    # clamd reports the database date in its own (container) local time; close enough.
    when = db_date.replace(tzinfo=UTC) if db_date else None
    stale = when is not None and datetime.now(UTC) - when > STALE_AFTER
    record(
        "clamav",
        "warning" if stale else "ok",
        (f"Signatures are from {when:%Y-%m-%d}; freshclam may be failing" if stale
         else f"ClamAV {engine}, signature database {db_version}"),
        version=engine,
        signatures_at=when,
        details={"database_version": db_version},
    )  # fmt: skip


def check_yara(settings: Settings) -> None:
    store = RuleStore(settings)
    manifest = store.read_manifest()
    if not store.compiled.exists() or not manifest:
        record("yara", "warning", "No rules compiled yet (the first download runs at startup)")
        return
    built = datetime.fromisoformat(manifest["built_at"])
    failed = {k: v for k, v in manifest.get("sources", {}).items() if v != "ok"}
    stale = datetime.now(UTC) - built > STALE_AFTER
    message = f"{manifest.get('rule_files', 0)} rule files compiled"
    if manifest.get("skipped"):
        message += f", {len(manifest['skipped'])} skipped (don't compile)"
    if failed:
        message += "; " + "; ".join(f"{k}: {v}" for k, v in failed.items())
    record(
        "yara",
        "warning" if failed or stale else "ok",
        message,
        version=None,
        signatures_at=built,
        details={
            "sources": manifest.get("sources", {}),
            "skipped": manifest.get("skipped", [])[:50],
        },
    )


def check_builtin() -> None:
    try:
        from oletools import olevba

        ole = getattr(olevba, "__version__", "?")
    except ImportError:
        ole = None
    record("heuristics", "ok", "Name, type and location checks")
    record(
        "documents",
        "ok" if ole else "error",
        f"Office macros (oletools {ole}) and PDF active content" if ole else "oletools missing",
        version=ole,
    )
    record("printing", "ok", "3MF/AMF contents, G-code commands, STL validity")


def check_all(settings: Settings) -> None:
    for check in (check_clamav, check_yara):
        try:
            check(settings)
        except Exception:
            log.exception("engine check %s failed", check.__name__)
    check_builtin()


class EngineStatusSource(Source):
    name = "engine-status"
    interval_seconds = 300.0

    async def run_once(self) -> None:
        await asyncio.to_thread(check_all, self.settings)


class YaraUpdateSource(Source):
    """Downloads and compiles the YARA rules when they're older than
    NASSCAN_YARA_REFRESH_HOURS (and at the first start)."""

    name = "yara-rules"
    # Checks this often; downloads only when the rules are older than the refresh interval,
    # recompiles without downloading when your local rules change.
    interval_seconds = 60.0

    def __init__(self, settings: Settings) -> None:
        super().__init__(settings)
        self.store = RuleStore(settings)

    async def run_once(self) -> None:
        if self.store.due():
            await asyncio.to_thread(self._refresh, True)
        elif self.store.local_changed():
            log.info("YARA: local rules changed; recompiling")
            await asyncio.to_thread(self._refresh, False)

    def _refresh(self, download: bool) -> None:
        try:
            self.store.refresh(download)
        except EngineUnavailableError as exc:
            log.warning("YARA rules not built: %s", exc)
        check_yara(self.settings)
