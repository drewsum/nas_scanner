"""Notifications through Apprise (NASSCAN_APPRISE_URLS): email with mailto://, ntfy, Discord and
the other services Apprise knows (github.com/caronc/apprise/wiki).

What goes out, every 30 seconds at most:
- **Alerts** for findings that opened (or reopened) at NASSCAN_NOTIFY_MIN_VERDICT or worse.
  All waiting at once go in one message. A finding alerts once per opening, so acknowledging
  it, or the next scan seeing it again, sends nothing.
- **Failed scans**, always; **scan digests** after every finished scan with NASSCAN_NOTIFY_DIGEST.
- **The weekly report**, when it's made (NASSCAN_NOTIFY_WEEKLY_REPORT).
- **Health problems:** an engine (ClamAV, YARA, ...) or the database backup in trouble for
  half an hour, or no backup for twice the backup interval; and again when it's fixed.

At most NASSCAN_NOTIFY_MAX_PER_HOUR messages go out in any hour (failed tries count, so a
broken mail server isn't hammered); what's left waits and goes out together. Only paths,
verdicts and engine names are sent: never file contents.
"""

import asyncio
import logging
from datetime import UTC, datetime, timedelta

import apprise
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from nasscan.config import Settings
from nasscan.db import get_sessionmaker
from nasscan.db.models import EngineStatus, File, Finding, Notification, Report, ScanRun
from nasscan.health import PROBLEMS
from nasscan.reports import weekly_summary
from nasscan.scanner.base import Source

log = logging.getLogger(__name__)

# Findings listed in one alert; the rest are counted.
MAX_LINES = 10
# Alerts and digests older than this when they could finally go out are dropped.
GIVE_UP = timedelta(days=2)
RANK = {"suspicious": 1, "malicious": 2}
# A problem must last this long before it's notified: clamd takes minutes to load after a
# restart, and the first YARA download runs at startup.
HEALTH_GRACE = timedelta(minutes=30)
HEALTH_LABELS = {
    "clamav": "ClamAV",
    "yara": "YARA",
    "documents": "The document checks",
    "backup": "The database backup",
}
NOTIFY_TYPES = {
    "info": apprise.NotifyType.INFO,
    "success": apprise.NotifyType.SUCCESS,
    "warning": apprise.NotifyType.WARNING,
    "failure": apprise.NotifyType.FAILURE,
}


class NotifyError(Exception):
    pass


class Notifier:
    """Apprise, loaded with NASSCAN_APPRISE_URLS."""

    def __init__(self, settings: Settings) -> None:
        self.apprise = apprise.Apprise()
        urls = settings.apprise_urls.get_secret_value() if settings.apprise_urls else ""
        if urls.strip():
            self.apprise.add(urls)
        self.public_url = settings.public_url.rstrip("/") if settings.public_url else None

    @property
    def services(self) -> int:
        return len(self.apprise)

    def link(self, fragment: str) -> str | None:
        return f"{self.public_url}/{fragment}" if self.public_url else None

    def send(self, title: str, body: str, level: str = "info") -> None:
        if not self.services:
            raise NotifyError("none of NASSCAN_APPRISE_URLS is a URL Apprise understands")
        if not self.apprise.notify(title=title, body=body, notify_type=NOTIFY_TYPES[level]):
            raise NotifyError(f"Apprise couldn't deliver to all {self.services} services")


def deliver(
    session: Session, notifier: Notifier, kind: str, title: str, body: str, level: str
) -> bool:
    """Send and log it. Returns whether it went out."""
    error = None
    try:
        notifier.send(title, body, level)
    except Exception as exc:  # Apprise's own errors too
        error = str(exc)[:2000] or type(exc).__name__
        log.warning("notification %r failed: %s", title, error)
    session.add(
        Notification(
            kind=kind,
            title=title,
            body=body,
            ok=error is None,
            error=error,
            created_at=datetime.now(UTC),
        )
    )
    session.commit()
    return error is None


def sent_last_hour(session: Session, now: datetime) -> int:
    return (
        session.scalar(
            select(func.count())
            .select_from(Notification)
            .where(Notification.created_at >= now - timedelta(hours=1), Notification.kind != "test")
        )
        or 0
    )


def _evidence(f: Finding) -> str:
    engines = []
    for e in f.evidence:
        if e.get("points") and e["engine"] not in engines:
            engines.append(f"{e['engine']} ({e['name']})")
    return ", ".join(engines[:4]) or "—"


def compose_alert(rows: list[tuple[Finding, str]], notifier: Notifier) -> tuple[str, str, str]:
    """Title, body and level of one alert for these (finding, path) pairs."""
    worst = max(rows, key=lambda r: (RANK[r[0].verdict], r[0].score))[0]
    level = "failure" if worst.verdict == "malicious" else "warning"
    if len(rows) == 1:
        f, path = rows[0]
        title = f"nasscan: {f.verdict} file found"
        lines = [path, f"Verdict: {f.verdict} (score {f.score})", f"Flagged by: {_evidence(f)}"]
        if f.sha256:
            lines.append(f"SHA-256: {f.sha256}")
        link = notifier.link(f"#/findings/{f.id}")
    else:
        counts = {v: sum(1 for f, _ in rows if f.verdict == v) for v in ("malicious", "suspicious")}
        title = "nasscan: " + ", ".join(f"{n} {v}" for v, n in counts.items() if n) + " files found"
        lines = [f"• [{f.verdict}] {path} — {_evidence(f)}" for f, path in rows[:MAX_LINES]]
        if len(rows) > MAX_LINES:
            lines.append(f"…and {len(rows) - MAX_LINES} more")
        link = notifier.link("#/findings")
    if link:
        lines += ["", link]
    return title, "\n".join(lines), level


def compose_run(run: ScanRun, notifier: Notifier) -> tuple[str, str, str]:
    what = f"{run.kind} scan" + (f" of {run.root}" if run.root else "")
    if run.status == "failed":
        title, level = f"nasscan: {what} failed", "failure"
    else:
        title = f"nasscan: {what} {run.status}"
        level = "warning" if run.files_flagged or run.errors else "success"
    lines = [run.message or ""]
    if run.status != "failed":
        lines = [
            f"{run.files_seen:,} files: {run.files_new:,} new, {run.files_changed:,} changed, "
            f"{run.files_removed:,} removed; {run.files_hashed:,} read.",
            f"Flagged: {run.files_flagged:,}. Errors: {run.errors:,}.",
        ]
    link = notifier.link(f"#/scans/{run.id}")
    if link:
        lines += ["", link]
    return title, "\n".join(lines), level


Health = tuple[EngineStatus, str]  # a row and what to say about it


def health_problems(
    session: Session, settings: Settings, now: datetime
) -> tuple[list[Health], list[Health]]:
    """Rows whose problem should be notified now, and rows whose notified problem is over."""
    problems, recovered = [], []
    overdue = timedelta(hours=settings.backup_interval_hours * 2 + 1)
    for row in session.scalars(select(EngineStatus).order_by(EngineStatus.name)):
        # A backup service that stopped writing is a problem too.
        silent = row.name == "backup" and row.checked_at < now - overdue
        since = row.problem_since or row.checked_at
        failing = row.status in PROBLEMS and since <= now - HEALTH_GRACE
        if (silent or failing) and row.alerted_at is None:
            message = row.message
            if silent and not failing:
                message = (
                    f"no backup since {row.checked_at.astimezone():%Y-%m-%d %H:%M}; "
                    "is the backup container running?"
                )
            problems.append((row, message))
        elif not silent and row.status not in PROBLEMS and row.alerted_at is not None:
            recovered.append((row, row.message))
    return problems, recovered


def compose_health(
    problems: list[Health], recovered: list[Health], notifier: Notifier
) -> tuple[str, str, str]:
    def label(row: EngineStatus) -> str:
        return HEALTH_LABELS.get(row.name, row.name)

    if problems:
        title = f"nasscan: {', '.join(label(r) for r, _ in problems)} needs attention"
        lines = [f"• {label(r)}: {m}" for r, m in problems]
        lines += [f"• {label(r)} is working again." for r, _ in recovered]
        level = "warning"
    else:
        title = f"nasscan: {', '.join(label(r) for r, _ in recovered)} working again"
        lines = [f"• {label(r)}: {m}" for r, m in recovered]
        level = "success"
    link = notifier.link("#/status")
    if link:
        lines += ["", link]
    return title, "\n".join(lines), level


def send_pending(session: Session, settings: Settings, notifier: Notifier, now: datetime) -> int:
    """One round: alerts first, then failed scans and digests, then reports, while the hourly
    cap allows. Returns how many messages went out."""
    budget = settings.notify_max_per_hour - sent_last_hour(session, now)
    sent = 0

    # Alerts: open findings whose latest opening hasn't been alerted.
    due = session.execute(
        select(Finding, File.path)
        .join(File, File.id == Finding.file_id)
        .where(
            Finding.status == "open",
            Finding.verdict.in_(
                [v for v, r in RANK.items() if r >= RANK[settings.notify_min_verdict]]
            ),
            (Finding.alerted_at.is_(None)) | (Finding.alerted_at < Finding.opened_at),
        )
        .order_by(Finding.score.desc(), Finding.opened_at)
    ).all()
    stale = [f for f, _ in due if f.opened_at < now - GIVE_UP]
    fresh = [(f, path) for f, path in due if f.opened_at >= now - GIVE_UP]
    for f in stale:
        f.alerted_at = now
    session.commit()
    if fresh and budget > 0:
        if deliver(session, notifier, "alert", *compose_alert(fresh, notifier)):
            for f, _ in fresh:
                f.alerted_at = now
            session.commit()
            sent += 1
        budget -= 1

    # Finished scans: failures always, the rest with the digest on.
    runs = session.scalars(
        select(ScanRun)
        .where(
            ScanRun.notified_at.is_(None), ScanRun.status.in_(("completed", "failed", "cancelled"))
        )
        .order_by(ScanRun.id)
    ).all()
    for run in runs:
        wanted = run.status == "failed" or (settings.notify_digest and run.status == "completed")
        too_old = (run.finished_at or now) < now - GIVE_UP
        if not wanted or too_old:
            run.notified_at = now
            continue
        if budget <= 0:
            break
        budget -= 1
        if deliver(session, notifier, "scan", *compose_run(run, notifier)):
            run.notified_at = now
            sent += 1
    session.commit()

    # Engine and backup health.
    problems, recovered = health_problems(session, settings, now)
    if (problems or recovered) and budget > 0:
        budget -= 1
        if deliver(session, notifier, "health", *compose_health(problems, recovered, notifier)):
            for row, _ in problems:
                row.alerted_at = now
            for row, _ in recovered:
                row.alerted_at = None
            sent += 1
        session.commit()

    # Weekly reports.
    for report in session.scalars(select(Report).where(Report.notified_at.is_(None))).all():
        if not settings.notify_weekly_report:
            report.notified_at = now
            continue
        if budget <= 0:
            break
        budget -= 1
        body = weekly_summary(report)
        link = notifier.link(f"api/reports/{report.id}")
        if link:
            body += f"\n\nThe report: {link}"
        end = report.period_end.astimezone().strftime("%Y-%m-%d")
        if deliver(session, notifier, "weekly", f"nasscan: weekly report to {end}", body, "info"):
            report.notified_at = now
            sent += 1
    session.commit()
    return sent


class NotifySource(Source):
    """Sends what's due, every 30 seconds. Off without NASSCAN_APPRISE_URLS."""

    name = "notify"
    interval_seconds = 30.0

    def __init__(self, settings: Settings) -> None:
        super().__init__(settings)
        self.notifier = Notifier(settings)

    def enabled(self) -> bool:
        return self.notifier.services > 0

    async def run_once(self) -> None:
        await asyncio.to_thread(self._run)

    def _run(self) -> None:
        with get_sessionmaker()() as session:
            send_pending(session, self.settings, self.notifier, datetime.now(UTC))
