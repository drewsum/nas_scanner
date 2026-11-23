"""Reports: a printable page per scan run, and a weekly summary stored after the scheduled full
scan. Both are plain HTML from Jinja2 templates (nasscan/templates), light and printable.

A weekly report keeps its figures (``Report.data``) rather than HTML, so it renders with the
current template and can be exported as JSON.
"""

import asyncio
import logging
from datetime import UTC, datetime, timedelta
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from nasscan import __version__
from nasscan.config import Settings
from nasscan.db import get_sessionmaker
from nasscan.db.models import (
    Detection,
    EngineStatus,
    File,
    Finding,
    IntelProvider,
    Report,
    ScanError,
    ScanRun,
)
from nasscan.scanner.base import Source

log = logging.getLogger(__name__)

WEEK = timedelta(days=7)
# Time after a scan for its last verdicts to land before the weekly report is made.
SETTLE = timedelta(seconds=30)
# Findings listed in a report; the rest are counted.
MAX_LISTED = 200

_env = Environment(
    loader=FileSystemLoader(Path(__file__).parent / "templates"),
    autoescape=select_autoescape(["html"]),
    trim_blocks=True,
    lstrip_blocks=True,
)


def _bytes(n: int | None) -> str:
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return ""


def _when(value: str | datetime | None) -> str:
    if not value:
        return ""
    if isinstance(value, str):
        value = datetime.fromisoformat(value)
    return value.astimezone().strftime("%Y-%m-%d %H:%M")


def _took(start: str | datetime | None, end: str | datetime | None) -> str:
    if not start or not end:
        return ""
    if isinstance(start, str):
        start, end = datetime.fromisoformat(start), datetime.fromisoformat(end)
    s = int((end - start).total_seconds())
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m {s % 60}s"
    return f"{s // 3600}h {s % 3600 // 60}m"


_env.filters.update(bytes=_bytes, when=_when, number=lambda n: f"{n or 0:,}")
_env.globals.update(took=_took, version=__version__)


def render(template: str, **context) -> str:
    return _env.get_template(template).render(**context)


def snapshot_versions(session: Session) -> dict:
    """Engines and feeds as they stand: what a run's results were measured against."""
    engines = [
        {
            "name": e.name,
            "status": e.status,
            "version": e.version,
            "signatures_at": e.signatures_at.isoformat() if e.signatures_at else None,
        }
        for e in session.scalars(select(EngineStatus).order_by(EngineStatus.name))
    ]
    intel = [
        {
            "name": p.name,
            "title": p.title,
            "kind": p.kind,
            "status": p.status,
            "entries": p.entries,
            "last_success": p.last_success.isoformat() if p.last_success else None,
        }
        for p in session.scalars(
            select(IntelProvider).where(IntelProvider.enabled).order_by(IntelProvider.name)
        )
    ]
    return {"engines": engines, "intel": intel}


def _finding_row(f: Finding, path: str, file_status: str) -> dict:
    counted = [e for e in f.evidence if e.get("points")]
    return {
        "id": f.id,
        "path": path,
        "file_status": file_status,
        "verdict": f.verdict,
        "score": f.score,
        "status": f.status,
        "opened_at": f.opened_at.isoformat(),
        "evidence": [f"{e['engine']}: {e['name']}" for e in counted][:5],
    }


def run_report(session: Session, run: ScanRun, settings: Settings) -> str:
    """One run's printable report: totals, what it flagged, what it couldn't read, and the
    engine and feed versions it ran with."""
    flagged_ids = select(Detection.file_id).where(Detection.run_id == run.id).distinct()
    rows = session.execute(
        select(Finding, File.path, File.status)
        .join(File, File.id == Finding.file_id)
        .where(Finding.file_id.in_(flagged_ids))
        .order_by(Finding.score.desc(), File.path)
        .limit(MAX_LISTED + 1)
    ).all()
    errors = list(
        session.scalars(
            select(ScanError).where(ScanError.run_id == run.id).order_by(ScanError.id).limit(100)
        )
    )
    return render(
        "run_report.html",
        run=run,
        findings=[_finding_row(f, path, status) for f, path, status in rows[:MAX_LISTED]],
        more_findings=len(rows) > MAX_LISTED,
        errors=errors,
        versions=run.versions or snapshot_versions(session),
        versions_live=run.versions is None,
        link=_link(settings, f"#/scans/{run.id}"),
        now=datetime.now(UTC),
    )


def _link(settings: Settings, fragment: str) -> str | None:
    return f"{settings.public_url.rstrip('/')}/{fragment}" if settings.public_url else None


def build_weekly(session: Session, end: datetime, run: ScanRun | None = None) -> Report:
    """The week to ``end``: scans, coverage, findings opened and resolved, what's open."""
    start = end - WEEK
    runs = list(
        session.scalars(
            select(ScanRun)
            .where(ScanRun.requested_at >= start, ScanRun.requested_at <= end)
            .order_by(ScanRun.id)
        )
    )
    present = File.status != "removed"
    totals = session.execute(
        select(
            func.count().filter(present),
            func.coalesce(func.sum(File.size).filter(present), 0),
            func.count().filter(present, File.last_scanned >= start),
            func.count().filter(File.status == "error"),
            func.count().filter(present, File.first_seen >= start),
            func.count().filter(File.removed_at >= start),
        )
    ).one()

    def by_verdict(*where) -> dict[str, int]:
        return dict(
            session.execute(
                select(Finding.verdict, func.count()).where(*where).group_by(Finding.verdict)
            ).all()
        )

    opened = by_verdict(Finding.opened_at >= start, Finding.opened_at <= end)
    resolved = len(
        session.scalars(
            select(Finding.id).where(Finding.resolved_at >= start, Finding.resolved_at <= end)
        ).all()
    )
    active = session.execute(
        select(Finding, File.path, File.status)
        .join(File, File.id == Finding.file_id)
        .where(Finding.status.in_(("open", "acknowledged")))
        .order_by(Finding.status, Finding.score.desc(), File.path)
        .limit(MAX_LISTED + 1)
    ).all()
    active_counts = dict(
        session.execute(
            select(Finding.status, func.count())
            .where(Finding.status.in_(("open", "acknowledged", "ignored", "allowlisted")))
            .group_by(Finding.status)
        ).all()
    )
    data = {
        "runs": [
            {
                "id": r.id,
                "kind": r.kind,
                "root": r.root,
                "trigger": r.trigger,
                "status": r.status,
                "started_at": r.started_at.isoformat() if r.started_at else None,
                "finished_at": r.finished_at.isoformat() if r.finished_at else None,
                "files_seen": r.files_seen,
                "files_new": r.files_new,
                "files_changed": r.files_changed,
                "files_removed": r.files_removed,
                "bytes_hashed": r.bytes_hashed,
                "files_flagged": r.files_flagged,
                "errors": r.errors,
            }
            for r in runs
        ],
        "files": totals[0],
        "bytes": int(totals[1]),
        "files_read": totals[2],
        "unreadable": totals[3],
        "files_new": totals[4],
        "files_removed": totals[5],
        "opened": opened,
        "resolved": resolved,
        "status_counts": active_counts,
        "active": [_finding_row(f, path, status) for f, path, status in active[:MAX_LISTED]],
        "more_active": len(active) > MAX_LISTED,
        "versions": (run.versions if run and run.versions else None) or snapshot_versions(session),
    }
    report = Report(
        kind="weekly",
        run_id=run.id if run else None,
        period_start=start,
        period_end=end,
        data=data,
        created_at=datetime.now(UTC),
    )
    session.add(report)
    session.flush()
    return report


def weekly_report_html(report: Report, settings: Settings) -> str:
    return render(
        "weekly_report.html",
        report=report,
        d=report.data,
        link=_link(settings, "#/reports"),
        findings_link=_link(settings, "#/findings"),
    )


def weekly_summary(report: Report) -> str:
    """A few lines for a notification."""
    d = report.data
    opened = d["opened"]
    open_now = d["status_counts"].get("open", 0)
    failed = sum(1 for r in d["runs"] if r["status"] == "failed")
    lines = [
        f"{d['files']:,} files ({_bytes(d['bytes'])}); {d['files_read']:,} read this week, "
        f"{d['files_new']:,} new, {d['files_removed']:,} removed.",
        f"{len(d['runs'])} scans" + (f", {failed} failed." if failed else "."),
        f"New findings: {opened.get('malicious', 0)} malicious, "
        f"{opened.get('suspicious', 0)} suspicious; {d['resolved']} resolved.",
        f"Open now: {open_now}." if open_now else "Nothing open. All clear.",
    ]
    return "\n".join(lines)


class ReportSource(Source):
    """Makes the weekly report once the scheduled full scan finishes."""

    name = "reports"
    interval_seconds = 60.0

    def __init__(self, settings: Settings) -> None:
        super().__init__(settings)
        self.sessions = get_sessionmaker()

    async def run_once(self) -> None:
        await asyncio.to_thread(self._run)

    def _run(self) -> None:
        with self.sessions() as session:
            made = make_due_reports(session)
            session.commit()
        for report_id in made:
            log.info("weekly report %d made", report_id)


def make_due_reports(session: Session) -> list[int]:
    """A report for each scheduled full scan that completed without one, covering the week to
    now. It waits until the scan's last verdicts are in (the verdict queue is empty), and only
    looks back a day, so a fresh install doesn't backfill."""
    now = datetime.now(UTC)
    if session.scalar(select(func.count()).select_from(File).where(File.verdict_pending)):
        return []
    reported = select(Report.run_id).where(Report.run_id.is_not(None))
    due = session.scalars(
        select(ScanRun)
        .where(
            ScanRun.kind == "full",
            ScanRun.trigger == "schedule",
            ScanRun.status == "completed",
            ScanRun.finished_at >= now - timedelta(days=1),
            ScanRun.finished_at <= now - SETTLE,
            ScanRun.id.not_in(reported),
        )
        .order_by(ScanRun.id)
    ).all()
    return [build_weekly(session, now, run).id for run in due]
