"""Reports (a printable page per scan run, stored weekly reports) and notifications (status,
recent sends, and a test button)."""

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select

from nasscan import reports
from nasscan.api.deps import DB
from nasscan.config import get_settings
from nasscan.db.models import Notification, Report, ScanRun
from nasscan.notify import Notifier, deliver

router = APIRouter(prefix="/api", tags=["reports"])


class ReportOut(BaseModel):
    id: int
    kind: str
    run_id: int | None
    period_start: datetime
    period_end: datetime
    created_at: datetime
    notified_at: datetime | None
    open_findings: int
    opened: dict[str, int]
    scans: int


def _out(r: Report) -> ReportOut:
    return ReportOut(
        id=r.id,
        kind=r.kind,
        run_id=r.run_id,
        period_start=r.period_start,
        period_end=r.period_end,
        created_at=r.created_at,
        notified_at=r.notified_at,
        open_findings=r.data.get("status_counts", {}).get("open", 0),
        opened=r.data.get("opened", {}),
        scans=len(r.data.get("runs", [])),
    )


@router.get("/runs/{run_id}/report", response_class=HTMLResponse)
def run_report(run_id: int, db: DB) -> HTMLResponse:
    """The run's printable report."""
    run = db.get(ScanRun, run_id)
    if run is None:
        raise HTTPException(404, "no such scan")
    return HTMLResponse(reports.run_report(db, run, get_settings()))


@router.get("/reports", response_model=list[ReportOut])
def list_reports(db: DB, limit: Annotated[int, Query(ge=1, le=500)] = 52) -> list[ReportOut]:
    """Newest first."""
    return [_out(r) for r in db.scalars(select(Report).order_by(Report.id.desc()).limit(limit))]


@router.post("/reports", response_model=ReportOut, status_code=201)
def make_report(db: DB) -> ReportOut:
    """A weekly report for the seven days to now (not sent anywhere)."""
    report = reports.build_weekly(db, datetime.now(UTC))
    report.notified_at = report.created_at
    db.commit()
    return _out(report)


def _get(db, report_id: int) -> Report:
    report = db.get(Report, report_id)
    if report is None:
        raise HTTPException(404, "no such report")
    return report


@router.get("/reports/{report_id}", response_class=HTMLResponse)
def read_report(report_id: int, db: DB) -> HTMLResponse:
    return HTMLResponse(reports.weekly_report_html(_get(db, report_id), get_settings()))


@router.get("/reports/{report_id}/data")
def report_data(report_id: int, db: DB) -> dict:
    """The report's figures, as JSON."""
    r = _get(db, report_id)
    return {
        "id": r.id,
        "kind": r.kind,
        "run_id": r.run_id,
        "period_start": r.period_start,
        "period_end": r.period_end,
        "created_at": r.created_at,
        **r.data,
    }


class NotificationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    kind: str
    title: str
    body: str
    ok: bool
    error: str | None
    created_at: datetime


class NotifyStatus(BaseModel):
    configured: bool
    services: int
    links: bool  # NASSCAN_PUBLIC_URL is set, so messages link back here
    min_verdict: str
    max_per_hour: int
    digest: bool
    weekly_report: bool
    recent: list[NotificationOut]


class TestResult(BaseModel):
    ok: bool
    error: str | None


@router.get("/notify", response_model=NotifyStatus)
def notify_status(db: DB) -> NotifyStatus:
    settings = get_settings()
    notifier = Notifier(settings)
    recent = db.scalars(select(Notification).order_by(Notification.id.desc()).limit(20))
    return NotifyStatus(
        configured=notifier.services > 0,
        services=notifier.services,
        links=bool(settings.public_url),
        min_verdict=settings.notify_min_verdict,
        max_per_hour=settings.notify_max_per_hour,
        digest=settings.notify_digest,
        weekly_report=settings.notify_weekly_report,
        recent=[NotificationOut.model_validate(n) for n in recent],
    )


@router.post("/notify/test", response_model=TestResult)
def notify_test(db: DB) -> TestResult:
    """Send a test message to every NASSCAN_APPRISE_URLS service, and say how it went."""
    notifier = Notifier(get_settings())
    if not notifier.services:
        raise HTTPException(409, "notifications are off: set NASSCAN_APPRISE_URLS")
    body = "If you can read this, NAS Scanner alerts will reach you here."
    link = notifier.link("")
    if link:
        body += f"\n\n{link}"
    ok = deliver(db, notifier, "test", "nasscan: test notification", body, "info")
    last = db.scalar(select(Notification).order_by(Notification.id.desc()).limit(1))
    return TestResult(ok=ok, error=None if ok else last.error if last else "failed")
