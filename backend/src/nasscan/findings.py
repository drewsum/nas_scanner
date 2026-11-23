"""Findings: the verdict for each file with detections, and its triage lifecycle.

Database triggers set ``files.verdict_pending`` whenever a file's detections, status or
content change (migration 0005). ``evaluate_pending`` works through those files: it scores
them, then opens, updates, reopens or resolves their finding.

Lifecycle, per file:
- suspicious or malicious, no finding yet: a new finding, ``open`` (``allowlisted`` when an
  allowlist entry matches).
- still flagged: evidence and score are updated. ``resolved`` and ``allowlisted`` findings
  reopen. ``acknowledged`` stays acknowledged unless it escalates (suspicious to malicious) or
  the content changes. ``ignored`` stays ignored until the content changes.
- clean again, or removed: ``resolved`` (resolution ``clean`` or ``removed``).
"""

import asyncio
import fnmatch
import logging
from collections import defaultdict
from collections.abc import Sequence
from datetime import UTC, datetime

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from nasscan.config import Settings
from nasscan.db import get_sessionmaker
from nasscan.db.models import AllowlistEntry, Detection, File, Finding, HashLookup
from nasscan.scanner.base import Source
from nasscan.verdict import RANK, Evidence, Scoring, judge

log = logging.getLogger(__name__)

BATCH = 500


def queue_all(session: Session) -> int:
    """Queue every file with detections or a finding, e.g. after an allowlist or weight
    change."""
    return session.execute(
        text(
            """
            UPDATE files SET verdict_pending = true
            WHERE NOT verdict_pending
              AND (id IN (SELECT file_id FROM detections) OR id IN (SELECT file_id FROM findings))
            """
        )
    ).rowcount


def _claim(session: Session, limit: int) -> list[int]:
    """Take a batch of queued files and clear their flag in this transaction. Rows another
    transaction is writing are skipped; its trigger re-queues them after this one commits, so
    a change can't slip between reading the evidence and clearing the flag."""
    # Files with nothing to judge are cleared in bulk first: a scan that removes thousands
    # of files queues them all.
    session.execute(
        text(
            """
            UPDATE files SET verdict_pending = false
            WHERE id IN (
                SELECT f.id FROM files f
                WHERE f.verdict_pending
                  AND NOT EXISTS (SELECT 1 FROM detections d WHERE d.file_id = f.id)
                  AND NOT EXISTS (SELECT 1 FROM findings x WHERE x.file_id = f.id)
                LIMIT 10000
                FOR UPDATE SKIP LOCKED
            )
            """
        )
    )
    return list(
        session.scalars(
            text(
                """
                UPDATE files SET verdict_pending = false
                WHERE id IN (
                    SELECT id FROM files WHERE verdict_pending
                    ORDER BY id LIMIT :limit FOR UPDATE SKIP LOCKED
                )
                RETURNING id
                """
            ),
            {"limit": limit},
        )
    )


def allowlisted(entries: Sequence[AllowlistEntry], file: File) -> AllowlistEntry | None:
    for entry in entries:
        if entry.kind == "sha256" and file.sha256 and entry.value == file.sha256:
            return entry
        if entry.kind == "path" and fnmatch.fnmatchcase(file.path, entry.value):
            return entry
    return None


def evaluate_pending(session: Session, settings: Settings, limit: int = BATCH) -> int:
    """Judge one batch of queued files. Returns how many were taken (0: queue empty).
    The caller commits."""
    ids = _claim(session, limit)
    if not ids:
        return 0
    now = datetime.now(UTC)
    scoring = Scoring.from_settings(settings)
    entries = list(session.scalars(select(AllowlistEntry)))

    files = {f.id: f for f in session.scalars(select(File).where(File.id.in_(ids)))}
    findings = {
        x.file_id: x for x in session.scalars(select(Finding).where(Finding.file_id.in_(ids)))
    }
    detections: dict[int, list[Detection]] = defaultdict(list)
    for d in session.scalars(select(Detection).where(Detection.file_id.in_(ids))):
        detections[d.file_id].append(d)
    shas = {f.sha256 for f in files.values() if f.sha256}
    known_good = set(
        session.scalars(
            select(HashLookup.sha256).where(
                HashLookup.sha256.in_(shas), HashLookup.verdict == "known_good"
            )
        )
        if shas
        else []
    )

    for file_id in ids:
        file = files.get(file_id)
        if file is None:
            continue
        _evaluate(
            session,
            file,
            detections.get(file_id, []),
            file.sha256 in known_good,
            findings.get(file_id),
            entries,
            scoring,
            now,
        )
    return len(ids)


def _evaluate(
    session: Session,
    file: File,
    detections: list[Detection],
    known_good: bool,
    finding: Finding | None,
    entries: Sequence[AllowlistEntry],
    scoring: Scoring,
    now: datetime,
) -> None:
    if file.status == "removed":
        if finding is not None:
            _resolve(finding, "removed", now)
        return
    v = judge(
        (
            Evidence(
                engine=d.engine,
                name=d.name,
                severity=d.severity,
                member=d.member,
                description=d.description,
                link=(d.details or {}).get("link"),
            )
            for d in detections
        ),
        scoring,
        known_good,
    )
    if v.verdict == "clean":
        if finding is not None:
            finding.score, finding.evidence = v.score, v.evidence
            _resolve(finding, "clean", now)
        return

    allowed = allowlisted(entries, file) is not None
    if finding is None:
        session.add(
            Finding(
                file_id=file.id,
                sha256=file.sha256,
                verdict=v.verdict,
                score=v.score,
                evidence=v.evidence,
                status="allowlisted" if allowed else "open",
                first_seen=now,
                last_seen=now,
                opened_at=now,
                status_changed_at=now,
                verdict_changed_at=now,
                updated_at=now,
            )
        )
        return

    new_content = finding.sha256 != file.sha256
    escalated = RANK[v.verdict] > RANK.get(finding.verdict, 0)
    if allowed:
        status = "allowlisted"
    elif (
        finding.status in ("resolved", "allowlisted")
        or (finding.status in ("acknowledged", "ignored") and new_content)
        or (finding.status == "acknowledged" and escalated)
    ):
        status = "open"
    else:
        status = finding.status
    if status != finding.status:
        finding.status, finding.status_changed_at = status, now
        if status == "open":
            finding.opened_at = now
    if status != "resolved":
        finding.resolution, finding.resolved_at = None, None
    if v.verdict != finding.verdict:
        finding.verdict, finding.verdict_changed_at = v.verdict, now
    finding.sha256 = file.sha256
    finding.score, finding.evidence = v.score, v.evidence
    finding.last_seen = finding.updated_at = now


def _resolve(finding: Finding, resolution: str, now: datetime) -> None:
    finding.updated_at = now
    if finding.status == "resolved" and finding.resolution == resolution:
        return
    finding.status, finding.resolution = "resolved", resolution
    finding.resolved_at = finding.status_changed_at = now


def evaluate_all(session: Session, settings: Settings) -> int:
    """Work the queue until empty, committing per batch (API calls after an allowlist change,
    and the scanner's loop)."""
    total = 0
    while done := evaluate_pending(session, settings):
        session.commit()
        total += done
    session.commit()
    return total


def set_status(finding: Finding, status: str, note: str | None, now: datetime) -> None:
    """A triage choice from the UI: open, acknowledged or ignored."""
    if finding.status in ("resolved", "allowlisted"):
        raise ValueError(f"the finding is {finding.status}")
    if status != finding.status:
        finding.status, finding.status_changed_at = status, now
        if status == "open":
            finding.opened_at = now
    if note is not None:
        finding.note = note.strip() or None
    finding.updated_at = now


class VerdictSource(Source):
    """Keeps findings in step with detections, a few seconds behind."""

    name = "verdicts"
    interval_seconds = 15.0

    def __init__(self, settings: Settings) -> None:
        super().__init__(settings)
        self._started = False

    async def run_once(self) -> None:
        await asyncio.to_thread(self._run)

    def _run(self) -> None:
        with get_sessionmaker()() as session:
            if not self._started:
                # Weights or thresholds may have changed since the last start.
                queue_all(session)
                session.commit()
                self._started = True
            total = 0
            while not self.stopping.is_set():
                done = evaluate_pending(session, self.settings)
                session.commit()
                total += done
                if not done:
                    break
        if total:
            log.info("verdicts updated for %d files", total)
