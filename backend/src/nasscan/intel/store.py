"""Threat intel in the database: turning feed matches and cached lookups into detections,
importing feeds, choosing what to look up next, and provider state.

Intel detections belong to files but come from hashes: the same answer applies to every
copy of a file. A file's intel detections are rebuilt from scratch whenever its content
changes or the evidence for its hash does, so they never outlive the evidence.
"""

import logging
from collections import defaultdict
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta

from sqlalchemy import delete, func, or_, select, text, tuple_, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from nasscan.config import Settings
from nasscan.db.models import Detection, FeedHash, File, HashLookup, IntelProvider
from nasscan.intel.base import DETECTION_VERDICTS, Hashes, LookupResult
from nasscan.scanner.engines import LOCAL_ENGINE_NAMES

log = logging.getLogger(__name__)

# More changed feed hashes than this and every file is re-matched instead of just the files
# holding those hashes (a feed's first import, say).
RESET_ALL_OVER = 200_000
CHUNK = 5000
KNOWN_GOOD_RECHECK = timedelta(days=90)


def _chunks(items: Sequence, size: int = CHUNK) -> Iterator[Sequence]:
    for i in range(0, len(items), size):
        yield items[i : i + size]


# --- applying evidence to files -------------------------------------------------------------


def apply_files(session: Session, files: Sequence[File], now: datetime) -> int:
    """Rebuild the intel detections of these files from feed matches and cached lookups,
    and mark them checked. Returns how many files have intel detections now."""
    if not files:
        return 0
    raw: set[bytes] = set()
    for f in files:
        for h in (f.sha256, f.sha1, f.md5):
            if h:
                raw.add(bytes.fromhex(h))
    feed_hits: dict[bytes, list[tuple[str, str | None]]] = defaultdict(list)
    for chunk in _chunks(list(raw)):
        for h, feed, name in session.execute(
            select(FeedHash.hash, FeedHash.feed, FeedHash.name).where(FeedHash.hash.in_(chunk))
        ):
            feed_hits[bytes(h)].append((feed, name))
    shas = list({f.sha256 for f in files if f.sha256})
    lookups: dict[str, list[HashLookup]] = defaultdict(list)
    for chunk in _chunks(shas):
        for lk in session.scalars(
            select(HashLookup).where(
                HashLookup.sha256.in_(chunk), HashLookup.verdict.in_(list(DETECTION_VERDICTS))
            )
        ):
            lookups[lk.sha256].append(lk)

    flagged = 0
    for f in files:
        evidence: dict[tuple[str, str], dict] = {}
        for value, kind in ((f.sha256, "sha256"), (f.sha1, "sha1"), (f.md5, "md5")):
            if not value:
                continue
            for feed, name in feed_hits.get(bytes.fromhex(value), []):
                evidence[(feed, (name or "Listed")[:500])] = {
                    "severity": "malicious",
                    "description": f"Listed in the {feed.removesuffix('-feed')} hash feed "
                    f"({kind} match)",
                    "details": {"feed": feed, "hash": value, "hash_type": kind, "name": name},
                }
        for lk in lookups.get(f.sha256 or "", []):
            evidence[(lk.provider, (lk.name or lk.provider)[:500])] = {
                "severity": DETECTION_VERDICTS[lk.verdict],
                "description": lk.description,
                "details": (lk.details or {}) | {"looked_up_at": lk.looked_up_at.isoformat()},
            }
        for (engine, name), values in evidence.items():
            stmt = insert(Detection).values(
                file_id=f.id,
                engine=engine,
                name=name,
                member="",
                severity=values["severity"],
                description=(values["description"] or "")[:2000],
                details=values["details"],
                run_id=None,
                first_seen=now,
                last_seen=now,
            )
            session.execute(
                stmt.on_conflict_do_update(
                    index_elements=["file_id", "engine", "name", "member"],
                    set_={k: stmt.excluded[k] for k in ("severity", "description", "details")}
                    | {"last_seen": stmt.excluded.last_seen},
                )
            )
        stale = delete(Detection).where(
            Detection.file_id == f.id, Detection.engine.not_in(LOCAL_ENGINE_NAMES)
        )
        if evidence:
            stale = stale.where(tuple_(Detection.engine, Detection.name).not_in(list(evidence)))
            flagged += 1
        session.execute(stale)
    session.execute(
        update(File).where(File.id.in_([f.id for f in files])).values(intel_checked_at=now)
    )
    return flagged


def process_pending(session: Session, limit: int = 1000) -> int:
    """Apply intel to files that are new, changed, or whose evidence changed. Returns how many
    were processed (0: nothing left)."""
    files = list(
        session.scalars(
            select(File)
            .where(File.intel_checked_at.is_(None), File.status == "active")
            .order_by(File.id)
            .limit(limit)
        )
    )
    apply_files(session, files, datetime.now(UTC))
    return len(files)


def apply_hashes(session: Session, shas: Iterable[str]) -> None:
    """Re-apply intel to every active copy of these hashes (after new lookups)."""
    shas = list(set(shas))
    for chunk in _chunks(shas):
        files = list(
            session.scalars(select(File).where(File.sha256.in_(chunk), File.status == "active"))
        )
        apply_files(session, files, datetime.now(UTC))


def reset_matching(session: Session, hex_hashes: Sequence[str]) -> None:
    """Queue the files holding any of these hashes to have their intel re-applied."""
    for chunk in _chunks(list(hex_hashes)):
        session.execute(
            update(File)
            .where(
                File.status == "active",
                or_(File.sha256.in_(chunk), File.md5.in_(chunk), File.sha1.in_(chunk)),
            )
            .values(intel_checked_at=None)
        )


def reset_all(session: Session) -> None:
    session.execute(
        update(File)
        .where(File.status == "active", File.intel_checked_at.is_not(None))
        .values(intel_checked_at=None)
    )


# --- feeds ----------------------------------------------------------------------------------


@dataclass
class ImportResult:
    parsed: int
    added: int
    removed: int
    total: int


class EmptyFeedError(RuntimeError):
    pass


def import_feed(
    session: Session,
    feed: str,
    pairs: Iterable[tuple[bytes, str | None]],
    replace: bool,
) -> ImportResult:
    """Load (hash, name) pairs into feed_hashes for one feed (COPY into a temp table, then
    one upsert). With ``replace``, hashes the feed no longer lists are dropped. Files holding
    added or dropped hashes are queued for re-matching."""
    now = datetime.now(UTC)
    conn = session.connection()
    conn.execute(text("CREATE TEMP TABLE feed_import (hash bytea, name text) ON COMMIT DROP"))
    parsed = 0
    raw = conn.connection.driver_connection
    with raw.cursor() as cur, cur.copy("COPY feed_import (hash, name) FROM STDIN") as copy:
        for h, name in pairs:
            copy.write_row((h, name))
            parsed += 1
    if replace and parsed == 0:
        raise EmptyFeedError("the download holds no hashes; keeping the previous copy")
    conn.execute(
        text(
            """
            INSERT INTO feed_hashes (hash, feed, name, added_at, seen_at)
            SELECT DISTINCT ON (hash) hash, :feed, name, :now, :now
            FROM feed_import ORDER BY hash, name NULLS LAST
            ON CONFLICT (hash, feed) DO UPDATE
            SET seen_at = EXCLUDED.seen_at, name = COALESCE(EXCLUDED.name, feed_hashes.name)
            """
        ),
        {"feed": feed, "now": now},
    )
    added = session.scalar(
        select(func.count()).where(FeedHash.feed == feed, FeedHash.added_at == now)
    )
    removed: list[bytes] = []
    if replace:
        removed = list(
            session.scalars(
                delete(FeedHash)
                .where(FeedHash.feed == feed, FeedHash.seen_at < now)
                .returning(FeedHash.hash)
            )
        )
    changed = (added or 0) + len(removed)
    if changed > RESET_ALL_OVER:
        reset_all(session)
    elif changed:
        new = session.scalars(
            select(FeedHash.hash).where(FeedHash.feed == feed, FeedHash.added_at == now)
        )
        reset_matching(session, [bytes(h).hex() for h in [*new, *removed]])
    total = session.scalar(select(func.count()).where(FeedHash.feed == feed)) or 0
    return ImportResult(parsed, added or 0, len(removed), total)


def drop_feed(session: Session, feed: str) -> int:
    """Forget a feed that was turned off, and re-match the files it had flagged."""
    flagged = list(
        session.scalars(select(Detection.file_id).where(Detection.engine == feed).distinct())
    )
    gone = session.execute(delete(FeedHash).where(FeedHash.feed == feed)).rowcount
    if flagged:
        for chunk in _chunks(flagged):
            session.execute(update(File).where(File.id.in_(chunk)).values(intel_checked_at=None))
    return gone or 0


# --- live lookups ---------------------------------------------------------------------------


def _candidate_sql(gate: str | None, count: bool) -> str:
    gating = ""
    if gate:
        # Wait until the known-good source has seen the hash.
        gating = (
            "AND EXISTS (SELECT 1 FROM hash_lookups g "
            "WHERE g.provider = :gate AND g.sha256 = f.sha256)"
        )
    body = f"""
        FROM files f
        LEFT JOIN hash_lookups hl ON hl.provider = :provider AND hl.sha256 = f.sha256
        WHERE f.status = 'active' AND f.intel_priority > 0 AND f.sha256 IS NOT NULL
          AND f.intel_checked_at IS NOT NULL
          AND (hl.sha256 IS NULL OR hl.expires_at <= :now)
          AND NOT EXISTS (SELECT 1 FROM detections d
                          WHERE d.file_id = f.id AND d.engine LIKE '%-feed')
          AND (:is_gate OR NOT EXISTS (SELECT 1 FROM hash_lookups k
                          WHERE k.sha256 = f.sha256 AND k.verdict = 'known_good'))
          {gating}
    """
    if count:
        return f"SELECT count(DISTINCT f.sha256) {body}"
    return f"""
        SELECT f.sha256, max(f.sha1) AS sha1, max(f.md5) AS md5
        {body}
        GROUP BY f.sha256
        ORDER BY bool_or(hl.sha256 IS NULL) DESC, max(f.intel_priority) DESC,
                 max(f.first_seen) DESC
        LIMIT :limit
    """


def candidates(
    session: Session,
    provider: str,
    limit: int,
    *,
    gate: str | None = None,
    is_gate: bool = False,
) -> list[Hashes]:
    """The next hashes to send a provider: never asked before first, then expired answers;
    the highest priority and newest files first. Hashes a feed already lists, and hashes known
    good, are skipped. With ``gate``, only hashes that provider has already answered."""
    rows = session.execute(
        text(_candidate_sql(gate, count=False)),
        {
            "provider": provider,
            "now": datetime.now(UTC),
            "gate": gate,
            "is_gate": is_gate,
            "limit": limit,
        },
    )
    return [Hashes(r.sha256, r.sha1, r.md5) for r in rows]


def pending_count(session: Session, provider: str, *, gate: str | None, is_gate: bool) -> int:
    return session.scalar(
        text(_candidate_sql(gate, count=True)),
        {"provider": provider, "now": datetime.now(UTC), "gate": gate, "is_gate": is_gate},
    )


def save_lookups(
    session: Session, provider: str, results: dict[str, LookupResult], settings: Settings
) -> None:
    now = datetime.now(UTC)
    for sha256, r in results.items():
        if r.verdict in DETECTION_VERDICTS:
            ttl = timedelta(days=settings.intel_hit_recheck_days)
        elif r.verdict == "known_good":
            ttl = KNOWN_GOOD_RECHECK
        else:
            ttl = timedelta(days=settings.intel_recheck_days)
        values = {
            "provider": provider,
            "sha256": sha256,
            "verdict": r.verdict,
            "name": (r.name or "")[:500] or None,
            "description": (r.description or "")[:2000] or None,
            "details": r.details or None,
            "looked_up_at": now,
            "expires_at": now + ttl,
        }
        stmt = insert(HashLookup).values(**values)
        session.execute(
            stmt.on_conflict_do_update(
                index_elements=["provider", "sha256"],
                set_={k: stmt.excluded[k] for k in values if k not in ("provider", "sha256")},
            )
        )


# --- provider state -------------------------------------------------------------------------


def ensure_provider(session: Session, name: str, kind: str, title: str) -> IntelProvider:
    session.execute(
        insert(IntelProvider)
        .values(name=name, kind=kind, title=title, status="idle", message="")
        .on_conflict_do_nothing(index_elements=["name"])
    )
    row = session.get_one(IntelProvider, name, populate_existing=True)
    row.kind, row.title = kind, title
    return row


def roll_day(row: IntelProvider, today: date) -> None:
    if row.day != today:
        row.day = today
        row.requests_today = 0
