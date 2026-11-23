"""Threat intel against a real database: feeds, lookups, prioritisation, quotas, and how
intel detections follow file contents."""

import hashlib
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, text, update

from nasscan.api.app import create_app
from nasscan.cli import main
from nasscan.config import get_settings
from nasscan.db import get_sessionmaker
from nasscan.db.models import Detection, File, HashLookup, IntelProvider
from nasscan.intel import store
from nasscan.intel.base import LookupResult, Provider, ProviderError
from nasscan.intel.sources import IntelStatusSource, LookupSource
from nasscan.scanner.crawler import Crawler
from nasscan.scanner.engines import Pipeline
from nasscan.scanner.runs import claim_next, enqueue

pytestmark = pytest.mark.db

MZ = b"MZ\x90\x00" + b"\x00" * 60 + b"PE\x00\x00"


@pytest.fixture
def root(db_env, monkeypatch, tmp_path):
    main(["migrate"])
    with get_sessionmaker()() as s:
        s.execute(
            text(
                "TRUNCATE files, scan_runs, engine_status, feed_hashes, hash_lookups, "
                "intel_providers RESTART IDENTITY CASCADE"
            )
        )
        s.commit()
    scan_root = tmp_path / "scan"
    scan_root.mkdir()
    monkeypatch.setenv("NASSCAN_SCAN_ROOT", str(scan_root))
    monkeypatch.setenv("NASSCAN_MAX_READ_MBPS", "0")
    monkeypatch.setenv("NASSCAN_INTEL_DISABLED", "circl")  # tests opt in to the gate
    get_settings.cache_clear()
    return scan_root


def put(root, rel, data):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)
    return hashlib.sha256(data).hexdigest()


def scan(kind="incremental"):
    sessions = get_sessionmaker()
    with sessions() as s:
        run_id = enqueue(s, kind, "manual", "").id
        claim_next(s)
    # No engines: these tests are about intel, and stay fast.
    Crawler(get_settings(), sessions, pipeline=Pipeline(get_settings(), engines=[])).execute(run_id)


def match():
    with get_sessionmaker()() as s:
        while store.process_pending(s):
            pass
        s.commit()


def detections() -> list[tuple[str, str, str, str]]:
    with get_sessionmaker()() as s:
        rows = s.execute(
            select(File.path, Detection.engine, Detection.name, Detection.severity)
            .join(File, File.id == Detection.file_id)
            .order_by(File.path, Detection.engine)
        )
        return [tuple(r) for r in rows]


def import_feed(feed, hashes, replace=True, name=None):
    with get_sessionmaker()() as s:
        result = store.import_feed(s, feed, [(bytes.fromhex(h), name) for h in hashes], replace)
        s.commit()
    return result


class FakeProvider(Provider):
    name = "fake"
    title = "Fake provider"
    daily_budget = 100
    per_minute = 6000  # no waiting between requests in tests
    batch_size = 10

    def __init__(self, settings, answers=None, error=None):
        super().__init__(settings)
        self.answers = answers or {}
        self.error = error
        self.calls: list[list[str]] = []

    def lookup(self, hashes):
        self.calls.append([h.sha256 for h in hashes])
        if self.error:
            raise self.error
        return {h.sha256: self.answers.get(h.sha256, LookupResult.not_found()) for h in hashes}


def provider_row(name) -> IntelProvider:
    with get_sessionmaker()() as s:
        row = s.get_one(IntelProvider, name)
        s.expunge(row)
        return row


# --- feeds ----------------------------------------------------------------------------------


def test_feed_hits_become_detections_and_follow_the_feed(root):
    bad = put(root, "downloads/bad.exe", MZ + b"bad")
    put(root, "downloads/good.exe", MZ + b"good")
    put(root, "copy/bad-again.bin", MZ + b"bad")  # same content elsewhere
    scan()
    result = import_feed("malwarebazaar-feed", [bad, "00" * 32], name="AgentTesla")
    assert (result.parsed, result.added, result.total) == (2, 2, 2)
    match()
    assert detections() == [
        ("copy/bad-again.bin", "malwarebazaar-feed", "AgentTesla", "malicious"),
        ("downloads/bad.exe", "malwarebazaar-feed", "AgentTesla", "malicious"),
    ]
    # The feed drops the hash: the detections go too.
    result = import_feed("malwarebazaar-feed", ["00" * 32])
    assert result.removed == 1
    match()
    assert detections() == []


def test_md5_feeds_match_and_new_files_are_matched_on_arrival(root):
    data = MZ + b"virusshare"
    import_feed("virusshare-feed", [hashlib.md5(data).hexdigest()], replace=False)
    put(root, "a.exe", data)
    scan()
    match()
    assert detections() == [("a.exe", "virusshare-feed", "Listed", "malicious")]


def test_an_empty_replacement_download_keeps_the_feed(root):
    import_feed("threatfox-feed", ["11" * 32])
    with pytest.raises(store.EmptyFeedError):
        import_feed("threatfox-feed", [])


def test_turning_a_feed_off_drops_it(root):
    bad = put(root, "x.exe", MZ + b"x")
    scan()
    import_feed("malwarebazaar-feed", [bad])
    match()
    assert len(detections()) == 1
    with get_sessionmaker()() as s:
        assert store.drop_feed(s, "malwarebazaar-feed") == 1
        s.commit()
    match()
    assert detections() == []


# --- lookups --------------------------------------------------------------------------------


def test_only_interesting_files_are_looked_up_most_interesting_first(root):
    exe = put(root, "apps/tool.exe", MZ + b"tool")
    script = put(root, "scripts/run.ps1", b"Write-Host hi")
    put(root, "movies/film.mkv", b"\x1a\x45\xdf\xa3" + b"\x00" * 100)
    put(root, "photos/cat.jpg", b"\xff\xd8\xff\xe0" + b"\x00" * 100)
    scan()
    match()
    fake = FakeProvider(get_settings())
    assert LookupSource(get_settings(), fake).run_sync() == 1
    assert fake.calls == [[exe, script]]  # executable before script; no media
    # Answered: nothing more to ask until the answers expire.
    assert LookupSource(get_settings(), fake).run_sync() == 0
    with get_sessionmaker()() as s:
        s.execute(update(HashLookup).values(expires_at=datetime.now(UTC) - timedelta(seconds=1)))
        s.commit()
    assert LookupSource(get_settings(), fake).run_sync() == 1


def test_lookup_hits_become_detections_on_every_copy(root):
    bad = put(root, "a/evil.exe", MZ + b"evil")
    put(root, "b/evil-copy.exe", MZ + b"evil")
    scan()
    match()
    answers = {
        bad: LookupResult(
            "malicious", "Trojan.X", "40/70 engines detect it", {"link": "https://example/x"}
        )
    }
    LookupSource(get_settings(), FakeProvider(get_settings(), answers)).run_sync()
    assert detections() == [
        ("a/evil.exe", "fake", "Trojan.X", "malicious"),
        ("b/evil-copy.exe", "fake", "Trojan.X", "malicious"),
    ]
    row = provider_row("fake")
    assert row.requests_today == 1 and row.status == "ok" and row.entries == 1


def test_feed_listed_and_known_good_hashes_are_skipped(root):
    listed = put(root, "listed.exe", MZ + b"listed")
    known = put(root, "known.exe", MZ + b"known")
    fresh = put(root, "fresh.exe", MZ + b"fresh")
    scan()
    import_feed("malwarebazaar-feed", [listed])
    match()
    with get_sessionmaker()() as s:
        store.save_lookups(
            s, "circl", {known: LookupResult("known_good", "Known file")}, get_settings()
        )
        s.commit()
    fake = FakeProvider(get_settings())
    LookupSource(get_settings(), fake).run_sync()
    assert fake.calls == [[fresh]]


def test_other_providers_wait_for_the_known_good_check(root, monkeypatch):
    monkeypatch.setenv("NASSCAN_INTEL_DISABLED", "")
    get_settings.cache_clear()
    exe = put(root, "a.exe", MZ + b"a")
    scan()
    match()
    fake = FakeProvider(get_settings())
    assert LookupSource(get_settings(), fake).run_sync() == 0  # CIRCL hasn't seen it
    with get_sessionmaker()() as s:
        store.save_lookups(s, "circl", {exe: LookupResult.not_found()}, get_settings())
        s.commit()
    assert LookupSource(get_settings(), fake).run_sync() == 1
    assert fake.calls == [[exe]]


def test_daily_budget_is_kept(root, monkeypatch):
    for i in range(5):
        put(root, f"f{i}.exe", MZ + bytes([i]))
    scan()
    match()
    fake = FakeProvider(get_settings())
    fake.batch_size, fake.daily_budget = 1, 2
    assert LookupSource(get_settings(), fake).run_sync() == 2
    assert LookupSource(get_settings(), fake).run_sync() == 0
    row = provider_row("fake")
    assert row.requests_today == 2 and row.status == "warning"
    # A new day, a new budget.
    with get_sessionmaker()() as s:
        s.execute(update(IntelProvider).values(day=datetime.now(UTC).date() - timedelta(days=1)))
        s.commit()
    assert LookupSource(get_settings(), fake).run_sync() == 2


def test_provider_errors_pause_it(root):
    put(root, "a.exe", MZ + b"a")
    scan()
    match()
    fake = FakeProvider(get_settings(), error=ProviderError("rate limited", timedelta(minutes=5)))
    assert LookupSource(get_settings(), fake).run_sync() == 1
    row = provider_row("fake")
    assert row.status == "error" and row.paused_until > datetime.now(UTC)
    assert "rate limited" in row.message
    assert LookupSource(get_settings(), fake).run_sync() == 0  # paused
    assert len(fake.calls) == 1


# --- intel and the crawler ------------------------------------------------------------------


def test_intel_detections_survive_rescans_and_go_when_the_content_changes(root):
    bad = put(root, "x.exe", MZ + b"bad")
    scan()
    import_feed("malwarebazaar-feed", [bad])
    match()
    assert len(detections()) == 1
    scan("full")  # re-read, same content: kept, not re-matched
    with get_sessionmaker()() as s:
        assert s.scalar(select(File.intel_checked_at)) is not None
    assert len(detections()) == 1
    put(root, "x.exe", MZ + b"clean now, and longer")
    scan()
    match()
    assert detections() == []


# --- status and API -------------------------------------------------------------------------


def test_status_and_api(root, monkeypatch):
    monkeypatch.setenv("NASSCAN_VIRUSTOTAL_API_KEY", "k")
    get_settings.cache_clear()
    exe = put(root, "a.exe", MZ + b"a")
    scan()
    match()
    IntelStatusSource(get_settings()).run_sync()
    with get_sessionmaker()() as s:
        store.save_lookups(
            s, "virustotal", {exe: LookupResult("clean", "VirusTotal detections")}, get_settings()
        )
        s.commit()
    with TestClient(create_app()) as client:
        providers = {p["name"]: p for p in client.get("/api/intel/providers").json()}
        assert providers["virustotal"]["enabled"]
        assert providers["virustotal"]["details"]["pending"] == 1
        assert providers["otx"]["status"] == "disabled"
        assert "NASSCAN_OTX_API_KEY" in providers["otx"]["message"]
        assert providers["circl"]["status"] == "disabled"  # listed in intel_disabled
        assert providers["malwarebazaar-feed"]["status"] == "disabled"  # no abuse.ch key
        assert providers["virusshare-feed"]["enabled"]
        assert next(iter(providers)).endswith("-feed")
        lookups = client.get(f"/api/intel/lookups/{exe}").json()
        assert [(lk["provider"], lk["verdict"]) for lk in lookups] == [("virustotal", "clean")]
        assert client.get("/api/intel/lookups/nothex").status_code == 422
