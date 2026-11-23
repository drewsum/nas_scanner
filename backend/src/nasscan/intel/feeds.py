"""Downloaded hash feeds: lists of known-malicious hashes, matched locally against every
hashed file, so even files no live provider is ever asked about get checked.

Built in: MalwareBazaar and ThreatFox (abuse.ch, need a free Auth-Key) and VirusShare's MD5
lists (no key). Any other hash list can be added by URL (NASSCAN_INTEL_EXTRA_FEEDS).
"""

import csv
import io
import logging
import re
import zipfile
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx

from nasscan.config import Settings

log = logging.getLogger(__name__)

HEX = re.compile(r"^[0-9a-fA-F]+$")
HASH_LENGTHS = {32: "md5", 40: "sha1", 64: "sha256"}
# Columns that name the threat, in the order they're preferred.
NAME_COLUMNS = ("signature", "malware_printable", "malware", "threat", "family")
HASH_TYPES = {"sha256_hash", "md5_hash", "sha1_hash"}
HEADER_NAMES = {"sha256_hash", "md5_hash", "sha1_hash", "ioc_value", "sha256", "sha1", "md5"}
MAX_DOWNLOAD = 4 * 1024**3


class FeedError(RuntimeError):
    pass


@dataclass
class Download:
    url: str
    # Every hash this feed holds is in this file: hashes it no longer lists are dropped.
    replace: bool
    label: str  # for logs and the UI, without any key in it


class Feed:
    name: str
    title: str
    needs_abusech_key = False
    # How often a refresh is due.
    refresh = timedelta(hours=24)

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.refresh = timedelta(hours=settings.intel_feed_refresh_hours)

    @property
    def abusech_key(self) -> str | None:
        key = self.settings.abusech_auth_key
        return key.get_secret_value() if key else None

    def disabled_reason(self) -> str | None:
        if self.name in self.settings.intel_disabled_names:
            return "listed in NASSCAN_INTEL_DISABLED"
        if self.needs_abusech_key and not self.abusech_key:
            return "set NASSCAN_ABUSECH_AUTH_KEY (free at auth.abuse.ch) to turn it on"
        return None

    def downloads(self, state: dict, client: httpx.Client) -> list[Download]:
        raise NotImplementedError

    def after_import(self, state: dict, download: Download) -> None:
        """Remember what was imported (in the provider's details)."""


class MalwareBazaarFeed(Feed):
    name = "malwarebazaar-feed"
    title = "MalwareBazaar hash export"
    needs_abusech_key = True
    base = "https://mb-api.abuse.ch/v2/files/exports/{key}/"
    full_every = timedelta(days=7)

    def downloads(self, state: dict, client: httpx.Client) -> list[Download]:
        base = self.base.format(key=self.abusech_key)
        last_full = state.get("last_full")
        if not last_full or datetime.fromisoformat(last_full) < datetime.now(UTC) - (
            self.full_every
        ):
            return [Download(base + "full.csv.zip", True, "full.csv.zip")]
        return [Download(base + "recent.csv", False, "recent.csv")]

    def after_import(self, state: dict, download: Download) -> None:
        if download.replace:
            state["last_full"] = datetime.now(UTC).isoformat()


class ThreatFoxFeed(Feed):
    """ThreatFox IOCs of the last six months; only the file hashes are used."""

    name = "threatfox-feed"
    title = "ThreatFox IOC export (file hashes)"
    needs_abusech_key = True
    url = "https://threatfox-api.abuse.ch/v2/files/exports/{key}/full.csv.zip"

    def downloads(self, state: dict, client: httpx.Client) -> list[Download]:
        return [Download(self.url.format(key=self.abusech_key), True, "full.csv.zip")]


class VirusShareFeed(Feed):
    """VirusShare's MD5 lists (65,536 hashes each in recent ones). Lists don't change once
    complete, so each is fetched once, plus the newest (which may still be filling) on every
    refresh."""

    name = "virusshare-feed"
    title = "VirusShare MD5 lists"
    index_url = "https://virusshare.com/hashes"
    list_url = "https://virusshare.com/hashfiles/VirusShare_{n:05d}.md5"

    def downloads(self, state: dict, client: httpx.Client) -> list[Download]:
        try:
            page = client.get(self.index_url)
            page.raise_for_status()
        except httpx.HTTPError as exc:
            raise FeedError(f"can't read the VirusShare index: {exc}") from exc
        numbers = [int(n) for n in re.findall(r"VirusShare_(\d+)\.md5", page.text)]
        if not numbers:
            raise FeedError("the VirusShare index lists no hash files")
        newest = max(numbers)
        wanted = range(max(0, newest - self.settings.virusshare_lists + 1), newest + 1)
        done = set(state.get("lists", []))
        return [
            Download(self.list_url.format(n=n), False, f"VirusShare_{n:05d}.md5")
            for n in wanted
            if n not in done or n == newest
        ]

    def after_import(self, state: dict, download: Download) -> None:
        n = int(re.search(r"(\d+)\.md5$", download.label).group(1))  # type: ignore[union-attr]
        state["lists"] = sorted(set(state.get("lists", [])) | {n})


class UrlFeed(Feed):
    """A hash list at any URL (NASSCAN_INTEL_EXTRA_FEEDS)."""

    def __init__(self, settings: Settings, name: str, url: str) -> None:
        super().__init__(settings)
        self.name = f"{name[:27]}-feed"
        self.title = f"Custom feed {name}"
        self.url = url
        self.needs_abusech_key = "{abusech_key}" in url

    def downloads(self, state: dict, client: httpx.Client) -> list[Download]:
        url = self.url.replace("{abusech_key}", self.abusech_key or "")
        label = re.sub(r"/exports/[^/]+/", "/exports/<key>/", self.url).replace(
            "{abusech_key}", "<key>"
        )
        return [Download(url, True, label)]


BUILTIN_FEEDS: dict[str, type[Feed]] = {
    "malwarebazaar": MalwareBazaarFeed,
    "threatfox": ThreatFoxFeed,
    "virusshare": VirusShareFeed,
}


def all_feeds(settings: Settings) -> list[Feed]:
    """Every feed that could run: the built-ins (listed or not, so the UI can show them
    as off) and the custom ones."""
    feeds: list[Feed] = [cls(settings) for cls in BUILTIN_FEEDS.values()]
    feeds += [UrlFeed(settings, n, u) for n, u in settings.intel_extra_feed_urls.items()]
    return feeds


def feed_listed(settings: Settings, feed: Feed) -> bool:
    if isinstance(feed, UrlFeed):
        return True
    short = feed.name.removesuffix("-feed")
    return short in settings.intel_feed_names


# --- download and parse ---------------------------------------------------------------------


def fetch(client: httpx.Client, download: Download, dest: Path) -> Path:
    """Stream a download to ``dest``."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    total = 0
    try:
        with client.stream("GET", download.url) as response:
            if response.status_code in (401, 403):
                raise FeedError(f"{download.label}: key rejected (HTTP {response.status_code})")
            if response.status_code >= 400:
                raise FeedError(f"{download.label}: HTTP {response.status_code}")
            with dest.open("wb") as out:
                for chunk in response.iter_bytes(1024 * 1024):
                    total += len(chunk)
                    if total > MAX_DOWNLOAD:
                        raise FeedError(f"{download.label}: bigger than 4 GB")
                    out.write(chunk)
    except httpx.HTTPError as exc:
        raise FeedError(f"{download.label}: {type(exc).__name__}: {exc}") from exc
    return dest


def text_lines(path: Path) -> Iterator[str]:
    """Lines of a downloaded file, unzipping it if it's a zip (every text member)."""
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as z:
            for info in z.infolist():
                if info.is_dir():
                    continue
                with z.open(info) as raw:
                    yield from io.TextIOWrapper(raw, encoding="utf-8", errors="replace")
        return
    with path.open(encoding="utf-8", errors="replace") as f:
        yield from f


def _header(line: str) -> list[str] | None:
    """abuse.ch exports put their column names in a comment: # "first_seen_utc","sha256_hash"."""
    body = line.lstrip("#").strip()
    if "," not in body:
        return None
    cols = [c.strip().strip('"').lower() for c in next(csv.reader([body]))]
    return cols if any(c in HEADER_NAMES for c in cols) else None


def parse_hashes(lines: Iterator[str]) -> Iterator[tuple[bytes, str | None]]:
    """(raw hash bytes, threat name) for every hash in a CSV or plain list. With a known
    header only the hash columns count (and ThreatFox rows only when the IOC is a file hash);
    without one, every field that looks like an MD5, SHA-1 or SHA-256 does."""
    header: list[str] | None = None
    for line in lines:
        line = line.strip()
        if not line:
            continue
        if line.startswith("#"):
            header = _header(line) or header
            continue
        fields = [f.strip().strip('"').strip() for f in next(csv.reader([line]), [])]
        lowered = [f.lower() for f in fields]
        if header is None and any(c in HEADER_NAMES for c in lowered):
            header = lowered  # a header row that isn't a comment
            continue
        name = None
        candidates = fields
        if header and len(fields) == len(header):
            row = dict(zip(header, fields, strict=True))
            for col in NAME_COLUMNS:
                value = row.get(col)
                if value and value.lower() not in ("n/a", "none", "null", ""):
                    name = value[:200]
                    break
            if "ioc_type" in row:
                candidates = [row.get("ioc_value", "")] if row["ioc_type"] in HASH_TYPES else []
            else:
                candidates = [
                    row[c]
                    for c in ("sha256_hash", "sha1_hash", "md5_hash", "sha256", "sha1", "md5")
                    if row.get(c)
                ]
        for value in candidates:
            if len(value) in HASH_LENGTHS and HEX.match(value):
                yield bytes.fromhex(value), name
