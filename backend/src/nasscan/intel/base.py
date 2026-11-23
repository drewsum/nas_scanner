"""What every live lookup provider shares: the interface, results and errors."""

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta

import httpx

from nasscan.config import Settings

log = logging.getLogger(__name__)

USER_AGENT = "nas-scanner (+https://github.com/drewsum/nas_scanner)"

# Verdicts that become detections, and the detection severity for each.
DETECTION_VERDICTS = {"malicious": "malicious", "suspicious": "suspicious", "info": "info"}


@dataclass(frozen=True)
class Hashes:
    sha256: str
    sha1: str | None = None
    md5: str | None = None


@dataclass
class LookupResult:
    """A provider's answer about one hash."""

    verdict: str  # one of db.models.VERDICTS
    name: str | None = None  # threat name; stable, it keys the detection
    description: str | None = None  # the human summary, e.g. "12/70 engines"
    details: dict = field(default_factory=dict)

    @classmethod
    def not_found(cls) -> "LookupResult":
        return cls("not_found")


class ProviderError(RuntimeError):
    """The provider couldn't answer. ``pause`` keeps it from being asked again for a while
    (rate limited, key rejected)."""

    def __init__(self, message: str, pause: timedelta | None = None) -> None:
        super().__init__(message)
        self.pause = pause


class Provider(ABC):
    name: str
    title: str
    # Settings attribute holding the API key, if the provider needs one.
    key_setting: str | None = None
    # Free-tier defaults; NASSCAN_INTEL_LIMITS overrides them.
    daily_budget: int = 1000
    per_minute: float = 10
    # Hashes per request.
    batch_size: int = 1
    # Its known_good answers keep hashes away from the other providers, so they wait for it.
    known_good_source: bool = False
    link: str | None = None  # web page for a hash, with {sha256}

    def __init__(self, settings: Settings, client: httpx.Client | None = None) -> None:
        self.settings = settings
        daily, minute = settings.intel_limit_overrides.get(self.name, (None, None))
        if daily is not None:
            self.daily_budget = daily
        if minute is not None and minute > 0:
            self.per_minute = minute
        self._client = client

    @property
    def client(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(
                timeout=httpx.Timeout(30.0, connect=10.0),
                headers={"User-Agent": USER_AGENT},
                follow_redirects=True,
            )
        return self._client

    @property
    def key(self) -> str | None:
        if not self.key_setting:
            return None
        secret = getattr(self.settings, self.key_setting)
        return secret.get_secret_value() if secret else None

    def disabled_reason(self) -> str | None:
        """Why it's off, or None when it's on."""
        if not self.settings.intel_lookups:
            return "NASSCAN_INTEL_LOOKUPS is off"
        if self.name in self.settings.intel_disabled_names:
            return "listed in NASSCAN_INTEL_DISABLED"
        if self.key_setting and not self.key:
            return f"set NASSCAN_{self.key_setting.upper()} to turn it on"
        return None

    def enabled(self) -> bool:
        return self.disabled_reason() is None

    def page(self, sha256: str) -> str | None:
        return self.link.format(sha256=sha256) if self.link else None

    @abstractmethod
    def lookup(self, hashes: list[Hashes]) -> dict[str, LookupResult]:
        """Answers by SHA-256 for every hash given (not_found for unknown ones). Raises
        ProviderError when the provider can't answer."""

    # --- helpers --------------------------------------------------------------------------

    def _check(self, response: httpx.Response) -> None:
        """Turn the usual HTTP failures into ProviderErrors with a sensible pause."""
        code = response.status_code
        if code == 429:
            retry = response.headers.get("Retry-After", "")
            pause = timedelta(seconds=int(retry)) if retry.isdigit() else timedelta(minutes=15)
            raise ProviderError("rate limited (HTTP 429)", max(pause, timedelta(minutes=1)))
        if code in (401, 403):
            raise ProviderError(f"API key rejected (HTTP {code})", timedelta(hours=6))
        if code >= 500:
            raise ProviderError(f"server error (HTTP {code})", timedelta(minutes=10))
        if code >= 400 and code != 404:
            raise ProviderError(f"HTTP {code}: {response.text[:200]}", timedelta(minutes=30))

    def _request(self, method: str, url: str, **kwargs) -> httpx.Response:
        try:
            response = self.client.request(method, url, **kwargs)
        except httpx.HTTPError as exc:
            raise ProviderError(f"{type(exc).__name__}: {exc}", timedelta(minutes=5)) from exc
        self._check(response)
        return response

    def _json(self, response: httpx.Response) -> dict | list:
        try:
            return response.json()
        except ValueError as exc:
            raise ProviderError(
                f"not JSON (HTTP {response.status_code}): {response.text[:200]}",
                timedelta(minutes=30),
            ) from exc

    def close(self) -> None:
        if self._client is not None:
            self._client.close()


def next_utc_midnight(now: datetime) -> datetime:
    return (now + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
