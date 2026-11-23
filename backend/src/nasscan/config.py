"""Application settings.

Every deployment-specific value (paths, credentials, API keys, schedules) comes from
environment variables prefixed with ``NASSCAN_``, so the same image runs unchanged on a dev
machine and on the TrueNAS host.
"""

from functools import lru_cache

from croniter import croniter
from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class MissingSettingError(RuntimeError):
    def __init__(self, name: str) -> None:
        super().__init__(f"NASSCAN_{name.upper()} must be set for this command")


class Settings(BaseSettings):
    # Empty vars count as unset: the server compose file passes every setting as
    # ${VAR:-}, so a blank optional value must fall back to its default.
    model_config = SettingsConfigDict(
        env_prefix="NASSCAN_", env_file=".env", extra="ignore", env_ignore_empty=True
    )

    database_url: str = Field(description="SQLAlchemy URL, e.g. postgresql+psycopg://...")

    # Where the NAS datasets are mounted inside the scanner (read-only). The compose files
    # mount the host's NASSCAN_SCAN_ROOT here and keep this at /scan.
    scan_root: str = "/scan"
    # When scans run (cron, in the container's time zone): new and changed files nightly,
    # and every file weekly so new signatures reach old files too.
    incremental_cron: str = "0 2 * * *"
    full_cron: str = "0 3 * * 0"
    # Paths the scanner skips, comma separated. A pattern without a slash matches any file or
    # folder name anywhere (fnmatch: *, ?, [..]); one with a slash matches the path from the
    # scan root, e.g. "apps/nas_scanner" or "media/*/cache". Excluded folders aren't entered.
    exclude_globs: str = ".zfs,ix-apps,.ix-apps,.ix-virt,.Trash-*,$RECYCLE.BIN,@eaDir"
    # Files read at once, and the most all of them may read together, in MB/s (0: no limit).
    scan_workers: int = Field(default=2, ge=1, le=32)
    max_read_mbps: float = Field(default=100.0, ge=0)
    # The scanner lowers its own CPU priority to this nice level, and its IO priority to the
    # idle class, so the NAS stays responsive (the throttle above is the main control on ZFS).
    scanner_nice: int = Field(default=10, ge=0, le=19)
    scanner_ionice_idle: bool = True

    # Reading files for the engines. Files up to memory_read_mb are read once into memory and
    # every engine scans that copy. Media files (by name and real type) over large_file_mb are
    # not read whole: only their first and last partial_chunk_mb, so a 50 GB movie costs a few
    # MB (and gets no hashes). large_media_full_read reads them whole anyway.
    memory_read_mb: int = Field(default=64, ge=1, le=1024)
    large_file_mb: int = Field(default=512, ge=16)
    partial_chunk_mb: int = Field(default=16, ge=1, le=256)
    large_media_full_read: bool = False
    # Folder names that hold media or documents, where executables and scripts are suspicious
    # (matched case-insensitively against every folder in a file's path).
    media_folders: str = (
        "movies,movie,films,film,tv,shows,series,music,audio,videos,video,photos,pictures,"
        "images,media,documents,docs,books,ebooks,3d,3dprints,prints,printing,stl"
    )
    # Content embedded in container files (a 3MF's members) scanned per file, in MB.
    embedded_max_mb: int = Field(default=256, ge=1)

    # ClamAV daemon (the stack's clamd service). Unset: no ClamAV.
    clamd_host: str | None = None
    clamd_port: int = Field(default=3310, ge=1, le=65535)
    clamd_timeout: float = Field(default=300.0, gt=0)
    # The most streamed to clamd at once, in MB. Must not exceed clamd's StreamMaxLength
    # (the compose files set it to 512M); bigger files are scanned in head and tail pieces.
    clamd_stream_max_mb: int = Field(default=400, ge=1)

    # YARA rule sets downloaded and compiled daily: forge-core, forge-extended, forge-full
    # (YARA Forge packages, which already include most of signature-base) and signature-base
    # (Neo23x0's own repo). Comma separated; empty turns downloads off.
    yara_sources: str = "forge-core"
    yara_refresh_hours: float = Field(default=24.0, ge=1)
    # Your own .yar/.yara rules, compiled in too (mount a folder here).
    yara_local_dir: str = "/rules"
    # Where downloaded rules and other scanner state live (a volume).
    data_dir: str = "/data"

    # --- Threat intel (hashes only ever leave the NAS, never file contents) ----------------
    # Hash feeds downloaded and matched locally against every hashed file: malwarebazaar and
    # threatfox (both need abusech_auth_key), virusshare (no key; the newest virusshare_lists
    # MD5 lists, 65,536 hashes each lately). Comma separated; empty turns feeds off.
    intel_feeds: str = "malwarebazaar,threatfox,virusshare"
    virusshare_lists: int = Field(default=16, ge=1, le=1000)
    # More hash lists to download, as name=url pairs, comma separated (CSV, text or a zipped
    # one; every MD5/SHA-1/SHA-256 in it counts as malicious). {abusech_key} in a URL is
    # replaced with abusech_auth_key.
    intel_extra_feeds: str = ""
    intel_feed_refresh_hours: float = Field(default=24.0, ge=1)
    # Live hash lookups, made only for "interesting" files (executables, scripts, macro
    # documents, archives, anything an engine flagged) and only hashes nobody lists as known
    # good. Providers without a key are off; names listed in intel_disabled are off too
    # (circl, cymru, malwarebazaar, yaraify, virustotal, hybrid-analysis, metadefender, otx,
    # opentip, or a feed's name).
    intel_lookups: bool = True
    intel_disabled: str = ""
    # Daily request budget and requests per minute per provider, overriding the defaults
    # (which fit each free tier), e.g. "virustotal=500/4,metadefender=2000".
    intel_limits: str = ""
    # Cached answers are asked again after this many days: not found or clean, and found.
    intel_recheck_days: float = Field(default=7.0, gt=0)
    intel_hit_recheck_days: float = Field(default=30.0, gt=0)
    # abuse.ch (MalwareBazaar, ThreatFox, YARAify); free at https://auth.abuse.ch/
    abusech_auth_key: SecretStr | None = None
    virustotal_api_key: SecretStr | None = None
    hybrid_analysis_api_key: SecretStr | None = None
    metadefender_api_key: SecretStr | None = None
    otx_api_key: SecretStr | None = None
    opentip_api_key: SecretStr | None = None

    # Password for the web UI and API. Unset leaves both open to anyone on the LAN.
    admin_password: SecretStr | None = None
    session_days: float = Field(default=30.0, gt=0)

    api_host: str = "0.0.0.0"
    api_port: int = 8000
    # Addresses of reverse proxies whose X-Forwarded-For/-Proto headers to trust, comma
    # separated (IPs or CIDRs, or * for any).
    trusted_proxies: str | None = None
    web_dist_dir: str | None = None
    log_level: str = "INFO"
    # The commit the image was built from (set by the Dockerfile), shown in the UI so you can
    # tell which build Portainer is running.
    git_sha: str = "dev"

    # `nasscan backup`: a database dump into backup_dir every backup_interval_hours, keeping
    # the newest backup_keep. The server stack mounts <NASSCAN_DATA_DIR>/backups there.
    backup_dir: str = "/backups"
    backup_interval_hours: float = Field(default=24.0, ge=1)
    backup_keep: int = Field(default=14, ge=1)
    # Where pg_dump and pg_restore are; the image installs PostgreSQL 16's.
    pg_bin_dir: str = "/usr/lib/postgresql/16/bin"

    scanner_heartbeat_file: str = "/tmp/nasscan-scanner-heartbeat"
    scanner_tick_seconds: float = Field(default=10.0, gt=0)

    @field_validator("incremental_cron", "full_cron")
    @classmethod
    def _valid_cron(cls, value: str) -> str:
        if not croniter.is_valid(value):
            raise ValueError(f"not a valid cron expression: {value!r}")
        return value

    @property
    def media_folder_names(self) -> set[str]:
        return {p.strip().lower() for p in self.media_folders.split(",") if p.strip()}

    @property
    def yara_source_names(self) -> list[str]:
        return [p.strip() for p in self.yara_sources.split(",") if p.strip()]

    @property
    def intel_feed_names(self) -> list[str]:
        return [p.strip().lower() for p in self.intel_feeds.split(",") if p.strip()]

    @property
    def intel_disabled_names(self) -> set[str]:
        return {p.strip().lower() for p in self.intel_disabled.split(",") if p.strip()}

    @property
    def intel_extra_feed_urls(self) -> dict[str, str]:
        out = {}
        for part in self.intel_extra_feeds.split(","):
            name, sep, url = part.partition("=")
            if sep and name.strip() and url.strip():
                out[name.strip().lower()] = url.strip()
        return out

    @property
    def intel_limit_overrides(self) -> dict[str, tuple[int | None, float | None]]:
        """name -> (daily budget, per minute); either may be None (keep the default)."""
        out: dict[str, tuple[int | None, float | None]] = {}
        for part in self.intel_limits.split(","):
            name, sep, value = part.partition("=")
            if not sep or not name.strip():
                continue
            daily, _, minute = value.partition("/")
            try:
                out[name.strip().lower()] = (
                    int(daily) if daily.strip() else None,
                    float(minute) if minute.strip() else None,
                )
            except ValueError:
                continue
        return out

    @property
    def exclude_patterns(self) -> list[str]:
        return [p.strip().strip("/") for p in self.exclude_globs.split(",") if p.strip()]

    def require(self, name: str):
        value = getattr(self, name)
        if value is None:
            raise MissingSettingError(name)
        return value


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
