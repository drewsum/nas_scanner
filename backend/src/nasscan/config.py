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

    # Where the NAS datasets are mounted inside the scanner (read-only).
    scan_root: str = "/scan"
    # When scans run (cron, in the container's time zone): new and changed files nightly,
    # and every file weekly so new signatures reach old files too.
    incremental_cron: str = "0 2 * * *"
    full_cron: str = "0 3 * * 0"

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

    def require(self, name: str):
        value = getattr(self, name)
        if value is None:
            raise MissingSettingError(name)
        return value


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
