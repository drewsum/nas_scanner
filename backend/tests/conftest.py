import os

import pytest

from nasscan.config import get_settings
from nasscan.db import get_engine, get_sessionmaker

# DB tests wipe data, so they use a dedicated URL and never NASSCAN_DATABASE_URL.
TEST_DB_URL = os.environ.get("NASSCAN_TEST_DATABASE_URL")


def _clear_caches() -> None:
    get_settings.cache_clear()
    get_engine.cache_clear()
    get_sessionmaker.cache_clear()


@pytest.fixture(autouse=True)
def isolated_env(monkeypatch, tmp_path):
    """Each test starts from a clean NASSCAN_* env and never reads a local .env file."""
    for key in list(os.environ):
        if key.startswith("NASSCAN_") and key != "NASSCAN_TEST_DATABASE_URL":
            monkeypatch.delenv(key)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("NASSCAN_DATABASE_URL", "postgresql+psycopg://unused@localhost/unused")
    _clear_caches()
    yield
    _clear_caches()


@pytest.fixture
def db_env(monkeypatch):
    if not TEST_DB_URL:
        pytest.skip("set NASSCAN_TEST_DATABASE_URL to run DB tests")
    monkeypatch.setenv("NASSCAN_DATABASE_URL", TEST_DB_URL)
    _clear_caches()
    return get_settings()
