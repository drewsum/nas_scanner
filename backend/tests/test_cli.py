import pytest

from nasscan.cli import ALEMBIC_INI, main


def test_alembic_ini_is_found():
    assert ALEMBIC_INI.is_file()


def test_unknown_command_exits():
    with pytest.raises(SystemExit):
        main(["frobnicate"])


@pytest.mark.db
def test_migrate_is_idempotent(db_env):
    main(["migrate"])
    main(["migrate"])
