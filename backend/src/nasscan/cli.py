"""`nasscan <command>`: single entry point for every container role."""

import argparse
import logging
from pathlib import Path

from nasscan.config import get_settings

ALEMBIC_INI = Path(__file__).resolve().parents[2] / "alembic.ini"


def cmd_migrate(_: argparse.Namespace) -> None:
    from alembic import command
    from alembic.config import Config

    command.upgrade(Config(str(ALEMBIC_INI)), "head")


def cmd_api(_: argparse.Namespace) -> None:
    import uvicorn

    settings = get_settings()
    uvicorn.run(
        "nasscan.api.app:create_app",
        factory=True,
        host=settings.api_host,
        port=settings.api_port,
        log_level=settings.log_level.lower(),
        # None keeps uvicorn's default: trust forwarded headers from loopback only.
        forwarded_allow_ips=settings.trusted_proxies,
    )


def cmd_scanner(_: argparse.Namespace) -> None:
    import asyncio

    from nasscan.scanner.main import run

    asyncio.run(run(get_settings()))


def cmd_backup(args: argparse.Namespace) -> None:
    from nasscan.backup import run_backups

    run_backups(get_settings(), once=args.once)


def cmd_restore(args: argparse.Namespace) -> None:
    from nasscan.backup import BackupError, restore
    from nasscan.db import get_engine

    settings = get_settings()
    live = get_engine().url.database
    target = args.database or live
    if target == live and not args.yes:
        raise SystemExit(
            f"This replaces everything in the {live} database with {args.file}. Stop the api and "
            "scanner, then run it again with --yes."
        )
    try:
        restore(settings, Path(args.file), target)
    except BackupError as exc:
        raise SystemExit(f"restore failed: {exc}") from exc
    if target == live:
        # Brings an older dump up to this version's schema.
        cmd_migrate(args)
    print(f"Restored {args.file} into {target}.")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="nasscan")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("migrate", help="apply DB migrations").set_defaults(func=cmd_migrate)
    sub.add_parser("api", help="run the web API and UI").set_defaults(func=cmd_api)
    sub.add_parser("scanner", help="run the scan scheduler and workers").set_defaults(
        func=cmd_scanner
    )
    backup_p = sub.add_parser(
        "backup", help="dump the database to NASSCAN_BACKUP_DIR on a schedule"
    )
    backup_p.add_argument("--once", action="store_true", help="dump now, then exit")
    backup_p.set_defaults(func=cmd_backup)
    restore_p = sub.add_parser("restore", help="replace the database with a backup")
    restore_p.add_argument("file", help="a dump made by `nasscan backup`")
    restore_p.add_argument(
        "--database", help="restore into this database instead (created; replaced if it exists)"
    )
    restore_p.add_argument("--yes", action="store_true", help="really replace the app's database")
    restore_p.set_defaults(func=cmd_restore)

    args = parser.parse_args(argv)
    logging.basicConfig(
        level=get_settings().log_level.upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    args.func(args)


if __name__ == "__main__":
    main()
