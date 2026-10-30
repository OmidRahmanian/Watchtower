"""``watchtower-db``: schema migrations and legacy data import."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from watchtower.config import load_settings
from watchtower.persistence import migrations


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="watchtower-db", description=__doc__)
    parser.add_argument("--profile", help="settings profile (default: $WATCHTOWER_PROFILE or development)")
    commands = parser.add_subparsers(dest="command", required=True)
    up = commands.add_parser("upgrade", help="apply migrations")
    up.add_argument("revision", nargs="?", default="head")
    down = commands.add_parser("downgrade", help="revert migrations")
    down.add_argument("revision")
    commands.add_parser("current", help="show the applied revision")
    legacy = commands.add_parser("import-mongo", help="import the legacy MongoDB inventory")
    legacy.add_argument("--targets", type=Path, default=Path("targets.json"), help="legacy targets.json")
    legacy.add_argument("--mongo-url", default="mongodb://localhost:27017/")
    legacy.add_argument(
        "--authorized-by",
        help="person attesting that the legacy scope is authorized (required unless --dry-run)",
    )
    legacy.add_argument("--dry-run", action="store_true", help="report what would be imported without writing")
    args = parser.parse_args(argv)

    settings = load_settings(args.profile)
    if args.command == "import-mongo":
        return _import_mongo(args, settings)
    url = settings.database.sqlalchemy_url()
    if args.command == "upgrade":
        migrations.upgrade(url, args.revision)
    elif args.command == "downgrade":
        migrations.downgrade(url, args.revision)
    else:
        migrations.current(url)
    return 0


def _import_mongo(args: argparse.Namespace, settings) -> int:
    try:
        import pymongo
    except ImportError:
        print("pymongo is required: pip install 'watchtower[legacy-import]'", file=sys.stderr)
        return 2
    from watchtower.persistence.database import Database
    from watchtower.persistence.legacy_mongo import MongoImporter, load_legacy_targets

    if not args.dry_run and not args.authorized_by:
        print("--authorized-by is required unless --dry-run is given", file=sys.stderr)
        return 2
    targets = load_legacy_targets(args.targets)
    client = pymongo.MongoClient(args.mongo_url, serverSelectionTimeoutMS=5000)
    # A dry run never opens a database connection, so it needs no database URL.
    database = None if args.dry_run else Database.from_settings(settings.database)
    try:
        importer = MongoImporter(
            database,
            client,
            authorized_by=args.authorized_by,
            dry_run=args.dry_run,
            permitted_ports=settings.scope.default_permitted_ports,
            destinations=settings.scope.destination_policy(),
        )
        report = importer.run(targets)
    finally:
        client.close()
        if database is not None:
            database.dispose()
    print(json.dumps(report.as_dict(), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
