"""``watchtower-worker``: run the monitoring runtime without Celery.

    watchtower-worker serve                 # worker threads + notifier until SIGTERM
    watchtower-worker drain                 # run every due job and notification, then exit
    watchtower-worker schedule --every 6h   # enqueue this slot's scheduled runs, then exit
    watchtower-worker recover               # finalize runs that stopped without a worker
"""
from __future__ import annotations

import argparse
import logging
import re
import sys
from datetime import timedelta

from watchtower.config.settings import Settings, load_settings
from watchtower.persistence.database import Database
from watchtower.services.jobs import RunService
from watchtower.services.scope import ScopeService
from watchtower.workers import egress
from watchtower.workers.runtime import Notifier, Worker, serve
from watchtower.workers.scheduler import schedule_due

_UNITS = {"m": "minutes", "h": "hours", "d": "days"}


def interval(text: str) -> timedelta:
    match = re.fullmatch(r"(\d+)([mhd])", text.strip())
    if not match:
        raise argparse.ArgumentTypeError("use a number and m, h or d, for example 6h")
    return timedelta(**{_UNITS[match.group(2)]: int(match.group(1))})


def build(settings: Settings) -> tuple[Database, ScopeService]:
    database = Database.from_settings(settings.database)
    return database, ScopeService(database, settings.scope)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="watchtower-worker", description=__doc__.split("\n\n")[0])
    parser.add_argument("--profile", help="settings profile (default: WATCHTOWER_PROFILE)")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("serve", help="run workers and the notifier until stopped")
    commands.add_parser("drain", help="run due jobs and notifications, then exit")
    every = commands.add_parser("schedule", help="enqueue the current slot's scheduled runs")
    every.add_argument("--every", type=interval, default=timedelta(hours=6))
    commands.add_parser("recover", help="finalize runs that stopped without a worker")
    args = parser.parse_args(argv)

    settings = load_settings(args.profile)
    logging.basicConfig(level=settings.log_level, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    database, scope = build(settings)
    try:
        if args.command == "serve":
            egress.install(settings)
            serve(database, scope, settings)
        elif args.command == "drain":
            egress.install(settings)
            jobs = Worker(database, scope, settings=settings).run_until_idle()
            sent = Notifier(database, settings).run_until_idle()
            print(f"ran {jobs} jobs, sent {sent} notifications")
        elif args.command == "schedule":
            started = schedule_due(database, RunService(database, scope, settings=settings), interval=args.every)
            print(f"{len(started)} scheduled runs queued or already queued")
        else:
            print(f"finalized {Worker(database, scope, settings=settings).recover()} notifications")
    finally:
        database.dispose()
    return 0


if __name__ == "__main__":
    sys.exit(main())
