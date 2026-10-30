"""Schedule monitoring runs on the platform runtime.

    python cron.py                 # enqueue each project's run every 6 hours, until stopped
    python cron.py --every 30m     # another interval (m, h or d)
    python cron.py --once          # enqueue the current slot's runs and exit (for crontab)

Every project with a published scope gets one run per slot. Slots are
idempotent, so running this from several hosts, or alongside Celery beat or
``watch.py --platform``, still enqueues each run once. Workers
(``watchtower-worker serve`` or Celery) execute the runs.

This replaces the earlier placeholder, which re-read setting.json in a loop
and scheduled print-only jobs. The legacy monitor's own schedule lives in
watch.py.
"""
import argparse
import sys
import time


def main(argv=None):
    parser = argparse.ArgumentParser(description="Enqueue scheduled WatchTower runs.")
    parser.add_argument("--every", default="6h", help="run interval, for example 30m, 6h or 1d (default 6h)")
    parser.add_argument("--once", action="store_true", help="enqueue the current slot and exit")
    parser.add_argument("--profile", help="settings profile (default: WATCHTOWER_PROFILE)")
    args = parser.parse_args(argv)
    if sys.version_info < (3, 11):
        parser.error("the platform runtime needs Python 3.11+")

    from watchtower.workers.cli import main as worker_main

    command = (["--profile", args.profile] if args.profile else []) + ["schedule", "--every", args.every]
    while True:
        status = worker_main(command)
        if args.once or status:
            return status
        time.sleep(300)  # re-checking within a slot is a no-op; a new slot starts new runs


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nScheduler stopped.", flush=True)
