"""Periodic monitoring runs.

Each project with a published scope gets one run per schedule slot. The run
id is derived from the project and the slot, and its first job's idempotency
key from the run id, so any number of schedulers (cron, Celery beat, several
hosts) enqueue each slot exactly once.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from watchtower.persistence.database import Database
from watchtower.services.jobs import RunService, RunSummary


def slot_for(now: datetime, interval: timedelta) -> str:
    seconds = int(interval.total_seconds())
    if seconds < 60:
        raise ValueError("schedule interval must be at least one minute")
    epoch = int(now.astimezone(UTC).timestamp())
    start = datetime.fromtimestamp(epoch - epoch % seconds, UTC)
    return f"{start.isoformat(timespec='minutes')}/{seconds}s"


def schedule_due(database: Database, runs: RunService, *, interval: timedelta,
                 now: datetime | None = None) -> list[RunSummary]:
    """Start this slot's run for every active project with a scope; returns the runs it touched."""
    slot = slot_for(now or datetime.now(UTC), interval)
    with database.system() as system:
        projects = list(system.projects.list())
    started = []
    for project in projects:
        summary = runs.start_scheduled(project.id, slot=slot)
        if summary is not None:
            started.append(summary)
    return started
