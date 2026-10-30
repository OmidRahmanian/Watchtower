"""Celery wiring over RabbitMQ.

The broker carries wake-ups, not work: every task leases from PostgreSQL
through the same ``Worker`` and ``Notifier`` the synchronous runtime uses.
Tasks are acknowledged late and rejected when a worker process dies, and
beat re-sends wake-ups on a timer, so lost, duplicated or redelivered
messages cost at most an empty claim. Retries, leases, cancellation and
concurrency limits all live in the database.

Start with::

    celery -A watchtower.workers.celery_app worker --concurrency 4 --prefetch-multiplier 1
    celery -A watchtower.workers.celery_app beat
"""
from __future__ import annotations

from datetime import timedelta
from functools import cache
from typing import Any

from celery import Celery
from celery.signals import worker_process_init

from watchtower.config.settings import Settings, load_settings

QUEUE = "watchtower"
TASK_WORK = "watchtower.work"
TASK_DELIVER = "watchtower.deliver"
TASK_RECOVER = "watchtower.recover"
TASK_SCHEDULE = "watchtower.schedule"


def configure(app: Celery, settings: Settings, *, schedule_every: timedelta = timedelta(hours=6)) -> Celery:
    broker = settings.runtime.broker_url.get_secret_value() if settings.runtime.broker_url else "memory://"
    app.conf.update(
        broker_url=broker,
        task_default_queue=QUEUE,
        task_serializer="json",
        accept_content=["json"],
        result_backend=None,
        task_ignore_result=True,
        task_acks_late=True,
        task_reject_on_worker_lost=True,
        worker_prefetch_multiplier=1,
        worker_concurrency=settings.runtime.concurrency,
        broker_connection_retry_on_startup=True,
        beat_schedule={
            "work": {"task": TASK_WORK, "schedule": 30.0},
            "deliver": {"task": TASK_DELIVER, "schedule": 15.0},
            "recover": {"task": TASK_RECOVER, "schedule": 120.0},
            "schedule": {"task": TASK_SCHEDULE, "schedule": 300.0,
                         "kwargs": {"interval_seconds": int(schedule_every.total_seconds())}},
        },
    )
    return app


app = Celery("watchtower")


@cache
def runtime() -> dict[str, Any]:
    """Per-process database, scope service, worker and notifier."""
    from watchtower.persistence.database import Database
    from watchtower.services.jobs import RunService
    from watchtower.services.scope import ScopeService
    from watchtower.workers.runtime import Notifier, Worker

    settings = load_settings()
    database = Database.from_settings(settings.database)
    scope = ScopeService(database, settings.scope)
    return {
        "settings": settings,
        "database": database,
        "worker": Worker(database, scope, settings=settings),
        "notifier": Notifier(database, settings),
        "runs": RunService(database, scope, settings=settings, on_enqueue=kick),
    }


def kick() -> None:
    """Wake a worker; ``RunService(on_enqueue=kick)`` calls this after enqueueing."""
    app.send_task(TASK_WORK)


@worker_process_init.connect
def _guard_egress(**_: Any) -> None:
    from watchtower.workers import egress

    egress.install(runtime()["settings"])


@app.task(name=TASK_WORK)
def work(max_jobs: int = 25) -> int:
    ran = runtime()["worker"].run_until_idle(max_jobs)
    if ran:
        kick()  # follow-on jobs were enqueued; another worker may pick them up in parallel
        app.send_task(TASK_DELIVER)
    return ran


@app.task(name=TASK_DELIVER)
def deliver() -> int:
    return runtime()["notifier"].run_until_idle()


@app.task(name=TASK_RECOVER)
def recover() -> int:
    return runtime()["worker"].recover()


@app.task(name=TASK_SCHEDULE)
def schedule(interval_seconds: int = 6 * 3600) -> int:
    from watchtower.workers.scheduler import schedule_due

    parts = runtime()
    started = schedule_due(parts["database"], parts["runs"], interval=timedelta(seconds=interval_seconds))
    return len(started)


try:
    configure(app, load_settings())
except Exception:  # no profile here (imported for inspection or tests); configure() again before use
    configure(app, Settings())
