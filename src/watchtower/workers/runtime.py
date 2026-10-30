"""Workers and the notifier: lease durable work from PostgreSQL and run it.

PostgreSQL is the source of truth. A job or notification is leased with an
expiry; a worker that dies simply stops renewing, and the next claim after
the lease expires picks the work up again (``claim`` treats an expired lease
as due). The broker (``watchtower.workers.celery_app``) only wakes workers,
so a lost or duplicated message neither loses nor duplicates work.

``Worker.run_once`` leases one job and runs it through ``Pipeline`` while a
heartbeat thread renews the lease. The heartbeat also carries cancellation:
when the job's run is cancelled, or the lease is lost, it trips the job's
``CancelToken``, which stops the pipeline between items and kills any tool's
process group. A job then ends as:

* ``complete`` when the pipeline returns;
* ``mark_cancelled`` on a cancel request (follow-on jobs are refused by
  ``enqueue``); after a lost lease nothing is written, the new holder owns it;
* ``fail`` with a backoff on any other error (and on worker shutdown, with no
  backoff), which requeues while attempts remain.

When a job of a run ends as cancelled or failed for good, the run is
finalized so the changes it already accepted are still alerted.
"""
from __future__ import annotations

import logging
import os
import signal
import socket
import threading
import time
import traceback
from collections.abc import Callable, Mapping, Sequence
from uuid import uuid4

from watchtower.adapters.notifications import SENDERS, DeliveryError, PinnedTransport, Sender, Transport
from watchtower.config.settings import Settings
from watchtower.domain.models import Job, JobStatus, Notification
from watchtower.persistence.database import Database
from watchtower.services.jobs import (
    JOB_KINDS, CancelToken, JobCancelled, Pipeline, PipelineAdapters, unfinalized_runs,
)
from watchtower.services.scope import ScopeService

log = logging.getLogger("watchtower.workers")


def default_worker_id(role: str = "worker") -> str:
    return f"{role}:{socket.gethostname()}:{os.getpid()}:{uuid4().hex[:6]}"


def backoff(attempt: int, *, base: float = 15.0, cap: float = 900.0) -> int:
    """Seconds before retry ``attempt`` + 1: 15, 30, 60, ... capped at 15 minutes."""
    return int(min(cap, base * 2 ** max(0, attempt - 1)))


class Heartbeat(threading.Thread):
    def __init__(self, database: Database, job: Job, worker_id: str, token: CancelToken, *,
                 lease_seconds: int, interval: float) -> None:
        super().__init__(name=f"heartbeat-{job.id}", daemon=True)
        self.database, self.job, self.worker_id, self.token = database, job, worker_id, token
        self.lease_seconds, self.interval = lease_seconds, interval
        self._halt = threading.Event()

    def run(self) -> None:
        while not self._halt.wait(self.interval):
            try:
                with self.database.system() as system:
                    status = system.job_leases.heartbeat(self.job.id, self.worker_id, lease_seconds=self.lease_seconds)
            except Exception:  # a database hiccup: try again next beat; the lease has slack
                log.warning("heartbeat for job %s failed", self.job.id, exc_info=True)
                continue
            if not status.held:
                self.token.cancel("lease lost to another worker", lease_lost=True)
                return
            if status.cancel_requested:
                self.token.cancel("cancel requested")
                return

    def stop(self) -> None:
        self._halt.set()
        if self.is_alive() and threading.current_thread() is not self:
            self.join(timeout=self.interval + 5)


class Worker:
    def __init__(self, database: Database, scope: ScopeService, *, settings: Settings | None = None,
                 adapters: PipelineAdapters | None = None, worker_id: str | None = None,
                 kinds: Sequence[str] | None = None, lease_seconds: int | None = None,
                 heartbeat_seconds: float | None = None, limits: Mapping[str, int] | None = None,
                 retry_backoff: Callable[[int], int] = backoff) -> None:
        self.settings = settings or Settings()
        runtime = self.settings.runtime
        self.database = database
        self.pipeline = Pipeline(database, scope, self.settings, adapters)
        self.worker_id = worker_id or default_worker_id()
        self.kinds = list(kinds or JOB_KINDS)
        self.lease_seconds = lease_seconds or runtime.lease_seconds
        self.heartbeat_seconds = heartbeat_seconds or runtime.heartbeat_seconds
        self.limits = dict(runtime.limits if limits is None else limits)
        self.retry_backoff = retry_backoff
        self._current: dict[str, CancelToken] = {}
        self._lock = threading.Lock()

    def claim(self) -> Job | None:
        # Its own short transaction: claims with limits hold per-key advisory locks until commit.
        with self.database.system() as system:
            found = system.job_leases.claim(self.worker_id, kinds=self.kinds, lease_seconds=self.lease_seconds,
                                            limit=1, limits=self.limits or None)
        return found[0] if found else None

    def run_once(self) -> bool:
        """Lease and run one job; ``False`` when nothing was due."""
        job = self.claim()
        if job is None:
            return False
        self.execute(job)
        return True

    def run_until_idle(self, max_jobs: int = 1000) -> int:
        ran = 0
        while ran < max_jobs and self.run_once():
            ran += 1
        return ran

    def shutdown(self, detail: str = "worker shutting down") -> None:
        """Stop in-flight jobs; they are requeued without backoff for another worker."""
        with self._lock:
            for token in self._current.values():
                token.cancel(detail, shutdown=True)

    def execute(self, job: Job) -> None:
        token = CancelToken()
        key = str(job.id)
        with self._lock:
            self._current[key] = token
        beat = Heartbeat(self.database, job, self.worker_id, token, lease_seconds=self.lease_seconds,
                         interval=self.heartbeat_seconds)
        beat.start()
        try:
            result = self.pipeline.run_job(job, token)
        except JobCancelled as stop:
            beat.stop()
            self._stopped(job, stop)
            return
        except Exception as exc:
            beat.stop()
            self._failed(job, f"{type(exc).__name__}: {exc}\n{traceback.format_exc(limit=5)}")
            return
        finally:
            with self._lock:
                self._current.pop(key, None)
        beat.stop()
        with self.database.system() as system:
            done = system.job_leases.complete(job.id, self.worker_id, result)
        if not done:
            log.warning("job %s finished after its lease was lost; the new holder will redo it idempotently", job.id)

    def _stopped(self, job: Job, stop: JobCancelled) -> None:
        if stop.lease_lost:
            return
        with self.database.system() as system:
            if stop.shutdown:
                system.job_leases.fail(job.id, self.worker_id, stop.detail, retry_in_seconds=0)
                return
            system.job_leases.mark_cancelled(job.id, self.worker_id, stop.detail)
        self.pipeline.finalize(job.project_id, job.run_id)

    def _failed(self, job: Job, error: str) -> None:
        with self.database.system() as system:
            system.job_leases.fail(job.id, self.worker_id, error, retry_in_seconds=self.retry_backoff(job.attempts))
        with self.database.project(job.project_id) as uow:
            current = uow.jobs.get(job.id)
        if current is not None and current.status in (JobStatus.FAILED, JobStatus.CANCELLED):
            self.pipeline.finalize(job.project_id, job.run_id)

    def recover(self) -> int:
        """Finalize runs that stopped without a worker noticing (lease expired on the last attempt)."""
        return sum(self.pipeline.finalize(project_id, run_id) for project_id, run_id in unfinalized_runs(self.database))


class Notifier:
    def __init__(self, database: Database, settings: Settings | None = None, *,
                 senders: Mapping[str, Sender] | None = None, transport: Transport | None = None,
                 worker_id: str | None = None, lease_seconds: int = 60,
                 retry_backoff: Callable[[int], int] = backoff) -> None:
        self.database = database
        self.settings = settings or Settings()
        self.senders = dict(SENDERS if senders is None else senders)
        self.transport = transport or PinnedTransport(self.settings.scope.destination_policy())
        self.worker_id = worker_id or default_worker_id("notifier")
        self.lease_seconds = lease_seconds
        self.retry_backoff = retry_backoff

    def deliver_once(self, limit: int = 10) -> int:
        """Deliver up to ``limit`` due notifications; returns how many were sent."""
        with self.database.system() as system:
            due = system.notification_leases.claim(self.worker_id, lease_seconds=self.lease_seconds, limit=limit)
        return sum(self.deliver(notification) for notification in due)

    def run_until_idle(self, max_rounds: int = 100) -> int:
        sent = 0
        for _ in range(max_rounds):
            with self.database.system() as system:
                due = system.notification_leases.claim(self.worker_id, lease_seconds=self.lease_seconds, limit=10)
            if not due:
                break
            sent += sum(self.deliver(notification) for notification in due)
        return sent

    def deliver(self, notification: Notification) -> bool:
        destination = self.settings.notifications.destination(notification.channel)
        sender = self.senders.get(destination.kind) if destination else None
        if destination is None or sender is None:
            self._mark_failed(notification, f"no enabled destination named {notification.channel!r}", None)
            return False
        try:
            sender.send(destination.url.get_secret_value(), notification, self.transport)
        except DeliveryError as exc:
            retry = None
            if exc.retryable:
                retry = max(int(exc.retry_after or 0), self.retry_backoff(notification.attempts))
            self._mark_failed(notification, str(exc), retry)
            return False
        except Exception as exc:  # a sender bug: retry, but never leak the URL into the error
            self._mark_failed(notification, f"{type(exc).__name__} while sending", self.retry_backoff(notification.attempts))
            return False
        with self.database.system() as system:
            system.notification_leases.mark_sent(notification.id, self.worker_id)
        return True

    def _mark_failed(self, notification: Notification, error: str, retry: int | None) -> None:
        with self.database.system() as system:
            system.notification_leases.mark_failed(notification.id, self.worker_id, error, retry_in_seconds=retry)


def serve(database: Database, scope: ScopeService, settings: Settings, *, adapters: PipelineAdapters | None = None,
          stop: threading.Event | None = None, idle_seconds: float = 2.0, recover_every: float = 60.0) -> None:
    """Run ``runtime.concurrency`` worker threads and a notifier until ``stop`` is set or SIGTERM/SIGINT.

    Used by ``watch.py --platform`` and ``watchtower-worker serve``; Celery
    deployments run the same ``Worker`` and ``Notifier`` from tasks instead.
    """
    stop = stop or threading.Event()
    workers = [Worker(database, scope, settings=settings, adapters=adapters)
               for _ in range(settings.runtime.concurrency)]
    notifier = Notifier(database, settings)

    def shutdown(*_: object) -> None:
        stop.set()
        for worker in workers:
            worker.shutdown()

    if threading.current_thread() is threading.main_thread():
        signal.signal(signal.SIGTERM, shutdown)
        signal.signal(signal.SIGINT, shutdown)

    def loop(step: Callable[[], object]) -> None:
        while not stop.is_set():
            try:
                busy = step()
            except Exception:
                log.exception("runtime loop error")
                busy = False
            if not busy:
                stop.wait(idle_seconds)

    threads = [threading.Thread(target=loop, args=(w.run_once,), name=f"worker-{i}", daemon=True)
               for i, w in enumerate(workers)]
    threads.append(threading.Thread(target=loop, args=(notifier.deliver_once,), name="notifier", daemon=True))
    for thread in threads:
        thread.start()
    last_recovery = 0.0
    while not stop.wait(1.0):
        if time.monotonic() - last_recovery >= recover_every:
            last_recovery = time.monotonic()
            try:
                workers[0].recover()
            except Exception:
                log.exception("recovery sweep failed")
    shutdown()
    for thread in threads:
        thread.join(timeout=settings.runtime.heartbeat_seconds + 10)
