"""Job queue and notification outbox, with cross-project leasing for workers."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import timedelta
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import Connection, and_, func, or_, select
from sqlalchemy.dialects.postgresql import insert

from watchtower.domain.models import (
    Job,
    JobStatus,
    NewJob,
    NewNotification,
    Notification,
    NotificationStatus,
)
from watchtower.persistence.repositories.records import _ProjectRepository
from watchtower.persistence.tables import jobs, notifications

_ERROR_LIMIT = 4000


def _job(row: Any) -> Job:
    return Job(
        id=row.id,
        project_id=row.project_id,
        kind=row.kind,
        status=JobStatus(row.status),
        scope_revision_id=row.scope_revision_id,
        payload=row.payload,
        priority=row.priority,
        run_after=row.run_after,
        attempts=row.attempts,
        max_attempts=row.max_attempts,
        created_at=row.created_at,
        idempotency_key=row.idempotency_key,
        lease_owner=row.lease_owner,
        lease_expires_at=row.lease_expires_at,
        started_at=row.started_at,
        finished_at=row.finished_at,
        result=row.result,
        last_error=row.last_error,
    )


def _later(seconds: int) -> Any:
    return func.now() + timedelta(seconds=seconds)


class PgJobRepository(_ProjectRepository):
    def enqueue(self, new: NewJob) -> tuple[Job, bool]:
        statement = (
            insert(jobs)
            .values(
                id=uuid4(),
                project_id=self.project_id,
                kind=new.kind,
                scope_revision_id=new.scope_revision_id,
                payload=dict(new.payload),
                priority=new.priority,
                run_after=new.run_after or func.now(),
                max_attempts=new.max_attempts,
                idempotency_key=new.idempotency_key,
            )
            .on_conflict_do_nothing(index_elements=[jobs.c.project_id, jobs.c.idempotency_key])
            .returning(*jobs.c)
        )
        row = self._conn.execute(statement).one_or_none()
        if row is not None:
            return _job(row), True
        existing = self._conn.execute(
            select(jobs).where(self._mine(jobs), jobs.c.idempotency_key == new.idempotency_key)
        ).one()
        return _job(existing), False

    def get(self, job_id: UUID) -> Job | None:
        row = self._conn.execute(select(jobs).where(self._mine(jobs), jobs.c.id == job_id)).one_or_none()
        return _job(row) if row else None

    def cancel(self, job_id: UUID) -> bool:
        result = self._conn.execute(
            jobs.update()
            .where(self._mine(jobs), jobs.c.id == job_id, jobs.c.status == JobStatus.QUEUED.value)
            .values(status=JobStatus.CANCELLED.value, finished_at=func.now())
        )
        return result.rowcount == 1


class PgJobLeaseRepository:
    def __init__(self, connection: Connection) -> None:
        self._conn = connection

    def claim(
        self, worker_id: str, *, kinds: Sequence[str] | None = None, lease_seconds: int = 300, limit: int = 1
    ) -> Sequence[Job]:
        expired = and_(jobs.c.status == JobStatus.RUNNING.value, jobs.c.lease_expires_at < func.now())
        # Jobs whose lease expired on their final attempt are failed rather than rerun.
        self._conn.execute(
            jobs.update()
            .where(expired, jobs.c.attempts >= jobs.c.max_attempts)
            .values(
                status=JobStatus.FAILED.value,
                finished_at=func.now(),
                lease_owner=None,
                lease_expires_at=None,
                last_error="lease expired on final attempt",
            )
        )
        due = select(jobs.c.id).where(
            or_(and_(jobs.c.status == JobStatus.QUEUED.value, jobs.c.run_after <= func.now()), expired)
        )
        if kinds is not None:
            due = due.where(jobs.c.kind.in_(list(kinds)))
        due = (
            due.order_by(jobs.c.priority.desc(), jobs.c.run_after)
            .limit(limit)
            .with_for_update(skip_locked=True)
            .cte("due")
        )
        rows = self._conn.execute(
            jobs.update()
            .where(jobs.c.id == due.c.id)
            .values(
                status=JobStatus.RUNNING.value,
                lease_owner=worker_id,
                lease_expires_at=_later(lease_seconds),
                attempts=jobs.c.attempts + 1,
                started_at=func.coalesce(jobs.c.started_at, func.now()),
            )
            .returning(*jobs.c)
        )
        return sorted((_job(row) for row in rows), key=lambda job: (-job.priority, job.run_after))

    def _held(self, job_id: UUID, worker_id: str) -> Any:
        return and_(
            jobs.c.id == job_id,
            jobs.c.status == JobStatus.RUNNING.value,
            jobs.c.lease_owner == worker_id,
        )

    def heartbeat(self, job_id: UUID, worker_id: str, *, lease_seconds: int = 300) -> bool:
        result = self._conn.execute(
            jobs.update().where(self._held(job_id, worker_id)).values(lease_expires_at=_later(lease_seconds))
        )
        return result.rowcount == 1

    def complete(self, job_id: UUID, worker_id: str, result: Mapping[str, Any] | None = None) -> bool:
        outcome = self._conn.execute(
            jobs.update()
            .where(self._held(job_id, worker_id))
            .values(
                status=JobStatus.SUCCEEDED.value,
                finished_at=func.now(),
                lease_owner=None,
                lease_expires_at=None,
                result=dict(result) if result is not None else None,
            )
        )
        return outcome.rowcount == 1

    def fail(self, job_id: UUID, worker_id: str, error: str, *, retry_in_seconds: int | None = None) -> bool:
        row = self._conn.execute(
            select(jobs.c.attempts, jobs.c.max_attempts).where(self._held(job_id, worker_id)).with_for_update()
        ).one_or_none()
        if row is None:
            return False
        values: dict[str, Any] = {"lease_owner": None, "lease_expires_at": None, "last_error": error[:_ERROR_LIMIT]}
        if retry_in_seconds is not None and row.attempts < row.max_attempts:
            values |= {"status": JobStatus.QUEUED.value, "run_after": _later(retry_in_seconds)}
        else:
            values |= {"status": JobStatus.FAILED.value, "finished_at": func.now()}
        self._conn.execute(jobs.update().where(jobs.c.id == job_id).values(**values))
        return True


def _notification(row: Any) -> Notification:
    return Notification(
        id=row.id,
        project_id=row.project_id,
        channel=row.channel,
        event_type=row.event_type,
        dedupe_key=row.dedupe_key,
        payload=row.payload,
        status=NotificationStatus(row.status),
        attempts=row.attempts,
        max_attempts=row.max_attempts,
        created_at=row.created_at,
        next_attempt_at=row.next_attempt_at,
        lease_owner=row.lease_owner,
        lease_expires_at=row.lease_expires_at,
        sent_at=row.sent_at,
        last_error=row.last_error,
    )


class PgNotificationRepository(_ProjectRepository):
    def enqueue(self, new: NewNotification) -> tuple[Notification, bool]:
        statement = (
            insert(notifications)
            .values(
                id=uuid4(),
                project_id=self.project_id,
                channel=new.channel,
                event_type=new.event_type,
                dedupe_key=new.dedupe_key,
                payload=dict(new.payload),
                max_attempts=new.max_attempts,
            )
            .on_conflict_do_nothing(index_elements=[notifications.c.project_id, notifications.c.dedupe_key])
            .returning(*notifications.c)
        )
        row = self._conn.execute(statement).one_or_none()
        if row is not None:
            return _notification(row), True
        existing = self._conn.execute(
            select(notifications).where(self._mine(notifications), notifications.c.dedupe_key == new.dedupe_key)
        ).one()
        return _notification(existing), False


class PgNotificationLeaseRepository:
    def __init__(self, connection: Connection) -> None:
        self._conn = connection

    def claim(
        self, worker_id: str, *, channels: Sequence[str] | None = None, lease_seconds: int = 60, limit: int = 10
    ) -> Sequence[Notification]:
        expired = and_(
            notifications.c.status == NotificationStatus.SENDING.value,
            notifications.c.lease_expires_at < func.now(),
        )
        self._conn.execute(
            notifications.update()
            .where(expired, notifications.c.attempts >= notifications.c.max_attempts)
            .values(
                status=NotificationStatus.FAILED.value,
                lease_owner=None,
                lease_expires_at=None,
                last_error="lease expired on final attempt",
            )
        )
        due = select(notifications.c.id).where(
            or_(
                and_(
                    notifications.c.status == NotificationStatus.PENDING.value,
                    notifications.c.next_attempt_at <= func.now(),
                ),
                expired,
            )
        )
        if channels is not None:
            due = due.where(notifications.c.channel.in_(list(channels)))
        due = due.order_by(notifications.c.next_attempt_at).limit(limit).with_for_update(skip_locked=True).cte("due")
        rows = self._conn.execute(
            notifications.update()
            .where(notifications.c.id == due.c.id)
            .values(
                status=NotificationStatus.SENDING.value,
                lease_owner=worker_id,
                lease_expires_at=_later(lease_seconds),
                attempts=notifications.c.attempts + 1,
            )
            .returning(*notifications.c)
        )
        return sorted((_notification(row) for row in rows), key=lambda n: n.next_attempt_at)

    def _held(self, notification_id: UUID, worker_id: str) -> Any:
        return and_(
            notifications.c.id == notification_id,
            notifications.c.status == NotificationStatus.SENDING.value,
            notifications.c.lease_owner == worker_id,
        )

    def mark_sent(self, notification_id: UUID, worker_id: str) -> bool:
        result = self._conn.execute(
            notifications.update()
            .where(self._held(notification_id, worker_id))
            .values(
                status=NotificationStatus.SENT.value,
                sent_at=func.now(),
                lease_owner=None,
                lease_expires_at=None,
            )
        )
        return result.rowcount == 1

    def mark_failed(
        self, notification_id: UUID, worker_id: str, error: str, *, retry_in_seconds: int | None = None
    ) -> bool:
        row = self._conn.execute(
            select(notifications.c.attempts, notifications.c.max_attempts)
            .where(self._held(notification_id, worker_id))
            .with_for_update()
        ).one_or_none()
        if row is None:
            return False
        values: dict[str, Any] = {"lease_owner": None, "lease_expires_at": None, "last_error": error[:_ERROR_LIMIT]}
        if retry_in_seconds is not None and row.attempts < row.max_attempts:
            values |= {"status": NotificationStatus.PENDING.value, "next_attempt_at": _later(retry_in_seconds)}
        else:
            values["status"] = NotificationStatus.FAILED.value
        self._conn.execute(notifications.update().where(notifications.c.id == notification_id).values(**values))
        return True
