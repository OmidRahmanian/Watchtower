"""Storage interfaces shared by every WatchTower component.

Code that works inside one project receives a ``ProjectUnitOfWork``. Its
repositories never take a ``project_id``: the unit of work is bound to one
project, and PostgreSQL row-level security rejects reads and writes for any
other project. Only schedulers, workers and the notifier use a
``SystemUnitOfWork``, which crosses projects to lease work.

Obtain them from ``watchtower.persistence.Database``::

    with database.project(project_id) as uow:
        asset = uow.assets.upsert(AssetKind.HOSTNAME, "api.example.com")
        uow.observations.record(NewObservation(asset.id, ...))
    # committed on normal exit, rolled back on exception

Values passed to ``assets`` must already be canonical (see
``watchtower.domain.targets``); the repositories reject values that are not.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any, Protocol
from uuid import UUID

from watchtower.domain.models import (
    Asset,
    AssetKind,
    Evidence,
    Finding,
    FindingStatus,
    Job,
    LeaseStatus,
    NewEvidence,
    NewFinding,
    NewJob,
    NewNotification,
    NewObservation,
    NewPhaseSnapshot,
    Notification,
    Observation,
    ObservationKind,
    PhaseSnapshot,
    Project,
    RunPhase,
    StoredBlob,
)
from watchtower.domain.scope import NewScopeRevision, ScopeRevision


class AssetRepository(Protocol):
    def upsert(
        self,
        kind: AssetKind,
        value: str,
        *,
        seen_at: datetime | None = None,
        attributes: Mapping[str, Any] | None = None,
        scope_revision_id: UUID | None = None,
    ) -> tuple[Asset, bool]:
        """Create the asset or bump ``last_seen_at``; returns ``(asset, created)``.

        ``attributes`` are merged into the stored attributes (top-level keys).
        """
        ...

    def get(self, asset_id: UUID) -> Asset | None: ...

    def find(self, kind: AssetKind, value: str) -> Asset | None: ...

    def list(
        self, *, kind: AssetKind | None = None, limit: int = 100, after_value: str | None = None
    ) -> Sequence[Asset]:
        """Assets ordered by ``(kind, value)``; page with ``after_value``."""
        ...


class ObservationRepository(Protocol):
    def record(self, new: NewObservation) -> tuple[Observation, bool]:
        """Append an observation; a repeated ``source_ref`` returns the existing one."""
        ...

    def latest(self, asset_id: UUID, kind: ObservationKind) -> Observation | None: ...

    def list_for_asset(
        self, asset_id: UUID, *, kind: ObservationKind | None = None, limit: int = 100
    ) -> Sequence[Observation]:
        """Newest first."""
        ...


class JobRepository(Protocol):
    def enqueue(self, new: NewJob) -> tuple[Job, bool]:
        """Queue a job; a repeated ``idempotency_key`` returns the existing job.

        Raises ``RunCancelled`` if ``new.run_id`` names a run whose cancellation
        was requested, even when the key matches an existing job.
        """
        ...

    def get(self, job_id: UUID) -> Job | None: ...

    def list_for_run(self, run_id: UUID) -> Sequence[Job]:
        """The run's jobs, oldest first."""
        ...

    def cancel(self, job_id: UUID) -> bool:
        """Cancel a queued job; running and finished jobs are left alone. Prefer ``request_cancel``."""
        ...

    def request_cancel(self, *, job_id: UUID | None = None, run_id: UUID | None = None, reason: str) -> int:
        """Ask a job, or every job of a run, to stop; pass exactly one of ``job_id`` and ``run_id``.

        Queued jobs become cancelled at once. Running jobs only get
        ``cancel_requested_at``: their worker sees it on its next heartbeat and
        calls ``JobLeaseRepository.mark_cancelled``. Finished jobs are left
        alone. Cancelling a run also refuses later ``enqueue`` calls for it,
        including when the run has no jobs yet. Returns how many jobs were
        newly cancelled or flagged; repeating a request returns 0.
        """
        ...


class JobLeaseRepository(Protocol):
    """Cross-project job leasing for workers (``SystemUnitOfWork`` only)."""

    def claim(
        self,
        worker_id: str,
        *,
        kinds: Sequence[str] | None = None,
        lease_seconds: int = 300,
        limit: int = 1,
        limits: Mapping[str, int] | None = None,
    ) -> Sequence[Job]:
        """Lease due jobs (queued, or running with an expired lease), highest priority first.

        Jobs with a cancel request are never leased; an expired lease on such a
        job turns it cancelled. ``limits`` caps how many jobs with each
        ``concurrency_key`` may run at once, counting unexpired leases in every
        project; keys not listed, and jobs without a key, are unlimited. Limits
        are enforced only among claims that pass them. A claim with
        ``limits`` serializes with other such claims on the same keys until its
        transaction commits, so claim in a short transaction of its own.
        """
        ...

    def heartbeat(self, job_id: UUID, worker_id: str, *, lease_seconds: int = 300) -> LeaseStatus:
        """Extend the lease. Falsy when the worker no longer holds it."""
        ...

    def complete(self, job_id: UUID, worker_id: str, result: Mapping[str, Any] | None = None) -> bool: ...

    def fail(self, job_id: UUID, worker_id: str, error: str, *, retry_in_seconds: int | None = None) -> bool:
        """Record a failure; requeue after ``retry_in_seconds`` while attempts remain.

        A job with a cancel request is cancelled instead of requeued.
        """
        ...

    def mark_cancelled(self, job_id: UUID, worker_id: str, detail: str) -> bool:
        """Finish a held job as cancelled; ``detail`` is stored as ``result["cancel_detail"]``.

        A worker may also cancel without a request; ``detail`` then becomes the
        cancel reason.
        """
        ...


class FindingRepository(Protocol):
    def upsert(self, new: NewFinding) -> tuple[Finding, bool]:
        """Create by ``fingerprint`` or refresh ``last_seen_at``/details; status is kept."""
        ...

    def get(self, finding_id: UUID) -> Finding | None: ...

    def get_by_fingerprint(self, fingerprint: str) -> Finding | None: ...

    def set_status(self, finding_id: UUID, status: FindingStatus) -> Finding: ...

    def list(
        self, *, status: FindingStatus | None = None, asset_id: UUID | None = None, limit: int = 100
    ) -> Sequence[Finding]: ...


class BlobStore(Protocol):
    """Content-addressed storage for evidence bodies; implementations live outside persistence."""

    def put(self, project_id: UUID, data: bytes, *, media_type: str) -> StoredBlob: ...

    def get(self, uri: str) -> bytes: ...


class EvidenceRepository(Protocol):
    def add(self, new: NewEvidence) -> Evidence: ...

    def get(self, evidence_id: UUID) -> Evidence | None: ...

    def list_for_finding(self, finding_id: UUID) -> Sequence[Evidence]: ...


class NotificationRepository(Protocol):
    def enqueue(self, new: NewNotification) -> tuple[Notification, bool]:
        """Add to the outbox; a repeated ``dedupe_key`` returns the existing row."""
        ...


class NotificationLeaseRepository(Protocol):
    """Cross-project outbox delivery for the notifier (``SystemUnitOfWork`` only)."""

    def claim(self, worker_id: str, *, channels: Sequence[str] | None = None, lease_seconds: int = 60, limit: int = 10) -> Sequence[Notification]: ...

    def mark_sent(self, notification_id: UUID, worker_id: str) -> bool: ...

    def mark_failed(self, notification_id: UUID, worker_id: str, error: str, *, retry_in_seconds: int | None = None) -> bool: ...


class PhaseSnapshotRepository(Protocol):
    """Append-only per-phase results of pipeline runs, used to compare runs."""

    def record(self, new: NewPhaseSnapshot) -> tuple[PhaseSnapshot, bool]:
        """Append a snapshot; a repeated ``(run_id, phase, target)`` returns the existing one."""
        ...

    def latest_comparable(self, target: str, phase: RunPhase) -> PhaseSnapshot | None:
        """The newest completed or partial snapshot for ``target`` and ``phase``."""
        ...

    def list_for_run(self, run_id: UUID) -> Sequence[PhaseSnapshot]:
        """Oldest first."""
        ...


class ScopeRepository(Protocol):
    """Immutable scope revisions. Use ``watchtower.services.scope`` rather than this directly."""

    def current(self) -> ScopeRevision | None: ...

    def get(self, revision_id: UUID) -> ScopeRevision | None: ...

    def history(self) -> Sequence[ScopeRevision]:
        """All revisions, newest first."""
        ...

    def publish(self, new: NewScopeRevision, *, created_by: UUID | None) -> ScopeRevision: ...

    def revoke(self, revision_id: UUID, *, reason: str, revoked_by: UUID | None) -> ScopeRevision: ...


class ProjectRepository(Protocol):
    def create(self, slug: str, name: str) -> Project: ...

    def get(self, project_id: UUID) -> Project | None: ...

    def get_by_slug(self, slug: str) -> Project | None: ...

    def list(self, *, include_archived: bool = False) -> Sequence[Project]: ...

    def archive(self, project_id: UUID) -> Project: ...


class ProjectUnitOfWork(Protocol):
    project_id: UUID
    assets: AssetRepository
    observations: ObservationRepository
    jobs: JobRepository
    findings: FindingRepository
    evidence: EvidenceRepository
    notifications: NotificationRepository
    phase_snapshots: PhaseSnapshotRepository
    scope: ScopeRepository

    def get_project(self) -> Project: ...


class SystemUnitOfWork(Protocol):
    projects: ProjectRepository
    job_leases: JobLeaseRepository
    notification_leases: NotificationLeaseRepository
