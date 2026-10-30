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
    NewEvidence,
    NewFinding,
    NewJob,
    NewNotification,
    NewObservation,
    Notification,
    Observation,
    ObservationKind,
    Project,
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
        """Queue a job; a repeated ``idempotency_key`` returns the existing job."""
        ...

    def get(self, job_id: UUID) -> Job | None: ...

    def cancel(self, job_id: UUID) -> bool:
        """Cancel a queued job; running and finished jobs are left alone."""
        ...


class JobLeaseRepository(Protocol):
    """Cross-project job leasing for workers (``SystemUnitOfWork`` only)."""

    def claim(
        self, worker_id: str, *, kinds: Sequence[str] | None = None, lease_seconds: int = 300, limit: int = 1
    ) -> Sequence[Job]:
        """Lease due jobs (queued, or running with an expired lease), highest priority first."""
        ...

    def heartbeat(self, job_id: UUID, worker_id: str, *, lease_seconds: int = 300) -> bool: ...

    def complete(self, job_id: UUID, worker_id: str, result: Mapping[str, Any] | None = None) -> bool: ...

    def fail(self, job_id: UUID, worker_id: str, error: str, *, retry_in_seconds: int | None = None) -> bool:
        """Record a failure; requeue after ``retry_in_seconds`` while attempts remain."""
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
    scope: ScopeRepository

    def get_project(self) -> Project: ...


class SystemUnitOfWork(Protocol):
    projects: ProjectRepository
    job_leases: JobLeaseRepository
    notification_leases: NotificationLeaseRepository
