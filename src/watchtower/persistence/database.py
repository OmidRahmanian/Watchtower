"""Engine setup and project-isolated units of work."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from uuid import UUID

from sqlalchemy import Connection, Engine, create_engine, select, text

from watchtower.config.settings import DatabaseSettings
from watchtower.domain.errors import NotFound
from watchtower.domain.models import Project
from watchtower.persistence.repositories.auth import PgAuthRepository
from watchtower.persistence.repositories.queue import (
    PgJobLeaseRepository,
    PgJobRepository,
    PgNotificationLeaseRepository,
    PgNotificationRepository,
)
from watchtower.persistence.repositories.records import (
    PgAssetRepository,
    PgEvidenceRepository,
    PgFindingRepository,
    PgObservationRepository,
)
from watchtower.persistence.repositories.scope import PgProjectRepository, PgScopeRepository
from watchtower.persistence.tables import projects


class PgProjectUnitOfWork:
    """Repositories bound to one project inside one transaction."""

    def __init__(self, connection: Connection, project_id: UUID) -> None:
        self.connection = connection
        self.project_id = project_id
        self.assets = PgAssetRepository(connection, project_id)
        self.observations = PgObservationRepository(connection, project_id)
        self.jobs = PgJobRepository(connection, project_id)
        self.findings = PgFindingRepository(connection, project_id)
        self.evidence = PgEvidenceRepository(connection, project_id)
        self.notifications = PgNotificationRepository(connection, project_id)
        self.scope = PgScopeRepository(connection, project_id)

    def get_project(self) -> Project:
        project = PgProjectRepository(self.connection).get(self.project_id)
        if project is None:
            raise NotFound(f"project {self.project_id} not found")
        return project


class PgSystemUnitOfWork:
    """Cross-project access for schedulers, workers, the notifier and administration."""

    def __init__(self, connection: Connection) -> None:
        self.connection = connection
        self.projects = PgProjectRepository(connection)
        self.auth = PgAuthRepository(connection)
        self.job_leases = PgJobLeaseRepository(connection)
        self.notification_leases = PgNotificationLeaseRepository(connection)


class Database:
    def __init__(self, engine: Engine, *, statement_timeout_ms: int | None = None) -> None:
        self.engine = engine
        self._statement_timeout_ms = statement_timeout_ms

    @classmethod
    def from_settings(cls, settings: DatabaseSettings) -> Database:
        engine = create_engine(
            settings.sqlalchemy_url(),
            pool_size=settings.pool_size,
            max_overflow=settings.max_overflow,
            pool_pre_ping=True,
            echo=settings.echo,
        )
        return cls(engine, statement_timeout_ms=settings.statement_timeout_ms or None)

    @contextmanager
    def project(self, project_id: UUID) -> Iterator[PgProjectUnitOfWork]:
        """A transaction that can only see and write ``project_id``'s rows.

        Commits when the block exits normally and rolls back on an exception.
        """
        with self.engine.begin() as connection:
            self._prepare(connection, project_id=str(project_id), system="off")
            exists = connection.execute(select(projects.c.id).where(projects.c.id == project_id)).one_or_none()
            if exists is None:
                raise NotFound(f"project {project_id} not found")
            yield PgProjectUnitOfWork(connection, project_id)

    @contextmanager
    def system(self) -> Iterator[PgSystemUnitOfWork]:
        """A transaction that bypasses project isolation. Keep its use narrow."""
        with self.engine.begin() as connection:
            self._prepare(connection, project_id="", system="on")
            yield PgSystemUnitOfWork(connection)

    def _prepare(self, connection: Connection, *, project_id: str, system: str) -> None:
        # Transaction-local settings (is_local = true) vanish at commit or
        # rollback, so pooled connections never carry a project over.
        connection.execute(
            text(
                "SELECT set_config('watchtower.project_id', :project_id, true),"
                " set_config('watchtower.system', :system, true)"
            ),
            {"project_id": project_id, "system": system},
        )
        if self._statement_timeout_ms:
            connection.execute(
                text("SELECT set_config('statement_timeout', :timeout, true)"),
                {"timeout": str(self._statement_timeout_ms)},
            )

    def dispose(self) -> None:
        self.engine.dispose()
