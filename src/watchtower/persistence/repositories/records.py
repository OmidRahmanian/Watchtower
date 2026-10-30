"""Project-scoped repositories for assets, observations, findings and evidence."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import ColumnElement, Connection, Table, func, literal_column, select
from sqlalchemy.dialects.postgresql import insert

from watchtower.domain.errors import InvalidTarget, NotFound
from watchtower.domain.models import (
    Asset,
    AssetKind,
    Evidence,
    Finding,
    FindingStatus,
    NewEvidence,
    NewFinding,
    NewObservation,
    Observation,
    ObservationKind,
    Severity,
    canonical_asset_value,
)
from watchtower.persistence.tables import assets, evidence, findings, observations

_CREATED = literal_column("(xmax = 0)").label("created")


class _ProjectRepository:
    def __init__(self, connection: Connection, project_id: UUID) -> None:
        self._conn = connection
        self.project_id = project_id

    def _mine(self, table: Table) -> ColumnElement[bool]:
        """Explicit project filter; row-level security enforces the same boundary."""
        return table.c.project_id == self.project_id


def _asset(row: Any) -> Asset:
    return Asset(
        id=row.id,
        project_id=row.project_id,
        kind=AssetKind(row.kind),
        value=row.value,
        first_seen_at=row.first_seen_at,
        last_seen_at=row.last_seen_at,
        attributes=row.attributes,
        scope_revision_id=row.scope_revision_id,
    )


class PgAssetRepository(_ProjectRepository):
    def upsert(
        self,
        kind: AssetKind,
        value: str,
        *,
        seen_at: datetime | None = None,
        attributes: Mapping[str, Any] | None = None,
        scope_revision_id: UUID | None = None,
    ) -> tuple[Asset, bool]:
        kind = AssetKind(kind)
        canonical = canonical_asset_value(kind, value)
        if canonical != value:
            raise InvalidTarget(f"asset value is not canonical: {value!r} (expected {canonical!r})")
        seen = seen_at or func.now()
        statement = insert(assets).values(
            id=uuid4(),
            project_id=self.project_id,
            kind=kind.value,
            value=value,
            first_seen_at=seen,
            last_seen_at=seen,
            attributes=dict(attributes or {}),
            scope_revision_id=scope_revision_id,
        )
        excluded = statement.excluded
        statement = statement.on_conflict_do_update(
            index_elements=[assets.c.project_id, assets.c.kind, assets.c.value],
            set_={
                "first_seen_at": func.least(assets.c.first_seen_at, excluded.first_seen_at),
                "last_seen_at": func.greatest(assets.c.last_seen_at, excluded.last_seen_at),
                "attributes": assets.c.attributes.op("||")(excluded.attributes),
                "scope_revision_id": func.coalesce(excluded.scope_revision_id, assets.c.scope_revision_id),
            },
        ).returning(*assets.c, _CREATED)
        row = self._conn.execute(statement).one()
        return _asset(row), row.created

    def get(self, asset_id: UUID) -> Asset | None:
        row = self._conn.execute(select(assets).where(self._mine(assets), assets.c.id == asset_id)).one_or_none()
        return _asset(row) if row else None

    def find(self, kind: AssetKind, value: str) -> Asset | None:
        row = self._conn.execute(
            select(assets).where(self._mine(assets), assets.c.kind == AssetKind(kind).value, assets.c.value == value)
        ).one_or_none()
        return _asset(row) if row else None

    def list(
        self, *, kind: AssetKind | None = None, limit: int = 100, after_value: str | None = None
    ) -> Sequence[Asset]:
        query = select(assets).where(self._mine(assets)).order_by(assets.c.kind, assets.c.value).limit(limit)
        if kind is not None:
            query = query.where(assets.c.kind == AssetKind(kind).value)
        if after_value is not None:
            query = query.where(assets.c.value > after_value)
        return [_asset(row) for row in self._conn.execute(query)]


def _observation(row: Any) -> Observation:
    return Observation(
        id=row.id,
        project_id=row.project_id,
        asset_id=row.asset_id,
        kind=ObservationKind(row.kind),
        source=row.source,
        data=row.data,
        observed_at=row.observed_at,
        recorded_at=row.recorded_at,
        job_id=row.job_id,
        scope_revision_id=row.scope_revision_id,
        source_ref=row.source_ref,
    )


class PgObservationRepository(_ProjectRepository):
    def record(self, new: NewObservation) -> tuple[Observation, bool]:
        statement = (
            insert(observations)
            .values(
                id=uuid4(),
                project_id=self.project_id,
                asset_id=new.asset_id,
                kind=ObservationKind(new.kind).value,
                source=new.source,
                data=dict(new.data),
                observed_at=new.observed_at or func.now(),
                job_id=new.job_id,
                scope_revision_id=new.scope_revision_id,
                source_ref=new.source_ref,
            )
            .on_conflict_do_nothing(index_elements=[observations.c.project_id, observations.c.source_ref])
            .returning(*observations.c)
        )
        row = self._conn.execute(statement).one_or_none()
        if row is not None:
            return _observation(row), True
        existing = self._conn.execute(
            select(observations).where(self._mine(observations), observations.c.source_ref == new.source_ref)
        ).one()
        return _observation(existing), False

    def latest(self, asset_id: UUID, kind: ObservationKind) -> Observation | None:
        found = self.list_for_asset(asset_id, kind=kind, limit=1)
        return found[0] if found else None

    def list_for_asset(
        self, asset_id: UUID, *, kind: ObservationKind | None = None, limit: int = 100
    ) -> Sequence[Observation]:
        query = (
            select(observations)
            .where(self._mine(observations), observations.c.asset_id == asset_id)
            .order_by(observations.c.observed_at.desc(), observations.c.recorded_at.desc())
            .limit(limit)
        )
        if kind is not None:
            query = query.where(observations.c.kind == ObservationKind(kind).value)
        return [_observation(row) for row in self._conn.execute(query)]


def _finding(row: Any) -> Finding:
    return Finding(
        id=row.id,
        project_id=row.project_id,
        asset_id=row.asset_id,
        fingerprint=row.fingerprint,
        title=row.title,
        severity=Severity(row.severity),
        status=FindingStatus(row.status),
        source=row.source,
        details=row.details,
        first_seen_at=row.first_seen_at,
        last_seen_at=row.last_seen_at,
        status_changed_at=row.status_changed_at,
        scope_revision_id=row.scope_revision_id,
    )


class PgFindingRepository(_ProjectRepository):
    def upsert(self, new: NewFinding) -> tuple[Finding, bool]:
        seen = new.observed_at or func.now()
        statement = insert(findings).values(
            id=uuid4(),
            project_id=self.project_id,
            asset_id=new.asset_id,
            fingerprint=new.fingerprint,
            title=new.title,
            severity=Severity(new.severity).value,
            source=new.source,
            details=dict(new.details),
            first_seen_at=seen,
            last_seen_at=seen,
            scope_revision_id=new.scope_revision_id,
        )
        excluded = statement.excluded
        statement = statement.on_conflict_do_update(
            index_elements=[findings.c.project_id, findings.c.fingerprint],
            set_={
                "title": excluded.title,
                "severity": excluded.severity,
                "details": excluded.details,
                "last_seen_at": func.greatest(findings.c.last_seen_at, excluded.last_seen_at),
                "scope_revision_id": func.coalesce(excluded.scope_revision_id, findings.c.scope_revision_id),
            },
        ).returning(*findings.c, _CREATED)
        row = self._conn.execute(statement).one()
        return _finding(row), row.created

    def get(self, finding_id: UUID) -> Finding | None:
        row = self._conn.execute(select(findings).where(self._mine(findings), findings.c.id == finding_id)).one_or_none()
        return _finding(row) if row else None

    def get_by_fingerprint(self, fingerprint: str) -> Finding | None:
        row = self._conn.execute(
            select(findings).where(self._mine(findings), findings.c.fingerprint == fingerprint)
        ).one_or_none()
        return _finding(row) if row else None

    def set_status(self, finding_id: UUID, status: FindingStatus) -> Finding:
        row = self._conn.execute(
            findings.update()
            .where(self._mine(findings), findings.c.id == finding_id)
            .values(status=FindingStatus(status).value, status_changed_at=func.now())
            .returning(*findings.c)
        ).one_or_none()
        if row is None:
            raise NotFound(f"finding {finding_id} not found")
        return _finding(row)

    def list(
        self, *, status: FindingStatus | None = None, asset_id: UUID | None = None, limit: int = 100
    ) -> Sequence[Finding]:
        query = select(findings).where(self._mine(findings)).order_by(findings.c.last_seen_at.desc()).limit(limit)
        if status is not None:
            query = query.where(findings.c.status == FindingStatus(status).value)
        if asset_id is not None:
            query = query.where(findings.c.asset_id == asset_id)
        return [_finding(row) for row in self._conn.execute(query)]


def _evidence(row: Any) -> Evidence:
    return Evidence(
        id=row.id,
        project_id=row.project_id,
        media_type=row.media_type,
        sha256=row.sha256,
        size_bytes=row.size_bytes,
        storage_uri=row.storage_uri,
        created_at=row.created_at,
        description=row.description,
        finding_id=row.finding_id,
        observation_id=row.observation_id,
    )


class PgEvidenceRepository(_ProjectRepository):
    def add(self, new: NewEvidence) -> Evidence:
        row = self._conn.execute(
            evidence.insert()
            .values(
                id=uuid4(),
                project_id=self.project_id,
                finding_id=new.finding_id,
                observation_id=new.observation_id,
                media_type=new.media_type,
                sha256=new.blob.sha256,
                size_bytes=new.blob.size_bytes,
                storage_uri=new.blob.uri,
                description=new.description,
            )
            .returning(*evidence.c)
        ).one()
        return _evidence(row)

    def get(self, evidence_id: UUID) -> Evidence | None:
        row = self._conn.execute(select(evidence).where(self._mine(evidence), evidence.c.id == evidence_id)).one_or_none()
        return _evidence(row) if row else None

    def list_for_finding(self, finding_id: UUID) -> Sequence[Evidence]:
        query = select(evidence).where(self._mine(evidence), evidence.c.finding_id == finding_id).order_by(evidence.c.created_at)
        return [_evidence(row) for row in self._conn.execute(query)]
