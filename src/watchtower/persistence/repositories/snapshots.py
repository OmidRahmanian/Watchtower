"""Append-only phase snapshots that let a run compare itself with earlier runs."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert

from watchtower.domain.models import (
    COMPARABLE_PHASE_STATUSES,
    NewPhaseSnapshot,
    PhaseComparison,
    PhaseSnapshot,
    PhaseStatus,
    RunPhase,
)
from watchtower.persistence.repositories.records import _ProjectRepository
from watchtower.persistence.tables import phase_snapshots


def _snapshot(row: Any) -> PhaseSnapshot:
    return PhaseSnapshot(
        id=row.id,
        project_id=row.project_id,
        run_id=row.run_id,
        target=row.target,
        phase=RunPhase(row.phase),
        status=PhaseStatus(row.status),
        comparison=PhaseComparison(row.comparison),
        items=row.items,
        pending=row.pending,
        changes=row.changes,
        stats=row.stats,
        created_at=row.created_at,
        job_id=row.job_id,
    )


class PgPhaseSnapshotRepository(_ProjectRepository):
    def record(self, new: NewPhaseSnapshot) -> tuple[PhaseSnapshot, bool]:
        phase = RunPhase(new.phase)
        statement = (
            insert(phase_snapshots)
            .values(
                id=uuid4(),
                project_id=self.project_id,
                run_id=new.run_id,
                job_id=new.job_id,
                target=new.target,
                phase=phase.value,
                status=PhaseStatus(new.status).value,
                comparison=PhaseComparison(new.comparison).value,
                items=list(new.items),
                pending=list(new.pending),
                changes=dict(new.changes),
                stats=dict(new.stats),
                # Unlike now(), distinct within one transaction, so "latest" is well defined.
                created_at=func.clock_timestamp(),
            )
            .on_conflict_do_nothing(
                index_elements=[
                    phase_snapshots.c.project_id,
                    phase_snapshots.c.run_id,
                    phase_snapshots.c.phase,
                    phase_snapshots.c.target,
                ]
            )
            .returning(*phase_snapshots.c)
        )
        row = self._conn.execute(statement).one_or_none()
        if row is not None:
            return _snapshot(row), True
        existing = self._conn.execute(
            select(phase_snapshots).where(
                self._mine(phase_snapshots),
                phase_snapshots.c.run_id == new.run_id,
                phase_snapshots.c.phase == phase.value,
                phase_snapshots.c.target == new.target,
            )
        ).one()
        return _snapshot(existing), False

    def latest_comparable(self, target: str, phase: RunPhase) -> PhaseSnapshot | None:
        row = self._conn.execute(
            select(phase_snapshots)
            .where(
                self._mine(phase_snapshots),
                phase_snapshots.c.target == target,
                phase_snapshots.c.phase == RunPhase(phase).value,
                phase_snapshots.c.status.in_([status.value for status in COMPARABLE_PHASE_STATUSES]),
            )
            .order_by(phase_snapshots.c.created_at.desc())
            .limit(1)
        ).one_or_none()
        return _snapshot(row) if row else None

    def list_for_run(self, run_id: UUID) -> Sequence[PhaseSnapshot]:
        rows = self._conn.execute(
            select(phase_snapshots)
            .where(self._mine(phase_snapshots), phase_snapshots.c.run_id == run_id)
            .order_by(phase_snapshots.c.created_at)
        )
        return [_snapshot(row) for row in rows]
