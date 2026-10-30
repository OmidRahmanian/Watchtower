"""Test doubles and helpers for the API and CLI tests."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID, uuid4

from watchtower.domain.errors import NotFound
from watchtower.domain.models import AssetKind, Notification, RunPhase
from watchtower.security.auth import Permission, ProjectContext
from watchtower.services.evidence import to_new_evidence
from watchtower.services.findings import FindingService, RepositoryFindingStore

START = datetime(2026, 10, 30, 12, tzinfo=timezone.utc)


@dataclass(frozen=True)
class PhaseState:
    phase: RunPhase
    target: str
    status: str
    comparison: str


@dataclass(frozen=True)
class RunSummary:
    run_id: UUID
    created_at: datetime
    finished_at: datetime | None
    scope_revision_id: UUID | None
    requested_by: str | None
    kind: str
    reason: str
    status: str
    job_counts: dict[str, int] = field(default_factory=dict)
    phases: list[PhaseState] = field(default_factory=list)
    last_error: str | None = None


@dataclass(frozen=True)
class RunDetail:
    summary: RunSummary
    jobs: list[Any]
    snapshots: list[Any]


class FakeRuns:
    """Records calls with the ``RunService`` signatures and enforces the same permissions."""

    def __init__(self) -> None:
        self.runs: dict[UUID, tuple[UUID, RunSummary]] = {}
        self.calls: list[tuple[str, Any]] = []
        self.clock = START

    def _tick(self) -> datetime:
        self.clock += timedelta(minutes=1)
        return self.clock

    def add(self, project_id: UUID, status: str, *, kind: str = "scan", last_error: str | None = None) -> RunSummary:
        summary = RunSummary(run_id=uuid4(), created_at=self._tick(), finished_at=None, scope_revision_id=None,
                             requested_by=None, kind=kind, reason="", status=status,
                             job_counts={"failed": 1} if status == "failed" else {"succeeded": 4},
                             phases=[PhaseState(RunPhase.CHECKS, "acme.example", "completed", "baseline")],
                             last_error=last_error)
        self.runs[summary.run_id] = (project_id, summary)
        return summary

    def start_run(self, project_id, *, actor: ProjectContext, targets=None, phases=None, reason=""):
        actor.require(Permission.OPERATE)
        self.calls.append(("start_run", (project_id, targets, phases, reason)))
        summary = self.add(project_id, "queued")
        summary = replace(summary, requested_by=str(actor.principal.id), reason=reason)
        self.runs[summary.run_id] = (project_id, summary)
        return summary

    def cancel_run(self, project_id, run_id, *, actor, reason):
        actor.require(Permission.OPERATE)
        self.calls.append(("cancel_run", (project_id, run_id, reason)))
        return 1

    def list_runs(self, project_id, *, actor, limit=50, before=None):
        actor.require(Permission.VIEW)
        rows = sorted((s for p, s in self.runs.values() if p == project_id),
                      key=lambda s: (s.created_at, s.run_id), reverse=True)
        if before is not None:
            rows = [s for s in rows if (s.created_at, s.run_id) < before]
        return rows[:limit]

    def get_run(self, project_id, run_id, *, actor):
        actor.require(Permission.VIEW)
        found = self.runs.get(run_id)
        if found is None or found[0] != project_id:
            raise NotFound(f"run {run_id} not found")
        return RunDetail(found[1], [], [])

    def request_retest(self, project_id, fingerprint, *, actor, reason=""):
        actor.require(Permission.OPERATE)
        self.calls.append(("request_retest", (project_id, fingerprint, reason)))
        return self.add(project_id, "queued", kind="retest")

    def list_notifications(self, project_id, *, actor, run_id=None, limit=50) -> list[Notification]:
        actor.require(Permission.VIEW)
        return []


def seed_finding(database, project_id, scanner, reply, at, *, blobs=None, check="exposed-git-config",
                 host="shop.example.com"):
    """Run a real (test-approved) check against a canned reply and store the finding and its evidence."""
    result = scanner.run(reply, at, check=check, host=host)
    with database.project(project_id) as uow:
        uow.assets.upsert(AssetKind.HOSTNAME, host)
        service = FindingService(RepositoryFindingStore(uow), canonical_id=scanner.ruleset.canonical_id)
        record = service.ingest(result)
        row = uow.findings.get_by_fingerprint(record.fingerprint)
        if blobs is not None and record.first_evidence:
            uow.evidence.add(to_new_evidence(service.evidence.get(record.first_evidence), blobs, project_id,
                                             finding_id=row.id))
        return row
