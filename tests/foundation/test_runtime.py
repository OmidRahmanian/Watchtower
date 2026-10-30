"""PostgreSQL runtime schema: run cancellation, concurrency limits and phase snapshots."""

from __future__ import annotations

import threading
from uuid import UUID, uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, IntegrityError

from watchtower.domain.errors import RunCancelled
from watchtower.domain.models import (
    JobStatus,
    NewJob,
    NewPhaseSnapshot,
    PhaseComparison,
    PhaseStatus,
    RunPhase,
)
from watchtower.domain.scope import NewScopeRevision, ScopeRule
from watchtower.domain.targets import PortSet
from watchtower.persistence import Database

pytestmark = pytest.mark.postgres


@pytest.fixture
def revision_id(database: Database, project_id: UUID, authorization) -> UUID:
    with database.project(project_id) as uow:
        new = NewScopeRevision((ScopeRule.parse("*.example.com"),), authorization, PortSet.parse("443"))
        return uow.scope.publish(new, created_by=None).id


@pytest.fixture
def kind() -> str:
    """A job kind no other test uses, so claims only see this test's jobs."""
    return f"runtime-{uuid4().hex[:8]}"


def _claim(database: Database, worker: str, kind: str, **options):
    with database.system() as system:
        return system.job_leases.claim(worker, kinds=[kind], **options)


def test_job_carries_run_and_concurrency_key(database: Database, project_id: UUID, revision_id: UUID, kind: str) -> None:
    run_id = uuid4()
    with database.project(project_id) as uow:
        job, _ = uow.jobs.enqueue(NewJob(kind, revision_id, run_id=run_id, concurrency_key="dns"))
        plain, _ = uow.jobs.enqueue(NewJob(kind, revision_id))
        assert job.run_id == run_id and job.concurrency_key == "dns" and not job.cancel_requested
        assert [j.id for j in uow.jobs.list_for_run(run_id)] == [job.id]
        assert plain.run_id is None and plain.concurrency_key is None


def test_request_cancel_job(database: Database, project_id: UUID, revision_id: UUID, kind: str) -> None:
    with database.project(project_id) as uow:
        queued, _ = uow.jobs.enqueue(NewJob(kind, revision_id, priority=-1))
        running, _ = uow.jobs.enqueue(NewJob(kind, revision_id))
    assert [j.id for j in _claim(database, "w1", kind)] == [running.id]
    with database.project(project_id) as uow:
        assert uow.jobs.request_cancel(job_id=queued.id, reason="operator stop") == 1
        assert uow.jobs.request_cancel(job_id=running.id, reason="operator stop") == 1
        assert uow.jobs.request_cancel(job_id=running.id, reason="again") == 0
        cancelled, flagged = uow.jobs.get(queued.id), uow.jobs.get(running.id)
    assert cancelled.status is JobStatus.CANCELLED and cancelled.cancel_reason == "operator stop"  # type: ignore[union-attr]
    assert flagged.status is JobStatus.RUNNING and flagged.cancel_requested  # type: ignore[union-attr]
    assert flagged.cancel_reason == "operator stop"  # type: ignore[union-attr]


def test_request_cancel_validates_arguments(database: Database, project_id: UUID) -> None:
    with database.project(project_id) as uow:
        with pytest.raises(ValueError):
            uow.jobs.request_cancel(reason="no target")
        with pytest.raises(ValueError):
            uow.jobs.request_cancel(job_id=uuid4(), run_id=uuid4(), reason="both")
        with pytest.raises(ValueError):
            uow.jobs.request_cancel(run_id=uuid4(), reason="   ")


def test_cancelled_run_refuses_new_jobs(database: Database, project_id: UUID, revision_id: UUID, kind: str) -> None:
    run_id, other_run = uuid4(), uuid4()
    with database.project(project_id) as uow:
        first, _ = uow.jobs.enqueue(NewJob(kind, revision_id, run_id=run_id, idempotency_key=f"{run_id}/1"))
        second, _ = uow.jobs.enqueue(NewJob(kind, revision_id, run_id=run_id, priority=5))
        uow.jobs.enqueue(NewJob(kind, revision_id, run_id=other_run))
    _claim(database, "w1", kind)  # leases `second`, the highest priority
    with database.project(project_id) as uow:
        assert uow.jobs.request_cancel(run_id=run_id, reason="run aborted") == 2
        assert uow.jobs.request_cancel(run_id=run_id, reason="run aborted") == 0
        statuses = {job.id: job.status for job in uow.jobs.list_for_run(run_id)}
    assert statuses == {first.id: JobStatus.CANCELLED, second.id: JobStatus.RUNNING}
    with pytest.raises(RunCancelled):
        with database.project(project_id) as uow:
            uow.jobs.enqueue(NewJob(kind, revision_id, run_id=run_id))
    with pytest.raises(RunCancelled):  # even a repeated idempotency key
        with database.project(project_id) as uow:
            uow.jobs.enqueue(NewJob(kind, revision_id, run_id=run_id, idempotency_key=f"{run_id}/1"))
    with database.project(project_id) as uow:
        assert len(uow.jobs.list_for_run(other_run)) == 1


def test_run_cancelled_before_it_has_jobs(database: Database, project_id: UUID, revision_id: UUID, kind: str) -> None:
    run_id = uuid4()
    with database.project(project_id) as uow:
        assert uow.jobs.request_cancel(run_id=run_id, reason="never mind") == 0
    with pytest.raises(RunCancelled):
        with database.project(project_id) as uow:
            uow.jobs.enqueue(NewJob(kind, revision_id, run_id=run_id))


def test_run_cancellation_is_per_project(
    database: Database, project_id: UUID, other_project_id: UUID, revision_id: UUID, authorization, kind: str
) -> None:
    run_id = uuid4()
    with database.project(other_project_id) as uow:
        uow.jobs.request_cancel(run_id=run_id, reason="other project")
    with database.project(project_id) as uow:
        job, created = uow.jobs.enqueue(NewJob(kind, revision_id, run_id=run_id))
        assert created and job.status is JobStatus.QUEUED


def test_cancel_and_enqueue_race(database: Database, project_id: UUID, revision_id: UUID, kind: str) -> None:
    """A job enqueued while a cancellation is in flight is either cancelled or refused."""
    run_id = uuid4()
    started, release = threading.Event(), threading.Event()
    outcome: dict[str, object] = {}

    def enqueue() -> None:
        try:
            with database.project(project_id) as uow:
                outcome["job"] = uow.jobs.enqueue(NewJob(kind, revision_id, run_id=run_id))[0]
                started.set()  # holds the run lock until this transaction commits
                release.wait(5)
        except RunCancelled as error:
            outcome["error"] = error

    worker = threading.Thread(target=enqueue)
    worker.start()
    assert started.wait(5)
    canceller = threading.Thread(target=_cancel, args=(database, project_id, run_id, outcome))
    canceller.start()
    canceller.join(0.5)
    assert canceller.is_alive()  # blocked behind the uncommitted enqueue
    release.set()
    worker.join(10)
    canceller.join(10)
    assert "job" in outcome and outcome["cancelled"] == 1
    with database.project(project_id) as uow:
        assert [job.status for job in uow.jobs.list_for_run(run_id)] == [JobStatus.CANCELLED]


def _cancel(database: Database, project_id: UUID, run_id: UUID, outcome: dict[str, object]) -> None:
    with database.project(project_id) as uow:
        outcome["cancelled"] = uow.jobs.request_cancel(run_id=run_id, reason="race")


def test_heartbeat_reports_cancel_and_worker_marks_cancelled(
    database: Database, project_id: UUID, revision_id: UUID, kind: str
) -> None:
    with database.project(project_id) as uow:
        job, _ = uow.jobs.enqueue(NewJob(kind, revision_id))
    _claim(database, "w1", kind)
    with database.system() as system:
        status = system.job_leases.heartbeat(job.id, "w1")
        assert status and status.held and not status.cancel_requested
        assert not system.job_leases.heartbeat(job.id, "w2")
    with database.project(project_id) as uow:
        uow.jobs.request_cancel(job_id=job.id, reason="stop")
    with database.system() as system:
        assert system.job_leases.heartbeat(job.id, "w1").cancel_requested
        assert not system.job_leases.mark_cancelled(job.id, "w2", "not mine")
        assert system.job_leases.mark_cancelled(job.id, "w1", "stopped after 3 of 10 hosts")
        assert not system.job_leases.mark_cancelled(job.id, "w1", "twice")
    with database.project(project_id) as uow:
        done = uow.jobs.get(job.id)
    assert done is not None and done.status is JobStatus.CANCELLED and done.lease_owner is None
    assert done.cancel_reason == "stop" and done.result == {"cancel_detail": "stopped after 3 of 10 hosts"}


def test_worker_may_cancel_without_request(database: Database, project_id: UUID, revision_id: UUID, kind: str) -> None:
    with database.project(project_id) as uow:
        job, _ = uow.jobs.enqueue(NewJob(kind, revision_id))
    _claim(database, "w1", kind)
    with database.system() as system:
        assert system.job_leases.mark_cancelled(job.id, "w1", "target scope revoked")
    with database.project(project_id) as uow:
        done = uow.jobs.get(job.id)
    assert done is not None and done.status is JobStatus.CANCELLED and done.cancel_reason == "target scope revoked"


def test_cancel_requested_job_is_not_retried(database: Database, project_id: UUID, revision_id: UUID, kind: str) -> None:
    with database.project(project_id) as uow:
        failing, _ = uow.jobs.enqueue(NewJob(kind, revision_id, priority=1))
        abandoned, _ = uow.jobs.enqueue(NewJob(kind, revision_id))
    _claim(database, "w1", kind, limit=1)
    _claim(database, "w2", kind, limit=1, lease_seconds=0)
    with database.project(project_id) as uow:
        uow.jobs.request_cancel(job_id=failing.id, reason="stop")
        uow.jobs.request_cancel(job_id=abandoned.id, reason="stop")
    with database.system() as system:
        assert system.job_leases.fail(failing.id, "w1", "interrupted", retry_in_seconds=0)
    # w2's lease has expired: the next claim cancels the job instead of leasing it.
    assert _claim(database, "w3", kind, limit=10) == []
    with database.project(project_id) as uow:
        assert uow.jobs.get(failing.id).status is JobStatus.CANCELLED  # type: ignore[union-attr]
        assert uow.jobs.get(abandoned.id).status is JobStatus.CANCELLED  # type: ignore[union-attr]


def test_claim_respects_concurrency_limits(database: Database, project_id: UUID, revision_id: UUID, kind: str) -> None:
    key, other = f"k-{uuid4().hex[:8]}", f"k-{uuid4().hex[:8]}"
    with database.project(project_id) as uow:
        limited = [uow.jobs.enqueue(NewJob(kind, revision_id, priority=10, concurrency_key=key))[0] for _ in range(4)]
        free = [uow.jobs.enqueue(NewJob(kind, revision_id, concurrency_key=other))[0] for _ in range(2)]
        unkeyed, _ = uow.jobs.enqueue(NewJob(kind, revision_id, priority=-1))
    limits = {key: 2}
    first = _claim(database, "w1", kind, limit=10, limits=limits)
    assert sorted(j.concurrency_key or "" for j in first) == sorted(["", key, key, other, other])
    assert _claim(database, "w2", kind, limit=10, limits=limits) == []
    with database.system() as system:
        running = [j for j in first if j.concurrency_key == key]
        system.job_leases.complete(running[0].id, "w1")
    again = _claim(database, "w2", kind, limit=10, limits=limits)
    assert [j.concurrency_key for j in again] == [key]
    claimed = {j.id for j in first + again}
    assert {j.id for j in free} | {unkeyed.id} <= claimed and len(claimed & {j.id for j in limited}) == 3
    # A zero limit pauses the key; without limits the claim ignores keys.
    assert _claim(database, "w3", kind, limits={key: 0}) == []
    assert [j.concurrency_key for j in _claim(database, "w3", kind)] == [key]


def test_concurrent_limited_claims_do_not_overshoot(
    database: Database, project_id: UUID, revision_id: UUID, kind: str
) -> None:
    key = f"k-{uuid4().hex[:8]}"
    with database.project(project_id) as uow:
        for _ in range(3):
            uow.jobs.enqueue(NewJob(kind, revision_id, concurrency_key=key))
    claimed: list[int] = []
    holding = threading.Event()

    def second_claim() -> None:
        holding.wait(5)
        claimed.append(len(_claim(database, "w2", kind, limit=5, limits={key: 1})))

    thread = threading.Thread(target=second_claim)
    thread.start()
    with database.system() as system:
        claimed.append(len(system.job_leases.claim("w1", kinds=[kind], limit=5, limits={key: 1})))
        holding.set()
        thread.join(0.5)
        assert thread.is_alive()  # waits for this claim's transaction
    thread.join(10)
    assert claimed == [1, 0]


def test_negative_limit_rejected(database: Database) -> None:
    with pytest.raises(ValueError):
        with database.system() as system:
            system.job_leases.claim("w", limits={"dns": -1})


def _snapshot(run_id: UUID, **overrides) -> NewPhaseSnapshot:
    values = {
        "run_id": run_id,
        "target": "example.com",
        "phase": RunPhase.DISCOVERY,
        "status": PhaseStatus.COMPLETED,
        "comparison": PhaseComparison.BASELINE,
        "items": ["a.example.com", "b.example.com"],
        "stats": {"found": 2},
    }
    return NewPhaseSnapshot(**(values | overrides))


def test_phase_snapshots(database: Database, project_id: UUID, revision_id: UUID, kind: str) -> None:
    runs = [uuid4() for _ in range(4)]
    with database.project(project_id) as uow:
        job, _ = uow.jobs.enqueue(NewJob(kind, revision_id, run_id=runs[0]))
        first, created = uow.phase_snapshots.record(_snapshot(runs[0], job_id=job.id))
        again, created_again = uow.phase_snapshots.record(_snapshot(runs[0], items=["changed"]))
        assert created and not created_again and again.id == first.id and again.items == first.items
        assert first.job_id == job.id and first.stats == {"found": 2} and first.pending == []
        uow.phase_snapshots.record(_snapshot(runs[0], phase=RunPhase.DNS))
        partial, _ = uow.phase_snapshots.record(
            _snapshot(runs[1], status=PhaseStatus.PARTIAL, comparison=PhaseComparison.PARTIAL, pending=["c"])
        )
        uow.phase_snapshots.record(_snapshot(runs[2], status=PhaseStatus.FAILED, comparison=PhaseComparison.FAILED))
        uow.phase_snapshots.record(_snapshot(runs[3], status=PhaseStatus.CANCELLED, comparison=PhaseComparison.FAILED))
        latest = uow.phase_snapshots.latest_comparable("example.com", RunPhase.DISCOVERY)
        assert latest is not None and latest.id == partial.id and latest.pending == ["c"]
        assert uow.phase_snapshots.latest_comparable("example.com", RunPhase.HTTP) is None
        assert uow.phase_snapshots.latest_comparable("other.example", RunPhase.DISCOVERY) is None
        assert [s.phase for s in uow.phase_snapshots.list_for_run(runs[0])] == [RunPhase.DISCOVERY, RunPhase.DNS]


def test_phase_snapshots_are_append_only_and_isolated(
    database: Database, project_id: UUID, other_project_id: UUID
) -> None:
    run_id = uuid4()
    with database.project(project_id) as uow:
        uow.phase_snapshots.record(_snapshot(run_id))
        uow.jobs.request_cancel(run_id=run_id, reason="done")
    for statement in ("UPDATE phase_snapshots SET status = 'failed'", "DELETE FROM phase_snapshots"):
        with pytest.raises(DBAPIError, match="append-only"):
            with database.project(project_id) as uow:
                uow.connection.execute(text(statement))
    with database.project(other_project_id) as uow:
        assert uow.phase_snapshots.list_for_run(run_id) == []
        assert uow.phase_snapshots.latest_comparable("example.com", RunPhase.DISCOVERY) is None
        assert uow.connection.execute(text("SELECT count(*) FROM phase_snapshots")).scalar_one() == 0
        assert uow.connection.execute(text("SELECT count(*) FROM run_cancellations")).scalar_one() == 0


def test_phase_snapshot_cannot_reference_another_projects_job(
    database: Database, project_id: UUID, other_project_id: UUID, revision_id: UUID, kind: str
) -> None:
    with database.project(project_id) as uow:
        job, _ = uow.jobs.enqueue(NewJob(kind, revision_id))
    with pytest.raises(IntegrityError):
        with database.project(other_project_id) as uow:
            uow.phase_snapshots.record(_snapshot(uuid4(), job_id=job.id))


@pytest.mark.parametrize(
    ("column", "value"),
    [
        ("target", "''"),
        ("phase", "'ports'"),
        ("status", "'done'"),
        ("comparison", "'same'"),
        ("items", "'{}'::jsonb"),
        ("pending", "'{}'::jsonb"),
        ("changes", "'[]'::jsonb"),
        ("stats", "'[]'::jsonb"),
    ],
)
def test_phase_snapshot_columns_are_checked(database: Database, project_id: UUID, column: str, value: str) -> None:
    values = {
        "target": "'example.com'",
        "phase": "'dns'",
        "status": "'completed'",
        "comparison": "'baseline'",
        column: value,
    }
    names = ", ".join(values)
    with pytest.raises(IntegrityError):
        with database.project(project_id) as uow:
            uow.connection.execute(
                text(
                    f"INSERT INTO phase_snapshots (id, project_id, run_id, {names})"
                    f" VALUES (gen_random_uuid(), :project, gen_random_uuid(), {', '.join(values.values())})"
                ),
                {"project": project_id},
            )


def test_cancel_request_requires_reason_in_schema(database: Database, project_id: UUID, revision_id: UUID, kind: str) -> None:
    with database.project(project_id) as uow:
        job, _ = uow.jobs.enqueue(NewJob(kind, revision_id))
    with pytest.raises(IntegrityError):
        with database.project(project_id) as uow:
            uow.connection.execute(
                text("UPDATE jobs SET cancel_requested_at = now() WHERE id = :id"), {"id": job.id}
            )
