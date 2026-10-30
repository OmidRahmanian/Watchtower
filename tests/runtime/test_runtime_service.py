"""RunService: permissions, scope, run status, listing, retests and scheduled runs."""
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from runtime_support import PUBLIC_IP, RecordingTransport, Runs, context, publish
from watchtower.domain.errors import NotFound, PermissionDenied, ScopeViolation
from watchtower.domain.models import FindingStatus, JobStatus, RunPhase
from watchtower.domain.scope import DecisionReason
from watchtower.security.auth import ProjectRole
from watchtower.workers.scheduler import schedule_due, slot_for

pytestmark = pytest.mark.postgres


def test_starting_and_cancelling_need_operate_and_viewing_needs_view(runs, project_id, viewer):
    with pytest.raises(PermissionDenied):
        runs.service.start_run(project_id, actor=viewer)
    summary = runs.service.start_run(project_id, actor=runs.actor)
    with pytest.raises(PermissionDenied):
        runs.service.cancel_run(project_id, summary.run_id, actor=viewer, reason="no")
    assert runs.service.get_run(project_id, summary.run_id, actor=viewer).summary.status == "queued"
    with pytest.raises(PermissionDenied):
        runs.service.get_run(uuid4(), summary.run_id, actor=viewer)  # credentials for another project
    with pytest.raises(NotFound):
        runs.service.get_run(project_id, uuid4(), actor=viewer)


def test_runs_need_a_published_scope_and_in_scope_targets(database, project_id, authorization, scope_service, lab):
    service = Runs(database, project_id, scope_service, lab, RecordingTransport()).service
    actor = context(project_id)
    with pytest.raises(ScopeViolation) as no_scope:
        service.start_run(project_id, actor=actor)
    assert no_scope.value.decision.reason is DecisionReason.NO_SCOPE
    publish(database, project_id, authorization, "*.example.com")
    with pytest.raises(ScopeViolation) as outside:
        service.start_run(project_id, actor=actor, targets=["example.net"])
    assert outside.value.decision.reason is DecisionReason.NOT_IN_SCOPE
    # The apex of a *.example.com rule is a discovery root even though the apex itself is not in scope.
    summary = service.start_run(project_id, actor=actor)
    assert summary.targets == ("example.com",) and summary.kind == "scan"
    assert summary.requested_by == str(actor.principal.id)


def test_a_revoked_scope_fails_closed_for_queued_jobs(database, project_id, authorization, scope_service, lab):
    revision = publish(database, project_id, authorization)
    runs = Runs(database, project_id, scope_service, lab, RecordingTransport())
    summary = runs.service.start_run(project_id, actor=runs.actor)
    with database.project(project_id) as uow:
        uow.scope.revoke(revision.id, reason="engagement ended", revoked_by=None)
    runs.worker().run_until_idle()
    detail = runs.service.get_run(project_id, summary.run_id, actor=runs.actor)
    assert lab.probes == [] and lab.lookups == []  # nothing was contacted
    assert {s.comparison.value for s in detail.snapshots} == {"failed"}
    assert all("revoked" in s.stats["skipped"] for s in detail.snapshots)
    assert detail.summary.status == "failed"


def test_failed_cancelled_partial_and_succeeded_stay_distinct(runs, lab, project_id):
    ok = runs.run()
    assert ok.summary.status == "succeeded" and ok.summary.finished_at is not None

    lab.http[("https", "www.example.com")] = "timeout"
    assert runs.run().summary.status == "partial"
    lab.http[("https", "www.example.com")] = (200, "Example")

    lab.explode["www.example.com"] = 99
    failed = runs.run()
    assert failed.summary.status == "failed"
    assert failed.summary.last_error and "crashed" in failed.summary.last_error
    assert [j.kind for j in failed.jobs] == ["monitor.discovery", "monitor.dns", "monitor.http"]
    assert failed.jobs[-1].status is JobStatus.FAILED and failed.jobs[-1].attempts == 3
    [alert] = [a for a in runs.alerts() if a["event_type"] == "monitor.run_failed"]
    assert alert["payload"]["failed_jobs"][0]["kind"] == "monitor.http"
    lab.explode.clear()

    queued = runs.service.start_run(project_id, actor=runs.actor)
    runs.service.cancel_run(project_id, queued.run_id, actor=runs.actor, reason="stop")
    assert runs.service.get_run(project_id, queued.run_id, actor=runs.actor).summary.status == "cancelled"

    statuses = [s.status for s in runs.service.list_runs(project_id, actor=runs.actor)]
    assert statuses == ["cancelled", "failed", "partial", "succeeded"]


def test_list_runs_pages_newest_first(runs, project_id):
    started = [runs.service.start_run(project_id, actor=runs.actor).run_id for _ in range(5)]
    first = runs.service.list_runs(project_id, actor=runs.actor, limit=2)
    rest = runs.service.list_runs(project_id, actor=runs.actor, limit=10,
                                  before=(first[-1].created_at, first[-1].run_id))
    assert [s.run_id for s in first + rest] == list(reversed(started))


def test_phase_selection_runs_only_those_phases_in_order(runs, project_id):
    summary = runs.service.start_run(project_id, actor=runs.actor, phases=[RunPhase.HTTP, RunPhase.DISCOVERY])
    runs.worker().run_until_idle()
    detail = runs.service.get_run(project_id, summary.run_id, actor=runs.actor)
    assert [j.kind for j in detail.jobs] == ["monitor.discovery", "monitor.http", "monitor.finalize"]
    assert [p.phase.value for p in detail.summary.phases] == ["discovery", "http"]


def finding_on_shop(runs, lab, database, project_id):
    runs.run()
    lab.exposed.add("shop.example.com")
    runs.run()
    with database.project(project_id) as uow:
        [finding] = uow.findings.list()
    return finding


def test_a_relevant_negative_retest_resolves_and_alerts_once(runs, lab, database, project_id):
    finding = finding_on_shop(runs, lab, database, project_id)
    lab.exposed.clear()
    lab.fetches.clear()
    summary = runs.service.request_retest(project_id, finding.fingerprint, actor=runs.actor, reason="fixed")
    assert summary.kind == "retest" and summary.targets == ("example.com",)
    runs.worker().run_until_idle()
    runs.notifier().run_until_idle()

    detail = runs.service.get_run(project_id, summary.run_id, actor=runs.actor)
    assert [j.kind for j in detail.jobs] == ["checks.retest", "monitor.finalize"]
    assert [u for _, u, _ in lab.fetches] == ["https://shop.example.com/.git/config"]  # only that check, that endpoint
    with database.project(project_id) as uow:
        assert uow.findings.get(finding.id).status is FindingStatus.RESOLVED
    assert [c["type"] for c in runs.alerts()[-1]["payload"]["changes"]] == ["finding.resolved"]
    runs.run()  # the next routine scan does not report the resolution again
    assert len(runs.alerts()) == 2


def test_a_retest_with_a_pending_rule_is_not_run_and_resolves_nothing(runs, lab, database, project_id):
    finding = finding_on_shop(runs, lab, database, project_id)
    lab.exposed.clear()
    lab.approved = False
    fetches = len(lab.fetches)
    summary = runs.service.request_retest(project_id, finding.fingerprint, actor=runs.actor)
    runs.worker().run_until_idle()
    detail = runs.service.get_run(project_id, summary.run_id, actor=runs.actor)
    [job] = [j for j in detail.jobs if j.kind == "checks.retest"]
    assert job.result["outcome"] == "not_run" and "exposed-git-config" in job.result["not_run"]
    [snapshot] = detail.snapshots
    assert snapshot.stats["outcome"] == "not_run" and detail.summary.status == "partial"
    assert len(lab.fetches) == fetches
    with database.project(project_id) as uow:
        assert uow.findings.get(finding.id).status is FindingStatus.OPEN


def test_retest_of_an_unknown_finding(runs, project_id):
    with pytest.raises(NotFound):
        runs.service.request_retest(project_id, "0" * 64, actor=runs.actor)


def test_notifications_can_be_listed_per_run(runs, lab, project_id):
    runs.run()
    lab.seeds.append("api.example.com")
    lab.dns["api.example.com"] = {"A": [PUBLIC_IP]}
    changed = runs.run()
    [row] = runs.service.list_notifications(project_id, actor=context(project_id, ProjectRole.VIEWER),
                                            run_id=changed.summary.run_id)
    assert row.channel == "ops" and row.event_type == "monitor.changes"
    assert row.dedupe_key == f"monitor.changes:{changed.summary.run_id}:ops"


def test_scheduled_slots_start_one_run_each(runs, database, project_id):
    now = datetime(2026, 10, 30, 7, 30, tzinfo=timezone.utc)
    every = timedelta(hours=6)
    assert slot_for(now, every) == slot_for(now + timedelta(hours=4), every) != slot_for(now + timedelta(hours=5), every)
    first = [s for s in schedule_due(database, runs.service, interval=every, now=now) if s.run_id]
    again = schedule_due(database, runs.service, interval=every, now=now + timedelta(minutes=5))
    mine = [s for s in first if s.targets == ("example.com",)]
    assert mine and {s.run_id for s in again} >= {s.run_id for s in mine}
    runs.worker().run_until_idle()
    scheduled = [s for s in runs.service.list_runs(project_id, actor=runs.actor) if s.reason.startswith("scheduled")]
    assert len(scheduled) == 1 and scheduled[0].requested_by is None and scheduled[0].status == "succeeded"
