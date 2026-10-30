"""Acceptance: worker termination and retries lose no findings and duplicate no notifications."""
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from runtime_support import RecordingTransport, Runs, publish, two_root_lab
from watchtower.domain.models import JobStatus, NotificationStatus, RunPhase
from watchtower.services.jobs import CancelToken
from watchtower.workers.runtime import Notifier, Worker

pytestmark = pytest.mark.postgres

HERE = Path(__file__).resolve().parent
ROOTS = ("example.com", "*.example.com", "example.org", "*.example.org")


@pytest.fixture
def two_roots(database, project_id, authorization, scope_service):
    publish(database, project_id, authorization, *ROOTS)
    lab = two_root_lab()
    runs = Runs(database, project_id, scope_service, lab, RecordingTransport())
    runs.run()  # baseline
    assert runs.alerts() == []
    return runs


def change(runs):
    changed = two_root_lab(changed=True)
    for name in ("seeds", "dns", "http", "exposed"):
        setattr(runs.lab, name, getattr(changed, name))


def findings(database, project_id):
    with database.project(project_id) as uow:
        return sorted((f.fingerprint, f.status.value) for f in uow.findings.list(limit=1000))


def expected_lines(alert):
    return sorted((c["type"], c["key"]) for c in alert["payload"]["changes"]
                  if c["type"] == "asset.discovered") + sorted(
        (c["type"], c["after"]["host"]) for c in alert["payload"]["changes"] if c["type"] == "finding.opened")


def test_a_worker_killed_mid_job_loses_nothing_and_duplicates_nothing(two_roots, database, project_id, migrated_url,
                                                                       tmp_path):
    runs = two_roots
    change(runs)
    summary = runs.service.start_run(project_id, actor=runs.actor)
    marker = tmp_path / "stuck"
    url = migrated_url.render_as_string(hide_password=False)
    # The doomed worker runs discovery, DNS and HTTP, records example.com's checks and
    # then hangs on a check request to shop.example.org, holding the lease.
    doomed = subprocess.Popen([sys.executable, str(HERE / "doomed_worker.py"), url, str(marker), "shop.example.org"],
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        deadline = time.monotonic() + 60
        while not marker.exists():
            assert doomed.poll() is None, doomed.stdout.read().decode()
            assert time.monotonic() < deadline, "the doomed worker never reached the checks phase"
            time.sleep(0.05)
    finally:
        os.kill(doomed.pid, signal.SIGKILL)
        doomed.wait()

    detail = runs.service.get_run(project_id, summary.run_id, actor=runs.actor)
    checks = [j for j in detail.jobs if j.kind == "monitor.checks"]
    assert [j.status for j in checks] == [JobStatus.RUNNING], [
        (j.kind, j.status, j.attempts, j.lease_owner) for j in detail.jobs]
    assert checks[0].lease_owner == "doomed"
    assert [(s.phase, s.target) for s in detail.snapshots if s.phase is RunPhase.CHECKS] == [
        (RunPhase.CHECKS, "example.com")]  # committed before the kill
    assert runs.notifications() == []  # nothing is alerted from a half-finished run

    # Expire the dead worker's lease explicitly. A tiny live lease or a fixed
    # wall-clock sleep makes this recovery test depend on machine/DB load.
    with database.system() as system:
        system.connection.exec_driver_sql(
            "UPDATE jobs SET lease_expires_at = now() - interval '1 second' "
            "WHERE id = %s", (checks[0].id,))
    fetched_before = len(runs.lab.fetches)
    runs.worker().run_until_idle()
    runs.notifier().run_until_idle()

    detail = runs.service.get_run(project_id, summary.run_id, actor=runs.actor)
    assert detail.summary.status == "succeeded"
    [checks] = [j for j in detail.jobs if j.kind == "monitor.checks"]
    assert checks.status is JobStatus.SUCCEEDED and checks.attempts == 2
    # The recovered attempt skipped example.com, whose results were already committed.
    assert {url.split("/")[2] for _, url, _ in runs.lab.fetches[fetched_before:]} <= {
        "www.example.org", "shop.example.org", "api.example.org"}
    assert sorted((s.phase.value, s.target) for s in detail.snapshots) == sorted(
        (phase, target) for phase in ("discovery", "dns", "http", "checks") for target in ("example.com", "example.org"))
    assert [status for _, status in findings(database, project_id)] == ["open", "open"]
    [alert] = runs.alerts()
    assert expected_lines(alert) == [("asset.discovered", "api.example.org"),
                                     ("finding.opened", "shop.example.com"), ("finding.opened", "shop.example.org")]
    assert len(runs.notifications()) == 1


def test_a_failing_job_is_retried_without_redoing_committed_targets(two_roots, database, project_id):
    runs = two_roots
    change(runs)
    runs.lab.explode["www.example.org"] = 1  # the first HTTP attempt crashes after example.com is recorded
    runs.lab.probes.clear()
    detail = runs.run()

    [http] = [j for j in detail.jobs if j.kind == "monitor.http"]
    assert http.status is JobStatus.SUCCEEDED and http.attempts == 2
    assert "probe of www.example.org crashed" in http.last_error
    probed = [host for _, host in runs.lab.probes]
    assert probed.count("www.example.com") == 1  # not probed again on the retry
    assert detail.summary.status == "succeeded"
    assert len(findings(database, project_id)) == 2
    alerts = runs.alerts()
    assert len(alerts) == 1, [(n.status, n.attempts, n.last_error) for n in runs.notifications()]
    [alert] = alerts
    assert len(alert["payload"]["changes"]) == 3


def test_a_rerun_job_records_its_snapshot_once(two_roots, database, project_id):
    """A job whose worker died after committing but before ``complete`` is replayed idempotently."""
    runs = two_roots
    change(runs)
    summary = runs.service.start_run(project_id, actor=runs.actor)
    worker = runs.worker()
    job = worker.claim()
    result = worker.pipeline.run_job(job, CancelToken())
    assert set(result["targets"]) == {"example.com", "example.org"}
    # The worker "dies" here: the job stays running, its follow-on job is already queued.
    with database.system() as system:
        system.connection.exec_driver_sql(f"UPDATE jobs SET lease_expires_at = now() - interval '1 second' "
                                          f"WHERE id = '{job.id}'")
    runs.worker().run_until_idle()
    runs.notifier().run_until_idle()
    detail = runs.service.get_run(project_id, summary.run_id, actor=runs.actor)
    assert detail.summary.status == "succeeded"
    discovery = [s for s in detail.snapshots if s.phase is RunPhase.DISCOVERY]
    assert len(discovery) == 2 and len([j for j in detail.jobs if j.kind == "monitor.dns"]) == 1
    assert len(runs.alerts()) == 1


class DiesAfterSending(RecordingTransport):
    """The notifier process dies after the receiver accepted the request, before ``mark_sent``."""

    def __init__(self):
        super().__init__()
        self.die = True

    def post(self, url, body, headers):
        response = super().post(url, body, headers)
        if self.die:
            self.die = False
            raise SystemExit("notifier killed")
        return response


def test_a_notifier_killed_after_sending_redelivers_with_the_same_idempotency_key(runs, lab, database, project_id):
    runs.run()
    lab.seeds.append("api.example.com")
    lab.dns["api.example.com"] = {"A": ["93.184.216.34"]}
    summary = runs.service.start_run(project_id, actor=runs.actor)
    runs.worker().run_until_idle()
    transport = DiesAfterSending()
    with pytest.raises(SystemExit):
        runs.notifier(transport=transport, lease_seconds=1).run_until_idle()
    time.sleep(1.2)
    runs.notifier(transport=transport, lease_seconds=1).run_until_idle()
    runs.notifier(transport=transport).run_until_idle()

    [row] = runs.service.list_notifications(project_id, actor=runs.actor, run_id=summary.run_id)
    assert row.status is NotificationStatus.SENT and row.attempts == 2
    # At least once: the receiver saw the request twice, with one idempotency key, so one alert.
    assert len(transport.requests) == 2
    assert len(transport.delivered) == 1
    assert transport.requests[0]["headers"]["Idempotency-Key"] == row.dedupe_key


class DiesBeforeSending(RecordingTransport):
    def post(self, url, body, headers):
        raise SystemExit("notifier killed before the request left")


def test_a_notifier_killed_before_sending_delivers_exactly_once(runs, lab, project_id):
    runs.run()
    lab.seeds.append("api.example.com")
    runs.service.start_run(project_id, actor=runs.actor)
    runs.worker().run_until_idle()
    with pytest.raises(SystemExit):
        runs.notifier(transport=DiesBeforeSending(), lease_seconds=1).run_until_idle()
    time.sleep(1.2)
    runs.notifier().run_until_idle()
    assert len(runs.transport.requests) == 1
    [row] = runs.notifications()
    assert row.status is NotificationStatus.SENT


def test_transient_delivery_errors_are_retried_into_one_alert(runs, lab):
    runs.run()
    lab.seeds.append("api.example.com")
    runs.transport.fail_next = 2
    detail = runs.run()
    runs.notifier().run_until_idle()
    runs.notifier().run_until_idle()
    assert len(runs.transport.requests) == 1, {
        "remaining_failures": runs.transport.fail_next,
        "run_status": detail.summary.status,
        "notifications": [(n.status, n.attempts, n.last_error, n.next_attempt_at) for n in runs.notifications()],
    }
    [row] = runs.notifications()
    assert row.status is NotificationStatus.SENT and row.attempts == 3


def test_finalize_is_idempotent(runs, lab, project_id):
    runs.run()
    lab.seeds.append("api.example.com")
    detail = runs.run()
    for _ in range(3):
        assert runs.worker().pipeline.finalize(project_id, detail.summary.run_id) == 0
    assert len(runs.notifications()) == 1


@pytest.mark.parametrize("role", [Worker, Notifier])
def test_fixture_waits_for_terminal_state_after_an_empty_claim(runs, lab, monkeypatch, role):
    runs.run()
    lab.seeds.append("api.example.com")
    lab.dns["api.example.com"] = {"A": ["93.184.216.34"]}
    lab.http[("https", "api.example.com")] = (200, "API")
    original = role.run_until_idle
    calls = 0

    def temporarily_idle(instance, *args, **kwargs):
        nonlocal calls
        calls += 1
        return 0 if calls == 1 else original(instance, *args, **kwargs)

    monkeypatch.setattr(role, "run_until_idle", temporarily_idle)
    detail = runs.run()
    assert detail.summary.status == "succeeded"
    assert len(runs.alerts()) == 1
    assert calls >= 2


@pytest.mark.parametrize("crash_after_complete", [False, True])
def test_an_early_finalizer_cannot_drop_the_last_phases_alert(runs, lab, database, project_id,
                                                            crash_after_complete):
    """Interleave workers deterministically at the enqueue/complete boundary."""
    runs.run()
    lab.exposed.add("shop.example.com")
    summary = runs.service.start_run(project_id, actor=runs.actor)
    predecessor = runs.worker()
    for _ in range(3):  # discovery, DNS, HTTP
        assert predecessor.run_once()
    job = predecessor.claim()
    assert job.kind == "monitor.checks"
    result = predecessor.pipeline.run_job(job, CancelToken())
    # The finalizer is available while its predecessor is still running.
    assert runs.worker().run_once()
    assert runs.notifications() == []
    if crash_after_complete:
        # Simulate a worker dying between the completion commit and its
        # post-completion reconciliation. The recovery sweep must repair it.
        with database.system() as system:
            assert system.job_leases.complete(job.id, predecessor.worker_id, result)
        assert runs.worker().recover() == 1
    else:
        predecessor.execute(job)
    runs.notifier().run_until_idle()
    detail = runs.service.get_run(project_id, summary.run_id, actor=runs.actor)
    assert detail.summary.status == "succeeded"
    [alert] = runs.alerts()
    assert [line["type"] for line in alert["payload"]["changes"]] == ["finding.opened"]
    assert runs.worker().recover() == 0
    assert len(runs.notifications()) == 1
