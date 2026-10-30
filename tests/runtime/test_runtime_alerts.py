"""Acceptance: one intended change produces one useful alert; unchanged reruns produce none.

Every run here is the real pipeline (RunService → Worker → Notifier) against
PostgreSQL with row-level security, with the outside world faked by ``Lab``.
"""
import pytest

from runtime_support import PUBLIC_IP
from watchtower.domain.models import PhaseComparison, PhaseStatus, RunPhase

pytestmark = pytest.mark.postgres


def comparisons(detail):
    return {(p.phase.value, p.target): p.comparison.value for p in detail.summary.phases}


def test_baseline_is_silent_and_unchanged_reruns_alert_nobody(runs):
    first = runs.run()
    assert first.summary.status == "succeeded"
    assert set(comparisons(first).values()) == {"baseline"}
    for _ in range(3):
        again = runs.run()
        assert again.summary.status == "succeeded"
        assert set(comparisons(again).values()) == {"unchanged"}
    assert runs.alerts() == []
    assert runs.notifications() == []


def test_a_new_host_is_one_alert_with_one_line(runs, lab):
    runs.run()
    lab.seeds.append("api.example.com")
    lab.dns["api.example.com"] = {"A": [PUBLIC_IP]}
    lab.http[("https", "api.example.com")] = (200, "API")

    changed = runs.run()
    assert comparisons(changed)[("discovery", "example.com")] == "changed"
    assert len(runs.alerts()) == 1
    alert = runs.alerts()[0]
    assert alert["event_type"] == "monitor.changes"
    # Its first DNS answer and HTTP response belong to discovering it: no extra lines.
    assert [(c["type"], c["key"]) for c in alert["payload"]["changes"]] == [("asset.discovered", "api.example.com")]
    assert alert["summary"].startswith("WatchTower: 1 change on example.com")

    for _ in range(2):
        runs.run()
    assert len(runs.alerts()) == 1
    assert len(runs.notifications()) == 1


def test_a_modified_response_alerts_once_after_confirmation(runs, lab):
    runs.run()
    lab.http[("https", "shop.example.com")] = (503, "Maintenance")

    pending = runs.run()
    # Seen once: held for confirmation, reported as uncertain, nobody alerted yet.
    assert comparisons(pending)[("http", "example.com")] == "uncertain"
    assert runs.alerts() == []

    confirmed = runs.run()
    assert comparisons(confirmed)[("http", "example.com")] == "changed"
    [alert] = runs.alerts()
    [line] = alert["payload"]["changes"]
    assert line["type"] == "http.changed" and line["key"] == "https://shop.example.com"
    assert (line["before"]["status_code"], line["after"]["status_code"]) == (200, 503)
    assert "status_code 200 → 503" in alert["lines"][0]

    runs.run()
    runs.run()
    assert len(runs.alerts()) == 1


def test_a_flapping_value_is_debounced_away(runs, lab):
    runs.run()
    lab.http[("https", "shop.example.com")] = (502, "Bad gateway")
    runs.run()
    lab.http[("https", "shop.example.com")] = (200, "Shop")
    settled = runs.run()
    assert comparisons(settled)[("http", "example.com")] == "unchanged"
    runs.run()
    assert runs.alerts() == []


def test_unobservable_items_are_uncertain_never_removed(runs, lab):
    runs.run()
    lab.dns_failures.add("shop.example.com")  # www still answers, so the scan is real but has a gap
    for _ in range(3):  # longer than the confirmation window
        flaky = runs.run()
        assert comparisons(flaky)[("dns", "example.com")] == "uncertain"
        assert comparisons(flaky)[("http", "example.com")] == "uncertain"
        assert flaky.summary.status == "partial"
    assert runs.alerts() == []

    lab.dns_failures.clear()
    recovered = runs.run()
    assert set(comparisons(recovered).values()) == {"unchanged"}
    assert runs.alerts() == []


def test_a_scan_that_observes_nothing_is_failed_not_partial(runs, lab):
    """Every host unreachable: a failed scan, alerted as such, that never reads as removals."""
    runs.run()
    lab.http = {key: "timeout" for key in lab.http}
    down = runs.run()
    [http] = [s for s in down.snapshots if s.phase is RunPhase.HTTP]
    assert (http.status, http.comparison) == (PhaseStatus.FAILED, PhaseComparison.FAILED)
    assert http.stats["failure"] == "nothing could be observed"
    assert down.summary.status == "failed"
    [alert] = runs.alerts()
    assert alert["event_type"] == "monitor.run_failed"
    assert alert["payload"]["failed_jobs"] == [
        {"kind": "monitor.http", "target": "example.com", "error": "nothing could be observed"}]

    lab.dns_failures |= {"www.example.com", "shop.example.com"}  # DNS gone too
    assert runs.run().summary.status == "failed"

    lab.dns_failures.clear()
    lab.http = {("https", "www.example.com"): (200, "Example"), ("https", "shop.example.com"): (200, "Shop")}
    back = runs.run()
    # Compared with the last good scan: nothing was removed, nothing is rediscovered.
    assert set(comparisons(back).values()) == {"unchanged"} and back.summary.status == "succeeded"
    assert [a["event_type"] for a in runs.alerts()] == ["monitor.run_failed", "monitor.run_failed"]


def test_checks_that_all_fail_are_a_failed_scan(runs, lab):
    runs.run()

    def broken(method, url, ip):
        raise ConnectionResetError("reset by peer")

    runs.lab.fetch = broken
    detail = runs.run()
    [checks] = [s for s in detail.snapshots if s.phase is RunPhase.CHECKS]
    assert checks.status is PhaseStatus.FAILED and detail.summary.status == "failed"
    assert [a["event_type"] for a in runs.alerts()] == ["monitor.run_failed"]


def test_a_dns_change_alerts_once(runs, lab):
    runs.run()
    lab.dns["www.example.com"] = {"A": ["93.184.216.35"]}
    runs.run()
    runs.run()
    runs.run()
    [alert] = runs.alerts()
    [line] = alert["payload"]["changes"]
    assert line["type"] == "dns.changed"
    assert line["before"]["a"] == [PUBLIC_IP] and line["after"]["a"] == ["93.184.216.35"]


def test_a_new_finding_is_one_alert_with_persisted_evidence(runs, lab, database, project_id):
    runs.run()
    lab.exposed.add("shop.example.com")
    runs.run()
    [alert] = runs.alerts()
    [line] = alert["payload"]["changes"]
    assert line["type"] == "finding.opened"
    assert line["after"]["host"] == "shop.example.com" and line["after"]["check_id"] == "exposed-git-config"

    runs.run()
    runs.run()
    assert len(runs.alerts()) == 1
    with database.project(project_id) as uow:
        [finding] = uow.findings.list()
        evidence = uow.evidence.list_for_finding(finding.id)
    assert finding.fingerprint == line["key"]
    assert evidence and all(e.finding_id == finding.id for e in evidence)


def test_pending_rules_are_not_run_and_never_resolve_anything(runs, lab, database, project_id):
    runs.run()
    lab.exposed.add("shop.example.com")
    runs.run()  # with the approved test ruleset: the finding is opened and alerted
    lab.exposed.clear()
    lab.approved = False  # the shipped manifest: every rule is pending maintainer approval
    fetches = len(lab.fetches)
    detail = runs.run()
    assert len(lab.fetches) == fetches  # nothing was sent
    [checks] = [s for s in detail.snapshots if s.phase is RunPhase.CHECKS]
    assert checks.status is PhaseStatus.PARTIAL and checks.comparison is PhaseComparison.PARTIAL
    assert "exposed-git-config" in checks.stats["not_run"]
    assert detail.summary.status == "partial"
    with database.project(project_id) as uow:
        [finding] = uow.findings.list()
    assert finding.status.value == "open"
    assert len(runs.alerts()) == 1  # only the original finding.opened
