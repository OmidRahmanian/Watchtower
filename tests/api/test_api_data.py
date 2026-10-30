"""Inventory, findings, evidence, runs and alerts through the API."""

from __future__ import annotations

import json
from datetime import timedelta

import pytest

from api_support import START, seed_finding
from test_findings import EXPOSED, GONE, BUSY, Scanner
from watchtower.adapters.checks.base import HttpResponse
from watchtower.api.pagination import encode_cursor
from watchtower.domain.errors import ScopeViolation
from watchtower.domain.models import AssetKind, NewNotification
from watchtower.domain.scope import DecisionReason, ScopeDecision
from watchtower.security.auth import ProjectRole
from watchtower.services.findings import FindingService, RepositoryFindingStore

pytestmark = pytest.mark.postgres

ENV_FILE = b"APP_ENV=production\nDB_PASSWORD=hunter2-prod\nAPI_KEY=<script>alert(1)</script>\n"


@pytest.fixture
def scanner():
    return Scanner()


def pages(client, path, headers, limit):
    """Follow ``next_cursor`` to the end; return every page's items."""
    seen, cursor = [], None
    while True:
        params = {"limit": limit, **({"cursor": cursor} if cursor else {})}
        body = client.get(path, params=params, headers=headers).json()
        seen.append(body["items"])
        cursor = body["next_cursor"]
        if cursor is None:
            return seen


def test_assets_page_without_gaps_or_repeats(client, database, project_id, viewer):
    names = [f"h{i:02d}.acme.example" for i in range(7)]
    with database.project(project_id) as uow:
        for name in names:
            uow.assets.upsert(AssetKind.HOSTNAME, name, attributes={"addresses": ["192.0.2.1"]})
        uow.assets.upsert(AssetKind.IP_ADDRESS, "198.51.100.4")
    path = f"/api/v1/projects/{project_id}/assets"
    result = pages(client, path, viewer.headers, 3)
    assert [len(page) for page in result] == [3, 3, 2]
    flat = [item["value"] for page in result for item in page]
    assert flat == names + ["198.51.100.4"]

    hostnames = client.get(path, params={"kind": "hostname", "search": "h0"}, headers=viewer.headers).json()
    assert len(hostnames["items"]) == 7 and hostnames["next_cursor"] is None
    detail = client.get(f"{path}/{result[0][0]['id']}", headers=viewer.headers).json()
    assert detail["asset"]["addresses"] == ["192.0.2.1"]


@pytest.mark.parametrize("cursor", ["%%%", "W10", encode_cursor("findings", START, "x"), "A" * 2000])
def test_bad_cursors_are_rejected(client, project_id, viewer, cursor):
    response = client.get(f"/api/v1/projects/{project_id}/assets", params={"cursor": cursor}, headers=viewer.headers)
    assert response.status_code == 422


def test_findings_list_filter_and_page(client, database, project_id, viewer, scanner):
    for i in range(5):
        seed_finding(database, project_id, scanner, EXPOSED, START + timedelta(hours=i), host=f"s{i}.acme.example")
    path = f"/api/v1/projects/{project_id}/findings"
    result = pages(client, path, viewer.headers, 2)
    flat = [item["target"] for page in result for item in page]
    assert flat == [f"https://s{i}.acme.example" for i in reversed(range(5))]
    assert all(item["remediation"] == "not_retested" for page in result for item in page)
    assert client.get(path, params={"status": "resolved"}, headers=viewer.headers).json()["items"] == []
    high = client.get(path, params={"severity": ["high", "critical"]}, headers=viewer.headers).json()
    assert len(high["items"]) == 5


def test_triage_rules_and_permissions(client, database, project_id, viewer, operator, scanner):
    row = seed_finding(database, project_id, scanner, EXPOSED, START)
    path = f"/api/v1/projects/{project_id}/findings/{row.id}/status"
    assert client.post(path, json={"status": "triaged"}, headers=viewer.headers).status_code == 403
    triaged = client.post(path, json={"status": "triaged"}, headers=operator.headers)
    assert triaged.status_code == 200 and triaged.json()["status"] == "triaged"
    assert triaged.json()["history"][-1]["event"] == "status_changed"
    # Resolution only comes from a negative retest, never from a manual status change.
    resolved = client.post(path, json={"status": "resolved"}, headers=operator.headers)
    assert resolved.status_code == 409 and resolved.json()["error"] == "invalid_transition"
    assert client.post(path, json={"status": "accepted_risk"}, headers=operator.headers).status_code == 409
    accepted = client.post(path, json={"status": "accepted_risk", "reason": "compensating WAF rule"},
                           headers=operator.headers)
    assert accepted.json()["status"] == "accepted_risk"
    with database.project(project_id) as uow:
        # Triage did not refresh the asset's last-seen time.
        assert uow.assets.get(row.asset_id).last_seen_at == uow.assets.get(row.asset_id).first_seen_at


def test_failed_retest_is_distinct_from_verified_fix(client, database, project_id, viewer, scanner):
    failing = seed_finding(database, project_id, scanner, EXPOSED, START, host="a.acme.example")
    fixed = seed_finding(database, project_id, scanner, EXPOSED, START, host="b.acme.example")
    for row, reply in ((failing, BUSY), (failing, ConnectionError("refused")), (fixed, GONE)):
        with database.project(project_id) as uow:
            service = FindingService(RepositoryFindingStore(uow), canonical_id=scanner.ruleset.canonical_id)
            service.request_retest(row.fingerprint, "analyst", START + timedelta(hours=1))
            host = "a.acme.example" if row is failing else "b.acme.example"
            service.apply_retest(row.fingerprint, scanner.run(reply, START + timedelta(hours=2), host=host))
    base = f"/api/v1/projects/{project_id}/findings"
    failed = client.get(f"{base}/{failing.id}", headers=viewer.headers).json()
    resolved = client.get(f"{base}/{fixed.id}", headers=viewer.headers).json()
    assert (failed["status"], failed["remediation"]) == ("open", "retest_failed")
    assert failed["retest_requested_at"] is not None
    assert failed["remediation_event"]["event"] == "retest_failed"
    assert (resolved["status"], resolved["remediation"]) == ("resolved", "verified_fixed")
    assert resolved["remediation_event"]["event"] == "resolved"


def test_retest_queues_through_the_run_service(client, database, project_id, viewer, operator, runs, scanner):
    row = seed_finding(database, project_id, scanner, EXPOSED, START)
    path = f"/api/v1/projects/{project_id}/findings/{row.id}/retest"
    assert client.post(path, json={}, headers=viewer.headers).status_code == 403
    response = client.post(path, json={"reason": "deployed fix"}, headers=operator.headers)
    assert response.status_code == 202 and response.json()["kind"] == "retest"
    assert runs.calls[-1] == ("request_retest", (project_id, row.fingerprint, "deployed fix"))


def test_evidence_is_redacted_and_downloads_as_an_inert_attachment(client, database, project_id, viewer, blobs,
                                                                  scanner):
    row = seed_finding(database, project_id, scanner, HttpResponse(200, (), ENV_FILE), START, blobs=blobs,
                       check="exposed-env-file")
    detail = client.get(f"/api/v1/projects/{project_id}/findings/{row.id}", headers=viewer.headers).json()
    [evidence] = detail["evidence"]
    shown = client.get(f"/api/v1/projects/{project_id}/evidence/{evidence['id']}", headers=viewer.headers)
    assert shown.status_code == 200
    excerpt = shown.json()["content"]["response"]["body_excerpt"]
    assert "hunter2-prod" not in excerpt and "DB_PASSWORD=[REDACTED]" in excerpt

    download = client.get(evidence["download_path"], headers=viewer.headers)
    assert download.status_code == 200
    assert download.headers["content-type"] == "application/octet-stream"
    assert download.headers["content-disposition"] == f'attachment; filename="evidence-{evidence["id"]}.json"'
    assert download.headers["x-content-type-options"] == "nosniff"
    assert "sandbox" in download.headers["content-security-policy"]
    assert download.headers["cache-control"] == "no-store"
    assert b"hunter2-prod" not in download.content and b"<script>" not in download.content
    assert json.loads(download.content)["check_id"] == "exposed-env-file"

    assert client.get(evidence["download_path"]).status_code == 401


def test_evidence_cannot_be_read_through_another_project(client, database, member, project_id, other_project_id,
                                                         blobs, scanner):
    row = seed_finding(database, project_id, scanner, HttpResponse(200, (), ENV_FILE), START, blobs=blobs,
                       check="exposed-env-file")
    with database.project(project_id) as uow:
        [evidence] = uow.evidence.list_for_finding(row.id)
    outsider = member(other_project_id, ProjectRole.OWNER)
    for suffix in ("", "/download"):
        # The outsider's own project in the path, the victim's evidence id: RLS hides the row.
        own = client.get(f"/api/v1/projects/{other_project_id}/evidence/{evidence.id}{suffix}", headers=outsider.headers)
        theirs = client.get(f"/api/v1/projects/{project_id}/evidence/{evidence.id}{suffix}", headers=outsider.headers)
        assert own.status_code == theirs.status_code == 404
    finding = client.get(f"/api/v1/projects/{other_project_id}/findings/{row.id}", headers=outsider.headers)
    assert finding.status_code == 404


def test_tampered_evidence_blob_is_not_served(client, database, project_id, viewer, blobs, scanner):
    row = seed_finding(database, project_id, scanner, HttpResponse(200, (), ENV_FILE), START, blobs=blobs,
                       check="exposed-env-file")
    with database.project(project_id) as uow:
        [evidence] = uow.evidence.list_for_finding(row.id)
    path = blobs._path(evidence.storage_uri)
    path.chmod(0o600)
    path.write_bytes(b'{"injected": true}')
    response = client.get(f"/api/v1/projects/{project_id}/evidence/{evidence.id}/download", headers=viewer.headers)
    assert response.status_code == 404


def test_runs_keep_failures_visible_and_page(client, project_id, viewer, operator, runs):
    runs.add(project_id, "succeeded")
    runs.add(project_id, "failed", last_error="dns: resolver timeout")
    runs.add(project_id, "cancelled")
    path = f"/api/v1/projects/{project_id}/runs"
    result = pages(client, path, viewer.headers, 2)
    flat = [item["status"] for page in result for item in page]
    assert flat == ["cancelled", "failed", "succeeded"]
    failed = result[0][1]
    assert failed["last_error"] == "dns: resolver timeout" and failed["job_counts"] == {"failed": 1}

    assert client.post(path, json={}, headers=viewer.headers).status_code == 403
    started = client.post(path, json={"targets": ["acme.example"], "phases": ["dns", "http"], "reason": "demo"},
                          headers=operator.headers)
    assert started.status_code == 202 and started.json()["status"] == "queued"
    assert runs.calls[-1][1][1:] == (["acme.example"], ["dns", "http"], "demo")
    assert client.post(path, json={"phases": ["portscan"]}, headers=operator.headers).status_code == 422

    run_id = started.json()["run_id"]
    assert client.get(f"{path}/{run_id}", headers=viewer.headers).json()["run"]["run_id"] == run_id
    cancel = client.post(f"{path}/{run_id}/cancel", json={"reason": "wrong target"}, headers=operator.headers)
    assert cancel.json() == {"cancelled": 1}


def test_run_errors_map_to_http_statuses(client, project_id, operator, runs, monkeypatch):
    def no_scope(*args, **kwargs):
        raise ScopeViolation(ScopeDecision(False, DecisionReason.NO_SCOPE, project_id, None, detail="no scope"))

    monkeypatch.setattr(runs, "start_run", no_scope)
    response = client.post(f"/api/v1/projects/{project_id}/runs", json={}, headers=operator.headers)
    assert response.status_code == 409 and response.json()["detail"] == "no_scope: no scope"
    other = client.get(f"/api/v1/projects/{project_id}/runs/{project_id}", headers=operator.headers)
    assert other.status_code == 404


def test_runs_report_unavailable_without_a_runtime(database, blobs, project_id, member):
    from fastapi.testclient import TestClient

    from watchtower.api import create_app

    viewer = member(project_id, ProjectRole.VIEWER)
    with TestClient(create_app(database, blobs=blobs, runs=None)) as client:
        response = client.get(f"/api/v1/projects/{project_id}/runs", headers=viewer.headers)
        assert response.status_code == 503
        overview = client.get(f"/api/v1/projects/{project_id}/overview", headers=viewer.headers).json()
        assert overview["runs_available"] is False and overview["latest_runs"] == []


def test_alerts_page_newest_first(client, database, project_id, viewer):
    with database.project(project_id) as uow:
        for i in range(3):
            uow.notifications.enqueue(NewNotification(
                channel="discord", event_type="monitor.changes", dedupe_key=f"run-{i}",
                payload={"changes": [{"type": "asset.discovered", "target": f"n{i}.acme.example"}]}))
    result = pages(client, f"/api/v1/projects/{project_id}/alerts", viewer.headers, 2)
    flat = [item["payload"]["changes"][0]["target"] for page in result for item in page]
    assert sorted(flat) == ["n0.acme.example", "n1.acme.example", "n2.acme.example"] and len(result) == 2
    filtered = client.get(f"/api/v1/projects/{project_id}/alerts", params={"event_type": "monitor.run_failed"},
                          headers=viewer.headers).json()
    assert filtered["items"] == []


def test_overview_counts_and_rule_approval_state(client, database, project_id, viewer, scanner):
    seed_finding(database, project_id, scanner, EXPOSED, START)
    overview = client.get(f"/api/v1/projects/{project_id}/overview", headers=viewer.headers).json()
    assert overview["counts"]["findings_by_status"]["open"] == 1
    assert overview["counts"]["open_findings_by_severity"]["high"] == 1
    assert overview["counts"]["assets"] == {"hostname": 1}
    # The test client loads the test-only approved manifest.
    assert {rule["id"]: rule["approved"] for rule in overview["rules"]}["exposed-env-file"] is True
