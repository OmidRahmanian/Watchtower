"""Blueprint investigation features on real project-isolated PostgreSQL records."""
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from uuid import uuid4

import pytest

from api_support import START, seed_finding
from test_findings import EXPOSED, Scanner
from watchtower.config.settings import Settings
from watchtower.domain.models import AssetKind, NewObservation, ObservationKind, NewPhaseSnapshot, RunPhase, PhaseStatus, PhaseComparison
from watchtower.adapters.intelligence import AdvisoryFeed
from watchtower.services.intelligence import IntelligenceService

pytestmark = pytest.mark.postgres


def test_asset_metadata_filters_and_project_isolation(client, database, project_id, other_project_id, owner, viewer):
    with database.project(project_id) as uow:
        asset, _ = uow.assets.upsert(AssetKind.HOSTNAME, "www.example.com", attributes={"last_http": {"headers": {"server": "nginx/1.0"}}})
    path = f"/api/v1/projects/{project_id}"
    changed = client.patch(f"{path}/assets/{asset.id}", headers=owner.headers,
                           json={"owner": "Security", "tags": ["edge", "edge"], "importance": "critical"})
    assert changed.status_code == 200 and changed.json()["attributes"]["tags"] == ["edge"]
    rows = client.get(f"{path}/assets?owner=Security&tag=edge&technology=nginx", headers=owner.headers).json()
    assert [a["id"] for a in rows["items"]] == [str(asset.id)]
    assert client.get(f"{path}/assets?owner=Other", headers=owner.headers).json()["items"] == []
    assert client.patch(f"{path}/assets/{asset.id}", headers=viewer.headers, json={"owner": "Other"}).status_code == 403
    assert client.patch(f"/api/v1/projects/{other_project_id}/assets/{asset.id}", headers=owner.headers, json={"owner": "Other"}).status_code == 404
    assert client.patch(f"{path}/assets/{asset.id}", headers=owner.headers, json={"authorization": "approved"}).status_code == 422


def test_scope_execution_restrictions_are_persisted_and_checked_without_network(client, project_id, owner):
    path = f"/api/v1/projects/{project_id}/scope"
    payload = {"includes": ["example.com"], "attest_authorized": True,
               "authorization": {"kind": "asset_owner", "reference": "owned fixture", "granted_by": "Owner"},
               "execution_policy": {"allowed_paths": ["/api"], "excluded_paths": ["/api/private"],
                                    "allowed_schemes": ["https"], "allowed_check_kinds": ["http"], "max_requests_per_run": 20}}
    result = client.post(path, headers=owner.headers, json=payload)
    assert result.status_code == 201 and result.json()["execution_policy"]["max_requests_per_run"] == 20
    for url, allowed in [("https://example.com/api", True), ("https://example.com/api/private", False),
                         ("http://example.com/api", False), ("https://example.com/api/%252e%252e/private", False)]:
        checked = client.post(path + "/check", headers=owner.headers, json={"target": url})
        assert checked.status_code == 200 and checked.json()["allowed"] is allowed


def test_timeline_pages_without_leaking_other_assets(client, database, project_id, owner):
    with database.project(project_id) as uow:
        asset, _ = uow.assets.upsert(AssetKind.HOSTNAME, "timeline.example.com")
        for i in range(3):
            uow.observations.record(NewObservation(asset_id=asset.id, kind=ObservationKind.DISCOVERY, source="manual",
                                                  data={"index": i}, observed_at=START + timedelta(seconds=i)))
    path = f"/api/v1/projects/{project_id}/assets/{asset.id}/timeline"
    first = client.get(path + "?limit=2", headers=owner.headers)
    assert first.status_code == 200
    data = first.json()
    assert [r["data"]["index"] for r in data["items"]] == [2, 1]
    page = client.get(path, params={"limit": 2, "cursor": data["next_cursor"]}, headers=owner.headers).json()
    assert [r["data"]["index"] for r in page["items"]] == [0]


def test_exports_are_paginated_and_escape_spreadsheet_formulas(client, database, project_id, owner):
    with database.project(project_id) as uow:
        for name in ("a.example.com", "b.example.com"):
            uow.assets.upsert(AssetKind.HOSTNAME, name, attributes={"owner": " =HYPERLINK(1)"})
    path = f"/api/v1/projects/{project_id}/exports"
    first = client.get(path, params={"limit": 1, "format": "csv"}, headers=owner.headers)
    assert first.status_code == 200 and "' =HYPERLINK" in first.text
    assert "attachment" in first.headers["content-disposition"] and first.headers.get("X-Next-Cursor")
    second = client.get(path, params={"limit": 1, "cursor": first.headers["X-Next-Cursor"]}, headers=owner.headers).json()
    assert second["items"][0]["value"] == "b.example.com" and second["next_cursor"] is None
    assert client.get(path).status_code == 401


def test_owner_notes_priority_and_in_progress_do_not_change_detection(client, database, project_id, owner):
    finding = seed_finding(database, project_id, Scanner(), EXPOSED, START)
    path = f"/api/v1/projects/{project_id}/findings/{finding.id}"
    updated = client.patch(path, headers=owner.headers, json={"owner": "App Team", "remediation_notes": "Upgrade",
                            "mitigation_notes": "Temporary firewall", "priority": "P2", "reason": "Important asset"})
    assert updated.status_code == 200
    data = updated.json()
    assert data["owner"] == "App Team" and data["priority_override"]["level"] == "P2"
    assert data["detection"]["state"] == "present" and data["status"] == "open"
    state = client.post(path + "/status", headers=owner.headers, json={"status": "in_progress"})
    assert state.status_code == 200 and state.json()["status"] == "in_progress"
    assert client.patch(path, headers=owner.headers, json={"priority": "P1"}).status_code == 409
    assert client.post(path + "/status", headers=owner.headers, json={"status": "resolved"}).status_code == 409
    filtered = client.get(f"/api/v1/projects/{project_id}/findings?owner=App%20Team&priority=P2", headers=owner.headers).json()
    assert [f["id"] for f in filtered["items"]] == [str(finding.id)]


def test_changes_acknowledgement_is_project_scoped_and_audited(client, database, project_id, owner, viewer):
    with database.project(project_id) as uow:
        snapshot, _ = uow.phase_snapshots.record(NewPhaseSnapshot(run_id=uuid4(), target="example.com", phase=RunPhase.HTTP,
            status=PhaseStatus.COMPLETED, comparison=PhaseComparison.CHANGED,
            changes={"modified": [{"key": "https://example.com", "before": {"status": 403}, "after": {"status": 200}}]}))
    path = f"/api/v1/projects/{project_id}/changes"
    rows = client.get(path, headers=owner.headers).json()["items"]
    assert str(snapshot.id) in [r["id"] for r in rows]
    assert client.post(f"{path}/{snapshot.id}/acknowledge", headers=viewer.headers, json={"reason": "Reviewed"}).status_code == 403
    assert client.post(f"{path}/{snapshot.id}/acknowledge", headers=owner.headers, json={"reason": "Expected deployment"}).status_code == 200
    data = client.get(path, headers=owner.headers).json()
    item = next(r for r in data["items"] if r["id"] == str(snapshot.id))
    assert item["acknowledgement"]["reason"] == "Expected deployment"


def test_intelligence_preserves_unknown_applicability_and_settings_hide_secrets(client, database, project_id, owner, tmp_path):
    settings = Settings.model_validate({"database": {"url": "postgresql://user:secret@db/database"},
                                       "intelligence": {"cache_root": str(tmp_path)}})
    service = IntelligenceService(settings)
    raw = Path(__file__).resolve().parents[1].joinpath("fixtures/advisories.json").read_bytes()
    report = service.store.refresh(AdvisoryFeed("fixtures", lambda _: raw))
    assert report.updated
    with database.project(project_id) as uow:
        uow.assets.upsert(AssetKind.HOSTNAME, "advisory.example.com", attributes={"last_http": {"headers": {"server": "Apache"}}})
    client.app.state.services.settings = settings
    path = f"/api/v1/projects/{project_id}"
    data = client.get(path + "/intelligence", headers=owner.headers).json()
    assert any(r["applicability"] == "unknown" for r in data["items"])
    assert all(r["action"] == "applicability_review" for r in data["items"])
    settings_response = client.get(path + "/settings", headers=owner.headers)
    assert settings_response.status_code == 200 and "secret" not in settings_response.text
