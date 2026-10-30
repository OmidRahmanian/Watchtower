"""Importing the legacy MongoDB inventory."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest

from watchtower.domain.models import AssetKind, ObservationKind
from watchtower.domain.scope import AuthorizationKind, DecisionReason
from watchtower.persistence import Database
from watchtower.persistence.legacy_mongo import LegacyTarget, MongoImporter, load_legacy_targets
from watchtower.services.scope import ScopeService


class FakeCollection:
    def __init__(self, documents: list[dict[str, Any]]) -> None:
        self._documents = documents

    def find(self) -> list[dict[str, Any]]:
        return list(self._documents)


class FakeMongo:
    def __init__(self, databases: dict[str, dict[str, list[dict[str, Any]]]]) -> None:
        self._databases = databases

    def list_database_names(self) -> list[str]:
        return [*self._databases, "admin", "local"]

    def __getitem__(self, name: str) -> dict[str, FakeCollection]:
        collections = self._databases.get(name, {})
        return {key: FakeCollection(collections.get(key, [])) for key in ("all", "resolve", "httpx")}


def legacy_data(database_name: str, domain: str) -> FakeMongo:
    return FakeMongo(
        {
            database_name: {
                "all": [
                    {"_id": "a1", "subdomain": f"www.{domain}", "date": "2024/05/01", "provider": "Subfinder"},
                    {"_id": "a2", "subdomain": f"API.{domain}", "date": "2024/05/02", "provider": "crt"},
                    {"_id": "a3", "subdomain": f"mi.{domain}", "date": "2024/05/02", "provider": "Subfinder"},
                    {"_id": "a4", "subdomain": "evil.net", "date": "2024/05/02", "provider": "Subfinder"},
                    {"_id": "a5", "subdomain": "bad host", "date": "2024/05/02", "provider": "Subfinder"},
                ],
                "resolve": [{"_id": "r1", "subdomain": f"www.{domain}", "date": "2024/05/03", "resolver": "Static_Brute"}],
                "httpx": [
                    {
                        "_id": "h1",
                        "subdomain": f"www.{domain}",
                        "status_code": 200,
                        "title": "Home",
                        "tech": "nginx",
                        "bodymd5": "d41d8cd98f00b204e9800998ecf8427e",
                        "last_change": "2024/06/01",
                        "action": "New Service",
                    }
                ],
            },
            "orphan-example-org": {"all": []},
        }
    )


def test_targets_file_parses(tmp_path: Path) -> None:
    path = tmp_path / "targets.json"
    path.write_text(json.dumps({"Example.COM": {"report_url": "https://h1/x", "out_of_scope": ["mi.example.com"]}, "": {}}))
    assert load_legacy_targets(path) == [LegacyTarget("example.com", "https://h1/x", ("mi.example.com",))]


def test_colliding_legacy_database_names_are_rejected(tmp_path: Path) -> None:
    path = tmp_path / "targets.json"
    path.write_text(json.dumps({"a-b.com": {}, "a.b.com": {}}))
    with pytest.raises(ValueError, match="share legacy database"):
        load_legacy_targets(path)


def test_import_requires_attestation() -> None:
    with pytest.raises(ValueError, match="authorized_by"):
        MongoImporter(None, FakeMongo({}), authorized_by=" ")


def test_dry_run_needs_no_database() -> None:
    domain = f"t{uuid4().hex[:6]}.example.com"
    target = LegacyTarget(domain, "https://hackerone.com/x", (f"mi.{domain}",))
    report = MongoImporter(None, legacy_data(target.mongo_database, domain), authorized_by=None, dry_run=True).run([target])
    result = report.targets[0]
    assert (result.observations_created, result.out_of_scope, result.invalid) == (4, 2, 1)
    assert report.unmapped_databases == ["orphan-example-org"]


@pytest.mark.postgres
def test_import_is_scoped_and_idempotent(database: Database) -> None:
    domain = f"t{uuid4().hex[:6]}.example.com"
    target = LegacyTarget(domain, "https://hackerone.com/x", (f"mi.{domain}", "not a host"))
    mongo = legacy_data(target.mongo_database, domain)

    report = MongoImporter(database, mongo, authorized_by="Omid").run([target])
    result = report.targets[0]
    assert result.scope_created and result.scope_revision == 1
    assert (result.assets_created, result.observations_created) == (2, 4)
    assert (result.out_of_scope, result.invalid, result.duplicates) == (2, 1, 0)
    assert result.invalid_exclusions == ["not a host"]

    again = MongoImporter(database, mongo, authorized_by="Omid").run([target]).targets[0]
    assert not again.scope_created and again.project_id == result.project_id
    assert (again.assets_created, again.observations_created, again.duplicates) == (0, 0, 4)

    assert result.project_id is not None
    scope = ScopeService(database)
    policy = scope.current_policy(result.project_id)
    assert policy.revision is not None
    assert policy.revision.authorization.kind is AuthorizationKind.LEGACY_IMPORT
    assert policy.revision.authorization.granted_by == "Omid"
    assert policy.check_target(domain).allowed
    assert policy.check_target(f"mi.{domain}").reason is DecisionReason.EXCLUDED

    with database.project(result.project_id) as uow:
        www = uow.assets.find(AssetKind.HOSTNAME, f"www.{domain}")
        assert www is not None
        assert www.first_seen_at.date().isoformat() == "2024-05-01"
        http = uow.observations.latest(www.id, ObservationKind.HTTP_RESPONSE)
        assert http is not None and http.data["status_code"] == 200 and http.source == "httpx"
        assert uow.assets.find(AssetKind.HOSTNAME, f"mi.{domain}") is None
