"""InventoryService against the real PostgreSQL repositories (row-level security on).

Each run is its own `database.project(...)` transaction, as a worker job would be.
"""
from datetime import datetime, timezone
from uuid import UUID

import pytest

from inventory_support import FixtureResolver, StepClock
from test_inventory_service import fixture_names
from watchtower.adapters.discovery.dns import DnsCollector
from watchtower.domain.models import AssetKind, NewJob, ObservationKind
from watchtower.domain.scope import NewScopeRevision, RuleEffect, ScopeRule
from watchtower.domain.targets import PortSet
from watchtower.persistence import Database
from watchtower.services.inventory import DiscoveredName, InventoryService
from watchtower.services.scope import ScopeService

pytestmark = pytest.mark.postgres

HOSTNAMES = ["api.example.com", "legacy.dev.example.com", "mail.example.com", "vpn.example.com", "www.example.com"]


@pytest.fixture
def policy(database: Database, project_id: UUID, authorization):
    rules = (
        ScopeRule.parse("example.com"),
        ScopeRule.parse("*.example.com"),
        ScopeRule.parse("mail.example.com", effect=RuleEffect.EXCLUDE),
    )
    with database.project(project_id) as uow:
        uow.scope.publish(NewScopeRevision(rules, authorization, PortSet.parse("80,443")), created_by=None)
    return ScopeService(database).current_policy(project_id)


def enqueue_job(database, project_id, policy) -> UUID:
    with database.project(project_id) as uow:
        job, _ = uow.jobs.enqueue(NewJob(kind="inventory", scope_revision_id=policy.revision_id))
        return job.id


def run(database, project_id, policy, *, job_id=None, clock=None, resolver=None, names=None):
    """One inventory job; observations reference a real job row (foreign key)."""
    job_id = job_id or enqueue_job(database, project_id, policy)
    clock = clock or StepClock()
    with database.project(project_id) as uow:
        inventory = InventoryService(uow, policy=policy, job_id=job_id, clock=clock)
        stats = inventory.ingest(fixture_names() if names is None else names)
        collector = DnsCollector(policy, resolver or FixtureResolver(), clock=clock)
        inventory.ingest_dns(collector.collect([a.value for a in inventory.assets()], root_domain="example.com"))
        return stats


def snapshot(database, project_id):
    with database.project(project_id) as uow:
        assets = {a.value: a for a in uow.assets.list(kind=AssetKind.HOSTNAME)}
        observations = {value: list(uow.observations.list_for_asset(a.id, limit=1000)) for value, a in assets.items()}
        return assets, observations


def test_repeated_runs_keep_identity_and_provenance(database, project_id, policy):
    first_stats = run(database, project_id, policy, clock=StepClock())
    before, observations_before = snapshot(database, project_id)
    second_stats = run(database, project_id, policy, clock=StepClock(start=datetime(2026, 10, 31, tzinfo=timezone.utc)))
    after, observations_after = snapshot(database, project_id)

    assert sorted(after) == HOSTNAMES
    assert (first_stats.created, second_stats.created) == (5, 0)
    for value, asset in after.items():
        assert asset.id == before[value].id
        assert asset.first_seen_at == before[value].first_seen_at
        assert asset.last_seen_at > before[value].last_seen_at
        provenance = asset.attributes["provenance"]
        assert set(provenance) == set(before[value].attributes["provenance"])
        for source, entry in provenance.items():
            assert entry["first_seen"] == before[value].attributes["provenance"][source]["first_seen"]
            assert entry["times_seen"] == 2
        # Append-only: every earlier observation is still there, unchanged.
        earlier = {o.id: o for o in observations_before[value]}
        later = {o.id: o for o in observations_after[value]}
        assert all(later[i] == o for i, o in earlier.items())
        assert len(later) == 2 * len(earlier)

    www = after["www.example.com"]
    assert www.first_seen_at == datetime(2026, 10, 1, tzinfo=timezone.utc)  # CSV discovered_at
    assert www.attributes["provenance"]["csv"]["first_seen"] == "2026-10-01T00:00:00Z"
    assert www.attributes["ownership_confidence"] == 0.95
    assert www.attributes["authorization"]["status"] == "authorized"
    assert www.scope_revision_id == policy.revision_id
    assert after["mail.example.com"].attributes["authorization"]["reason"] == "excluded"
    assert after["api.example.com"].attributes["provenance"]["subfinder"]["detail"]["upstream_sources"] == ["crtsh", "virustotal"]


def test_job_retry_does_not_duplicate_observations_or_sightings(database, project_id, policy):
    job = enqueue_job(database, project_id, policy)
    names = fixture_names()
    run(database, project_id, policy, job_id=job, clock=StepClock(), names=names)
    before, observations_before = snapshot(database, project_id)
    run(database, project_id, policy, job_id=job, clock=StepClock(), names=names)
    after, observations_after = snapshot(database, project_id)

    assert {v: a.id for v, a in after.items()} == {v: a.id for v, a in before.items()}
    for value in after:
        assert [o.id for o in observations_after[value]] == [o.id for o in observations_before[value]]
        assert all(o.job_id == job and o.source_ref for o in observations_after[value])
        for entry in after[value].attributes["provenance"].values():
            assert entry["times_seen"] == 1


def test_ip_change_updates_the_same_asset_and_keeps_history(database, project_id, policy):
    names = [DiscoveredName("www.example.com", "manual", "example.com")]
    resolver = FixtureResolver()
    run(database, project_id, policy, names=names, resolver=resolver)
    resolver.records["www.example.com"] = {"A": ["198.51.100.11"], "AAAA": ["2001:db8::10"]}
    run(database, project_id, policy, names=names, resolver=resolver,
        clock=StepClock(start=datetime(2026, 10, 31, tzinfo=timezone.utc)))
    del resolver.records["www.example.com"]
    run(database, project_id, policy, names=names, resolver=resolver,
        clock=StepClock(start=datetime(2026, 11, 1, tzinfo=timezone.utc)))

    assets, _ = snapshot(database, project_id)
    assert list(assets) == ["www.example.com"]
    asset = assets["www.example.com"]
    assert asset.attributes["addresses"] == ["198.51.100.11", "2001:db8::10"]  # NXDOMAIN keeps the last answer
    assert asset.attributes["dns_status"] == "nxdomain"
    with database.project(project_id) as uow:
        dns = list(reversed(uow.observations.list_for_asset(asset.id, kind=ObservationKind.DNS_RESOLUTION)))
    assert [o.data["status"] for o in dns] == ["resolved", "resolved", "nxdomain"]
    assert [o.data["a"] for o in dns[:2]] == [["198.51.100.10"], ["198.51.100.11"]]
    assert [o.data["address_changed"] for o in dns[:2]] == [False, True]
    assert dns[1].data["previous_addresses"] == ["198.51.100.10", "2001:db8::10"]
