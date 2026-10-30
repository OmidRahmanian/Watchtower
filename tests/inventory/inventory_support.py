"""Test doubles for inventory tests: scope policies, a fixture resolver and in-memory repositories."""
import json
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urljoin, urlsplit
from uuid import uuid4

from watchtower.adapters.discovery.dns import NoAnswer, NXDomain
from watchtower.domain.models import Asset, Observation
from watchtower.domain.scope import (
    AuthorizationReference,
    RuleEffect,
    ScopePolicy,
    ScopeRevision,
    ScopeRule,
)
from watchtower.domain.targets import PortSet, canonical_hostname
from watchtower.services.inventory import in_domain

FIXTURES = Path(__file__).resolve().parent / "fixtures"
PROJECT_ID = uuid4()


def scope_policy(*, include=("example.com", "*.example.com"), exclude=(), ports="80,443", clock=None):
    """A real ScopePolicy, as ScopeService.current_policy would return it."""
    rules = tuple(ScopeRule.parse(p) for p in include) + tuple(ScopeRule.parse(p, effect=RuleEffect.EXCLUDE) for p in exclude)
    revision = ScopeRevision(
        id=uuid4(), project_id=PROJECT_ID, number=1, rules=rules,
        authorization=AuthorizationReference("asset_owner", "test-authorization", "tests"),
        permitted_ports=PortSet.parse(ports), created_at=datetime.now(timezone.utc),
    )
    return ScopePolicy(PROJECT_ID, revision, **({"clock": clock} if clock else {}))


def deny_all_policy():
    """A project without a scope revision: ScopePolicy denies everything."""
    return ScopePolicy(PROJECT_ID, None)


@dataclass(frozen=True)
class FakeDecision:
    allowed: bool
    reason: str = ""
    detail: str = ""
    url: str = None

    def __bool__(self):
        return self.allowed


class FakeScope:
    """ScopePolicy-shaped double for tests whose servers live on loopback.

    The real policy always prohibits loopback, so live-traffic tests use this
    and record every call the adapter makes.
    """

    def __init__(self, domains=("example.com",), destinations=None, excluded=()):
        self.domains = tuple(domains)
        # None allows any destination; otherwise a set of (ip, port) pairs.
        self.destinations = destinations
        self.excluded = set(excluded)
        self.calls = []

    def _in_scope(self, host):
        host = (host or "").lower().rstrip(".")
        return host not in self.excluded and any(in_domain(host, root) for root in self.domains)

    def check_target(self, target, *, port=None):
        self.calls.append(("target", target, port))
        allowed = self._in_scope(target)
        return FakeDecision(allowed, "" if allowed else "not_in_scope", target)

    def check_connection(self, host, port, resolved_addresses):
        addresses = list(resolved_addresses)
        self.calls.append(("connection", host, port, tuple(addresses)))
        if not addresses or not self._in_scope(host):
            return FakeDecision(False, "not_in_scope", host)
        if self.destinations is not None and any((ip, port) not in self.destinations for ip in addresses):
            return FakeDecision(False, "prohibited_destination", f"{addresses}:{port}")
        return FakeDecision(True)

    def check_redirect(self, current_url, location, *, redirects_followed):
        self.calls.append(("redirect", current_url, location, redirects_followed))
        url = urljoin(current_url, location)
        if not self._in_scope(urlsplit(url).hostname):
            return FakeDecision(False, "not_in_scope", url)
        return FakeDecision(True, url=url)


class FixtureResolver:
    """Answers from dns_zone.json, including wildcard zones."""

    def __init__(self, records=None, wildcards=None):
        zone = json.loads((FIXTURES / "dns_zone.json").read_text())
        self.records = dict(zone["records"] if records is None else records)
        self.wildcards = zone["wildcards"] if wildcards is None else wildcards
        self.queries = []

    def query(self, name, rdtype):
        self.queries.append((name, rdtype))
        entry = self.records.get(name)
        if entry is None:
            entry = self.wildcards.get(name.partition(".")[2])
        if entry is None:
            raise NXDomain(name)
        if rdtype not in entry:
            raise NoAnswer(name)
        return list(entry[rdtype])


class StepClock:
    def __init__(self, start=datetime(2026, 10, 30, tzinfo=timezone.utc), step=timedelta(minutes=1)):
        self.now, self.step = start, step

    def __call__(self):
        self.now += self.step
        return self.now


class MemoryAssets:
    """AssetRepository semantics: identity is (kind, value); attributes merge by top-level key."""

    def __init__(self, project_id):
        self.project_id = project_id
        self.rows = {}

    def upsert(self, kind, value, *, seen_at=None, attributes=None, scope_revision_id=None):
        if kind == "hostname" and canonical_hostname(value) != value:
            raise ValueError(f"non-canonical hostname {value!r}")
        seen_at = seen_at or datetime.now(timezone.utc)
        existing = self.rows.get((kind, value))
        if existing is None:
            asset = Asset(uuid4(), self.project_id, kind, value, seen_at, seen_at, dict(attributes or {}), scope_revision_id)
            self.rows[(kind, value)] = asset
            return asset, True
        asset = replace(
            existing,
            last_seen_at=max(existing.last_seen_at, seen_at),
            attributes={**existing.attributes, **(attributes or {})},
            scope_revision_id=scope_revision_id or existing.scope_revision_id,
        )
        self.rows[(kind, value)] = asset
        return asset, False

    def get(self, asset_id):
        return next((a for a in self.rows.values() if a.id == asset_id), None)

    def find(self, kind, value):
        return self.rows.get((kind, value))

    def list(self, *, kind=None, limit=100, after_value=None):
        rows = sorted((a for a in self.rows.values() if kind is None or a.kind == kind), key=lambda a: (a.kind, a.value))
        if after_value is not None:
            rows = [a for a in rows if a.value > after_value]
        return rows[:limit]


class MemoryObservations:
    """ObservationRepository semantics: append-only, idempotent on source_ref."""

    def __init__(self, project_id):
        self.project_id = project_id
        self.rows = []

    def record(self, new):
        if new.source_ref is not None:
            for row in self.rows:
                if row.source_ref == new.source_ref:
                    return row, False
        now = datetime.now(timezone.utc)
        row = Observation(uuid4(), self.project_id, new.asset_id, new.kind, new.source, json.loads(json.dumps(new.data)),
                          new.observed_at or now, now, new.job_id, new.scope_revision_id, new.source_ref)
        self.rows.append(row)
        return row, True

    def latest(self, asset_id, kind):
        rows = self.list_for_asset(asset_id, kind=kind, limit=1)
        return rows[0] if rows else None

    def list_for_asset(self, asset_id, *, kind=None, limit=100):
        rows = [r for r in self.rows if r.asset_id == asset_id and (kind is None or r.kind == kind)]
        return list(reversed(rows))[:limit]


class MemoryUnitOfWork:
    def __init__(self, project_id=PROJECT_ID):
        self.project_id = project_id
        self.assets = MemoryAssets(project_id)
        self.observations = MemoryObservations(project_id)

    def history(self, asset, kind=None):
        """Observations for an asset, oldest first."""
        return list(reversed(self.observations.list_for_asset(asset.id, kind=kind, limit=10_000)))
