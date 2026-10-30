"""A fake world for runtime tests: every outbound call is answered in-process.

``Lab`` holds what the "internet" currently looks like (seed hostnames, DNS
records, HTTP responses, check responses). Tests mutate it between runs to
make one intended change, then drive the real Worker and Notifier against
PostgreSQL.
"""
from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import uuid4

import pytest

from checks_support import approved_ruleset
from watchtower.adapters.checks import Authorization
from watchtower.adapters.checks.base import HttpResponse
from watchtower.adapters.discovery.dns import NXDomain, NoAnswer, DnsFailure
from watchtower.adapters.notifications import Response
from watchtower.config.settings import Settings
from watchtower.domain.scope import NewScopeRevision, ScopeRule
from watchtower.domain.targets import PortSet
from watchtower.security.auth import Principal, PrincipalKind, ProjectContext, ProjectRole
from watchtower.services.jobs import PipelineAdapters, RunService
from watchtower.services.scope import ScopeService
from watchtower.workers.runtime import Notifier, Worker

PUBLIC_IP = "93.184.216.34"
WEBHOOK = "https://hooks.example.net/watchtower/secret-token"
GIT_CONFIG = b"[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = https://example.com/repo.git\n"


class LabResolver:
    def __init__(self, lab: "Lab") -> None:
        self.lab = lab

    def query(self, name, rdtype):
        if name in self.lab.dns_failures:
            raise DnsFailure("SERVFAIL")
        records = self.lab.dns.get(name)
        if records is None:
            raise NXDomain(name)
        if rdtype not in records:
            raise NoAnswer(name)
        return list(records[rdtype])


class LabProber:
    """HttpProber.probe-shaped: answers from ``lab.http``; ``lab.block`` makes a host hang."""

    def __init__(self, lab: "Lab", policy) -> None:
        self.lab, self.policy = lab, policy

    def probe(self, hostname, *, scheme="https", port=None, path="/"):
        self.lab.probes.append((scheme, hostname))
        if hostname in self.lab.hang:
            self.lab.hanging.set()
            threading.Event().wait(3600)
        if hostname in self.lab.explode and self.lab.explode[hostname] > 0:
            self.lab.explode[hostname] -= 1
            raise RuntimeError(f"probe of {hostname} crashed")
        base = {"hostname": hostname, "url": f"{scheme}://{hostname}/", "scheme": scheme, "port": port or 443,
                "observed_at": datetime.now(timezone.utc).isoformat(), "headers": {}, "redirects": [],
                "status_code": None, "title": "", "body_sha256": None, "error": None}
        if not self.policy.check_target(hostname, port=443 if scheme == "https" else 80):
            return {**base, "outcome": "unauthorized", "error": {"kind": "unauthorized", "message": "denied"}}
        reply = self.lab.http.get((scheme, hostname))
        if reply is None:
            return {**base, "outcome": "error", "error": {"kind": "connection_refused", "message": "refused"}}
        if reply == "timeout":
            return {**base, "outcome": "error", "error": {"kind": "timeout", "message": "timed out"}}
        status, title = reply
        return {**base, "outcome": "ok", "status_code": status, "title": title, "ip": PUBLIC_IP}


@dataclass
class Lab:
    seeds: list[str] = field(default_factory=lambda: ["www.example.com", "shop.example.com"])
    dns: dict = field(default_factory=lambda: {
        "www.example.com": {"A": [PUBLIC_IP]},
        "shop.example.com": {"A": [PUBLIC_IP]},
    })
    dns_failures: set = field(default_factory=set)
    http: dict = field(default_factory=lambda: {
        ("https", "www.example.com"): (200, "Example"),
        ("https", "shop.example.com"): (200, "Shop"),
    })
    exposed: set = field(default_factory=set)  # hosts that serve /.git/config
    hang: set = field(default_factory=set)
    explode: dict = field(default_factory=dict)
    probes: list = field(default_factory=list)
    fetches: list = field(default_factory=list)
    hanging: threading.Event = field(default_factory=threading.Event)
    approved: bool = True

    def fetch(self, method, url, ip):
        self.fetches.append((method, url, ip))
        host = url.split("://", 1)[1].split("/", 1)[0]
        if url.endswith("/.git/config") and host in self.exposed:
            return HttpResponse(200, (("Content-Type", "text/plain"),), GIT_CONFIG)
        return HttpResponse(404, (), b"not found")

    def adapters(self, **overrides) -> PipelineAdapters:
        from watchtower.adapters.checks import load_manifest

        options = dict(
            resolver=LabResolver(self),
            prober=lambda policy: LabProber(self, policy),
            ruleset=approved_ruleset() if self.approved else load_manifest(),
            fetch=self.fetch,
            authorizer=lambda policy: (lambda url: Authorization(True, (PUBLIC_IP,))),
            seed_text=lambda: "\n".join(self.seeds),
        )
        options.update(overrides)
        return PipelineAdapters(**options)


class RecordingTransport:
    """A webhook receiver that deduplicates on Idempotency-Key, as a well-behaved receiver should."""

    def __init__(self, status: int = 204) -> None:
        self.requests: list[dict] = []
        self.status = status
        self.fail_next = 0

    def post(self, url, body, headers):
        if self.fail_next:
            self.fail_next -= 1
            return Response(503, {})
        self.requests.append({"url": url, "body": json.loads(body), "headers": dict(headers)})
        return Response(self.status, {})

    @property
    def delivered(self) -> dict[str, dict]:
        """Effective alerts: one per idempotency key."""
        return {r["headers"]["Idempotency-Key"]: r["body"] for r in self.requests}


def settings(**pipeline) -> Settings:
    return Settings.model_validate({
        "runtime": {"lease_seconds": 30, "heartbeat_seconds": 5},
        "notifications": {"destinations": [{"name": "ops", "kind": "webhook", "url": WEBHOOK}]},
        "pipeline": {"discovery_sources": ["manual"], "seed_file": "seeds.txt", "http_schemes": ["https"],
                     **pipeline},
    })


def context(project_id, role=ProjectRole.OPERATOR) -> ProjectContext:
    return ProjectContext(project_id, Principal(uuid4(), PrincipalKind.USER, "Test Operator"), role)


class Runs:
    """Drives a project through runs: start, work until idle, deliver."""

    def __init__(self, database, project_id, scope, lab, transport, **settings_overrides) -> None:
        self.database, self.project_id, self.scope, self.lab = database, project_id, scope, lab
        self.transport = transport
        self.settings = settings(**settings_overrides)
        self.service = RunService(database, scope, settings=self.settings)
        self.actor = context(project_id)

    def worker(self, **options) -> Worker:
        options.setdefault("adapters", self.lab.adapters())
        options.setdefault("retry_backoff", lambda attempt: 0)
        options.setdefault("heartbeat_seconds", 0.2)
        return Worker(self.database, self.scope, settings=self.settings, **options)

    def notifier(self, **options) -> Notifier:
        options.setdefault("transport", self.transport)
        options.setdefault("retry_backoff", lambda attempt: 0)
        return Notifier(self.database, self.settings, **options)

    def run(self, **start):
        summary = self.service.start_run(self.project_id, actor=self.actor, **start)
        self.worker().run_until_idle()
        self.notifier().run_until_idle()
        return self.service.get_run(self.project_id, summary.run_id, actor=self.actor)

    def alerts(self) -> list[dict]:
        return [r["body"] for r in self.transport.requests]

    def notifications(self):
        return self.service.list_notifications(self.project_id, actor=self.actor, limit=500)


def publish(database, project_id, authorization, *patterns, ports="80,443"):
    rules = tuple(ScopeRule.parse(p) for p in (patterns or ("example.com", "*.example.com")))
    with database.project(project_id) as uow:
        return uow.scope.publish(NewScopeRevision(rules, authorization, PortSet.parse(ports)), created_by=None)


@pytest.fixture
def scope_service(database):
    from watchtower.config.settings import ScopeSettings

    return ScopeService(database, ScopeSettings(policy_cache_seconds=0))


@pytest.fixture
def lab():
    return Lab()


@pytest.fixture
def runs(database, project_id, authorization, scope_service, lab):
    publish(database, project_id, authorization)
    return Runs(database, project_id, scope_service, lab, RecordingTransport())


@pytest.fixture
def operator(project_id):
    return context(project_id)


@pytest.fixture
def viewer(project_id):
    return context(project_id, ProjectRole.VIEWER)
