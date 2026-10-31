"""Monitoring runs: the synchronous pipeline, its durable jobs, and the run API.

A run is a chain of jobs sharing ``run_id``: one job per phase
(``monitor.discovery`` → ``monitor.dns`` → ``monitor.http`` →
``monitor.checks``) and a closing ``monitor.finalize``. Each job enqueues the
next one under the idempotency key ``run:<run_id>:<step>``, so a retried job
never forks the chain, and ``request_cancel(run_id=...)`` stops it: queued
jobs are cancelled and the next ``enqueue`` raises ``RunCancelled``.

Every phase handles each of the run's root domains (targets) in turn. Network
work happens outside any transaction; the inventory, findings, evidence and
the phase snapshot for one target are then written in one transaction. A job
that is retried, or recovered after its worker died, skips targets whose
snapshot already exists, so findings are neither lost nor written twice.

``finalize`` turns the run's snapshots into at most one grouped alert per
notification destination, enqueued in the outbox with a dedupe key per run
and destination. It runs once the run has no active jobs: as the last step,
or when a run is cancelled or fails, so changes a run already accepted are
always reported.

``Pipeline`` executes one leased job. ``watchtower.workers.runtime.Worker``
leases jobs, heartbeats, and turns ``JobCancelled`` and errors into the
lease calls; ``RunService`` is what the API and CLI call.
"""

from __future__ import annotations

import threading
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from functools import partial
from pathlib import Path
import hashlib
import json
import ssl
from typing import Any
from uuid import UUID, NAMESPACE_URL, uuid4, uuid5

from sqlalchemy import and_, func, or_, select, tuple_, text

from watchtower.adapters.checks import (
    CheckResult, Endpoint, Outcome as CheckOutcome, RuleNotApproved, RuleSet, build_checks, load_manifest,
    scope_authorizer,
)
from watchtower.adapters.checks.base import Authorizer, Fetcher
from watchtower.adapters.discovery import manual, subfinder
from watchtower.adapters.discovery.dns import DnsCollector, DnsPythonResolver, Resolver
from watchtower.adapters.probing.guard import explain
from watchtower.adapters.probing.http import HttpProber
from watchtower.config.settings import Settings
from watchtower.domain.errors import NotFound, RunCancelled, ScopeViolation, RequestConflict
from watchtower.domain.models import (
    Job, JobStatus, NewJob, NewNotification, NewPhaseSnapshot, Notification, PhaseComparison, PhaseSnapshot,
    PhaseStatus, RunPhase, AssetKind,
)
from watchtower.domain.repositories import BlobStore, ProjectUnitOfWork
from watchtower.domain.scope import DecisionReason, RuleKind, ScopePolicy
from watchtower.persistence.database import Database
from watchtower.persistence.repositories.queue import _notification
from watchtower.persistence.tables import jobs as jobs_table, notifications as notifications_table, run_requests
from watchtower.security.auth import Permission, ProjectContext
from watchtower.services import changes
from watchtower.services.evidence import to_new_evidence
from watchtower.services.findings import FindingError, FindingRecord, FindingService, RepositoryFindingStore
from watchtower.services.inventory import InventoryService, in_domain, normalize_hostname, utcnow
from watchtower.services.scope import ScopeService, LiveScopePolicy

PHASES: tuple[RunPhase, ...] = (RunPhase.DISCOVERY, RunPhase.DNS, RunPhase.HTTP, RunPhase.CHECKS)
PHASE_KINDS = {phase: f"monitor.{phase.value}" for phase in PHASES}
FINALIZE = "monitor.finalize"
RETEST = "checks.retest"
JOB_KINDS = (*PHASE_KINDS.values(), FINALIZE, RETEST)
ACTIVE = (JobStatus.QUEUED, JobStatus.RUNNING)


# -- cancellation ----------------------------------------------------------


class JobCancelled(Exception):
    """The job must stop: its run was cancelled, or its worker lost the lease or is shutting down."""

    def __init__(self, detail: str, *, lease_lost: bool = False, shutdown: bool = False) -> None:
        super().__init__(detail)
        self.detail = detail
        self.lease_lost = lease_lost
        self.shutdown = shutdown


class CancelToken:
    """Set by the worker's heartbeat; checked by the pipeline and by subprocess runners."""

    def __init__(self) -> None:
        self._event = threading.Event()
        self.detail = ""
        self.lease_lost = False
        self.shutdown = False

    def cancel(self, detail: str, *, lease_lost: bool = False, shutdown: bool = False) -> None:
        if not self._event.is_set():
            self.detail, self.lease_lost, self.shutdown = detail, lease_lost, shutdown
            self._event.set()

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()

    def wait(self, seconds: float) -> bool:
        return self._event.wait(seconds)

    def check(self) -> None:
        if self._event.is_set():
            raise JobCancelled(self.detail, lease_lost=self.lease_lost, shutdown=self.shutdown)


# -- adapters --------------------------------------------------------------


@dataclass
class PipelineAdapters:
    """Hooks for everything that leaves the process; ``None`` means the production default.

    ``process_runner(argv, *, timeout, max_stdout, cancel)`` runs external tools
    (default: ``watchtower.workers.process.run_in_group``, which kills the whole
    process group on cancel or timeout).
    """

    process_runner: Callable[..., Any] | None = None
    resolver: Resolver | None = None
    prober: Callable[[ScopePolicy], Any] | None = None  # returns an object with HttpProber.probe
    ruleset: RuleSet | None = None
    fetch: Fetcher | None = None
    authorizer: Callable[[ScopePolicy], Authorizer] | None = None
    blobs: BlobStore | None = None
    seed_text: Callable[[], str] | None = None  # contents of pipeline.seed_file


# -- run payloads ----------------------------------------------------------


def _steps(meta: Mapping[str, Any]) -> list[str]:
    if meta.get("kind") == "retest":
        return [RETEST, FINALIZE]
    return [PHASE_KINDS[RunPhase(phase)] for phase in meta["phases"]] + [FINALIZE]


def _concurrency_key(kind: str) -> str | None:
    return kind.removeprefix("monitor.") if kind in PHASE_KINDS.values() else ("checks" if kind == RETEST else None)


def _new_step(run_id: UUID, revision_id: UUID, meta: Mapping[str, Any], kind: str, extra: Mapping[str, Any]) -> NewJob:
    return NewJob(
        kind=kind,
        scope_revision_id=revision_id,
        payload={"run": dict(meta), **extra},
        idempotency_key=f"run:{run_id}:{kind}",
        run_id=run_id,
        concurrency_key=_concurrency_key(kind),
        priority=1 if kind == FINALIZE else 0,  # finish started runs before starting new work
    )


def scope_roots(policy: ScopePolicy) -> list[str]:
    """Root domains named by the revision's include rules (``example.com`` for ``*.example.com``)."""
    if policy.revision is None:
        return []
    roots: set[str] = set()
    for rule in policy.revision.includes:
        if rule.kind in (RuleKind.HOST, RuleKind.SUBDOMAINS):
            try:
                roots.add(normalize_hostname(rule.value))
            except ValueError:
                continue  # an IP host rule, or a single-label name
    return sorted(roots)


def root_allowed(policy: ScopePolicy, target: str, decision: Any) -> bool:
    """Whether ``target`` may be a run's root domain.

    It must be in scope, except that the apex named by a ``*.example.com``
    rule is a root even though the apex itself is not in scope. Only that one
    denial is waived: a revoked, expired or superseded scope still refuses.
    """
    if decision:
        return True
    return decision.reason is DecisionReason.NOT_IN_SCOPE and target in scope_roots(policy)


def _hosts_under(inventory: InventoryService, target: str) -> list[Any]:
    return [asset for asset in inventory.assets() if in_domain(asset.value, target)]


# -- the pipeline ----------------------------------------------------------


class Pipeline:
    """Runs one leased job synchronously and returns its result for ``complete``."""

    def __init__(self, database: Database, scope: ScopeService, settings: Settings | None = None,
                 adapters: PipelineAdapters | None = None, *, clock: Callable[[], datetime] = utcnow) -> None:
        self.db = database
        self.scope = scope
        self.settings = settings or Settings()
        self.adapters = adapters or PipelineAdapters()
        self.clock = clock
        self._ruleset = self.adapters.ruleset

    # helpers

    @property
    def ruleset(self) -> RuleSet:
        if self._ruleset is None:
            self._ruleset = load_manifest()
        return self._ruleset

    def _blobs(self) -> BlobStore:
        if self.adapters.blobs is None:
            from watchtower.services.evidence_store import FilesystemBlobStore

            self.adapters.blobs = FilesystemBlobStore(self.settings.pipeline.evidence_root)
        return self.adapters.blobs

    def _runner(self) -> Callable[..., Any]:
        if self.adapters.process_runner is None:
            from watchtower.workers.process import run_in_group

            self.adapters.process_runner = run_in_group
        return self.adapters.process_runner

    def _confirm(self) -> Mapping[str, int]:
        return self.settings.pipeline.confirm_changes

    # dispatch

    def run_job(self, job: Job, token: CancelToken) -> dict[str, Any]:
        token.check()
        meta = job.payload["run"]
        if job.kind == FINALIZE:
            with self.db.project(job.project_id) as uow:
                pending = any(j.status in ACTIVE and j.kind != FINALIZE
                              for j in uow.jobs.list_for_run(job.run_id))
            if pending:
                # Keep a durable reconciliation marker if this worker wins
                # the race with its predecessor's completion commit.
                return {"notifications": 0, "pending_predecessors": True}
            return {"notifications": self.finalize(job.project_id, job.run_id)}
        policy = LiveScopePolicy(self.scope, job.project_id, job.scope_revision_id)
        from watchtower.services.budgets import RequestLimiter
        limits = self.settings.scope.model_copy(update={"max_requests_per_run": min(self.settings.scope.max_requests_per_run,
                                                                                 policy.execution_policy.max_requests_per_run)})
        policy.limiter = RequestLimiter(self.db, limits, job.project_id, job.run_id, token,
                                       lambda host: self.scope.policy_for_revision(job.project_id, job.scope_revision_id).check_target(host, port=None))
        if job.kind == RETEST:
            result = self._retest(job, policy, token)
        else:
            phase = RunPhase(job.kind.removeprefix("monitor."))
            result = {"targets": {target: self._phase(job, phase, target, policy, token) for target in meta["targets"]}}
        self._enqueue_next(job, token)
        return result

    def _enqueue_next(self, job: Job, token: CancelToken) -> None:
        steps = _steps(job.payload["run"])
        following = steps[steps.index(job.kind) + 1:]
        if not following:
            return
        token.check()
        try:
            with self.db.project(job.project_id) as uow:
                uow.jobs.enqueue(_new_step(job.run_id, job.scope_revision_id, job.payload["run"], following[0],
                                           {k: v for k, v in job.payload.items() if k != "run"}))
        except RunCancelled as exc:
            raise JobCancelled(f"run cancelled; {following[0]} not started") from exc

    def _phase(self, job: Job, phase: RunPhase, target: str, policy: ScopePolicy, token: CancelToken) -> str:
        token.check()
        with self.db.project(job.project_id) as uow:
            done = {(s.phase, s.target): s for s in uow.phase_snapshots.list_for_run(job.run_id)}
        if (phase, target) in done:
            return done[(phase, target)].comparison.value  # recorded before a crash or retry
        gate = policy.check_target(target, port=None)
        if not root_allowed(policy, target, gate):
            observed = changes.Observed(failed=True, stats={"skipped": explain(gate)})
            return self._record(job, phase, target, observed, lambda uow: None)
        handler = {
            RunPhase.DISCOVERY: self._discovery,
            RunPhase.DNS: self._dns,
            RunPhase.HTTP: self._http,
            RunPhase.CHECKS: self._checks,
        }[phase]
        return handler(job, target, policy, token)

    def _record(self, job: Job, phase: RunPhase, target: str, observed: changes.Observed | Callable,
                write: Callable[[ProjectUnitOfWork], Any]) -> str:
        """Apply ``write`` and record the phase snapshot for ``target`` in one transaction."""
        with self.db.project(job.project_id) as uow:
            extra = write(uow)
            if callable(observed):
                observed = observed(uow, extra)
            previous = uow.phase_snapshots.latest_comparable(target, phase)
            outcome = changes.compare(previous, observed, changes.rules_for(phase, self._confirm()))
            snapshot, _ = uow.phase_snapshots.record(NewPhaseSnapshot(
                run_id=job.run_id, target=target, phase=phase, status=outcome.status,
                comparison=outcome.comparison, items=outcome.items, pending=outcome.pending,
                changes=outcome.changes, stats=outcome.stats, job_id=job.id,
            ))
            return snapshot.comparison.value

    # phases

    def _discovery(self, job: Job, target: str, policy: ScopePolicy, token: CancelToken) -> str:
        settings = self.settings.pipeline
        names, errors, skipped = [], [], []
        for source in settings.discovery_sources:
            token.check()
            if source == "subfinder":
                runner = partial(self._runner(), cancel=token)
                found = subfinder.discover(target, policy, binary=settings.subfinder_binary, runner=runner)
                token.check()  # a cancelled tool returns early; do not record its partial output as complete
                names += found.names
                errors += found.errors
                if found.skipped:
                    skipped.append(found.skipped)
            else:
                text = self.adapters.seed_text() if self.adapters.seed_text else Path(settings.seed_file).read_text()
                lines = text.splitlines()
                parsed = (manual.import_csv(text, root_domain=target, source_file=settings.seed_file)
                          if lines and lines[0].strip().lower().startswith("hostname")
                          else manual.manual_entries((line.strip() for line in lines if line.strip()
                                                      and not line.lstrip().startswith("#")), root_domain=target))
                names += parsed.names  # names outside this root are reported as errors and skipped
        allowed = [name for name in names if policy.check_target(name.hostname, port=None)]
        failed = not allowed and len(skipped) + bool(errors) >= len(settings.discovery_sources)
        observed = changes.Observed(
            items=[changes.Item(name.hostname, True) for name in allowed],
            complete=not errors and not skipped, failed=failed,
            stats={"errors": errors[:20], "skipped": skipped, "out_of_scope": len(names) - len(allowed)},
        )
        return self._record(job, RunPhase.DISCOVERY, target, observed,
                            lambda uow: InventoryService(uow, policy=policy, job_id=job.id).ingest(names))

    def _dns(self, job: Job, target: str, policy: ScopePolicy, token: CancelToken) -> str:
        with self.db.project(job.project_id) as uow:
            hosts = [a.value for a in _hosts_under(InventoryService(uow), target)]
        nameservers = list(self.settings.pipeline.dns_nameservers) or None
        collector = DnsCollector(policy, self.adapters.resolver or DnsPythonResolver(nameservers), clock=self.clock)
        answers = []
        for host in hosts:
            token.check()
            answers.append(collector.lookup(host, root_domain=target))
        items = []
        for answer in answers:
            if answer["wildcard"]:
                continue
            if answer["status"] == "resolved" and not answer["wildcard_unknown"]:
                value = {key: sorted(answer[key]) for key in ("a", "aaaa", "cname")}
                items.append(changes.Item(answer["hostname"], value))
            elif answer["status"] in ("nxdomain", "no_answer"):
                items.append(changes.Item(answer["hostname"], {"status": answer["status"]}))
            else:  # resolver error, refused by scope, or an inconclusive wildcard check
                items.append(changes.Item(answer["hostname"], uncertain=True))
        observed = changes.Observed(items=items, stats={"hosts": len(hosts)})
        return self._record(job, RunPhase.DNS, target, observed,
                            lambda uow: InventoryService(uow, policy=policy, job_id=job.id).ingest_dns(answers))

    def _http(self, job: Job, target: str, policy: ScopePolicy, token: CancelToken) -> str:
        with self.db.project(job.project_id) as uow:
            assets = _hosts_under(InventoryService(uow), target)
        schemes = [scheme for scheme in self.settings.pipeline.http_schemes if scheme in policy.execution_policy.allowed_schemes]
        if not schemes:
            return self._record(job, RunPhase.HTTP, target,
                                changes.Observed(items=[], failed=True, complete=False,
                                                 stats={"probes": 0, "reason": "No configured HTTP scheme is permitted by the scope"}),
                                lambda uow: None)
        hosts = [a.value for a in assets if a.attributes.get("dns_status", "resolved") == "resolved"]
        # Hosts without a current address are not probed. The DNS phase reports them as
        # gone or unresolvable; here they are unknown, so they are neither removed nor alerted twice.
        items = [changes.Item(f"{scheme}://{a.value}", uncertain=True) for a in assets if a.value not in hosts
                 for scheme in schemes]
        prober = self.adapters.prober(policy) if self.adapters.prober else HttpProber(
            policy, clock=self.clock, max_redirects=self.settings.scope.max_redirects)
        results = []
        for host in hosts:
            for scheme in schemes:
                token.check()
                path = policy.execution_policy.allowed_paths[0]
                results.append(prober.probe(host, scheme=scheme, path=path))
        for result in results:
            key = f"{result['scheme']}://{result['hostname']}"
            if result["outcome"] == "ok":
                location = (result.get("headers") or {}).get("location")
                tls = result.get("tls") or {}
                expiring = None
                if tls.get("not_after"):
                    try:
                        expiring = ssl.cert_time_to_seconds(tls["not_after"]) - self.clock().timestamp() <= 30 * 86400
                    except (ValueError, TypeError):
                        pass
                items.append(changes.Item(key, {"status_code": result["status_code"], "title": result.get("title", ""),
                                                "location": location, "server": (result.get("headers") or {}).get("server"),
                                                "body_sha256": result.get("body_sha256"),
                                                "tls_fingerprint": tls.get("sha256"), "tls_expiring": expiring,
                                                "tls_hostname_mismatch": "hostname mismatch" in str(tls.get("verify_error", "")).lower()}))
            elif (result.get("error") or {}).get("kind") == "connection_refused":
                items.append(changes.Item(key, {"reachable": False}))
            else:  # timeouts, TLS and protocol errors, refused or unauthorized destinations prove nothing
                items.append(changes.Item(key, uncertain=True))
        observed = changes.Observed(items=items, stats={"hosts": len(hosts), "probes": len(results)})

        def write(uow: ProjectUnitOfWork) -> None:
            inventory = InventoryService(uow, policy=policy, job_id=job.id)
            for result in results:
                inventory.record_http(result)

        return self._record(job, RunPhase.HTTP, target, observed, write)

    def _endpoints(self, job: Job, target: str) -> list[Endpoint]:
        with self.db.project(job.project_id) as uow:
            snapshots = [s for s in uow.phase_snapshots.list_for_run(job.run_id)
                         if s.phase is RunPhase.HTTP and s.target == target]
            snapshot = snapshots[-1] if snapshots else uow.phase_snapshots.latest_comparable(target, RunPhase.HTTP)
        endpoints = []
        for item in snapshot.items if snapshot else ():
            if (item.get("value") or {}).get("status_code") is not None:
                scheme, _, host = item["key"].partition("://")
                endpoints.append(Endpoint(host, scheme))
        return endpoints

    def _run_checks(self, policy: ScopePolicy, endpoints: Iterable[Endpoint], token: CancelToken,
                    only: str | None = None) -> tuple[list[CheckResult], dict[str, str], dict[str, str]]:
        """Run the HTTP checks; returns ``(results, not_run, not_scheduled)``.

        ``not_run`` names checks that should have run but could not (pending
        approval): the phase is then partial. ``not_scheduled`` names checks the
        pipeline does not run at all, which does not make a phase partial.
        """
        authorize = self.adapters.authorizer(policy) if self.adapters.authorizer else scope_authorizer(policy)
        endpoints = list(endpoints)
        options = {"fetch": self.adapters.fetch} if self.adapters.fetch else {}
        http_checks, component_checks = build_checks(self.ruleset, authorize=authorize, **options)
        configured = bool(self.settings.intelligence.advisory_file or self.settings.intelligence.advisory_url)
        not_scheduled = {}
        not_run: dict[str, str] = {}
        results = []
        for rule_id, check in sorted(http_checks.items()):
            if "http" not in self.settings.pipeline.check_kinds:
                not_scheduled[rule_id] = "HTTP checks disabled in this profile"
                continue
            if "http" not in policy.execution_policy.allowed_check_kinds:
                not_run[rule_id] = "HTTP checks not permitted by this scope revision"
                continue
            source_rule = component_checks[only].rule.definition["source_rule"] if only in component_checks else None
            if only is not None and rule_id not in (only, source_rule):
                continue
            for endpoint in endpoints:
                token.check()
                try:
                    results.append(check.run(endpoint, now=self.clock()))
                except RuleNotApproved as exc:
                    # Recorded as "not run": never a negative, so it can never resolve a finding.
                    not_run[rule_id] = str(exc)
                    break
        from watchtower.services.intelligence import IntelligenceService
        intelligence = IntelligenceService(self.settings)
        advisories = intelligence.store.records("advisories") if configured else []
        sources = list(results)
        for rule_id, check in component_checks.items():
            if only not in (None, rule_id):
                continue
            if "component" not in self.settings.pipeline.check_kinds:
                not_scheduled[rule_id] = "component checks disabled in this profile"
                continue
            if "component" not in policy.execution_policy.allowed_check_kinds:
                not_run[rule_id] = "component checks not permitted by this scope revision"
                continue
            if not check.rule.approved:
                not_run[rule_id] = f"{rule_id} is pending maintainer approval"
                continue
            if not configured:
                not_run[rule_id] = "advisory input is not configured; component coverage is unavailable"
                continue
            if not advisories:
                not_run[rule_id] = "configured advisory feed has no cached data; refresh intelligence first"
                continue
            usable = [source for source in sources if source.check_id == check.rule.definition["source_rule"]
                      and source.outcome == CheckOutcome.DETECTED]
            if endpoints and not usable:
                not_run[rule_id] = "source check disclosed no usable component evidence; applicability remains unknown"
                continue
            for source in usable:
                token.check()
                results.extend(check.evaluate(source, advisories))
        if only is not None:
            results = [result for result in results if result.check_id == only]
        return results, not_run, not_scheduled

    def _ingest(self, uow: ProjectUnitOfWork, policy: ScopePolicy, results: Sequence[CheckResult],
                apply: Callable[[FindingService, CheckResult], Any]) -> None:
        from watchtower.services.maintenance import evidence_lock
        evidence_lock(uow.connection, uow.project_id)
        service = FindingService(RepositoryFindingStore(uow, policy.revision_id),
                                 canonical_id=self.ruleset.canonical_id)
        from watchtower.services.intelligence import IntelligenceService
        from watchtower.services.prioritization import prioritize
        intelligence = IntelligenceService(self.settings)
        for result in results:
            record = apply(service, result)
            if record is not None:
                asset = uow.assets.find(AssetKind.HOSTNAME, record.target.host)
                service.set_priority(record.fingerprint, prioritize(record, intelligence.store, intelligence.feeds[0],
                                     intelligence.feeds[1], importance=asset.attributes.get("importance", "normal") if asset else "normal"))
            if record is not None and result.evidence:
                stored = uow.findings.get_by_fingerprint(record.fingerprint)
                uow.evidence.add(to_new_evidence(result.evidence, self._blobs(), uow.project_id, finding_id=stored.id))

    def _finding_items(self, uow: ProjectUnitOfWork, target: str) -> list[changes.Item]:
        items = []
        for asset in _hosts_under(InventoryService(uow), target):
            for finding in uow.findings.list(asset_id=asset.id, limit=1000):
                items.append(changes.Item(finding.fingerprint, {
                    "status": finding.status.value, "severity": finding.severity.value, "title": finding.title,
                    "host": asset.value, "check_id": finding.details.get("check_id", finding.source),
                    "recurrences": finding.details.get("recurrences", 0),
                }))
        return items

    def _checks(self, job: Job, target: str, policy: ScopePolicy, token: CancelToken) -> str:
        endpoints = self._endpoints(job, target)
        results, not_run, not_scheduled = self._run_checks(policy, endpoints, token)
        inconclusive = [r for r in results if not r.outcome.conclusive]
        stats = {"endpoints": len(endpoints), "results": len(results), "not_run": not_run,
                 "not_scheduled": not_scheduled,
                 "inconclusive": len(inconclusive),
                 "detected": sum(r.outcome is CheckOutcome.DETECTED for r in results)}

        # Checks ran and none produced a conclusive answer: the scan failed, it did not merely skip work.
        failed = bool(results) and len(inconclusive) == len(results)

        def observe(uow: ProjectUnitOfWork, _: Any) -> changes.Observed:
            return changes.Observed(items=self._finding_items(uow, target), failed=failed,
                                    complete=not not_run and not inconclusive, stats=stats)

        return self._record(job, RunPhase.CHECKS, target, observe,
                            lambda uow: self._ingest(uow, policy, results, FindingService.ingest))

    def _retest(self, job: Job, policy: ScopePolicy, token: CancelToken) -> dict[str, Any]:
        fingerprint = job.payload["fingerprint"]
        target = job.payload["run"]["targets"][0]
        with self.db.project(job.project_id) as uow:
            if any(s.phase is RunPhase.CHECKS for s in uow.phase_snapshots.list_for_run(job.run_id)):
                return {"outcome": "recorded"}
            stored = uow.findings.get_by_fingerprint(fingerprint)
        if stored is None:
            raise NotFound(f"finding {fingerprint} not found")
        record = FindingRecord.from_finding(stored)
        endpoint = Endpoint(record.target.host, record.target.scheme, record.target.port)
        results, not_run, _ = self._run_checks(policy, [endpoint], token, only=record.check_id)
        results = [r for r in results if self._fingerprint(r) == fingerprint]
        outcome = results[0].outcome.value if results else "not_run"
        stats = {"fingerprint": fingerprint, "outcome": outcome, "not_run": not_run}

        def apply(service: FindingService, result: CheckResult) -> FindingRecord | None:
            try:
                return service.apply_retest(fingerprint, result)
            except FindingError as exc:  # irrelevant or stale retest: recorded, never applied
                stats["rejected"] = str(exc)
                return None

        def observe(uow: ProjectUnitOfWork, _: Any) -> changes.Observed:
            # Not run (pending rule) is partial; a failed or inconclusive retest is a failed retest.
            ran = bool(results)
            return changes.Observed(items=self._finding_items(uow, target), stats=stats,
                                    failed=ran and not results[0].outcome.conclusive,
                                    complete=ran and results[0].outcome.conclusive)

        self._record(job, RunPhase.CHECKS, target, observe, lambda uow: self._ingest(uow, policy, results, apply))
        return {"outcome": outcome, "not_run": not_run}

    def _fingerprint(self, result: CheckResult) -> str:
        return FindingService(canonical_id=self.ruleset.canonical_id).fingerprint_for(result)

    # alerts

    def finalize(self, project_id: UUID, run_id: UUID) -> int:
        """Enqueue the run's grouped alerts; idempotent, and a no-op while the run still has active jobs."""
        destinations = [d for d in self.settings.notifications.destinations if d.enabled]
        with self.db.project(project_id) as uow:
            run_jobs = list(uow.jobs.list_for_run(run_id))
            active = [j for j in run_jobs if j.status in ACTIVE and j.kind != FINALIZE]
            if not run_jobs or active:
                return 0
            snapshots = list(uow.phase_snapshots.list_for_run(run_id))
            found = [change for snapshot in snapshots for change in changes.alertable(snapshot)]
            failed = [{"kind": j.kind, "error": (j.last_error or "")[:500]}
                      for j in run_jobs if j.status is JobStatus.FAILED]
            failed += [{"kind": PHASE_KINDS[s.phase], "target": s.target,
                        "error": str(s.stats.get("failure") or s.stats.get("skipped") or "phase failed")[:500]}
                       for s in snapshots if s.status is PhaseStatus.FAILED]
            meta = run_jobs[0].payload["run"]
            created = 0
            for event, lines in ((changes.ALERT_EVENT, found), (changes.RUN_FAILED_EVENT, failed)):
                if not lines:
                    continue
                for destination in destinations:
                    if event == changes.ALERT_EVENT:
                        keep = set(changes.wanted({c.type for c in found}, event, destination.events))
                        selected: list[Any] = [c.as_dict() for c in found if c.type in keep]
                    else:
                        if destination.events and event not in destination.events:
                            continue
                        selected = failed
                    if not selected:
                        continue
                    payload = {"project_id": str(project_id), "run_id": str(run_id), "kind": meta.get("kind", "scan"),
                               "targets": meta.get("targets", []), "changes" if event == changes.ALERT_EVENT
                               else "failed_jobs": selected}
                    _, new = uow.notifications.enqueue(NewNotification(
                        channel=destination.name, event_type=event, payload=payload,
                        dedupe_key=f"{event}:{run_id}:{destination.name}",
                    ))
                    created += new
            # Clear deferred finalizers in the same transaction as the outbox.
            # Recovery then scans unfinished reconciliations, not every
            # successful baseline run from the past day.
            uow.connection.execute(
                jobs_table.update().where(
                    jobs_table.c.project_id == project_id, jobs_table.c.run_id == run_id,
                    jobs_table.c.kind == FINALIZE, jobs_table.c.status == JobStatus.SUCCEEDED.value,
                    jobs_table.c.result["pending_predecessors"].as_boolean().is_(True),
                ).values(result={"notifications": created, "pending_predecessors": False})
            )
            return created


# -- the run API -----------------------------------------------------------


@dataclass(frozen=True, slots=True)
class PhaseState:
    phase: RunPhase
    target: str
    status: PhaseStatus
    comparison: PhaseComparison


@dataclass(frozen=True, slots=True)
class RunSummary:
    run_id: UUID
    created_at: datetime
    status: str  # queued | running | succeeded | partial | failed | cancelled
    scope_revision_id: UUID
    kind: str  # scan | retest
    requested_by: str | None
    reason: str
    targets: tuple[str, ...]
    job_counts: Mapping[str, int]
    phases: tuple[PhaseState, ...]
    finished_at: datetime | None = None
    last_error: str | None = None


@dataclass(frozen=True, slots=True)
class RunDetail:
    summary: RunSummary
    jobs: tuple[Job, ...]
    snapshots: tuple[PhaseSnapshot, ...]


def summarize(run_jobs: Sequence[Job], snapshots: Sequence[PhaseSnapshot]) -> RunSummary:
    first = run_jobs[0]
    meta = first.payload["run"]
    counts: dict[str, int] = {}
    for job in run_jobs:
        counts[job.status.value] = counts.get(job.status.value, 0) + 1
    statuses = {job.status for job in run_jobs}
    if JobStatus.RUNNING in statuses:
        status = "running"
    elif JobStatus.QUEUED in statuses:
        status = "queued"
    elif JobStatus.CANCELLED in statuses:
        status = "cancelled"
    elif JobStatus.FAILED in statuses or any(s.status is PhaseStatus.FAILED for s in snapshots):
        status = "failed"  # a job gave up, or a phase observed nothing
    elif any(s.status is PhaseStatus.PARTIAL or s.comparison is PhaseComparison.UNCERTAIN for s in snapshots):
        status = "partial"  # real coverage with gaps: pending rules, some hosts unobservable"
    else:
        status = "succeeded"
    finished = [job.finished_at for job in run_jobs if job.finished_at]
    errors = [job.last_error for job in run_jobs if job.last_error]
    return RunSummary(
        run_id=first.run_id, created_at=min(job.created_at for job in run_jobs), status=status,
        scope_revision_id=first.scope_revision_id, kind=meta.get("kind", "scan"),
        requested_by=meta.get("requested_by"), reason=meta.get("reason", ""), targets=tuple(meta.get("targets", ())),
        job_counts=counts,
        phases=tuple(PhaseState(s.phase, s.target, s.status, s.comparison) for s in snapshots),
        finished_at=max(finished) if finished and status not in ("queued", "running") else None,
        last_error=errors[-1] if errors else None,
    )


def _require(actor: ProjectContext, project_id: UUID, permission: Permission) -> None:
    if actor.project_id != project_id:
        from watchtower.domain.errors import PermissionDenied

        raise PermissionDenied(f"credentials are for project {actor.project_id}, not {project_id}")
    actor.require(permission)


class RunService:
    """Start, cancel and inspect runs. ``on_enqueue`` wakes workers (for example a Celery task)."""

    def __init__(self, database: Database, scope: ScopeService, *, settings: Settings | None = None,
                 on_enqueue: Callable[[], None] | None = None, clock: Callable[[], datetime] = utcnow) -> None:
        self.db = database
        self.scope = scope
        self.settings = settings or Settings()
        self.on_enqueue = on_enqueue
        self.clock = clock

    def _kick(self) -> None:
        if self.on_enqueue is not None:
            self.on_enqueue()

    def _targets(self, policy: ScopePolicy, targets: Sequence[str] | None) -> list[str]:
        roots = scope_roots(policy)
        if policy.revision is None:
            raise ScopeViolation(policy.check_target(targets[0] if targets else "scope.example", port=None))
        chosen = sorted({normalize_hostname(t) for t in targets}) if targets else roots
        for target in chosen:
            decision = policy.check_target(target, port=None)
            if not root_allowed(policy, target, decision):
                raise ScopeViolation(decision)
        if not chosen:
            raise ScopeViolation(policy.check_target("scope.example", port=None))
        return chosen

    def _start(self, project_id: UUID, policy: ScopePolicy, meta: dict[str, Any], *, run_id: UUID | None = None,
               extra: Mapping[str, Any] | None = None, reuse_active: bool = False, request_id: UUID | None = None) -> RunSummary:
        run_id = run_id or uuid4()
        with self.db.project(project_id) as uow:
            uow.connection.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
                                   {"key": "watchtower:start:" + str(project_id)})
            payload_hash = hashlib.sha256(json.dumps({"scope": str(policy.revision_id), "run": meta}, sort_keys=True).encode()).hexdigest()
            if request_id is not None:
                previous = uow.connection.execute(select(run_requests).where(
                    run_requests.c.project_id == project_id, run_requests.c.request_id == request_id)).one_or_none()
                if previous is not None:
                    if previous.payload_sha256 != payload_hash:
                        raise RequestConflict("idempotency key already used with different parameters or scope")
                    return summarize(uow.jobs.list_for_run(previous.run_id), uow.phase_snapshots.list_for_run(previous.run_id))
            def remember(actual_run_id):
                if request_id is not None:
                    uow.connection.execute(run_requests.insert().values(project_id=project_id, request_id=request_id,
                                                                        run_id=actual_run_id, payload_sha256=payload_hash))
            existing = list(uow.jobs.list_for_run(run_id))
            if existing:
                old = existing[0].payload["run"]
                if existing[0].scope_revision_id != policy.revision_id or old != meta:
                    raise RequestConflict("idempotency key already used with different parameters or scope")
                remember(run_id)
                return summarize(existing, uow.phase_snapshots.list_for_run(run_id))
            if reuse_active:
                active = list(uow.connection.execute(select(jobs_table.c.run_id, jobs_table.c.payload, jobs_table.c.scope_revision_id).where(
                    jobs_table.c.project_id == project_id, jobs_table.c.status.in_(["queued", "running"]),
                    jobs_table.c.run_id.is_not(None))))
                for row in active:
                    old = row.payload.get("run", {})
                    if row.scope_revision_id == policy.revision_id and all(old.get(k) == meta.get(k) for k in ("kind", "targets", "phases")):
                        remember(row.run_id)
                        return summarize(uow.jobs.list_for_run(row.run_id), uow.phase_snapshots.list_for_run(row.run_id))
            uow.jobs.enqueue(_new_step(run_id, policy.revision_id, meta, _steps(meta)[0], extra or {}))
            remember(run_id)
            summary = summarize(uow.jobs.list_for_run(run_id), [])
        self._kick()
        return summary

    def start_run(self, project_id: UUID, *, actor: ProjectContext, targets: list[str] | None = None,
                  phases: list[RunPhase] | None = None, reason: str = "", idempotency_key: str | None = None,
                  reuse_active: bool = False) -> RunSummary:
        _require(actor, project_id, Permission.OPERATE)
        self.scope.invalidate(project_id)
        policy = self.scope.current_policy(project_id)
        chosen = self._targets(policy, targets)
        ordered = [p.value for p in PHASES if p in {RunPhase(x) for x in phases}] if phases else [p.value for p in PHASES]
        meta = {"kind": "scan", "requested_by": str(actor.principal.id), "reason": reason, "targets": chosen,
                "phases": ordered}
        if idempotency_key is not None and not 1 <= len(idempotency_key) <= 200:
            raise ValueError("idempotency key must contain 1-200 characters")
        run_id = uuid5(NAMESPACE_URL, f"watchtower:{project_id}:request:{actor.principal.id}:{idempotency_key}") if idempotency_key else None
        return self._start(project_id, policy, meta, run_id=run_id, reuse_active=reuse_active, request_id=run_id)

    def start_scheduled(self, project_id: UUID, *, slot: str) -> RunSummary | None:
        """Start the run for schedule slot ``slot`` (for example ``"2026-10-30T06"``); repeats are no-ops."""
        policy = self.scope.current_policy(project_id)
        try:
            chosen = self._targets(policy, None)
        except ScopeViolation:
            return None
        meta = {"kind": "scan", "requested_by": None, "reason": f"scheduled {slot}", "targets": chosen,
                "phases": [p.value for p in PHASES]}
        run_id = uuid5(NAMESPACE_URL, f"watchtower:{project_id}:scheduled:{slot}")
        try:
            return self._start(project_id, policy, meta, run_id=run_id)
        except (RunCancelled, RequestConflict):
            # A published scope must not enqueue a second run for the same slot.
            return None

    def request_retest(self, project_id: UUID, fingerprint: str, *, actor: ProjectContext,
                       reason: str = "") -> RunSummary:
        _require(actor, project_id, Permission.OPERATE)
        self.scope.invalidate(project_id)
        policy = self.scope.current_policy(project_id)
        with self.db.project(project_id) as uow:
            finding = uow.findings.get_by_fingerprint(fingerprint)
            if finding is None:
                raise NotFound(f"finding {fingerprint} not found")
            asset = uow.assets.get(finding.asset_id)
        root = (asset.attributes.get("root_domain") if asset else None) or (asset.value if asset else "")
        decision = policy.check_target(asset.value if asset else root, port=None)
        if not decision:
            raise ScopeViolation(decision)
        meta = {"kind": "retest", "requested_by": str(actor.principal.id), "reason": reason, "targets": [root],
                "phases": [RunPhase.CHECKS.value]}
        return self._start(project_id, policy, meta, extra={"fingerprint": fingerprint})

    def cancel_run(self, project_id: UUID, run_id: UUID, *, actor: ProjectContext, reason: str) -> int:
        _require(actor, project_id, Permission.OPERATE)
        with self.db.project(project_id) as uow:
            if not uow.jobs.list_for_run(run_id):
                raise NotFound(f"run {run_id} not found")
            count = uow.jobs.request_cancel(run_id=run_id, reason=reason)
        # When nothing was running, no worker will see the cancel: report what the run already found.
        Pipeline(self.db, self.scope, self.settings).finalize(project_id, run_id)
        return count

    def get_run(self, project_id: UUID, run_id: UUID, *, actor: ProjectContext) -> RunDetail:
        _require(actor, project_id, Permission.VIEW)
        with self.db.project(project_id) as uow:
            run_jobs = list(uow.jobs.list_for_run(run_id))
            if not run_jobs:
                raise NotFound(f"run {run_id} not found")
            snapshots = list(uow.phase_snapshots.list_for_run(run_id))
        return RunDetail(summarize(run_jobs, snapshots), tuple(run_jobs), tuple(snapshots))

    def list_runs(self, project_id: UUID, *, actor: ProjectContext, limit: int = 50,
                  before: tuple[datetime, UUID] | None = None) -> list[RunSummary]:
        """Newest first; page by passing the last summary's ``(created_at, run_id)`` as ``before``."""
        _require(actor, project_id, Permission.VIEW)
        started = func.min(jobs_table.c.created_at).label("started")
        query = (select(jobs_table.c.run_id, started)
                 .where(jobs_table.c.project_id == project_id, jobs_table.c.run_id.is_not(None))
                 .group_by(jobs_table.c.run_id))
        if before is not None:
            query = query.having(tuple_(func.min(jobs_table.c.created_at), jobs_table.c.run_id) < tuple_(*before))
        query = query.order_by(started.desc(), jobs_table.c.run_id.desc()).limit(max(1, min(limit, 500)))
        summaries = []
        with self.db.project(project_id) as uow:
            for row in uow.connection.execute(query):
                summaries.append(summarize(uow.jobs.list_for_run(row.run_id),
                                           uow.phase_snapshots.list_for_run(row.run_id)))
        return summaries

    def list_notifications(self, project_id: UUID, *, actor: ProjectContext, run_id: UUID | None = None,
                           limit: int = 50) -> list[Notification]:
        _require(actor, project_id, Permission.VIEW)
        query = select(notifications_table).where(notifications_table.c.project_id == project_id)
        if run_id is not None:
            query = query.where(notifications_table.c.payload["run_id"].astext == str(run_id))
        query = query.order_by(notifications_table.c.created_at.desc()).limit(max(1, min(limit, 500)))
        with self.db.project(project_id) as uow:
            return [_notification(row) for row in uow.connection.execute(query)]


# -- recovery --------------------------------------------------------------


def unfinalized_runs(database: Database, *, within: timedelta = timedelta(days=1),
                     limit: int = 100) -> list[tuple[UUID, UUID]]:
    """``(project_id, run_id)`` of recent stopped or deferred runs to reconcile.

    Covers jobs that failed or were cancelled when their lease expired on the
    final attempt, and a crash after completing a predecessor whose finalizer
    already ran early. Finalization and outbox writes are idempotent.
    """
    stopped = (select(jobs_table.c.project_id, jobs_table.c.run_id)
               .where(jobs_table.c.run_id.is_not(None),
                      or_(jobs_table.c.status.in_([JobStatus.FAILED.value, JobStatus.CANCELLED.value]),
                          and_(jobs_table.c.kind == FINALIZE,
                               jobs_table.c.status == JobStatus.SUCCEEDED.value,
                               jobs_table.c.result["pending_predecessors"].as_boolean().is_(True))),
                      jobs_table.c.finished_at > func.now() - within)
               .group_by(jobs_table.c.project_id, jobs_table.c.run_id)
               .order_by(func.max(jobs_table.c.finished_at).desc()))
    active = select(jobs_table.c.run_id).where(and_(
        jobs_table.c.status.in_([s.value for s in ACTIVE]), jobs_table.c.run_id.is_not(None)))
    query = stopped.where(jobs_table.c.run_id.not_in(active)).limit(limit)
    with database.system() as system:
        return [(row.project_id, row.run_id) for row in system.connection.execute(query)]


__all__ = [
    "FINALIZE", "JOB_KINDS", "PHASES", "PHASE_KINDS", "RETEST", "CancelToken", "JobCancelled", "PhaseState",
    "Pipeline", "PipelineAdapters", "RunDetail", "RunService", "RunSummary", "scope_roots", "summarize",
    "unfinalized_runs",
]
