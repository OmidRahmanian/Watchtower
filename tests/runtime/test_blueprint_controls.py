"""Durable request limits, revocation and request idempotency; no live targets."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from watchtower.config.settings import ScopeSettings
from watchtower.domain.errors import RequestConflict
from watchtower.services.budgets import RequestLimiter
from watchtower.services.jobs import CancelToken
from watchtower.services.scope import LiveScopePolicy
from watchtower.adapters.discovery.dns import DnsCollector, NoAnswer

pytestmark = pytest.mark.postgres


def test_request_key_is_durable_and_conflicting_payload_is_rejected(runs):
    one = runs.service.start_run(runs.actor.project_id, actor=runs.actor, reason="test", idempotency_key="retry-1")
    again = runs.service.start_run(runs.actor.project_id, actor=runs.actor, reason="test", idempotency_key="retry-1")
    assert one.run_id == again.run_id
    with pytest.raises(RequestConflict):
        runs.service.start_run(runs.actor.project_id, actor=runs.actor, reason="different", idempotency_key="retry-1")


def test_concurrent_equivalent_scan_requests_reuse_one_run_and_keep_alias_keys(runs):
    def start(key):
        return runs.service.start_run(runs.actor.project_id, actor=runs.actor, idempotency_key=key, reuse_active=True)
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(start, ["a", "b"]))
    assert results[0].run_id == results[1].run_id
    runs.finish(results[0].run_id)
    # A key which reused the other request's active run must stay bound after completion.
    assert start("a").run_id == results[0].run_id
    assert start("b").run_id == results[0].run_id


def test_request_budget_survives_new_worker_instances(database, project_id):
    settings = ScopeSettings(max_requests_per_run=2)
    run = uuid4()
    make = lambda: RequestLimiter(database, settings, project_id, run, CancelToken(), lambda _: True)
    assert make().acquire("budget.example.com")
    assert make().acquire("budget.example.com")
    assert make().acquire("budget.example.com") is False


def test_rate_limit_wait_is_cancellable_and_does_not_consume_a_permit(database, project_id):
    from watchtower.services.jobs import JobCancelled
    token = CancelToken()
    host = uuid4().hex + ".example.com"
    limiter = RequestLimiter(database, ScopeSettings(per_host_requests_per_minute=1), project_id, uuid4(), token, lambda _: True)
    assert limiter.acquire(host)
    def stop(_):
        token.cancel("cancelled while throttled")
    token.wait = stop
    with pytest.raises(JobCancelled):
        limiter.acquire(host)


def test_revocation_mid_dns_phase_stops_further_queries(runs):
    service = runs.scope
    policy = service.current_policy(runs.actor.project_id)
    guard = LiveScopePolicy(service, runs.actor.project_id, policy.revision_id)
    seen = []
    class Resolver:
        def query(self, name, kind):
            seen.append((name, kind))
            service.revoke(runs.actor.project_id, policy.revision_id, reason="revoked during query", actor=None)
            raise NoAnswer(name)
    result = DnsCollector(guard, Resolver()).lookup("www.example.com", root_domain="example.com")
    assert len(seen) == 1 and result["status"] == "unauthorized"


def test_no_permitted_http_scheme_is_failed_coverage(runs):
    from watchtower.domain.models import RunPhase
    from watchtower.domain.scope import ScopeExecution
    current = runs.scope.current_policy(runs.actor.project_id).revision
    runs.scope.publish(runs.actor.project_id, current.rules, current.authorization, actor=None,
                       execution_policy=ScopeExecution(allowed_schemes=("https",)))
    runs.settings = runs.settings.model_copy(update={"pipeline": runs.settings.pipeline.model_copy(update={"http_schemes": ("http",)})})
    runs.service.settings = runs.settings
    detail = runs.run()
    http = [snapshot for snapshot in detail.snapshots if snapshot.phase == RunPhase.HTTP]
    assert http and all(snapshot.comparison.value == "failed" for snapshot in http)
    assert detail.summary.status == "failed"


def test_schedule_slot_does_not_duplicate_after_scope_changes(runs):
    first = runs.service.start_scheduled(runs.actor.project_id, slot="synthetic-hour")
    current = runs.scope.current_policy(runs.actor.project_id).revision
    runs.scope.publish(runs.actor.project_id, current.rules, current.authorization, actor=None)
    assert runs.service.start_scheduled(runs.actor.project_id, slot="synthetic-hour") is None
    assert [run.run_id for run in runs.service.list_runs(runs.actor.project_id, actor=runs.actor)] == [first.run_id]
