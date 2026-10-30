"""PostgreSQL repositories: assets, observations, jobs, findings, evidence, notifications, auth."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from uuid import UUID, uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from watchtower.domain.errors import AuthenticationFailed, InvalidTarget, NotFound, PermissionDenied
from watchtower.domain.models import (
    AssetKind,
    FindingStatus,
    JobStatus,
    NewEvidence,
    NewFinding,
    NewJob,
    NewNotification,
    NewObservation,
    NotificationStatus,
    ObservationKind,
    Severity,
    StoredBlob,
)
from watchtower.domain.scope import NewScopeRevision, ScopeRule
from watchtower.domain.targets import PortSet
from watchtower.persistence import Database
from watchtower.security.auth import ProjectRole

pytestmark = pytest.mark.postgres


@pytest.fixture
def revision_id(database: Database, project_id: UUID, authorization) -> UUID:
    with database.project(project_id) as uow:
        new = NewScopeRevision((ScopeRule.parse("*.example.com"),), authorization, PortSet.parse("443"))
        return uow.scope.publish(new, created_by=None).id


def test_asset_upsert_is_idempotent_and_merges(database: Database, project_id: UUID) -> None:
    early = datetime(2025, 1, 1, tzinfo=timezone.utc)
    with database.project(project_id) as uow:
        first, created = uow.assets.upsert(AssetKind.HOSTNAME, "api.example.com", attributes={"a": 1})
        assert created
        second, created = uow.assets.upsert(AssetKind.HOSTNAME, "api.example.com", seen_at=early, attributes={"b": 2})
        assert not created and second.id == first.id
        assert second.first_seen_at == early
        assert second.last_seen_at == first.last_seen_at
        assert second.attributes == {"a": 1, "b": 2}


@pytest.mark.parametrize(
    ("kind", "value"),
    [
        (AssetKind.HOSTNAME, "API.example.com"),
        (AssetKind.HOSTNAME, "bücher.example"),
        (AssetKind.IP_ADDRESS, "::ffff:1.2.3.4"),
        (AssetKind.URL, "https://example.com"),
        (AssetKind.SERVICE, "example.com:443"),
    ],
)
def test_assets_must_be_canonical(database: Database, project_id: UUID, kind: AssetKind, value: str) -> None:
    with pytest.raises(InvalidTarget):
        with database.project(project_id) as uow:
            uow.assets.upsert(kind, value)


def test_observations_are_idempotent_and_append_only(database: Database, project_id: UUID) -> None:
    with database.project(project_id) as uow:
        asset, _ = uow.assets.upsert(AssetKind.HOSTNAME, "www.example.com")
        new = NewObservation(asset.id, ObservationKind.DISCOVERY, "subfinder", {"n": 1}, source_ref="run-1/www")
        first, created = uow.observations.record(new)
        again, created_again = uow.observations.record(new)
        assert created and not created_again and again.id == first.id
        uow.observations.record(NewObservation(asset.id, ObservationKind.DNS_RESOLUTION, "dnsx", {"a": ["1.2.3.4"]}))
        assert uow.observations.latest(asset.id, ObservationKind.DISCOVERY).id == first.id  # type: ignore[union-attr]
        assert len(uow.observations.list_for_asset(asset.id)) == 2
    with pytest.raises(DBAPIError, match="append-only"):
        with database.project(project_id) as uow:
            uow.connection.execute(text("UPDATE observations SET data = '{}'"))


def test_job_lifecycle(database: Database, project_id: UUID, revision_id: UUID) -> None:
    with database.project(project_id) as uow:
        job, created = uow.jobs.enqueue(NewJob("probe", revision_id, {"host": "a.example.com"}, idempotency_key="k1"))
        same, created_again = uow.jobs.enqueue(NewJob("probe", revision_id, idempotency_key="k1"))
        assert created and not created_again and same.id == job.id
        low, _ = uow.jobs.enqueue(NewJob("probe", revision_id, priority=-5))
        cancelled, _ = uow.jobs.enqueue(NewJob("probe", revision_id))
        assert uow.jobs.cancel(cancelled.id)
        assert not uow.jobs.cancel(cancelled.id)

    worker = f"w-{uuid4().hex[:6]}"
    with database.system() as system:
        claimed = [j for j in system.job_leases.claim(worker, kinds=["probe"], limit=50) if j.project_id == project_id]
    assert [j.id for j in claimed] == [job.id, low.id]
    assert claimed[0].status is JobStatus.RUNNING and claimed[0].attempts == 1

    with database.system() as system:
        assert system.job_leases.heartbeat(job.id, worker)
        assert not system.job_leases.complete(job.id, "someone-else")
        assert system.job_leases.complete(job.id, worker, {"ok": True})
        assert system.job_leases.fail(low.id, worker, "timeout", retry_in_seconds=0)
    with database.project(project_id) as uow:
        done = uow.jobs.get(job.id)
        retried = uow.jobs.get(low.id)
    assert done is not None and done.status is JobStatus.SUCCEEDED and done.result == {"ok": True}
    assert retried is not None and retried.status is JobStatus.QUEUED and retried.last_error == "timeout"


def test_job_fails_after_max_attempts(database: Database, project_id: UUID, revision_id: UUID) -> None:
    with database.project(project_id) as uow:
        job, _ = uow.jobs.enqueue(NewJob("scan-once", revision_id, max_attempts=1))
    worker = "w-max"
    with database.system() as system:
        assert [j.id for j in system.job_leases.claim(worker, kinds=["scan-once"])] == [job.id]
        assert system.job_leases.fail(job.id, worker, "boom", retry_in_seconds=0)
    with database.project(project_id) as uow:
        assert uow.jobs.get(job.id).status is JobStatus.FAILED  # type: ignore[union-attr]


def test_expired_lease_is_reclaimed(database: Database, project_id: UUID, revision_id: UUID) -> None:
    with database.project(project_id) as uow:
        job, _ = uow.jobs.enqueue(NewJob("lease-test", revision_id))
    with database.system() as system:
        system.job_leases.claim("w1", kinds=["lease-test"], lease_seconds=0)
    with database.system() as system:
        reclaimed = system.job_leases.claim("w2", kinds=["lease-test"])
        assert [j.id for j in reclaimed] == [job.id]
        assert reclaimed[0].lease_owner == "w2" and reclaimed[0].attempts == 2


def test_findings_and_evidence(database: Database, project_id: UUID, revision_id: UUID) -> None:
    body = b"HTTP/1.1 200 OK"
    blob = StoredBlob("file:///evidence/x", hashlib.sha256(body).hexdigest(), len(body))
    with database.project(project_id) as uow:
        asset, _ = uow.assets.upsert(AssetKind.HOSTNAME, "app.example.com")
        new = NewFinding(asset.id, "fp-1", "Exposed panel", Severity.MEDIUM, "check:panel", {"v": 1}, scope_revision_id=revision_id)
        finding, created = uow.findings.upsert(new)
        assert created and finding.status is FindingStatus.OPEN
        uow.findings.set_status(finding.id, FindingStatus.TRIAGED)
        again, created = uow.findings.upsert(
            NewFinding(asset.id, "fp-1", "Exposed panel", Severity.HIGH, "check:panel", {"v": 2})
        )
        assert not created and again.id == finding.id
        assert again.status is FindingStatus.TRIAGED and again.severity is Severity.HIGH and again.details == {"v": 2}
        assert uow.findings.get_by_fingerprint("fp-1").id == finding.id  # type: ignore[union-attr]
        assert uow.findings.get_by_fingerprint("missing") is None
        assert [f.id for f in uow.findings.list(status=FindingStatus.TRIAGED)] == [finding.id]
        evidence = uow.evidence.add(NewEvidence(blob, "text/plain", finding_id=finding.id))
        assert [e.id for e in uow.evidence.list_for_finding(finding.id)] == [evidence.id]
        with pytest.raises(NotFound):
            uow.findings.set_status(uuid4(), FindingStatus.RESOLVED)
    with pytest.raises(DBAPIError, match="append-only"):
        with database.project(project_id) as uow:
            uow.connection.execute(text("UPDATE evidence SET storage_uri = 'x'"))


def test_notification_outbox(database: Database, project_id: UUID) -> None:
    with database.project(project_id) as uow:
        note, created = uow.notifications.enqueue(NewNotification("discord", "asset.discovered", "d-1", {"x": 1}, max_attempts=2))
        _, created_again = uow.notifications.enqueue(NewNotification("discord", "asset.discovered", "d-1", {"x": 2}))
        assert created and not created_again
    with database.system() as system:
        claimed = [n for n in system.notification_leases.claim("n1", channels=["discord"], limit=100) if n.id == note.id]
        assert claimed and claimed[0].status is NotificationStatus.SENDING
        assert system.notification_leases.mark_failed(note.id, "n1", "429", retry_in_seconds=0)
    with database.system() as system:
        claimed = [n for n in system.notification_leases.claim("n1", channels=["discord"], limit=100) if n.id == note.id]
        assert claimed[0].attempts == 2
        assert system.notification_leases.mark_sent(note.id, "n1")
        assert not system.notification_leases.mark_sent(note.id, "n1")


def test_token_authentication(database: Database, project_id: UUID, other_project_id: UUID) -> None:
    with database.system() as system:
        user = system.auth.create_principal("Analyst", email="Analyst@Example.com")
        system.auth.set_membership(project_id, user.id, ProjectRole.OPERATOR)
        token = system.auth.issue_token(user.id, "ci")
        scoped = system.auth.issue_token(user.id, "scoped", project_id=project_id)
        expired = system.auth.issue_token(user.id, "old", ttl_days=1)
        system.connection.execute(
            text("UPDATE api_tokens SET expires_at = now() - interval '1 second' WHERE id = :id"),
            {"id": expired.token_id},
        )

    with database.system() as system:
        context = system.auth.project_context(token.secret, project_id)
        assert context.role is ProjectRole.OPERATOR and context.principal.email == "analyst@example.com"
        with pytest.raises(PermissionDenied):
            system.auth.project_context(token.secret, other_project_id)  # not a member
        with pytest.raises(PermissionDenied):
            system.auth.project_context(scoped.secret, other_project_id)  # token restricted
        with pytest.raises(AuthenticationFailed):
            system.auth.authenticate(expired.secret)
        with pytest.raises(AuthenticationFailed):
            system.auth.authenticate(token.secret[:-1] + ("A" if token.secret[-1] != "A" else "B"))
        stored = system.connection.execute(text("SELECT token_hash FROM api_tokens WHERE id = :id"), {"id": token.token_id}).scalar_one()
        assert token.secret not in stored

    with database.system() as system:
        system.auth.revoke_token(token.token_id)
    with database.system() as system:
        with pytest.raises(AuthenticationFailed, match="revoked"):
            system.auth.authenticate(token.secret)
        system.auth.disable_principal(user.id)
    with database.system() as system:
        with pytest.raises(AuthenticationFailed, match="disabled"):
            system.auth.authenticate(scoped.secret)
