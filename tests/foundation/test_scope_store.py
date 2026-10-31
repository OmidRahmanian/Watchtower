"""Scope revisions in PostgreSQL and the ScopeService."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from watchtower.config.settings import ScopeSettings
from watchtower.domain.errors import InvalidScopeRule, NotFound, PermissionDenied
from watchtower.domain.scope import (
    AuthorizationKind,
    AuthorizationReference,
    DecisionReason,
    RuleEffect,
    ScopeRule,
)
from watchtower.persistence import Database
from watchtower.security.auth import Principal, PrincipalKind, ProjectContext, ProjectRole
from watchtower.services.scope import ScopeService

pytestmark = pytest.mark.postgres

RULES = ["example.com", "*.example.com", ScopeRule.parse("admin.example.com", effect=RuleEffect.EXCLUDE)]


@pytest.fixture
def service(database: Database) -> ScopeService:
    return ScopeService(database, ScopeSettings(policy_cache_seconds=0))


def owner(project_id: UUID, database: Database) -> ProjectContext:
    with database.system() as system:
        principal = system.auth.create_principal("Owner")
        system.auth.set_membership(project_id, principal.id, ProjectRole.OWNER)
    return ProjectContext(project_id, principal, ProjectRole.OWNER)


def test_no_revision_denies(service: ScopeService, project_id: UUID) -> None:
    assert service.authorize_target(project_id, "example.com").reason is DecisionReason.NO_SCOPE


def test_unknown_project_denies(service: ScopeService) -> None:
    assert service.authorize_target(uuid4(), "example.com").reason is DecisionReason.NO_SCOPE


def test_publish_and_authorize(service: ScopeService, project_id: UUID, authorization, database: Database) -> None:
    actor = owner(project_id, database)
    revision = service.publish(project_id, RULES, authorization, actor=actor, permitted_ports="443")
    assert revision.number == 1 and revision.created_by == actor.principal.id
    assert [rule.pattern for rule in revision.rules] == ["example.com", "*.example.com", "admin.example.com"]
    assert service.authorize_target(project_id, "www.example.com", port=443).allowed
    assert service.authorize_target(project_id, "www.example.com", port=80).reason is DecisionReason.PORT_NOT_PERMITTED
    assert service.authorize_target(project_id, "admin.example.com").reason is DecisionReason.EXCLUDED
    decision = service.authorize_connection(project_id, "www.example.com", 443, ["10.0.0.1"])
    assert decision.reason is DecisionReason.PROHIBITED_DESTINATION
    redirect = service.authorize_redirect(project_id, "https://www.example.com/", "https://evil.net/", redirects_followed=0)
    assert redirect.reason is DecisionReason.REDIRECT_LIMIT  # redirects are disabled unless explicitly enabled


def test_new_revision_supersedes(service: ScopeService, project_id: UUID, authorization) -> None:
    first = service.publish(project_id, ["example.com"], authorization, actor=None)
    second = service.publish(project_id, ["example.org"], authorization, actor=None)
    assert second.number == first.number + 1
    assert not service.authorize_target(project_id, "example.com")
    assert service.authorize_target(project_id, "example.org")
    assert service.policy_for_revision(project_id, first.id).check_target("example.org").reason is DecisionReason.SUPERSEDED
    assert service.policy_for_revision(project_id, second.id).check_target("example.org").allowed
    assert [r.number for r in service.history(project_id, actor=None)] == [2, 1]


def test_revocation(service: ScopeService, project_id: UUID, authorization) -> None:
    revision = service.publish(project_id, RULES, authorization, actor=None)
    service.revoke(project_id, revision.id, reason="program paused", actor=None)
    decision = service.authorize_target(project_id, "www.example.com")
    assert decision.reason is DecisionReason.REVOKED
    assert "program paused" in decision.detail
    with pytest.raises(InvalidScopeRule):
        service.revoke(project_id, revision.id, reason="again", actor=None)
    with pytest.raises(InvalidScopeRule):
        service.revoke(project_id, revision.id, reason="  ", actor=None)
    # Publishing a new revision restores authorization.
    service.publish(project_id, RULES, authorization, actor=None)
    assert service.authorize_target(project_id, "www.example.com")


def test_revoking_unknown_revision(service: ScopeService, project_id: UUID, other_project_id: UUID, authorization) -> None:
    foreign = service.publish(other_project_id, RULES, authorization, actor=None)
    with pytest.raises(NotFound):
        service.revoke(project_id, foreign.id, reason="x", actor=None)


def test_revocation_reaches_cached_policies_after_ttl(database: Database, project_id: UUID, authorization) -> None:
    clock = [0.0]
    cached = ScopeService(database, ScopeSettings(policy_cache_seconds=5), monotonic=lambda: clock[0])
    other_process = ScopeService(database, ScopeSettings(policy_cache_seconds=0))
    revision = other_process.publish(project_id, RULES, authorization, actor=None)
    assert cached.authorize_target(project_id, "example.com")
    other_process.revoke(project_id, revision.id, reason="stop", actor=None)
    assert cached.authorize_target(project_id, "example.com")  # still inside the cache window
    clock[0] = 5.0
    assert cached.authorize_target(project_id, "example.com").reason is DecisionReason.REVOKED


def test_expired_authorization(service: ScopeService, project_id: UUID) -> None:
    past = datetime.now(timezone.utc) - timedelta(days=1)
    expired = AuthorizationReference(
        AuthorizationKind.CONTRACT, "SOW-7", "Client", valid_from=past - timedelta(days=30), valid_until=past
    )
    service.publish(project_id, RULES, expired, actor=None)
    assert service.authorize_target(project_id, "example.com").reason is DecisionReason.AUTHORIZATION_EXPIRED


def test_archived_project_denies_and_rejects_new_scope(
    service: ScopeService, project_id: UUID, authorization, database: Database
) -> None:
    service.publish(project_id, RULES, authorization, actor=None)
    with database.system() as system:
        system.projects.archive(project_id)
    assert service.authorize_target(project_id, "example.com").reason is DecisionReason.PROJECT_ARCHIVED
    with pytest.raises(InvalidScopeRule):
        service.publish(project_id, RULES, authorization, actor=None)


def test_permissions(service: ScopeService, project_id: UUID, other_project_id: UUID, authorization) -> None:
    principal = Principal(uuid4(), PrincipalKind.USER, "Analyst")
    with pytest.raises(PermissionDenied):
        service.publish(project_id, RULES, authorization, actor=ProjectContext(project_id, principal, ProjectRole.OPERATOR))
    with pytest.raises(PermissionDenied):
        service.publish(
            project_id, RULES, authorization, actor=ProjectContext(other_project_id, principal, ProjectRole.OWNER)
        )


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE scope_rules SET value = 'evil.net'",
        "DELETE FROM scope_rules",
        "UPDATE scope_revisions SET permitted_ports = '1-65535'",
        "DELETE FROM scope_revisions",
        "DELETE FROM scope_revocations",
        "TRUNCATE scope_rules CASCADE",
    ],
)
def test_scope_revisions_are_immutable(
    statement: str, service: ScopeService, project_id: UUID, authorization, database: Database
) -> None:
    revision = service.publish(project_id, RULES, authorization, actor=None)
    service.revoke(project_id, revision.id, reason="x", actor=None)
    with pytest.raises(DBAPIError, match="append-only"):
        with database.project(project_id) as uow:
            uow.connection.execute(text(statement))
    # Even the system context cannot rewrite history.
    with pytest.raises(DBAPIError, match="append-only"):
        with database.system() as system:
            system.connection.execute(text(statement))


def test_scope_changes_are_audited(service: ScopeService, project_id: UUID, authorization, database: Database) -> None:
    revision = service.publish(project_id, RULES, authorization, actor=None)
    service.revoke(project_id, revision.id, reason="done", actor=None)
    with database.system() as system:
        actions = system.connection.execute(
            text("SELECT action FROM audit_events WHERE project_id = :p ORDER BY id"), {"p": project_id}
        ).scalars().all()
    assert actions == ["project.created", "scope.published", "scope.revoked"]
