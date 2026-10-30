"""Scope management and database-backed authorization decisions.

``ScopeService`` publishes and revokes scope revisions and hands out
``ScopePolicy`` objects for a project's current revision. Policies are
cached for ``ScopeSettings.policy_cache_seconds`` (a few seconds by default),
so revocation in another process takes effect within that window. Publishing
or revoking through this service clears the local cache at once.

Long-running work should call ``current_policy`` (or the ``authorize_*``
helpers) for each destination instead of holding one policy for the length of
a job.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable, Iterable
from datetime import datetime
from uuid import UUID

from watchtower.config.settings import ScopeSettings
from watchtower.domain.errors import NotFound, PermissionDenied
from watchtower.domain.scope import (
    AuthorizationReference,
    DecisionReason,
    NewScopeRevision,
    RedirectDecision,
    ScopeDecision,
    ScopePolicy,
    ScopeRevision,
    ScopeRule,
    utcnow,
)
from watchtower.domain.targets import PortSet
from watchtower.persistence.database import Database
from watchtower.security.auth import Permission, ProjectContext


class ScopeService:
    def __init__(
        self,
        database: Database,
        settings: ScopeSettings | None = None,
        *,
        clock: Callable[[], datetime] = utcnow,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._db = database
        self._settings = settings or ScopeSettings()
        self._destinations = self._settings.destination_policy()
        self._clock = clock
        self._monotonic = monotonic
        self._cache: dict[UUID, tuple[float, ScopePolicy]] = {}
        self._lock = threading.Lock()

    # -- policies ------------------------------------------------------

    def current_policy(self, project_id: UUID) -> ScopePolicy:
        """The policy for the project's newest revision; it denies everything when there is none."""
        ttl = self._settings.policy_cache_seconds
        now = self._monotonic()
        with self._lock:
            cached = self._cache.get(project_id)
            if cached is not None and now - cached[0] < ttl:
                return cached[1]
        policy = self._load_policy(project_id, None)
        if ttl > 0:
            with self._lock:
                self._cache[project_id] = (now, policy)
        return policy

    def policy_for_revision(self, project_id: UUID, revision_id: UUID) -> ScopePolicy:
        """A policy for ``revision_id`` that denies everything unless it is still current.

        Use this to check that the revision a job was queued under has not
        been superseded or revoked.
        """
        return self._load_policy(project_id, revision_id)

    def invalidate(self, project_id: UUID | None = None) -> None:
        with self._lock:
            if project_id is None:
                self._cache.clear()
            else:
                self._cache.pop(project_id, None)

    def _load_policy(self, project_id: UUID, expected_revision: UUID | None) -> ScopePolicy:
        options = {
            "destinations": self._destinations,
            "max_redirects": self._settings.max_redirects,
            "allow_https_downgrade": self._settings.allow_https_downgrade,
            "clock": self._clock,
        }
        try:
            with self._db.project(project_id) as uow:
                project = uow.get_project()
                revision = uow.scope.current()
        except NotFound:
            return ScopePolicy.deny_all(project_id, DecisionReason.NO_SCOPE, "project not found", **options)
        if project.archived:
            return ScopePolicy.deny_all(project_id, DecisionReason.PROJECT_ARCHIVED, "project is archived", **options)
        if revision is None:
            return ScopePolicy.deny_all(project_id, DecisionReason.NO_SCOPE, "no scope revision published", **options)
        if expected_revision is not None and revision.id != expected_revision:
            return ScopePolicy.deny_all(
                project_id,
                DecisionReason.SUPERSEDED,
                f"revision {expected_revision} was superseded by revision {revision.number}",
                **options,
            )
        return ScopePolicy(project_id, revision, **options)  # type: ignore[arg-type]

    # -- decisions -----------------------------------------------------

    def authorize_target(self, project_id: UUID, target: str, *, port: int | None = None) -> ScopeDecision:
        return self.current_policy(project_id).check_target(target, port=port)

    def authorize_connection(
        self, project_id: UUID, host: str, port: int, resolved_addresses: Iterable[str]
    ) -> ScopeDecision:
        return self.current_policy(project_id).check_connection(host, port, resolved_addresses)

    def authorize_url(self, project_id: UUID, url: str) -> ScopeDecision:
        return self.current_policy(project_id).check_url(url)

    def authorize_redirect(
        self, project_id: UUID, current_url: str, location: str, *, redirects_followed: int
    ) -> RedirectDecision:
        return self.current_policy(project_id).check_redirect(
            current_url, location, redirects_followed=redirects_followed
        )

    # -- management ----------------------------------------------------

    def publish(
        self,
        project_id: UUID,
        rules: Iterable[ScopeRule | str],
        authorization: AuthorizationReference,
        *,
        actor: ProjectContext | None,
        permitted_ports: PortSet | str | None = None,
        notes: str = "",
    ) -> ScopeRevision:
        """Publish a new revision; it takes effect immediately and supersedes the previous one.

        ``rules`` may be ``ScopeRule`` objects or include patterns as strings.
        ``actor`` is ``None`` only for trusted automation such as the importer.
        """
        _require(actor, project_id, Permission.MANAGE_SCOPE)
        new = NewScopeRevision(
            rules=tuple(rule if isinstance(rule, ScopeRule) else ScopeRule.parse(rule) for rule in rules),
            authorization=authorization,
            permitted_ports=PortSet.parse(permitted_ports or self._settings.default_permitted_ports),
            notes=notes,
        )
        with self._db.project(project_id) as uow:
            revision = uow.scope.publish(new, created_by=actor.principal.id if actor else None)
        self.invalidate(project_id)
        return revision

    def revoke(
        self, project_id: UUID, revision_id: UUID, *, reason: str, actor: ProjectContext | None
    ) -> ScopeRevision:
        """Revoke a revision. Revoking the current one leaves the project with no authorized scope."""
        _require(actor, project_id, Permission.MANAGE_SCOPE)
        with self._db.project(project_id) as uow:
            revision = uow.scope.revoke(revision_id, reason=reason, revoked_by=actor.principal.id if actor else None)
        self.invalidate(project_id)
        return revision

    def history(self, project_id: UUID, *, actor: ProjectContext | None) -> list[ScopeRevision]:
        _require(actor, project_id, Permission.VIEW)
        with self._db.project(project_id) as uow:
            return list(uow.scope.history())


def _require(actor: ProjectContext | None, project_id: UUID, permission: Permission) -> None:
    if actor is None:
        return
    if actor.project_id != project_id:
        raise PermissionDenied("actor context belongs to a different project")
    actor.require(permission)
