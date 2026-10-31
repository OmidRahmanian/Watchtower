"""Projects and immutable scope revisions."""

from __future__ import annotations

import re
from dataclasses import asdict
from collections.abc import Sequence
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import Connection, func, select

from watchtower.domain.errors import InvalidScopeRule, NotFound
from watchtower.domain.models import Project
from watchtower.domain.scope import (
    AuthorizationReference,
    NewScopeRevision,
    PortSet,
    Revocation,
    RuleEffect,
    RuleKind,
    ScopeRevision,
    ScopeRule,
    ScopeExecution,
)
from watchtower.persistence.repositories.audit import record_audit
from watchtower.persistence.repositories.records import _ProjectRepository
from watchtower.persistence.tables import projects, scope_revisions, scope_revocations, scope_rules

SLUG_PATTERN = re.compile(r"[a-z0-9][a-z0-9-]{0,62}\Z")


def _project(row: Any) -> Project:
    return Project(id=row.id, slug=row.slug, name=row.name, created_at=row.created_at, archived_at=row.archived_at)


class PgProjectRepository:
    """Projects are global records; access to their contents is what is isolated."""

    def __init__(self, connection: Connection) -> None:
        self._conn = connection

    def create(self, slug: str, name: str) -> Project:
        if not SLUG_PATTERN.match(slug):
            raise ValueError("project slug must be 1-63 lowercase letters, digits or hyphens")
        row = self._conn.execute(
            projects.insert().values(id=uuid4(), slug=slug, name=name.strip() or slug).returning(*projects.c)
        ).one()
        record_audit(self._conn, "project.created", f"project:{row.id}", project_id=row.id, details={"slug": slug})
        return _project(row)

    def get(self, project_id: UUID) -> Project | None:
        row = self._conn.execute(select(projects).where(projects.c.id == project_id)).one_or_none()
        return _project(row) if row else None

    def get_by_slug(self, slug: str) -> Project | None:
        row = self._conn.execute(select(projects).where(projects.c.slug == slug)).one_or_none()
        return _project(row) if row else None

    def list(self, *, include_archived: bool = False) -> Sequence[Project]:
        query = select(projects).order_by(projects.c.slug)
        if not include_archived:
            query = query.where(projects.c.archived_at.is_(None))
        return [_project(row) for row in self._conn.execute(query)]

    def archive(self, project_id: UUID) -> Project:
        row = self._conn.execute(
            projects.update()
            .where(projects.c.id == project_id)
            .values(archived_at=func.coalesce(projects.c.archived_at, func.now()))
            .returning(*projects.c)
        ).one_or_none()
        if row is None:
            raise NotFound(f"project {project_id} not found")
        record_audit(self._conn, "project.archived", f"project:{project_id}", project_id=project_id)
        return _project(row)


class PgScopeRepository(_ProjectRepository):
    def current(self) -> ScopeRevision | None:
        row = self._conn.execute(
            select(scope_revisions)
            .where(self._mine(scope_revisions))
            .order_by(scope_revisions.c.number.desc())
            .limit(1)
        ).one_or_none()
        return self._load(row) if row else None

    def get(self, revision_id: UUID) -> ScopeRevision | None:
        row = self._conn.execute(
            select(scope_revisions).where(self._mine(scope_revisions), scope_revisions.c.id == revision_id)
        ).one_or_none()
        return self._load(row) if row else None

    def history(self) -> Sequence[ScopeRevision]:
        rows = self._conn.execute(
            select(scope_revisions).where(self._mine(scope_revisions)).order_by(scope_revisions.c.number.desc())
        )
        return [self._load(row) for row in rows]

    def publish(self, new: NewScopeRevision, *, created_by: UUID | None) -> ScopeRevision:
        # Locking the project row serializes publishers so revision numbers stay gapless.
        locked = self._conn.execute(
            select(projects.c.archived_at).where(projects.c.id == self.project_id).with_for_update()
        ).one_or_none()
        if locked is None:
            raise NotFound(f"project {self.project_id} not found")
        if locked.archived_at is not None:
            raise InvalidScopeRule("cannot publish scope for an archived project")
        number = self._conn.execute(
            select(func.coalesce(func.max(scope_revisions.c.number), 0) + 1).where(self._mine(scope_revisions))
        ).scalar_one()
        auth = new.authorization
        revision_id = uuid4()
        self._conn.execute(
            scope_revisions.insert().values(
                id=revision_id,
                project_id=self.project_id,
                number=number,
                authorization_kind=auth.kind.value,
                authorization_reference=auth.reference,
                granted_by=auth.granted_by,
                valid_from=auth.valid_from,
                valid_until=auth.valid_until,
                permitted_ports=str(new.permitted_ports),
                notes=new.notes,
                execution_policy=asdict(new.execution_policy),
                created_by=created_by,
            )
        )
        if new.rules:
            self._conn.execute(
                scope_rules.insert(),
                [
                    {
                        "id": uuid4(),
                        "project_id": self.project_id,
                        "revision_id": revision_id,
                        "ordinal": ordinal,
                        "effect": rule.effect.value,
                        "kind": rule.kind.value,
                        "value": rule.value,
                        "ports": None if rule.ports is None else str(rule.ports),
                        "note": rule.note,
                    }
                    for ordinal, rule in enumerate(new.rules)
                ],
            )
        record_audit(
            self._conn,
            "scope.published",
            f"scope_revision:{revision_id}",
            project_id=self.project_id,
            actor=created_by,
            details={"number": number, "rules": len(new.rules), "authorization": auth.reference},
        )
        published = self.get(revision_id)
        assert published is not None
        return published

    def revoke(self, revision_id: UUID, *, reason: str, revoked_by: UUID | None) -> ScopeRevision:
        if not reason.strip():
            raise InvalidScopeRule("a revocation needs a reason")
        existing = self.get(revision_id)
        if existing is None:
            raise NotFound(f"scope revision {revision_id} not found")
        if existing.revocation is not None:
            raise InvalidScopeRule(f"scope revision {existing.number} is already revoked")
        self._conn.execute(
            scope_revocations.insert().values(
                revision_id=revision_id, project_id=self.project_id, revoked_by=revoked_by, reason=reason
            )
        )
        record_audit(
            self._conn,
            "scope.revoked",
            f"scope_revision:{revision_id}",
            project_id=self.project_id,
            actor=revoked_by,
            details={"reason": reason},
        )
        revoked = self.get(revision_id)
        assert revoked is not None
        return revoked

    def _load(self, row: Any) -> ScopeRevision:
        rules = self._conn.execute(
            select(scope_rules)
            .where(self._mine(scope_rules), scope_rules.c.revision_id == row.id)
            .order_by(scope_rules.c.ordinal)
        )
        revocation = self._conn.execute(
            select(scope_revocations).where(
                self._mine(scope_revocations), scope_revocations.c.revision_id == row.id
            )
        ).one_or_none()
        return ScopeRevision(
            id=row.id,
            project_id=row.project_id,
            number=row.number,
            rules=tuple(
                ScopeRule(
                    effect=RuleEffect(rule.effect),
                    kind=RuleKind(rule.kind),
                    value=rule.value,
                    ports=None if rule.ports is None else PortSet.parse(rule.ports),
                    note=rule.note,
                    id=rule.id,
                )
                for rule in rules
            ),
            authorization=AuthorizationReference(
                kind=row.authorization_kind,
                reference=row.authorization_reference,
                granted_by=row.granted_by,
                valid_from=row.valid_from,
                valid_until=row.valid_until,
            ),
            permitted_ports=PortSet.parse(row.permitted_ports),
            created_at=row.created_at,
            created_by=row.created_by,
            notes=row.notes,
            execution_policy=ScopeExecution(**row.execution_policy),
            revocation=None
            if revocation is None
            else Revocation(revoked_at=revocation.revoked_at, reason=revocation.reason, revoked_by=revocation.revoked_by),
        )
