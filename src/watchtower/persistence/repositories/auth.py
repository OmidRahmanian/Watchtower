"""Principals, project memberships and API tokens."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import timedelta
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import Connection, func, select
from sqlalchemy.dialects.postgresql import insert

from watchtower.domain.errors import AuthenticationFailed, NotFound, PermissionDenied
from watchtower.persistence.repositories.audit import record_audit
from watchtower.persistence.tables import api_tokens, principals, project_memberships
from watchtower.security.auth import (
    IssuedToken,
    Principal,
    PrincipalKind,
    ProjectContext,
    ProjectRole,
    generate_token,
    hash_token,
    parse_token,
    token_matches,
)


def _principal(row: Any) -> Principal:
    return Principal(
        id=row.id,
        kind=PrincipalKind(row.kind),
        display_name=row.display_name,
        email=row.email,
        disabled=row.disabled_at is not None,
    )


class PgAuthRepository:
    """Authentication runs before any project is selected, so it is system-scoped."""

    def __init__(self, connection: Connection) -> None:
        self._conn = connection

    def create_principal(
        self, display_name: str, *, kind: PrincipalKind = PrincipalKind.USER, email: str | None = None
    ) -> Principal:
        row = self._conn.execute(
            principals.insert()
            .values(
                id=uuid4(),
                kind=PrincipalKind(kind).value,
                display_name=display_name,
                email=email.strip().lower() if email else None,
            )
            .returning(*principals.c)
        ).one()
        record_audit(self._conn, "principal.created", f"principal:{row.id}")
        return _principal(row)

    def get_principal(self, principal_id: UUID) -> Principal | None:
        row = self._conn.execute(select(principals).where(principals.c.id == principal_id)).one_or_none()
        return _principal(row) if row else None

    def disable_principal(self, principal_id: UUID) -> None:
        self._conn.execute(
            principals.update()
            .where(principals.c.id == principal_id, principals.c.disabled_at.is_(None))
            .values(disabled_at=func.now())
        )
        record_audit(self._conn, "principal.disabled", f"principal:{principal_id}")

    def set_membership(
        self, project_id: UUID, principal_id: UUID, role: ProjectRole, *, actor: UUID | None = None
    ) -> None:
        statement = insert(project_memberships).values(
            project_id=project_id, principal_id=principal_id, role=ProjectRole(role).value
        )
        self._conn.execute(
            statement.on_conflict_do_update(
                index_elements=[project_memberships.c.project_id, project_memberships.c.principal_id],
                set_={"role": statement.excluded.role},
            )
        )
        record_audit(
            self._conn, "membership.set", f"principal:{principal_id}", project_id=project_id, actor=actor,
            details={"role": ProjectRole(role).value},
        )

    def remove_membership(self, project_id: UUID, principal_id: UUID, *, actor: UUID | None = None) -> None:
        self._conn.execute(
            project_memberships.delete().where(
                project_memberships.c.project_id == project_id,
                project_memberships.c.principal_id == principal_id,
            )
        )
        record_audit(self._conn, "membership.removed", f"principal:{principal_id}", project_id=project_id, actor=actor)

    def memberships(self, principal_id: UUID) -> Sequence[tuple[UUID, ProjectRole]]:
        rows = self._conn.execute(
            select(project_memberships.c.project_id, project_memberships.c.role).where(
                project_memberships.c.principal_id == principal_id
            )
        )
        return [(row.project_id, ProjectRole(row.role)) for row in rows]

    def issue_token(
        self,
        principal_id: UUID,
        name: str,
        *,
        project_id: UUID | None = None,
        ttl_days: int | None = 90,
        actor: UUID | None = None,
    ) -> IssuedToken:
        """Create a token, optionally restricted to one project. The secret is returned once."""
        secret, prefix, digest = generate_token()
        token_id = uuid4()
        self._conn.execute(
            api_tokens.insert().values(
                id=token_id,
                principal_id=principal_id,
                project_id=project_id,
                name=name,
                prefix=prefix,
                token_hash=digest,
                expires_at=None if ttl_days is None else func.now() + timedelta(days=ttl_days),
            )
        )
        record_audit(
            self._conn, "token.issued", f"token:{token_id}", project_id=project_id, actor=actor,
            details={"principal": str(principal_id), "prefix": prefix},
        )
        return IssuedToken(token_id=token_id, prefix=prefix, secret=secret)

    def revoke_token(self, token_id: UUID, *, actor: UUID | None = None) -> None:
        result = self._conn.execute(
            api_tokens.update()
            .where(api_tokens.c.id == token_id, api_tokens.c.revoked_at.is_(None))
            .values(revoked_at=func.now())
        )
        if result.rowcount != 1:
            raise NotFound(f"active token {token_id} not found")
        record_audit(self._conn, "token.revoked", f"token:{token_id}", actor=actor)

    def authenticate(self, token: str) -> tuple[Principal, UUID | None]:
        """Return the principal and the project the token is restricted to, if any."""
        prefix = parse_token(token)
        row = self._conn.execute(
            select(api_tokens, principals.c.disabled_at.label("principal_disabled_at"))
            .join(principals, principals.c.id == api_tokens.c.principal_id)
            .where(api_tokens.c.prefix == prefix)
        ).one_or_none()
        # Hash even when no row matches so timing does not reveal valid prefixes.
        if row is None or not token_matches(token, row.token_hash):
            hash_token(token)
            raise AuthenticationFailed("invalid API token")
        if row.revoked_at is not None:
            raise AuthenticationFailed("API token has been revoked")
        now = self._conn.execute(select(func.now())).scalar_one()
        if row.expires_at is not None and row.expires_at <= now:
            raise AuthenticationFailed("API token has expired")
        if row.principal_disabled_at is not None:
            raise AuthenticationFailed("principal is disabled")
        self._conn.execute(api_tokens.update().where(api_tokens.c.id == row.id).values(last_used_at=func.now()))
        principal = self.get_principal(row.principal_id)
        assert principal is not None
        return principal, row.project_id

    def project_context(self, token: str, project_id: UUID) -> ProjectContext:
        """Authenticate ``token`` and resolve its role in ``project_id``."""
        principal, restricted_to = self.authenticate(token)
        if restricted_to is not None and restricted_to != project_id:
            raise PermissionDenied("API token is restricted to a different project")
        row = self._conn.execute(
            select(project_memberships.c.role).where(
                project_memberships.c.project_id == project_id,
                project_memberships.c.principal_id == principal.id,
            )
        ).one_or_none()
        if row is None:
            raise PermissionDenied("principal is not a member of this project")
        return ProjectContext(project_id=project_id, principal=principal, role=ProjectRole(row.role))
