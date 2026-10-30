"""Authentication and project authorization primitives.

API tokens look like ``wt_<prefix>_<secret>``. Only the SHA-256 digest of
the full token is stored; the prefix is stored in clear text so a token can
be identified in listings and logs without revealing it. Tokens carry 256
bits of randomness, so a fast hash is appropriate and no pepper is needed.

Principals act within a project through a ``ProjectRole``. ``ProjectContext``
is what request handlers and services receive after authentication. Pass it
to ``require`` before acting.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass
from enum import StrEnum
from uuid import UUID

from watchtower.domain.errors import AuthenticationFailed, PermissionDenied

TOKEN_PREFIX = "wt"
_TOKEN_PATTERN = re.compile(r"wt_([A-Za-z0-9]{8})_([A-Za-z0-9_-]{43})\Z")


class Permission(StrEnum):
    VIEW = "view"  # read inventory, findings and scope
    OPERATE = "operate"  # queue jobs, triage findings
    MANAGE_SCOPE = "manage_scope"  # publish and revoke scope revisions
    MANAGE_PROJECT = "manage_project"  # memberships, tokens, archive


class ProjectRole(StrEnum):
    VIEWER = "viewer"
    OPERATOR = "operator"
    OWNER = "owner"


ROLE_PERMISSIONS: dict[ProjectRole, frozenset[Permission]] = {
    ProjectRole.VIEWER: frozenset({Permission.VIEW}),
    ProjectRole.OPERATOR: frozenset({Permission.VIEW, Permission.OPERATE}),
    ProjectRole.OWNER: frozenset(Permission),
}


class PrincipalKind(StrEnum):
    USER = "user"
    SERVICE = "service"


@dataclass(frozen=True, slots=True)
class Principal:
    id: UUID
    kind: PrincipalKind
    display_name: str
    email: str | None = None
    disabled: bool = False


@dataclass(frozen=True, slots=True)
class ProjectContext:
    """An authenticated principal acting in one project with one role."""

    project_id: UUID
    principal: Principal
    role: ProjectRole

    def can(self, permission: Permission) -> bool:
        return not self.principal.disabled and permission in ROLE_PERMISSIONS[self.role]

    def require(self, permission: Permission) -> None:
        if not self.can(permission):
            raise PermissionDenied(f"{self.role} role lacks {permission} in project {self.project_id}")


@dataclass(frozen=True, slots=True)
class IssuedToken:
    """Returned once at creation; ``secret`` is never stored or retrievable again."""

    token_id: UUID
    prefix: str
    secret: str


def generate_token() -> tuple[str, str, str]:
    """Return ``(token, prefix, digest)``. Store only the prefix and digest."""
    prefix = "".join(secrets.choice("ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789") for _ in range(8))
    token = f"{TOKEN_PREFIX}_{prefix}_{secrets.token_urlsafe(32)}"
    return token, prefix, hash_token(token)


def parse_token(token: str) -> str:
    """Validate a presented token's shape and return its prefix."""
    match = _TOKEN_PATTERN.match(token or "")
    if match is None:
        raise AuthenticationFailed("malformed API token")
    return match.group(1)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def token_matches(token: str, digest: str) -> bool:
    return hmac.compare_digest(hash_token(token), digest)
