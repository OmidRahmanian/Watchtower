"""Exceptions shared across WatchTower layers."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from watchtower.domain.scope import ScopeDecision


class WatchtowerError(Exception):
    """Base class for errors raised by WatchTower code."""


class InvalidTarget(WatchtowerError, ValueError):
    """A hostname, IP address, URL or port could not be parsed safely."""


class InvalidScopeRule(WatchtowerError, ValueError):
    """A scope rule or scope revision is malformed."""


class ScopeViolation(WatchtowerError):
    """An operation was attempted against a destination the scope does not authorize."""

    def __init__(self, decision: ScopeDecision) -> None:
        self.decision = decision
        super().__init__(f"{decision.reason.value}: {decision.detail}")


class NotFound(WatchtowerError, LookupError):
    """A record does not exist, or exists in a different project."""


class AuthenticationFailed(WatchtowerError):
    """Credentials are missing, malformed, expired or revoked."""


class PermissionDenied(WatchtowerError):
    """An authenticated principal lacks the permission for an action."""
