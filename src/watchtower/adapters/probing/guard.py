"""The slice of `watchtower.domain.scope.ScopePolicy` the adapters rely on.

Adapters take the project's ScopePolicy (from `ScopeService.current_policy`)
as a required argument; there is no permissive default. This Protocol names
only the calls they make, so tests can supply a narrower double.
"""
from __future__ import annotations

from collections.abc import Iterable
from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class ScopeGuard(Protocol):
    def check_target(self, target: str, *, port: int | None = None) -> Any:
        """ScopeDecision: truthy when allowed. `port=None` for name-only (passive) checks."""

    def check_connection(self, host: str, port: int, resolved_addresses: Iterable[str]) -> Any:
        """ScopeDecision for opening sockets to `resolved_addresses` on behalf of `host`."""

    def check_redirect(self, current_url: str, location: str, *, redirects_followed: int) -> Any:
        """RedirectDecision: truthy when allowed, with the absolute target in `.url`."""


def explain(decision: Any) -> str:
    """`reason: detail` from a ScopeDecision, for observations and logs."""
    reason = getattr(decision, "reason", "") or ""
    reason = getattr(reason, "value", reason)
    detail = getattr(decision, "detail", "") or ""
    return f"{reason}: {detail}" if reason and detail else str(reason or detail or "denied")
