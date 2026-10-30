"""Shared types for checks: endpoints, raw responses, and technical check outcomes.

A check reports only what it technically observed. Severity, confidence,
priority, and workflow status live on the finding and are never inferred from
the outcome alone.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import datetime, UTC
from enum import StrEnum
import socket
from typing import Any, Protocol

from watchtower.domain.models import Severity
from watchtower.domain.scope import ScopePolicy
from watchtower.domain.targets import parse_target, parse_url

DEFAULT_PORTS = {"http": 80, "https": 443}


class Outcome(StrEnum):
    DETECTED = "detected"
    NOT_DETECTED = "not_detected"
    FAILED = "failed"
    INCONCLUSIVE = "inconclusive"

    @property
    def conclusive(self) -> bool:
        return self in (Outcome.DETECTED, Outcome.NOT_DETECTED)


def utcnow() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class Endpoint:
    """A web service identified by canonical hostname (or IP), scheme, and port.

    ``resolved_ip`` is recorded with evidence but excluded from identity, so a
    hostname that moves to a new IP keeps the same findings.
    """

    host: str
    scheme: str = "https"
    port: int | None = None
    resolved_ip: str | None = field(default=None, compare=False)

    def __post_init__(self) -> None:
        scheme = self.scheme.lower()
        if scheme not in DEFAULT_PORTS:
            raise ValueError(f"unsupported scheme: {self.scheme}")
        object.__setattr__(self, "scheme", scheme)
        object.__setattr__(self, "host", parse_target(self.host).value)
        port = DEFAULT_PORTS[scheme] if self.port is None else int(self.port)
        if not 0 < port < 65536:
            raise ValueError(f"invalid port: {self.port}")
        object.__setattr__(self, "port", port)

    @property
    def identity(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        if self.port == DEFAULT_PORTS[self.scheme]:
            return f"{self.scheme}://{host}"
        return f"{self.scheme}://{host}:{self.port}"

    def url(self, path: str) -> str:
        return self.identity + path


@dataclass(frozen=True, slots=True)
class HttpResponse:
    status: int
    headers: tuple[tuple[str, str], ...]
    body: bytes = b""
    truncated: bool = False

    def header(self, name: str) -> str | None:
        name = name.lower()
        for key, value in self.headers:
            if key.lower() == name:
                return value
        return None

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")


Fetcher = Callable[[str, str], HttpResponse]


class Decision(Protocol):
    """Anything truthy when allowed; ``ScopeDecision`` satisfies this."""

    def __bool__(self) -> bool: ...


Authorizer = Callable[[str], Any]


def deny_all(url: str) -> bool:
    return False


def resolve_addresses(host: str, port: int) -> list[str]:
    return sorted({info[4][0] for info in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)})


def scope_authorizer(policy: ScopePolicy,
                     resolve: Callable[[str, int], Iterable[str]] = resolve_addresses) -> Authorizer:
    """Authorize a URL by scope, then authorize its resolved addresses.

    Redirects are never followed by checks, so ``check_redirect`` is not needed.
    """

    def authorize(url: str):
        decision = policy.check_url(url)
        if not decision:
            return decision
        parsed = parse_url(url)
        try:
            addresses = [] if parsed.host.is_ip else list(resolve(parsed.host.value, parsed.port))
        except OSError:
            addresses = []
        return policy.check_connection(parsed.host, parsed.port, addresses)

    return authorize


@dataclass(frozen=True, slots=True)
class CheckResult:
    """The technical result of one check run against one endpoint."""

    check_id: str
    rule_version: str
    target: Endpoint
    outcome: Outcome
    observed_at: datetime
    location: str = ""
    detail: str = ""
    evidence: dict | None = None
    observations: dict[str, str] = field(default_factory=dict)
    cves: tuple[str, ...] = ()
    severity: Severity = Severity.INFO
    confidence: str = "firm"
    title: str = ""
    # Variant distinguishes several findings from one check on one location,
    # such as one finding per advisory for a vulnerable component.
    variant: str = ""
