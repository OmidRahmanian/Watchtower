"""Scope rules, immutable scope revisions and the authorization engine.

A project's scope is a sequence of immutable revisions. Each revision carries
include and exclude rules, the ports it permits, and a reference to the
authorization that allows testing (a program policy, contract or owner
approval). Only the newest revision of a project is in force; revoking it
leaves the project with no authorized scope until a new revision is
published.

``ScopePolicy`` evaluates one revision and is pure: it does no I/O, so
workers can hold one for the length of a job. Every check fails closed, and
any parse error is a denial rather than an exception.

Rule semantics:

* ``example.com`` matches exactly that host; ``*.example.com`` matches any
  name strictly below it (any depth) but not ``example.com`` itself, and
  never ``badexample.com`` or ``example.com.evil.net``.
* ``10.0.0.0/24`` or a single address matches IP targets only.
* An exclude without ports removes the target entirely; an exclude with
  ports removes only those ports. Excludes always beat includes.
* When several includes match, the most specific one decides which ports
  are permitted (host > deeper wildcard > shallower wildcard; longer
  network prefix > shorter). A rule without ports uses the revision's
  ``permitted_ports``.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field, fields
from datetime import datetime, timezone
from enum import StrEnum
from urllib.parse import urljoin, unquote
import posixpath
from uuid import UUID

from watchtower.domain.errors import InvalidScopeRule, InvalidTarget, ScopeViolation
from watchtower.domain.targets import (
    IPAddress,
    IPNetwork,
    InvalidUrl,
    PortSet,
    Target,
    TargetKind,
    canonical_ip,
    canonical_port,
    parse_target,
    parse_url,
)
from watchtower.security.destinations import DestinationPolicy


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class RuleEffect(StrEnum):
    INCLUDE = "include"
    EXCLUDE = "exclude"


class RuleKind(StrEnum):
    HOST = "host"
    SUBDOMAINS = "subdomains"
    NETWORK = "network"


@dataclass(frozen=True, slots=True)
class ScopeRule:
    """One include or exclude rule. ``value`` is canonical; build rules with ``parse``."""

    effect: RuleEffect
    kind: RuleKind
    value: str
    ports: PortSet | None = None
    note: str = ""
    id: UUID | None = None
    _network: IPNetwork | None = field(default=None, init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "effect", RuleEffect(self.effect))
        object.__setattr__(self, "kind", RuleKind(self.kind))
        if self.ports is not None:
            object.__setattr__(self, "ports", PortSet.parse(self.ports))
        if self.kind is RuleKind.NETWORK:
            object.__setattr__(self, "_network", ipaddress.ip_network(self.value, strict=True))

    @classmethod
    def parse(
        cls,
        pattern: str,
        *,
        effect: RuleEffect | str = RuleEffect.INCLUDE,
        ports: PortSet | str | Iterable[int | str] | None = None,
        note: str = "",
        id: UUID | None = None,
    ) -> ScopeRule:
        """Build a rule from ``example.com``, ``*.example.com``, ``192.0.2.10`` or a CIDR."""
        if not isinstance(pattern, str) or not pattern.strip():
            raise InvalidScopeRule("scope rule pattern is empty")
        text = pattern.strip()
        try:
            port_set = None if ports is None else PortSet.parse(ports)
            if "/" in text:
                kind, value = RuleKind.NETWORK, _canonical_network(text)
            elif text.startswith("*."):
                suffix = parse_target(text[2:])
                if suffix.is_ip:
                    raise InvalidScopeRule(f"wildcards apply to hostnames, not addresses: {pattern!r}")
                if suffix.value.count(".") < 1:
                    raise InvalidScopeRule(f"wildcard covers a whole top-level domain: {pattern!r}")
                kind, value = RuleKind.SUBDOMAINS, suffix.value
            elif "*" in text:
                raise InvalidScopeRule(f"only leading '*.' wildcards are supported: {pattern!r}")
            else:
                target = parse_target(text)
                if target.ip is not None:
                    kind, value = RuleKind.NETWORK, str(ipaddress.ip_network(target.ip))
                else:
                    kind, value = RuleKind.HOST, target.value
        except InvalidTarget as exc:
            raise InvalidScopeRule(f"invalid scope rule {pattern!r}: {exc}") from None
        return cls(RuleEffect(effect), kind, value, port_set, note, id)

    @property
    def pattern(self) -> str:
        return f"*.{self.value}" if self.kind is RuleKind.SUBDOMAINS else self.value

    @property
    def network(self) -> IPNetwork | None:
        return self._network

    @property
    def specificity(self) -> tuple[int, int]:
        if self._network is not None:
            return (0, self._network.prefixlen)
        depth = self.value.count(".") + 1
        return (2, depth) if self.kind is RuleKind.HOST else (1, depth)

    def matches(self, target: Target) -> bool:
        if self._network is not None:
            return target.ip is not None and _in_network(target.ip, self._network)
        if target.kind is not TargetKind.HOSTNAME:
            return False
        if self.kind is RuleKind.HOST:
            return target.value == self.value
        return target.value.endswith("." + self.value)

    def matches_address(self, address: IPAddress) -> bool:
        return self._network is not None and _in_network(address, self._network)

    def covers_port(self, port: int | None) -> bool:
        """For excludes: whether this rule removes ``port`` (``None`` = the whole target)."""
        if self.ports is None:
            return True
        return port is not None and port in self.ports


def _canonical_network(text: str) -> str:
    try:
        network = ipaddress.ip_network(text, strict=True)
    except ValueError as exc:
        raise InvalidTarget(str(exc)) from None
    if isinstance(network, ipaddress.IPv6Network) and network.subnet_of(
        ipaddress.IPv6Network("::ffff:0:0/96")
    ):
        raise InvalidTarget("write IPv4-mapped networks in IPv4 notation")
    return str(network)


def _in_network(address: IPAddress, network: IPNetwork) -> bool:
    return address.version == network.version and address in network


class AuthorizationKind(StrEnum):
    BUG_BOUNTY_PROGRAM = "bug_bounty_program"
    VULNERABILITY_DISCLOSURE_PROGRAM = "vulnerability_disclosure_program"
    CONTRACT = "contract"
    ASSET_OWNER = "asset_owner"
    INTERNAL_APPROVAL = "internal_approval"
    LEGACY_IMPORT = "legacy_import"


@dataclass(frozen=True, slots=True)
class AuthorizationReference:
    """Who authorized testing, under what document, and for how long."""

    kind: AuthorizationKind
    reference: str
    granted_by: str
    valid_from: datetime | None = None
    valid_until: datetime | None = None
    notes: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", AuthorizationKind(self.kind))
        if not self.reference.strip():
            raise InvalidScopeRule("authorization reference is required")
        if not self.granted_by.strip():
            raise InvalidScopeRule("authorization must name who granted it")
        for moment in (self.valid_from, self.valid_until):
            if moment is not None and moment.utcoffset() is None:
                raise InvalidScopeRule("authorization dates must be timezone-aware")
        if self.valid_from and self.valid_until and self.valid_until <= self.valid_from:
            raise InvalidScopeRule("authorization ends before it starts")


@dataclass(frozen=True, slots=True)
class Revocation:
    revoked_at: datetime
    reason: str
    revoked_by: UUID | None = None


@dataclass(frozen=True, slots=True)
class ScopeExecution:
    allowed_schemes: tuple[str, ...] = ("https", "http")
    allowed_paths: tuple[str, ...] = ("/",)
    excluded_paths: tuple[str, ...] = ()
    allowed_check_kinds: tuple[str, ...] = ("http", "component")
    max_requests_per_run: int = 10000

    def __post_init__(self):
        for name in ("allowed_schemes", "allowed_paths", "excluded_paths", "allowed_check_kinds"):
            object.__setattr__(self, name, tuple(getattr(self, name)))
            if len(getattr(self, name)) > 100:
                raise InvalidScopeRule("scope execution policy has too many entries")
        if not self.allowed_schemes or set(self.allowed_schemes) - {"http", "https"}:
            raise InvalidScopeRule("scope schemes must be http and/or https")
        if set(self.allowed_check_kinds) - {"http", "component"}:
            raise InvalidScopeRule("unsupported check class")
        if not self.allowed_paths or not isinstance(self.max_requests_per_run, int) or not 1 <= self.max_requests_per_run <= 10000000:
            raise InvalidScopeRule("scope needs allowed paths and a positive bounded request budget")
        for value in (*self.allowed_paths, *self.excluded_paths):
            if not isinstance(value, str) or _scope_path(value) != (value.rstrip("/") or "/"):
                raise InvalidScopeRule("scope paths must be canonical absolute path prefixes without query strings")


def _scope_path(value):
    if not value.startswith("/") or value.startswith("//") or "?" in value or "#" in value:
        raise InvalidScopeRule("invalid scope path")
    for _ in range(4):
        decoded = unquote(value, errors="strict")
        if decoded == value:
            break
        value = decoded
    if "%" in value or "\\" in value or ";" in value or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise InvalidScopeRule("ambiguous encoded scope path")
    return posixpath.normpath(value)


@dataclass(frozen=True, slots=True)
class NewScopeRevision:
    """Input for publishing a revision; the store assigns id, number and timestamps."""

    rules: tuple[ScopeRule, ...]
    authorization: AuthorizationReference
    permitted_ports: PortSet
    notes: str = ""
    execution_policy: ScopeExecution = field(default_factory=ScopeExecution)

    def __post_init__(self) -> None:
        object.__setattr__(self, "rules", tuple(self.rules))
        object.__setattr__(self, "permitted_ports", PortSet.parse(self.permitted_ports))
        if not any(rule.effect is RuleEffect.INCLUDE for rule in self.rules):
            raise InvalidScopeRule("a scope revision needs at least one include rule")
        seen: set[tuple[RuleEffect, RuleKind, str]] = set()
        for rule in self.rules:
            key = (rule.effect, rule.kind, rule.value)
            if key in seen:
                raise InvalidScopeRule(f"duplicate {rule.effect} rule for {rule.pattern}")
            seen.add(key)


@dataclass(frozen=True, slots=True)
class ScopeRevision:
    id: UUID
    project_id: UUID
    number: int
    rules: tuple[ScopeRule, ...]
    authorization: AuthorizationReference
    permitted_ports: PortSet
    created_at: datetime
    created_by: UUID | None = None
    notes: str = ""
    revocation: Revocation | None = None
    execution_policy: ScopeExecution = field(default_factory=ScopeExecution)

    @property
    def includes(self) -> tuple[ScopeRule, ...]:
        return tuple(rule for rule in self.rules if rule.effect is RuleEffect.INCLUDE)

    @property
    def excludes(self) -> tuple[ScopeRule, ...]:
        return tuple(rule for rule in self.rules if rule.effect is RuleEffect.EXCLUDE)


class DecisionReason(StrEnum):
    ALLOWED = "allowed"
    NO_SCOPE = "no_scope"
    PROJECT_ARCHIVED = "project_archived"
    REVOKED = "revoked"
    SUPERSEDED = "superseded"
    AUTHORIZATION_NOT_YET_VALID = "authorization_not_yet_valid"
    AUTHORIZATION_EXPIRED = "authorization_expired"
    INVALID_TARGET = "invalid_target"
    NOT_IN_SCOPE = "not_in_scope"
    EXCLUDED = "excluded"
    PORT_NOT_PERMITTED = "port_not_permitted"
    PORT_REQUIRED = "port_required"
    PROHIBITED_DESTINATION = "prohibited_destination"
    UNRESOLVED = "unresolved"
    ADDRESS_MISMATCH = "address_mismatch"
    UNSUPPORTED_SCHEME = "unsupported_scheme"
    CREDENTIALS_IN_URL = "credentials_in_url"
    REDIRECT_LIMIT = "redirect_limit"
    HTTPS_DOWNGRADE = "https_downgrade"
    REQUEST_BUDGET = "request_budget_exhausted"
    PATH_NOT_PERMITTED = "path_not_permitted"


@dataclass(frozen=True, slots=True)
class ScopeDecision:
    allowed: bool
    reason: DecisionReason
    project_id: UUID
    revision_id: UUID | None
    target: str | None = None
    port: int | None = None
    matched_rule_id: UUID | None = None
    detail: str = ""

    def __bool__(self) -> bool:
        return self.allowed

    def require(self) -> ScopeDecision:
        """Return the decision when allowed; raise ``ScopeViolation`` otherwise."""
        if not self.allowed:
            raise ScopeViolation(self)
        return self


@dataclass(frozen=True, slots=True)
class RedirectDecision(ScopeDecision):
    """``url`` is the absolute redirect target, canonicalized when it parsed."""

    url: str | None = None


_URL_REASONS = {
    "scheme": DecisionReason.UNSUPPORTED_SCHEME,
    "credentials": DecisionReason.CREDENTIALS_IN_URL,
}


class ScopePolicy:
    """Evaluates targets against one scope revision; immutable and free of I/O."""

    def __init__(
        self,
        project_id: UUID,
        revision: ScopeRevision | None,
        *,
        destinations: DestinationPolicy | None = None,
        max_redirects: int = 5,
        allow_https_downgrade: bool = False,
        denial: DecisionReason | None = None,
        denial_detail: str = "",
        clock: Callable[[], datetime] = utcnow,
    ) -> None:
        if revision is not None and revision.project_id != project_id:
            raise ValueError("scope revision belongs to a different project")
        if revision is None and denial is None:
            denial = DecisionReason.NO_SCOPE
            denial_detail = denial_detail or "the project has no scope revision"
        self.project_id = project_id
        self.revision = revision
        self.execution_policy = revision.execution_policy if revision else ScopeExecution()
        self.destinations = destinations or DestinationPolicy()
        self.max_redirects = max_redirects
        self.allow_https_downgrade = allow_https_downgrade
        self._denial = denial
        self._denial_detail = denial_detail
        self._clock = clock
        self._includes: Sequence[ScopeRule] = revision.includes if revision else ()
        self._excludes: Sequence[ScopeRule] = revision.excludes if revision else ()

    @classmethod
    def deny_all(
        cls, project_id: UUID, reason: DecisionReason, detail: str, **kwargs: object
    ) -> ScopePolicy:
        return cls(project_id, None, denial=reason, denial_detail=detail, **kwargs)  # type: ignore[arg-type]

    @property
    def revision_id(self) -> UUID | None:
        return self.revision.id if self.revision else None

    # -- public checks -------------------------------------------------

    def check_target(self, target: str | Target, *, port: int | None = None) -> ScopeDecision:
        """Is ``target`` (hostname or IP) authorized, optionally on ``port``?

        Pass ``port=None`` for passive, name-only work such as querying
        certificate transparency for a domain.
        """
        blocked = self._gate()
        if blocked is not None:
            return blocked
        try:
            parsed = parse_target(target)
            port = None if port is None else canonical_port(port)
        except InvalidTarget as exc:
            return self._deny(DecisionReason.INVALID_TARGET, str(exc), target=_text(target), port=port)
        prohibited = self.destinations.check_target(parsed)
        if prohibited is not None:
            return self._deny(DecisionReason.PROHIBITED_DESTINATION, prohibited, parsed.value, port)
        return self._evaluate(parsed, port)

    def check_connection(
        self, host: str | Target, port: int, resolved_addresses: Iterable[str | IPAddress]
    ) -> ScopeDecision:
        """Authorize opening a socket to ``host:port`` at each of ``resolved_addresses``.

        Call this after DNS resolution and connect only to the addresses
        checked here. Every address must pass: one prohibited or excluded
        address denies the whole connection, which also defeats DNS
        rebinding towards internal ranges. For an IP literal host the
        address list may be empty.
        """
        if port is None:
            return self._deny(DecisionReason.PORT_REQUIRED, "connections need a port", _text(host))
        decision = self.check_target(host, port=port)
        if not decision.allowed:
            return decision
        parsed = parse_target(host)
        try:
            addresses = [canonical_ip(address) for address in resolved_addresses]
        except InvalidTarget as exc:
            return self._deny(DecisionReason.INVALID_TARGET, str(exc), parsed.value, port)
        if parsed.ip is not None:
            if any(address != parsed.ip for address in addresses):
                return self._deny(
                    DecisionReason.ADDRESS_MISMATCH,
                    f"{parsed.value} is an IP literal but other addresses were supplied",
                    parsed.value,
                    port,
                )
            addresses = [parsed.ip]
        if not addresses:
            return self._deny(DecisionReason.UNRESOLVED, f"{parsed.value} has no addresses", parsed.value, port)
        for address in addresses:
            prohibited = self.destinations.check_address(address)
            if prohibited is not None:
                return self._deny(
                    DecisionReason.PROHIBITED_DESTINATION,
                    f"{parsed.value} resolves to {prohibited}",
                    parsed.value,
                    port,
                )
            for rule in self._excludes:
                if rule.matches_address(address) and rule.covers_port(port):
                    return self._deny(
                        DecisionReason.EXCLUDED,
                        f"{parsed.value} resolves to {address}, excluded by {rule.pattern}",
                        parsed.value,
                        port,
                        rule.id,
                    )
        return decision

    def check_url(self, url: str) -> ScopeDecision:
        """Authorize an absolute http(s) URL by its host and effective port."""
        blocked = self._gate()
        if blocked is not None:
            return blocked
        try:
            parsed = parse_url(url)
        except InvalidUrl as exc:
            reason = _URL_REASONS.get(exc.code, DecisionReason.INVALID_TARGET)
            return self._deny(reason, str(exc), target=None)
        except InvalidTarget as exc:
            return self._deny(DecisionReason.INVALID_TARGET, str(exc), target=None)
        decision = self.check_target(parsed.host, port=parsed.port)
        if not decision:
            return decision
        execution = self.execution_policy
        if parsed.scheme not in execution.allowed_schemes:
            return self._deny(DecisionReason.UNSUPPORTED_SCHEME, "scheme not permitted by scope", parsed.host.value, parsed.port)
        if execution.allowed_paths != ("/",) or execution.excluded_paths:
            try:
                path = _scope_path(parsed.path or "/")
            except (InvalidScopeRule, UnicodeError):
                return self._deny(DecisionReason.PATH_NOT_PERMITTED, "ambiguous or invalid path", parsed.host.value, parsed.port)
            def matches(prefix):
                prefix = prefix.rstrip("/") or "/"
                return prefix == "/" or path == prefix or path.startswith(prefix + "/")
            if any(matches(p) for p in execution.excluded_paths) or not any(matches(p) for p in execution.allowed_paths):
                return self._deny(DecisionReason.PATH_NOT_PERMITTED, "path not permitted by scope", parsed.host.value, parsed.port)
        return decision

    def check_redirect(
        self, current_url: str, location: str, *, redirects_followed: int
    ) -> RedirectDecision:
        """Decide whether to follow ``location`` received while fetching ``current_url``.

        ``redirects_followed`` counts redirects already taken in this chain.
        An allowed decision still requires ``check_connection`` against the
        new host's resolved addresses before connecting.
        """
        blocked = self._gate()
        if blocked is not None:
            return _redirect(blocked, None)
        if redirects_followed >= self.max_redirects:
            return _redirect(
                self._deny(DecisionReason.REDIRECT_LIMIT, f"more than {self.max_redirects} redirects"),
                None,
            )
        try:
            current = parse_url(current_url)
        except InvalidTarget as exc:
            return _redirect(self._deny(DecisionReason.INVALID_TARGET, f"current URL: {exc}"), None)
        if not isinstance(location, str) or not location.strip():
            return _redirect(self._deny(DecisionReason.INVALID_TARGET, "empty Location header"), None)
        absolute = urljoin(current.geturl(), location.strip())
        decision = self.check_url(absolute)
        if not decision.allowed:
            return _redirect(decision, absolute)
        target = parse_url(absolute)
        if current.scheme == "https" and target.scheme == "http" and not self.allow_https_downgrade:
            return _redirect(
                self._deny(DecisionReason.HTTPS_DOWNGRADE, "redirect downgrades HTTPS to HTTP", target.host.value, target.port),
                target.geturl(),
            )
        return _redirect(decision, target.geturl())

    # -- internals -----------------------------------------------------

    def _gate(self) -> ScopeDecision | None:
        if self._denial is not None:
            return self._deny(self._denial, self._denial_detail)
        assert self.revision is not None
        if self.revision.revocation is not None:
            return self._deny(DecisionReason.REVOKED, f"revision {self.revision.number} was revoked: {self.revision.revocation.reason}")
        now = self._clock()
        auth = self.revision.authorization
        if auth.valid_from is not None and now < auth.valid_from:
            return self._deny(DecisionReason.AUTHORIZATION_NOT_YET_VALID, f"authorization starts {auth.valid_from.isoformat()}")
        if auth.valid_until is not None and now >= auth.valid_until:
            return self._deny(DecisionReason.AUTHORIZATION_EXPIRED, f"authorization ended {auth.valid_until.isoformat()}")
        return None

    def _evaluate(self, target: Target, port: int | None) -> ScopeDecision:
        for rule in self._excludes:
            if rule.matches(target) and rule.covers_port(port):
                return self._deny(DecisionReason.EXCLUDED, f"excluded by {rule.pattern}", target.value, port, rule.id)
        matching = [rule for rule in self._includes if rule.matches(target)]
        if not matching:
            return self._deny(DecisionReason.NOT_IN_SCOPE, f"{target.value} matches no include rule", target.value, port)
        best = max(matching, key=lambda rule: rule.specificity)
        assert self.revision is not None
        permitted = best.ports or self.revision.permitted_ports
        if port is not None and port not in permitted:
            return self._deny(
                DecisionReason.PORT_NOT_PERMITTED,
                f"port {port} is not in {permitted} for {best.pattern}",
                target.value,
                port,
                best.id,
            )
        return ScopeDecision(
            True, DecisionReason.ALLOWED, self.project_id, self.revision_id, target.value, port, best.id,
            f"included by {best.pattern}",
        )

    def _deny(
        self,
        reason: DecisionReason,
        detail: str,
        target: str | None = None,
        port: int | None = None,
        rule_id: UUID | None = None,
    ) -> ScopeDecision:
        return ScopeDecision(False, reason, self.project_id, self.revision_id, target, port, rule_id, detail)


def _redirect(decision: ScopeDecision, url: str | None) -> RedirectDecision:
    values = {f.name: getattr(decision, f.name) for f in fields(ScopeDecision)}
    return RedirectDecision(**values, url=url)


def _text(value: object) -> str | None:
    return value if isinstance(value, str) else str(value) if isinstance(value, Target) else None
