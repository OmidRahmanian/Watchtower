"""DNS collection with wildcard detection.

Each name is checked against the scope policy before it is queried. Wildcard
zones are fingerprinted by resolving random labels under the parent name; a
name whose answers fall inside that fingerprint is flagged so the inventory
does not create an asset for it.
"""
from __future__ import annotations

import secrets
import string
from collections.abc import Callable, Iterable
from datetime import datetime
from typing import Any, Protocol

from watchtower.adapters.probing.guard import ScopeGuard, explain
from watchtower.services.inventory import in_domain, isoformat, normalize_hostname, utcnow

RECORD_TYPES = ("A", "AAAA", "CNAME")


class NXDomain(Exception):
    pass


class NoAnswer(Exception):
    pass


class DnsFailure(Exception):
    pass


class Resolver(Protocol):
    def query(self, name: str, rdtype: str) -> list[str]:
        """Return answers as text; raise NXDomain, NoAnswer, or DnsFailure."""


class DnsPythonResolver:
    """dnspython-backed resolver with per-query timeouts."""

    def __init__(self, nameservers: list[str] | None = None, *, timeout: float = 3.0, lifetime: float = 6.0) -> None:
        import dns.resolver

        self._dns = dns
        self._resolver = dns.resolver.Resolver(configure=nameservers is None)
        if nameservers is not None:
            self._resolver.nameservers = list(nameservers)
        self._resolver.timeout = timeout
        self._resolver.lifetime = lifetime

    def query(self, name: str, rdtype: str) -> list[str]:
        resolver = self._dns.resolver
        try:
            answer = self._resolver.resolve(name, rdtype, search=False)
        except resolver.NXDOMAIN as exc:
            raise NXDomain(name) from exc
        except resolver.NoAnswer as exc:
            raise NoAnswer(name) from exc
        except (resolver.NoNameservers, resolver.LifetimeTimeout, self._dns.exception.DNSException) as exc:
            raise DnsFailure(f"{type(exc).__name__}: {exc}") from exc
        return sorted(rdata.to_text().rstrip(".").lower() for rdata in answer)


def random_label() -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "wt-" + "".join(secrets.choice(alphabet) for _ in range(16))


class DnsCollector:
    def __init__(
        self,
        guard: ScopeGuard,
        resolver: Resolver | None = None,
        *,
        clock: Callable[[], datetime] = utcnow,
        label_factory: Callable[[], str] = random_label,
        wildcard_probes: int = 2,
    ) -> None:
        self.guard = guard
        self.resolver = resolver if resolver is not None else DnsPythonResolver()
        self._clock = clock
        self._label = label_factory
        self._wildcard_probes = wildcard_probes
        self._wildcards: dict[str, dict[str, Any] | None] = {}

    def _answers(self, name: str) -> dict[str, Any]:
        """Resolve A, AAAA and CNAME. NXDOMAIN on any type ends the lookup."""
        result: dict[str, Any] = {"status": "no_answer", "a": [], "aaaa": [], "cname": [], "error": ""}
        for rdtype in RECORD_TYPES:
            decision = self.guard.check_target(name, port=None)
            if not decision:
                return {**result, "status": "unauthorized", "error": explain(decision)}
            permit = getattr(self.guard, "request_permit", None)
            if permit is not None:
                decision = permit(name)
                if not decision:
                    return {**result, "status": "unauthorized", "error": explain(decision)}
            try:
                result[rdtype.lower()] = self.resolver.query(name, rdtype)
            except NXDomain:
                return {**result, "status": "nxdomain"}
            except NoAnswer:
                continue
            except DnsFailure as exc:
                result["status"] = "error"
                result["error"] = str(exc)
        if result["a"] or result["aaaa"] or result["cname"]:
            result["status"] = "resolved"
        return result

    def wildcard_for(self, parent: str) -> dict[str, Any] | None:
        """Fingerprint of a wildcard under `parent`, or None when there is none.

        An inconclusive check (probe refused by scope or a resolver failure)
        returns `{"unknown": True}` and is not cached, so it is retried later.
        """
        if parent in self._wildcards:
            return self._wildcards[parent]
        addresses: set[str] = set()
        cnames: set[str] = set()
        for _ in range(self._wildcard_probes):
            probe = f"{self._label()}.{parent}"
            if not self.guard.check_target(probe, port=None):
                return {"parent": parent, "unknown": True}
            answers = self._answers(probe)
            if answers["status"] == "error":
                return {"parent": parent, "unknown": True}
            if answers["status"] != "resolved":
                self._wildcards[parent] = None
                return None
            addresses.update(answers["a"] + answers["aaaa"])
            cnames.update(answers["cname"])
        fingerprint = {"parent": parent, "addresses": sorted(addresses), "cnames": sorted(cnames)}
        self._wildcards[parent] = fingerprint
        return fingerprint

    def lookup(self, hostname: str, *, root_domain: str = "") -> dict[str, Any]:
        hostname = normalize_hostname(hostname)
        observation: dict[str, Any] = {
            "hostname": hostname,
            "observed_at": isoformat(self._clock()),
            "status": "",
            "a": [],
            "aaaa": [],
            "cname": [],
            "wildcard": False,
            "wildcard_unknown": False,
            "wildcard_parent": "",
            "error": "",
        }
        decision = self.guard.check_target(hostname, port=None)
        if not decision:
            return {**observation, "status": "unauthorized", "error": explain(decision)}

        observation.update(self._answers(hostname))
        parent = hostname.partition(".")[2]
        root = normalize_hostname(root_domain) if root_domain else ""
        checkable = parent.count(".") >= 1 and (not root or in_domain(parent, root))
        if observation["status"] == "resolved" and checkable:
            wildcard = self.wildcard_for(parent)
            if wildcard and wildcard.get("unknown"):
                observation["wildcard_unknown"] = True
                observation["wildcard_parent"] = parent
            elif wildcard and _matches(observation, wildcard):
                observation["wildcard"] = True
                observation["wildcard_parent"] = parent
        return observation

    def collect(self, hostnames: Iterable[str], *, root_domain: str = "") -> list[dict[str, Any]]:
        observations = []
        for hostname in dict.fromkeys(hostnames):
            try:
                observations.append(self.lookup(hostname, root_domain=root_domain))
            except ValueError:
                continue
        return observations


def _matches(observation: dict[str, Any], wildcard: dict[str, Any]) -> bool:
    addresses = set(observation["a"] + observation["aaaa"])
    if observation["cname"] and set(observation["cname"]) <= set(wildcard["cnames"]):
        return True
    return bool(addresses) and addresses <= set(wildcard["addresses"])
