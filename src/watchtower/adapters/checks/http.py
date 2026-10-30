"""Declarative HTTP checks driven by pinned rules.

Each check sends one GET or HEAD request to an authorized URL and never
follows redirects. The socket is opened only to an address that the
authorizer approved from its own resolution of the hostname, so a DNS answer
that changes afterwards cannot redirect the request. Rules still pending
maintainer approval are refused before anything is authorized or sent. A response only counts as a negative when its status is
listed in the rule's ``negative_status``; anything else, such as rate
limiting, server errors, or a truncated body, is inconclusive.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime
import http.client
import re
import ssl
import time
from urllib.parse import urlsplit

from watchtower.adapters.checks.base import (
    DEFAULT_PORTS, Authorizer, CheckResult, Endpoint, Fetcher, HttpResponse, Outcome, deny_all, utcnow,
)
from watchtower.adapters.checks.manifest import Rule
from watchtower.adapters.probing import PinnedHTTPConnection, PinnedHTTPSConnection
from watchtower.services.evidence import http_evidence

MAX_BODY = 256 * 1024
TIMEOUT = 10
USER_AGENT = "WatchTower-checks/1"


def pinned_fetcher(method: str, url: str, ip: str) -> HttpResponse:
    """Send one request for ``url`` to ``ip`` only, with SNI and Host set to the URL's hostname.

    Certificates are verified, proxies are not used, and redirects are returned
    as responses rather than followed.
    """
    parts = urlsplit(url)
    if parts.scheme not in DEFAULT_PORTS or not parts.hostname:
        raise ValueError(f"unsupported URL: {url}")
    port = parts.port or DEFAULT_PORTS[parts.scheme]
    path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    if parts.scheme == "https":
        connection: http.client.HTTPConnection = PinnedHTTPSConnection(
            parts.hostname, ip, port, TIMEOUT, ssl.create_default_context())
    else:
        connection = PinnedHTTPConnection(parts.hostname, ip, port, TIMEOUT)
    deadline = time.monotonic() + TIMEOUT * 3
    try:
        connection.request(method, path, headers={"User-Agent": USER_AGENT, "Accept": "*/*", "Connection": "close"})
        response = connection.getresponse()
        body, truncated = bytearray(), False
        if method != "HEAD":
            while len(body) <= MAX_BODY:
                if time.monotonic() > deadline:
                    raise TimeoutError(f"body read exceeded {TIMEOUT * 3}s")
                chunk = response.read(min(65536, MAX_BODY + 1 - len(body)))
                if not chunk:
                    break
                body.extend(chunk)
            truncated = len(body) > MAX_BODY
        return HttpResponse(response.status, tuple(response.getheaders()), bytes(body[:MAX_BODY]), truncated)
    finally:
        connection.close()


def evaluate(match: dict, response: HttpResponse) -> tuple[bool, tuple[int, int] | None]:
    """Return whether every matcher passed, and the span of the first body match."""
    if "status" in match and response.status not in match["status"]:
        return False, None
    text = response.text
    span = None
    for pattern in match.get("body_all", []):
        found = re.search(pattern, text)
        if not found:
            return False, None
        span = span or found.span()
    if match.get("body_any"):
        found = next((m for m in (re.search(p, text) for p in match["body_any"]) if m), None)
        if not found:
            return False, None
        span = span or found.span()
    if any(re.search(pattern, text) for pattern in match.get("body_none", [])):
        return False, None
    for name, pattern in match.get("headers", {}).items():
        value = response.header(name)
        if value is None or not re.search(pattern, value):
            return False, None
    return True, span


def extract(rule: dict, response: HttpResponse) -> dict[str, str]:
    values = {}
    for name, source in rule.get("extract", {}).items():
        value = response.header(source["header"]) if "header" in source else None
        if value:
            values[name] = value.strip()[:256]
    return values


class HttpRuleCheck:
    def __init__(self, rule: Rule, fetch: Fetcher = pinned_fetcher, authorize: Authorizer = deny_all):
        if rule.kind != "http":
            raise ValueError(f"{rule.id} is not an HTTP rule")
        self.rule = rule
        self.fetch = fetch
        self.authorize = authorize

    def _result(self, target: Endpoint, outcome: Outcome, observed_at: datetime, **kwargs) -> CheckResult:
        definition = self.rule.definition
        return CheckResult(
            check_id=self.rule.id, rule_version=self.rule.version, target=target, outcome=outcome,
            observed_at=observed_at, location=definition["request"]["path"], cves=self.rule.cves,
            severity=self.rule.severity, confidence=self.rule.confidence, title=self.rule.title, **kwargs,
        )

    def run(self, target: Endpoint, now: datetime | None = None) -> CheckResult:
        """Run the rule once. Raises ``RuleNotApproved`` for a pending rule without sending anything."""
        self.rule.require_approved()
        now = now or utcnow()
        definition = self.rule.definition
        method = definition["request"]["method"]
        url = target.url(definition["request"]["path"])
        decision = self.authorize(url)
        addresses = tuple(getattr(decision, "addresses", ()))
        if not decision or not addresses:
            reason = getattr(decision, "detail", "") or "no approved address"
            return self._result(target, Outcome.FAILED, now, detail=f"destination not authorized: {reason}")
        target = replace(target, resolved_ip=addresses[0])
        try:
            response = self.fetch(method, url, addresses[0])
        except Exception as error:
            return self._result(target, Outcome.FAILED, now, detail=f"request failed: {type(error).__name__}")
        matched, span = evaluate(definition["match"], response)
        evidence = http_evidence(
            url, method, response, observed_at=now, check_id=self.rule.id, rule_version=self.rule.version,
            resolved_ip=target.resolved_ip, match_span=span,
            profile=definition.get("evidence", {}).get("profile", "default"),
        )
        if matched:
            outcome, detail = Outcome.DETECTED, "all matchers passed"
        elif response.truncated:
            outcome, detail = Outcome.INCONCLUSIVE, "body truncated before a full negative could be established"
        elif response.status in definition["negative_status"]:
            outcome, detail = Outcome.NOT_DETECTED, f"status {response.status} without a match"
        else:
            outcome, detail = Outcome.INCONCLUSIVE, f"status {response.status} cannot establish a negative"
        return self._result(target, outcome, now, detail=detail, evidence=evidence,
                            observations=extract(definition, response))
