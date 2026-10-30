"""Vulnerable-component checks derived from disclosed software versions.

This check sends no traffic of its own. It reads the observations of its
pinned source rule (for example the ``Server`` header) and matches them to
advisories. Like HTTP checks, it refuses to evaluate while its rule is
pending maintainer approval. Each product and CVE pair becomes one finding variant, so the
fingerprint survives version changes inside the affected range.
"""

from __future__ import annotations

from dataclasses import replace
import re
from collections.abc import Iterable

from watchtower.adapters.checks.base import CheckResult, Outcome
from watchtower.adapters.checks.manifest import Rule
from watchtower.adapters.intelligence.applicability import Applicability, match_component
from watchtower.domain.models import Severity

TOKEN = re.compile(r"([A-Za-z][A-Za-z0-9_.-]*)/([^\s/()]+)")


def parse_banner(banner: str) -> list[tuple[str, str]]:
    banner = re.sub(r"\([^)]*\)", " ", banner or "")
    found = TOKEN.findall(banner)
    if found:
        return [(name.lower(), version) for name, version in found]
    name = banner.strip().split(" ")[0].lower()
    return [(name, "")] if name else []


def severity_for(cvss: float | None, default: Severity) -> Severity:
    if cvss is None:
        return default
    for floor, severity in ((9.0, Severity.CRITICAL), (7.0, Severity.HIGH), (4.0, Severity.MEDIUM), (0.1, Severity.LOW)):
        if cvss >= floor:
            return severity
    return Severity.INFO


class VulnerableComponentCheck:
    def __init__(self, rule: Rule):
        if rule.kind != "component":
            raise ValueError(f"{rule.id} is not a component rule")
        self.rule = rule

    def components(self, source: CheckResult) -> dict[str, str]:
        banner = source.observations.get(self.rule.definition["observation"], "")
        products = self.rule.definition["product_map"]
        return {products[name]: version for name, version in parse_banner(banner) if name in products}

    def _result(self, source: CheckResult, outcome: Outcome, product: str, advisory: dict,
                detail: str, version: str = "", applicability: str = "") -> CheckResult:
        cves = tuple(advisory.get("cves", ()))
        confidence = "tentative" if applicability == Applicability.POSSIBLE.value else self.rule.confidence
        evidence = None
        if source.evidence is not None:
            evidence = {
                "kind": "component", "check_id": self.rule.id, "rule_version": self.rule.version,
                "observed_at": source.observed_at.isoformat(), "product": product, "version": version,
                "advisory": advisory["id"], "applicability": applicability, "reason": detail,
                "source": source.evidence,
            }
        return CheckResult(
            check_id=self.rule.id, rule_version=self.rule.version, target=source.target, outcome=outcome,
            observed_at=source.observed_at, location=f"component:{product}", detail=detail,
            evidence=evidence, observations={"product": product, "version": version}, cves=cves,
            severity=severity_for(advisory.get("cvss"), self.rule.severity), confidence=confidence,
            title=f"{self.rule.title}: {advisory.get('summary') or advisory['id']}",
            variant=advisory["id"],
        )

    def _match(self, source: CheckResult, product: str, version: str, advisory: dict) -> CheckResult:
        found = match_component(product, version, advisory)
        outcome = {
            Applicability.AFFECTED: Outcome.DETECTED,
            Applicability.POSSIBLE: Outcome.DETECTED,
            Applicability.NOT_AFFECTED: Outcome.NOT_DETECTED,
            Applicability.UNKNOWN: Outcome.INCONCLUSIVE,
        }[found.applicability]
        return self._result(source, outcome, product, advisory, found.reason, version, found.applicability.value)

    def evaluate(self, source: CheckResult, advisories: Iterable[dict]) -> list[CheckResult]:
        """Match every disclosed component to every advisory for that product."""
        self.rule.require_approved()
        if source.check_id != self.rule.definition["source_rule"] or source.outcome != Outcome.DETECTED:
            return []
        components = self.components(source)
        return [self._match(source, advisory["product"], components[advisory["product"]], advisory)
                for advisory in advisories if advisory["product"] in components]

    def evaluate_variant(self, source: CheckResult, advisory: dict) -> CheckResult:
        """Retest one product and advisory pair. A hidden banner proves nothing about a fix."""
        self.rule.require_approved()
        product = advisory["product"]
        if source.check_id != self.rule.definition["source_rule"]:
            raise ValueError("source result comes from the wrong rule")
        if source.outcome == Outcome.FAILED:
            return replace(self._result(source, Outcome.FAILED, product, advisory, source.detail), evidence=None)
        components = self.components(source) if source.outcome == Outcome.DETECTED else {}
        if product not in components:
            return self._result(source, Outcome.INCONCLUSIVE, product, advisory,
                                "component is no longer disclosed, so a fix cannot be confirmed")
        return self._match(source, product, components[product], advisory)
