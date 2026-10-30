"""Reviewed checks loaded from the pinned rule manifest."""

from __future__ import annotations

from watchtower.adapters.checks.base import (
    Authorizer, CheckResult, Endpoint, Fetcher, Outcome, deny_all, scope_authorizer,
)
from watchtower.adapters.checks.component import VulnerableComponentCheck
from watchtower.adapters.checks.http import HttpRuleCheck, requests_fetcher
from watchtower.adapters.checks.manifest import RuleIntegrityError, RuleSet, load_manifest


def build_checks(ruleset: RuleSet, fetch: Fetcher = requests_fetcher, authorize: Authorizer = deny_all,
                 ) -> tuple[dict[str, HttpRuleCheck], dict[str, VulnerableComponentCheck]]:
    """Build every pinned check. Without an authorizer, HTTP checks refuse to send anything."""
    http = {rule.id: HttpRuleCheck(rule, fetch, authorize) for rule in ruleset if rule.kind == "http"}
    component = {rule.id: VulnerableComponentCheck(rule) for rule in ruleset if rule.kind == "component"}
    return http, component


__all__ = [
    "CheckResult", "Endpoint", "HttpRuleCheck", "Outcome", "RuleIntegrityError", "RuleSet",
    "VulnerableComponentCheck", "build_checks", "load_manifest", "scope_authorizer",
]
