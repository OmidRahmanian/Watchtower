"""Reviewed checks loaded from the pinned rule manifest."""

from __future__ import annotations

from watchtower.adapters.checks.base import (
    Authorization, Authorizer, CheckResult, Endpoint, Fetcher, Outcome, deny_all, scope_authorizer,
)
from watchtower.adapters.checks.component import VulnerableComponentCheck
from watchtower.adapters.checks.http import HttpRuleCheck, pinned_fetcher
from watchtower.adapters.checks.manifest import RuleIntegrityError, RuleNotApproved, RuleSet, load_manifest


def build_checks(ruleset: RuleSet, fetch: Fetcher = pinned_fetcher, authorize: Authorizer = deny_all,
                 ) -> tuple[dict[str, HttpRuleCheck], dict[str, VulnerableComponentCheck]]:
    """Build every pinned check; this is the entry point for workers.

    Without an authorizer, HTTP checks refuse to send anything. Checks for rules
    still pending maintainer approval are built so they can be listed, but
    running one raises ``RuleNotApproved``; ``ruleset.pending`` names them.
    """
    http = {rule.id: HttpRuleCheck(rule, fetch, authorize) for rule in ruleset if rule.kind == "http"}
    component = {rule.id: VulnerableComponentCheck(rule) for rule in ruleset if rule.kind == "component"}
    return http, component


__all__ = [
    "Authorization", "CheckResult", "Endpoint", "HttpRuleCheck", "Outcome", "RuleIntegrityError",
    "RuleNotApproved", "RuleSet", "VulnerableComponentCheck", "build_checks", "load_manifest", "pinned_fetcher",
    "scope_authorizer",
]
