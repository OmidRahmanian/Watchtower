"""Vulnerability intelligence: KEV, EPSS, advisories, and applicability matching."""
from watchtower.adapters.intelligence.applicability import Applicability, match_component
from watchtower.adapters.intelligence.feeds import AdvisoryFeed, EpssFeed, Feed, FeedError, KevFeed, ParsedFeed
from watchtower.adapters.intelligence.store import Freshness, FreshnessState, IntelligenceStore, RefreshReport

__all__ = [
    "AdvisoryFeed", "Applicability", "EpssFeed", "Feed", "FeedError", "Freshness", "FreshnessState",
    "IntelligenceStore", "KevFeed", "ParsedFeed", "RefreshReport", "match_component",
]
