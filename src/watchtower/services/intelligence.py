"""Operator-controlled feed refresh, applicability review and priority updates.

Correlation sends no scanner traffic. Advisory matches are review tasks, not
confirmed CVEs. Enabling a check still requires a separate pinned human approval.
"""
from __future__ import annotations

from pathlib import Path
from uuid import UUID
from datetime import datetime, timezone
import fcntl

from watchtower.adapters.checks.component import parse_banner
from watchtower.adapters.intelligence import AdvisoryFeed, EpssFeed, IntelligenceStore, KevFeed, match_component
from watchtower.config.settings import Settings
from watchtower.domain.errors import NotFound
from watchtower.domain.models import AssetKind
from watchtower.security.auth import Permission, ProjectContext
from watchtower.services.findings import FindingRecord, FindingService, RepositoryFindingStore
from watchtower.services.prioritization import prioritize

PRODUCTS = {"apache": "apache:http_server", "nginx": "f5:nginx", "openssl": "openssl:openssl",
            "microsoft-iis": "microsoft:iis", "lighttpd": "lighttpd:lighttpd"}


def feeds(settings: Settings):
    config = settings.intelligence
    advisory = AdvisoryFeed(config.advisory_url or "operator-supplied")
    if config.advisory_file:
        def read(_):
            path = Path(config.advisory_file)
            if path.stat().st_size > 128 * 1024 * 1024:
                raise ValueError("advisory file exceeds size limit")
            return path.read_bytes()
        advisory = AdvisoryFeed("operator-supplied", transport=read)
    return (KevFeed(), EpssFeed(), advisory)


class IntelligenceService:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.store = IntelligenceStore(Path(settings.intelligence.cache_root))
        self.feeds = feeds(settings)

    def status(self):
        return [self.store.freshness(feed).to_dict() for feed in self.feeds]

    def refresh(self, source: str, *, force=False):
        feed = next((f for f in self.feeds if f.name == source), None)
        if feed is None:
            raise ValueError("unknown intelligence source")
        if source == "advisories" and not (self.settings.intelligence.advisory_file or self.settings.intelligence.advisory_url):
            raise ValueError("configure intelligence.advisory_file or intelligence.advisory_url first")
        self.store.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        with (self.store.root / ("." + source + ".lock")).open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            self.store._snapshots.pop(source, None)  # another process may have refreshed while this one waited
            state = self.store.freshness(feed)
            if state.last_attempt_at:
                age = (datetime.now(timezone.utc) - state.last_attempt_at).total_seconds()
                minimum = 60 if force else self.settings.intelligence.refresh_interval_seconds
                if age < minimum:
                    return {"source": source, "updated": False, "record_count": len(self.store.records(source)),
                            "error": state.last_error, "freshness": state.to_dict(),
                            "note": "cached; minimum refresh interval has not elapsed"}
            report = self.store.refresh(feed)
        return {"source": report.source, "updated": report.updated, "record_count": report.record_count,
                "error": report.error, "freshness": self.store.freshness(feed).to_dict()}

    def correlate(self, uow, *, limit=100, after_value=None):
        """A bounded page of review tasks, including unknown component versions."""
        result = []
        advisories = self.store.records("advisories")
        by_product = {}
        for advisory in advisories:
            by_product.setdefault(advisory["product"], []).append(advisory)
        assets = list(uow.assets.list(kind=AssetKind.HOSTNAME, limit=limit + 1, after_value=after_value))
        for asset in assets[:limit]:
            http = asset.attributes.get("last_http") or {}
            banners = parse_banner((http.get("headers") or {}).get("server", ""))
            components = [(PRODUCTS.get(product, product), version) for product, version in banners]
            for component in http.get("technologies") or []:
                if isinstance(component, dict) and component.get("product"):
                    components.append((component["product"], component.get("version")))
            for product, version in dict.fromkeys(components):
                for advisory in by_product.get(product, []):
                    match = match_component(product, version, advisory)
                    if match.applicability.value == "not_affected":
                        continue
                    result.append({"asset_id": str(asset.id), "asset": asset.value, "advisory_id": advisory["id"],
                                   "product": product, "version": version, "applicability": match.applicability.value,
                                   "reason": match.reason, "cves": advisory.get("cves", []),
                                   "action": "applicability_review", "evidence": "HTTP inventory technology hint; not proof of vulnerability"})
                    if len(result) >= 500:
                        # Do not silently skip the rest of an asset's matches.
                        raise ValueError("too many matches; request a smaller asset page")
        return {"items": result, "next_asset": assets[limit - 1].value if len(assets) > limit else None,
                "feeds": self.status(), "coverage": "No automatic assessment was started. Review applicability and approved checks."}

    def reprioritize(self, uow, actor: ProjectContext, finding_id: UUID):
        actor.require(Permission.OPERATE)
        finding = uow.findings.get(finding_id)
        if finding is None:
            raise NotFound("finding not found")
        record = FindingRecord.from_finding(finding)
        importance = (uow.assets.get(finding.asset_id).attributes or {}).get("importance", "normal")
        priority = prioritize(record, self.store, self.feeds[0], self.feeds[1], importance=importance)
        store = RepositoryFindingStore(uow, finding.scope_revision_id, asset_for=lambda _: finding.asset_id)
        FindingService(store).set_priority(record.fingerprint, priority)
        return priority
