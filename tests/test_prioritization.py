from datetime import datetime, timedelta, UTC
import json
from pathlib import Path
import tempfile
import unittest

from checks_support import allow, approved_ruleset
from watchtower.adapters.checks import Endpoint, build_checks
from watchtower.adapters.checks.base import HttpResponse
from watchtower.adapters.intelligence import EpssFeed, IntelligenceStore, KevFeed
from watchtower.domain.models import FindingStatus, Severity
from watchtower.services.findings import FindingService
from watchtower.services.prioritization import prioritize

FIXTURES = Path(__file__).parent / "fixtures"
NOW = datetime(2026, 10, 30, 12, tzinfo=UTC)
ADVISORIES = json.loads((FIXTURES / "advisories.json").read_text())["advisories"]


def serve(path):
    return lambda url: (FIXTURES / path).read_bytes()


class PrioritizationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.store = IntelligenceStore(Path(self.temporary.name))
        self.kev = KevFeed(transport=serve("kev.json"))
        self.epss = EpssFeed(transport=serve("epss.csv"))
        self.store.refresh(self.kev, NOW)
        self.store.refresh(self.epss, NOW)
        self.ruleset = approved_ruleset()
        self.service = FindingService(canonical_id=self.ruleset.canonical_id)

    def component_finding(self, banner, variant="CVE-2021-41773"):
        fetch = lambda method, url, ip: HttpResponse(200, (("Server", banner),))
        http, component = build_checks(self.ruleset, fetch, allow("203.0.113.10"))
        source = http["server-version-disclosure"].run(Endpoint("shop.example.com"), NOW)
        results = component["vulnerable-component"].evaluate(source, ADVISORIES)
        return self.service.ingest(next(r for r in results if r.variant == variant))

    def explain(self, priority):
        return {item["factor"]: item for item in priority["factors"]}

    def test_kev_listed_affected_component_is_p1_with_reasons(self):
        finding = self.component_finding("Apache/2.4.49 (Unix)")
        priority = prioritize(finding, self.store, self.kev, self.epss, NOW)
        self.assertEqual((priority["level"], priority["applicability"]), ("P1", "affected"))
        factors = self.explain(priority)
        self.assertIn("CISA KEV", factors["kev"]["detail"])
        self.assertIn("ransomware", factors["kev_ransomware"]["detail"])
        self.assertIn("EPSS 0.944", factors["epss"]["detail"])
        self.assertEqual(priority["score"], sum(item["points"] for item in priority["factors"]))
        self.assertEqual(priority["intelligence"]["kev"]["state"], "fresh")

    def test_backported_build_is_capped_by_tentative_applicability(self):
        finding = self.component_finding("Apache/2.4.49-1ubuntu1")
        priority = prioritize(finding, self.store, self.kev, self.epss, NOW)
        self.assertEqual((priority["level"], priority["applicability"]), ("P2", "possible"))
        self.assertIn("backported", self.explain(priority)["applicability_cap"]["detail"])

    def test_priority_does_not_touch_severity_confidence_status_or_detection(self):
        finding = self.component_finding("Apache/2.4.49")
        before = (finding.severity, finding.confidence, finding.status, finding.detection.state)
        self.service.set_priority(finding.fingerprint, prioritize(finding, self.store, self.kev, self.epss, NOW))
        self.assertEqual((finding.severity, finding.confidence, finding.status, finding.detection.state), before)
        self.assertEqual(before[:3], (Severity.HIGH, "firm", FindingStatus.OPEN))
        self.assertEqual(finding.priority["level"], "P1")

    def test_stale_and_missing_intelligence_is_disclosed(self):
        finding = self.component_finding("Apache/2.4.49")
        self.store.refresh(KevFeed(transport=lambda url: (_ for _ in ()).throw(OSError("down"))),
                           NOW + timedelta(days=3))
        priority = prioritize(finding, self.store, self.kev, self.epss, NOW + timedelta(days=3))
        factors = self.explain(priority)
        self.assertIn("KEV data stale", factors["kev_freshness"]["detail"])
        self.assertEqual(priority["level"], "P1")
        self.assertEqual(priority["intelligence"]["kev"]["last_error"], "OSError: down")

        empty = IntelligenceStore(Path(self.temporary.name) / "empty")
        priority = prioritize(finding, empty, self.kev, self.epss, NOW)
        self.assertNotIn("kev", self.explain(priority))
        self.assertIn("missing", self.explain(priority)["kev_freshness"]["detail"])
        self.assertEqual(priority["level"], "P2")

    def test_findings_without_cves_rank_by_severity_and_confidence(self):
        fetch = lambda method, url, ip: HttpResponse(200, (), b"APP_KEY=x\nDB_PASSWORD=y\n")
        http, _ = build_checks(self.ruleset, fetch, allow("203.0.113.10"))
        finding = self.service.ingest(http["exposed-env-file"].run(Endpoint("shop.example.com"), NOW))
        priority = prioritize(finding, self.store, self.kev, self.epss, NOW)
        self.assertEqual((priority["level"], priority["score"], priority["applicability"]), ("P1", 90, None))
        self.assertEqual([item["factor"] for item in priority["factors"]], ["severity"])


if __name__ == "__main__":
    unittest.main()
