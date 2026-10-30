from datetime import datetime, timedelta, UTC
import gzip
import json
from pathlib import Path
import tempfile
import unittest

from watchtower.adapters.intelligence import (
    AdvisoryFeed, Applicability, EpssFeed, FeedError, FreshnessState, IntelligenceStore, KevFeed, match_component,
)
from watchtower.adapters.intelligence.applicability import parse_version

FIXTURES = Path(__file__).parent / "fixtures"
NOW = datetime(2026, 10, 30, 12, tzinfo=UTC)
ADVISORY = json.loads((FIXTURES / "advisories.json").read_text())["advisories"][0]


class Transport:
    """Serves queued payloads; an exception in the queue simulates an outage."""

    def __init__(self, *payloads):
        self.payloads = list(payloads)
        self.urls = []

    def __call__(self, url):
        self.urls.append(url)
        payload = self.payloads.pop(0)
        if isinstance(payload, Exception):
            raise payload
        return payload


def kev_payload(*cves, released="2026-10-29T17:00:01.4387Z"):
    items = [{"cveID": cve, "vendorProject": "V", "product": "P", "dateAdded": "2026-01-01",
              "knownRansomwareCampaignUse": "Unknown"} for cve in cves]
    return json.dumps({"dateReleased": released, "count": len(items), "vulnerabilities": items}).encode()


class FeedParsingTests(unittest.TestCase):
    def test_kev_fixture(self):
        parsed = KevFeed().parse((FIXTURES / "kev.json").read_bytes())
        self.assertEqual(set(parsed.records), {"CVE-2021-41773", "CVE-2021-42013"})
        self.assertEqual(parsed.records["CVE-2021-41773"]["ransomware"], "Known")
        self.assertEqual(parsed.published_at, datetime(2026, 10, 29, 17, 0, 1, 438700, tzinfo=UTC))
        self.assertEqual(parsed.meta["catalog_version"], "2026.10.29")

    def test_epss_fixture_plain_and_gzipped(self):
        raw = (FIXTURES / "epss.csv").read_bytes()
        for payload in (raw, gzip.compress(raw)):
            parsed = EpssFeed().parse(payload)
            self.assertEqual(parsed.records["CVE-2021-41773"], {"epss": 0.9442, "percentile": 0.9996})
            self.assertEqual(parsed.published_at, datetime(2026, 10, 29, 12, 55, tzinfo=UTC))
            self.assertEqual(parsed.meta["model_version"], "v2025.03.14")

    def test_advisory_fixture(self):
        parsed = AdvisoryFeed("file:advisories").parse((FIXTURES / "advisories.json").read_bytes())
        self.assertEqual(parsed.records["CVE-2021-41773"]["product"], "apache:http_server")

    def test_malformed_feeds_raise(self):
        cases = [
            (KevFeed(), b"<html>maintenance</html>"),
            (KevFeed(), json.dumps({"count": 5, "vulnerabilities": []}).encode()),
            (KevFeed(), kev_payload("not-a-cve")),
            (EpssFeed(), b"cve,epss,percentile\nCVE-2021-0001,1.7,0.5\n"),
            (EpssFeed(), b"cve,epss\nCVE-2021-0001,0.1\n"),
            (AdvisoryFeed("x"), json.dumps({"advisories": [{"id": "A", "product": "p", "affected": []}]}).encode()),
            (AdvisoryFeed("x"), json.dumps({"advisories": [{"id": "A", "product": "p", "affected": [
                {"introduced": "1", "fixed": "2", "last_affected": "2"}]}]}).encode()),
        ]
        for feed, payload in cases:
            with self.subTest(feed=feed.name, payload=payload[:40]), self.assertRaises(FeedError):
                feed.parse(payload)


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def test_missing_until_first_refresh(self):
        store = IntelligenceStore(self.root)
        self.assertEqual(store.freshness(KevFeed(transport=Transport()), NOW).state, FreshnessState.MISSING)
        self.assertIsNone(store.record("kev", "CVE-2021-41773"))

    def test_outages_preserve_previous_intelligence(self):
        catalog = json.loads((FIXTURES / "kev.json").read_text())
        catalog["vulnerabilities"] += [dict(catalog["vulnerabilities"][1], cveID=f"CVE-2020-000{n}") for n in (1, 2)]
        catalog["count"] = len(catalog["vulnerabilities"])
        good = json.dumps(catalog).encode()
        failures = [
            ConnectionError("cisa.gov unreachable"),
            b"<html>502 Bad Gateway</html>",
            kev_payload(),
            kev_payload("CVE-2024-0001", released="2026-10-29T18:00:00Z"),
        ]
        feed = KevFeed(transport=Transport(good, *failures))
        store = IntelligenceStore(self.root)
        self.assertTrue(store.refresh(feed, NOW).updated)
        for hours, expected in zip(range(1, 5), ("ConnectionError", "malformed", "no records", "shrank"), strict=False):
            with self.subTest(expected=expected):
                report = store.refresh(feed, NOW + timedelta(hours=hours))
                self.assertFalse(report.updated)
                self.assertIn(expected, report.error)
                reopened = IntelligenceStore(self.root)
                self.assertEqual(reopened.record("kev", "CVE-2021-41773")["ransomware"], "Known")
                freshness = reopened.freshness(feed, NOW + timedelta(hours=hours))
                self.assertEqual(freshness.state, FreshnessState.FRESH)
                self.assertEqual(freshness.fetched_at, NOW)
                self.assertIn(expected, freshness.last_error)

    def test_freshness_turns_stale_during_a_long_outage_and_recovers(self):
        feed = KevFeed(transport=Transport((FIXTURES / "kev.json").read_bytes(), OSError("down"),
                                           (FIXTURES / "kev.json").read_bytes()))
        store = IntelligenceStore(self.root)
        store.refresh(feed, NOW)
        later = NOW + timedelta(days=3)
        store.refresh(feed, later)
        stale = store.freshness(feed, later)
        self.assertEqual(stale.state, FreshnessState.STALE)
        self.assertEqual(stale.last_attempt_at, later)
        self.assertIsNotNone(store.record("kev", "CVE-2021-41773"))
        store.refresh(feed, later + timedelta(hours=1))
        recovered = store.freshness(feed, later + timedelta(hours=1))
        self.assertEqual((recovered.state, recovered.last_error), (FreshnessState.FRESH, None))

    def test_rollback_to_an_older_catalog_is_refused(self):
        newer = kev_payload("CVE-2021-41773", released="2026-10-29T00:00:00Z")
        older = kev_payload("CVE-2021-41773", "CVE-2021-42013", released="2026-10-01T00:00:00Z")
        store = IntelligenceStore(self.root)
        feed = KevFeed(transport=Transport(newer, older))
        store.refresh(feed, NOW)
        report = store.refresh(feed, NOW + timedelta(hours=1))
        self.assertIn("older than cached", report.error)
        self.assertIsNone(store.record("kev", "CVE-2021-42013"))

    def test_epss_is_stale_when_scores_are_old_even_if_fetched_recently(self):
        feed = EpssFeed(transport=Transport((FIXTURES / "epss.csv").read_bytes()))
        store = IntelligenceStore(self.root)
        late = NOW + timedelta(days=4)
        store.refresh(feed, late)
        freshness = store.freshness(feed, late)
        self.assertEqual(freshness.state, FreshnessState.STALE)
        self.assertIn("feed data dated", freshness.reason)


class ApplicabilityTests(unittest.TestCase):
    def test_versions(self):
        self.assertEqual(parse_version("2.4.49"), ((2, 4, 49), ""))
        self.assertEqual(parse_version("v1.1.1k"), ((1, 1, 1), "k"))
        self.assertEqual(parse_version("unknown"), (None, "unknown"))

    def test_matching_is_conservative(self):
        cases = [
            ("apache:http_server", "2.4.49", Applicability.AFFECTED),
            ("apache:http_server", "2.4.49.0", Applicability.AFFECTED),
            ("apache:http_server", "2.4.50", Applicability.NOT_AFFECTED),
            ("apache:http_server", "2.4.48", Applicability.NOT_AFFECTED),
            ("apache:http_server", "2.4.49-1ubuntu1", Applicability.POSSIBLE),
            ("apache:http_server", "", Applicability.UNKNOWN),
            ("apache:http_server", "trunk", Applicability.UNKNOWN),
            ("apache:tomcat", "2.4.49", Applicability.NOT_AFFECTED),
        ]
        for product, version, expected in cases:
            with self.subTest(product=product, version=version):
                self.assertEqual(match_component(product, version, ADVISORY).applicability, expected)

    def test_last_affected_is_inclusive(self):
        advisory = dict(ADVISORY, affected=[{"introduced": "2.4.49", "last_affected": "2.4.50"}])
        self.assertEqual(match_component("apache:http_server", "2.4.50", advisory).applicability,
                         Applicability.AFFECTED)
        self.assertEqual(match_component("apache:http_server", "2.4.51", advisory).applicability,
                         Applicability.NOT_AFFECTED)


if __name__ == "__main__":
    unittest.main()
