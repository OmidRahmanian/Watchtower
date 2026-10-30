from dataclasses import replace
from datetime import datetime, timedelta, UTC
import json
import unittest
from uuid import uuid4

from watchtower.adapters.checks import Endpoint, build_checks, load_manifest
from watchtower.adapters.checks.base import HttpResponse
from watchtower.domain.models import Asset, AssetKind, Finding, FindingStatus, NewFinding, Severity, StoredBlob
from watchtower.services.evidence import MEDIA_TYPE, to_new_evidence
from watchtower.services.findings import (
    FindingError, FindingService, IrrelevantRetest, RepositoryFindingStore, fingerprint,
)

START = datetime(2026, 10, 30, 12, tzinfo=UTC)
GIT_CONFIG = b"[core]\n\trepositoryformatversion = 0\n\tbare = false\n"
URL = "https://shop.example.com/.git/config"


class Scanner:
    """Runs the real pinned git-config rule against canned responses."""

    def __init__(self):
        self.ruleset = load_manifest()
        self.reply = HttpResponse(200, (), GIT_CONFIG)

    def fetch(self, method, url):
        if isinstance(self.reply, Exception):
            raise self.reply
        return self.reply

    def run(self, reply, at, ip="203.0.113.10", check="exposed-git-config", host="shop.example.com"):
        self.reply = reply
        http, _ = build_checks(self.ruleset, self.fetch, lambda url: True)
        return http[check].run(Endpoint(host, resolved_ip=ip), at)


EXPOSED = HttpResponse(200, (), GIT_CONFIG)
GONE = HttpResponse(404, (), b"not found")
BUSY = HttpResponse(503, (), b"maintenance")


class FindingLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.scanner = Scanner()
        self.service = FindingService(canonical_id=self.scanner.ruleset.canonical_id)
        self.finding = self.service.ingest(self.scanner.run(EXPOSED, START))
        self.key = self.finding.fingerprint

    def at(self, hours):
        return START + timedelta(hours=hours)

    def test_fixture_finding_appears_once_across_scans_and_ip_changes(self):
        self.service.ingest(self.scanner.run(EXPOSED, self.at(1)))
        self.service.ingest(self.scanner.run(EXPOSED, self.at(2), ip="198.51.100.7"))
        self.assertEqual(len(self.service.store), 1)
        finding = self.service.get(self.key)
        self.assertEqual(finding.occurrences, 3)
        self.assertEqual(finding.target.resolved_ip, "198.51.100.7")
        self.assertEqual(finding.status, FindingStatus.OPEN)
        first = self.service.evidence.get(finding.first_evidence)
        self.assertEqual(first["resolved_ip"], "203.0.113.10")

    def test_scan_negatives_failures_and_inconclusive_results_do_not_resolve(self):
        self.service.ingest(self.scanner.run(GONE, self.at(1)))
        self.assertEqual(self.finding.status, FindingStatus.OPEN)
        self.assertEqual(self.finding.detection.state, "absent")
        self.service.ingest(self.scanner.run(BUSY, self.at(2)))
        self.service.ingest(self.scanner.run(OSError("timeout"), self.at(3)))
        self.assertEqual(self.finding.status, FindingStatus.OPEN)
        self.assertEqual(self.finding.detection.last_outcome, "failed")
        self.assertEqual(self.finding.detection.state, "absent")

    def test_failed_and_inconclusive_retests_cannot_establish_remediation(self):
        self.service.request_retest(self.key, "analyst", self.at(1))
        for hours, reply in ((2, BUSY), (3, ConnectionError("refused")), (4, HttpResponse(200, (), b"x", True))):
            result = self.scanner.run(reply, self.at(hours))
            self.assertFalse(result.outcome.conclusive)
            finding = self.service.apply_retest(self.key, result)
            self.assertEqual(finding.status, FindingStatus.OPEN)
            self.assertIsNone(finding.resolution_evidence)
            self.assertIsNotNone(finding.retest_requested_at)
        self.assertEqual(self.finding.detection.state, "present")

    def test_irrelevant_or_stale_retests_are_rejected(self):
        other_check = self.scanner.run(GONE, self.at(1), check="exposed-env-file")
        other_host = self.scanner.run(GONE, self.at(1), host="blog.example.com")
        stale = self.scanner.run(GONE, START - timedelta(minutes=1))
        for result in (other_check, other_host, stale):
            with self.subTest(result=result.check_id), self.assertRaises(IrrelevantRetest):
                self.service.apply_retest(self.key, result)
        self.assertEqual(self.finding.status, FindingStatus.OPEN)

    def test_relevant_negative_retest_resolves_and_recurrence_reopens(self):
        self.service.transition(self.key, FindingStatus.TRIAGED, "analyst", now=self.at(1))
        self.service.request_retest(self.key, "analyst", self.at(2))
        finding = self.service.apply_retest(self.key, self.scanner.run(GONE, self.at(3)))
        self.assertEqual(finding.status, FindingStatus.RESOLVED)
        self.assertIsNone(finding.retest_requested_at)
        resolution = self.service.evidence.get(finding.resolution_evidence)
        self.assertEqual(resolution["response"]["status"], 404)

        self.service.ingest(self.scanner.run(EXPOSED, self.at(4), ip="198.51.100.7"))
        self.assertEqual(len(self.service.store), 1)
        self.assertEqual(finding.status, FindingStatus.OPEN)
        self.assertEqual(finding.recurrences, 1)
        self.assertIsNone(finding.resolution_evidence)
        self.assertEqual([event["event"] for event in finding.history],
                         ["created", "status_changed", "retest_requested", "resolved", "reopened"])

    def test_resolution_and_reopening_are_not_manual(self):
        for status in (FindingStatus.RESOLVED,):
            with self.subTest(status=status), self.assertRaises(FindingError):
                self.service.transition(self.key, status, "analyst")

    def test_accepting_risk_needs_a_reason_and_false_positives_stay_closed(self):
        with self.assertRaisesRegex(FindingError, "requires a reason"):
            self.service.transition(self.key, FindingStatus.ACCEPTED_RISK, "analyst", " ")
        self.service.transition(self.key, FindingStatus.FALSE_POSITIVE, "analyst", "honeypot", self.at(1))
        self.service.ingest(self.scanner.run(EXPOSED, self.at(2)))
        self.assertEqual(self.finding.status, FindingStatus.FALSE_POSITIVE)
        self.service.apply_retest(self.key, self.scanner.run(GONE, self.at(3)))
        self.assertEqual(self.finding.status, FindingStatus.FALSE_POSITIVE)

    def test_fields_stay_separate(self):
        self.service.set_priority(self.key, {"level": "P1"})
        self.assertEqual((self.finding.severity, self.finding.confidence), ("high", "firm"))
        self.assertEqual(self.finding.status, FindingStatus.OPEN)
        self.assertEqual(self.finding.detection.state, "present")
        data = json.loads(json.dumps(self.finding.to_dict()))
        self.assertEqual({data[key] for key in ("severity", "confidence", "status")}, {"high", "firm", "open"})
        self.assertEqual(data["detection"]["state"], "present")
        self.assertEqual(data["priority"], {"level": "P1"})

    def test_maps_onto_shared_records(self):
        asset, revision = uuid4(), uuid4()
        new = self.finding.to_new_finding(asset, revision)
        self.assertIsInstance(new, NewFinding)
        self.assertEqual((new.fingerprint, new.severity, new.source), (self.key, Severity.HIGH, "exposed-git-config"))
        self.assertEqual(new.details["confidence"], "firm")
        self.assertEqual(new.details["detection"]["state"], "present")
        self.assertNotIn("status", new.details)
        json.dumps(dict(new.details))

        class Blobs:
            def put(self, project_id, data, *, media_type):
                self.data = data
                return StoredBlob("blob://1", "0" * 64, len(data))

        blobs, finding_id = Blobs(), uuid4()
        evidence = to_new_evidence(self.service.evidence.get(self.finding.first_evidence), blobs, uuid4(),
                                   finding_id=finding_id)
        self.assertEqual((evidence.media_type, evidence.finding_id), (MEDIA_TYPE, finding_id))
        self.assertIn(b'"check_id":"exposed-git-config"', blobs.data)

    def test_resolved_findings_cannot_be_reopened_by_hand(self):
        self.service.apply_retest(self.key, self.scanner.run(GONE, self.at(1)))
        for status in (FindingStatus.OPEN, FindingStatus.TRIAGED):
            with self.subTest(status=status), self.assertRaises(FindingError):
                self.service.transition(self.key, status, "analyst")

    def test_non_detections_without_a_finding_create_nothing(self):
        service = FindingService()
        for reply in (GONE, BUSY, OSError("down")):
            self.assertIsNone(service.ingest(self.scanner.run(reply, START)))
        self.assertEqual(len(service.store), 0)


class FakeUnitOfWork:
    """Mimics the shared repositories: upsert replaces details and keeps status."""

    def __init__(self):
        self.rows, self.asset_values = {}, []
        self.findings, self.assets = self, self

    def upsert(self, *args, **kwargs):
        if isinstance(args[0], NewFinding):
            new, row = args[0], self.rows.get(args[0].fingerprint)
            stored = Finding(row.id if row else uuid4(), uuid4(), new.asset_id, new.fingerprint, new.title,
                             new.severity, row.status if row else FindingStatus.OPEN, new.source,
                             json.loads(json.dumps(dict(new.details))), START, new.observed_at,
                             row.status_changed_at if row else START)
            self.rows[new.fingerprint] = stored
            return stored, row is None
        kind, value = args
        self.asset_values.append((kind, value))
        return Asset(uuid4(), uuid4(), kind, value, START, START), True

    def get_by_fingerprint(self, key):
        return self.rows.get(key)

    def set_status(self, finding_id, status):
        key = next(key for key, row in self.rows.items() if row.id == finding_id)
        self.rows[key] = replace(self.rows[key], status=status, status_changed_at=START)
        return self.rows[key]


class RepositoryStoreTests(unittest.TestCase):
    def test_lifecycle_survives_round_trips_through_shared_records(self):
        uow, scanner = FakeUnitOfWork(), Scanner()
        service = FindingService(RepositoryFindingStore(uow), canonical_id=scanner.ruleset.canonical_id)
        key = service.ingest(scanner.run(EXPOSED, START)).fingerprint
        service.ingest(scanner.run(EXPOSED, START + timedelta(hours=1), ip="198.51.100.7"))
        service.request_retest(key, "analyst", START + timedelta(hours=2))
        service.apply_retest(key, scanner.run(BUSY, START + timedelta(hours=3)))
        self.assertEqual(service.get(key).retest_requested_at, START + timedelta(hours=2))
        service.apply_retest(key, scanner.run(GONE, START + timedelta(hours=4)))
        self.assertEqual(uow.rows[key].status, FindingStatus.RESOLVED)
        service.ingest(scanner.run(EXPOSED, START + timedelta(hours=5)))

        finding = service.get(key)
        self.assertEqual(len(uow.rows), 1)
        self.assertEqual((uow.rows[key].status, finding.status), (FindingStatus.OPEN, FindingStatus.OPEN))
        self.assertEqual((finding.occurrences, finding.recurrences), (3, 1))
        self.assertEqual(finding.detection.state, "present")
        self.assertEqual(finding.target.resolved_ip, "203.0.113.10")
        self.assertEqual([event["event"] for event in finding.history][-3:], ["retest_inconclusive", "resolved",
                                                                               "reopened"])
        self.assertEqual(set(uow.asset_values), {(AssetKind.HOSTNAME, "shop.example.com")})


class FingerprintTests(unittest.TestCase):
    def setUp(self):
        self.result = Scanner().run(EXPOSED, START)
        self.service = FindingService(canonical_id={"git-config-exposure": "exposed-git-config"}.get)

    def test_stable_across_rule_versions_severity_and_ip(self):
        original = fingerprint("exposed-git-config", self.result.target, "/.git/config")
        updated = replace(self.result, rule_version="2.0.0", severity=Severity.CRITICAL,
                          target=Endpoint("SHOP.example.com.", resolved_ip="192.0.2.1"), evidence={"other": True})
        self.assertEqual(FindingService().fingerprint_for(updated), original)

    def test_renamed_rule_keeps_fingerprint_through_alias(self):
        service = FindingService(canonical_id=lambda rule_id: {"git-config-exposure": "exposed-git-config"}
                                 .get(rule_id, rule_id))
        finding = service.ingest(self.result)
        renamed = replace(self.result, check_id="git-config-exposure", rule_version="2.0.0",
                          observed_at=START + timedelta(days=1))
        self.assertIs(service.ingest(renamed), finding)
        self.assertEqual(len(service.store), 1)

    def test_rule_update_changing_severity_is_recorded(self):
        service = FindingService()
        finding = service.ingest(self.result)
        service.ingest(replace(self.result, rule_version="1.1.0", severity=Severity.CRITICAL,
                               observed_at=START + timedelta(hours=1)))
        self.assertEqual((finding.severity, finding.rule_version), ("critical", "1.1.0"))
        self.assertEqual(finding.history[-2]["event"], "severity_changed")

    def test_distinct_assets_ports_and_variants_differ(self):
        base = fingerprint("c", Endpoint("a.example.com"), "/")
        self.assertNotEqual(base, fingerprint("c", Endpoint("b.example.com"), "/"))
        self.assertNotEqual(base, fingerprint("c", Endpoint("a.example.com", port=8443), "/"))
        self.assertNotEqual(base, fingerprint("c", Endpoint("a.example.com", scheme="http"), "/"))
        self.assertNotEqual(base, fingerprint("c", Endpoint("a.example.com"), "/", "CVE-2021-41773"))
        self.assertEqual(base, fingerprint("c", Endpoint("a.example.com", port=443), "/"))


if __name__ == "__main__":
    unittest.main()
