import unittest
from datetime import datetime, timezone
from uuid import uuid4

from inventory_support import (
    FIXTURES,
    FixtureResolver,
    MemoryUnitOfWork,
    StepClock,
    scope_policy,
)
from watchtower.adapters.discovery.dns import DnsCollector
from watchtower.adapters.discovery.manual import import_csv, manual_entries
from watchtower.adapters.discovery.subfinder import SubfinderRun, parse_output
from watchtower.domain.models import ObservationKind
from watchtower.services.inventory import DiscoveredName, InventoryService


def fixture_names():
    run = SubfinderRun("example.com")
    parse_output((FIXTURES / "subfinder.jsonl").read_bytes(), "example.com", run)
    csv_names = import_csv((FIXTURES / "assets.csv").read_text(), source_file="assets.csv").names
    manual = manual_entries(["Mail.Example.com"], root_domain="example.com", operator="analyst").names
    return run.names + csv_names + manual


class RepeatedRunTests(unittest.TestCase):
    def setUp(self):
        self.uow = MemoryUnitOfWork()
        self.clock = StepClock()
        self.policy = scope_policy(exclude=("mail.example.com",))

    def run_fixture(self):
        """One scheduled run: import every discovery source, then collect DNS."""
        inventory = InventoryService(self.uow, policy=self.policy, job_id=uuid4(), clock=self.clock)
        stats = inventory.ingest(fixture_names())
        collector = DnsCollector(self.policy, FixtureResolver(), clock=self.clock)
        inventory.ingest_dns(collector.collect([a.value for a in inventory.assets()], root_domain="example.com"))
        return inventory, stats

    def test_repeated_runs_keep_identity_and_provenance(self):
        first, first_stats = self.run_fixture()
        before = {asset.value: asset for asset in first.assets()}
        observations_before = list(self.uow.observations.rows)
        second, second_stats = self.run_fixture()
        after = {asset.value: asset for asset in second.assets()}

        self.assertEqual(
            sorted(after),
            ["api.example.com", "legacy.dev.example.com", "mail.example.com", "vpn.example.com", "www.example.com"],
        )
        self.assertEqual((first_stats.created, second_stats.created), (5, 0))
        for value, asset in after.items():
            self.assertEqual(asset.id, before[value].id)
            self.assertEqual(asset.first_seen_at, before[value].first_seen_at)
            self.assertEqual(set(asset.attributes["provenance"]), set(before[value].attributes["provenance"]))
            for source, entry in asset.attributes["provenance"].items():
                self.assertEqual(entry["first_seen"], before[value].attributes["provenance"][source]["first_seen"])
                self.assertEqual(entry["times_seen"], 2)

        www = after["www.example.com"].attributes
        self.assertEqual(set(www["provenance"]), {"subfinder", "csv"})
        self.assertEqual(www["provenance"]["csv"]["first_seen"], "2026-10-01T00:00:00Z")
        self.assertEqual(www["provenance"]["csv"]["detail"]["note"], "marketing site")
        self.assertEqual(www["ownership_confidence"], 0.95)
        self.assertEqual(www["root_domain"], "example.com")

        api = after["api.example.com"].attributes["provenance"]["subfinder"]
        self.assertEqual(api["detail"]["upstream_sources"], ["crtsh", "virustotal"])
        self.assertEqual(after["mail.example.com"].attributes["provenance"]["manual"]["detail"], {"operator": "analyst"})

        # Earlier observations are untouched; the second run only appended.
        self.assertEqual(self.uow.observations.rows[: len(observations_before)], observations_before)
        self.assertEqual(len(self.uow.observations.rows), 2 * len(observations_before))

    def test_authorization_snapshot_and_scope_revision_are_recorded(self):
        inventory, _ = self.run_fixture()
        www, mail = inventory.get("www.example.com"), inventory.get("mail.example.com")
        self.assertEqual(www.attributes["authorization"]["status"], "authorized")
        self.assertEqual(mail.attributes["authorization"]["status"], "unauthorized")
        self.assertEqual(mail.attributes["authorization"]["reason"], "excluded")
        self.assertEqual(www.scope_revision_id, self.policy.revision_id)
        self.assertTrue(all(row.scope_revision_id == self.policy.revision_id for row in self.uow.observations.rows))

    def test_excluded_names_are_inventoried_but_never_resolved(self):
        resolver = FixtureResolver()
        inventory, _ = self.run_fixture()
        DnsCollector(self.policy, resolver).collect(["mail.example.com"])
        self.assertEqual(resolver.queries, [])
        dns = self.uow.history(inventory.get("mail.example.com"), ObservationKind.DNS_RESOLUTION)
        self.assertEqual([row.data["status"] for row in dns], ["unauthorized"])

    def test_passively_discovered_name_under_wildcard_is_kept_but_flagged(self):
        inventory, _ = self.run_fixture()
        dns = self.uow.history(inventory.get("legacy.dev.example.com"), ObservationKind.DNS_RESOLUTION)
        self.assertTrue(dns[-1].data["wildcard"])
        self.assertEqual(dns[-1].data["wildcard_parent"], "dev.example.com")

    def test_retried_job_does_not_duplicate_observations(self):
        job = uuid4()
        moment = datetime(2026, 10, 30, 12, tzinfo=timezone.utc)
        for _ in range(2):
            InventoryService(self.uow, policy=self.policy, job_id=job).record_discovery(
                DiscoveredName("www.example.com", "subfinder", "example.com", observed_at=moment))
        self.assertEqual(len(self.uow.observations.rows), 1)
        provenance = InventoryService(self.uow).get("www.example.com").attributes["provenance"]["subfinder"]
        self.assertEqual(provenance["times_seen"], 1)


class IdentityTests(unittest.TestCase):
    def setUp(self):
        self.uow = MemoryUnitOfWork()
        self.inventory = InventoryService(self.uow, clock=StepClock())

    def test_hostname_spellings_share_one_asset(self):
        for spelling in ("WWW.Example.COM.", "www.example.com", " www.example.com "):
            self.inventory.record_discovery(DiscoveredName(spelling, "manual", "example.com"))
        assets = self.inventory.assets()
        self.assertEqual([a.value for a in assets], ["www.example.com"])
        self.assertEqual(assets[0].attributes["provenance"]["manual"]["times_seen"], 3)

    def test_idn_names_are_stored_as_a_labels(self):
        asset, _ = self.inventory.record_discovery(DiscoveredName("bücher.example.com", "manual", "example.com"))
        self.assertEqual(asset.value, "xn--bcher-kva.example.com")
        self.assertEqual(self.inventory.get("BÜCHER.example.com").id, asset.id)

    def test_names_outside_root_and_invalid_names_are_rejected(self):
        stats = self.inventory.ingest([
            DiscoveredName("example.com.evil.net", "subfinder", "example.com"),
            DiscoveredName("https://www.example.com", "manual", "example.com"),
            DiscoveredName("198.51.100.1", "manual"),
            DiscoveredName("*.example.com", "subfinder", "example.com"),
            DiscoveredName("intranet", "manual"),
        ])
        self.assertEqual(stats.rejected, 5)
        self.assertEqual(self.inventory.assets(), [])

    def test_ip_change_updates_the_same_asset_and_keeps_history(self):
        policy = scope_policy()
        asset, _ = self.inventory.record_discovery(DiscoveredName("www.example.com", "manual", "example.com"))
        resolver = FixtureResolver()
        self.inventory.ingest_dns(DnsCollector(policy, resolver).collect(["www.example.com"]))
        resolver.records["www.example.com"] = {"A": ["198.51.100.11"], "AAAA": ["2001:db8::10"]}
        self.inventory.ingest_dns(DnsCollector(policy, resolver).collect(["www.example.com"]))

        self.assertEqual(len(self.inventory.assets()), 1)
        current = self.inventory.get("www.example.com")
        self.assertEqual(current.id, asset.id)
        self.assertEqual(current.attributes["addresses"], ["198.51.100.11", "2001:db8::10"])
        dns = self.uow.history(current, ObservationKind.DNS_RESOLUTION)
        self.assertEqual([row.data["a"] for row in dns], [["198.51.100.10"], ["198.51.100.11"]])
        self.assertEqual([row.data["address_changed"] for row in dns], [False, True])
        self.assertEqual(dns[1].data["previous_addresses"], ["198.51.100.10", "2001:db8::10"])

    def test_failed_lookup_keeps_known_addresses_and_last_seen(self):
        policy = scope_policy()
        self.inventory.record_discovery(DiscoveredName("www.example.com", "manual", "example.com"))
        resolver = FixtureResolver()
        self.inventory.ingest_dns(DnsCollector(policy, resolver).collect(["www.example.com"]))
        seen = self.inventory.get("www.example.com").last_seen_at
        del resolver.records["www.example.com"]
        self.inventory.ingest_dns(DnsCollector(policy, resolver).collect(["www.example.com"]))
        asset = self.inventory.get("www.example.com")
        self.assertEqual(asset.attributes["dns_status"], "nxdomain")
        self.assertEqual(asset.attributes["addresses"], ["198.51.100.10", "2001:db8::10"])
        self.assertEqual(asset.last_seen_at, seen)


class HttpObservationTests(unittest.TestCase):
    def setUp(self):
        self.uow = MemoryUnitOfWork()
        self.inventory = InventoryService(self.uow, clock=StepClock())

    def test_http_errors_are_observations_not_deletions(self):
        self.inventory.record_discovery(DiscoveredName("www.example.com", "manual", "example.com"))
        seen = self.inventory.get("www.example.com").last_seen_at
        for outcome in ({"outcome": "error", "error": {"kind": "timeout", "message": "timed out"}},
                        {"outcome": "ok", "status_code": 503},
                        {"outcome": "blocked_destination", "error": {"kind": "blocked_destination", "message": "x"}},
                        {"outcome": "unauthorized", "error": {"kind": "unauthorized", "message": "x"}}):
            self.inventory.record_http({"hostname": "www.example.com", "url": "https://www.example.com/", **outcome})

        asset = self.inventory.get("www.example.com")
        self.assertEqual([a.value for a in self.inventory.assets()], ["www.example.com"])
        self.assertEqual(asset.attributes["last_http"]["outcome"], "unauthorized")
        self.assertGreater(asset.last_seen_at, seen)  # bumped once, by the 503 response
        http = self.uow.history(asset, ObservationKind.HTTP_RESPONSE)
        self.assertEqual([row.data["outcome"] for row in http], ["error", "ok", "blocked_destination", "unauthorized"])

    def test_http_results_do_not_create_assets(self):
        self.assertIsNone(self.inventory.record_http({"hostname": "new.example.com", "outcome": "ok"}))
        self.assertEqual(self.inventory.assets(), [])
        self.assertEqual(self.uow.observations.rows, [])


if __name__ == "__main__":
    unittest.main()
