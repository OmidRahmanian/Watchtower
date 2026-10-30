import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from inventory_support import FIXTURES, FixtureResolver, MemoryUnitOfWork, StepClock, deny_all_policy, scope_policy
from watchtower.adapters.discovery import subfinder
from watchtower.adapters.discovery.dns import DnsCollector
from watchtower.adapters.discovery.manual import import_csv, manual_entries
from watchtower.adapters.discovery.process import run_bounded
from watchtower.services.inventory import InventoryService

FAKE_SUBFINDER = [sys.executable, str(FIXTURES / "fake_subfinder.py")]


class ManualImportTests(unittest.TestCase):
    def test_csv_keeps_valid_rows_and_reports_bad_ones(self):
        result = import_csv((FIXTURES / "assets.csv").read_text(), source_file="assets.csv")
        self.assertEqual([n.hostname for n in result.names], ["www.example.com", "vpn.example.com"])
        www = result.names[0]
        self.assertEqual((www.source, www.root_domain, www.confidence), ("csv", "example.com", 0.95))
        self.assertEqual(www.observed_at.isoformat(), "2026-10-01T00:00:00+00:00")
        self.assertEqual(www.detail, {"row": 2, "file": "assets.csv", "note": "marketing site"})
        self.assertEqual([line for line, _ in result.errors], [4, 5, 6, 7])

    def test_csv_without_hostname_column_is_rejected(self):
        result = import_csv("name\nwww.example.com\n")
        self.assertEqual(result.names, [])
        self.assertIn("hostname column", result.errors[0][1])

    def test_manual_entries_normalize_and_enforce_root(self):
        result = manual_entries(["WWW.example.com.", "other.org", "not a host"], root_domain="example.com", operator="analyst")
        self.assertEqual([n.hostname for n in result.names], ["www.example.com"])
        self.assertEqual(result.names[0].detail, {"operator": "analyst"})
        self.assertEqual(len(result.errors), 2)


class SubfinderTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.argv_file = Path(directory.name) / "argv.json"

    def run_fake(self, mode, **kwargs):
        env = {"FAKE_SUBFINDER_MODE": mode, "FAKE_SUBFINDER_ARGV": str(self.argv_file)}

        def runner(argv, **limits):
            # Swap the binary for the fake script but keep subfinder's arguments.
            with patch.dict(os.environ, env):
                return run_bounded(FAKE_SUBFINDER + argv[1:], **limits)

        return subfinder.discover("Example.com", scope_policy(), runner=runner, **kwargs)

    def test_parses_fixture_output(self):
        run = self.run_fake("fixture")
        self.assertEqual(run.errors, [])
        self.assertEqual(
            sorted(n.hostname for n in run.names),
            ["api.example.com", "legacy.dev.example.com", "mail.example.com", "www.example.com"],
        )
        self.assertEqual(run.ignored_lines, 4)
        api = next(n for n in run.names if n.hostname == "api.example.com")
        self.assertEqual(api.detail, {"upstream_sources": ["crtsh", "virustotal"]})

    def test_argv_is_a_passive_argument_array(self):
        self.run_fake("fixture")
        argv = json.loads(self.argv_file.read_text())
        self.assertEqual(argv[:2], ["-d", "example.com"])
        self.assertIn("-json", argv)
        self.assertFalse(subfinder.FORBIDDEN_FLAGS & set(argv))

    def test_out_of_scope_domain_never_starts_the_tool(self):
        runner = Mock()
        run = subfinder.discover("example.org", scope_policy(), runner=runner)
        runner.assert_not_called()
        self.assertEqual(run.names, [])
        self.assertIn("not_in_scope", run.skipped)
        self.assertIn("no_scope", subfinder.discover("example.com", deny_all_policy(), runner=runner).skipped)
        runner.assert_not_called()

    def test_option_like_and_multi_domain_input_is_rejected_before_launch(self):
        runner = Mock()
        for domain in ("-active", "example.com,evil.com", "example.com -active"):
            with self.assertRaises(ValueError):
                subfinder.discover(domain, scope_policy(), runner=runner)
        runner.assert_not_called()

    def test_timeout_kills_the_tool(self):
        started = time.monotonic()
        run = self.run_fake("sleep", timeout=1.0)
        self.assertLess(time.monotonic() - started, 10)
        self.assertIn("timed out", run.errors[0])

    def test_output_is_bounded(self):
        run = self.run_fake("flood", timeout=20.0, max_output_bytes=100_000)
        self.assertIn("exceeded", run.errors[0])
        self.assertEqual([n.hostname for n in run.names], ["x.example.com"])

    def test_failure_reports_exit_code_and_stderr(self):
        run = self.run_fake("fail")
        self.assertIn("exited with 2: rate limited", run.errors[0])

    def test_missing_binary_is_an_error_not_an_exception(self):
        run = subfinder.discover("example.com", scope_policy(), binary="/nonexistent/subfinder")
        self.assertIn("could not start", run.errors[0])


class DnsCollectionTests(unittest.TestCase):
    def test_wildcard_names_do_not_inflate_inventory(self):
        resolver = FixtureResolver()
        collector = DnsCollector(scope_policy(), resolver, clock=StepClock())
        candidates = [f"guess{i}.dev.example.com" for i in range(50)] + ["real.dev.example.com", "www.example.com"]
        inventory = InventoryService(MemoryUnitOfWork(), clock=StepClock())

        stats = inventory.ingest_dns(collector.collect(candidates, root_domain="example.com"), create_missing=True, root_domain="example.com")

        self.assertEqual(stats.wildcard_suppressed, 50)
        self.assertEqual(stats.created, 2)
        self.assertEqual([a.value for a in inventory.assets()], ["real.dev.example.com", "www.example.com"])
        self.assertEqual(set(inventory.get("real.dev.example.com").attributes["provenance"]), {"dns"})
        # The wildcard under dev.example.com is fingerprinted once, not per candidate.
        probes = {name for name, _ in resolver.queries if name.startswith("wt-")}
        # Two probes confirm dev.example.com; one NXDOMAIN probe rules out example.com.
        self.assertEqual(len(probes), 3)

    def test_rotating_wildcard_answers_inside_fingerprint_are_matched(self):
        labels = iter(["wt-a", "wt-b", "wt-c", "wt-d"])
        collector = DnsCollector(scope_policy(), FixtureResolver(), label_factory=lambda: next(labels))
        observation = collector.lookup("anything.dev.example.com")
        self.assertTrue(observation["wildcard"])
        self.assertEqual(observation["a"], ["203.0.113.50", "203.0.113.51"])

    def test_cname_into_wildcard_target_is_flagged(self):
        resolver = FixtureResolver(wildcards={"dev.example.com": {"CNAME": ["catchall.example.net"], "A": ["203.0.113.70"]}})
        resolver.records["cdn.dev.example.com"] = {"CNAME": ["catchall.example.net"], "A": ["203.0.113.71"]}
        observation = DnsCollector(scope_policy(), resolver).lookup("cdn.dev.example.com")
        self.assertTrue(observation["wildcard"])

    def test_inconclusive_wildcard_check_creates_nothing_and_is_retried(self):
        class Failing(FixtureResolver):
            failing = True

            def query(self, name, rdtype):
                if self.failing and name.startswith("wt-"):
                    from watchtower.adapters.discovery.dns import DnsFailure
                    raise DnsFailure("SERVFAIL")
                return super().query(name, rdtype)

        resolver = Failing()
        collector = DnsCollector(scope_policy(), resolver)
        inventory = InventoryService(MemoryUnitOfWork())
        observation = collector.lookup("guess.dev.example.com")
        self.assertEqual((observation["wildcard"], observation["wildcard_unknown"]), (False, True))
        stats = inventory.ingest_dns([observation], create_missing=True)
        self.assertEqual((stats.created, stats.wildcard_suppressed), (0, 1))

        resolver.failing = False
        self.assertTrue(collector.lookup("guess.dev.example.com")["wildcard"])

    def test_out_of_scope_names_are_never_queried(self):
        resolver = FixtureResolver()
        collector = DnsCollector(scope_policy(exclude=("vpn.example.com",)), resolver)
        observations = collector.collect(["vpn.example.com", "www.example.org"])
        self.assertEqual([o["status"] for o in observations], ["unauthorized", "unauthorized"])
        self.assertEqual(resolver.queries, [])

    def test_project_without_scope_denies_everything(self):
        resolver = FixtureResolver()
        observation = DnsCollector(deny_all_policy(), resolver).lookup("www.example.com")
        self.assertEqual(observation["status"], "unauthorized")
        self.assertEqual(resolver.queries, [])

    def test_nxdomain_and_resolution_errors_are_reported(self):
        class Flaky(FixtureResolver):
            def query(self, name, rdtype):
                if name == "broken.example.com":
                    from watchtower.adapters.discovery.dns import DnsFailure
                    raise DnsFailure("SERVFAIL")
                return super().query(name, rdtype)

        collector = DnsCollector(scope_policy(), Flaky())
        missing, broken = collector.collect(["missing.example.com", "broken.example.com"])
        self.assertEqual(missing["status"], "nxdomain")
        self.assertEqual((broken["status"], broken["error"]), ("error", "SERVFAIL"))
        inventory = InventoryService(MemoryUnitOfWork())
        stats = inventory.ingest_dns([missing, broken], create_missing=True)
        self.assertEqual((stats.created, stats.rejected), (0, 2))


if __name__ == "__main__":
    unittest.main()
