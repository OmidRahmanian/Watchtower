from datetime import datetime, UTC
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from uuid import uuid4

from watchtower.adapters.checks import Endpoint, Outcome, build_checks, load_manifest, scope_authorizer
from watchtower.domain.scope import AuthorizationKind, AuthorizationReference, ScopePolicy, ScopeRevision, ScopeRule
from watchtower.domain.targets import PortSet
from watchtower.adapters.checks.base import HttpResponse
from watchtower.adapters.checks.component import VulnerableComponentCheck, parse_banner
from watchtower.domain.models import Severity
from watchtower.adapters.checks.manifest import RULES_ROOT, RuleIntegrityError, digest, unpinned_files, validate_definition

NOW = datetime(2026, 10, 30, 12, tzinfo=UTC)
GIT_CONFIG = b"[core]\n\trepositoryformatversion = 0\n\tbare = false\n[remote \"origin\"]\n" \
             b"\turl = https://deploy:ghp_supersecret@github.com/acme/site.git\n"
ADVISORIES = json.loads((Path(__file__).parent / "fixtures" / "advisories.json").read_text())["advisories"]


def response(status=200, body=b"", headers=(), truncated=False):
    return HttpResponse(status, tuple(headers), body, truncated)


class FakeFetcher:
    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def __call__(self, method, url):
        self.calls.append((method, url))
        result = self.routes[url]
        if isinstance(result, Exception):
            raise result
        return result


class ManifestTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "rules"
        shutil.copytree(RULES_ROOT, self.root)

    def manifest(self):
        return json.loads((self.root / "manifest.json").read_text())

    def save(self, manifest):
        (self.root / "manifest.json").write_text(json.dumps(manifest))

    def test_shipped_rules_are_pinned_and_reviewed(self):
        ruleset = load_manifest()
        self.assertEqual(set(ruleset.rules), {"exposed-git-config", "exposed-env-file", "directory-listing",
                                              "server-version-disclosure", "vulnerable-component"})
        self.assertEqual(unpinned_files(), [])
        for rule in ruleset:
            self.assertTrue(rule.review["reviewer"])

    def test_modified_rule_is_rejected(self):
        path = self.root / "http" / "exposed-git-config.json"
        path.write_text(path.read_text().replace('"high"', '"low"'))
        with self.assertRaisesRegex(RuleIntegrityError, "does not match pinned"):
            load_manifest(self.root)

    def test_unreviewed_escaping_and_mismatched_entries_are_rejected(self):
        cases = {
            "no review record": lambda entry: entry.pop("review"),
            "escapes rules directory": lambda entry: entry.update(path="../manifest.json"),
            "disagree": lambda entry: entry.update(version="9.9.9"),
        }
        for message, change in cases.items():
            with self.subTest(message=message):
                manifest = json.loads((RULES_ROOT / "manifest.json").read_text())
                change(manifest["rules"][0])
                self.save(manifest)
                with self.assertRaisesRegex(RuleIntegrityError, message):
                    load_manifest(self.root)

    def test_unpinned_rule_files_do_not_load(self):
        (self.root / "http" / "extra.json").write_text("{}")
        self.assertNotIn("extra", load_manifest(self.root).rules)
        self.assertEqual([path.name for path in unpinned_files(self.root)], ["extra.json"])

    def test_aliases_resolve_to_the_renamed_rule(self):
        manifest = self.manifest()
        manifest["rules"][0]["aliases"] = ["old-name"]
        self.save(manifest)
        ruleset = load_manifest(self.root)
        self.assertEqual(ruleset.canonical_id("old-name"), manifest["rules"][0]["id"])

    def test_unsafe_definitions_are_invalid(self):
        base = json.loads((RULES_ROOT / "http" / "exposed-git-config.json").read_text())
        for change in ({"request": {"method": "POST", "path": "/"}},
                       {"request": {"method": "GET", "path": "http://elsewhere.example/"}},
                       {"request": {"method": "GET", "path": "//elsewhere.example/"}},
                       {"negative_status": []},
                       {"match": {"body_all": ["("]}}):
            with self.subTest(change=change), self.assertRaises(RuleIntegrityError):
                validate_definition(dict(base, **change))

    def test_digest_matches_manifest(self):
        for entry in self.manifest()["rules"]:
            self.assertEqual(digest(self.root / entry["path"]), entry["sha256"])


class HttpCheckTests(unittest.TestCase):
    def setUp(self):
        self.ruleset = load_manifest()
        self.target = Endpoint("Shop.Example.com.", resolved_ip="203.0.113.10")
        self.url = "https://shop.example.com/.git/config"

    def run_git(self, result, authorize=lambda url: True):
        fetch = FakeFetcher({self.url: result})
        http, _ = build_checks(self.ruleset, fetch, authorize)
        return http["exposed-git-config"].run(self.target, NOW), fetch

    def test_detects_exposed_git_config_with_redacted_evidence(self):
        result, fetch = self.run_git(response(200, GIT_CONFIG, [("Server", "nginx"), ("Set-Cookie", "s=1")]))
        self.assertEqual(result.outcome, Outcome.DETECTED)
        self.assertEqual(fetch.calls, [("GET", self.url)])
        body = result.evidence["response"]["body_excerpt"]
        self.assertIn("[core]", body)
        self.assertNotIn("ghp_supersecret", json.dumps(result.evidence))
        self.assertIn(["Set-Cookie", "[REDACTED]"], result.evidence["response"]["headers"])
        self.assertEqual(result.evidence["resolved_ip"], "203.0.113.10")
        self.assertEqual((result.severity, result.confidence), (Severity.HIGH, "firm"))

    def test_outcomes_for_negative_and_unclear_responses(self):
        cases = [
            (response(404, b"not found"), Outcome.NOT_DETECTED),
            (response(200, b"<html>[core]\nrepositoryformatversion = 0</html>"), Outcome.NOT_DETECTED),
            (response(503, b"busy"), Outcome.INCONCLUSIVE),
            (response(429, b"slow down"), Outcome.INCONCLUSIVE),
            (response(200, b"partial", truncated=True), Outcome.INCONCLUSIVE),
            (ConnectionError("reset"), Outcome.FAILED),
        ]
        for reply, expected in cases:
            with self.subTest(expected=expected, reply=reply):
                self.assertEqual(self.run_git(reply)[0].outcome, expected)

    def test_unauthorized_destination_is_never_requested(self):
        result, fetch = self.run_git(response(200, GIT_CONFIG), authorize=lambda url: False)
        self.assertEqual(result.outcome, Outcome.FAILED)
        self.assertEqual(fetch.calls, [])

    def test_default_authorizer_denies(self):
        fetch = FakeFetcher({})
        http, _ = build_checks(self.ruleset, fetch)
        self.assertEqual(http["directory-listing"].run(self.target, NOW).outcome, Outcome.FAILED)
        self.assertEqual(fetch.calls, [])

    def test_env_file_keeps_key_names_only(self):
        body = b"APP_NAME=shop\nDB_PASSWORD=hunter2\nAWS_SECRET_ACCESS_KEY=abc/def\n"
        fetch = FakeFetcher({"https://shop.example.com/.env": response(200, body)})
        http, _ = build_checks(self.ruleset, fetch, lambda url: True)
        result = http["exposed-env-file"].run(self.target, NOW)
        self.assertEqual(result.outcome, Outcome.DETECTED)
        excerpt = result.evidence["response"]["body_excerpt"]
        self.assertIn("DB_PASSWORD=[REDACTED]", excerpt)
        for secret in ("shop\n", "hunter2", "abc/def"):
            self.assertNotIn(secret, excerpt)

    def test_server_banner_is_extracted(self):
        fetch = FakeFetcher({"https://shop.example.com/": response(200, headers=[("Server", "Apache/2.4.49 (Unix)")])})
        http, _ = build_checks(self.ruleset, fetch, lambda url: True)
        result = http["server-version-disclosure"].run(self.target, NOW)
        self.assertEqual(result.outcome, Outcome.DETECTED)
        self.assertEqual(fetch.calls[0][0], "HEAD")
        self.assertEqual(result.observations, {"server": "Apache/2.4.49 (Unix)"})


class ScopeAuthorizerTests(unittest.TestCase):
    def setUp(self):
        project = uuid4()
        revision = ScopeRevision(
            id=uuid4(), project_id=project, number=1, created_at=NOW,
            rules=(ScopeRule.parse("*.acme-corp.com"), ScopeRule.parse("old.acme-corp.com", effect="exclude")),
            authorization=AuthorizationReference(AuthorizationKind.ASSET_OWNER, "TEST-1", "asset owner"),
            permitted_ports=PortSet.parse("443"),
        )
        self.policy = ScopePolicy(project, revision, clock=lambda: NOW)
        self.addresses = {"shop.acme-corp.com": ["93.184.215.14"], "rebind.acme-corp.com": ["10.0.0.5"]}

    def run_check(self, host, port=None):
        fetch = FakeFetcher({f"https://{host}{'' if port is None else f':{port}'}/.git/config": response(404)})
        authorize = scope_authorizer(self.policy, lambda name, port: self.addresses.get(name, []))
        http, _ = build_checks(load_manifest(), fetch, authorize)
        return http["exposed-git-config"].run(Endpoint(host, port=port), NOW), fetch

    def test_in_scope_endpoint_is_checked(self):
        result, fetch = self.run_check("shop.acme-corp.com")
        self.assertEqual(result.outcome, Outcome.NOT_DETECTED)
        self.assertEqual(len(fetch.calls), 1)

    def test_out_of_scope_excluded_wrong_port_rebinding_and_unresolved_are_refused(self):
        for host, port, reason in (("shop.other.com", None, "no include rule"),
                                   ("old.acme-corp.com", None, "excluded"),
                                   ("shop.acme-corp.com", 8443, "port"),
                                   ("rebind.acme-corp.com", None, "resolves to"),
                                   ("ghost.acme-corp.com", None, "no addresses")):
            with self.subTest(host=host, port=port):
                result, fetch = self.run_check(host, port)
                self.assertEqual(result.outcome, Outcome.FAILED)
                self.assertIn(reason, result.detail)
                self.assertEqual(fetch.calls, [])


class ComponentCheckTests(unittest.TestCase):
    def setUp(self):
        self.ruleset = load_manifest()
        self.check = VulnerableComponentCheck(self.ruleset.get("vulnerable-component"))
        self.target = Endpoint("shop.example.com")

    def banner(self, server, status=200):
        headers = [("Server", server)] if server else []
        fetch = FakeFetcher({"https://shop.example.com/": response(status, headers=headers)})
        http, _ = build_checks(self.ruleset, fetch, lambda url: True)
        return http["server-version-disclosure"].run(self.target, NOW)

    def test_parse_banner(self):
        self.assertEqual(parse_banner("Apache/2.4.49 (Unix) OpenSSL/1.1.1k"),
                         [("apache", "2.4.49"), ("openssl", "1.1.1k")])
        self.assertEqual(parse_banner("nginx"), [("nginx", "")])

    def test_affected_version_creates_one_result_per_advisory(self):
        results = {r.variant: r for r in self.check.evaluate(self.banner("Apache/2.4.49 (Unix)"), ADVISORIES)}
        self.assertEqual(set(results), {"CVE-2021-41773", "CVE-2021-42013"})
        first = results["CVE-2021-41773"]
        self.assertEqual((first.outcome, first.confidence, first.severity), (Outcome.DETECTED, "firm", "high"))
        self.assertEqual(results["CVE-2021-42013"].severity, "critical")
        self.assertEqual(first.location, "component:apache:http_server")
        self.assertEqual(first.cves, ("CVE-2021-41773",))

    def test_backported_build_is_only_tentative(self):
        result = self.check.evaluate(self.banner("Apache/2.4.49-1ubuntu1"), ADVISORIES)[0]
        self.assertEqual((result.outcome, result.confidence), (Outcome.DETECTED, "tentative"))
        self.assertEqual(result.evidence["applicability"], "possible")

    def test_retest_outcomes(self):
        advisory = ADVISORIES[0]
        cases = [
            (self.banner("Apache/2.4.51"), Outcome.NOT_DETECTED),
            (self.banner("Apache/2.4.49"), Outcome.DETECTED),
            (self.banner(None), Outcome.INCONCLUSIVE),
            (self.banner("Apache"), Outcome.INCONCLUSIVE),
        ]
        for source, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(self.check.evaluate_variant(source, advisory).outcome, expected)
        failed = build_checks(self.ruleset, FakeFetcher({"https://shop.example.com/": OSError("down")}),
                              lambda url: True)[0]["server-version-disclosure"].run(self.target, NOW)
        self.assertEqual(self.check.evaluate_variant(failed, advisory).outcome, Outcome.FAILED)


if __name__ == "__main__":
    unittest.main()
