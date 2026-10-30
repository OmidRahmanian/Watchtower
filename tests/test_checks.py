from datetime import datetime, UTC
import http.server
import ipaddress
import json
from pathlib import Path
import shutil
import socket
import ssl
import tempfile
import threading
import unittest
from unittest import mock
from uuid import uuid4

from checks_support import TEST_APPROVER, allow, approve, approved_ruleset
from watchtower.adapters.checks import (
    Authorization, Endpoint, HttpRuleCheck, Outcome, RuleNotApproved, build_checks, load_manifest, pinned_fetcher,
    scope_authorizer,
)
from watchtower.adapters.checks import http as http_checks
from watchtower.domain.scope import AuthorizationKind, AuthorizationReference, ScopePolicy, ScopeRevision, ScopeRule
from watchtower.domain.targets import PortSet
from watchtower.adapters.checks.base import HttpResponse
from watchtower.adapters.checks.component import VulnerableComponentCheck, parse_banner
from watchtower.domain.models import Severity
from watchtower.adapters.checks.manifest import RULES_ROOT, RuleIntegrityError, digest, unpinned_files, validate_definition
from watchtower.domain.models import FindingStatus
from watchtower.services.findings import FindingService

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
        self.addresses = []

    def __call__(self, method, url, ip):
        self.calls.append((method, url))
        self.addresses.append(ip)
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
        """A fresh copy of the shipped manifest, independent of earlier saves."""
        return json.loads((RULES_ROOT / "manifest.json").read_text())

    def save(self, manifest):
        (self.root / "manifest.json").write_text(json.dumps(manifest))

    def test_shipped_rules_are_pinned_reviewed_and_pending_approval(self):
        ruleset = load_manifest()
        self.assertEqual(set(ruleset.rules), {"exposed-git-config", "exposed-env-file", "directory-listing",
                                              "server-version-disclosure", "vulnerable-component"})
        self.assertEqual(unpinned_files(), [])
        for rule in ruleset:
            self.assertTrue(rule.review["reviewer"])
            self.assertEqual(rule.review["status"], "pending")
            self.assertFalse(rule.approved)
        self.assertEqual(ruleset.pending, sorted(ruleset.rules))

    def test_human_approval_of_the_pinned_hash_makes_a_rule_runnable(self):
        self.save(approve(self.manifest()))
        ruleset = load_manifest(self.root)
        self.assertEqual(ruleset.pending, [])
        self.assertEqual(ruleset.get("exposed-git-config").review["approved_by"], TEST_APPROVER)

    def test_invalid_approval_records_are_rejected(self):
        pending = [
            ("status must be", lambda review: review.pop("status")),
            ("status must be", lambda review: review.update(status="approved-ish")),
            ("pending review must not carry", lambda review: review.update(approved_by="Jane Maintainer")),
        ]
        approved = [
            ("needs approved_by", lambda review: review.pop("approved_by")),
            ("needs approved_by", lambda review: review.update(approved_by="  ")),
            ("needs approved_at", lambda review: review.pop("approved_at")),
            ("needs approved_at", lambda review: review.update(approved_at="yesterday")),
            ("approval covers other content", lambda review: review.update(approved_sha256="0" * 64)),
            ("approval covers other content", lambda review: review.pop("approved_sha256")),
        ]
        for manifest_for, cases in ((self.manifest, pending), (lambda: approve(self.manifest()), approved)):
            for message, change in cases:
                with self.subTest(message=message):
                    manifest = manifest_for()
                    change(manifest["rules"][0]["review"])
                    self.save(manifest)
                    with self.assertRaisesRegex(RuleIntegrityError, message):
                        load_manifest(self.root)

    def test_agents_and_automation_cannot_approve(self):
        for approver in ("agent-03 (Claude); pending maintainer sign-off", "Claude", "claude-opus-5-5",
                         "Agent 4", "watchtower-agent", "dependabot[bot]", "release-bot", "CI", "GPT-5",
                         "GitHub Copilot", "automated approval", "AI reviewer"):
            with self.subTest(approver=approver):
                self.save(approve(self.manifest(), approver=approver))
                with self.assertRaisesRegex(RuleIntegrityError, "only a human maintainer may approve"):
                    load_manifest(self.root)

    def test_editing_an_approved_rule_needs_a_new_approval(self):
        manifest = approve(self.manifest())
        path = self.root / "http" / "exposed-git-config.json"
        path.write_text(path.read_text().replace('"high"', '"low"'))
        entry = next(entry for entry in manifest["rules"] if entry["id"] == "exposed-git-config")
        entry["sha256"] = digest(path)
        self.save(manifest)
        with self.assertRaisesRegex(RuleIntegrityError, "approval covers other content"):
            load_manifest(self.root)
        entry["review"].update(status="pending")
        for name in ("approved_by", "approved_at", "approved_sha256"):
            entry["review"].pop(name)
        self.save(manifest)
        self.assertEqual(load_manifest(self.root).pending, ["exposed-git-config"])

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


class PendingRuleTests(unittest.TestCase):
    """The shipped rules are pending approval: nothing may run them or send a request."""

    def setUp(self):
        self.ruleset = load_manifest()
        self.fetch = FakeFetcher({})
        self.authorized = []

    def authorize(self, url):
        self.authorized.append(url)
        return Authorization(True, ("203.0.113.10",))

    def test_pending_http_rules_refuse_before_authorizing_or_sending(self):
        http, _ = build_checks(self.ruleset, self.fetch, self.authorize)
        self.assertEqual(set(http), {"exposed-git-config", "exposed-env-file", "directory-listing",
                                     "server-version-disclosure"})
        runners = [check.run for check in http.values()]
        runners.append(HttpRuleCheck(self.ruleset.get("exposed-git-config"), self.fetch, self.authorize).run)
        for run in runners:
            with self.subTest(run=run.__self__.rule.id), self.assertRaisesRegex(RuleNotApproved, "pending"):
                run(Endpoint("shop.example.com"), NOW)
        self.assertEqual((self.fetch.calls, self.authorized), ([], []))

    def test_pending_component_rule_refuses_to_evaluate(self):
        source = build_checks(approved_ruleset(), FakeFetcher({"https://shop.example.com/": response(
            200, headers=[("Server", "Apache/2.4.51")])}), allow("203.0.113.10"))[0]["server-version-disclosure"]
        result = source.run(Endpoint("shop.example.com"), NOW)
        _, component = build_checks(self.ruleset, self.fetch, self.authorize)
        check = component["vulnerable-component"]
        with self.assertRaises(RuleNotApproved):
            check.evaluate(result, ADVISORIES)
        with self.assertRaises(RuleNotApproved):
            check.evaluate_variant(result, ADVISORIES[0])

    def test_pending_rule_cannot_resolve_a_finding(self):
        approved = approved_ruleset()
        service = FindingService(canonical_id=approved.canonical_id)
        exposed = FakeFetcher({"https://shop.example.com/.git/config": response(200, GIT_CONFIG)})
        detected = build_checks(approved, exposed, allow("203.0.113.10"))[0]["exposed-git-config"]
        finding = service.ingest(detected.run(Endpoint("shop.example.com"), NOW))
        service.request_retest(finding.fingerprint, "analyst", NOW)

        gone = FakeFetcher({"https://shop.example.com/.git/config": response(404)})
        pending = build_checks(self.ruleset, gone, self.authorize)[0]["exposed-git-config"]
        with self.assertRaises(RuleNotApproved):
            service.apply_retest(finding.fingerprint, pending.run(Endpoint("shop.example.com"), NOW))
        self.assertEqual((gone.calls, self.authorized), ([], []))
        self.assertEqual(finding.status, FindingStatus.OPEN)
        self.assertIsNotNone(finding.retest_requested_at)

    def test_approved_rule_in_a_test_manifest_runs(self):
        fetch = FakeFetcher({"https://shop.example.com/.git/config": response(404)})
        http, _ = build_checks(approved_ruleset(), fetch, self.authorize)
        result = http["exposed-git-config"].run(Endpoint("shop.example.com"), NOW)
        self.assertEqual(result.outcome, Outcome.NOT_DETECTED)
        self.assertEqual((len(fetch.calls), len(self.authorized)), (1, 1))


class HttpCheckTests(unittest.TestCase):
    def setUp(self):
        self.ruleset = approved_ruleset()
        self.target = Endpoint("Shop.Example.com.")
        self.url = "https://shop.example.com/.git/config"

    def run_git(self, result, authorize=allow("203.0.113.10")):
        fetch = FakeFetcher({self.url: result})
        http, _ = build_checks(self.ruleset, fetch, authorize)
        return http["exposed-git-config"].run(self.target, NOW), fetch

    def test_detects_exposed_git_config_with_redacted_evidence(self):
        result, fetch = self.run_git(response(200, GIT_CONFIG, [("Server", "nginx"), ("Set-Cookie", "s=1")]))
        self.assertEqual(result.outcome, Outcome.DETECTED)
        self.assertEqual(fetch.calls, [("GET", self.url)])
        self.assertEqual(fetch.addresses, ["203.0.113.10"])
        self.assertEqual(result.target.resolved_ip, "203.0.113.10")
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
        for decision in (Authorization(False, ("203.0.113.10",), "denied"), Authorization(True, ()), True, False):
            with self.subTest(decision=decision):
                result, fetch = self.run_git(response(200, GIT_CONFIG), authorize=lambda url: decision)
                self.assertEqual(result.outcome, Outcome.FAILED)
                self.assertIn("not authorized", result.detail)
                self.assertEqual(fetch.calls, [])

    def test_default_authorizer_denies(self):
        fetch = FakeFetcher({})
        http, _ = build_checks(self.ruleset, fetch)
        self.assertEqual(http["directory-listing"].run(self.target, NOW).outcome, Outcome.FAILED)
        self.assertEqual(fetch.calls, [])

    def test_env_file_keeps_key_names_only(self):
        body = b"APP_NAME=shop\nDB_PASSWORD=hunter2\nAWS_SECRET_ACCESS_KEY=abc/def\n"
        fetch = FakeFetcher({"https://shop.example.com/.env": response(200, body)})
        http, _ = build_checks(self.ruleset, fetch, allow("203.0.113.10"))
        result = http["exposed-env-file"].run(self.target, NOW)
        self.assertEqual(result.outcome, Outcome.DETECTED)
        excerpt = result.evidence["response"]["body_excerpt"]
        self.assertIn("DB_PASSWORD=[REDACTED]", excerpt)
        for secret in ("shop\n", "hunter2", "abc/def"):
            self.assertNotIn(secret, excerpt)

    def test_server_banner_is_extracted(self):
        fetch = FakeFetcher({"https://shop.example.com/": response(200, headers=[("Server", "Apache/2.4.49 (Unix)")])})
        http, _ = build_checks(self.ruleset, fetch, allow("203.0.113.10"))
        result = http["server-version-disclosure"].run(self.target, NOW)
        self.assertEqual(result.outcome, Outcome.DETECTED)
        self.assertEqual(fetch.calls[0][0], "HEAD")
        self.assertEqual(result.observations, {"server": "Apache/2.4.49 (Unix)"})


class ScopeAuthorizerTests(unittest.TestCase):
    @staticmethod
    def policy_for_acme():
        project = uuid4()
        revision = ScopeRevision(
            id=uuid4(), project_id=project, number=1, created_at=NOW,
            rules=(ScopeRule.parse("*.acme-corp.com"), ScopeRule.parse("old.acme-corp.com", effect="exclude")),
            authorization=AuthorizationReference(AuthorizationKind.ASSET_OWNER, "TEST-1", "asset owner"),
            permitted_ports=PortSet.parse("443"),
        )
        return ScopePolicy(project, revision, clock=lambda: NOW)

    def setUp(self):
        self.policy = self.policy_for_acme()
        self.addresses = {"shop.acme-corp.com": ["93.184.215.14"], "rebind.acme-corp.com": ["10.0.0.5"]}

    def run_check(self, host, port=None):
        fetch = FakeFetcher({f"https://{host}{'' if port is None else f':{port}'}/.git/config": response(404)})
        authorize = scope_authorizer(self.policy, lambda name, port: self.addresses.get(name, []))
        http, _ = build_checks(approved_ruleset(), fetch, authorize)
        return http["exposed-git-config"].run(Endpoint(host, port=port), NOW), fetch

    def test_in_scope_endpoint_is_checked(self):
        result, fetch = self.run_check("shop.acme-corp.com")
        self.assertEqual(result.outcome, Outcome.NOT_DETECTED)
        self.assertEqual(fetch.addresses, ["93.184.215.14"])

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


class RecordingHandler(http.server.BaseHTTPRequestHandler):
    requests: list = []
    body = b"[core]\n\trepositoryformatversion = 0\n"

    def do_GET(self):
        self.requests.append((self.command, self.path, self.headers["Host"]))
        self.send_response(200)
        self.end_headers()
        self.wfile.write(self.body)

    def do_HEAD(self):
        self.requests.append((self.command, self.path, self.headers["Host"]))
        self.send_response(200)
        self.send_header("X-Probe", "head")
        self.end_headers()

    def log_message(self, *args):
        pass


class PinnedFetcherTests(unittest.TestCase):
    def setUp(self):
        RecordingHandler.requests = []
        self.server = http.server.HTTPServer(("127.0.0.1", 0), RecordingHandler)
        self.port = self.server.server_address[1]
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    def test_connects_to_the_given_ip_with_the_hostname_as_host_and_never_resolves(self):
        url = f"http://shop.example.com:{self.port}/.git/config?x=1"
        real_getaddrinfo = socket.getaddrinfo

        def numeric_only(host, *args, **kwargs):
            ipaddress.ip_address(host)  # connecting to an IP literal is fine; a hostname lookup is not
            return real_getaddrinfo(host, *args, **kwargs)

        with mock.patch("socket.getaddrinfo", side_effect=numeric_only):
            reply = pinned_fetcher("GET", url, "127.0.0.1")
            head = pinned_fetcher("HEAD", f"http://shop.example.com:{self.port}/", "127.0.0.1")
        self.assertEqual((reply.status, reply.body, reply.truncated), (200, RecordingHandler.body, False))
        self.assertEqual((head.header("x-probe"), head.body), ("head", b""))
        self.assertEqual(RecordingHandler.requests, [("GET", "/.git/config?x=1", f"shop.example.com:{self.port}"),
                                                     ("HEAD", "/", f"shop.example.com:{self.port}")])

    def test_large_bodies_are_truncated(self):
        with mock.patch.object(http_checks, "MAX_BODY", 8):
            reply = pinned_fetcher("GET", f"http://shop.example.com:{self.port}/", "127.0.0.1")
        self.assertEqual((reply.body, reply.truncated), (RecordingHandler.body[:8], True))

    def test_https_uses_the_hostname_for_sni_and_verifies_certificates(self):
        sock = mock.MagicMock()
        context = mock.MagicMock()
        context.wrap_socket.side_effect = ssl.SSLCertVerificationError("bad certificate")
        with mock.patch("socket.create_connection", return_value=sock) as connect, \
                mock.patch.object(http_checks.ssl, "create_default_context", return_value=context), \
                self.assertRaises(ssl.SSLCertVerificationError):
            pinned_fetcher("GET", "https://shop.example.com/.git/config", "93.184.215.14")
        self.assertEqual(connect.call_args.args[0], ("93.184.215.14", 443))
        self.assertEqual(context.wrap_socket.call_args.kwargs["server_hostname"], "shop.example.com")
        self.assertNotEqual(context.verify_mode, ssl.CERT_NONE)

    def test_rebinding_to_loopback_after_authorization_never_reaches_loopback(self):
        policy = ScopeAuthorizerTests.policy_for_acme()
        answers = iter([["93.184.215.14"], ["127.0.0.1"], ["127.0.0.1"]])
        lookups = []

        def resolve(name, port):
            lookups.append(name)
            return next(answers)

        connected = []

        def create_connection(address, *args, **kwargs):
            connected.append(address[0])
            raise ConnectionRefusedError("test network is closed")

        check = build_checks(approved_ruleset(), pinned_fetcher, scope_authorizer(policy, resolve))[0]
        with mock.patch("socket.create_connection", side_effect=create_connection), \
                mock.patch("socket.getaddrinfo", side_effect=AssertionError("second resolution")):
            first = check["exposed-git-config"].run(Endpoint("shop.acme-corp.com"), NOW)
            second = check["exposed-git-config"].run(Endpoint("shop.acme-corp.com"), NOW)
        self.assertEqual(connected, ["93.184.215.14"])
        self.assertEqual(lookups, ["shop.acme-corp.com", "shop.acme-corp.com"])
        self.assertEqual((first.outcome, first.target.resolved_ip), (Outcome.FAILED, "93.184.215.14"))
        self.assertIn("ConnectionRefusedError", first.detail)
        self.assertEqual(second.outcome, Outcome.FAILED)
        self.assertIn("not authorized", second.detail)


class ComponentCheckTests(unittest.TestCase):
    def setUp(self):
        self.ruleset = approved_ruleset()
        self.check = VulnerableComponentCheck(self.ruleset.get("vulnerable-component"))
        self.target = Endpoint("shop.example.com")

    def banner(self, server, status=200):
        headers = [("Server", server)] if server else []
        fetch = FakeFetcher({"https://shop.example.com/": response(status, headers=headers)})
        http, _ = build_checks(self.ruleset, fetch, allow("203.0.113.10"))
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
                              allow("203.0.113.10"))[0]["server-version-disclosure"].run(self.target, NOW)
        self.assertEqual(self.check.evaluate_variant(failed, advisory).outcome, Outcome.FAILED)


if __name__ == "__main__":
    unittest.main()
