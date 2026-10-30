from datetime import datetime, UTC
import unittest

from watchtower.adapters.checks.base import HttpResponse
from watchtower.services.evidence import EXCERPT_LIMIT, EvidenceStore, http_evidence, redact_headers, redact_text, redact_url

NOW = datetime(2026, 10, 30, 12, tzinfo=UTC)


class RedactionTests(unittest.TestCase):
    def test_common_secret_shapes_are_redacted(self):
        secrets = {
            "aws key": "id AKIAABCDEFGHIJKLMNOP here",
            "jwt": "token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ.c2lnbmF0dXJlLXZhbHVl",
            "bearer": "Authorization: Bearer abcdef123456789",
            "url credentials": "url = https://deploy:s3cretpass@github.com/acme/site.git",
            "password field": '{"password": "letmein-123"}',
            "api key": "api_key=sk_live_0123456789",
            "private key": "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----",
        }
        leaked = ("AKIAABCDEFGHIJKLMNOP", "c2lnbmF0dXJlLXZhbHVl", "abcdef123456789", "s3cretpass",
                  "letmein-123", "sk_live_0123456789", "MIIEow")
        for name, text in secrets.items():
            with self.subTest(name=name):
                redacted, count = redact_text(text)
                self.assertGreater(count, 0)
                for value in leaked:
                    self.assertNotIn(value, redacted)

    def test_env_profile_redacts_every_value(self):
        redacted, count = redact_text("APP_ENV=production\nexport HOST=db.internal\n# comment\n", "env")
        self.assertEqual(redacted, "APP_ENV=[REDACTED]\nexport HOST=[REDACTED]\n# comment\n")
        self.assertEqual(count, 2)

    def test_default_profile_keeps_plain_content(self):
        text = "<title>Index of /</title><a href=\"backup/\">backup/</a>"
        self.assertEqual(redact_text(text), (text, 0))

    def test_urls_and_headers(self):
        self.assertEqual(redact_url("https://user:pw@example.com/a?token=abc&page=2#frag"),
                         "https://example.com/a?token=[REDACTED]&page=2")
        headers = redact_headers([("Cookie", "sid=1"), ("Server", "nginx"), ("X-Internal-Trace", "drop-me")])
        self.assertEqual(headers, [["Cookie", "[REDACTED]"], ["Server", "nginx"]])

    def test_excerpt_is_bounded_and_digest_excludes_raw_secrets(self):
        body = ("x" * 5000 + "\npassword=hunter2\n" + "y" * 5000).encode()
        evidence = http_evidence("https://example.com/", "GET", HttpResponse(200, (), body), observed_at=NOW,
                                 check_id="c", rule_version="1", match_span=(5001, 5010))
        excerpt = evidence["response"]["body_excerpt"]
        self.assertLessEqual(len(excerpt), EXCERPT_LIMIT)
        self.assertIn("password=[REDACTED]", excerpt)
        self.assertNotIn("hunter2", str(evidence))


class EvidenceStoreTests(unittest.TestCase):
    def test_store_is_content_addressed_and_immutable(self):
        store = EvidenceStore()
        item = {"kind": "http", "value": [1]}
        key = store.add(item)
        self.assertEqual(store.add(dict(item)), key)
        item["value"].append(2)
        copy = store.get(key)
        copy["value"].append(3)
        self.assertEqual(store.get(key)["value"], [1])
        self.assertEqual(len(store), 1)


if __name__ == "__main__":
    unittest.main()
