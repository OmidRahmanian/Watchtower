"""HTTP/TLS probe tests against local servers that count every request they receive."""
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from inventory_support import FakeScope, MemoryUnitOfWork, StepClock, deny_all_policy, scope_policy
from watchtower.adapters.probing import DISABLED_ADAPTERS, PinnedHTTPConnection
from watchtower.adapters.probing.http import HttpProber
from watchtower.domain.models import ObservationKind
from watchtower.services.inventory import DiscoveredName, InventoryService

LOCAL = "127.0.0.1"


class CountingServer:
    """Serves canned responses per path and records each request's Host header."""

    def __init__(self, routes, tls_context=None):
        self.routes = routes
        self.requests = []
        server = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                server.requests.append((self.headers.get("Host"), self.path))
                status, headers, body = server.routes.get(self.path, (404, {}, b"missing"))
                self.send_response(status)
                for key, value in headers.items():
                    self.send_header(key, value.format(port=server.port))
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        self.httpd = ThreadingHTTPServer((LOCAL, 0), Handler)
        if tls_context:
            self.httpd.socket = tls_context.wrap_socket(self.httpd.socket, server_side=True)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


class ProbeTests(unittest.TestCase):
    def setUp(self):
        self.servers = []
        self.resolved = []

    def tearDown(self):
        for server in self.servers:
            server.close()

    def serve(self, routes, **kwargs):
        server = CountingServer(routes, **kwargs)
        self.servers.append(server)
        return server

    def resolver(self, mapping=None):
        def resolve(host, port):
            self.resolved.append(host)
            return (mapping or {}).get(host, [LOCAL])
        return resolve

    def prober(self, scope, **kwargs):
        kwargs.setdefault("resolve", self.resolver())
        return HttpProber(scope, timeout=3.0, clock=StepClock(), **kwargs)

    def test_records_status_title_headers_and_body_hash(self):
        server = self.serve({"/": (200, {"Server": "fixture", "X-Secret": "dropped"}, b"<html><title> Hello &amp; welcome </title></html>")})
        result = self.prober(FakeScope()).probe("www.example.com", scheme="http", port=server.port)
        self.assertEqual(result["outcome"], "ok")
        self.assertEqual((result["status_code"], result["title"], result["ip"]), (200, "Hello & welcome", LOCAL))
        self.assertEqual(result["headers"], {"server": "fixture", "content-length": "49"})
        self.assertEqual(len(result["body_sha256"]), 64)
        self.assertEqual(server.requests, [(f"www.example.com:{server.port}", "/")])

    def test_unauthorized_target_gets_no_dns_and_no_traffic(self):
        server = self.serve({"/": (200, {}, b"")})
        result = self.prober(FakeScope(excluded={"admin.example.com"})).probe("admin.example.com", scheme="http", port=server.port)
        self.assertEqual(result["outcome"], "unauthorized")
        self.assertEqual((server.requests, self.resolved), ([], []))

    def test_project_without_scope_sends_nothing(self):
        server = self.serve({"/": (200, {}, b"")})
        result = HttpProber(deny_all_policy(), resolve=self.resolver()).probe("www.example.com", scheme="http", port=server.port)
        self.assertEqual(result["outcome"], "unauthorized")
        self.assertEqual(server.requests, [])

    def test_prohibited_destination_gets_no_traffic(self):
        server = self.serve({"/": (200, {}, b"")})
        scope = FakeScope(destinations={("198.51.100.10", server.port)})
        result = self.prober(scope).probe("www.example.com", scheme="http", port=server.port)
        self.assertEqual(result["outcome"], "blocked_destination")
        self.assertIn("prohibited_destination", result["error"]["message"])
        self.assertEqual(server.requests, [])

    def test_real_policy_blocks_loopback_metadata_and_rebinding(self):
        server = self.serve({"/": (200, {}, b"")})
        policy = scope_policy(ports=f"80,443,{server.port}")
        for addresses in ([LOCAL], ["169.254.169.254"], ["93.184.216.34", LOCAL], ["::ffff:127.0.0.1"], ["10.0.0.5"]):
            prober = HttpProber(policy, resolve=self.resolver({"www.example.com": addresses}))
            result = prober.probe("www.example.com", scheme="http", port=server.port)
            self.assertEqual(result["outcome"], "blocked_destination", addresses)
            self.assertIn("prohibited_destination", result["error"]["message"])
        self.assertEqual(server.requests, [])

    def test_real_policy_rejects_ports_outside_scope_before_resolving(self):
        result = HttpProber(scope_policy(), resolve=self.resolver()).probe("www.example.com", scheme="http", port=8080)
        self.assertEqual(result["outcome"], "unauthorized")
        self.assertIn("port_not_permitted", result["error"]["message"])
        self.assertEqual(self.resolved, [])

    def test_connection_check_receives_every_resolved_address(self):
        server = self.serve({"/": (200, {}, b"")})
        scope = FakeScope()
        self.prober(scope, resolve=self.resolver({"www.example.com": [LOCAL, LOCAL, "::1"]})).probe(
            "www.example.com", scheme="http", port=server.port)
        self.assertIn(("connection", "www.example.com", server.port, (LOCAL, "::1")), scope.calls)

    def test_redirect_out_of_scope_is_not_followed(self):
        outside = self.serve({"/": (200, {}, b"")})
        server = self.serve({"/": (302, {"Location": f"http://login.example.org:{outside.port}/"}, b"")})
        result = self.prober(FakeScope()).probe("www.example.com", scheme="http", port=server.port)
        self.assertEqual(result["status_code"], 302)
        self.assertEqual(result["redirects"][0]["followed"], False)
        self.assertIn("not_in_scope", result["redirects"][0]["reason"])
        self.assertEqual(outside.requests, [])
        self.assertNotIn("login.example.org", self.resolved)

    def test_redirect_to_prohibited_destination_gets_no_traffic(self):
        other = self.serve({"/": (200, {}, b"")})
        server = self.serve({"/": (301, {"Location": f"http://api.example.com:{other.port}/"}, b"")})
        scope = FakeScope(destinations={(LOCAL, server.port)})
        result = self.prober(scope).probe("www.example.com", scheme="http", port=server.port)
        self.assertEqual(result["outcome"], "blocked_destination")
        self.assertTrue(result["redirects"][0]["followed"])
        self.assertEqual(other.requests, [])

    def test_redirect_to_excluded_host_is_not_resolved_or_contacted(self):
        other = self.serve({"/": (200, {}, b"")})
        server = self.serve({"/": (302, {"Location": f"http://admin.example.com:{other.port}/"}, b"")})
        result = self.prober(FakeScope(excluded={"admin.example.com"})).probe("www.example.com", scheme="http", port=server.port)
        self.assertFalse(result["redirects"][0]["followed"])
        self.assertEqual(other.requests, [])
        self.assertNotIn("admin.example.com", self.resolved)

    def test_in_scope_redirects_are_followed_up_to_the_limit(self):
        server = self.serve({
            "/": (302, {"Location": "/a"}, b""),
            "/a": (302, {"Location": "http://api.example.com:{port}/b?x=1"}, b""),
            "/b?x=1": (302, {"Location": "/c"}, b""),
            "/c": (200, {}, b"<title>done</title>"),
        })
        scope = FakeScope()
        result = self.prober(scope, max_redirects=2).probe("www.example.com", scheme="http", port=server.port)
        self.assertEqual([path for _, path in server.requests], ["/", "/a", "/b?x=1"])
        self.assertEqual(server.requests[2][0], f"api.example.com:{server.port}")
        self.assertEqual([hop["followed"] for hop in result["redirects"]], [True, True, False])
        self.assertEqual(result["redirects"][2]["reason"], "redirect limit reached")
        self.assertEqual(len([c for c in scope.calls if c[0] == "redirect"]), 2)

    def test_body_read_is_bounded(self):
        server = self.serve({"/": (200, {}, b"a" * 5000)})
        result = self.prober(FakeScope(), max_body_bytes=1000).probe("www.example.com", scheme="http", port=server.port)
        self.assertEqual((result["body_bytes"], result["truncated"]), (1000, True))

    def test_http_errors_stay_observations_and_never_delete_assets(self):
        server = self.serve({"/": (500, {}, b"<title>Internal error</title>")})
        with socket.socket() as closed:
            closed.bind((LOCAL, 0))
            refused_port = closed.getsockname()[1]
        uow = MemoryUnitOfWork()
        inventory = InventoryService(uow, clock=StepClock())
        inventory.record_discovery(DiscoveredName("www.example.com", "manual", "example.com"))
        prober = self.prober(FakeScope())

        inventory.record_http(prober.probe("www.example.com", scheme="http", port=server.port))
        inventory.record_http(prober.probe("www.example.com", scheme="http", port=refused_port))

        self.assertEqual(len(inventory.assets()), 1)
        asset = inventory.get("www.example.com")
        http = [row.data for row in uow.history(asset, ObservationKind.HTTP_RESPONSE)]
        self.assertEqual([(o["outcome"], o["status_code"]) for o in http], [("ok", 500), ("error", None)])
        self.assertEqual(http[1]["error"]["kind"], "connection_refused")
        self.assertEqual(asset.attributes["last_http"]["outcome"], "error")

    def test_unresolvable_host_is_an_error_observation(self):
        result = self.prober(FakeScope(), resolve=self.resolver({"www.example.com": []})).probe("www.example.com", scheme="http")
        self.assertEqual((result["outcome"], result["error"]["kind"]), ("error", "dns_error"))

    def test_pinned_connection_never_resolves_its_hostname(self):
        server = self.serve({"/": (200, {}, b"pinned")})
        real_getaddrinfo = socket.getaddrinfo

        def literal_only(host, *args, **kwargs):
            # create_connection passes the IP literal through getaddrinfo; any name means a DNS lookup.
            if host != LOCAL:
                raise AssertionError(f"{host} was resolved")
            return real_getaddrinfo(host, *args, **kwargs)

        with patch("socket.getaddrinfo", literal_only):
            connection = PinnedHTTPConnection("unresolvable.invalid", LOCAL, server.port, timeout=3.0)
            try:
                connection.request("GET", "/")
                self.assertEqual(connection.getresponse().read(), b"pinned")
            finally:
                connection.close()
        self.assertEqual(server.requests, [(f"unresolvable.invalid:{server.port}", "/")])

    def test_httpx_cli_adapter_stays_disabled(self):
        self.assertIn("httpx-cli", DISABLED_ADAPTERS)


class RealPolicyRedirectTests(unittest.TestCase):
    """Redirect handling under the real ScopePolicy.

    The policy never allows loopback, so names resolve to a public address and
    the socket layer routes only that address to the local test server.
    Every connection attempt is recorded.
    """

    PUBLIC = "93.184.216.34"

    def setUp(self):
        self.connections = []
        real_connect = socket.create_connection

        def connect(address, *args, **kwargs):
            self.connections.append(address)
            host, port = address
            return real_connect((LOCAL if host == self.PUBLIC else host, port), *args, **kwargs)

        patcher = patch("watchtower.adapters.probing.http.socket.create_connection", connect)
        patcher.start()
        self.addCleanup(patcher.stop)

    def probe(self, routes):
        self.server = CountingServer(routes)
        self.addCleanup(self.server.close)
        policy = scope_policy(ports=f"80,443,{self.server.port}")
        prober = HttpProber(policy, resolve=lambda host, port: [self.PUBLIC], timeout=3.0)
        return prober.probe("www.example.com", scheme="http", port=self.server.port)

    def test_in_scope_redirect_is_followed(self):
        result = self.probe({"/": (302, {"Location": "http://api.example.com:{port}/next"}, b""),
                             "/next": (200, {}, b"<title>api</title>")})
        self.assertEqual((result["outcome"], result["title"]), ("ok", "api"))
        self.assertEqual([host for host, _ in self.server.requests], [f"www.example.com:{self.server.port}", f"api.example.com:{self.server.port}"])

    def test_redirects_to_prohibited_or_out_of_scope_targets_get_no_traffic(self):
        for location, reason in (("http://169.254.169.254/latest/meta-data/", "prohibited_destination"),
                                 ("http://127.0.0.1:{port}/", "prohibited_destination"),
                                 ("http://localhost:{port}/", "prohibited_destination"),
                                 ("http://login.example.org:{port}/", "not_in_scope"),
                                 ("http://api.example.com:9999/", "port_not_permitted"),
                                 ("ftp://files.example.com/", "")):
            self.connections.clear()
            result = self.probe({"/": (302, {"Location": location}, b"")})
            hop = result["redirects"][0]
            self.assertFalse(hop["followed"], location)
            self.assertIn(reason, hop["reason"], location)
            self.assertEqual(self.connections, [(self.PUBLIC, self.server.port)], location)


@unittest.skipUnless(shutil.which("openssl"), "openssl is needed to mint a test certificate")
class TlsProbeTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        cert, key = Path(directory.name) / "cert.pem", Path(directory.name) / "key.pem"
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
             "-subj", "/CN=secure.example.com", "-keyout", str(key), "-out", str(cert)],
            check=True, capture_output=True, timeout=60,
        )
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        self.server = CountingServer({"/": (200, {}, b"<title>secure</title>")}, tls_context=context)
        self.addCleanup(self.server.close)

    def test_self_signed_certificate_is_recorded_and_http_still_inventoried(self):
        prober = HttpProber(FakeScope(), resolve=lambda host, port: [LOCAL], timeout=3.0)
        result = prober.probe("secure.example.com", scheme="https", port=self.server.port)
        self.assertEqual((result["outcome"], result["status_code"], result["title"]), ("ok", 200, "secure"))
        tls = result["tls"]
        self.assertFalse(tls["verified"])
        self.assertIn("self", tls["verify_error"])
        self.assertEqual(len(tls["sha256"]), 64)
        self.assertTrue(tls["version"].startswith("TLS"))

        uow = MemoryUnitOfWork()
        inventory = InventoryService(uow, clock=StepClock())
        inventory.record_discovery(DiscoveredName("secure.example.com", "manual", "example.com"))
        asset = inventory.record_http(result)
        self.assertEqual([row.kind for row in uow.history(asset)], ["discovery", "http_response", "tls_certificate"])
        self.assertEqual(uow.history(asset, ObservationKind.TLS_CERTIFICATE)[0].data["sha256"], tls["sha256"])

    def test_unverified_retry_can_be_disabled(self):
        prober = HttpProber(FakeScope(), resolve=lambda host, port: [LOCAL], timeout=3.0, retry_unverified_tls=False)
        result = prober.probe("secure.example.com", scheme="https", port=self.server.port)
        self.assertEqual((result["outcome"], result["error"]["kind"]), ("error", "tls_error"))
        self.assertEqual(self.server.requests, [])


if __name__ == "__main__":
    unittest.main()
