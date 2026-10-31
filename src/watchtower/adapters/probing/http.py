"""HTTP and TLS inventory probe that only connects to approved destinations.

For every hop: the hostname is checked with `check_target`, resolved once,
the resolved addresses are checked with `check_connection`, and the socket is
opened to that exact address (no second resolution, so no rebinding gap).
Redirects are never followed automatically: each Location goes through
`check_redirect` and then the same target and connection checks.
"""
from __future__ import annotations

import hashlib
import html
import http.client
import re
import socket
import ssl
import time
from collections.abc import Callable, Iterable
from datetime import datetime
from typing import Any
from urllib.parse import urlsplit

from watchtower.adapters.probing.guard import ScopeGuard, explain
from watchtower.services.inventory import isoformat, normalize_hostname, utcnow

DEFAULT_PORTS = {"http": 80, "https": 443}
KEPT_HEADERS = ("server", "content-type", "content-length", "location", "strict-transport-security", "x-powered-by")
USER_AGENT = "WatchTower-Inventory/1.0"


def _no_response() -> dict[str, Any]:
    return {
        "ip": "",
        "status_code": None,
        "title": "",
        "headers": {},
        "body_sha256": "",
        "body_bytes": 0,
        "truncated": False,
        "tls": None,
        "error": None,
    }


_TITLE = re.compile(rb"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


class ProbeError(Exception):
    def __init__(self, kind: str, message: str) -> None:
        super().__init__(message)
        self.kind = kind


def system_resolve(host: str, port: int) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ProbeError("dns_error", str(exc)) from exc
    return list(dict.fromkeys(info[4][0] for info in infos))


class PinnedHTTPConnection(http.client.HTTPConnection):
    """HTTP connection for `host` that only ever opens a socket to `ip:port`.

    The hostname is used for the Host header only; it is never resolved, so a
    DNS answer that changes after `check_connection` approved `ip` cannot
    redirect the connection (no rebinding window). Proxies are not used.
    """

    def __init__(self, host: str, ip: str, port: int, timeout: float) -> None:
        super().__init__(host, port, timeout=timeout)
        self._ip = ip

    def connect(self) -> None:
        self.sock = socket.create_connection((self._ip, self.port), self.timeout)


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection for `host` that only ever opens a socket to `ip:port`.

    `host` is used for SNI, certificate hostname checks and the Host header,
    and is never resolved, so the connection cannot be rebound to another
    address after `check_connection` approved `ip`. Proxies are not used.
    """

    def __init__(self, host: str, ip: str, port: int, timeout: float, context: ssl.SSLContext) -> None:
        super().__init__(host, port, timeout=timeout, context=context)
        self._ip = ip

    def connect(self) -> None:
        sock = socket.create_connection((self._ip, self.port), self.timeout)
        try:
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
        except BaseException:
            sock.close()
            raise


def _tls_details(sock: ssl.SSLSocket, verified: bool) -> dict[str, Any]:
    der = sock.getpeercert(binary_form=True) or b""
    details: dict[str, Any] = {
        "verified": verified,
        "version": sock.version(),
        "cipher": (sock.cipher() or ("",))[0],
        "sha256": hashlib.sha256(der).hexdigest() if der else "",
    }
    cert = sock.getpeercert() if verified else None
    if cert:
        flatten = lambda pairs: {key: value for rdn in pairs for key, value in rdn}
        details.update({
            "subject": flatten(cert.get("subject", ())),
            "issuer": flatten(cert.get("issuer", ())),
            "san": [value for kind, value in cert.get("subjectAltName", ()) if kind == "DNS"],
            "not_before": cert.get("notBefore", ""),
            "not_after": cert.get("notAfter", ""),
            "serial": cert.get("serialNumber", ""),
        })
    return details


def _title(body: bytes) -> str:
    match = _TITLE.search(body)
    if not match:
        return ""
    return " ".join(html.unescape(match.group(1).decode("utf-8", "replace")).split())[:512]


class HttpProber:
    def __init__(
        self,
        guard: ScopeGuard,
        *,
        resolve: Callable[[str, int], Iterable[str]] = system_resolve,
        timeout: float = 10.0,
        max_body_bytes: int = 256 * 1024,
        max_redirects: int = 0,
        retry_unverified_tls: bool = True,
        clock: Callable[[], datetime] = utcnow,
    ) -> None:
        self.guard = guard
        self._resolve = resolve
        self.timeout = timeout
        self.max_body_bytes = max_body_bytes
        self.max_redirects = max_redirects
        self.retry_unverified_tls = retry_unverified_tls
        self._clock = clock

    def probe(self, hostname: str, *, scheme: str = "https", port: int | None = None, path: str = "/") -> dict[str, Any]:
        hostname = normalize_hostname(hostname)
        port = port or DEFAULT_PORTS[scheme]
        netloc = hostname if port == DEFAULT_PORTS[scheme] else f"{hostname}:{port}"
        url = f"{scheme}://{netloc}{path}"
        observation: dict[str, Any] = {
            "hostname": hostname,
            "url": url,
            "observed_at": isoformat(self._clock()),
            "outcome": "",
            "scheme": scheme,
            "port": port,
            **_no_response(),
            "redirects": [],
        }

        decision = self.guard.check_target(hostname, port=port)
        if not decision:
            return {**observation, "outcome": "unauthorized", "error": {"kind": "unauthorized", "message": explain(decision)}}

        host = hostname
        for followed in range(self.max_redirects + 1):
            check_url = getattr(self.guard, "check_url", None)
            if check_url is not None:
                decision = check_url(url)
                if not decision:
                    return {**observation, "outcome": "unauthorized", "error": {"kind": "unauthorized", "message": explain(decision)}}
            try:
                ip = self._approved_address(host, port)
                response = self._fetch(host, ip, port, scheme, urlsplit(url))
            except ProbeError as exc:
                # Top-level fields describe the last URL attempted; earlier hops are in "redirects".
                outcome = "blocked_destination" if exc.kind == "blocked_destination" else "error"
                observation.update(_no_response(), url=url, scheme=scheme, port=port, outcome=outcome,
                                   error={"kind": exc.kind, "message": str(exc)})
                return observation
            observation.update(url=url, scheme=scheme, port=port, outcome="ok", **response)

            location = response["headers"].get("location")
            if not (300 <= response["status_code"] < 400 and location):
                return observation
            hop = {"url": url, "ip": ip, "status_code": response["status_code"], "location": location}
            observation["redirects"].append(hop)
            if followed == self.max_redirects:
                hop["followed"] = False
                hop["reason"] = "redirect limit reached"
                return observation

            verdict = self.guard.check_redirect(url, location, redirects_followed=followed)
            target = urlsplit(verdict.url or "") if verdict else None
            if target is None or target.scheme not in DEFAULT_PORTS or not target.hostname:
                hop.update(followed=False, reason=explain(verdict) if not verdict else "unsupported redirect target")
                return observation
            next_port = target.port or DEFAULT_PORTS[target.scheme]
            target_decision = self.guard.check_target(target.hostname, port=next_port)
            if not target_decision:
                hop.update(followed=False, reason=explain(target_decision))
                return observation
            hop["followed"] = True
            url, scheme, host, port = verdict.url, target.scheme, target.hostname, next_port
        return observation

    def _approved_address(self, host: str, port: int) -> str:
        addresses = list(dict.fromkeys(self._resolve(host, port)))
        if not addresses:
            raise ProbeError("dns_error", f"{host} did not resolve")
        # ScopePolicy denies the whole set if any address is prohibited or excluded
        # (loopback, metadata, private ranges, rebinding), so connect only to these.
        decision = self.guard.check_connection(host, port, addresses)
        if not decision:
            raise ProbeError("blocked_destination", explain(decision))
        return addresses[0]

    def _fetch(self, host: str, ip: str, port: int, scheme: str, target) -> dict[str, Any]:
        path = target.path or "/"
        if target.query:
            path += "?" + target.query
        tls = None
        try:
            if scheme == "https":
                try:
                    return self._request(host, ip, port, path, ssl.create_default_context())
                except ssl.SSLCertVerificationError as exc:
                    if not self.retry_unverified_tls:
                        raise
                    tls = {"verified": False, "verify_error": exc.verify_message or str(exc)}
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    response = self._request(host, ip, port, path, context)
                    response["tls"] = {**response["tls"], **tls}
                    return response
            return self._request(host, ip, port, path, None)
        except ProbeError:
            raise
        except socket.timeout as exc:
            raise ProbeError("timeout", f"{host} ({ip}:{port}) timed out") from exc
        except ConnectionRefusedError as exc:
            raise ProbeError("connection_refused", f"{ip}:{port} refused the connection") from exc
        except ssl.SSLError as exc:
            raise ProbeError("tls_error", str(exc)) from exc
        except http.client.HTTPException as exc:
            raise ProbeError("protocol_error", f"{type(exc).__name__}: {exc}") from exc
        except OSError as exc:
            raise ProbeError("network_error", str(exc)) from exc

    def _request(self, host: str, ip: str, port: int, path: str, context: ssl.SSLContext | None) -> dict[str, Any]:
        if context is None:
            connection: http.client.HTTPConnection = PinnedHTTPConnection(host, ip, port, self.timeout)
        else:
            connection = PinnedHTTPSConnection(host, ip, port, self.timeout, context)
        deadline = time.monotonic() + self.timeout * 3
        started = time.monotonic()
        try:
            connection.request("GET", path, headers={"User-Agent": USER_AGENT, "Accept": "*/*", "Connection": "close"})
            tls = _tls_details(connection.sock, context.verify_mode != ssl.CERT_NONE) if context else None
            response = connection.getresponse()
            body = bytearray()
            while len(body) <= self.max_body_bytes:
                if time.monotonic() > deadline:
                    raise ProbeError("timeout", f"{host} body read exceeded {self.timeout * 3:g}s")
                chunk = response.read(min(65536, self.max_body_bytes + 1 - len(body)))
                if not chunk:
                    break
                body.extend(chunk)
            truncated = len(body) > self.max_body_bytes
            body = bytes(body[: self.max_body_bytes])
            headers = {key.lower(): value[:1024] for key, value in response.getheaders() if key.lower() in KEPT_HEADERS}
            return {
                "ip": ip,
                "status_code": response.status,
                "response_time_ms": round((time.monotonic() - started) * 1000, 3),
                "title": _title(body),
                "headers": headers,
                "body_sha256": hashlib.sha256(body).hexdigest(),
                "body_bytes": len(body),
                "truncated": truncated,
                "tls": tls,
                "error": None,
            }
        finally:
            connection.close()
