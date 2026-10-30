"""Process-wide egress guard for workers and the notifier.

Adapters already authorize every target through ``ScopePolicy`` before they
connect. This guard is the backstop beneath them: an audit hook on
``socket.connect`` and ``socket.sendto`` refuses any destination the
``DestinationPolicy`` prohibits (loopback, link-local and cloud metadata,
multicast, reserved ranges and, unless allowed, private networks), so a bug
or a library that ignores scope cannot reach the metadata service or the
host's internal services from a worker.

The worker's own infrastructure is the only exception: the database, the
broker, and the configured DNS resolvers on port 53, given as exact
``(address, port)`` pairs. Hostnames are not checked here because sockets
only ever see addresses.

It does not cover external tools a worker starts (they are separate
processes): run workers in a container whose network only reaches the
database, the broker and the internet (see ``deploy/compose.workers.yaml``).
Audit hooks cannot be removed, so ``install`` is idempotent and ``active``
switches enforcement for tests.
"""
from __future__ import annotations

import ipaddress
import socket
import sys
import threading
from collections.abc import Iterable
from pathlib import Path
from urllib.parse import urlsplit

from watchtower.config.settings import Settings
from watchtower.security.destinations import DestinationPolicy


class EgressRefused(PermissionError):
    pass


class EgressGuard:
    def __init__(self, destinations: DestinationPolicy, allowed: Iterable[tuple[str, int]] = ()) -> None:
        self.destinations = destinations
        self.allowed = {(str(ipaddress.ip_address(host)), int(port)) for host, port in allowed}
        self.active = True
        self.refused: list[str] = []
        self._lock = threading.Lock()

    def check(self, host: str, port: int) -> str | None:
        """Why connecting to ``host:port`` is refused, or ``None``."""
        try:
            address = str(ipaddress.ip_address(host.split("%", 1)[0]))
        except ValueError:
            return f"{host} is not an address"
        if (address, port) in self.allowed:
            return None
        return self.destinations.check_address(address)

    def __call__(self, event: str, args: tuple) -> None:
        if not self.active or event not in ("socket.connect", "socket.sendto"):
            return
        sock, address = args[0], args[-1]
        if getattr(sock, "family", None) not in (socket.AF_INET, socket.AF_INET6):
            return  # Unix sockets and the like
        if not isinstance(address, tuple) or len(address) < 2:
            return
        reason = self.check(str(address[0]), int(address[1]))
        if reason:
            with self._lock:
                self.refused.append(f"{address[0]}:{address[1]}")
            raise EgressRefused(f"egress refused: {reason}")


_installed: EgressGuard | None = None


def _endpoint(url: str | None, default_port: int) -> list[tuple[str, int]]:
    if not url:
        return []
    parts = urlsplit(url)
    if not parts.hostname:
        return []
    port = parts.port or default_port
    try:
        infos = socket.getaddrinfo(parts.hostname, port, type=socket.SOCK_STREAM)
    except OSError:
        return []
    return [(info[4][0], port) for info in infos]


def system_nameservers(path: str = "/etc/resolv.conf") -> list[str]:
    try:
        lines = Path(path).read_text().splitlines()
    except OSError:
        return []
    return [line.split()[1] for line in lines if line.startswith("nameserver") and len(line.split()) > 1]


def infrastructure(settings: Settings) -> list[tuple[str, int]]:
    """The database, the broker and the DNS resolvers a worker must reach."""
    allowed: list[tuple[str, int]] = []
    if settings.database.url is not None:
        allowed += _endpoint(settings.database.url.get_secret_value().replace("+psycopg", ""), 5432)
    if settings.runtime.broker_url is not None:
        allowed += _endpoint(settings.runtime.broker_url.get_secret_value(), 5672)
    for server in list(settings.pipeline.dns_nameservers) or system_nameservers():
        try:
            allowed.append((str(ipaddress.ip_address(server)), 53))
        except ValueError:
            continue
    return allowed


def install(settings: Settings, *, extra: Iterable[tuple[str, int]] = ()) -> EgressGuard:
    """Install the guard for this process (once); later calls return the installed guard."""
    global _installed
    if _installed is None:
        _installed = EgressGuard(settings.scope.destination_policy(), [*infrastructure(settings), *extra])
        sys.addaudithook(_installed)
    return _installed
