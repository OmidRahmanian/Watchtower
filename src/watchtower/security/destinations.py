"""Destinations WatchTower must never contact, whatever a scope says.

Two tiers apply. ``ALWAYS_PROHIBITED`` networks and hostnames (loopback,
link-local, cloud metadata, multicast, documentation and reserved ranges) are
refused unconditionally. ``PRIVATE`` networks and hostnames (RFC 1918, CGNAT,
unique-local IPv6, ``.internal`` and similar names) are refused unless a
deployment explicitly sets ``allow_private_networks`` for internal
assessments. IPv6 addresses that embed IPv4 (mapped, NAT64, 6to4, Teredo) are
checked against the embedded address as well.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from dataclasses import dataclass

from watchtower.domain.targets import IPAddress, IPNetwork, Target, canonical_ip, canonical_hostname

_net = ipaddress.ip_network

ALWAYS_PROHIBITED_NETWORKS: tuple[IPNetwork, ...] = tuple(
    _net(cidr)
    for cidr in (
        "0.0.0.0/8",  # "this network"
        "127.0.0.0/8",  # loopback
        "169.254.0.0/16",  # link-local, including 169.254.169.254 metadata
        "100.100.100.200/32",  # Alibaba Cloud metadata (inside CGNAT space)
        "192.0.0.0/24",  # IETF protocol assignments
        "192.0.2.0/24",  # TEST-NET-1
        "192.88.99.0/24",  # deprecated 6to4 relay anycast
        "198.18.0.0/15",  # benchmarking
        "198.51.100.0/24",  # TEST-NET-2
        "203.0.113.0/24",  # TEST-NET-3
        "224.0.0.0/4",  # multicast
        "240.0.0.0/4",  # reserved and limited broadcast
        "::/96",  # unspecified, loopback and deprecated IPv4-compatible
        "100::/64",  # discard-only
        "2001:db8::/32",  # documentation
        "fd00:ec2::254/128",  # AWS IMDS over IPv6 (inside ULA space)
        "fe80::/10",  # link-local
        "fec0::/10",  # deprecated site-local
        "ff00::/8",  # multicast
    )
)

PRIVATE_NETWORKS: tuple[IPNetwork, ...] = tuple(
    _net(cidr)
    for cidr in (
        "10.0.0.0/8",
        "100.64.0.0/10",  # carrier-grade NAT
        "172.16.0.0/12",
        "192.168.0.0/16",
        "fc00::/7",  # unique local
    )
)

ALWAYS_PROHIBITED_HOSTNAMES: tuple[str, ...] = (
    "localhost",
    "metadata",
    "metadata.google.internal",
    "instance-data",
    "alt",
    "onion",
    "invalid",
)

PRIVATE_HOSTNAMES: tuple[str, ...] = (
    "internal",
    "local",
    "localdomain",
    "home.arpa",
    "lan",
    "intranet",
)

_NAT64 = (_net("64:ff9b::/96"), _net("64:ff9b:1::/48"))


@dataclass(frozen=True, slots=True)
class DestinationPolicy:
    """Checks one address or hostname against the prohibited lists."""

    allow_private_networks: bool = False
    extra_networks: tuple[IPNetwork, ...] = ()
    extra_hostnames: tuple[str, ...] = ()

    @classmethod
    def build(
        cls,
        *,
        allow_private_networks: bool = False,
        extra_networks: Iterable[str] = (),
        extra_hostnames: Iterable[str] = (),
    ) -> DestinationPolicy:
        return cls(
            allow_private_networks=allow_private_networks,
            extra_networks=tuple(ipaddress.ip_network(cidr, strict=True) for cidr in extra_networks),
            extra_hostnames=tuple(canonical_hostname(name) for name in extra_hostnames),
        )

    def check_target(self, target: Target) -> str | None:
        """Return why ``target`` is prohibited, or ``None`` when it is not."""
        if target.ip is not None:
            return self.check_address(target.ip)
        return self.check_hostname(target.value)

    def check_address(self, address: IPAddress | str) -> str | None:
        address = canonical_ip(address)
        for candidate in (address, *_embedded_ipv4(address)):
            reason = self._check_single_address(candidate)
            if reason is not None:
                if candidate is not address:
                    return f"{address} embeds {candidate}: {reason}"
                return reason
        return None

    def check_hostname(self, name: str) -> str | None:
        for suffix in (*ALWAYS_PROHIBITED_HOSTNAMES, *self.extra_hostnames):
            if _under(name, suffix):
                return f"{name} is a prohibited name (.{suffix})"
        if not self.allow_private_networks:
            for suffix in PRIVATE_HOSTNAMES:
                if _under(name, suffix):
                    return f"{name} is a private-use name (.{suffix})"
        return None

    def _check_single_address(self, address: IPAddress) -> str | None:
        for network in (*ALWAYS_PROHIBITED_NETWORKS, *self.extra_networks):
            if address.version == network.version and address in network:
                return f"{address} is in prohibited network {network}"
        if not self.allow_private_networks:
            for network in PRIVATE_NETWORKS:
                if address.version == network.version and address in network:
                    return f"{address} is in private network {network}"
        return None


def _under(name: str, suffix: str) -> bool:
    return name == suffix or name.endswith("." + suffix)


def _embedded_ipv4(address: IPAddress) -> tuple[ipaddress.IPv4Address, ...]:
    if not isinstance(address, ipaddress.IPv6Address):
        return ()
    embedded: list[ipaddress.IPv4Address] = []
    if address.sixtofour is not None:
        embedded.append(address.sixtofour)
    if address.teredo is not None:
        embedded.extend(address.teredo)
    if any(address in prefix for prefix in _NAT64):
        embedded.append(ipaddress.IPv4Address(int(address) & 0xFFFFFFFF))
    return tuple(embedded)
