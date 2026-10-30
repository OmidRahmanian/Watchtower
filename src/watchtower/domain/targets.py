"""Canonical hostnames, IP addresses, ports and URLs.

Every identifier a scope decision depends on passes through this module, so
the parsers err on the side of rejecting input. Hostnames become lowercase
IDNA A-labels without a trailing dot. IPv4-mapped IPv6 addresses become IPv4.
Numeric hostnames that browsers and HTTP clients would treat as IPv4
(``127.1``, ``0x7f.0.0.1``, ``2130706433``) are parsed as IP addresses, so they
cannot slip past address checks by looking like names.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from urllib.parse import urlsplit, urlunsplit

import idna

from watchtower.domain.errors import InvalidTarget

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

MAX_HOSTNAME_LENGTH = 253
MAX_LABEL_LENGTH = 63
MAX_INPUT_LENGTH = 1024
DEFAULT_PORTS = {"http": 80, "https": 443}

# Underscores are accepted because discovery sources report names such as
# _dmarc.example.com; they never appear in IDNA-encoded labels.
_ASCII_LABEL = re.compile(r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\Z")
_FORBIDDEN_HOST_CHARS = re.compile(r"[\x00-\x20\x7f%/\\@?#*\[\]:<>^|\"'`{}~!$&()+,;=]")
_UNSAFE_URL_CHARS = re.compile(r"[\x00-\x20\x7f\\]")
_HEX_NUMBER = re.compile(r"0x[0-9a-f]*\Z")


class TargetKind(StrEnum):
    HOSTNAME = "hostname"
    IP = "ip"


@dataclass(frozen=True, slots=True)
class Target:
    """A canonical network destination without a port."""

    kind: TargetKind
    value: str
    ip: IPAddress | None = None

    def __str__(self) -> str:
        return self.value

    @property
    def is_ip(self) -> bool:
        return self.kind is TargetKind.IP

    @property
    def unicode(self) -> str:
        """Human-readable form; IDN labels are decoded to Unicode."""
        if self.kind is TargetKind.IP:
            return self.value
        try:
            return idna.decode(self.value)
        except idna.IDNAError:
            return self.value

    @property
    def url_host(self) -> str:
        if self.ip is not None and self.ip.version == 6:
            return f"[{self.value}]"
        return self.value


def canonical_ip(raw: str | IPAddress) -> IPAddress:
    """Parse an IP address; brackets are allowed, zone identifiers are not."""
    if isinstance(raw, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        address = raw
    else:
        if not isinstance(raw, str):
            raise InvalidTarget("IP address must be a string")
        text = raw.strip()
        if text.startswith("[") and text.endswith("]"):
            text = text[1:-1]
        if "%" in text:
            raise InvalidTarget("IPv6 zone identifiers are not supported")
        try:
            address = ipaddress.ip_address(text)
        except ValueError:
            raise InvalidTarget(f"invalid IP address: {raw!r}") from None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


def parse_target(raw: str | Target) -> Target:
    """Parse a hostname or IP address into its canonical form."""
    if isinstance(raw, Target):
        return raw
    if not isinstance(raw, str):
        raise InvalidTarget("target must be a string")
    text = raw.strip()
    if not text:
        raise InvalidTarget("target is empty")
    if len(text) > MAX_INPUT_LENGTH:
        raise InvalidTarget("target is too long")
    if text.startswith("[") or ":" in text:
        address = canonical_ip(text)
        return Target(TargetKind.IP, str(address), address)
    try:
        address = canonical_ip(text)
    except InvalidTarget:
        pass
    else:
        return Target(TargetKind.IP, str(address), address)

    # UTS #46 mapping folds case and full-width forms and turns ideographic
    # full stops into dots before the name is split into labels.
    try:
        mapped = idna.uts46_remap(text, std3_rules=False, transitional=False)
    except (idna.IDNAError, UnicodeError):
        raise InvalidTarget(f"invalid hostname: {raw!r}") from None
    if mapped.endswith("."):
        mapped = mapped[:-1]
    if not mapped:
        raise InvalidTarget("hostname is empty")
    if _FORBIDDEN_HOST_CHARS.search(mapped):
        raise InvalidTarget(f"hostname contains forbidden characters: {raw!r}")

    labels = mapped.split(".")
    if _ends_in_number(labels):
        address = _legacy_ipv4(labels)
        return Target(TargetKind.IP, str(address), address)

    name = ".".join(_to_alabel(label) for label in labels)
    if len(name) > MAX_HOSTNAME_LENGTH:
        raise InvalidTarget("hostname is longer than 253 characters")
    return Target(TargetKind.HOSTNAME, name)


def canonical_hostname(raw: str) -> str:
    """Return the canonical A-label hostname; IP addresses are rejected."""
    target = parse_target(raw)
    if target.is_ip:
        raise InvalidTarget(f"expected a hostname, got IP address {target.value}")
    return target.value


def _to_alabel(label: str) -> str:
    if not label:
        raise InvalidTarget("hostname contains an empty label")
    if label.isascii():
        if not _ASCII_LABEL.match(label):
            raise InvalidTarget(f"invalid hostname label: {label!r}")
        if label.startswith("xn--"):
            try:
                if idna.encode(idna.decode(label)).decode("ascii") != label:
                    raise InvalidTarget(f"non-canonical IDN label: {label!r}")
            except (idna.IDNAError, UnicodeError):
                raise InvalidTarget(f"invalid IDN label: {label!r}") from None
        return label
    try:
        alabel = idna.alabel(label).decode("ascii")
    except (idna.IDNAError, UnicodeError):
        raise InvalidTarget(f"invalid internationalized label: {label!r}") from None
    if len(alabel) > MAX_LABEL_LENGTH:
        raise InvalidTarget(f"hostname label is longer than 63 characters: {label!r}")
    return alabel


def _ends_in_number(labels: list[str]) -> bool:
    last = labels[-1]
    return last.isascii() and (last.isdigit() or bool(_HEX_NUMBER.match(last)))


def _legacy_ipv4(labels: list[str]) -> ipaddress.IPv4Address:
    """The WHATWG URL IPv4 parser, which accepts octal, hex and short forms."""
    if len(labels) > 4:
        raise InvalidTarget("numeric hostname has too many parts")
    numbers = [_ipv4_number(part) for part in labels]
    if any(n > 255 for n in numbers[:-1]) or numbers[-1] >= 256 ** (5 - len(numbers)):
        raise InvalidTarget("numeric hostname is out of IPv4 range")
    value = numbers[-1]
    for index, number in enumerate(numbers[:-1]):
        value += number * 256 ** (3 - index)
    return ipaddress.IPv4Address(value)


def _ipv4_number(part: str) -> int:
    if not part or not part.isascii():
        raise InvalidTarget("numeric hostname has an empty or non-ASCII part")
    digits, base = part, 10
    if part.startswith("0x"):
        digits, base = part[2:], 16
    elif len(part) > 1 and part.startswith("0"):
        digits, base = part[1:], 8
    if not digits:
        return 0
    try:
        return int(digits, base)
    except ValueError:
        raise InvalidTarget(f"numeric hostname part is not a number: {part!r}") from None


def canonical_port(value: int | str) -> int:
    if isinstance(value, bool):
        raise InvalidTarget("port must be an integer")
    if isinstance(value, str):
        if not value.isascii() or not value.isdigit():
            raise InvalidTarget(f"invalid port: {value!r}")
        value = int(value)
    if not isinstance(value, int) or not 1 <= value <= 65535:
        raise InvalidTarget(f"port out of range: {value!r}")
    return value


@dataclass(frozen=True, slots=True)
class PortSet:
    """An ordered set of inclusive port ranges, e.g. ``80,443,8000-8100``."""

    ranges: tuple[tuple[int, int], ...]

    @classmethod
    def parse(cls, spec: PortSet | str | Iterable[int | str]) -> PortSet:
        if isinstance(spec, PortSet):
            return spec
        items: Iterable[int | str]
        if isinstance(spec, str):
            text = spec.strip().lower()
            if text in {"*", "all"}:
                return cls(((1, 65535),))
            items = [part.strip() for part in text.split(",")]
        else:
            items = spec
        ranges: list[tuple[int, int]] = []
        for item in items:
            if isinstance(item, str) and "-" in item:
                low_text, _, high_text = item.partition("-")
                low, high = canonical_port(low_text.strip()), canonical_port(high_text.strip())
                if low > high:
                    raise InvalidTarget(f"port range is reversed: {item!r}")
            else:
                low = high = canonical_port(item)
            ranges.append((low, high))
        if not ranges:
            raise InvalidTarget("port set is empty")
        merged: list[tuple[int, int]] = []
        for low, high in sorted(ranges):
            if merged and low <= merged[-1][1] + 1:
                merged[-1] = (merged[-1][0], max(merged[-1][1], high))
            else:
                merged.append((low, high))
        return cls(tuple(merged))

    def __contains__(self, port: object) -> bool:
        return isinstance(port, int) and any(low <= port <= high for low, high in self.ranges)

    def __str__(self) -> str:
        return ",".join(str(low) if low == high else f"{low}-{high}" for low, high in self.ranges)


class InvalidUrl(InvalidTarget):
    """A URL was rejected; ``code`` is ``syntax``, ``scheme`` or ``credentials``."""

    def __init__(self, message: str, code: str = "syntax") -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class ParsedUrl:
    scheme: str
    host: Target
    port: int
    path: str
    query: str

    def geturl(self) -> str:
        netloc = self.host.url_host
        if DEFAULT_PORTS.get(self.scheme) != self.port:
            netloc = f"{netloc}:{self.port}"
        return urlunsplit((self.scheme, netloc, self.path or "/", self.query, ""))


def parse_url(raw: str) -> ParsedUrl:
    """Parse an absolute http(s) URL; userinfo, backslashes and whitespace are rejected."""
    if not isinstance(raw, str) or not raw or len(raw) > 8192:
        raise InvalidUrl("URL is empty or too long")
    if _UNSAFE_URL_CHARS.search(raw):
        raise InvalidUrl("URL contains whitespace, control characters or backslashes")
    try:
        parts = urlsplit(raw)
    except ValueError as exc:
        raise InvalidUrl(f"invalid URL: {exc}") from None
    scheme = parts.scheme.lower()
    if scheme not in DEFAULT_PORTS:
        raise InvalidUrl(f"unsupported URL scheme: {parts.scheme!r}", "scheme")
    netloc = parts.netloc
    if not netloc:
        raise InvalidUrl("URL has no host")
    if "@" in netloc:
        raise InvalidUrl("URLs with embedded credentials are not allowed", "credentials")
    if netloc.startswith("["):
        host_text, bracket, rest = netloc[1:].partition("]")
        if not bracket or (rest and not rest.startswith(":")):
            raise InvalidUrl("malformed IPv6 URL host")
        host = parse_target(f"[{host_text}]")
        port_text = rest[1:] if rest else ""
    else:
        host_text, _, port_text = netloc.partition(":")
        host = parse_target(host_text)
    port = canonical_port(port_text) if port_text else DEFAULT_PORTS[scheme]
    return ParsedUrl(scheme, host, port, parts.path, parts.query)
