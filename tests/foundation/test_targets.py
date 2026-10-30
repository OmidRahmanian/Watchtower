from __future__ import annotations

import pytest

from watchtower.domain.errors import InvalidTarget
from watchtower.domain.models import AssetKind, canonical_asset_value, service_value
from watchtower.domain.targets import (
    InvalidUrl,
    PortSet,
    TargetKind,
    canonical_hostname,
    canonical_ip,
    parse_target,
    parse_url,
)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Example.COM", "example.com"),
        ("example.com.", "example.com"),
        ("  api.example.com  ", "api.example.com"),
        ("_dmarc.example.com", "_dmarc.example.com"),
        ("bücher.example", "xn--bcher-kva.example"),
        ("BÜCHER.example", "xn--bcher-kva.example"),
        ("xn--bcher-kva.example", "xn--bcher-kva.example"),
        ("ｅｘａｍｐｌｅ。ｃｏｍ", "example.com"),  # full-width letters and ideographic full stop
        ("例え.テスト", "xn--r8jz45g.xn--zckzah"),
    ],
)
def test_hostnames_are_canonicalized(raw: str, expected: str) -> None:
    assert canonical_hostname(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "",
        ".",
        "example..com",
        ".example.com",
        "-bad.example.com",
        "bad-.example.com",
        "exa mple.com",
        "example.com/path",
        "user@example.com",
        "example.com\\evil",
        "ex%61mple.com",
        "*.example.com",
        "a" * 64 + ".example.com",
        ".".join(["a" * 63] * 4) + ".com",  # longer than 253
        "xn--zz.example",  # invalid punycode
        "xn--.example",
        "xn--example-.com",  # punycode for an all-ASCII label is not a valid A-label
    ],
)
def test_invalid_hostnames_are_rejected(raw: str) -> None:
    with pytest.raises(InvalidTarget):
        canonical_hostname(raw)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("127.0.0.1", "127.0.0.1"),
        ("127.1", "127.0.0.1"),
        ("0x7f.0.0.1", "127.0.0.1"),
        ("0177.0.0.1", "127.0.0.1"),
        ("2130706433", "127.0.0.1"),
        ("169.254.169.254.", "169.254.169.254"),
        ("::1", "::1"),
        ("[2001:DB8::0:1]", "2001:db8::1"),
        ("::ffff:10.0.0.1", "10.0.0.1"),
        ("[::ffff:7f00:1]", "127.0.0.1"),
    ],
)
def test_ip_forms_are_canonicalized(raw: str, expected: str) -> None:
    target = parse_target(raw)
    assert target.kind is TargetKind.IP
    assert target.value == expected


@pytest.mark.parametrize("raw", ["256.0.0.1", "1.2.3.4.5", "0x1g.0.0.1", "fe80::1%eth0", "[::1", "1.2.3.999"])
def test_invalid_ip_forms_are_rejected(raw: str) -> None:
    with pytest.raises(InvalidTarget):
        parse_target(raw)


def test_hostname_with_numeric_middle_label_is_a_hostname() -> None:
    assert parse_target("1.2.example.com").kind is TargetKind.HOSTNAME


def test_canonical_hostname_rejects_ip() -> None:
    with pytest.raises(InvalidTarget):
        canonical_hostname("10.0.0.1")


def test_canonical_ip_unwraps_mapped_addresses() -> None:
    assert str(canonical_ip("::ffff:192.0.2.1")) == "192.0.2.1"


def test_unicode_display_round_trips() -> None:
    assert parse_target("bücher.example").unicode == "bücher.example"


@pytest.mark.parametrize(
    ("spec", "expected"),
    [("443,80", "80,443"), ("80-90,85-100", "80-100"), ("8000-8001,8002", "8000-8002"), ("*", "1-65535")],
)
def test_port_sets_merge(spec: str, expected: str) -> None:
    assert str(PortSet.parse(spec)) == expected


@pytest.mark.parametrize("spec", ["0", "65536", "90-80", "", "http", "-1"])
def test_invalid_port_sets(spec: str) -> None:
    with pytest.raises(InvalidTarget):
        PortSet.parse(spec)


def test_port_membership() -> None:
    ports = PortSet.parse("80,443,8000-8100")
    assert 8050 in ports and 443 in ports
    assert 22 not in ports and True not in ports


@pytest.mark.parametrize(
    ("raw", "host", "port", "canonical"),
    [
        ("https://Example.com", "example.com", 443, "https://example.com/"),
        ("http://example.com:8080/a?b=1", "example.com", 8080, "http://example.com:8080/a?b=1"),
        ("https://[2001:db8::1]:8443/", "2001:db8::1", 8443, "https://[2001:db8::1]:8443/"),
        ("HTTP://bücher.example:80/x", "xn--bcher-kva.example", 80, "http://xn--bcher-kva.example/x"),
    ],
)
def test_urls_parse(raw: str, host: str, port: int, canonical: str) -> None:
    url = parse_url(raw)
    assert (url.host.value, url.port, url.geturl()) == (host, port, canonical)


@pytest.mark.parametrize(
    ("raw", "code"),
    [
        ("ftp://example.com/", "scheme"),
        ("javascript:alert(1)", "scheme"),
        ("https://user:pass@example.com/", "credentials"),
        ("https://example.com@evil.net/", "credentials"),
        ("https://exa mple.com/", "syntax"),
        ("https://example.com\\@evil.net/", "syntax"),
        ("https:///path", "syntax"),
    ],
)
def test_unsafe_urls_rejected(raw: str, code: str) -> None:
    with pytest.raises(InvalidUrl) as raised:
        parse_url(raw)
    assert raised.value.code == code


def test_asset_values() -> None:
    assert service_value("[2001:db8::1]", 443) == "[2001:db8::1]:443/tcp"
    assert canonical_asset_value(AssetKind.SERVICE, "API.example.com:8443/tcp") == "api.example.com:8443/tcp"
    assert canonical_asset_value(AssetKind.URL, "https://Example.com") == "https://example.com/"
    with pytest.raises(InvalidTarget):
        canonical_asset_value(AssetKind.SERVICE, "example.com/tcp")
