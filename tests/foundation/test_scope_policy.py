from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from watchtower.domain.errors import InvalidScopeRule, ScopeViolation
from watchtower.domain.scope import (
    AuthorizationKind,
    AuthorizationReference,
    DecisionReason,
    NewScopeRevision,
    Revocation,
    RuleEffect,
    RuleKind,
    ScopePolicy,
    ScopeRevision,
    ScopeRule,
)
from watchtower.domain.targets import PortSet
from watchtower.security.destinations import DestinationPolicy

NOW = datetime(2026, 10, 30, 12, 0, tzinfo=timezone.utc)
PROJECT = uuid4()
AUTH = AuthorizationReference(AuthorizationKind.BUG_BOUNTY_PROGRAM, "https://hackerone.com/example", "Program team")


def include(pattern: str, ports: str | None = None) -> ScopeRule:
    return ScopeRule.parse(pattern, ports=ports, id=uuid4())


def exclude(pattern: str, ports: str | None = None) -> ScopeRule:
    return ScopeRule.parse(pattern, effect=RuleEffect.EXCLUDE, ports=ports, id=uuid4())


def policy(
    *rules: ScopeRule,
    ports: str = "80,443",
    auth: AuthorizationReference = AUTH,
    revocation: Revocation | None = None,
    destinations: DestinationPolicy | None = None,
    **options: object,
) -> ScopePolicy:
    revision = ScopeRevision(
        id=uuid4(),
        project_id=PROJECT,
        number=1,
        rules=tuple(rules),
        authorization=auth,
        permitted_ports=PortSet.parse(ports),
        created_at=NOW,
        revocation=revocation,
    )
    return ScopePolicy(PROJECT, revision, destinations=destinations, clock=lambda: NOW, **options)  # type: ignore[arg-type]


STANDARD = (include("example.com"), include("*.example.com"), exclude("admin.example.com"))


# -- rule parsing ------------------------------------------------------


@pytest.mark.parametrize(
    ("pattern", "kind", "value"),
    [
        ("Example.com.", RuleKind.HOST, "example.com"),
        ("*.Example.COM", RuleKind.SUBDOMAINS, "example.com"),
        ("*.bücher.example", RuleKind.SUBDOMAINS, "xn--bcher-kva.example"),
        ("192.0.2.10", RuleKind.NETWORK, "192.0.2.10/32"),
        ("10.0.0.0/8", RuleKind.NETWORK, "10.0.0.0/8"),
        ("2001:DB8::/32", RuleKind.NETWORK, "2001:db8::/32"),
        ("::ffff:45.33.32.7", RuleKind.NETWORK, "45.33.32.7/32"),
    ],
)
def test_rules_are_canonical(pattern: str, kind: RuleKind, value: str) -> None:
    rule = ScopeRule.parse(pattern)
    assert (rule.kind, rule.value) == (kind, value)


@pytest.mark.parametrize(
    "pattern",
    ["", "*", "*.com", "api-*.example.com", "*.*.example.com", "10.0.0.1/8", "*.10.0.0.1", "::ffff:0:0/96", "exa mple.com"],
)
def test_bad_rules_are_rejected(pattern: str) -> None:
    with pytest.raises(InvalidScopeRule):
        ScopeRule.parse(pattern)


def test_revision_needs_an_include() -> None:
    with pytest.raises(InvalidScopeRule):
        NewScopeRevision((exclude("example.com"),), AUTH, PortSet.parse("443"))


def test_revision_rejects_duplicate_rules() -> None:
    with pytest.raises(InvalidScopeRule):
        NewScopeRevision((include("example.com"), include("EXAMPLE.com.")), AUTH, PortSet.parse("443"))


def test_authorization_requires_reference_and_grantor() -> None:
    with pytest.raises(InvalidScopeRule):
        AuthorizationReference(AuthorizationKind.CONTRACT, " ", "someone")
    with pytest.raises(InvalidScopeRule):
        AuthorizationReference(AuthorizationKind.CONTRACT, "SOW-1", "")
    with pytest.raises(InvalidScopeRule):
        AuthorizationReference(AuthorizationKind.CONTRACT, "SOW-1", "x", valid_from=datetime(2026, 1, 1))


# -- hostname boundaries ------------------------------------------------


@pytest.mark.parametrize(
    ("target", "reason"),
    [
        ("example.com", DecisionReason.ALLOWED),
        ("EXAMPLE.com.", DecisionReason.ALLOWED),
        ("www.example.com", DecisionReason.ALLOWED),
        ("a.b.c.example.com", DecisionReason.ALLOWED),
        ("badexample.com", DecisionReason.NOT_IN_SCOPE),
        ("example.com.evil.net", DecisionReason.NOT_IN_SCOPE),
        ("example.co", DecisionReason.NOT_IN_SCOPE),
        ("xample.com", DecisionReason.NOT_IN_SCOPE),
        ("wwwexample.com", DecisionReason.NOT_IN_SCOPE),
        ("admin.example.com", DecisionReason.EXCLUDED),
        ("ADMIN.example.com.", DecisionReason.EXCLUDED),
        ("x.admin.example.com", DecisionReason.ALLOWED),  # exact excludes do not cover children
        ("example.com/evil", DecisionReason.INVALID_TARGET),
        ("", DecisionReason.INVALID_TARGET),
    ],
)
def test_hostname_boundaries(target: str, reason: DecisionReason) -> None:
    decision = policy(*STANDARD).check_target(target)
    assert decision.reason is reason
    assert decision.allowed is (reason is DecisionReason.ALLOWED)


def test_wildcard_does_not_include_apex() -> None:
    scope = policy(include("*.example.com"))
    assert not scope.check_target("example.com")
    assert scope.check_target("api.example.com")


def test_wildcard_exclusion_covers_subtree_but_not_apex() -> None:
    scope = policy(include("*.example.com"), include("example.com"), exclude("*.internal-tools.example.com"))
    assert scope.check_target("a.internal-tools.example.com").reason is DecisionReason.EXCLUDED
    assert scope.check_target("internal-tools.example.com").allowed


def test_decision_records_matched_rule() -> None:
    host_rule, wildcard = include("example.com"), include("*.example.com")
    scope = policy(host_rule, wildcard)
    assert scope.check_target("example.com").matched_rule_id == host_rule.id
    assert scope.check_target("a.example.com").matched_rule_id == wildcard.id


# -- IDN -------------------------------------------------------------------


@pytest.mark.parametrize("target", ["shop.bücher.example", "shop.xn--bcher-kva.example", "SHOP.BÜCHER.example"])
def test_idn_targets_match_idn_rules(target: str) -> None:
    decision = policy(include("*.bücher.example")).check_target(target)
    assert decision.allowed
    assert decision.target == "shop.xn--bcher-kva.example"


def test_idn_lookalike_is_not_in_scope() -> None:
    # Cyrillic "е" (U+0435) in place of Latin "e".
    assert policy(*STANDARD).check_target("www.еxample.com").reason is DecisionReason.NOT_IN_SCOPE


def test_idn_exclusion_applies_to_both_forms() -> None:
    scope = policy(include("*.bücher.example"), exclude("admin.bücher.example"))
    assert scope.check_target("admin.xn--bcher-kva.example").reason is DecisionReason.EXCLUDED


# -- IP and IPv6 ----------------------------------------------------------


def test_ipv4_network_rules() -> None:
    scope = policy(include("45.33.32.0/24"), exclude("45.33.32.128/25"))
    assert scope.check_target("45.33.32.7")
    assert scope.check_target("45.33.32.200").reason is DecisionReason.EXCLUDED
    assert scope.check_target("45.33.33.1").reason is DecisionReason.NOT_IN_SCOPE


@pytest.mark.parametrize(
    ("target", "allowed"),
    [
        ("2606:4700::1", True),
        ("2606:4700:0:0:0:0:0:1", True),
        ("[2606:4700::1]", True),
        ("2606:4700:ffff::1", True),
        ("2606:4701::1", False),
        ("2606:4700:dead::beef", False),  # excluded /48
    ],
)
def test_ipv6_network_rules(target: str, allowed: bool) -> None:
    scope = policy(include("2606:4700::/32"), exclude("2606:4700:dead::/48"))
    assert scope.check_target(target).allowed is allowed


def test_ipv4_mapped_ipv6_matches_ipv4_rules() -> None:
    scope = policy(include("45.33.32.0/24"))
    assert scope.check_target("::ffff:45.33.32.9").allowed


def test_hostname_rules_do_not_match_ips_and_vice_versa() -> None:
    scope = policy(include("example.com"), include("45.33.32.0/24"))
    assert not scope.check_target("93.184.216.34")
    assert scope.check_target("45.33.32.1")


# -- ports -----------------------------------------------------------------


def test_revision_ports_apply_by_default() -> None:
    scope = policy(*STANDARD, ports="80,443")
    assert scope.check_target("www.example.com", port=443)
    assert scope.check_target("www.example.com", port=8080).reason is DecisionReason.PORT_NOT_PERMITTED


def test_most_specific_rule_ports_win() -> None:
    scope = policy(include("*.example.com", ports="443"), include("dev.example.com", ports="8000-8100"))
    assert scope.check_target("dev.example.com", port=8080)
    assert not scope.check_target("dev.example.com", port=443)
    assert scope.check_target("www.example.com", port=443)
    assert not scope.check_target("www.example.com", port=8080)


def test_port_specific_exclusion() -> None:
    scope = policy(include("*.example.com", ports="22,443"), exclude("bastion.example.com", ports="22"))
    assert scope.check_target("bastion.example.com", port=443)
    assert scope.check_target("bastion.example.com", port=22).reason is DecisionReason.EXCLUDED
    assert scope.check_target("bastion.example.com").allowed  # passive checks are not port specific


def test_invalid_port_is_denied() -> None:
    assert policy(*STANDARD).check_target("example.com", port=70000).reason is DecisionReason.INVALID_TARGET


# -- revocation and authorization windows -----------------------------------


def test_revoked_revision_denies_everything() -> None:
    scope = policy(*STANDARD, revocation=Revocation(NOW, "program closed"))
    decision = scope.check_target("www.example.com")
    assert decision.reason is DecisionReason.REVOKED
    assert scope.check_url("https://www.example.com/").reason is DecisionReason.REVOKED
    assert scope.check_connection("www.example.com", 443, ["93.184.216.34"]).reason is DecisionReason.REVOKED


def test_expired_authorization_denies() -> None:
    auth = AuthorizationReference(AuthorizationKind.CONTRACT, "SOW-1", "Client", valid_until=NOW - timedelta(seconds=1))
    assert policy(*STANDARD, auth=auth).check_target("example.com").reason is DecisionReason.AUTHORIZATION_EXPIRED


def test_future_authorization_denies() -> None:
    auth = AuthorizationReference(AuthorizationKind.CONTRACT, "SOW-1", "Client", valid_from=NOW + timedelta(hours=1))
    assert policy(*STANDARD, auth=auth).check_target("example.com").reason is DecisionReason.AUTHORIZATION_NOT_YET_VALID


def test_missing_revision_denies() -> None:
    scope = ScopePolicy(PROJECT, None)
    assert scope.check_target("example.com").reason is DecisionReason.NO_SCOPE
    assert scope.revision_id is None


def test_require_raises() -> None:
    with pytest.raises(ScopeViolation) as raised:
        policy(*STANDARD).check_target("evil.net").require()
    assert raised.value.decision.reason is DecisionReason.NOT_IN_SCOPE


def test_policy_rejects_foreign_revision() -> None:
    with pytest.raises(ValueError):
        ScopePolicy(uuid4(), policy(*STANDARD).revision)


# -- prohibited destinations ---------------------------------------------------


@pytest.mark.parametrize(
    "target",
    [
        "127.0.0.1",
        "127.1",
        "0x7f000001",
        "2130706433",
        "0.0.0.0",
        "169.254.169.254",
        "100.100.100.200",
        "10.1.2.3",
        "192.168.1.1",
        "172.16.0.1",
        "100.64.0.1",
        "224.0.0.1",
        "255.255.255.255",
        "::1",
        "::",
        "fe80::1",
        "fd00:ec2::254",
        "fc00::1",
        "ff02::1",
        "::ffff:127.0.0.1",
        "64:ff9b::a9fe:a9fe",  # NAT64 of 169.254.169.254
        "2002:7f00:1::",  # 6to4 of 127.0.0.1
        "localhost",
        "api.localhost",
        "metadata.google.internal",
        "service.internal",
        "printer.local",
        "router.home.arpa",
    ],
)
def test_prohibited_destinations_are_denied_even_if_included(target: str) -> None:
    rules = [include("0.0.0.0/0"), include("::/0")]
    if any(c.isalpha() for c in target) and ":" not in target and not target.startswith("0x"):
        rules.append(include(target))  # an exact host rule cannot override the prohibition
    decision = policy(*rules).check_target(target)
    assert decision.reason is DecisionReason.PROHIBITED_DESTINATION, decision


def test_private_networks_can_be_allowed_for_internal_assessments() -> None:
    destinations = DestinationPolicy(allow_private_networks=True)
    scope = policy(include("10.0.0.0/8"), include("*.corp.internal"), destinations=destinations)
    assert scope.check_target("10.1.2.3")
    assert scope.check_target("git.corp.internal")
    # Loopback, link-local and metadata stay prohibited.
    internal_all = policy(include("0.0.0.0/0"), destinations=destinations)
    assert not internal_all.check_target("169.254.169.254")
    assert not internal_all.check_target("100.100.100.200")
    assert not internal_all.check_target("127.0.0.1")


def test_extra_prohibited_entries() -> None:
    destinations = DestinationPolicy.build(extra_networks=["45.33.32.0/28"], extra_hostnames=["vault.example.com"])
    scope = policy(*STANDARD, include("45.33.32.0/24"), destinations=destinations)
    assert scope.check_target("45.33.32.3").reason is DecisionReason.PROHIBITED_DESTINATION
    assert scope.check_target("a.vault.example.com").reason is DecisionReason.PROHIBITED_DESTINATION
    assert scope.check_target("45.33.32.30")


# -- connections -----------------------------------------------------------------


def test_connection_to_public_address_is_allowed() -> None:
    decision = policy(*STANDARD).check_connection("www.example.com", 443, ["93.184.216.34", "2606:2800:220:1::1"])
    assert decision.allowed


@pytest.mark.parametrize("address", ["127.0.0.1", "169.254.169.254", "10.0.0.5", "::1", "::ffff:169.254.169.254"])
def test_dns_rebinding_to_prohibited_address_is_denied(address: str) -> None:
    decision = policy(*STANDARD).check_connection("www.example.com", 443, ["93.184.216.34", address])
    assert decision.reason is DecisionReason.PROHIBITED_DESTINATION


def test_connection_to_excluded_network_is_denied() -> None:
    scope = policy(*STANDARD, exclude("93.184.216.0/24"))
    assert scope.check_connection("www.example.com", 443, ["93.184.216.34"]).reason is DecisionReason.EXCLUDED


def test_connection_requires_addresses_and_port() -> None:
    scope = policy(*STANDARD)
    assert scope.check_connection("www.example.com", 443, []).reason is DecisionReason.UNRESOLVED
    assert scope.check_connection("www.example.com", 22, ["93.184.216.34"]).reason is DecisionReason.PORT_NOT_PERMITTED
    assert scope.check_connection("www.example.com", None, ["93.184.216.34"]).reason is DecisionReason.PORT_REQUIRED  # type: ignore[arg-type]
    assert scope.check_connection("www.example.com", 443, ["not-an-ip"]).reason is DecisionReason.INVALID_TARGET


def test_connection_to_ip_literal() -> None:
    scope = policy(include("45.33.32.0/24"))
    assert scope.check_connection("45.33.32.5", 443, [])
    assert scope.check_connection("45.33.32.5", 443, ["45.33.32.5"])
    assert scope.check_connection("45.33.32.5", 443, ["45.33.32.6"]).reason is DecisionReason.ADDRESS_MISMATCH


def test_connection_to_out_of_scope_host_denied_before_addresses() -> None:
    assert not policy(*STANDARD).check_connection("evil.net", 443, ["93.184.216.34"])


# -- URLs and redirects ----------------------------------------------------------------


def test_check_url() -> None:
    scope = policy(*STANDARD)
    assert scope.check_url("https://www.example.com/login")
    assert scope.check_url("https://www.example.com:8443/").reason is DecisionReason.PORT_NOT_PERMITTED
    assert scope.check_url("ftp://www.example.com/").reason is DecisionReason.UNSUPPORTED_SCHEME
    assert scope.check_url("https://u:p@www.example.com/").reason is DecisionReason.CREDENTIALS_IN_URL
    assert scope.check_url("https://admin.example.com/").reason is DecisionReason.EXCLUDED


@pytest.mark.parametrize(
    ("location", "reason", "url"),
    [
        ("/next", DecisionReason.ALLOWED, "https://www.example.com/next"),
        ("https://api.example.com/v1", DecisionReason.ALLOWED, "https://api.example.com/v1"),
        ("//api.example.com/x", DecisionReason.ALLOWED, "https://api.example.com/x"),
        ("https://evil.net/", DecisionReason.NOT_IN_SCOPE, "https://evil.net/"),
        ("https://www.example.com.evil.net/", DecisionReason.NOT_IN_SCOPE, None),
        ("https://admin.example.com/", DecisionReason.EXCLUDED, None),
        ("http://169.254.169.254/latest/meta-data/", DecisionReason.PROHIBITED_DESTINATION, None),
        ("https://169.254.169.254/latest/meta-data/", DecisionReason.PROHIBITED_DESTINATION, None),
        ("https://127.1/", DecisionReason.PROHIBITED_DESTINATION, None),
        ("http://www.example.com/", DecisionReason.HTTPS_DOWNGRADE, "http://www.example.com/"),
        ("https://www.example.com:22/", DecisionReason.PORT_NOT_PERMITTED, None),
        ("https://user@www.example.com/", DecisionReason.CREDENTIALS_IN_URL, None),
        ("javascript:alert(1)", DecisionReason.UNSUPPORTED_SCHEME, None),
        ("file:///etc/passwd", DecisionReason.UNSUPPORTED_SCHEME, None),
        ("https://evil.net\\@www.example.com/", DecisionReason.INVALID_TARGET, None),
        ("", DecisionReason.INVALID_TARGET, None),
    ],
)
def test_redirect_decisions(location: str, reason: DecisionReason, url: str | None) -> None:
    decision = policy(*STANDARD).check_redirect("https://www.example.com/start", location, redirects_followed=0)
    assert decision.reason is reason, decision
    if url is not None:
        assert decision.url == url


def test_redirect_downgrade_can_be_allowed() -> None:
    scope = policy(*STANDARD, allow_https_downgrade=True)
    assert scope.check_redirect("https://www.example.com/", "http://www.example.com/", redirects_followed=0)


def test_redirect_to_prohibited_ip_over_plain_http_is_denied_when_downgrade_allowed() -> None:
    scope = policy(*STANDARD, allow_https_downgrade=True)
    decision = scope.check_redirect("https://www.example.com/", "http://169.254.169.254/", redirects_followed=0)
    assert decision.reason is DecisionReason.PROHIBITED_DESTINATION


def test_redirect_limit() -> None:
    scope = policy(*STANDARD, max_redirects=2)
    assert scope.check_redirect("https://www.example.com/", "/a", redirects_followed=1)
    assert scope.check_redirect("https://www.example.com/", "/a", redirects_followed=2).reason is DecisionReason.REDIRECT_LIMIT


def test_redirect_from_invalid_current_url() -> None:
    decision = policy(*STANDARD).check_redirect("not a url", "/x", redirects_followed=0)
    assert decision.reason is DecisionReason.INVALID_TARGET
