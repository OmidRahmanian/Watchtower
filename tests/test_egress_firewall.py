"""Validate namespace firewall policy without changing the host firewall."""
import importlib.util
from pathlib import Path
from unittest.mock import Mock

import pytest

spec = importlib.util.spec_from_file_location("firewall", Path(__file__).parents[1] / "deploy/egress_guard.py")
firewall = importlib.util.module_from_spec(spec)
spec.loader.exec_module(firewall)


def test_private_destinations_are_denied_after_exact_infrastructure_exceptions():
    rules = firewall.rules([("172.20.0.2", 5432)], ["127.0.0.11"])
    assert ["-d", "172.20.0.2", "-p", "tcp", "--dport", "5432", "-j", "ACCEPT"] in rules
    assert ["-d", "169.254.0.0/16", "-j", "REJECT"] in rules
    assert ["-d", "127.0.0.0/8", "-j", "REJECT"] in rules
    assert rules[-1] == ["-j", "REJECT"]
    assert rules.index(["-d", "172.20.0.2", "-p", "tcp", "--dport", "5432", "-j", "ACCEPT"]) < rules.index(["-d", "172.16.0.0/12", "-j", "REJECT"])


def test_invalid_addresses_cannot_inject_firewall_arguments():
    with pytest.raises(ValueError):
        firewall.rules([("1.2.3.4 -j ACCEPT", 5432)], [])


def test_firewall_replacement_is_atomic_and_ipv6_fails_closed(monkeypatch):
    call = Mock(return_value=Mock(returncode=0))
    monkeypatch.setattr(firewall.subprocess, "run", call)
    firewall.install([], [])
    command = call.call_args_list[0]
    assert command.args[0] == ["iptables-restore", "--noflush"]
    assert "-F WATCHTOWER_OUT" in command.kwargs["input"] and command.kwargs["input"].endswith("COMMIT\n")
    assert any(c.args[0] == ("ip6tables", "-P", "OUTPUT", "DROP") or c.args[0] == ["ip6tables", "-P", "OUTPUT", "DROP"] for c in call.call_args_list)
