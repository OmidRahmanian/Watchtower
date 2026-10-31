"""Namespace firewall for scanning tools, including subprocesses.

Only the bootstrap container has NET_ADMIN. Workers share its namespace but
run without capabilities and cannot change these rules. This is an address/
port backstop; the application still checks hostname, scope and each request.
"""
import ipaddress
import os
from pathlib import Path
import signal
import socket
import subprocess

BLOCKED = ("0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
           "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
           "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4")


def run(*args):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def rules(infrastructure, nameservers):
    output = [["-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"]]
    for address, port in infrastructure:
        address = str(ipaddress.IPv4Address(address))
        if not 1 <= int(port) <= 65535:
            raise ValueError("invalid infrastructure port")
        output.append(["-d", address, "-p", "tcp", "--dport", str(port), "-j", "ACCEPT"])
    for address in nameservers:
        address = str(ipaddress.IPv4Address(address))
        for protocol in ("udp", "tcp"):
            output.append(["-d", address, "-p", protocol, "--dport", "53", "-j", "ACCEPT"])
    output += [["-d", network, "-j", "REJECT"] for network in BLOCKED]
    output += [["-p", "tcp", "-m", "multiport", "--dports", "80,443", "-j", "ACCEPT"], ["-j", "REJECT"]]
    return output


def install(infrastructure, nameservers):
    # Build a fresh chain before attaching it. No scanning process starts until
    # the health check sees ready, including on a restart of this container.
    policy = ["*filter", ":WATCHTOWER_OUT - [0:0]", "-F WATCHTOWER_OUT"]
    policy += ["-A WATCHTOWER_OUT " + " ".join(rule) for rule in rules(infrastructure, nameservers)]
    policy.append("COMMIT")
    # iptables-restore replaces the chain atomically; restarting the guard does
    # not briefly expose a flushed/empty chain to an already-running worker.
    subprocess.run(["iptables-restore", "--noflush"], input="\n".join(policy) + "\n", text=True,
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    exists = subprocess.run(["iptables", "-C", "OUTPUT", "-j", "WATCHTOWER_OUT"], capture_output=True).returncode == 0
    if not exists:
        run("iptables", "-I", "OUTPUT", "1", "-j", "WATCHTOWER_OUT")
    # IPv6 is deliberately disabled in this deployment until equivalent
    # infrastructure allowlists and egress tests are configured.
    run("ip6tables", "-P", "OUTPUT", "DROP")


def main():
    infrastructure = []
    for entry in os.environ.get("WATCHTOWER_ALLOWED_INFRA", "postgres:5432,rabbitmq:5672").split(","):
        if not entry.strip():
            continue
        host, port = entry.rsplit(":", 1)
        infrastructure.extend((row[4][0], int(port)) for row in socket.getaddrinfo(host, int(port), socket.AF_INET, socket.SOCK_STREAM))
    nameservers = [line.split()[1] for line in Path("/etc/resolv.conf").read_text().splitlines() if line.startswith("nameserver")]
    install(infrastructure, nameservers)
    Path("/tmp/ready").touch()
    signal.pause()


if __name__ == "__main__":
    main()
