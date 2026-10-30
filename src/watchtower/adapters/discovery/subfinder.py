"""Passive Subfinder adapter.

Subfinder only queries third-party data sources here. Flags that would resolve
or contact the target (-active, -ip, -nW/-rL resolver options) are never
passed, so this adapter needs passive discovery authorization only.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field

from watchtower.adapters.discovery.process import ProcessResult, run_bounded
from watchtower.adapters.probing.guard import ScopeGuard, explain
from watchtower.services.inventory import DiscoveredName, in_domain, normalize_hostname

# Flags that make subfinder resolve names itself or contact resolvers we have not approved.
FORBIDDEN_FLAGS = frozenset({"-active", "-nW", "-ip", "-oI", "-r", "-rL", "-rlist"})


@dataclass
class SubfinderRun:
    domain: str
    names: list[DiscoveredName] = field(default_factory=list)
    skipped: str = ""
    errors: list[str] = field(default_factory=list)
    ignored_lines: int = 0


def build_argv(domain: str, *, binary: str = "subfinder", timeout: int = 30, max_minutes: int = 10, all_sources: bool = True) -> list[str]:
    argv = [binary, "-d", domain, "-silent", "-json", "-timeout", str(timeout), "-max-time", str(max_minutes)]
    if all_sources:
        argv.append("-all")
    return argv


def parse_output(stdout: bytes, domain: str, run: SubfinderRun) -> None:
    """Collect one DiscoveredName per hostname, merging the upstream sources that reported it."""
    sources_by_host: dict[str, set[str]] = {}
    for raw in stdout.decode("utf-8", "replace").splitlines():
        raw = raw.strip()
        if not raw:
            continue
        try:
            record = json.loads(raw)
            hostname = normalize_hostname(record["host"])
        except (ValueError, KeyError, TypeError):
            run.ignored_lines += 1
            continue
        if not in_domain(hostname, domain):
            run.ignored_lines += 1
            continue
        sources = record.get("sources") or ([record["source"]] if record.get("source") else [])
        sources_by_host.setdefault(hostname, set()).update(str(source) for source in sources)
    for hostname, sources in sources_by_host.items():
        detail = {"upstream_sources": sorted(sources)} if sources else {}
        run.names.append(DiscoveredName(hostname, "subfinder", domain, detail=detail))


def discover(
    domain: str,
    guard: ScopeGuard,
    *,
    binary: str = "subfinder",
    timeout: float = 900.0,
    max_output_bytes: int = 8 * 1024 * 1024,
    runner=run_bounded,
) -> SubfinderRun:
    domain = normalize_hostname(domain)
    run = SubfinderRun(domain)
    # Passive sources never contact the target, so a name-only scope check suffices.
    decision = guard.check_target(domain, port=None)
    if not decision:
        run.skipped = explain(decision)
        return run

    argv = build_argv(domain, binary=binary, max_minutes=max(1, int(timeout // 60) - 1))
    result: ProcessResult = runner(argv, timeout=timeout, max_stdout=max_output_bytes)
    if result.error:
        run.errors.append(result.error)
        return run
    if result.timed_out:
        run.errors.append(f"subfinder timed out after {timeout:g}s; keeping partial output")
    if result.truncated:
        run.errors.append(f"subfinder output exceeded {max_output_bytes} bytes; keeping partial output")
    if result.returncode not in (0, None) and not result.timed_out and not result.truncated:
        stderr = result.stderr.decode("utf-8", "replace").strip()[-500:]
        run.errors.append(f"subfinder exited with {result.returncode}: {stderr}")
    parse_output(result.stdout, domain, run)
    return run
