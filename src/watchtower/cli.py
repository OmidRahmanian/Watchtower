"""``watchtower``: operate the platform from a terminal.

Administration (``bootstrap``, ``member``, ``token``) talks to the database
directly and is for whoever holds the database URL. Every other command
authenticates with an API token, exactly like the HTTP API, and acts with
that token's role in the selected project:

    WATCHTOWER_TOKEN      the token (or --token-file / ~/.config/watchtower/token)
    WATCHTOWER_PROJECT    project slug or id (or --project)
    WATCHTOWER_PROFILE    settings profile (or --profile), e.g. development or lab

Captured content (hostnames, page titles, evidence) is printed with control
characters escaped, so a hostile page cannot drive the terminal.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import unicodedata
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TextIO
from uuid import UUID

from watchtower.api import queries, schemas
from watchtower.api.runs import FINISHED_RUN_STATUSES, RunsPort, default_runs
from watchtower.api.storage import default_evidence_root
from watchtower.config import load_settings
from watchtower.config.settings import Settings
from watchtower.domain.errors import (
    AuthenticationFailed,
    InvalidScopeRule,
    InvalidTarget,
    NotFound,
    PermissionDenied,
    ScopeViolation,
    WatchtowerError,
)
from watchtower.domain.models import FindingStatus, RunPhase
from watchtower.domain.scope import AuthorizationKind, AuthorizationReference, RuleEffect, ScopeRule
from watchtower.persistence.database import Database
from watchtower.security.auth import Permission, ProjectContext, ProjectRole
from watchtower.services.evidence_store import BlobError, FilesystemBlobStore
from watchtower.services.findings import FindingError, FindingService, RepositoryFindingStore
from watchtower.services.scope import ScopeService

DEFAULT_TOKEN_FILE = Path("~/.config/watchtower/token")
TOKEN_FILE_MODE = 0o600

# -- output ---------------------------------------------------------------


def safe(value: Any) -> str:
    """Text with control, format and separator characters escaped, for printing captured data."""
    text = "" if value is None else str(value)
    out = []
    for char in text:
        if char == " " or not unicodedata.category(char).startswith(("C", "Z")):
            out.append(char)
            continue
        code = ord(char)
        out.append(f"\\x{code:02x}" if code < 0x100 else f"\\u{code:04x}" if code < 0x10000 else f"\\U{code:08x}")
    return "".join(out)


class Style:
    """ANSI styling that is off for pipes, ``NO_COLOR`` and dumb terminals."""

    CODES = {"red": "1;31", "green": "1;32", "yellow": "1;33", "grey": "90", "bold": "1", "cyan": "36"}

    def __init__(self, stream: TextIO) -> None:
        self.enabled = stream.isatty() and "NO_COLOR" not in os.environ and os.environ.get("TERM") != "dumb"

    def __call__(self, text: str, colour: str) -> str:
        return f"\033[{self.CODES[colour]}m{text}\033[0m" if self.enabled else text


# Failed and cancelled work is never shown in the colour of success.
RUN_COLOURS = {"succeeded": "green", "partial": "yellow", "failed": "red", "cancelled": "grey",
               "queued": "cyan", "running": "cyan"}
REMEDIATION_LABELS = {
    "verified_fixed": ("FIXED (verified by retest)", "green"),
    "retest_failed": ("RETEST FAILED - not verified", "red"),
    "retest_inconclusive": ("RETEST INCONCLUSIVE - not verified", "yellow"),
    "retest_pending": ("retest pending", "cyan"),
    "still_present": ("still present after retest", "red"),
    "not_retested": ("not retested", "grey"),
}
_ANSI = re.compile(r"\033\[[0-9;]*m")
SEVERITY_COLOURS = {"critical": "red", "high": "red", "medium": "yellow", "low": "cyan", "info": "grey"}


def table(out: TextIO, rows: Sequence[Sequence[str]], headers: Sequence[str]) -> None:
    """Left-aligned columns; widths ignore ANSI styling."""
    widths = [len(header) for header in headers]
    for row in rows:
        widths = [max(width, len(_strip(str(cell)))) for width, cell in zip(widths, row, strict=True)]
    print("  ".join(h.upper().ljust(w) for h, w in zip(headers, widths, strict=True)), file=out)
    for row in rows:
        cells = (str(c) + " " * (w - len(_strip(str(c)))) for c, w in zip(row, widths, strict=True))
        print("  ".join(cells).rstrip(), file=out)


def _strip(text: str) -> str:
    return _ANSI.sub("", text)


def when(moment: datetime | str | None) -> str:
    if moment is None:
        return "-"
    if isinstance(moment, str):
        moment = datetime.fromisoformat(moment)
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")


def as_json(model: Any) -> str:
    if hasattr(model, "model_dump"):
        return json.dumps(model.model_dump(mode="json"), indent=2)
    return json.dumps(model, indent=2, default=str)


# -- context --------------------------------------------------------------


class CliError(Exception):
    """A problem to report to the user without a traceback."""


@dataclass
class App:
    settings: Settings
    database: Database
    scope: ScopeService
    out: TextIO
    style: Style
    runs_factory: Callable[[Database, ScopeService], RunsPort | None] = default_runs
    _runs: RunsPort | None = None
    work_step: Callable[[], int] | None = None  # replaces the in-process worker for --work (tests)

    @property
    def runs(self) -> RunsPort:
        if self._runs is None:
            self._runs = self.runs_factory(self.database, self.scope)
        if self._runs is None:
            raise CliError("the monitoring runtime (watchtower.services.jobs) is not installed")
        return self._runs

    def say(self, text: str = "") -> None:
        print(text, file=self.out, flush=True)


def read_token(args: argparse.Namespace) -> str:
    if os.environ.get("WATCHTOWER_TOKEN"):
        return os.environ["WATCHTOWER_TOKEN"].strip()
    path = Path(args.token_file or DEFAULT_TOKEN_FILE).expanduser()
    try:
        mode = path.stat().st_mode & 0o777
        if mode & 0o077:
            raise CliError(f"{path} is readable by other users; run: chmod 600 {path}")
        return path.read_text().strip()
    except FileNotFoundError:
        raise CliError("no API token: set WATCHTOWER_TOKEN, pass --token-file, or run `watchtower bootstrap "
                       "--save-token`") from None


def save_token(path: Path, token: str) -> Path:
    path = path.expanduser()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, TOKEN_FILE_MODE)
    with os.fdopen(descriptor, "w") as handle:
        os.fchmod(handle.fileno(), TOKEN_FILE_MODE)
        handle.write(token + "\n")
    return path


def resolve_project(app: App, reference: str | None) -> UUID:
    reference = reference or os.environ.get("WATCHTOWER_PROJECT")
    if not reference:
        raise CliError("choose a project with --project or WATCHTOWER_PROJECT")
    try:
        return UUID(reference)
    except ValueError:
        pass
    with app.database.system() as system:
        project = system.projects.get_by_slug(reference)
    if project is None:
        raise CliError(f"project {reference!r} not found")
    return project.id


def context(app: App, args: argparse.Namespace) -> ProjectContext:
    project_id = resolve_project(app, args.project)
    token = read_token(args)
    with app.database.system() as system:
        try:
            return system.auth.project_context(token, project_id)
        except PermissionDenied:
            raise CliError("project not found, or this token has no access to it") from None


# -- administration -------------------------------------------------------


def cmd_bootstrap(app: App, args: argparse.Namespace) -> int:
    """Create a project with an owner and print the owner's API token once."""
    with app.database.system() as system:
        project = system.projects.get_by_slug(args.slug)
        if project is None:
            project = system.projects.create(args.slug, args.name or args.slug)
            app.say(f"Created project {safe(project.slug)} ({project.id})")
        else:
            app.say(f"Using existing project {safe(project.slug)} ({project.id})")
        principal = system.auth.create_principal(args.owner, email=args.email)
        system.auth.set_membership(project.id, principal.id, ProjectRole.OWNER)
        issued = system.auth.issue_token(principal.id, args.token_name, project_id=project.id,
                                         ttl_days=app.settings.auth.token_ttl_days)
    _report_token(app, args, issued.secret, f"owner {safe(args.owner)}")
    return 0


def cmd_member_add(app: App, args: argparse.Namespace) -> int:
    project_id = resolve_project(app, args.project)
    with app.database.system() as system:
        principal = system.auth.create_principal(args.name, email=args.email)
        system.auth.set_membership(project_id, principal.id, ProjectRole(args.role))
        issued = system.auth.issue_token(principal.id, args.token_name, project_id=project_id,
                                         ttl_days=app.settings.auth.token_ttl_days)
    _report_token(app, args, issued.secret, f"{args.role} {safe(args.name)}")
    return 0


def cmd_token_revoke(app: App, args: argparse.Namespace) -> int:
    with app.database.system() as system:
        system.auth.revoke_token(UUID(args.token_id))
    app.say("Token revoked.")
    return 0


def _report_token(app: App, args: argparse.Namespace, token: str, who: str) -> None:
    if getattr(args, "save_token", None):
        path = save_token(Path(args.save_token), token)
        app.say(f"API token for {who} saved to {path} (mode 600). It is not shown again.")
    else:
        app.say(f"API token for {who} (shown once; store it securely):")
        app.say(token)


# -- projects and scope ---------------------------------------------------


def cmd_status(app: App, args: argparse.Namespace) -> int:
    ctx = context(app, args)
    with app.database.project(ctx.project_id) as uow:
        project = uow.get_project()
        current = uow.scope.current()
        counts = queries.counts(uow)
    if args.json:
        app.say(json.dumps({"project": schemas.project_out(project, ctx).model_dump(mode="json"),
                            "scope": schemas.revision_out(current).model_dump(mode="json") if current else None,
                            "counts": counts}, indent=2))
        return 0
    s = app.style
    app.say(f"{s(safe(project.name), 'bold')} ({safe(project.slug)}), you are {ctx.role.value}")
    if current is None:
        app.say(s("Scope: none published. Nothing will be scanned until you publish an authorized scope.", "yellow"))
    else:
        includes = ", ".join(safe(r.pattern) for r in current.includes)
        app.say(f"Scope: revision {current.number}, includes {includes}")
        app.say(f"  authorized by {safe(current.authorization.granted_by)} "
                f"({current.authorization.kind.value}: {safe(current.authorization.reference)})")
    open_count = counts["findings_by_status"]["open"] + counts["findings_by_status"]["triaged"]
    app.say(f"Assets: {sum(counts['assets'].values())}   Open findings: {open_count}   "
            f"Resolved: {counts['findings_by_status']['resolved']}")
    return 0


def cmd_scope_show(app: App, args: argparse.Namespace) -> int:
    ctx = context(app, args)
    history = app.scope.history(ctx.project_id, actor=ctx)
    if args.json:
        app.say(json.dumps([schemas.revision_out(r).model_dump(mode="json") for r in history], indent=2))
        return 0
    if not history:
        app.say("No scope revisions published.")
        return 0
    for revision in history:
        state = app.style("revoked", "red") if revision.revocation else "published"
        app.say(f"Revision {revision.number} ({state}) {when(revision.created_at)}, ports {revision.permitted_ports}")
        app.say(f"  authorization: {revision.authorization.kind.value} by {safe(revision.authorization.granted_by)}"
                f": {safe(revision.authorization.reference)}")
        for rule in revision.rules:
            app.say(f"  {rule.effect.value:<7} {safe(rule.pattern)}" + (f" ports {rule.ports}" if rule.ports else ""))
        if revision.revocation:
            app.say(f"  revoked {when(revision.revocation.revoked_at)}: {safe(revision.revocation.reason)}")
    return 0


def cmd_scope_publish(app: App, args: argparse.Namespace) -> int:
    ctx = context(app, args)
    ctx.require(Permission.MANAGE_SCOPE)
    if not args.i_am_authorized:
        raise CliError("publishing scope states that you are authorized to test every included target; "
                       "pass --i-am-authorized to confirm")
    rules = [ScopeRule.parse(p) for p in args.include]
    rules += [ScopeRule.parse(p, effect=RuleEffect.EXCLUDE) for p in args.exclude or []]
    kind = AuthorizationKind(args.authorization_kind)
    if kind is AuthorizationKind.LEGACY_IMPORT:
        raise CliError("legacy_import is reserved for the MongoDB importer")
    revision = app.scope.publish(
        ctx.project_id, rules,
        AuthorizationReference(kind=kind, reference=args.reference, granted_by=args.granted_by),
        actor=ctx, permitted_ports=args.ports, notes=args.notes or "",
    )
    app.say(f"Published scope revision {revision.number}: "
            + ", ".join(safe(r.pattern) for r in revision.includes)
            + (f" (excluding {', '.join(safe(r.pattern) for r in revision.excludes)})" if revision.excludes else ""))
    return 0


def cmd_scope_revoke(app: App, args: argparse.Namespace) -> int:
    ctx = context(app, args)
    revision = app.scope.revoke(ctx.project_id, UUID(args.revision), reason=args.reason, actor=ctx)
    app.say(f"Revoked revision {revision.number}. Scanning stops until a new revision is published.")
    return 0


def cmd_scope_check(app: App, args: argparse.Namespace) -> int:
    ctx = context(app, args)
    ctx.require(Permission.VIEW)
    decision = app.scope.authorize_target(ctx.project_id, args.target, port=args.port)
    verdict = app.style("allowed", "green") if decision else app.style("denied", "red")
    app.say(f"{safe(args.target)}: {verdict} ({decision.reason.value}) {safe(decision.detail)}".rstrip())
    return 0 if decision else 3


# -- runs and monitoring --------------------------------------------------


# Phase comparisons that mean the run could not see what it was asked to look at.
COMPARISON_COLOURS = {"failed": "red", "uncertain": "red", "partial": "yellow", "changed": "cyan"}


def _run_line(app: App, run: schemas.RunOut) -> list[str]:
    phases = " ".join(app.style(safe(f"{p.phase}:{p.comparison}"), COMPARISON_COLOURS[p.comparison])
                      if p.comparison in COMPARISON_COLOURS else safe(f"{p.phase}:{p.comparison}")
                      for p in run.phases[:4])
    return [str(run.run_id)[:8], run.kind, app.style(run.status.upper(), RUN_COLOURS.get(run.status, "bold")),
            when(run.created_at), phases or "-", safe(run.last_error or "")]


def cmd_run_start(app: App, args: argparse.Namespace) -> int:
    ctx = context(app, args)
    phases = [RunPhase(p) for p in args.phase] if args.phase else None
    run = schemas.run_out(app.runs.start_run(ctx.project_id, actor=ctx, targets=args.target or None,
                                             phases=phases, reason=args.reason or ""))
    app.say(f"Queued run {run.run_id} ({run.kind}).")
    if args.watch:
        return monitor(app, ctx, args, follow=run.run_id)
    return 0


def cmd_run_list(app: App, args: argparse.Namespace) -> int:
    ctx = context(app, args)
    runs = [schemas.run_out(r) for r in app.runs.list_runs(ctx.project_id, actor=ctx, limit=args.limit)]
    if args.json:
        app.say(json.dumps([r.model_dump(mode="json") for r in runs], indent=2))
        return 0
    table(app.out, [_run_line(app, r) for r in runs], ["run", "kind", "status", "created", "phases", "error"])
    return 0


def cmd_run_show(app: App, args: argparse.Namespace) -> int:
    ctx = context(app, args)
    detail = schemas.run_detail_out(app.runs.get_run(ctx.project_id, _run_id(app, ctx, args.run), actor=ctx))
    if args.json:
        app.say(as_json(detail))
        return 0
    run = detail.run
    app.say(f"Run {run.run_id} ({run.kind}) {app.style(run.status.upper(), RUN_COLOURS.get(run.status, 'bold'))}")
    app.say(f"  created {when(run.created_at)}  finished {when(run.finished_at)}  reason {safe(run.reason) or '-'}")
    if run.last_error:
        app.say("  " + app.style(f"error: {safe(run.last_error)}", "red"))
    if detail.retest_outcome:
        app.say(f"  retest outcome: {safe(detail.retest_outcome)}")
    table(app.out, [[j.kind, app.style(j.status, RUN_COLOURS.get(j.status, "bold")), f"{j.attempts}/{j.max_attempts}",
                     safe((j.result or {}).get("outcome", "")), safe(j.last_error or "")] for j in detail.jobs],
          ["job", "status", "attempts", "outcome", "error"])
    for snapshot in detail.snapshots:
        changes = sum(len(v) if isinstance(v, list) else 1 for v in snapshot.changes.values())
        comparison = snapshot.comparison
        if comparison in COMPARISON_COLOURS:
            comparison = app.style(comparison, COMPARISON_COLOURS[comparison])
        app.say(f"  {snapshot.phase:<9} {safe(snapshot.target)}: {snapshot.status}, {comparison}"
                + (f", {changes} change(s)" if changes else ""))
    _say_not_run(app, detail)
    return 0


def _say_not_run(app: App, detail: schemas.RunDetailOut) -> None:
    for rule_id, reason in detail.checks_not_run.items():
        app.say(app.style(f"Check {safe(rule_id)} did not run: {safe(reason)}", "yellow"))
    if detail.retest_outcome == "not_run":
        app.say(app.style("The retest did not run, so the finding was left unchanged.", "yellow"))


def cmd_run_cancel(app: App, args: argparse.Namespace) -> int:
    ctx = context(app, args)
    count = app.runs.cancel_run(ctx.project_id, _run_id(app, ctx, args.run), actor=ctx, reason=args.reason)
    app.say(f"Cancellation requested for {count} job(s).")
    return 0


def _run_id(app: App, ctx: ProjectContext, reference: str) -> UUID:
    """A full run id, or a unique prefix of a recent one as printed by ``run list``."""
    try:
        return UUID(reference)
    except ValueError:
        pass
    matches = [r.run_id for r in app.runs.list_runs(ctx.project_id, actor=ctx, limit=200)
               if str(r.run_id).startswith(reference.lower())]
    if len(matches) != 1:
        raise CliError(f"no single recent run starts with {reference!r}")
    return matches[0]


def _worker(app: App) -> Callable[[], int]:
    """Drive the queue in this process: run due jobs, then deliver notifications."""
    if app.work_step is not None:
        return app.work_step
    try:
        from watchtower.workers.runtime import Notifier, Worker
    except ImportError:
        raise CliError("--work needs the monitoring runtime (watchtower.workers.runtime)") from None
    worker = Worker(app.database, app.scope, settings=app.settings)
    notifier = Notifier(app.database, app.settings)

    def step() -> int:
        return worker.run_until_idle() + notifier.run_until_idle()

    return step


def describe_change(change: dict[str, Any]) -> str:
    """One readable line for an alert change: what changed, where, and from what to what."""
    kind = str(change.get("type", "change"))
    key = change.get("key") or change.get("target") or ""
    before, after = change.get("before"), change.get("after")
    if kind.startswith("finding."):
        finding = after if isinstance(after, dict) else before if isinstance(before, dict) else {}
        line = (f"{kind} [{finding.get('severity', '?')}] {finding.get('title', key)} on "
                f"{finding.get('host', '?')} ({finding.get('check_id', '?')})")
    elif kind.startswith("asset."):
        line = f"{kind} {key}"
    elif isinstance(before, dict) and isinstance(after, dict):
        differences = [f"{name}: {before.get(name)!r} -> {after.get(name)!r}"
                       for name in sorted(set(before) | set(after)) if before.get(name) != after.get(name)]
        line = f"{kind} {key} " + "; ".join(differences)
    else:
        line = f"{kind} {key}: {before!r} -> {after!r}"
    return safe(line)


def monitor(app: App, ctx: ProjectContext, args: argparse.Namespace, *, follow: UUID | None = None) -> int:
    """Print run status changes and new alerts until interrupted (or until ``follow`` finishes)."""
    step = _worker(app) if getattr(args, "work", False) else None
    seen_status: dict[UUID, str] = {}
    seen_alerts: set[UUID] = set()
    with app.database.project(ctx.project_id) as uow:
        seen_alerts.update(a.id for a in queries.list_alerts(uow, limit=200))
    interval = max(float(getattr(args, "interval", 5.0)), 0.0)
    app.say(f"Watching {'run ' + str(follow) if follow else 'project'}; press Ctrl+C to stop.")
    try:
        while True:
            if step is not None:
                step()
            for run in reversed([schemas.run_out(r) for r in app.runs.list_runs(ctx.project_id, actor=ctx, limit=10)]):
                if follow is not None and run.run_id != follow:
                    continue
                if seen_status.get(run.run_id) != run.status:
                    seen_status[run.run_id] = run.status
                    line = _run_line(app, run)
                    app.say(f"[{when(datetime.now(timezone.utc))}] run {line[0]} {line[1]} {line[2]}"
                            + (f" - {line[5]}" if line[5] else ""))
            with app.database.project(ctx.project_id) as uow:
                fresh = [a for a in reversed(queries.list_alerts(uow, limit=50)) if a.id not in seen_alerts]
            for alert in fresh:
                seen_alerts.add(alert.id)
                colour = "red" if alert.event_type == "monitor.run_failed" else "yellow"
                app.say(app.style(f"ALERT {alert.event_type}", colour) + f" ({alert.channel}, {alert.status.value})")
                for change in alert.payload.get("changes", [])[:50]:
                    app.say(f"  - {describe_change(change)}")
            if follow is not None and seen_status.get(follow) in FINISHED_RUN_STATUSES:
                status = seen_status[follow]
                return 0 if status in ("succeeded", "partial") else 4
            time.sleep(interval)
    except KeyboardInterrupt:
        app.say("\nStopped watching.")
        return 0


def cmd_watch(app: App, args: argparse.Namespace) -> int:
    ctx = context(app, args)
    follow = _run_id(app, ctx, args.run) if args.run else None
    return monitor(app, ctx, args, follow=follow)


# -- inventory, findings, evidence, alerts --------------------------------


def cmd_assets(app: App, args: argparse.Namespace) -> int:
    ctx = context(app, args)
    ctx.require(Permission.VIEW)
    with app.database.project(ctx.project_id) as uow:
        assets = [schemas.asset_out(a) for a in queries.list_assets(uow, limit=args.limit, search=args.search)]
    if args.json:
        app.say(json.dumps([a.model_dump(mode="json") for a in assets], indent=2))
        return 0
    rows = []
    for asset in assets:
        http = asset.last_http or {}
        rows.append([safe(asset.value), asset.kind, safe(", ".join(asset.addresses)) or "-",
                     safe(http.get("status_code") or http.get("outcome") or "-"), safe(http.get("title") or ""),
                     when(asset.last_seen_at)])
    table(app.out, rows, ["asset", "kind", "addresses", "http", "title", "last seen"])
    return 0


def _finding(app: App, ctx: ProjectContext, reference: str) -> Any:
    with app.database.project(ctx.project_id) as uow:
        try:
            finding = uow.findings.get(UUID(reference))
        except ValueError:
            matches = [f for f in queries.list_findings(uow, limit=500) if str(f.id).startswith(reference.lower())]
            finding = matches[0] if len(matches) == 1 else None
        if finding is None:
            raise CliError(f"finding {reference!r} not found")
        return schemas.finding_detail_out(finding, list(uow.evidence.list_for_finding(finding.id)))


def remediation_label(app: App, state: str) -> str:
    label, colour = REMEDIATION_LABELS[state]
    return app.style(label, colour)


def cmd_findings(app: App, args: argparse.Namespace) -> int:
    ctx = context(app, args)
    ctx.require(Permission.VIEW)
    statuses = [FindingStatus(s) for s in args.status] if args.status else (
        [] if args.all else [FindingStatus.OPEN, FindingStatus.TRIAGED])
    with app.database.project(ctx.project_id) as uow:
        findings = [schemas.finding_out(f) for f in queries.list_findings(uow, limit=args.limit, statuses=statuses)]
    if args.json:
        app.say(json.dumps([f.model_dump(mode="json") for f in findings], indent=2))
        return 0
    table(app.out, [[str(f.id)[:8], app.style(f.severity.value, SEVERITY_COLOURS[f.severity.value]), f.status.value,
                     remediation_label(app, f.remediation), safe(f.title), safe(f.target + f.location),
                     when(f.last_seen_at)] for f in findings],
          ["id", "severity", "status", "remediation", "title", "where", "last seen"])
    return 0


def cmd_finding_show(app: App, args: argparse.Namespace) -> int:
    ctx = context(app, args)
    ctx.require(Permission.VIEW)
    finding = _finding(app, ctx, args.finding)
    if args.json:
        app.say(as_json(finding))
        return 0
    s = app.style
    app.say(f"{s(safe(finding.title), 'bold')}  [{s(finding.severity.value, SEVERITY_COLOURS[finding.severity.value])}]")
    app.say(f"  id {finding.id}")
    app.say(f"  where {safe(finding.target)}{safe(finding.location)}   check {safe(finding.check_id)} "
            f"v{safe(finding.rule_version)}   confidence {safe(finding.confidence)}")
    app.say(f"  status {finding.status.value}   remediation {remediation_label(app, finding.remediation)}")
    app.say(f"  detection {finding.detection.state} (last outcome {finding.detection.last_outcome} at "
            f"{when(finding.detection.last_outcome_at)})")
    app.say(f"  first seen {when(finding.first_seen_at)}   last seen {when(finding.last_seen_at)}   "
            f"seen {finding.occurrences}x, recurred {finding.recurrences}x")
    if finding.cves:
        app.say("  CVEs " + ", ".join(safe(c) for c in finding.cves))
    app.say("  history:")
    for event in finding.history[-15:]:
        extra = {k: v for k, v in event.items() if k not in ("at", "event") and v not in (None, "")}
        app.say(f"    {when(event.get('at'))} {safe(event.get('event'))} "
                + " ".join(f"{safe(k)}={safe(v)}" for k, v in extra.items()))
    app.say("  evidence:")
    for item in finding.evidence:
        app.say(f"    {item.id}  {when(item.created_at)}  {item.size_bytes} bytes  {safe(item.description)}")
    if not finding.evidence:
        app.say("    none stored")
    return 0


def cmd_finding_triage(app: App, args: argparse.Namespace) -> int:
    ctx = context(app, args)
    ctx.require(Permission.OPERATE)
    target = _finding(app, ctx, args.finding)
    with app.database.project(ctx.project_id) as uow:
        row = uow.findings.get(target.id)
        store = RepositoryFindingStore(uow, row.scope_revision_id, asset_for=lambda _target: row.asset_id)
        record = FindingService(store).transition(row.fingerprint, FindingStatus(args.status),
                                                  f"{ctx.principal.display_name} <{ctx.principal.id}>",
                                                  args.reason or "")
    app.say(f"Finding {str(target.id)[:8]} is now {record.status.value}.")
    return 0


def cmd_finding_retest(app: App, args: argparse.Namespace) -> int:
    ctx = context(app, args)
    ctx.require(Permission.OPERATE)
    target = _finding(app, ctx, args.finding)
    run = schemas.run_out(app.runs.request_retest(ctx.project_id, target.fingerprint, actor=ctx,
                                                  reason=args.reason or ""))
    app.say(f"Queued retest run {run.run_id} for finding {str(target.id)[:8]}.")
    if args.watch:
        code = monitor(app, ctx, args, follow=run.run_id)
        after = _finding(app, ctx, str(target.id))
        app.say(f"Finding {str(target.id)[:8]}: {after.status.value}, {remediation_label(app, after.remediation)}")
        detail = schemas.run_detail_out(app.runs.get_run(ctx.project_id, run.run_id, actor=ctx))
        _say_not_run(app, detail)
        return code
    return 0


def _evidence_store(app: App) -> FilesystemBlobStore:
    return FilesystemBlobStore(default_evidence_root(app.settings))


def cmd_evidence(app: App, args: argparse.Namespace) -> int:
    ctx = context(app, args)
    ctx.require(Permission.VIEW)
    with app.database.project(ctx.project_id) as uow:
        evidence = uow.evidence.get(UUID(args.evidence))
    if evidence is None or not evidence.storage_uri.startswith(f"fs:{ctx.project_id}/"):
        raise CliError("evidence not found")
    try:
        data = _evidence_store(app).get(evidence.storage_uri)
    except BlobError:
        raise CliError("evidence content is unavailable or failed verification") from None
    if args.output:
        path = Path(args.output)
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
        app.say(f"Saved {len(data)} bytes to {path} (sha256 {evidence.sha256}).")
        return 0
    try:
        content = json.loads(data)
    except ValueError:
        raise CliError("evidence is not JSON; use --output to save it") from None
    app.say(safe_json(content))
    return 0


def safe_json(content: Any) -> str:
    """Pretty JSON whose strings cannot carry raw control characters to the terminal."""
    return json.dumps(content, indent=2, ensure_ascii=True)


def cmd_alerts(app: App, args: argparse.Namespace) -> int:
    ctx = context(app, args)
    ctx.require(Permission.VIEW)
    with app.database.project(ctx.project_id) as uow:
        alerts = [schemas.alert_out(a) for a in queries.list_alerts(uow, limit=args.limit)]
    if args.json:
        app.say(json.dumps([a.model_dump(mode="json") for a in alerts], indent=2))
        return 0
    for alert in alerts:
        colour = "red" if alert.event_type == "monitor.run_failed" else "yellow"
        app.say(f"{when(alert.created_at)} {app.style(alert.event_type, colour)} to {safe(alert.channel)} "
                f"({alert.status}{', ' + safe(alert.last_error) if alert.last_error else ''})")
        for change in alert.payload.get("changes", [])[:20]:
            app.say(f"  - {describe_change(change)}")
    if not alerts:
        app.say("No alerts yet.")
    return 0


def cmd_serve(app: App, args: argparse.Namespace) -> int:
    try:
        import uvicorn
    except ImportError:
        raise CliError("install the API extra: pip install 'watchtower[api]'") from None
    from watchtower.api import create_app

    if args.host not in ("127.0.0.1", "::1", "localhost") and not args.allow_remote:
        raise CliError("refusing to listen beyond loopback without --allow-remote (put TLS in front of it)")
    uvicorn.run(create_app(app.database, settings=app.settings, scope=app.scope), host=args.host, port=args.port,
                log_level=app.settings.log_level.lower(), proxy_headers=False, server_header=False)
    return 0


# -- parser ---------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="watchtower", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--profile", help="settings profile (default: $WATCHTOWER_PROFILE or development)")
    parser.add_argument("--project", help="project slug or id (default: $WATCHTOWER_PROJECT)")
    parser.add_argument("--token-file", help=f"file holding the API token (default: {DEFAULT_TOKEN_FILE})")
    commands = parser.add_subparsers(dest="command", required=True, metavar="command")

    def add(name: str, handler: Callable[[App, argparse.Namespace], int], help: str, *, json_output: bool = False,
            parent: Any = commands) -> argparse.ArgumentParser:
        sub = parent.add_parser(name, help=help, description=help)
        sub.set_defaults(handler=handler)
        if json_output:
            sub.add_argument("--json", action="store_true", help="print JSON instead of a table")
        return sub

    boot = add("bootstrap", cmd_bootstrap, "create a project and its owner, and issue the owner's token (admin)")
    boot.add_argument("slug")
    boot.add_argument("--name", help="display name of the project")
    boot.add_argument("--owner", required=True, help="the owner's display name")
    boot.add_argument("--email")
    boot.add_argument("--token-name", default="cli")
    boot.add_argument("--save-token", metavar="PATH", help=f"write the token to PATH (mode 600), e.g. {DEFAULT_TOKEN_FILE}")

    member = commands.add_parser("member", help="project members (admin)").add_subparsers(dest="sub", required=True)
    member_add = add("add", cmd_member_add, "add a member and issue their token", parent=member)
    member_add.add_argument("name")
    member_add.add_argument("--role", choices=[r.value for r in ProjectRole], required=True)
    member_add.add_argument("--email")
    member_add.add_argument("--token-name", default="cli")
    member_add.add_argument("--save-token", metavar="PATH")

    token = commands.add_parser("token", help="API tokens (admin)").add_subparsers(dest="sub", required=True)
    add("revoke", cmd_token_revoke, "revoke a token by id", parent=token).add_argument("token_id")

    add("status", cmd_status, "project, scope and totals", json_output=True)

    scope = commands.add_parser("scope", help="authorized scope").add_subparsers(dest="sub", required=True)
    add("show", cmd_scope_show, "scope revisions, newest first", json_output=True, parent=scope)
    publish = add("publish", cmd_scope_publish, "publish a new scope revision (needs owner)", parent=scope)
    publish.add_argument("--include", action="append", required=True, metavar="PATTERN",
                         help="example.com, *.example.com, or a CIDR; repeat for more")
    publish.add_argument("--exclude", action="append", metavar="PATTERN")
    publish.add_argument("--ports", help="permitted ports, e.g. 80,443 (default from the profile)")
    publish.add_argument("--authorization-kind", required=True,
                         choices=[k.value for k in AuthorizationKind if k is not AuthorizationKind.LEGACY_IMPORT])
    publish.add_argument("--reference", required=True, help="link or id of the program policy, contract or approval")
    publish.add_argument("--granted-by", required=True, help="who granted the authorization")
    publish.add_argument("--notes")
    publish.add_argument("--i-am-authorized", action="store_true",
                         help="confirm that the authorization covers every included target")
    revoke = add("revoke", cmd_scope_revoke, "revoke a revision; scanning stops at once", parent=scope)
    revoke.add_argument("revision")
    revoke.add_argument("--reason", required=True)
    check = add("check", cmd_scope_check, "would the current scope allow this target? (sends nothing)", parent=scope)
    check.add_argument("target")
    check.add_argument("--port", type=int)

    run = commands.add_parser("run", help="monitoring runs").add_subparsers(dest="sub", required=True)
    start = add("start", cmd_run_start, "queue a run pinned to the current scope", parent=run)
    start.add_argument("--target", action="append", help="root domain; default: every root in scope")
    start.add_argument("--phase", action="append", choices=[p.value for p in RunPhase])
    start.add_argument("--reason")
    _watch_options(start, follow_flag=True)
    run_list = add("list", cmd_run_list, "recent runs", json_output=True, parent=run)
    run_list.add_argument("--limit", type=int, default=20)
    add("show", cmd_run_show, "jobs and phase results of one run", json_output=True, parent=run).add_argument("run")
    cancel = add("cancel", cmd_run_cancel, "cancel a run", parent=run)
    cancel.add_argument("run")
    cancel.add_argument("--reason", required=True)

    watch = add("watch", cmd_watch, "follow run status changes and alerts")
    watch.add_argument("--run", help="stop when this run finishes; exit 4 if it failed or was cancelled")
    _watch_options(watch)

    assets = add("assets", cmd_assets, "inventory", json_output=True)
    assets.add_argument("--search")
    assets.add_argument("--limit", type=int, default=100)

    findings = add("findings", cmd_findings, "open findings (or --status / --all)", json_output=True)
    findings.add_argument("--status", action="append", choices=[s.value for s in FindingStatus])
    findings.add_argument("--all", action="store_true")
    findings.add_argument("--limit", type=int, default=100)

    finding = commands.add_parser("finding", help="one finding").add_subparsers(dest="sub", required=True)
    add("show", cmd_finding_show, "details, history and evidence", json_output=True, parent=finding).add_argument("finding")
    triage = add("triage", cmd_finding_triage, "change workflow status (not resolve)", parent=finding)
    triage.add_argument("finding")
    triage.add_argument("--status", required=True,
                        choices=[s.value for s in FindingStatus if s is not FindingStatus.RESOLVED])
    triage.add_argument("--reason")
    retest = add("retest", cmd_finding_retest, "queue a retest of this finding", parent=finding)
    retest.add_argument("finding")
    retest.add_argument("--reason")
    _watch_options(retest, follow_flag=True)

    evidence = add("evidence", cmd_evidence, "print redacted evidence, or save it with --output")
    evidence.add_argument("evidence")
    evidence.add_argument("--output", help="write the stored bytes to a new file (mode 600)")

    alerts = add("alerts", cmd_alerts, "notification outbox, newest first", json_output=True)
    alerts.add_argument("--limit", type=int, default=20)

    serve = add("serve", cmd_serve, "run the API and dashboard")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8080)
    serve.add_argument("--allow-remote", action="store_true")
    return parser


def _watch_options(parser: argparse.ArgumentParser, *, follow_flag: bool = False) -> None:
    if follow_flag:
        parser.add_argument("--watch", action="store_true", help="follow the run until it finishes")
    parser.add_argument("--work", action="store_true", help="also run due jobs in this process (local and lab use)")
    parser.add_argument("--interval", type=float, default=5.0, help="seconds between polls")


ERRORS: list[tuple[type[Exception], int, str]] = [
    (AuthenticationFailed, 2, "authentication failed"),
    (PermissionDenied, 2, "permission denied"),
    (NotFound, 1, "not found"),
    (ScopeViolation, 3, "not authorized by scope"),
    (InvalidScopeRule, 1, "invalid scope"),
    (InvalidTarget, 1, "invalid target"),
    (FindingError, 1, "not allowed"),
    (WatchtowerError, 1, "error"),
]


@contextmanager
def _database(settings: Settings) -> Iterator[Database]:
    database = Database.from_settings(settings.database)
    try:
        yield database
    finally:
        database.dispose()


def main(argv: Sequence[str] | None = None, *, out: TextIO | None = None, database: Database | None = None,
         runs: RunsPort | None = None, work: Callable[[], int] | None = None) -> int:
    """Entry point. Tests pass ``database``, ``runs`` and ``work`` to run in-process."""
    out = out or sys.stdout
    args = build_parser().parse_args(argv)
    try:
        settings = load_settings(args.profile)
        if database is None:
            with _database(settings) as owned:
                return _dispatch(settings, owned, out, args, runs, work)
        return _dispatch(settings, database, out, args, runs, work)
    except CliError as error:
        print(f"watchtower: {error}", file=sys.stderr)
        return 1
    except ScopeViolation as error:
        print(f"watchtower: not authorized by scope: {error.decision.reason.value}: {safe(error.decision.detail)}",
              file=sys.stderr)
        return 3
    except tuple(e for e, _, _ in ERRORS) as error:  # type: ignore[misc]
        code, label = next((code, label) for kind, code, label in ERRORS if isinstance(error, kind))
        print(f"watchtower: {label}: {safe(error)}", file=sys.stderr)
        return code
    except (ValueError, OSError) as error:
        print(f"watchtower: {safe(error)}", file=sys.stderr)
        return 1


def _dispatch(settings: Settings, database: Database, out: TextIO, args: argparse.Namespace,
              runs: RunsPort | None, work: Callable[[], int] | None) -> int:
    scope = ScopeService(database, settings.scope)
    app = App(settings=settings, database=database, scope=scope, out=out, style=Style(out), work_step=work)
    if runs is not None:
        app._runs = runs
    return args.handler(app, args)


if __name__ == "__main__":
    raise SystemExit(main())
