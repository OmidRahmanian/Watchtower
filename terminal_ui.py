#!/usr/bin/env python3
"""Interactive platform presentation. All mutations use the existing CLI/services.

Window commands contain identifiers and paths only. Every new terminal loads .env
itself; no credentials are embedded in shell commands or generated scripts.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
from urllib.error import URLError
from urllib.request import urlopen
from uuid import UUID, uuid4
import webbrowser

import launcher
from watchtower.cli import safe, Style, RUN_COLOURS

ROOT = Path(__file__).resolve().parent
FINISHED = {"succeeded", "partial", "failed", "cancelled"}
PROFILES = ("development", "lab", "production")
PHASES = ("discovery", "dns", "http", "checks", "finalize")
HOME = {
    "1": "Start scan", "2": "View scan progress", "3": "Browse inventory",
    "4": "Browse findings", "5": "Manage targets and scope", "6": "View alerts",
    "7": "Open dashboard", "8": "Switch or create project", "9": "Settings and help", "0": "Exit",
}


class UiError(Exception):
    pass


class Back(Exception):
    pass


def tell(value=""):
    """Bound and wrap untrusted data; never interpret terminal control sequences."""
    width = max(20, min(shutil.get_terminal_size((80, 24)).columns, 120))
    for line in str(value).split("\n"):
        print(textwrap.fill(safe(line)[:4000], width=width, replace_whitespace=False) or "", flush=True)


def field(label, default="", validate=None):
    while True:
        answer = launcher.ask(label + " (b: Back)", default)
        if answer.lower() == "b":
            raise Back()
        try:
            return validate(answer) if validate else answer
        except ValueError as exc:
            tell(exc)


def menu(label, options, default="0"):
    return launcher.choose(label, options, default)


class Preferences:
    """Per-checkout UI preferences; token paths only, never token contents."""
    def __init__(self, root=ROOT):
        self.directory = root / "files" / "terminal-ui"
        self.path = self.directory / "preferences.json"
        try:
            data = json.loads(self.path.read_text())
            self.data = data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            self.data = {}
        if not isinstance(self.data.get("tokens"), dict):
            self.data["tokens"] = {}
        for key in ("profile", "project", "token_file"):
            if key in self.data and not isinstance(self.data[key], str):
                self.data.pop(key)

    def save(self, profile, project, token_file):
        self.data.update(profile=profile, project=project, token_file=str(token_file))
        self.data["tokens"][profile + ":" + project] = str(token_file)
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        descriptor, name = tempfile.mkstemp(dir=self.directory)
        try:
            with os.fdopen(descriptor, "w") as output:
                json.dump(self.data, output, indent=2)
            os.replace(name, self.path)
        finally:
            Path(name).unlink(missing_ok=True)


class Client:
    def __init__(self, root=ROOT, *, profile="development", project="", token_file=None, env=None):
        self.root = Path(root).absolute()
        self.python = launcher.python_executable(self.root)
        self.env = dict(env if env is not None else launcher.runtime_environment(self.root, self.python))
        self.profile = profile
        self.project = project
        self.token_file = Path(token_file or self.env.get("WATCHTOWER_TOKEN_FILE", "~/.config/watchtower/token")).expanduser().absolute()
        # An explicit selection must not be silently overridden by an old shell token.
        if token_file is not None:
            self.env.pop("WATCHTOWER_TOKEN", None)

    def command(self, *args):
        return [self.python, "-m", "watchtower.cli", "--profile", self.profile,
                "--project", self.project, "--token-file", str(self.token_file), *args]

    def call(self, *args, data=False):
        result = subprocess.run(self.command(*args, *(["--json"] if data else [])), cwd=self.root,
                                env=self.env, text=True, capture_output=True, timeout=45)
        if result.returncode:
            # Do not replay tracebacks, URLs or credentials from a database driver.
            lines = [line for line in result.stderr.splitlines() if line.startswith("watchtower:")]
            message = lines[-1] if lines else "Command failed. Check database connectivity, credentials and project access."
            if "://" in message:
                message = "Command failed. Check connection settings in .env and project access."
            raise UiError(message)
        if not data:
            return result.stdout
        try:
            return json.loads(result.stdout)
        except ValueError:
            raise UiError("The CLI returned an unreadable response; no action will be repeated automatically.") from None

    def json(self, *args):
        return self.call(*args, data=True)

    def show(self, *args):
        tell(self.call(*args))


@contextmanager
def session_lock(client, key):
    directory = client.root / "files" / "terminal-ui" / "locks"
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    name = hashlib.sha256((client.profile + ":" + client.project + ":" + key).encode()).hexdigest()
    with (directory / name).open("a") as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise UiError("Another terminal is already performing this action. View the existing run instead.") from None
        yield


def window_arguments(client, *, run=None, dashboard=False):
    argv = [client.python, str(client.root / "terminal_ui.py"), "--profile", client.profile,
            "--project", client.project, "--token-file", str(client.token_file), "--hold"]
    if dashboard:
        argv.append("--dashboard")
    else:
        argv += ["--run", str(UUID(str(run)))]
    return argv


def open_window(client, *, run=None, dashboard=False):
    """Best-effort dispatch. A run remains queued if the OS refuses a window."""
    argv = window_arguments(client, run=run, dashboard=dashboard)
    title = "WatchTower - " + safe(client.project)
    if sys.platform == "darwin":
        command = "cd " + shlex.quote(str(client.root)) + " && exec " + shlex.join(argv)
        script = ('on run argv\n tell application "Terminal"\n activate\n'
                  ' do script (item 1 of argv)\n end tell\nend run')
        result = subprocess.run(["osascript", "-e", script, command], capture_output=True, text=True, timeout=20)
        if result.returncode:
            raise UiError("macOS could not open Terminal. Allow terminal automation if prompted, or use this terminal.")
        return
    if sys.platform.startswith("linux"):
        variants = (
            ("gnome-terminal", ["--title", title, "--"]),
            ("konsole", ["--new-window", "-p", "tabtitle=" + title, "-e"]),
            ("xfce4-terminal", ["--disable-server", "--title", title, "-x"]),
            ("xterm", ["-T", title, "-e"]),
        )
        for executable, flags in variants:
            if shutil.which(executable):
                process = subprocess.Popen([executable, *flags, *argv], cwd=client.root,
                                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                           start_new_session=True)
                try:
                    code = process.wait(timeout=0.5)
                    if code != 0:
                        raise UiError("The terminal emulator could not open a window.")
                except subprocess.TimeoutExpired:
                    pass
                return
    raise UiError("No supported terminal window launcher was found. Use this terminal instead.")


def scope_summary(status):
    revision = status.get("scope")
    if not revision:
        return "None published - scanning is unavailable"
    return ", ".join(("exclude " if r["effect"] == "exclude" else "") + r["pattern"] for r in revision["rules"])


def current_phase(detail):
    active = sorted({j["kind"].removeprefix("monitor.") for j in detail.get("jobs", []) if j["status"] == "running"})
    return ", ".join(active) if active else "waiting for worker / next due job"


def render_progress(detail, project):
    run = detail["run"]
    end = run.get("finished_at") or datetime.now(timezone.utc).isoformat()
    elapsed = max(0, int((datetime.fromisoformat(end) - datetime.fromisoformat(run["created_at"])).total_seconds()))
    tell(f"\n{project} | Run {run['run_id']} | Elapsed {elapsed // 60}m {elapsed % 60}s")
    style = Style(sys.stdout)
    print(style(run["status"].upper(), RUN_COLOURS.get(run["status"], "bold")), flush=True)
    tell("Discovery > DNS > HTTP > Checks > Finalize")
    tell("Current: " + ("finished" if run["status"] in FINISHED else current_phase(detail)))
    for phase in PHASES:
        jobs = [j for j in detail.get("jobs", []) if j["kind"].split(".")[-1] == phase]
        if jobs:
            states = ", ".join(sorted({j["status"] for j in jobs}))
            tell(f"  {phase.upper()}: {states}")
    snapshots = detail.get("snapshots", [])
    for snapshot in snapshots[-12:]:
        tell(f"  {snapshot['phase']} / {snapshot['target']}: {snapshot['status']}, {snapshot['comparison']}")
        if snapshot.get("stats"):
            tell("    Counts: " + json.dumps(snapshot["stats"], ensure_ascii=True)[:600])
    if len(snapshots) > 12:
        tell(f"  Showing the latest 12 of {len(snapshots)} phase snapshots. Use run show for full details.")
    for name, reason in detail.get("checks_not_run", {}).items():
        tell(f"  NOT RUN: {name} - {reason}")
    errors = [j for j in detail.get("jobs", []) if j.get("last_error")]
    for job in errors[-5:]:
        tell(f"  Job {job['kind']}: {job['last_error']}")
    if len(errors) > 5:
        tell(f"  Showing the latest 5 of {len(errors)} job errors. Use run show for full details.")
    if run.get("last_error"):
        tell("Error: " + run["last_error"])
    if detail.get("retest_outcome"):
        tell("Retest outcome: " + detail["retest_outcome"])
    if run["status"] == "failed":
        tell("Run failed. Check the reported phase, target connectivity and installed tools; existing findings are not resolved.")
    elif run["status"] == "partial":
        tell("Run completed with gaps. Review NOT RUN checks and phase results; this is not a complete successful scan.")


class LocalProcessor:
    """Use the existing worker with graceful shutdown; it can claim other projects' jobs."""
    def __init__(self, client):
        from watchtower.config import load_settings
        from watchtower.persistence.database import Database
        from watchtower.services.scope import ScopeService
        from watchtower.workers import egress
        from watchtower.workers.runtime import Worker, Notifier

        settings = load_settings(client.profile)
        egress.install(settings)
        self.database = Database.from_settings(settings.database)
        self.worker = Worker(self.database, ScopeService(self.database, settings.scope), settings=settings)
        self.notifier = Notifier(self.database, settings)
        self.stop_event = threading.Event()
        self.error = None
        self.thread = threading.Thread(target=self.loop, daemon=True, name="watchtower-ui-worker")

    def loop(self):
        try:
            while not self.stop_event.is_set():
                worked = self.worker.run_once()
                if not self.stop_event.is_set():
                    self.notifier.deliver_once()
                if not worked:
                    self.stop_event.wait(1)
        except Exception as exc:
            self.error = type(exc).__name__  # no secret-bearing exception repr

    def start(self):
        self.thread.start()

    def close(self):
        self.stop_event.set()
        # The first shutdown may race a claim; repeat while the thread winds down.
        deadline = time.monotonic() + 15
        while self.thread.is_alive() and time.monotonic() < deadline:
            self.worker.shutdown()
            self.thread.join(timeout=0.2)
        if not self.thread.is_alive():
            self.database.dispose()
        else:
            tell("Local processing is stopping. In-flight leases may need to expire before another worker resumes them.")


def watch_run(client, run_id, *, work=False, interval=2):
    run_id = str(UUID(str(run_id)))
    # Validate access and the identifier before starting any worker.
    detail = client.json("run", "show", run_id)
    if work and detail["run"]["status"] in FINISHED:
        render_progress(detail, client.project)
        return 0 if detail["run"]["status"] in ("succeeded", "partial") else 4
    tell("Ctrl+C stops this viewer and its local processing, not the run. Use Cancel run in the home menu to cancel it.")
    processor = None
    previous = None
    last_print = 0.0
    try:
        if work:
            tell("Local worker enabled: it may also process due jobs and notifications from other projects.")
            processor = LocalProcessor(client)
            processor.start()
        while True:
            detail = client.json("run", "show", run_id)
            signature = json.dumps(detail, sort_keys=True)
            now = time.monotonic()
            if signature != previous or now - last_print >= 30:
                render_progress(detail, client.project)
                previous, last_print = signature, now
            status = detail["run"]["status"]
            if status in FINISHED:
                tell("Final result shown above. Alerts: Home > View alerts.")
                return 0 if status in ("succeeded", "partial") else 4
            if processor and processor.error:
                raise UiError("Local worker stopped (" + processor.error + "). Check configuration and resume this existing run; do not queue it again.")
            time.sleep(interval)
    except KeyboardInterrupt:
        tell("Stopped viewing and local processing. The run was not cancelled; another worker can resume it.")
        return 0
    finally:
        if processor:
            processor.close()


def scan_window(client, run_id):
    with session_lock(client, "process-" + str(UUID(str(run_id)))):
        return watch_run(client, run_id, work=True)


def process_here(client, run_id):
    # Keep the worker's process-wide egress guard and signal cleanup isolated
    # from Home, just as they are in a separate terminal window.
    argv = [arg for arg in window_arguments(client, run=run_id) if arg != "--hold"]
    process = subprocess.Popen(argv, cwd=client.root, env=client.env)
    try:
        return process.wait()
    except KeyboardInterrupt:
        tell("Waiting for local processing to stop safely; the run is not cancelled.")
        try:
            process.send_signal(signal.SIGINT)
            return process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            process.terminate()
            try:
                return process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                raise UiError("Worker shutdown timed out. Resume the existing run after its leases expire.") from None


def launch_scan(client, run_id):
    while True:
        try:
            open_window(client, run=run_id)
            tell(f"Scan window requested for {run_id}. This menu remains available.")
            tell("If no window appears, use View scan progress > Open processing window to retry this same run.")
            return
        except (UiError, OSError, subprocess.TimeoutExpired) as exc:
            tell(str(exc) if isinstance(exc, UiError) else "Could not launch the scan window.")
            tell(f"Run {run_id} is retained. No second run will be queued.")
            action = menu("Where should this run continue?", {"1": "Retry new window", "2": "Process in this terminal",
                                                            "0": "Back - leave queued for a worker"}, "0")
            if action == "2":
                process_here(client, run_id)
                return
            if action == "0":
                return


def start_scan(client):
    # Serializes launches from multiple home menus on this checkout.
    with session_lock(client, "start"):
        active = [r for r in client.json("run", "list", "--limit", "200") if r["status"] not in FINISHED]
        if active:
            tell("A run is already active. View or resume it instead of queueing a duplicate:")
            for run in active:
                tell(f"  {run['run_id']} {run['status']}")
            return
        status = client.json("status")
        tell(f"Project: {client.project} | Profile: {client.profile}")
        tell("Scope: " + scope_summary(status))
        if not status.get("scope"):
            tell("Publish scope through Manage targets and scope first.")
            return
        tell("Options: all authorized roots; Discovery > DNS > HTTP > Checks > Finalize.")
        tell("Pending detection rules will not run. A separate local worker window will process the queue.")
        if not launcher.yes_no("Queue this scan and open its progress window?", default=False):
            return
        run = client.json("run", "start", "--reason", "started from terminal home", "--reuse-active",
                          "--idempotency-key", str(uuid4()))
    tell("Queued run " + run["run_id"])
    launch_scan(client, run["run_id"])


def select_run(client):
    runs = client.json("run", "list", "--limit", "20")
    if not runs:
        tell("No runs yet. Use Start scan from Home.")
        raise Back()
    options = {str(i): safe(f"{r['run_id'][:8]} {r['status']} {r['created_at']}") for i, r in enumerate(runs, 1)}
    choice = menu("Recent runs", {**options, "0": "Back"})
    if choice == "0":
        raise Back()
    return runs[int(choice) - 1]


def progress_menu(client):
    run = select_run(client)
    while True:
        action = menu("Run " + run["run_id"], {"1": "Show current details", "2": "Watch here (no worker)",
                      "3": "Open processing window / resume", "4": "Cancel run", "0": "Back"})
        if action == "0":
            return
        if action == "1":
            render_progress(client.json("run", "show", run["run_id"]), client.project)
        elif action == "2":
            watch_run(client, run["run_id"])
        elif action == "3":
            launch_scan(client, run["run_id"])
        elif launcher.yes_no("Cancel this run?", default=False):
            reason = field("Cancellation reason", validate=launcher.required_text)
            client.show("run", "cancel", run["run_id"], "--reason", reason)


def manage_scope(client):
    while True:
        action = menu("Targets and scope", {"1": "Show scope and history", "2": "Publish scope", "3": "Check target (no network)",
                                           "4": "Revoke current scope", "0": "Back"})
        if action == "0":
            return
        if action == "1":
            client.show("scope", "show")
        elif action == "3":
            client.show("scope", "check", field("Target to check", validate=launcher.required_text))
        elif action == "4":
            current = client.json("status").get("scope")
            if current and launcher.yes_no("Revoke current scope and stop authorization for new requests?", default=False):
                client.show("scope", "revoke", current["id"], "--reason", field("Reason", validate=launcher.required_text))
        else:
            domain = field("Target domain (text, e.g. example.com)", validate=launcher.domain_name)
            include = [domain]
            if launcher.yes_no("Also include ALL subdomains (*." + domain + ")?", default=False):
                include.append("*." + domain)
            excluded = field("Excluded exact subdomains, comma-separated (- for none)", "-",
                             lambda value: launcher.exclusions(value, domain))
            choice = menu("Authorization", {**{k: label for k, (_, label) in launcher.AUTHORIZATIONS.items()}, "0": "Back"})
            if choice == "0":
                continue
            kind = launcher.AUTHORIZATIONS[choice][0]
            reference = field("Authorization reference (policy URL, contract or ticket)", validate=launcher.required_text)
            granted = field("Person or organization granting permission", validate=launcher.required_text)
            tell("New scope: " + ", ".join(include) + "; excluded: " + (", ".join(excluded) or "none"))
            if not launcher.yes_no("Do you have authorization covering every included target?", default=False):
                tell("Cancelled. Scope unchanged.")
                continue
            args = ["scope", "publish", "--authorization-kind", kind, "--reference", reference,
                    "--granted-by", granted, "--i-am-authorized"]
            for pattern in include:
                args += ["--include", pattern]
            for pattern in excluded:
                args += ["--exclude", pattern]
            client.show(*args)


def browse_findings(client):
    client.show("findings", "--all")
    while True:
        action = menu("Findings", {"1": "Inspect finding", "2": "Retest finding", "3": "Triage finding",
                                   "4": "Assign owner / add remediation notes", "5": "Recompute priority", "0": "Back"})
        if action == "0":
            return
        finding = field("Finding ID or unique prefix", validate=launcher.required_text)
        if action == "1":
            client.show("finding", "show", finding)
        elif action == "2":
            if launcher.yes_no("Queue a retest? It needs a worker; this does not mark the finding fixed.", default=False):
                client.show("finding", "retest", finding)
                tell("Use View scan progress to open the retest's processing window.")
        elif action == "4":
            client.show("finding", "annotate", finding, "--owner", field("Owner (Enter: unassigned)"),
                        "--remediation-notes", field("Remediation notes (Enter: clear)"))
        elif action == "5":
            client.show("finding", "prioritize", finding)
        else:
            status = menu("Triage status", {"1": "open", "2": "triaged", "3": "accepted_risk", "4": "false_positive", "5": "in_progress", "0": "Back"})
            if status != "0":
                value = {"1": "open", "2": "triaged", "3": "accepted_risk", "4": "false_positive", "5": "in_progress"}[status]
                reason = field("Reason", validate=launcher.required_text)
                if launcher.yes_no("Set this finding to " + value + "?", default=False):
                    client.show("finding", "triage", finding, "--status", value, "--reason", reason)


def dashboard_state():
    try:
        with urlopen("http://127.0.0.1:8080/api/v1/health", timeout=1) as response:
            body = json.load(response)
            return "ready" if body.get("status") == "ok" and "version" in body else "other"
    except URLError:
        return "unavailable"
    except (ValueError, OSError):
        return "other"


def open_dashboard(client):
    if dashboard_state() != "ready":
        try:
            open_window(client, dashboard=True)
        except (UiError, OSError, subprocess.TimeoutExpired):
            tell("Could not open a dashboard window. Your home menu is still available.")
            tell("From another terminal in this folder, run .venv/bin/python terminal_ui.py --dashboard")
            return
        for _ in range(10):
            if dashboard_state() == "ready":
                break
            time.sleep(0.5)
    if dashboard_state() == "ready":
        webbrowser.open("http://127.0.0.1:8080")
        tell("Dashboard: http://127.0.0.1:8080 (the existing server is reused when available).")
    else:
        tell("Dashboard window requested. Check that window for startup errors or a port conflict.")
    tell("Sign in with your local token file: " + str(client.token_file))
    tell("On macOS, copy privately: pbcopy < " + shlex.quote(str(client.token_file)))


def select_project(client, preferences):
    while True:
        candidates = {}
        paths = [client.token_file]
        paths += [Path(p) for key, p in preferences.data["tokens"].items()
                  if isinstance(key, str) and key.startswith(client.profile + ":") and isinstance(p, str)]
        for path in dict.fromkeys(paths):
            candidate = Client(client.root, profile=client.profile, token_file=path, env=client.env)
            try:
                for project in candidate.json("projects"):
                    if not project["archived"]:
                        candidates[project["slug"]] = (project, path)
            except UiError:
                continue
        rows = sorted(candidates.values(), key=lambda entry: entry[0]["slug"])
        if not rows:
            tell("No accessible projects found with the selected token files. Create a project, choose another token, or check .env and PostgreSQL.")
        options = {str(i): safe(f"{p['name']} ({p['slug']}, {p['role']})") for i, (p, _) in enumerate(rows, 1)}
        default = next((str(i) for i, (p, _) in enumerate(rows, 1) if p["slug"] == preferences.data.get("project")), "1" if rows else "0")
        action = menu("Projects - choose a number", {**options, "c": "Create project", "t": "Use another token file",
                      "p": "Change profile (current: " + client.profile + ")", "0": "Back"}, default)
        if action == "0":
            raise Back()
        if action == "p":
            choice = menu("Profile", {"1": "Development", "2": "Lab", "3": "Production", "0": "Back"})
            if choice != "0":
                client = Client(client.root, profile=PROFILES[int(choice) - 1], env=client.env)
        elif action == "t":
            path = field("Existing token FILE path (not the token itself)", validate=launcher.required_text)
            client = Client(client.root, profile=client.profile, token_file=path, env=client.env)
            # Validate immediately, with useful failure feedback.
            client.json("projects")
        elif action == "c":
            slug = field("New project NAME (text, e.g. acme-lab)", validate=launcher.project_slug)
            owner = field("Your name", validate=launcher.required_text)
            if not launcher.yes_no("Create this project using your configured database access?", default=False):
                continue
            directory = preferences.directory / "tokens"
            directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            token = directory / (client.profile + "-" + slug + "-" + uuid4().hex)
            client.show("bootstrap", slug, "--owner", owner, "--save-token", str(token))
            client = Client(client.root, profile=client.profile, project=slug, token_file=token, env=client.env)
            preferences.save(client.profile, slug, token)
            return client
        else:
            project, token = rows[int(action) - 1]
            client = Client(client.root, profile=client.profile, project=project["slug"], token_file=token, env=client.env)
            preferences.save(client.profile, client.project, token)
            return client


def settings_menu(client, preferences):
    while True:
        action = menu("Settings and help", {"1": "Change profile", "2": "Token and configuration help", "3": "Legacy discovery help",
                                            "4": "Effective settings and rule coverage", "5": "Intelligence feed status", "0": "Back"})
        if action == "0":
            return client
        if action == "1":
            choice = menu("Profile", {"1": "Development", "2": "Lab (isolated lab setup required)", "3": "Production", "0": "Back"})
            if choice != "0":
                candidate = Client(client.root, profile=PROFILES[int(choice) - 1], env=client.env)
                client = select_project(candidate, preferences)
                return client
        elif action == "2":
            tell("Platform: PostgreSQL, scope revisions and owner/operator/viewer roles.")
            tell("Secrets load from .env. UI remembers project/profile and token FILE paths only.")
            tell("Token file: " + str(client.token_file))
            tell("New windows read .env again. Shell-only credentials are not embedded in launch commands.")
            tell("Pending detection rules stay disabled. See docs/installation.md and rules/README.md.")
            tell("Closing a scan window stops its local processing, not the queued run. Cancel explicitly in View scan progress.")
            tell("Noninteractive commands: watchtower projects; watchtower --project <slug> run list; watchtower --help.")
        elif action == "4":
            tell(json.dumps(client.json("settings"), indent=2))
        elif action == "5":
            client.show("intelligence", "status")
        else:
            tell("Legacy discovery is separate: python launcher.py --legacy")
            tell("It uses MongoDB, targets.json and setting.json. Platform scope lives in PostgreSQL.")


def home(root=ROOT):
    preferences = Preferences(root)
    profile = preferences.data.get("profile", "development")
    if profile not in PROFILES:
        profile = "development"
    token = preferences.data.get("token_file")
    client = Client(root, profile=profile, project=preferences.data.get("project", ""), token_file=token)
    if client.project:
        try:
            client.json("status")
        except UiError:
            tell("The remembered project is unavailable. Choose a project or another token.")
            client.project = ""
    if not client.project:
        tell("Platform home - setup is saved between launches. 0 or b returns; Ctrl+C returns home.")
        try:
            client = select_project(client, preferences)
        except Back:
            return 0
    while True:
        try:
            tell("\nWATCHTOWER | Platform")
            tell(f"Project: {client.project} | Profile: {client.profile}")
            try:
                status = client.json("status")
                tell("Database: Connected | Scope: " + scope_summary(status))
                runs = client.json("run", "list", "--limit", "1")
                if runs:
                    detail = client.json("run", "show", runs[0]["run_id"])
                    tell("Latest run: " + runs[0]["status"].upper() + " / " +
                         ("finished" if runs[0]["status"] in FINISHED else current_phase(detail)))
                else:
                    tell("Latest run: none")
            except UiError as exc:
                tell("Connection / access unavailable: " + str(exc))
                tell("Retry after checking .env and PostgreSQL, or switch project through option 8.")
            action = menu("Home", HOME)
            if action == "0":
                return 0
            if action == "1":
                start_scan(client)
            elif action == "2":
                progress_menu(client)
            elif action == "3":
                search = field("Search assets (Enter: all)")
                client.show("assets", *(["--search", search] if search else []))
            elif action == "4":
                browse_findings(client)
            elif action == "5":
                manage_scope(client)
            elif action == "6":
                client.show("alerts")
            elif action == "7":
                open_dashboard(client)
            elif action == "8":
                client = select_project(client, preferences)
            else:
                client = settings_menu(client, preferences)
        except (Back, KeyboardInterrupt):
            tell("\nBack to Home. No implicit scan cancellation.")
        except EOFError:
            return 0
        except (UiError, OSError, subprocess.TimeoutExpired) as exc:
            tell(str(exc) if isinstance(exc, UiError) else "Action could not finish. Check local files, tools and connection settings.")
            tell("Back to Home. Queued actions are not automatically repeated.")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=PROFILES, default="development")
    parser.add_argument("--project", default="")
    parser.add_argument("--token-file")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--run", type=UUID)
    mode.add_argument("--dashboard", action="store_true")
    parser.add_argument("--hold", action="store_true")
    args = parser.parse_args(argv)
    # Terminal close and termination get the same cleanup path as Ctrl+C.
    def interrupted(signum, frame):
        raise KeyboardInterrupt()
    saved_handlers = {sig: signal.signal(sig, interrupted) for sig in (signal.SIGTERM, signal.SIGHUP)}
    code = 0
    try:
        if args.run or args.dashboard:
            client = Client(profile=args.profile, project=args.project, token_file=args.token_file)
            os.environ.update(client.env)  # settings/worker read credentials privately from .env
            if sys.stdout.isatty():
                sys.stdout.write("\033]0;WatchTower - " + safe(client.project) + "\007")
                sys.stdout.flush()
            if args.dashboard:
                if dashboard_state() == "ready":
                    tell("Dashboard is already running at http://127.0.0.1:8080.")
                else:
                    tell("Dashboard: http://127.0.0.1:8080. Ctrl+C stops this server; Home remains open.")
                    code = subprocess.call(client.command("serve"), cwd=client.root, env=client.env)
            else:
                code = scan_window(client, args.run)
        else:
            code = home()
    except (Back, KeyboardInterrupt, EOFError):
        tell("\nWatchTower stopped. Runs were not implicitly cancelled.")
    except (UiError, OSError, subprocess.TimeoutExpired) as exc:
        tell(str(exc) if isinstance(exc, UiError) else "Could not continue. Check configuration and local tools.")
        code = 1
    finally:
        if args.hold:
            try:
                input("\nSession ended. Press Enter to close this window. ")
            except (EOFError, KeyboardInterrupt):
                pass
        for sig, handler in saved_handlers.items():
            signal.signal(sig, handler)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
