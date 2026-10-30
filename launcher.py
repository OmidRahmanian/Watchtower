#!/usr/bin/env python3
"""Interactive setup for WatchTower: the platform or legacy discovery. Uses only the standard library."""

import argparse
from datetime import datetime
import getpass
import ipaddress
import json
import os
from pathlib import Path
import re
import random
import shutil
import signal
import subprocess
import sys
import tempfile
from urllib.parse import urlsplit

from session import acquire_session, running_pid, stop_session

ROOT = Path(__file__).resolve().parent
JOBS = (
    "subfinder", "crt", "securitytrials", "static_resolve", "all_resolve",
    "dynamic_resolve", "httpx", "new_template", "new_sub_nuclei",
)
WEBHOOK_KEYS = (
    "NEW_SUB_WEBHOOK_URL", "NEW_RES_WEBHOOK_URL", "HTTP_CHANGE_WEBHOOK_URL",
    "NEW_HTTP_WEBHOOK_URL", "NUCLEI_WEBHOOK_URL", "OTHER_WEBHOOK_URL",
)
EYE = (
    "                                  ,,,,,,,%%%%%,,,,,,,,,,,",
    "                          ,,,,,,,,,,,,*%%%%%%%%%%%%%,,,,,,",
    "                  .,,,,,,%%%%%%%%%%%%%%*,,,,,,,%%%%%%%%%%%,****",
    "              ,,,,%%%%%%%%%%,,,,,,,,           ,,,,,%%%%%%%%%%#****",
    "         ..,.,&&&&&&%%,,,,,,         ,,,,,,,,,,,    ,,,,,%%%%%%%%%(***,",
    "      ....&&&&&&&&,,,,.              ,,,,|%%%%%%*|,,,     .,,,*%%%%%%%%%***,",
    "    ...&&&&&&&,,.,            .,,,      ,,|%%%%%%%%|,,        ,*,*%%%%%%%%%***",
    " ...&&&&&&&....               ,,|%,,.   ,,,%%%%%%%%%|,,          ,,,,%%%%%%%%(***",
    "..&&&&&&(...                 ,,|#%%%,,,,%%%%%%%%%%%%|,,             ,,,*%%%%%%%%**",
    " ...&&&&&&&....               ,,|%%%%%%%%%%%%%%%%%%%|,,          ,,,,%%%%%%%%***.",
    "   ....&&&&&&&....            ,,,|&&%%%%%%%%%%%%%%#|,,        ,,,,%%%%%%%%%,,*",
    "      ....&&&&&&&&....          ,,,|&&%%%%%%%%%%|,,,,     ,,,,#%%%%%%%%%,,,.",
    "          ....&&&&&&&&......       ,,,,,,,,,,,,,    ,,,,(%%%%%%%%%#,,,.",
    "              .....&&&&&&&&&........           ,,,,,%%%%%%%%%%%,,,,",
    "                   ........&&&&&&&&&&,..,,,,,,(%%%%%%%%%%%,,,,,",
    "                       ...............&&&&&&&&&%%%%%%,,,,,.",
    "                       .....(&&&&&&&&&&&&&&&,,,,,,,,.",
    "                              ............",
)
COMPACT_EYE = (
    "            .-''''''''-.",
    "       .-''     .--.    ''-.",
    "    .-'        (|@@@@|)       '-.",
    "  <            (|@@@@|)           >",
    "    '-.         '--'        .-'",
    "       '-..____________..-'",
)
TAGLINES = ("Always watching.", "See what changes.", "Know your surface.")


def banner(stream=None):
    """Render the startup eye without requiring terminal colour packages."""
    stream = sys.stdout if stream is None else stream
    width = min(shutil.get_terminal_size(fallback=(80, 24)).columns, 80)
    eye = EYE
    if width < max(len(line.replace("|", "")) for line in eye):
        eye = COMPACT_EYE
    if width < max(len(line.replace("|", "")) for line in eye):
        eye = ("<((|@|))>",)
    colour = stream.isatty() and "NO_COLOR" not in os.environ and os.environ.get("TERM") != "dumb"
    grey, red, white, reset = ("\033[90m", "\033[1;31m", "\033[1;37m", "\033[0m") if colour else ("", "", "", "")
    eye_width = max(len(line.replace("|", "")) for line in eye)
    padding = " " * max(0, (width - eye_width) // 2)
    print(file=stream)
    for line in eye:
        parts = line.split("|")
        rendered = "".join((red if i % 2 else grey) + part for i, part in enumerate(parts))
        print(padding + rendered + reset, file=stream)
    print(file=stream)
    print(white + "WATCHTOWER".center(width) + reset, file=stream)
    print(red + random.choice(TAGLINES).center(width) + reset, file=stream)
    print(grey + "Discover. Track. Monitor.".center(width) + reset, file=stream)
    print(red + ("-" * min(width, 76)).center(width) + reset, file=stream, flush=True)


def say(message):
    print(message, flush=True)


def ask(prompt, default=""):
    value = input(f"{prompt}{' [' + default + ']' if default else ''}: ").strip()
    return value or default


def choose(prompt, options, default="1"):
    say("\n" + prompt)
    for key, label in options.items():
        say(f"  {key}) {label}")
    while True:
        answer = ask("Choose", default)
        if answer in options:
            return answer
        say("Please choose one of the listed numbers.")


def yes_no(prompt, default=True):
    while True:
        answer = ask(prompt + (" (Y/n)" if default else " (y/N)"), "y" if default else "n").lower()
        if answer in ("y", "yes", "n", "no"):
            return answer in ("y", "yes")
        say("Please enter y or n.")


def domain_name(value):
    value = value.strip().rstrip(".").lower()
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError:
        raise ValueError("Enter a valid domain name.") from None
    if len(value) > 253 or "." not in value or any(
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part)
        for part in value.split(".")
    ):
        raise ValueError("Use a domain such as example.com, without https://, paths, ports, or wildcards.")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise ValueError("Enter a domain name rather than an IP address.")


def exclusions(value, domain):
    if value == "-":
        return []
    result = []
    for item in value.split(","):
        if not item.strip():
            continue
        item = domain_name(item)
        if not item.endswith("." + domain):
            raise ValueError(f"Exclusions must be exact subdomains of {domain}.")
        if item not in result:
            result.append(item)
    return result


def valid_webhook(value):
    return bool(re.fullmatch(
        r"https://(?:(?:canary|ptb)\.)?discord(?:app)?\.com/api/webhooks/[0-9]{17,20}/[A-Za-z0-9._-]{60,}/?",
        value,
    ))


def validated(prompt, validator, default=""):
    while True:
        try:
            return validator(ask(prompt, default))
        except ValueError as error:
            say(str(error))


def report_url(value):
    if value == "-":
        return ""
    if value:
        parsed = urlsplit(value)
        if parsed.scheme not in ("http", "https") or not parsed.netloc or any(c.isspace() for c in value):
            raise ValueError("Use a complete http:// or https:// report URL, or leave it blank.")
    return value


def read_config(root, name):
    try:
        data = json.loads((root / name).read_text())
    except (OSError, ValueError) as error:
        raise RuntimeError(f"Cannot read {name}: {error}") from None
    if not isinstance(data, dict):
        raise RuntimeError(f"{name} must contain a JSON object.")
    return data


def discovery_settings(original, interval, unit, notifications):
    if interval <= 0 or unit not in ("minutes", "hours", "days"):
        raise ValueError("Choose a positive interval in minutes, hours, or days.")
    settings = json.loads(json.dumps(original))
    for key in JOBS:
        settings.setdefault(key, {})["status"] = "disable"
    settings["subfinder"] = {"time": unit, "value": str(interval), "status": "enable"}
    settings.setdefault("sendmessage", {})["status"] = "enable" if notifications else "disable"
    return settings


def atomic_write(path, text, mode=None):
    fd, temporary = tempfile.mkstemp(prefix="." + path.name, dir=str(path.parent))
    try:
        with os.fdopen(fd, "w") as handle:
            handle.write(text)
        if mode is not None:
            os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def save_configuration(root, targets, settings, webhook=None):
    """Back up original bytes before replacing either configuration file."""
    directory = root / "files/config-backups"
    directory.mkdir(parents=True, exist_ok=True)
    backup = Path(tempfile.mkdtemp(prefix=datetime.now().strftime("%Y%m%d-%H%M%S-"), dir=str(directory)))
    names = ["targets.json", "setting.json"]
    if webhook:
        names.append(".env")
    for name in names:
        path = root / name
        if path.exists():
            shutil.copy2(path, backup / name)
            os.chmod(backup / name, 0o600)
    try:
        atomic_write(root / "targets.json", json.dumps(targets, indent=4) + "\n")
        atomic_write(root / "setting.json", json.dumps(settings, indent=4) + "\n")
        if webhook:
            path = root / ".env"
            existing = path.read_text() if path.exists() else ""
            # Preserve other credentials and override Discord categories together.
            content = existing.rstrip() + "\n\n# Discord notifications configured by WatchTower\n"
            content += "".join(f"export {key}='{webhook}'\n" for key in WEBHOOK_KEYS)
            atomic_write(path, content, mode=0o600)
    except OSError:
        for name in names:
            saved = backup / name
            if saved.exists():
                shutil.copy2(saved, root / name)
            elif (root / name).exists():
                (root / name).unlink()
        raise
    return backup


def python_executable(root):
    local = root / ".venv/bin/python"
    return str(local) if local.exists() else sys.executable


def runtime_environment(root, python):
    # Use the same shell expansion as run.sh, capturing credentials privately.
    script = 'set -a; if [ -f .env ]; then . ./.env; fi; exec "$1" -c "$2"'
    result = subprocess.run(
        ["/bin/sh", "-ec", script, "watchtower", python,
         "import os,json; print(json.dumps(dict(os.environ)))"],
        cwd=root, capture_output=True, text=True,
    )
    if result.returncode:
        raise RuntimeError("Could not load .env. Check that it contains valid shell KEY=value assignments.")
    try:
        return json.loads(result.stdout)
    except ValueError:
        raise RuntimeError("Could not load .env; it should contain variable assignments without printed output.") from None


def compose_command():
    for command in (["docker", "compose"], ["docker-compose"]):
        if shutil.which(command[0]):
            result = subprocess.run(command + ["version"], capture_output=True, text=True)
            if result.returncode == 0:
                return command
    raise RuntimeError("Install Docker with Compose, then start Docker Desktop or Colima and try again.")


def check_dependencies(python, env):
    if not shutil.which("subfinder", path=env.get("PATH")):
        raise RuntimeError("Subfinder is missing from PATH. Install Subfinder before starting discovery.")
    result = subprocess.run(
        [python, "-c", "import pymongo, requests, discord, schedule"],
        capture_output=True, text=True, env=env,
    )
    if result.returncode:
        raise RuntimeError(f"Python dependencies are missing. Run: {python} -m pip install -r requirements.txt")


def start_mongodb(root, python, env):
    command = compose_command()
    say("\nStarting MongoDB...")
    result = subprocess.run(command + ["up", "-d", "mongodb"], cwd=root)
    if result.returncode:
        raise RuntimeError("MongoDB could not start. Check the Docker output above and that Docker is running.")
    result = subprocess.run(
        [python, "-c", "from pymongo import MongoClient; "
         "MongoClient('mongodb://localhost:27017/', serverSelectionTimeoutMS=15000).admin.command('ping')"],
        capture_output=True, text=True, env=env,
    )
    if result.returncode:
        raise RuntimeError("MongoDB started but did not become ready at localhost:27017. Check its container logs.")
    say("MongoDB is ready.")


def run_monitor(root, python, env, lock):
    log_path = root / "files/watchtower.log"
    env = dict(env, WATCHTOWER_LOCK_FD=str(lock.fileno()))
    say("\nStarting WatchTower. Your first discovery runs after the selected interval.")
    say(f"Live log: {log_path}\nPress Ctrl+C to stop monitoring.\n")
    with log_path.open("a", buffering=1) as log:
        log.write(f"\n--- WatchTower session {datetime.now().isoformat(timespec='seconds')} ---\n")
        process = subprocess.Popen(
            [python, "-u", "watch.py"], cwd=root, env=env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            bufsize=1, start_new_session=True, pass_fds=(lock.fileno(),),
        )
        try:
            for line in process.stdout:
                print(line, end="", flush=True)
                log.write(line)
            return process.wait()
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
            process.stdout.close()
            pid_path = root / "files/watchtower.pid"
            if pid_path.exists() and pid_path.read_text().strip() == str(process.pid):
                pid_path.unlink()


def wizard(root=ROOT, configure_only=False):
    banner()
    say("\nDiscovery setup")
    say("Choose a target, configure discovery, and start from here.")
    original_targets = read_config(root, "targets.json")
    original_settings = read_config(root, "setting.json")
    python = python_executable(root)
    env = runtime_environment(root, python)
    selection = choose("Choose your target", {"1": "Enter a domain", "2": "Choose a saved target"})
    if selection == "2" and original_targets:
        domains = list(original_targets)
        picked = choose("Saved targets", {str(i + 1): domain for i, domain in enumerate(domains)})
        domain = domain_name(domains[int(picked) - 1])
    else:
        domain = validated("Target domain (example.com)", domain_name)
    previous = original_targets.get(domain, {})
    url = validated("Report URL (optional; - clears)", report_url, previous.get("report_url", ""))
    excluded = validated(
        "Excluded subdomains (comma-separated exact names; - clears)",
        lambda value: exclusions(value, domain), ", ".join(previous.get("out_of_scope", [])),
    )
    profile = choose("Discovery schedule", {
        "1": "Quick discovery test: every 1 minute",
        "2": "Recurring discovery: every 3 hours",
        "3": "Choose a custom interval",
    })
    interval, unit = (1, "minutes") if profile == "1" else (3, "hours")
    if profile == "3":
        def positive(value):
            if not value.isdecimal() or int(value) < 1:
                raise ValueError("Enter a whole number greater than zero.")
            return int(value)
        interval = validated("Run every", positive, "1")
        unit = {"1": "minutes", "2": "hours", "3": "days"}[
            choose("Time unit", {"1": "Minutes", "2": "Hours", "3": "Days"})
        ]
    notifications = yes_no("Send Discord notifications?")
    webhook = None
    if notifications and not all(valid_webhook(env.get(key, "")) for key in WEBHOOK_KEYS):
        say("Enter one Discord webhook for all notification categories; it will be saved privately in .env.")
        while True:
            webhook = getpass.getpass("Discord webhook URL (hidden): ").strip()
            if valid_webhook(webhook):
                break
            say("Enter a Discord webhook URL from your channel's Integrations settings.")
    settings = discovery_settings(original_settings, interval, unit, notifications)
    targets = {domain: {"report_url": url, "out_of_scope": excluded}}
    say(f"\nReady: {domain} | Subfinder every {interval} {unit} | Discord {'on' if notifications else 'off'}")
    say("Excluded: " + (", ".join(excluded) or "none"))
    say("This profile selects only this target and disables the other discovery jobs and Nuclei scans.")
    actions = {"1": "Save and start", "2": "Save setup only", "3": "Cancel"}
    action = "2" if configure_only else choose("What next?", actions)
    if action == "3":
        say("Cancelled. Configuration unchanged.")
        return 0
    if action == "1":
        check_dependencies(python, env)
    pid = running_pid(root)
    if pid:
        if not yes_no(f"WatchTower is running (PID {pid}). Stop that session and continue?", default=False):
            say("Configuration unchanged. The existing session is still running.")
            return 0
        stop_session(pid)
    with acquire_session(root) as lock:
        backup = save_configuration(root, targets, settings, webhook)
        say(f"\nConfiguration saved. Previous files: {backup}")
        if action == "2":
            say("Ready to start. Run python3 launcher.py and choose Save and start when you want to begin monitoring.")
            return 0
        env = runtime_environment(root, python)
        start_mongodb(root, python, env)
        return run_monitor(root, python, env, lock)


# -- WatchTower platform -----------------------------------------------------
#
# The platform (PostgreSQL, published scope, runs, findings) is driven through
# the `watchtower` CLI in a subprocess, so this launcher stays standard-library
# only and every action goes through the same authentication and permission
# checks as the API.

PROFILES = {
    "1": ("development", "Development: your own authorized targets"),
    "2": ("lab", "Lab: the isolated demonstration network (lab/README.md)"),
    "3": ("production", "Production"),
}
AUTHORIZATIONS = {
    "1": ("asset_owner", "I own or administer these assets"),
    "2": ("contract", "A signed testing contract or statement of work"),
    "3": ("internal_approval", "Internal approval from the asset owner"),
    "4": ("bug_bounty_program", "A bug bounty program that lists them in scope"),
    "5": ("vulnerability_disclosure_program", "A vulnerability disclosure program that permits testing"),
}
DEFAULT_TOKEN_FILE = Path("~/.config/watchtower/token")


def project_slug(value):
    value = value.strip().lower()
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,62}", value):
        raise ValueError("Use 2-63 lowercase letters, digits, or hyphens, such as acme-lab.")
    return value


def required_text(value):
    value = value.strip()
    if not value or any(ord(c) < 32 for c in value):
        raise ValueError("This is required.")
    return value


def platform_cli(root, python, env, *args):
    """Run one `watchtower` CLI command with live output; return its exit code."""
    return subprocess.run([python, "-m", "watchtower.cli", *args], cwd=root, env=env).returncode


def platform_ready(root, python, env):
    result = subprocess.run(
        [python, "-c", "import sys, watchtower.cli; sys.exit(sys.version_info < (3, 11))"],
        cwd=root, env=env, capture_output=True, text=True,
    )
    if result.returncode:
        raise RuntimeError(
            f"The WatchTower platform needs Python 3.11+ with the package installed. Run: {python} -m pip install -e '.[api]'"
        )
    if not env.get("WATCHTOWER__DATABASE__URL"):
        raise RuntimeError("Set WATCHTOWER__DATABASE__URL in .env (see docs/installation.md), then try again.")


def platform_wizard(root=ROOT):
    banner()
    say("\nPlatform setup")
    say("Choose a project, publish the scope you are authorized to test, and monitor it.")
    python = python_executable(root)
    env = runtime_environment(root, python)
    platform_ready(root, python, env)
    profile = PROFILES[choose("Settings profile", {key: label for key, (_, label) in PROFILES.items()})][0]
    slug = validated("Project (slug)", project_slug, env.get("WATCHTOWER_PROJECT", "acme-lab" if profile == "lab" else ""))
    token_file = Path(env.get("WATCHTOWER_TOKEN_FILE", str(DEFAULT_TOKEN_FILE))).expanduser()
    env = dict(env, WATCHTOWER_PROFILE=profile, WATCHTOWER_PROJECT=slug)
    cli = ["--token-file", str(token_file)]

    if not token_file.exists():
        say(f"\nNo API token at {token_file}.")
        if not yes_no(f"Create project {slug} (if needed) with you as owner, and save your token there?"):
            say("Cancelled. Nothing was changed.")
            return 0
        owner = validated("Your name (recorded as the project owner)", required_text)
        if platform_cli(root, python, env, "bootstrap", slug, "--owner", owner, "--save-token", str(token_file)):
            raise RuntimeError("Could not create the project. Check the database settings and the output above.")
    if platform_cli(root, python, env, *cli, "status"):
        raise RuntimeError("Could not open the project with this token.")

    target = choose("Target", {"1": "Authorize a domain", "2": "Keep the current scope"})
    if target == "1":
        domain = validated("Target domain (example.com)", domain_name, "acme-lab.test" if profile == "lab" else "")
        excluded = validated(
            "Excluded subdomains (comma-separated exact names; - for none)",
            lambda value: exclusions(value or "-", domain),
        )
        say("\nScanning needs written authorization for every target. Record where it comes from.")
        kind = AUTHORIZATIONS[choose("Authorization", {key: label for key, (_, label) in AUTHORIZATIONS.items()})][0]
        reference = validated("Reference (program URL, contract or ticket id)", required_text)
        granted_by = validated("Granted by (person or organization)", required_text)
        say(f"\nScope: {domain} and *.{domain}" + (f", excluding {', '.join(excluded)}" if excluded else ""))
        if not yes_no(f"Do you confirm that {granted_by} authorized you to test all of it?", default=False):
            say("Cancelled. The scope was not changed.")
            return 0
        command = [*cli, "scope", "publish", "--include", domain, "--include", f"*.{domain}",
                   "--authorization-kind", kind, "--reference", reference, "--granted-by", granted_by,
                   "--i-am-authorized"]
        for name in excluded:
            command += ["--exclude", name]
        if platform_cli(root, python, env, *command):
            raise RuntimeError("The scope was not published. See the message above.")

    action = choose("What next?", {
        "1": "Start a run and watch it",
        "2": "Watch for changes and alerts",
        "3": "Open the dashboard (http://127.0.0.1:8080)",
        "4": "Exit",
    })
    if action == "4":
        return 0
    if action == "3":
        say("Sign in with the token in " + str(token_file) + ". Press Ctrl+C to stop the server.")
        return platform_cli(root, python, env, *cli, "serve")
    work = yes_no("Run the scan jobs in this terminal (no separate worker)?", default=profile != "production")
    extra = ["--work"] if work else []
    if action == "1":
        return platform_cli(root, python, env, *cli, "run", "start", "--reason", "started from launcher",
                            "--watch", *extra)
    return platform_cli(root, python, env, *cli, "watch", *extra)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Configure a WatchTower target and start monitoring interactively.")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--platform", action="store_true", help="Use the WatchTower platform (PostgreSQL, authorized scope)")
    mode.add_argument("--legacy", action="store_true", help="Use legacy discovery (MongoDB and Subfinder)")
    parser.add_argument("--configure-only", action="store_true", help="Save the legacy setup without starting services")
    parser.add_argument("--banner", action="store_true", help="Preview the WatchTower banner without changing configuration")
    args = parser.parse_args(argv)
    try:
        if args.banner:
            banner()
            return 0
        if args.platform:
            return platform_wizard()
        if args.legacy or args.configure_only:
            return wizard(configure_only=args.configure_only)
        if choose("How do you want to run WatchTower?", {
            "1": "Platform: authorized scope, runs, findings and dashboard (PostgreSQL)",
            "2": "Legacy discovery: Subfinder with MongoDB",
        }) == "1":
            return platform_wizard()
        return wizard()
    except (KeyboardInterrupt, EOFError):
        say("\nWatchTower stopped.")
        return 0
    except (OSError, RuntimeError, ValueError) as error:
        say(f"\nCould not continue: {error}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
