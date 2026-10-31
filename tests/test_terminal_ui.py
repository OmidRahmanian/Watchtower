"""Terminal UX and process boundaries: never launch terminals or outbound scans."""
import os
import shlex
import subprocess
from unittest.mock import Mock
from uuid import uuid4

import pytest

import launcher
import terminal_ui as ui


@pytest.fixture
def client(tmp_path):
    return ui.Client(tmp_path, project="acme", token_file=tmp_path / "owner.token", env={})


def run_detail(status="running"):
    return {"run": {"run_id": str(uuid4()), "status": status, "created_at": "2026-10-30T10:00:00+00:00",
                    "finished_at": "2026-10-30T10:02:00+00:00" if status in ui.FINISHED else None},
            "jobs": [{"kind": "monitor.discovery", "status": "running"}], "snapshots": [], "checks_not_run": {}}


def test_preferences_store_paths_only_and_recover_from_corruption(tmp_path):
    prefs = ui.Preferences(tmp_path)
    token = tmp_path / "original.token"
    token.write_text("wt_private_secret")
    prefs.save("development", "acme", token)
    loaded = ui.Preferences(tmp_path)
    assert loaded.data["project"] == "acme"
    assert loaded.data["tokens"]["development:acme"] == str(token)
    assert "wt_private_secret" not in prefs.path.read_text()
    assert prefs.path.stat().st_mode & 0o777 == 0o600
    prefs.path.write_text('{"project": [], "profile": {}, "token_file": 1, "tokens": false}')
    assert ui.Preferences(tmp_path).data == {"tokens": {}}
    prefs.path.write_text("broken")
    assert ui.Preferences(tmp_path).data == {"tokens": {}}


def test_project_selection_is_numbered_and_preserves_token(client, tmp_path, monkeypatch):
    token = client.token_file
    token.write_text("existing-secret")
    prefs = ui.Preferences(tmp_path)
    monkeypatch.setattr(ui.Client, "json", lambda self, *args: [{"slug": "acme", "name": "Acme", "role": "owner", "archived": False}])
    monkeypatch.setattr("builtins.input", lambda prompt: "1")
    result = ui.select_project(client, prefs)
    assert result.project == "acme" and result.token_file == token
    assert token.read_text() == "existing-secret"
    assert prefs.data["project"] == "acme"


def test_new_project_gets_a_unique_token_path(client, tmp_path, monkeypatch):
    client.token_file.write_text("keep-me")
    prefs = ui.Preferences(tmp_path)
    monkeypatch.setattr(ui.Client, "json", lambda self, *args: [])
    show = Mock()
    monkeypatch.setattr(ui.Client, "show", show)
    answers = iter(["c", "new-project", "Ada", "y"])
    monkeypatch.setattr("builtins.input", lambda prompt: next(answers))
    result = ui.select_project(client, prefs)
    assert result.token_file != client.token_file
    assert result.token_file.parent == prefs.directory / "tokens"
    assert client.token_file.read_text() == "keep-me"
    assert show.call_args.args[:2] == ("bootstrap", "new-project")


def test_remembered_project_skips_repeated_setup(client, tmp_path, monkeypatch, capsys):
    ui.Preferences(tmp_path).save("development", "acme", client.token_file)
    def data(self, *args):
        return {"scope": None} if args == ("status",) else []
    monkeypatch.setattr(ui.Client, "json", data)
    monkeypatch.setattr(ui.launcher, "runtime_environment", lambda *a: {})
    select = Mock()
    monkeypatch.setattr(ui, "select_project", select)
    answers = iter(["3", "", "6", "0"])
    monkeypatch.setattr("builtins.input", lambda prompt: next(answers))
    show = Mock()
    monkeypatch.setattr(ui.Client, "show", show)
    assert ui.home(tmp_path) == 0
    select.assert_not_called()
    assert show.call_args_list[0].args == ("assets",)
    assert show.call_args_list[1].args == ("alerts",)
    assert capsys.readouterr().out.count("WATCHTOWER | Platform") == 3


def test_missing_remembered_project_returns_to_selection(client, tmp_path, monkeypatch, capsys):
    ui.Preferences(tmp_path).save("development", "deleted", client.token_file)
    monkeypatch.setattr(ui.Client, "json", Mock(side_effect=ui.UiError("not found")))
    monkeypatch.setattr(ui.launcher, "runtime_environment", lambda *a: {})
    select = Mock(side_effect=ui.Back)
    monkeypatch.setattr(ui, "select_project", select)
    assert ui.home(tmp_path) == 0
    select.assert_called_once()
    assert "remembered project is unavailable" in capsys.readouterr().out


def test_start_queues_once_and_passes_existing_id_to_window(client, monkeypatch):
    run = {"run_id": str(uuid4())}
    client.json = Mock(side_effect=[[], {"scope": {"rules": [{"effect": "include", "pattern": "acme.example"}]}}, run])
    monkeypatch.setattr(launcher, "yes_no", lambda *a, **kw: True)
    launch = Mock()
    monkeypatch.setattr(ui, "launch_scan", launch)
    ui.start_scan(client)
    assert len([c for c in client.json.call_args_list if c.args[:2] == ("run", "start")]) == 1
    launch.assert_called_once_with(client, run["run_id"])


def test_existing_active_run_prevents_duplicate_queue(client, monkeypatch, capsys):
    client.json = Mock(return_value=[{"run_id": str(uuid4()), "status": "queued"}])
    launch = Mock()
    monkeypatch.setattr(ui, "launch_scan", launch)
    ui.start_scan(client)
    assert client.json.call_count == 1
    launch.assert_not_called()
    assert "already active" in capsys.readouterr().out


def test_start_requires_scope_and_confirmation(client, monkeypatch):
    launch = Mock()
    monkeypatch.setattr(ui, "launch_scan", launch)
    client.json = Mock(side_effect=[[], {"scope": None}])
    ui.start_scan(client)
    launch.assert_not_called()


def test_start_lock_blocks_a_second_home(client):
    with ui.session_lock(client, "start"):
        with pytest.raises(ui.UiError, match="already performing"):
            with ui.session_lock(client, "start"):
                pytest.fail("second launch entered")


def test_macos_command_is_quoted_and_contains_no_secrets(tmp_path, monkeypatch):
    root = tmp_path / "space ' quote $(touch NEVER) `echo nope`"
    root.mkdir()
    client = ui.Client(root, profile="lab", project="acme", token_file=root / "owner token", env={"SECRET": "never-in-arguments"})
    monkeypatch.setattr(ui.sys, "platform", "darwin")
    invoke = Mock(return_value=Mock(returncode=0))
    monkeypatch.setattr(ui.subprocess, "run", invoke)
    run_id = str(uuid4())
    ui.open_window(client, run=run_id)
    argv = invoke.call_args.args[0]
    assert argv[0] == "osascript"
    assert "NEVER" not in argv[2]  # fixed AppleScript, data only via argv
    assert "never-in-arguments" not in " ".join(argv)
    parsed = shlex.split(argv[-1])
    assert parsed[:4] == ["cd", str(root), "&&", "exec"]
    command = parsed[4:]
    assert command == ui.window_arguments(client, run=run_id)
    assert "--run" in command and "start" not in command
    assert command[command.index("--profile") + 1] == "lab"
    assert command[command.index("--project") + 1] == "acme"
    assert command[command.index("--run") + 1] == run_id


def test_linux_launch_uses_argument_array(client, monkeypatch):
    monkeypatch.setattr(ui.sys, "platform", "linux")
    monkeypatch.setattr(ui.shutil, "which", lambda name: name if name == "xterm" else None)
    process = Mock()
    process.wait.side_effect = subprocess.TimeoutExpired("xterm", 0.5)
    invoke = Mock(return_value=process)
    monkeypatch.setattr(ui.subprocess, "Popen", invoke)
    ui.open_window(client, run=str(uuid4()))
    assert invoke.call_args.args[0][:4] == ["xterm", "-T", "WatchTower - acme", "-e"]
    assert "shell" not in invoke.call_args.kwargs


@pytest.mark.parametrize("action", ["0", "2"])
def test_launch_failure_retains_same_run_and_offers_fallback(client, monkeypatch, action):
    run_id = str(uuid4())
    client.json = Mock()
    monkeypatch.setattr(ui, "open_window", Mock(side_effect=ui.UiError("blocked")))
    monkeypatch.setattr("builtins.input", lambda prompt: action)
    fallback = Mock()
    monkeypatch.setattr(ui, "process_here", fallback)
    ui.launch_scan(client, run_id)
    client.json.assert_not_called()  # no second queue
    if action == "2":
        fallback.assert_called_once_with(client, run_id)
    else:
        fallback.assert_not_called()


def test_retry_reuses_the_run(client, monkeypatch):
    run_id = str(uuid4())
    launch = Mock(side_effect=[ui.UiError("blocked"), None])
    monkeypatch.setattr(ui, "open_window", launch)
    monkeypatch.setattr("builtins.input", lambda prompt: "1")
    ui.launch_scan(client, run_id)
    assert launch.call_count == 2
    assert all(c.kwargs["run"] == run_id for c in launch.call_args_list)


def test_progress_renders_real_phases_counts_errors_and_pending_checks(capsys):
    detail = run_detail("partial")
    detail["checks_not_run"] = {"exposed-env-file": "pending approval"}
    detail["snapshots"] = [{"phase": "discovery", "target": "acme.example", "status": "succeeded", "comparison": "baseline", "stats": {"hosts": 7}}]
    ui.render_progress(detail, "acme\x1b[2J")
    out = capsys.readouterr().out
    assert "PARTIAL" in out and "NOT RUN" in out and '"hosts": 7' in out
    assert "2m 0s" in out and "not a complete successful scan" in " ".join(out.split())
    assert "\x1b" not in out and "\\x1b" in out and "%" not in out
    detail = run_detail("failed")
    detail["run"]["last_error"] = "discovery tool missing"
    ui.render_progress(detail, "acme")
    assert "discovery tool missing" in capsys.readouterr().out


def test_watcher_shows_updates_before_completion_without_queueing(client, monkeypatch, capsys):
    running, done = run_detail(), run_detail("succeeded")
    client.json = Mock(side_effect=[running, running, done])
    monkeypatch.setattr(ui.time, "sleep", lambda *a: None)
    assert ui.watch_run(client, running["run"]["run_id"]) == 0
    out = capsys.readouterr().out
    assert "RUNNING" in out and "SUCCEEDED" in out and "discovery" in out
    assert all(c.args[:2] == ("run", "show") for c in client.json.call_args_list)


def test_interrupt_closes_processor_without_cancelling_run(client, monkeypatch, capsys):
    detail = run_detail()
    client.json = Mock(side_effect=[detail, KeyboardInterrupt])
    processor = Mock(error=None)
    monkeypatch.setattr(ui, "LocalProcessor", Mock(return_value=processor))
    assert ui.watch_run(client, detail["run"]["run_id"], work=True) == 0
    processor.close.assert_called_once()
    assert "not cancelled" in capsys.readouterr().out
    assert all(c.args[:2] == ("run", "show") for c in client.json.call_args_list)


def test_cancel_is_explicit_and_uses_cli(client, monkeypatch):
    run_id = str(uuid4())
    monkeypatch.setattr(ui, "select_run", lambda c: {"run_id": run_id})
    answers = iter(["4", "y", "stop test run", "0"])
    monkeypatch.setattr("builtins.input", lambda prompt: next(answers))
    client.show = Mock()
    ui.progress_menu(client)
    client.show.assert_called_once_with("run", "cancel", run_id, "--reason", "stop test run")


def test_scope_decline_never_publishes_and_wildcard_is_opt_in(client, monkeypatch):
    answers = iter(["2", "acme.example", "n", "-", "1", "SOW-1", "Acme", "n", "0"])
    monkeypatch.setattr("builtins.input", lambda prompt: next(answers))
    client.show = Mock()
    ui.manage_scope(client)
    client.show.assert_not_called()


def test_scope_publish_validates_and_requires_explicit_authorization(client, monkeypatch):
    answers = iter(["2", "https://bad.example/x", "acme.example", "y", "old.acme.example", "2", "SOW-1", "Acme", "y", "0"])
    monkeypatch.setattr("builtins.input", lambda prompt: next(answers))
    client.show = Mock()
    ui.manage_scope(client)
    args = client.show.call_args.args
    assert "*.acme.example" in args and "--i-am-authorized" in args
    assert "old.acme.example" in args and "contract" in args


def test_dashboard_reuses_existing_server(client, monkeypatch):
    monkeypatch.setattr(ui, "dashboard_state", lambda: "ready")
    launch, browse = Mock(), Mock()
    monkeypatch.setattr(ui, "open_window", launch)
    monkeypatch.setattr(ui.webbrowser, "open", browse)
    ui.open_dashboard(client)
    launch.assert_not_called()
    browse.assert_called_once_with("http://127.0.0.1:8080")


def test_client_filters_secret_bearing_driver_errors(client, monkeypatch):
    monkeypatch.setattr(ui.subprocess, "run", Mock(return_value=Mock(returncode=1, stderr="watchtower: postgresql://user:password@host/db", stdout="")))
    with pytest.raises(ui.UiError) as err:
        client.json("status")
    assert "password" not in str(err.value)


def test_narrow_plain_terminal_output_escapes_control_characters(monkeypatch, capsys):
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.setattr(ui.shutil, "get_terminal_size", lambda *a: os.terminal_size((25, 20)))
    ui.tell("untrusted\x1b[2J" + "x" * 100)
    out = capsys.readouterr().out
    assert "\x1b" not in out
    assert all(len(line) <= 25 for line in out.splitlines())


def test_local_processor_uses_existing_worker_and_shuts_it_down(client, monkeypatch):
    # No outbound work: mock runtime objects at the public boundary.
    database, worker, notifier = Mock(), Mock(), Mock()
    monkeypatch.setattr("watchtower.config.load_settings", lambda profile: Mock())
    monkeypatch.setattr("watchtower.persistence.database.Database.from_settings", lambda settings: database)
    monkeypatch.setattr("watchtower.workers.egress.install", lambda settings: None)
    monkeypatch.setattr("watchtower.workers.runtime.Worker", lambda *a, **kw: worker)
    monkeypatch.setattr("watchtower.workers.runtime.Notifier", lambda *a, **kw: notifier)
    processor = ui.LocalProcessor(client)
    notifier.deliver_once.side_effect = processor.stop_event.set
    worker.run_once.return_value = True
    processor.start()
    processor.thread.join(timeout=2)
    processor.close()
    worker.run_once.assert_called_once()
    notifier.deliver_once.assert_called_once()
    database.dispose.assert_called_once()


def test_local_processor_requests_graceful_shutdown(client, monkeypatch):
    # Exercise the stop path with an active fake thread without touching a DB.
    processor = object.__new__(ui.LocalProcessor)
    import threading
    processor.stop_event = threading.Event()
    processor.worker, processor.database, processor.thread = Mock(), Mock(), Mock()
    processor.thread.is_alive.side_effect = [True, False, False]
    processor.close()
    assert processor.stop_event.is_set()
    processor.worker.shutdown.assert_called_once()
    processor.database.dispose.assert_called_once()


def test_finished_run_does_not_start_an_unnecessary_worker(client, monkeypatch):
    detail = run_detail("failed")
    client.json = Mock(return_value=detail)
    processor = Mock()
    monkeypatch.setattr(ui, "LocalProcessor", processor)
    # Completed failures still return a failing exit status.
    assert ui.watch_run(client, detail["run"]["run_id"], work=True) == 4
    processor.assert_not_called()


def test_unsupported_terminal_never_queues_a_run(client, monkeypatch):
    monkeypatch.setattr(ui.sys, "platform", "unsupported")
    client.json = Mock()
    with pytest.raises(ui.UiError, match="No supported"):
        ui.open_window(client, run=str(uuid4()))
    client.json.assert_not_called()


def test_scope_defaults_do_not_expand_to_wildcards(client, monkeypatch):
    answers = iter(["2", "acme.example", "", "-", "1", "SOW-1", "Acme", "y", "0"])
    monkeypatch.setattr("builtins.input", lambda prompt: next(answers))
    client.show = Mock()
    ui.manage_scope(client)
    args = client.show.call_args.args
    assert "acme.example" in args and "*.acme.example" not in args
