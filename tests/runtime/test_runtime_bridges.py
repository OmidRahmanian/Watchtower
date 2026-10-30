"""Legacy entry points bridged to the platform runtime: watch.py --platform, session.run_platform, cron.py."""
import importlib.util
import os
import shutil
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from runtime_support import publish

ROOT = Path(__file__).resolve().parents[2]


def load(name):
    spec = importlib.util.spec_from_file_location(f"bridge_{name}", ROOT / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_platform_mode_is_opt_in():
    session = load("session")
    assert session.platform_requested(["--platform"], {})
    assert session.platform_requested([], {"WATCHTOWER_RUNTIME": "platform"})
    assert not session.platform_requested([], {})
    assert not session.platform_requested([], {"WATCHTOWER_RUNTIME": "legacy"})


def test_watch_hands_off_before_any_legacy_import(tmp_path):
    for name in ("watch.py", "session.py"):
        shutil.copy2(ROOT / name, tmp_path / name)
    # Shadow the legacy dependencies: importing either one means the hand-off came too late.
    for name in ("pymongo", "discord", "schedule"):
        (tmp_path / f"{name}.py").write_text(f"raise SystemExit('legacy import of {name}')\n")
    env = dict(os.environ, WATCHTOWER_PROFILE="no-such-profile", WATCHTOWER_PROFILE_DIR=str(tmp_path))
    result = subprocess.run([sys.executable, "watch.py", "--platform"], cwd=tmp_path, env=env,
                            capture_output=True, text=True, timeout=60)
    assert "legacy import" not in result.stdout + result.stderr
    assert "settings profile not found" in result.stderr  # it reached the platform runtime
    assert not (tmp_path / "files/watchtower.pid").exists()  # and cleaned up its session


@pytest.mark.postgres
def test_run_platform_holds_the_session_and_schedules_runs(tmp_path, monkeypatch, database, project_id,
                                                          authorization, migrated_url):
    publish(database, project_id, authorization)
    session = load("session")
    served = threading.Event()
    stop = threading.Event()

    def fake_serve(database_, scope, settings, *, stop):
        served.set()
        assert (tmp_path / "files/watchtower.pid").read_text().strip() == str(os.getpid())
        with pytest.raises(RuntimeError, match="already running"):
            session.acquire_session(tmp_path)  # launcher.py sees a running session
        stop.wait(10)

    monkeypatch.setattr("watchtower.workers.runtime.serve", fake_serve)
    monkeypatch.setattr("watchtower.workers.egress.install", lambda settings: None)  # keep this process unguarded
    monkeypatch.setenv("WATCHTOWER_PROFILE", "test")
    monkeypatch.setenv("WATCHTOWER_PROFILE_DIR", str(ROOT / "config/profiles"))
    monkeypatch.setenv("WATCHTOWER__DATABASE__URL", migrated_url.render_as_string(hide_password=False))
    threading.Timer(1.5, stop.set).start()
    assert session.run_platform(tmp_path, schedule_every="6h", stop=stop) == 0
    assert served.is_set()
    assert not (tmp_path / "files/watchtower.pid").exists()
    session.acquire_session(tmp_path).close()  # released
    with database.project(project_id) as uow:
        from watchtower.persistence.tables import jobs

        rows = uow.connection.execute(jobs.select().where(jobs.c.project_id == project_id)).all()
    assert [row.kind for row in rows] == ["monitor.discovery"]
    assert rows[0].payload["run"]["reason"].startswith("scheduled ")


def test_cron_schedules_through_the_platform(monkeypatch):
    cron = load("cron")
    calls = []
    monkeypatch.setattr("watchtower.workers.cli.main", lambda argv: calls.append(argv) or 0)
    assert cron.main(["--once", "--every", "30m"]) == 0
    assert cron.main(["--once", "--profile", "lab"]) == 0
    assert calls == [["schedule", "--every", "30m"], ["--profile", "lab", "schedule", "--every", "6h"]]


def test_worker_cli_intervals():
    from watchtower.workers.cli import interval

    assert interval("30m").total_seconds() == 1800 and interval("6h").total_seconds() == 21600
    with pytest.raises(Exception):
        interval("soon")
