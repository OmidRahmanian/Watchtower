"""Acceptance: cancellation stops subprocess groups and follow-on work."""
import os
import subprocess
import sys
import textwrap
import threading
import time

import pytest

from runtime_support import PUBLIC_IP, Runs
from watchtower.domain.errors import RunCancelled
from watchtower.domain.models import JobStatus, NewJob
from watchtower.workers.process import run_in_group

FAKE_TOOL = textwrap.dedent("""\
    #!{python}
    # Stands in for subfinder: forks a long-lived grandchild, records both pids, then hangs.
    import os, subprocess, sys, time
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(600)"])
    with open({pids!r}, "w") as f:
        f.write(f"{{os.getpid()}} {{child.pid}}")
    time.sleep(600)
""")


def alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    state = subprocess.run(["ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True).stdout.strip()
    return bool(state) and not state.startswith("Z")


def wait_dead(*pids: int, timeout: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not any(alive(pid) for pid in pids):
            return True
        time.sleep(0.05)
    return False


def fake_tool(tmp_path):
    pids = tmp_path / "pids"
    tool = tmp_path / "fake-subfinder"
    tool.write_text(FAKE_TOOL.format(python=sys.executable, pids=str(pids)))
    tool.chmod(0o755)
    return tool, pids


def wait_for(path, timeout=20.0):
    deadline = time.monotonic() + timeout
    while not (path.exists() and path.read_text().strip()):
        assert time.monotonic() < deadline, f"{path} never appeared"
        time.sleep(0.05)
    return [int(pid) for pid in path.read_text().split()]


def kinds(detail):
    return [(job.kind, job.status) for job in detail.jobs]


@pytest.mark.postgres
def test_cancelling_a_run_kills_the_tool_process_group_and_stops_follow_on_jobs(
        database, project_id, authorization, scope_service, lab, tmp_path):
    from runtime_support import RecordingTransport, publish

    publish(database, project_id, authorization)
    tool, pids = fake_tool(tmp_path)
    runs = Runs(database, project_id, scope_service, lab, RecordingTransport(),
                discovery_sources=["subfinder"], subfinder_binary=str(tool), seed_file="")
    summary = runs.service.start_run(project_id, actor=runs.actor, reason="cancel test")
    worker = runs.worker(adapters=lab.adapters(process_runner=None))  # the real process-group runner
    thread = threading.Thread(target=worker.run_once)
    thread.start()
    tool_pid, grandchild_pid = wait_for(pids)
    assert alive(tool_pid) and alive(grandchild_pid)

    assert runs.service.cancel_run(project_id, summary.run_id, actor=runs.actor, reason="operator stop") == 1
    thread.join(timeout=20)
    assert not thread.is_alive()

    assert wait_dead(tool_pid, grandchild_pid), "the tool or its child survived cancellation"
    detail = runs.service.get_run(project_id, summary.run_id, actor=runs.actor)
    assert kinds(detail) == [("monitor.discovery", JobStatus.CANCELLED)]  # no DNS, HTTP, checks or finalize job
    assert detail.jobs[0].cancel_reason == "operator stop"
    assert detail.snapshots == ()  # output of a killed tool is not recorded as a completed phase
    assert detail.summary.status == "cancelled"
    assert runs.worker().run_until_idle() == 0
    with database.project(project_id) as uow, pytest.raises(RunCancelled):
        uow.jobs.enqueue(NewJob("monitor.dns", detail.summary.scope_revision_id, run_id=summary.run_id))


@pytest.mark.postgres
def test_cancelling_mid_phase_stops_between_items_and_still_reports_accepted_changes(runs, lab, project_id):
    runs.run()
    lab.seeds += ["api.example.com", "zz.example.com"]
    lab.dns["api.example.com"] = {"A": [PUBLIC_IP]}
    lab.block_dns_on = "shop.example.com"
    lab.lookups.clear()
    summary = runs.service.start_run(project_id, actor=runs.actor)
    worker = runs.worker()
    assert worker.run_once()  # discovery: api and zz are new, and accepted
    thread = threading.Thread(target=worker.run_once)  # DNS: blocks on shop.example.com
    thread.start()
    assert lab.dns_blocked.wait(10)
    runs.service.cancel_run(project_id, summary.run_id, actor=runs.actor, reason="enough")
    time.sleep(0.5)  # a heartbeat carries the cancel request to the job's token
    lab.release_dns.set()
    thread.join(timeout=20)

    detail = runs.service.get_run(project_id, summary.run_id, actor=runs.actor)
    assert kinds(detail) == [("monitor.discovery", JobStatus.SUCCEEDED), ("monitor.dns", JobStatus.CANCELLED)]
    # Hosts are looked up in order (api, shop, www, zz): the job stopped right after shop.
    assert "api.example.com" in lab.lookups and "shop.example.com" in lab.lookups
    assert "www.example.com" not in lab.lookups and "zz.example.com" not in lab.lookups
    assert detail.summary.status == "cancelled"
    assert runs.worker().run_until_idle() == 0
    runs.notifier().run_until_idle()
    # Discovery accepted the new hosts into the baseline, so they are reported now or never.
    [alert] = runs.alerts()
    assert sorted(c["key"] for c in alert["payload"]["changes"]) == ["api.example.com", "zz.example.com"]
    runs.run()
    assert len(runs.alerts()) == 1


@pytest.mark.postgres
def test_cancelling_a_queued_run_starts_nothing(runs, project_id):
    summary = runs.service.start_run(project_id, actor=runs.actor)
    assert runs.service.cancel_run(project_id, summary.run_id, actor=runs.actor, reason="changed my mind") == 1
    assert runs.service.cancel_run(project_id, summary.run_id, actor=runs.actor, reason="again") == 0
    assert runs.worker().run_until_idle() == 0
    detail = runs.service.get_run(project_id, summary.run_id, actor=runs.actor)
    assert kinds(detail) == [("monitor.discovery", JobStatus.CANCELLED)]
    assert detail.summary.status == "cancelled"
    assert runs.lab.probes == [] and runs.lab.lookups == []


def test_a_timeout_kills_the_whole_process_group(tmp_path):
    tool, pids = fake_tool(tmp_path)
    started = time.monotonic()
    result = run_in_group([str(tool)], timeout=1.5, grace=0.5)
    assert result.timed_out and time.monotonic() - started < 10
    tool_pid, grandchild_pid = [int(pid) for pid in pids.read_text().split()]
    assert wait_dead(tool_pid, grandchild_pid)


def test_a_cancel_token_kills_the_whole_process_group(tmp_path):
    from watchtower.services.jobs import CancelToken

    tool, pids = fake_tool(tmp_path)
    token = CancelToken()
    threading.Timer(1.0, token.cancel, args=("stop",)).start()
    result = run_in_group([str(tool)], timeout=60, cancel=token, grace=0.5)
    assert result.error == "cancelled" and not result.timed_out
    assert wait_dead(*[int(pid) for pid in pids.read_text().split()])


def test_bounded_output_still_applies(tmp_path):
    result = run_in_group([sys.executable, "-c", "import sys; sys.stdout.write('x' * 100000)"], max_stdout=1000)
    assert result.truncated and len(result.stdout) == 1000
    assert run_in_group([str(tmp_path / "missing")]).error.startswith("could not start")
