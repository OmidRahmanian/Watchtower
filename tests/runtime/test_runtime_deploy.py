"""Worker egress controls, container isolation and the Celery wiring."""
import socket
from pathlib import Path

import pytest
import yaml

from watchtower.config.settings import Settings
from watchtower.security.destinations import DestinationPolicy
from watchtower.workers import celery_app, egress

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def guard():
    """The process-wide guard, enforcing only for the test: audit hooks cannot be removed,
    and later tests reach PostgreSQL on loopback."""
    installed = egress.install(Settings())
    previous = (installed.allowed, installed.destinations)
    installed.active = True
    try:
        yield installed
    finally:
        installed.active = False
        installed.allowed, installed.destinations = previous


def connect(host, port, family=socket.AF_INET):
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.2)
        sock.connect((host, port))


def test_the_guard_refuses_metadata_loopback_and_private_destinations(guard):
    guard.allowed = set()
    for host in ("169.254.169.254", "127.0.0.1", "10.1.2.3"):
        with pytest.raises(egress.EgressRefused):
            connect(host, 80)
    with pytest.raises(egress.EgressRefused):
        connect("::1", 80, socket.AF_INET6)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp, pytest.raises(egress.EgressRefused):
        udp.sendto(b"x", ("169.254.169.254", 53))
    assert "169.254.169.254:80" in guard.refused


def test_infrastructure_endpoints_are_allowed_exactly(guard):
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen()
        port = server.getsockname()[1]
        guard.allowed = {("127.0.0.1", port)}
        connect("127.0.0.1", port)  # the database or broker on loopback
        with pytest.raises(egress.EgressRefused):
            connect("127.0.0.1", port + 1 if port < 65535 else port - 1)


def test_private_networks_follow_the_scope_setting(guard):
    guard.allowed = set()
    guard.destinations = DestinationPolicy.build(allow_private_networks=True)
    assert guard.check("10.1.2.3", 80) is None
    assert guard.check("169.254.169.254", 80)  # metadata stays prohibited
    assert guard.check("93.184.216.34", 443) is None


def test_infrastructure_comes_from_settings(tmp_path):
    resolv = tmp_path / "resolv.conf"
    resolv.write_text("# docker\nnameserver 127.0.0.11\noptions ndots:0\n")
    assert egress.system_nameservers(str(resolv)) == ["127.0.0.11"]
    settings = Settings.model_validate({
        "database": {"url": "postgresql+psycopg://u:p@127.0.0.1:6543/db"},
        "runtime": {"broker_url": "amqp://u:p@127.0.0.1:5673//"},
        "pipeline": {"dns_nameservers": ["9.9.9.9"]},
    })
    assert set(egress.infrastructure(settings)) >= {("127.0.0.1", 6543), ("127.0.0.1", 5673), ("9.9.9.9", 53)}


def compose():
    base = yaml.safe_load((ROOT / "deploy/compose.yaml").read_text())
    workers = yaml.safe_load((ROOT / "deploy/compose.workers.yaml").read_text())
    return base, workers


def test_no_container_gets_the_docker_socket_or_host_privileges():
    base, workers = compose()
    for name, service in {**base["services"], **workers["services"]}.items():
        volumes = [str(v) for v in service.get("volumes", [])]
        assert not any("docker.sock" in v or v.startswith("/var/run") for v in volumes), name
        assert not service.get("privileged"), name
        assert service.get("network_mode") != "host", name
        assert service.get("pid") != "host", name
    runtime = workers["x-runtime"]
    assert runtime["read_only"] and runtime["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in runtime["security_opt"] and runtime["user"] != "0"


def test_the_backend_is_internal_and_only_workers_reach_targets():
    _, workers = compose()
    assert workers["networks"]["backend"]["internal"] is True
    services = workers["services"]
    assert services["postgres"]["networks"] == ["backend"] and services["rabbitmq"]["networks"] == ["backend"]
    assert services["egress-guard"]["networks"] == ["backend", "egress"]
    assert services["egress-guard"]["cap_add"] == ["NET_ADMIN"]
    assert services["worker"]["network_mode"] == "service:egress-guard"
    assert services["notifier"]["network_mode"] == "service:egress-guard"
    assert "egress" not in services["beat"]["networks"]
    assert "watchtower.notify" in services["notifier"]["command"]


def test_celery_acknowledges_late_and_routes_delivery_to_the_notifier():
    conf = celery_app.app.conf
    assert conf.task_acks_late and conf.task_reject_on_worker_lost and conf.worker_prefetch_multiplier == 1
    assert conf.task_routes[celery_app.TASK_DELIVER]["queue"] == celery_app.NOTIFY_QUEUE
    assert {celery_app.TASK_WORK, celery_app.TASK_DELIVER, celery_app.TASK_RECOVER, celery_app.TASK_SCHEDULE} <= set(
        celery_app.app.tasks)
    assert {entry["task"] for entry in conf.beat_schedule.values()} == {
        celery_app.TASK_WORK, celery_app.TASK_DELIVER, celery_app.TASK_RECOVER, celery_app.TASK_SCHEDULE}


def test_celery_tasks_drive_the_database_runtime(monkeypatch):
    class Fake:
        def __init__(self):
            self.calls = []

        def run_until_idle(self, *args):
            self.calls.append(args)
            return 2

        def recover(self):
            return 1

    worker, notifier, sent = Fake(), Fake(), []
    monkeypatch.setattr(celery_app, "runtime", lambda: {"worker": worker, "notifier": notifier})
    monkeypatch.setattr(celery_app.app, "send_task", lambda name, *a, **k: sent.append(name))
    assert celery_app.work.run(max_jobs=5) == 2 and worker.calls == [(5,)]
    assert sent == [celery_app.TASK_WORK, celery_app.TASK_DELIVER]  # more work may have been enqueued
    assert celery_app.deliver.run() == 2 and celery_app.recover.run() == 1
