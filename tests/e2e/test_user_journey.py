"""The complete user journey through the CLI, API, workers and notifier.

authorize a target -> establish a baseline -> introduce a change -> receive an
alert -> inspect the finding -> fix it -> retest, with a failed scan and a
failed retest along the way that must stay visibly distinct from the verified
fix. Only the outbound network is simulated (tests/runtime/runtime_support.py);
everything else is the real stack on PostgreSQL.
"""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

pytest.importorskip("watchtower.services.jobs", reason="needs the monitoring runtime (agent/04)")

from runtime_support import PUBLIC_IP, Lab, RecordingTransport, settings as runtime_settings  # noqa: E402
from watchtower import cli  # noqa: E402
from watchtower.api import create_app  # noqa: E402
from watchtower.config.settings import ScopeSettings  # noqa: E402
from watchtower.services.evidence_store import FilesystemBlobStore  # noqa: E402
from watchtower.services.jobs import RunService  # noqa: E402
from watchtower.services.scope import ScopeService  # noqa: E402
from watchtower.workers.runtime import Notifier, Worker  # noqa: E402

pytestmark = [pytest.mark.postgres, pytest.mark.e2e]

AUTHORIZATION = {"kind": "asset_owner", "reference": "https://example.com/security/scanning-approval",
                 "granted_by": "Example Security Lead"}


class Journey:
    """One project driven the way a user would: CLI for setup and monitoring, API for everything else."""

    def __init__(self, database, tmp_path: Path, monkeypatch, *, approved: bool = True) -> None:
        self.database = database
        self.tmp_path = tmp_path
        self.lab = Lab(approved=approved)
        self.transport = RecordingTransport()
        self.settings = runtime_settings(confirm_changes={"dns": 1, "http": 1},
                                         evidence_root=str(tmp_path / "evidence"))
        self.scope = ScopeService(database, ScopeSettings(policy_cache_seconds=0))
        self.blobs = FilesystemBlobStore(tmp_path / "evidence")
        self.runs = RunService(database, self.scope, settings=self.settings)
        self.ruleset = self.lab.adapters().ruleset
        app = create_app(database, settings=self.settings, scope=self.scope, runs=self.runs, blobs=self.blobs,
                         rules=lambda: self.ruleset)
        self.client = TestClient(app)
        monkeypatch.setattr(cli, "default_evidence_root", lambda settings: tmp_path / "evidence")
        monkeypatch.setenv("WATCHTOWER_PROFILE_DIR", str(Path(__file__).resolve().parents[2] / "config/profiles"))
        monkeypatch.delenv("WATCHTOWER_TOKEN", raising=False)
        self.monkeypatch = monkeypatch
        self.fetch = self.lab.fetch

    # -- drivers ------------------------------------------------------------

    def work(self) -> int:
        """What `--work` does: run every due job, then deliver the outbox."""
        adapters = self.lab.adapters(blobs=self.blobs, fetch=self.fetch)
        worker = Worker(self.database, self.scope, settings=self.settings, adapters=adapters,
                        retry_backoff=lambda attempt: 0, heartbeat_seconds=0.2)
        notifier = Notifier(self.database, self.settings, transport=self.transport, retry_backoff=lambda attempt: 0)
        return worker.run_until_idle() + notifier.run_until_idle()

    def cli(self, *argv: str, token: str | None = None, project: str | None = None) -> tuple[int, str]:
        if token:
            self.monkeypatch.setenv("WATCHTOWER_TOKEN", token)
        out = io.StringIO()
        prefix = ["--profile", "test", *(["--project", project] if project else [])]
        code = cli.main([*prefix, *argv], out=out, database=self.database, runs=self.runs, work=self.work)
        return code, out.getvalue()

    def api(self, method: str, path: str, token: str, **kwargs):
        return self.client.request(method, f"/api/v1/projects/{self.project_id}{path}",
                                   headers={"Authorization": f"Bearer {token}"}, **kwargs)

    def bootstrap(self) -> str:
        token_file = self.tmp_path / "owner-token"
        code, out = self.cli("bootstrap", "example-co", "--owner", "Ada Owner", "--save-token", str(token_file))
        assert code == 0, out
        token = token_file.read_text().strip()
        [project] = self.client.get("/api/v1/projects", headers={"Authorization": f"Bearer {token}"}).json()
        self.project_id = project["id"]
        return token

    def member(self, role: str) -> str:
        token_file = self.tmp_path / f"{role}-token"
        code, out = self.cli("member", "add", f"{role.title()} User", "--role", role, "--save-token", str(token_file),
                             project="example-co")
        assert code == 0, out
        return token_file.read_text().strip()

    def change_types(self, alert: dict) -> set[str]:
        return {change["type"] for change in alert["payload"].get("changes", [])}


@pytest.fixture
def journey(database, tmp_path, monkeypatch):
    return Journey(database, tmp_path, monkeypatch)


def test_authorize_baseline_change_alert_inspect_fix_retest(journey):
    j = journey
    owner = j.bootstrap()
    operator = j.member("operator")
    viewer = j.member("viewer")

    # 1. Authorize. Nothing can run before a scope is published, and only owners publish one.
    assert j.api("POST", "/runs", operator, json={}).json()["error"] == "scope_violation"
    scope = {"includes": ["example.com", "*.example.com"], "authorization": AUTHORIZATION, "attest_authorized": True}
    assert j.api("POST", "/scope", operator, json=scope).status_code == 403
    assert j.api("POST", "/scope", owner, json=scope).status_code == 201
    code, out = j.cli("scope", "check", "shop.example.com", token=viewer, project="example-co")
    assert code == 0 and "allowed" in out

    # 2. Baseline: the first run records the current state and never alerts.
    assert j.api("POST", "/runs", viewer, json={}).status_code == 403
    baseline = j.api("POST", "/runs", operator, json={"reason": "baseline"}).json()
    j.work()
    detail = j.api("GET", f"/runs/{baseline['run_id']}", viewer).json()
    assert detail["run"]["status"] == "succeeded", detail
    assert {p["comparison"] for p in detail["run"]["phases"]} == {"baseline"}
    assert j.api("GET", "/alerts", viewer).json()["items"] == [] and j.transport.requests == []
    hosts = {a["value"] for a in j.api("GET", "/assets", viewer, params={"kind": "hostname"}).json()["items"]}
    assert hosts == {"www.example.com", "shop.example.com"}

    # 3. Introduce a change: a new host appears, a page changes, and shop starts serving /.git/config.
    j.lab.seeds.append("api.example.com")
    j.lab.dns["api.example.com"] = {"A": [PUBLIC_IP]}
    j.lab.http[("https", "api.example.com")] = (200, "API")
    j.lab.http[("https", "www.example.com")] = (200, "Example v2")
    j.lab.exposed.add("shop.example.com")

    # 4. Receive the alert, by following the run from the terminal monitoring loop.
    code, out = j.cli("run", "start", "--reason", "after deploy", "--watch", "--work", "--interval", "0",
                      token=operator, project="example-co")
    assert code == 0, out
    assert "ALERT monitor.changes" in out
    assert "finding.opened" in out and "asset.discovered api.example.com" in out
    [alert] = j.api("GET", "/alerts", viewer).json()["items"]
    assert {"asset.discovered", "http.changed", "finding.opened"} <= j.change_types(alert)
    [delivered] = j.transport.delivered.values()
    assert {c["type"] for c in delivered["changes"]} == j.change_types(alert)

    # 5. Inspect the finding and its evidence.
    [finding] = j.api("GET", "/findings", viewer).json()["items"]
    assert (finding["check_id"], finding["target"], finding["status"], finding["remediation"]) == (
        "exposed-git-config", "https://shop.example.com", "open", "not_retested")
    detail = j.api("GET", f"/findings/{finding['id']}", viewer).json()
    [evidence] = detail["evidence"]
    content = j.api("GET", f"/evidence/{evidence['id']}", viewer).json()["content"]
    assert content["request"]["url"] == "https://shop.example.com/.git/config"
    assert "repositoryformatversion" in content["response"]["body_excerpt"]
    download = j.client.get(evidence["download_path"], headers={"Authorization": f"Bearer {viewer}"})
    assert download.headers["content-disposition"].startswith("attachment;")
    assert download.headers["x-content-type-options"] == "nosniff"
    assert json.loads(download.content)["check_id"] == "exposed-git-config"
    code, out = j.cli("finding", "show", finding["id"][:8], token=viewer, project="example-co")
    assert code == 0 and "exposed-git-config" in out and str(evidence["id"]) in out

    # 6a. A scan that fails is a failed run with its own alert, never a clean result.
    j.lab.explode["www.example.com"] = 1000
    failed_scan = j.api("POST", "/runs", operator, json={"reason": "probe outage"}).json()
    j.work()
    j.lab.explode.clear()
    failed_detail = j.api("GET", f"/runs/{failed_scan['run_id']}", viewer).json()
    assert failed_detail["run"]["status"] == "failed" and failed_detail["run"]["last_error"]
    assert "monitor.run_failed" in {a["event_type"] for a in j.api("GET", "/alerts", viewer).json()["items"]}
    assert j.api("GET", f"/findings/{finding['id']}", viewer).json()["status"] == "open"

    # 6b. A retest that cannot reach the host proves nothing: the finding stays open.
    def refused(method, url, ip):
        raise ConnectionRefusedError("connection refused")

    j.fetch = refused
    failed_retest = j.api("POST", f"/findings/{finding['id']}/retest", operator, json={}).json()
    j.work()
    j.fetch = j.lab.fetch
    failed_retest_detail = j.api("GET", f"/runs/{failed_retest['run_id']}", viewer).json()
    assert failed_retest_detail["retest_outcome"] == "failed"
    assert failed_retest_detail["run"]["status"] != "succeeded"
    after_failure = j.api("GET", f"/findings/{finding['id']}", viewer).json()
    assert (after_failure["status"], after_failure["remediation"]) == ("open", "retest_failed")

    # 7. Fix it, and 8. retest from the terminal until the result is in.
    j.lab.exposed.discard("shop.example.com")
    code, out = j.cli("finding", "retest", finding["id"], "--reason", "removed .git from web root", "--watch",
                      "--work", "--interval", "0", token=operator, project="example-co")
    assert code == 0, out
    assert "FIXED (verified by retest)" in out
    fixed = j.api("GET", f"/findings/{finding['id']}", viewer).json()
    assert (fixed["status"], fixed["remediation"]) == ("resolved", "verified_fixed")
    assert fixed["remediation_event"]["event"] == "resolved"
    runs = j.api("GET", "/runs", viewer).json()["items"]
    fix_run = runs[0]
    assert fix_run["kind"] == "retest" and fix_run["status"] == "succeeded"
    assert j.api("GET", f"/runs/{fix_run['run_id']}", viewer).json()["retest_outcome"] == "not_detected"
    resolved_alerts = [a for a in j.api("GET", "/alerts", viewer).json()["items"]
                       if "finding.resolved" in j.change_types(a)]
    assert len(resolved_alerts) == 1

    # The history keeps the failed scan and failed retest apart from the verified fix.
    statuses = {run["run_id"]: run["status"] for run in runs}
    assert statuses[failed_scan["run_id"]] == "failed"
    assert statuses[fix_run["run_id"]] == "succeeded"
    events = [e["event"] for e in fixed["history"]]
    assert events.index("retest_failed") < events.index("resolved")
    code, out = j.cli("run", "list", token=viewer, project="example-co")
    lines = {line.split()[0]: line for line in out.splitlines()[1:]}
    assert "FAILED" in lines[failed_scan["run_id"][:8]]
    assert "SUCCEEDED" in lines[fix_run["run_id"][:8]]


def test_shipped_rules_pending_approval_never_run_or_resolve(database, tmp_path, monkeypatch):
    """With the manifest as shipped, checks are reported as not run and nothing can open or resolve."""
    j = Journey(database, tmp_path, monkeypatch, approved=False)
    owner = j.bootstrap()
    scope = {"includes": ["example.com", "*.example.com"], "authorization": AUTHORIZATION, "attest_authorized": True}
    assert j.api("POST", "/scope", owner, json=scope).status_code == 201
    j.lab.exposed.add("shop.example.com")

    code, out = j.cli("run", "start", "--watch", "--work", "--interval", "0", token=owner, project="example-co")
    assert code == 0, out
    [run] = j.api("GET", "/runs", owner).json()["items"]
    assert run["status"] == "partial"  # incomplete coverage, never "succeeded"
    detail = j.api("GET", f"/runs/{run['run_id']}", owner).json()
    assert set(detail["checks_not_run"]) >= {"exposed-git-config", "exposed-env-file"}
    assert all("approv" in reason for reason in detail["checks_not_run"].values())
    assert j.lab.fetches == []  # no check request was sent
    assert j.api("GET", "/findings", owner, params={"status": ["open", "resolved"]}).json()["items"] == []
    overview = j.api("GET", "/overview", owner).json()
    assert not any(rule["approved"] for rule in overview["rules"])
    code, out = j.cli("run", "show", run["run_id"], token=owner, project="example-co")
    assert "PARTIAL" in out and "did not run" in out
