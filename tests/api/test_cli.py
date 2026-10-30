"""The ``watchtower`` CLI, run in-process against the real database."""

from __future__ import annotations

import io
import os
import stat
from datetime import timedelta
from uuid import uuid4

import pytest

from api_support import START, FakeRuns, seed_finding
from test_findings import EXPOSED, GONE, Scanner
from watchtower import cli
from watchtower.adapters.checks.base import HttpResponse
from watchtower.security.auth import ProjectRole
from watchtower.services.findings import FindingService, RepositoryFindingStore

pytestmark = pytest.mark.postgres

PUBLISH = ["scope", "publish", "--include", "acme.example", "--include", "*.acme.example",
           "--authorization-kind", "asset_owner", "--reference", "https://acme.example/authorization",
           "--granted-by", "Acme Security Lead"]


@pytest.fixture
def run_cli(database, monkeypatch, capsys):
    runs = FakeRuns()

    def run(*argv, token=None, project=None):
        if token is not None:
            monkeypatch.setenv("WATCHTOWER_TOKEN", token)
        out = io.StringIO()
        prefix = ["--profile", "test"] + (["--project", str(project)] if project else [])
        code = cli.main([*prefix, *argv], out=out, database=database, runs=runs)
        return code, out.getvalue(), capsys.readouterr().err

    run.runs = runs
    monkeypatch.delenv("WATCHTOWER_TOKEN", raising=False)
    monkeypatch.delenv("WATCHTOWER_PROJECT", raising=False)
    monkeypatch.setenv("WATCHTOWER_PROFILE_DIR", str(cli.Path(__file__).resolve().parents[2] / "config/profiles"))
    return run


def test_bootstrap_saves_a_private_token_and_status_needs_scope(run_cli, tmp_path):
    slug = f"acme-{uuid4().hex[:6]}"
    token_file = tmp_path / "config" / "token"
    code, out, _ = run_cli("bootstrap", slug, "--owner", "Ada Owner", "--save-token", str(token_file))
    assert code == 0 and "saved to" in out and "wt_" not in out
    assert stat.S_IMODE(token_file.stat().st_mode) == 0o600
    token = token_file.read_text().strip()

    code, out, _ = run_cli("--token-file", str(token_file), "status", project=slug)
    assert code == 0 and "you are owner" in out and "none published" in out

    code, out, err = run_cli(*PUBLISH, token=token, project=slug)
    assert code == 1 and "--i-am-authorized" in err
    code, out, _ = run_cli(*PUBLISH, "--i-am-authorized", token=token, project=slug)
    assert code == 0 and "Published scope revision 1" in out
    code, out, _ = run_cli("scope", "check", "www.acme.example", token=token, project=slug)
    assert code == 0 and "allowed" in out
    code, out, _ = run_cli("scope", "check", "acme.example.evil.test", token=token, project=slug)
    assert code == 3 and "not_in_scope" in out


def test_world_readable_token_file_is_refused(run_cli, tmp_path, project_id):
    token_file = tmp_path / "token"
    token_file.write_text("wt_x")
    token_file.chmod(0o644)
    code, _, err = run_cli("--token-file", str(token_file), "status", project=project_id)
    assert code == 1 and "chmod 600" in err


def test_roles_are_enforced(run_cli, member, project_id):
    viewer = member(project_id, ProjectRole.VIEWER)
    code, _, err = run_cli(*PUBLISH, "--i-am-authorized", token=viewer.token, project=project_id)
    assert code == 2 and "permission denied" in err
    code, _, err = run_cli("run", "start", token=viewer.token, project=project_id)
    assert code == 2
    code, _, err = run_cli("status", token=viewer.token, project=uuid4())
    assert code == 1 and "no access" in err


def test_findings_show_failed_retests_apart_from_verified_fixes(run_cli, database, member, project_id):
    scanner = Scanner()
    viewer = member(project_id, ProjectRole.VIEWER)
    failing = seed_finding(database, project_id, scanner, EXPOSED, START, host="a.acme.example")
    fixed = seed_finding(database, project_id, scanner, EXPOSED, START, host="b.acme.example")
    for row, reply, host in ((failing, ConnectionError("refused"), "a.acme.example"), (fixed, GONE, "b.acme.example")):
        with database.project(project_id) as uow:
            service = FindingService(RepositoryFindingStore(uow), canonical_id=scanner.ruleset.canonical_id)
            service.request_retest(row.fingerprint, "analyst", START + timedelta(hours=1))
            service.apply_retest(row.fingerprint, scanner.run(reply, START + timedelta(hours=2), host=host))

    code, out, _ = run_cli("findings", "--all", token=viewer.token, project=project_id)
    assert code == 0
    lines = {line.split()[0]: line for line in out.splitlines()[1:]}
    assert "RETEST FAILED - not verified" in lines[str(failing.id)[:8]]
    assert "FIXED (verified by retest)" in lines[str(fixed.id)[:8]]
    code, out, _ = run_cli("finding", "show", str(failing.id)[:8], token=viewer.token, project=project_id)
    assert "status open" in out and "retest_failed" in out


def test_captured_content_cannot_drive_the_terminal(run_cli, database, member, project_id):
    viewer = member(project_id, ProjectRole.VIEWER)
    from watchtower.domain.models import AssetKind

    with database.project(project_id) as uow:
        uow.assets.upsert(AssetKind.HOSTNAME, "evil.acme.example",
                          attributes={"last_http": {"status_code": 200, "title": "pwn\x1b]0;owned\x07\x1b[2J‮"}})
    code, out, _ = run_cli("assets", token=viewer.token, project=project_id)
    assert code == 0 and "\x1b" not in out and "\x07" not in out and "‮" not in out
    assert "\\x1b]0;owned\\x07" in out


def test_evidence_prints_redacted_and_saves_privately(run_cli, database, member, project_id, tmp_path, monkeypatch):
    from watchtower.services.evidence_store import FilesystemBlobStore

    monkeypatch.setenv("WATCHTOWER_EVIDENCE_DIR", str(tmp_path / "evidence"))
    blobs = FilesystemBlobStore(tmp_path / "evidence")
    env = b"APP_ENV=prod\nDB_PASSWORD=hunter2-prod\n"
    row = seed_finding(database, project_id, Scanner(), HttpResponse(200, (), env), START, blobs=blobs,
                       check="exposed-env-file")
    with database.project(project_id) as uow:
        [evidence] = uow.evidence.list_for_finding(row.id)
    viewer = member(project_id, ProjectRole.VIEWER)
    code, out, _ = run_cli("evidence", str(evidence.id), token=viewer.token, project=project_id)
    assert code == 0 and "DB_PASSWORD=[REDACTED]" in out and "hunter2" not in out
    target = tmp_path / "saved.json"
    code, out, _ = run_cli("evidence", str(evidence.id), "--output", str(target), token=viewer.token,
                           project=project_id)
    assert code == 0 and stat.S_IMODE(os.stat(target).st_mode) == 0o600
    code, _, err = run_cli("evidence", str(evidence.id), "--output", str(target), token=viewer.token,
                           project=project_id)
    assert code == 1  # never overwrites


def test_run_list_marks_failures(run_cli, member, project_id):
    viewer = member(project_id, ProjectRole.VIEWER)
    run_cli.runs.add(project_id, "succeeded")
    run_cli.runs.add(project_id, "failed", last_error="http: connection refused")
    code, out, _ = run_cli("run", "list", token=viewer.token, project=project_id)
    assert code == 0
    rows = out.splitlines()[1:]
    assert "FAILED" in rows[0] and "connection refused" in rows[0]
    assert "SUCCEEDED" in rows[1]
