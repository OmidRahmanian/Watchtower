"""Findings and evidence against the real PostgreSQL unit of work.

Skipped unless ``WATCHTOWER_TEST_DATABASE_URL`` is set; see tests/foundation/conftest.py.
Every step runs in its own transaction, so state survives only through the shared rows.
"""

from datetime import timedelta
import json

import pytest

from foundation.conftest import admin_url, database, fresh_database, migrated_url, project_id  # noqa: F401
from test_findings import BUSY, EXPOSED, GONE, START, Scanner
from watchtower.adapters.checks.base import HttpResponse
from watchtower.domain.models import FindingStatus, Severity
from watchtower.services.evidence import MEDIA_TYPE, REDACTED, to_new_evidence
from watchtower.services.evidence_store import FilesystemBlobStore
from watchtower.services.findings import FindingService, RepositoryFindingStore

pytestmark = pytest.mark.postgres

ENV_FILE = b"APP_ENV=production\nDB_PASSWORD=hunter2-prod\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG\n"


@pytest.fixture
def scanner():
    return Scanner()


@pytest.fixture
def step(database, project_id, scanner):  # noqa: F811
    """Run ``action(service, uow)`` in a fresh project transaction."""

    def run(action):
        with database.project(project_id) as uow:
            service = FindingService(RepositoryFindingStore(uow), canonical_id=scanner.ruleset.canonical_id)
            return action(service, uow)

    return run


def at(hours):
    return START + timedelta(hours=hours)


def test_finding_is_created_once_across_scans_and_ip_changes(step, scanner):
    key = step(lambda service, uow: service.ingest(scanner.run(EXPOSED, START)).fingerprint)
    step(lambda service, uow: service.ingest(scanner.run(EXPOSED, at(1), ip="198.51.100.7")))
    step(lambda service, uow: service.ingest(scanner.run(EXPOSED, at(2), ip="203.0.113.99")))

    def check(service, uow):
        rows = uow.findings.list()
        assert [row.fingerprint for row in rows] == [key]
        assert (rows[0].status, rows[0].severity, rows[0].source) == (FindingStatus.OPEN, Severity.HIGH,
                                                                      "exposed-git-config")
        finding = service.get(key)
        assert finding.occurrences == 3
        assert finding.target.resolved_ip == "203.0.113.99"
        assert uow.assets.get(rows[0].asset_id).value == "shop.example.com"

    step(check)


def test_failed_and_inconclusive_results_do_not_resolve(step, scanner):
    key = step(lambda service, uow: service.ingest(scanner.run(EXPOSED, START)).fingerprint)
    step(lambda service, uow: service.request_retest(key, "analyst", at(1)))
    replies = [BUSY, ConnectionError("refused"), HttpResponse(200, (), b"x", True)]
    for hours, reply in enumerate(replies, start=2):
        result = scanner.run(reply, at(hours))
        assert not result.outcome.conclusive
        step(lambda service, uow, result=result: service.apply_retest(key, result))
    step(lambda service, uow: service.ingest(scanner.run(GONE, at(9))))

    def check(service, uow):
        row = uow.findings.get_by_fingerprint(key)
        finding = service.get(key)
        assert row.status == finding.status == FindingStatus.OPEN
        assert finding.resolution_evidence is None
        assert finding.retest_requested_at == at(1)
        assert finding.detection.state == "absent"

    step(check)


def test_relevant_negative_retest_resolves_and_recurrence_reopens(step, scanner):
    key = step(lambda service, uow: service.ingest(scanner.run(EXPOSED, START)).fingerprint)
    step(lambda service, uow: service.transition(key, FindingStatus.TRIAGED, "analyst", now=at(1)))
    step(lambda service, uow: service.request_retest(key, "analyst", at(2)))
    step(lambda service, uow: service.apply_retest(key, scanner.run(GONE, at(3))))

    def resolved(service, uow):
        row = uow.findings.get_by_fingerprint(key)
        assert row.status == FindingStatus.RESOLVED
        assert service.get(key).retest_requested_at is None

    step(resolved)
    step(lambda service, uow: service.ingest(scanner.run(EXPOSED, at(4), ip="198.51.100.7")))

    def reopened(service, uow):
        rows = uow.findings.list()
        assert [row.fingerprint for row in rows] == [key]
        assert rows[0].status == FindingStatus.OPEN
        finding = service.get(key)
        assert (finding.occurrences, finding.recurrences) == (2, 1)
        assert finding.resolution_evidence is None
        assert [event["event"] for event in finding.history] == [
            "created", "status_changed", "retest_requested", "resolved", "reopened"]

    step(reopened)


def test_evidence_is_stored_as_a_blob_and_row_and_reads_back_redacted(step, scanner, tmp_path):
    blobs = FilesystemBlobStore(tmp_path / "blobs")
    result = scanner.run(HttpResponse(200, (("Set-Cookie", "session=abc123"),), ENV_FILE), START,
                         check="exposed-env-file")

    def store(service, uow):
        finding = service.ingest(result)
        row = uow.findings.get_by_fingerprint(finding.fingerprint)
        new = to_new_evidence(service.evidence.get(finding.first_evidence), blobs, uow.project_id,
                              finding_id=row.id)
        return row.id, uow.evidence.add(new).id

    finding_id, evidence_id = step(store)

    def check(service, uow):
        rows = uow.evidence.list_for_finding(finding_id)
        assert [row.id for row in rows] == [evidence_id]
        row = rows[0]
        assert row.media_type == MEDIA_TYPE
        raw = blobs.get(row.storage_uri)
        assert (len(raw), row.sha256) == (row.size_bytes, row.storage_uri.rsplit("/", 1)[1])
        for secret in (b"hunter2-prod", b"wJalrXUtnFEMI", b"abc123"):
            assert secret not in raw
        evidence = json.loads(raw)
        assert evidence["check_id"] == "exposed-env-file"
        assert f"DB_PASSWORD={REDACTED}" in evidence["response"]["body_excerpt"]
        assert ["Set-Cookie", REDACTED] in evidence["response"]["headers"]

    step(check)
