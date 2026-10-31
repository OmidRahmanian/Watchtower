from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from api_support import START, seed_finding
from test_findings import EXPOSED, Scanner
from watchtower.config.settings import Settings
from watchtower.domain.models import FindingStatus
from watchtower.persistence.tables import evidence
from watchtower.services.findings import FindingService, RepositoryFindingStore
from watchtower.services.maintenance import maintain

pytestmark = pytest.mark.postgres


def test_retention_preview_apply_and_new_shared_reference_are_safe(database, project_id, owner, blobs, client):
    now = datetime.now(timezone.utc)
    settings = Settings.model_validate({"pipeline": {"evidence_retention_days": 30}})
    old = blobs.put(project_id, b'expired', media_type="application/json")
    shared = blobs.put(project_id, b'shared', media_type="application/json")
    with database.system() as system:
        actor = system.auth.project_context(owner.token, project_id)
    with database.project(project_id) as uow:
        for blob, created in [(old, now - timedelta(days=60)), (shared, now - timedelta(days=60)), (shared, now)]:
            uow.connection.execute(evidence.insert().values(id=uuid4(), project_id=project_id, media_type="application/json",
                sha256=blob.sha256, size_bytes=blob.size_bytes, storage_uri=blob.uri, created_at=created, description="fixture"))
    preview = maintain(database, project_id, actor, settings, blobs, now=now)
    assert preview["expired_blobs"] == [old.uri]
    assert blobs.get(old.uri) == b'expired'
    maintain(database, project_id, actor, settings, blobs, now=now, apply=True)
    assert not blobs._path(old.uri).exists()
    assert blobs.get(shared.uri) == b'shared'


def test_expired_risk_returns_to_triage_and_never_resolves(database, project_id, owner, blobs):
    finding = seed_finding(database, project_id, Scanner(), EXPOSED, START)
    now = datetime.now(timezone.utc)
    with database.system() as system:
        actor = system.auth.project_context(owner.token, project_id)
    with database.project(project_id) as uow:
        store = RepositoryFindingStore(uow, asset_for=lambda _: finding.asset_id)
        FindingService(store).transition(finding.fingerprint, FindingStatus.ACCEPTED_RISK, "owner", "temporary exception",
                                          now=now, risk_expires_at=now + timedelta(days=1))
    result = maintain(database, project_id, actor, Settings(), blobs, now=now + timedelta(days=2), apply=True)
    assert result["expired_risk_acceptances"] == [str(finding.id)]
    with database.project(project_id) as uow:
        current = uow.findings.get(finding.id)
        assert current.status == FindingStatus.TRIAGED
        assert current.details["detection"]["state"] == "present"
        assert current.details["history"][-1]["event"] == "risk_acceptance_expired"
