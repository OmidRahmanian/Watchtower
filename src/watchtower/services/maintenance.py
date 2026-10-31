"""Explicit owner-controlled evidence retention and risk-acceptance expiry.

Metadata/history stay append-only. Purging affects only expired blob files with
no newer reference in the same project; shared content is protected by a
project advisory lock also held by evidence writers.
"""
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, text

from watchtower.domain.errors import NotFound
from watchtower.domain.models import FindingStatus
from watchtower.persistence.tables import evidence
from watchtower.persistence.repositories.audit import record_audit
from watchtower.security.auth import Permission
from watchtower.services.findings import FindingService, RepositoryFindingStore


def expired(row, settings, now=None):
    return row.created_at < (now or datetime.now(timezone.utc)) - timedelta(days=settings.pipeline.evidence_retention_days)


def evidence_lock(connection, project_id):
    connection.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
                       {"key": "watchtower:evidence:" + str(project_id)})


def maintain(database, project_id, actor, settings, blobs, *, apply=False, now=None):
    actor.require(Permission.MANAGE_PROJECT)
    now = now or datetime.now(timezone.utc)
    cutoff = now - timedelta(days=settings.pipeline.evidence_retention_days)
    result = {"apply": apply, "expired_risk_acceptances": [], "expired_blobs": [], "retention_days": settings.pipeline.evidence_retention_days}
    with database.project(project_id) as uow:
        evidence_lock(uow.connection, project_id)
        rows = list(uow.connection.execute(select(evidence.c.storage_uri, evidence.c.created_at).where(evidence.c.project_id == project_id)))
        live = {r.storage_uri for r in rows if r.created_at >= cutoff}
        for uri in sorted({r.storage_uri for r in rows if r.created_at < cutoff} - live):
            if not uri.startswith(f"fs:{project_id}/"):
                continue
            path = blobs._path(uri)
            if path.is_symlink() or not path.is_file():
                continue
            result["expired_blobs"].append(uri)
            if apply:
                path.unlink()
        # Risk expiry is a workflow change, never a technical resolution.
        from watchtower.api.queries import list_findings
        before = None
        while True:
            findings = list_findings(uow, limit=200, statuses=[FindingStatus.ACCEPTED_RISK], before=before)
            for finding in findings:
                value = finding.details.get("risk_expires_at")
                if value and datetime.fromisoformat(value) <= now:
                    result["expired_risk_acceptances"].append(str(finding.id))
                    if apply:
                        store = RepositoryFindingStore(uow, finding.scope_revision_id, asset_for=lambda _: finding.asset_id)
                        FindingService(store).expire_risk(finding.fingerprint, now)
            if len(findings) < 200:
                break
            before = (findings[-1].last_seen_at, findings[-1].id)
        if apply:
            record_audit(uow.connection, "maintenance.applied", "retention-and-risk", project_id=project_id,
                         actor=actor.principal.id, details={"expired_blobs": len(result["expired_blobs"]),
                                                            "expired_risks": len(result["expired_risk_acceptances"])})
    return result
