"""Investigation, ownership, exports and intelligence on project-isolated records."""
from __future__ import annotations

from typing import Annotated, Any, Literal
from uuid import UUID

from fastapi import APIRouter, Query, Response
from fastapi.responses import JSONResponse
from pydantic import Field
from sqlalchemy import select, tuple_

from watchtower.api import queries, schemas
from watchtower.api.app import Context, Services, Limit, _actor, _finding_detail
from watchtower.api.pagination import decode_cursor, encode_cursor, cursor_time, cursor_uuid, DEFAULT_LIMIT
from watchtower.domain.errors import NotFound
from watchtower.domain.models import AssetKind
from watchtower.persistence.repositories.audit import record_audit
from watchtower.persistence.repositories.records import _observation
from watchtower.persistence.tables import observations, phase_snapshots, audit_events
from watchtower.security.auth import Permission
from watchtower.services.findings import FindingService, RepositoryFindingStore
from watchtower.services.intelligence import IntelligenceService

router = APIRouter(prefix="/api/v1/projects/{project_id}")


class AssetMetadataIn(schemas._In):
    owner: str | None = Field(default=None, max_length=200)
    tags: list[Annotated[str, Field(min_length=1, max_length=64)]] | None = Field(default=None, max_length=50)
    importance: Literal["low", "normal", "high", "critical"] | None = None
    ownership_state: Literal["verified", "strong", "uncertain", "rejected"] | None = None


class FindingMetadataIn(schemas._In):
    owner: str | None = Field(default=None, max_length=200)
    remediation_notes: str | None = Field(default=None, max_length=4000)
    mitigation_notes: str | None = Field(default=None, max_length=4000)
    priority: Literal["P1", "P2", "P3", "P4", "clear"] | None = None
    reason: str = Field(default="", max_length=4000)


class AcknowledgeIn(schemas._In):
    reason: str = Field(min_length=1, max_length=2000)


@router.patch("/assets/{asset_id}", response_model=schemas.AssetOut)
def update_asset(project_id: UUID, asset_id: UUID, body: AssetMetadataIn, ctx: Context, svc: Services):
    ctx.require(Permission.OPERATE)
    with svc.database.project(project_id) as uow:
        asset = uow.assets.get(asset_id)
        if asset is None:
            raise NotFound("asset not found")
        patch = body.model_dump(exclude_none=True)
        if "tags" in patch:
            patch["tags"] = sorted(set(patch["tags"]))
        changed, _ = uow.assets.upsert(asset.kind, asset.value, seen_at=asset.last_seen_at, attributes=patch,
                                     scope_revision_id=asset.scope_revision_id)
        record_audit(uow.connection, "asset.annotated", str(asset_id), project_id=project_id,
                     actor=ctx.principal.id, details=patch)
        return schemas.asset_out(changed)


@router.patch("/findings/{finding_id}", response_model=schemas.FindingDetailOut)
def update_finding(project_id: UUID, finding_id: UUID, body: FindingMetadataIn, ctx: Context, svc: Services):
    ctx.require(Permission.OPERATE)
    with svc.database.project(project_id) as uow:
        finding = uow.findings.get(finding_id)
        if finding is None:
            raise NotFound("finding not found")
        store = RepositoryFindingStore(uow, finding.scope_revision_id, asset_for=lambda _: finding.asset_id)
        FindingService(store).annotate(finding.fingerprint, _actor(ctx), **body.model_dump())
        record_audit(uow.connection, "finding.annotated", str(finding_id), project_id=project_id,
                     actor=ctx.principal.id, details=body.model_dump(exclude_none=True))
        return _finding_detail(uow, finding_id)


@router.get("/assets/{asset_id}/timeline", response_model=schemas.Page[schemas.ObservationOut])
def timeline(project_id: UUID, asset_id: UUID, ctx: Context, svc: Services, limit: Limit = DEFAULT_LIMIT,
             cursor: Annotated[str | None, Query(max_length=1024)] = None):
    ctx.require(Permission.VIEW)
    with svc.database.project(project_id) as uow:
        if uow.assets.get(asset_id) is None:
            raise NotFound("asset not found")
        query = select(observations).where(observations.c.project_id == project_id, observations.c.asset_id == asset_id)
        if cursor:
            at, identifier = decode_cursor(cursor, "timeline:" + str(asset_id), 2)
            query = query.where(tuple_(observations.c.observed_at, observations.c.id) < tuple_(cursor_time(at), cursor_uuid(identifier)))
        rows = list(uow.connection.execute(query.order_by(observations.c.observed_at.desc(), observations.c.id.desc()).limit(limit + 1)))
        page = rows[:limit]
        return {"items": [schemas.observation_out(_observation(row)) for row in page],
                "next_cursor": encode_cursor("timeline:" + str(asset_id), page[-1].observed_at, page[-1].id) if len(rows) > limit else None}


@router.get("/candidates", response_model=schemas.Page[schemas.AssetOut])
def candidates(project_id: UUID, ctx: Context, svc: Services, limit: Limit = DEFAULT_LIMIT,
               cursor: Annotated[str | None, Query(max_length=1024)] = None):
    """Candidate provenance and ownership are evidence, never scan permission."""
    ctx.require(Permission.VIEW)
    after = None
    if cursor:
        kind, value = decode_cursor(cursor, "candidates", 2)
        after = (str(kind), str(value))
    with svc.database.project(project_id) as uow:
        rows = queries.list_assets(uow, limit=limit + 1, kind=AssetKind.HOSTNAME, after=after)
    page = rows[:limit]
    policy = svc.scope.current_policy(project_id)
    items = []
    for asset in page:
        out = schemas.asset_out(asset)
        decision = policy.check_target(asset.value, port=None)
        state = "approved" if decision else ("revoked" if decision.reason.value in ("revoked", "superseded") else
                                            "excluded" if decision.reason.value == "excluded" else "pending")
        items.append(out.model_copy(update={"attributes": {**out.attributes, "authorization_status": state,
                                                           "authorization_reason": decision.reason.value}}))
    return {"items": items,
            "next_cursor": encode_cursor("candidates", page[-1].kind.value, page[-1].value) if len(rows) > limit else None}


@router.get("/changes", response_model=schemas.Page[dict[str, Any]])
def changes(project_id: UUID, ctx: Context, svc: Services, limit: Limit = DEFAULT_LIMIT,
            cursor: Annotated[str | None, Query(max_length=1024)] = None):
    ctx.require(Permission.VIEW)
    query = select(phase_snapshots).where(phase_snapshots.c.project_id == project_id,
                                        phase_snapshots.c.changes != {})
    if cursor:
        at, identifier = decode_cursor(cursor, "changes", 2)
        query = query.where(tuple_(phase_snapshots.c.created_at, phase_snapshots.c.id) < tuple_(cursor_time(at), cursor_uuid(identifier)))
    with svc.database.project(project_id) as uow:
        rows = list(uow.connection.execute(query.order_by(phase_snapshots.c.created_at.desc(), phase_snapshots.c.id.desc()).limit(limit + 1)))
        page = rows[:limit]
        acknowledgements = list(uow.connection.execute(select(audit_events.c.subject, audit_events.c.details,
                                                              audit_events.c.occurred_at).where(
            audit_events.c.project_id == project_id, audit_events.c.action == "change.acknowledged",
            audit_events.c.subject.in_([str(row.id) for row in page])).order_by(audit_events.c.id)))
        acks = {r.subject: {**r.details, "at": r.occurred_at} for r in acknowledgements}
    return {"items": [{"id": r.id, "run_id": r.run_id, "target": r.target, "phase": r.phase,
                        "comparison": r.comparison, "changes": r.changes, "created_at": r.created_at,
                        "acknowledgement": acks.get(str(r.id))} for r in page],
            "next_cursor": encode_cursor("changes", page[-1].created_at, page[-1].id) if len(rows) > limit else None}


@router.post("/changes/{change_id}/acknowledge", response_model=dict[str, bool])
def acknowledge(project_id: UUID, change_id: UUID, body: AcknowledgeIn, ctx: Context, svc: Services):
    ctx.require(Permission.OPERATE)
    with svc.database.project(project_id) as uow:
        exists = uow.connection.execute(select(phase_snapshots.c.id).where(phase_snapshots.c.project_id == project_id,
                                                                          phase_snapshots.c.id == change_id)).scalar_one_or_none()
        if exists is None:
            raise NotFound("change not found")
        record_audit(uow.connection, "change.acknowledged", str(change_id), project_id=project_id,
                     actor=ctx.principal.id, details={"reason": body.reason, "actor": str(ctx.principal.id)})
    return {"acknowledged": True}


@router.get("/exports", response_class=Response)
def exports(project_id: UUID, ctx: Context, svc: Services, dataset: Literal["assets", "findings"] = "assets",
            format: Literal["json", "csv"] = "json", limit: Limit = DEFAULT_LIMIT,
            cursor: Annotated[str | None, Query(max_length=1024)] = None):
    from watchtower.services.reports import build_report
    content, media_type, headers = build_report(svc.database, project_id, ctx, dataset=dataset, format=format, limit=limit, cursor=cursor)
    return Response(content, media_type=media_type, headers=headers)


@router.get("/intelligence", response_model=dict[str, Any])
def intelligence(project_id: UUID, ctx: Context, svc: Services, limit: Limit = DEFAULT_LIMIT,
                 after_asset: Annotated[str | None, Query(max_length=253)] = None):
    ctx.require(Permission.VIEW)
    with svc.database.project(project_id) as uow:
        try:
            return IntelligenceService(svc.settings).correlate(uow, limit=limit, after_value=after_asset)
        except ValueError as exc:
            return JSONResponse({"error": "invalid_request", "detail": str(exc)}, status_code=422)


@router.post("/findings/{finding_id}/prioritize", response_model=dict[str, Any])
def reprioritize(project_id: UUID, finding_id: UUID, ctx: Context, svc: Services):
    ctx.require(Permission.OPERATE)
    with svc.database.project(project_id) as uow:
        return IntelligenceService(svc.settings).reprioritize(uow, ctx, finding_id)


@router.get("/settings", response_model=dict[str, Any])
def settings(project_id: UUID, ctx: Context, svc: Services):
    """Operational settings without connection strings, tokens or destination URLs."""
    ctx.require(Permission.VIEW)
    from watchtower.services.public_settings import public_settings
    return public_settings(svc.settings, svc.rules)
