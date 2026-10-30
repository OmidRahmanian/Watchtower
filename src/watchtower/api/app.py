"""The project-scoped HTTP API and the dashboard that uses it.

Every route under ``/api/v1/projects/{project_id}`` authenticates a bearer
token, resolves the caller's role in that project with
``PgAuthRepository.project_context`` and checks the permission the action
needs before touching data. Data access goes through ``Database.project``, so
row-level security confines each request to the project in its path. A
project the caller is not a member of is reported as not found, so the API
does not reveal which projects exist.

Run with ``watchtower serve`` (see ``watchtower.cli``).
"""

from __future__ import annotations

import json
import logging
import os
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, FastAPI, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles

import watchtower
from watchtower.adapters.checks import RuleIntegrityError, RuleSet, load_manifest
from watchtower.api import queries, schemas
from watchtower.api.pagination import (
    DEFAULT_LIMIT,
    MAX_LIMIT,
    InvalidCursor,
    cursor_time,
    cursor_uuid,
    decode_cursor,
    encode_cursor,
)
from watchtower.api.runs import RunsPort, default_runs
from watchtower.config.settings import Settings
from watchtower.domain.errors import (
    AuthenticationFailed,
    InvalidScopeRule,
    InvalidTarget,
    NotFound,
    PermissionDenied,
    RunCancelled,
    ScopeViolation,
    WatchtowerError,
)
from watchtower.domain.models import AssetKind, FindingStatus, Severity
from watchtower.domain.repositories import BlobStore
from watchtower.domain.scope import AuthorizationReference, RuleEffect, ScopeRule
from watchtower.persistence.database import Database
from watchtower.security.auth import Permission, ProjectContext
from watchtower.services.evidence_store import BlobError, FilesystemBlobStore
from watchtower.services.findings import FindingError, FindingService, RepositoryFindingStore
from watchtower.services.scope import ScopeService

log = logging.getLogger(__name__)

API_PREFIX = "/api/v1"
EVIDENCE_DOWNLOAD_TYPE = "application/octet-stream"
# The dashboard is static files from this origin; nothing else may run.
CONTENT_SECURITY_POLICY = (
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; "
    "base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
)


def default_frontend_root() -> Path:
    packaged = Path(watchtower.__file__).resolve().parent / "_frontend"
    return packaged if packaged.is_dir() else Path(__file__).resolve().parents[3] / "frontend"


def default_evidence_root(settings: Settings) -> Path:
    pipeline = getattr(settings, "pipeline", None)
    configured = getattr(pipeline, "evidence_root", None)
    return Path(configured or os.environ.get("WATCHTOWER_EVIDENCE_DIR", "data/evidence"))


@dataclass
class ApiServices:
    database: Database
    scope: ScopeService
    blobs: BlobStore
    runs: RunsPort | None = None
    rules: Callable[[], RuleSet] = load_manifest
    settings: Settings = field(default_factory=Settings)


# -- authentication -------------------------------------------------------

_bearer = HTTPBearer(auto_error=False, description="A WatchTower API token: wt_<prefix>_<secret>")


def services(request: Request) -> ApiServices:
    return request.app.state.services


def project_context(
    project_id: UUID,
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> ProjectContext:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise AuthenticationFailed("missing bearer token")
    with services(request).database.system() as system:
        try:
            return system.auth.project_context(credentials.credentials, project_id)
        except PermissionDenied:
            # Not a member, or a token restricted to another project.
            raise NotFound("project not found") from None


Context = Annotated[ProjectContext, Depends(project_context)]
Services = Annotated[ApiServices, Depends(services)]
Limit = Annotated[int, Query(ge=1, le=MAX_LIMIT)]


def _runs(svc: ApiServices) -> RunsPort:
    if svc.runs is None:
        raise RunsUnavailable("the monitoring runtime is not installed")
    return svc.runs


class RunsUnavailable(WatchtowerError):
    pass


# -- errors and headers ---------------------------------------------------

_STATUS: list[tuple[type[Exception], int, str]] = [
    (AuthenticationFailed, 401, "authentication_failed"),
    (PermissionDenied, 403, "permission_denied"),
    (NotFound, 404, "not_found"),
    (ScopeViolation, 409, "scope_violation"),
    (RunCancelled, 409, "run_cancelled"),
    (FindingError, 409, "invalid_transition"),
    (InvalidCursor, 422, "invalid_cursor"),
    (InvalidScopeRule, 422, "invalid_scope"),
    (InvalidTarget, 422, "invalid_target"),
    (RunsUnavailable, 503, "runs_unavailable"),
]


def _error(status: int, error: str, detail: str, headers: dict[str, str] | None = None) -> JSONResponse:
    return JSONResponse({"error": error, "detail": detail}, status_code=status, headers=headers)


def _install_error_handlers(app: FastAPI) -> None:
    for exception, status, code in _STATUS:
        def handler(request: Request, exc: Exception, status: int = status, code: str = code) -> JSONResponse:
            headers = {"WWW-Authenticate": "Bearer"} if status == 401 else None
            detail = str(exc)
            if isinstance(exc, ScopeViolation):
                detail = f"{exc.decision.reason.value}: {exc.decision.detail}"
            return _error(status, code, detail, headers)

        app.add_exception_handler(exception, handler)

    def validation(request: Request, exc: RequestValidationError) -> JSONResponse:
        problems = "; ".join(
            f"{'.'.join(str(part) for part in item['loc'])}: {item['msg']}" for item in exc.errors()
        )
        return _error(422, "invalid_request", problems)

    app.add_exception_handler(RequestValidationError, validation)


def _install_security_headers(app: FastAPI) -> None:
    @app.middleware("http")
    async def headers(request: Request, call_next: Any) -> Response:
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Content-Security-Policy", CONTENT_SECURITY_POLICY)
        if request.url.path.startswith(API_PREFIX):
            response.headers.setdefault("Cache-Control", "no-store")
        return response


# -- routes ---------------------------------------------------------------

router = APIRouter(prefix=API_PREFIX)
project_router = APIRouter(prefix=API_PREFIX + "/projects/{project_id}")


@router.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "version": watchtower.__version__}


@router.get("/projects", response_model=list[schemas.ProjectOut])
def list_projects(
    svc: Services, credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)]
) -> list[schemas.ProjectOut]:
    """Projects the token's principal belongs to."""
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise AuthenticationFailed("missing bearer token")
    with svc.database.system() as system:
        principal, restricted_to = system.auth.authenticate(credentials.credentials)
        result = []
        for project_id, role in system.auth.memberships(principal.id):
            if restricted_to is not None and project_id != restricted_to:
                continue
            project = system.projects.get(project_id)
            if project is not None:
                context = ProjectContext(project_id=project_id, principal=principal, role=role)
                result.append(schemas.project_out(project, context))
    return sorted(result, key=lambda project: project.slug)


@project_router.get("", response_model=schemas.ProjectOut)
def get_project(project_id: UUID, ctx: Context, svc: Services) -> schemas.ProjectOut:
    ctx.require(Permission.VIEW)
    with svc.database.project(project_id) as uow:
        return schemas.project_out(uow.get_project(), ctx)


@project_router.get("/overview", response_model=schemas.OverviewOut)
def overview(project_id: UUID, ctx: Context, svc: Services) -> schemas.OverviewOut:
    ctx.require(Permission.VIEW)
    with svc.database.project(project_id) as uow:
        project = uow.get_project()
        current = uow.scope.current()
        counts = queries.counts(uow)
    runs = list(svc.runs.list_runs(project_id, actor=ctx, limit=5)) if svc.runs is not None else []
    return schemas.OverviewOut(
        project=schemas.project_out(project, ctx),
        scope=schemas.revision_out(current) if current else None,
        counts=counts,
        latest_runs=[schemas.run_out(run) for run in runs],
        runs_available=svc.runs is not None,
        rules=_rules(svc),
    )


def _rules(svc: ApiServices) -> list[schemas.RuleOut]:
    try:
        ruleset = svc.rules()
    except (RuleIntegrityError, OSError) as error:
        log.warning("rule manifest could not be loaded: %s", error)
        return []
    return [schemas.RuleOut(id=rule.id, version=rule.version, kind=rule.kind, title=rule.title,
                            severity=rule.severity.value, approved=rule.approved) for rule in ruleset]


# -- scope ----------------------------------------------------------------


@project_router.get("/scope", response_model=schemas.ScopeOut)
def get_scope(project_id: UUID, ctx: Context, svc: Services) -> schemas.ScopeOut:
    history = svc.scope.history(project_id, actor=ctx)
    with svc.database.project(project_id) as uow:
        current = uow.scope.current()
    return schemas.ScopeOut(
        current=schemas.revision_out(current) if current else None,
        history=[schemas.revision_out(revision) for revision in history],
    )


@project_router.post("/scope", response_model=schemas.ScopeRevisionOut, status_code=201)
def publish_scope(project_id: UUID, body: schemas.PublishScopeIn, ctx: Context, svc: Services) -> schemas.ScopeRevisionOut:
    """Publish a new scope revision; it supersedes the current one at once."""
    ctx.require(Permission.MANAGE_SCOPE)
    auth = body.authorization
    rules = [ScopeRule.parse(pattern) for pattern in body.includes]
    rules += [ScopeRule.parse(pattern, effect=RuleEffect.EXCLUDE) for pattern in body.excludes]
    revision = svc.scope.publish(
        project_id,
        rules,
        AuthorizationReference(kind=auth.kind, reference=auth.reference, granted_by=auth.granted_by,
                               valid_from=auth.valid_from, valid_until=auth.valid_until, notes=auth.notes),
        actor=ctx,
        permitted_ports=body.permitted_ports,
        notes=body.notes,
    )
    return schemas.revision_out(revision)


@project_router.post("/scope/{revision_id}/revoke", response_model=schemas.ScopeRevisionOut)
def revoke_scope(
    project_id: UUID, revision_id: UUID, body: schemas.RevokeScopeIn, ctx: Context, svc: Services
) -> schemas.ScopeRevisionOut:
    ctx.require(Permission.MANAGE_SCOPE)
    return schemas.revision_out(svc.scope.revoke(project_id, revision_id, reason=body.reason, actor=ctx))


@project_router.post("/scope/check", response_model=schemas.ScopeDecisionOut)
def check_scope(project_id: UUID, body: schemas.ScopeCheckIn, ctx: Context, svc: Services) -> schemas.ScopeDecisionOut:
    """Would the current scope authorize this target? Sends no traffic."""
    ctx.require(Permission.VIEW)
    return schemas.decision_out(svc.scope.authorize_target(project_id, body.target, port=body.port))


# -- inventory ------------------------------------------------------------


@project_router.get("/assets", response_model=schemas.Page[schemas.AssetOut])
def list_assets(
    project_id: UUID,
    ctx: Context,
    svc: Services,
    kind: AssetKind | None = None,
    search: Annotated[str | None, Query(max_length=253)] = None,
    cursor: Annotated[str | None, Query(max_length=1024)] = None,
    limit: Limit = DEFAULT_LIMIT,
) -> schemas.Page[schemas.AssetOut]:
    ctx.require(Permission.VIEW)
    after = None
    if cursor:
        kind_value, value = decode_cursor(cursor, "assets", 2)
        after = (str(kind_value), str(value))
    with svc.database.project(project_id) as uow:
        rows = queries.list_assets(uow, limit=limit + 1, kind=kind, search=search, after=after)
    page, more = rows[:limit], len(rows) > limit
    return schemas.Page[schemas.AssetOut](
        items=[schemas.asset_out(asset) for asset in page],
        next_cursor=encode_cursor("assets", page[-1].kind.value, page[-1].value) if more else None,
    )


@project_router.get("/assets/{asset_id}", response_model=schemas.AssetDetailOut)
def get_asset(
    project_id: UUID, asset_id: UUID, ctx: Context, svc: Services, observations: Limit = 20
) -> schemas.AssetDetailOut:
    ctx.require(Permission.VIEW)
    with svc.database.project(project_id) as uow:
        asset = uow.assets.get(asset_id)
        if asset is None:
            raise NotFound("asset not found")
        recent = uow.observations.list_for_asset(asset_id, limit=observations)
    return schemas.AssetDetailOut(asset=schemas.asset_out(asset),
                                  observations=[schemas.observation_out(item) for item in recent])


# -- findings -------------------------------------------------------------


@project_router.get("/findings", response_model=schemas.Page[schemas.FindingOut])
def list_findings(
    project_id: UUID,
    ctx: Context,
    svc: Services,
    status: Annotated[list[FindingStatus], Query()] = [],  # noqa: B006 - FastAPI copies defaults
    severity: Annotated[list[Severity], Query()] = [],  # noqa: B006
    asset_id: UUID | None = None,
    cursor: Annotated[str | None, Query(max_length=1024)] = None,
    limit: Limit = DEFAULT_LIMIT,
) -> schemas.Page[schemas.FindingOut]:
    ctx.require(Permission.VIEW)
    before = None
    if cursor:
        moment, finding_id = decode_cursor(cursor, "findings", 2)
        before = (cursor_time(moment), cursor_uuid(finding_id))
    with svc.database.project(project_id) as uow:
        rows = queries.list_findings(uow, limit=limit + 1, statuses=status, severities=severity,
                                     asset_id=asset_id, before=before)
    page, more = rows[:limit], len(rows) > limit
    return schemas.Page[schemas.FindingOut](
        items=[schemas.finding_out(finding) for finding in page],
        next_cursor=encode_cursor("findings", page[-1].last_seen_at, page[-1].id) if more else None,
    )


def _finding_detail(uow: Any, finding_id: UUID) -> schemas.FindingDetailOut:
    finding = uow.findings.get(finding_id)
    if finding is None:
        raise NotFound("finding not found")
    return schemas.finding_detail_out(finding, list(uow.evidence.list_for_finding(finding_id)))


@project_router.get("/findings/{finding_id}", response_model=schemas.FindingDetailOut)
def get_finding(project_id: UUID, finding_id: UUID, ctx: Context, svc: Services) -> schemas.FindingDetailOut:
    ctx.require(Permission.VIEW)
    with svc.database.project(project_id) as uow:
        return _finding_detail(uow, finding_id)


def _actor(ctx: ProjectContext) -> str:
    return f"{ctx.principal.display_name} <{ctx.principal.id}>"


@project_router.post("/findings/{finding_id}/status", response_model=schemas.FindingDetailOut)
def transition_finding(
    project_id: UUID, finding_id: UUID, body: schemas.TransitionIn, ctx: Context, svc: Services
) -> schemas.FindingDetailOut:
    """Triage a finding. Only a relevant negative retest can mark it resolved."""
    ctx.require(Permission.OPERATE)
    with svc.database.project(project_id) as uow:
        finding = uow.findings.get(finding_id)
        if finding is None:
            raise NotFound("finding not found")
        # The finding's asset already exists; do not touch its last-seen time.
        store = RepositoryFindingStore(uow, finding.scope_revision_id, asset_for=lambda _target: finding.asset_id)
        FindingService(store).transition(finding.fingerprint, body.status, _actor(ctx), body.reason)
        return _finding_detail(uow, finding_id)


@project_router.post("/findings/{finding_id}/retest", response_model=schemas.RunOut, status_code=202)
def retest_finding(
    project_id: UUID, finding_id: UUID, body: schemas.RetestIn, ctx: Context, svc: Services
) -> schemas.RunOut:
    """Queue a retest of exactly this finding's check and endpoint."""
    ctx.require(Permission.OPERATE)
    runs = _runs(svc)
    with svc.database.project(project_id) as uow:
        finding = uow.findings.get(finding_id)
        if finding is None:
            raise NotFound("finding not found")
    return schemas.run_out(runs.request_retest(project_id, finding.fingerprint, actor=ctx, reason=body.reason))


# -- evidence -------------------------------------------------------------


def _load_evidence(svc: ApiServices, project_id: UUID, evidence_id: UUID) -> tuple[Any, bytes]:
    with svc.database.project(project_id) as uow:
        evidence = uow.evidence.get(evidence_id)
    if evidence is None:
        raise NotFound("evidence not found")
    # Blob URIs name their project; refuse one that points elsewhere even if
    # a row were ever written with a foreign URI.
    if not evidence.storage_uri.startswith(f"fs:{project_id}/"):
        log.error("evidence %s in project %s points outside the project", evidence_id, project_id)
        raise NotFound("evidence not found")
    try:
        data = svc.blobs.get(evidence.storage_uri)
    except BlobError as error:
        log.error("evidence %s could not be read: %s", evidence_id, error)
        raise NotFound("evidence content is unavailable") from None
    if len(data) != evidence.size_bytes:
        raise NotFound("evidence content is unavailable")
    return evidence, data


@project_router.get("/evidence/{evidence_id}", response_model=schemas.EvidenceContentOut)
def get_evidence(project_id: UUID, evidence_id: UUID, ctx: Context, svc: Services) -> schemas.EvidenceContentOut:
    """Evidence metadata and its already-redacted content as JSON data."""
    ctx.require(Permission.VIEW)
    evidence, data = _load_evidence(svc, project_id, evidence_id)
    try:
        content = json.loads(data)
    except ValueError:
        content = None
    if not isinstance(content, dict):
        content = {"note": "this evidence is not structured JSON; download it to inspect"}
    return schemas.EvidenceContentOut(evidence=schemas.evidence_out(project_id, evidence), content=content)


@project_router.get("/evidence/{evidence_id}/download", response_class=Response)
def download_evidence(project_id: UUID, evidence_id: UUID, ctx: Context, svc: Services) -> Response:
    """The stored bytes, always as an attachment that browsers will not render."""
    ctx.require(Permission.VIEW)
    evidence, data = _load_evidence(svc, project_id, evidence_id)
    return Response(
        content=data,
        media_type=EVIDENCE_DOWNLOAD_TYPE,
        headers={
            "Content-Disposition": f'attachment; filename="evidence-{evidence.id}.json"',
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "default-src 'none'; sandbox",
            "Cache-Control": "no-store",
            "Digest": f"sha-256={evidence.sha256}",
        },
    )


# -- runs and alerts ------------------------------------------------------


@project_router.get("/runs", response_model=schemas.Page[schemas.RunOut])
def list_runs(
    project_id: UUID,
    ctx: Context,
    svc: Services,
    cursor: Annotated[str | None, Query(max_length=1024)] = None,
    limit: Limit = DEFAULT_LIMIT,
) -> schemas.Page[schemas.RunOut]:
    ctx.require(Permission.VIEW)
    runs = _runs(svc)
    before = None
    if cursor:
        moment, run_id = decode_cursor(cursor, "runs", 2)
        before = (cursor_time(moment), cursor_uuid(run_id))
    rows = list(runs.list_runs(project_id, actor=ctx, limit=limit + 1, before=before))
    page, more = rows[:limit], len(rows) > limit
    return schemas.Page[schemas.RunOut](
        items=[schemas.run_out(run) for run in page],
        next_cursor=encode_cursor("runs", page[-1].created_at, page[-1].run_id) if more else None,
    )


@project_router.post("/runs", response_model=schemas.RunOut, status_code=202)
def start_run(project_id: UUID, body: schemas.StartRunIn, ctx: Context, svc: Services) -> schemas.RunOut:
    """Queue a monitoring run pinned to the current scope revision."""
    ctx.require(Permission.OPERATE)
    summary = _runs(svc).start_run(project_id, actor=ctx, targets=body.targets, phases=body.phases,
                                   reason=body.reason)
    return schemas.run_out(summary)


@project_router.get("/runs/{run_id}", response_model=schemas.RunDetailOut)
def get_run(project_id: UUID, run_id: UUID, ctx: Context, svc: Services) -> schemas.RunDetailOut:
    ctx.require(Permission.VIEW)
    return schemas.run_detail_out(_runs(svc).get_run(project_id, run_id, actor=ctx))


@project_router.post("/runs/{run_id}/cancel")
def cancel_run(project_id: UUID, run_id: UUID, body: schemas.CancelRunIn, ctx: Context, svc: Services) -> dict[str, int]:
    ctx.require(Permission.OPERATE)
    runs = _runs(svc)
    runs.get_run(project_id, run_id, actor=ctx)  # 404 for a run outside this project
    return {"cancelled": runs.cancel_run(project_id, run_id, actor=ctx, reason=body.reason)}


@project_router.get("/alerts", response_model=schemas.Page[schemas.AlertOut])
def list_alerts(
    project_id: UUID,
    ctx: Context,
    svc: Services,
    event_type: Annotated[list[str], Query(max_length=20)] = [],  # noqa: B006
    cursor: Annotated[str | None, Query(max_length=1024)] = None,
    limit: Limit = DEFAULT_LIMIT,
) -> schemas.Page[schemas.AlertOut]:
    ctx.require(Permission.VIEW)
    before = None
    if cursor:
        moment, notification_id = decode_cursor(cursor, "alerts", 2)
        before = (cursor_time(moment), cursor_uuid(notification_id))
    with svc.database.project(project_id) as uow:
        rows = queries.list_alerts(uow, limit=limit + 1, event_types=event_type, before=before)
    page, more = rows[:limit], len(rows) > limit
    return schemas.Page[schemas.AlertOut](
        items=[schemas.alert_out(item) for item in page],
        next_cursor=encode_cursor("alerts", page[-1].created_at, page[-1].id) if more else None,
    )


# -- application ----------------------------------------------------------

_DEFAULT_RUNS = object()


def create_app(
    database: Database,
    *,
    settings: Settings | None = None,
    scope: ScopeService | None = None,
    blobs: BlobStore | None = None,
    runs: RunsPort | None | object = _DEFAULT_RUNS,
    rules: Callable[[], RuleSet] = load_manifest,
    frontend: Path | None = None,
) -> FastAPI:
    """Build the API. ``runs=None`` disables run routes; the default loads ``RunService`` if installed."""
    settings = settings or Settings()
    scope = scope or ScopeService(database, settings.scope)
    app = FastAPI(
        title="WatchTower",
        version=watchtower.__version__,
        description="Authorized attack surface monitoring. Every project route needs a bearer API token.",
        docs_url=API_PREFIX + "/docs",
        redoc_url=None,
        openapi_url=API_PREFIX + "/openapi.json",
    )
    app.state.services = ApiServices(
        database=database,
        scope=scope,
        blobs=blobs or FilesystemBlobStore(default_evidence_root(settings)),
        runs=default_runs(database, scope) if runs is _DEFAULT_RUNS else runs,  # type: ignore[arg-type]
        rules=rules,
        settings=settings,
    )
    _install_error_handlers(app)
    _install_security_headers(app)
    app.include_router(router)
    app.include_router(project_router)

    root = frontend or default_frontend_root()
    if (root / "index.html").is_file():
        app.mount("/static", StaticFiles(directory=root), name="static")

        @app.get("/", include_in_schema=False)
        def dashboard() -> FileResponse:
            return FileResponse(root / "index.html", media_type="text/html")

    return app
