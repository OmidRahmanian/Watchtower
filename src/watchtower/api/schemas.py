"""Validated request and response bodies.

Responses are built from domain records by the ``*_out`` functions so routes
never return raw rows. Captured content (titles, headers, evidence excerpts)
is passed through as data; clients must render it as text.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Generic, Literal, TypeVar
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from watchtower.domain.models import (
    Asset,
    Evidence,
    Finding,
    FindingStatus,
    Job,
    Notification,
    Observation,
    PhaseSnapshot,
    Project,
    RunPhase,
    Severity,
)
from watchtower.domain.scope import AuthorizationKind, ScopeDecision, ScopeRevision
from watchtower.security.auth import ROLE_PERMISSIONS, ProjectContext
from watchtower.services.findings import FindingRecord

T = TypeVar("T")


class _Out(BaseModel):
    model_config = ConfigDict(frozen=True)


class _In(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Page(_Out, Generic[T]):
    items: list[T]
    next_cursor: str | None = None


class ErrorOut(_Out):
    error: str
    detail: str


# -- projects -------------------------------------------------------------


class ProjectOut(_Out):
    id: UUID
    slug: str
    name: str
    archived: bool
    created_at: datetime
    role: str
    permissions: list[str]


def project_out(project: Project, context: ProjectContext) -> ProjectOut:
    return ProjectOut(
        id=project.id, slug=project.slug, name=project.name, archived=project.archived,
        created_at=project.created_at, role=context.role.value,
        permissions=sorted(p.value for p in ROLE_PERMISSIONS[context.role] if context.can(p)),
    )


# -- scope ----------------------------------------------------------------


class AuthorizationIn(_In):
    kind: AuthorizationKind
    reference: str = Field(min_length=1, max_length=2000)
    granted_by: str = Field(min_length=1, max_length=500)
    valid_from: datetime | None = None
    valid_until: datetime | None = None
    notes: str = Field(default="", max_length=4000)

    @field_validator("kind")
    @classmethod
    def _not_legacy(cls, value: AuthorizationKind) -> AuthorizationKind:
        if value is AuthorizationKind.LEGACY_IMPORT:
            raise ValueError("legacy_import is reserved for the MongoDB importer")
        return value


class PublishScopeIn(_In):
    includes: list[str] = Field(min_length=1, max_length=500)
    excludes: list[str] = Field(default_factory=list, max_length=500)
    permitted_ports: str | None = Field(default=None, max_length=200)
    authorization: AuthorizationIn
    notes: str = Field(default="", max_length=4000)
    # The caller states that the authorization covers every include rule.
    attest_authorized: Literal[True]


class RevokeScopeIn(_In):
    reason: str = Field(min_length=3, max_length=2000)


class ScopeCheckIn(_In):
    target: str = Field(min_length=1, max_length=2048)
    port: int | None = Field(default=None, ge=1, le=65535)


class ScopeRuleOut(_Out):
    effect: str
    kind: str
    pattern: str
    ports: str | None
    note: str


class AuthorizationOut(_Out):
    kind: str
    reference: str
    granted_by: str
    valid_from: datetime | None
    valid_until: datetime | None
    notes: str


class RevocationOut(_Out):
    revoked_at: datetime
    reason: str
    revoked_by: UUID | None


class ScopeRevisionOut(_Out):
    id: UUID
    number: int
    rules: list[ScopeRuleOut]
    authorization: AuthorizationOut
    permitted_ports: str
    created_at: datetime
    created_by: UUID | None
    notes: str
    revocation: RevocationOut | None


class ScopeOut(_Out):
    current: ScopeRevisionOut | None
    history: list[ScopeRevisionOut]


class ScopeDecisionOut(_Out):
    allowed: bool
    reason: str
    detail: str
    revision_id: UUID | None
    target: str | None
    port: int | None


def revision_out(revision: ScopeRevision) -> ScopeRevisionOut:
    auth = revision.authorization
    revocation = revision.revocation
    return ScopeRevisionOut(
        id=revision.id, number=revision.number,
        rules=[ScopeRuleOut(effect=r.effect.value, kind=r.kind.value, pattern=r.pattern,
                            ports=str(r.ports) if r.ports is not None else None, note=r.note)
               for r in revision.rules],
        authorization=AuthorizationOut(kind=auth.kind.value, reference=auth.reference, granted_by=auth.granted_by,
                                       valid_from=auth.valid_from, valid_until=auth.valid_until, notes=auth.notes),
        permitted_ports=str(revision.permitted_ports), created_at=revision.created_at,
        created_by=revision.created_by, notes=revision.notes,
        revocation=RevocationOut(revoked_at=revocation.revoked_at, reason=revocation.reason,
                                 revoked_by=revocation.revoked_by) if revocation else None,
    )


def decision_out(decision: ScopeDecision) -> ScopeDecisionOut:
    return ScopeDecisionOut(allowed=decision.allowed, reason=decision.reason.value, detail=decision.detail,
                            revision_id=decision.revision_id, target=decision.target, port=decision.port)


# -- inventory ------------------------------------------------------------


class AssetOut(_Out):
    id: UUID
    kind: str
    value: str
    first_seen_at: datetime
    last_seen_at: datetime
    authorization: str  # authorized | unauthorized | unknown, as of the last sighting
    addresses: list[str]
    last_http: dict[str, Any] | None
    attributes: dict[str, Any]


class ObservationOut(_Out):
    id: UUID
    kind: str
    source: str
    observed_at: datetime
    data: dict[str, Any]


class AssetDetailOut(_Out):
    asset: AssetOut
    observations: list[ObservationOut]


def asset_out(asset: Asset) -> AssetOut:
    attributes = dict(asset.attributes)
    authorization = attributes.get("authorization") or {}
    return AssetOut(
        id=asset.id, kind=asset.kind.value, value=asset.value, first_seen_at=asset.first_seen_at,
        last_seen_at=asset.last_seen_at, authorization=str(authorization.get("status", "unknown")),
        addresses=list(attributes.get("addresses", [])), last_http=attributes.get("last_http"),
        attributes=attributes,
    )


def observation_out(observation: Observation) -> ObservationOut:
    return ObservationOut(id=observation.id, kind=observation.kind.value, source=observation.source,
                          observed_at=observation.observed_at, data=dict(observation.data))


# -- findings and evidence ------------------------------------------------

# How far remediation of a finding has been verified. Only "verified_fixed"
# means a relevant retest came back negative; a failed or inconclusive retest
# proves nothing and is reported as such.
Remediation = Literal[
    "not_retested", "retest_pending", "retest_failed", "retest_inconclusive", "still_present", "verified_fixed",
]
_RETEST_EVENTS = {"resolved", "retest_failed", "retest_inconclusive", "retest_not_detected", "retest_requested"}


def remediation(record: FindingRecord) -> tuple[Remediation, dict[str, Any] | None]:
    """The remediation state and the history event it was derived from."""
    last = next(
        (event for event in reversed(record.history)
         if event.get("event") in _RETEST_EVENTS
         or (event.get("event") in ("detected", "reopened") and event.get("source") == "retest")),
        None,
    )
    if record.status is FindingStatus.RESOLVED:
        return "verified_fixed", last
    if last is None:
        return ("retest_pending" if record.retest_requested_at else "not_retested"), None
    kind = last["event"]
    if kind == "retest_failed":
        return "retest_failed", last
    if kind == "retest_inconclusive":
        return "retest_inconclusive", last
    if kind in ("detected", "reopened"):
        return "still_present", last
    return ("retest_pending" if record.retest_requested_at else "not_retested"), last


class EvidenceOut(_Out):
    id: UUID
    media_type: str
    sha256: str
    size_bytes: int
    created_at: datetime
    description: str
    finding_id: UUID | None
    download_path: str


class EvidenceContentOut(_Out):
    evidence: EvidenceOut
    content: dict[str, Any]


class DetectionOut(_Out):
    state: str
    last_outcome: str
    last_outcome_at: datetime | None
    last_conclusive_at: datetime | None


class FindingOut(_Out):
    id: UUID
    asset_id: UUID
    fingerprint: str
    title: str
    severity: Severity
    status: FindingStatus
    check_id: str
    target: str
    location: str
    first_seen_at: datetime
    last_seen_at: datetime
    status_changed_at: datetime
    detection: DetectionOut
    remediation: Remediation
    priority: dict[str, Any] | None


class FindingDetailOut(FindingOut):
    confidence: str
    cves: list[str]
    rule_version: str
    occurrences: int
    recurrences: int
    retest_requested_at: datetime | None
    remediation_event: dict[str, Any] | None
    history: list[dict[str, Any]]
    evidence: list[EvidenceOut]


class TransitionIn(_In):
    status: FindingStatus
    reason: str = Field(default="", max_length=4000)


class RetestIn(_In):
    reason: str = Field(default="", max_length=2000)


def evidence_out(project_id: UUID, evidence: Evidence) -> EvidenceOut:
    return EvidenceOut(
        id=evidence.id, media_type=evidence.media_type, sha256=evidence.sha256, size_bytes=evidence.size_bytes,
        created_at=evidence.created_at, description=evidence.description, finding_id=evidence.finding_id,
        download_path=f"/api/v1/projects/{project_id}/evidence/{evidence.id}/download",
    )


def _finding_fields(finding: Finding, record: FindingRecord) -> dict[str, Any]:
    detection = record.detection
    return dict(
        id=finding.id, asset_id=finding.asset_id, fingerprint=finding.fingerprint, title=finding.title,
        severity=finding.severity, status=finding.status, check_id=record.check_id,
        target=record.target.identity, location=record.location, first_seen_at=finding.first_seen_at,
        last_seen_at=finding.last_seen_at, status_changed_at=finding.status_changed_at,
        detection=DetectionOut(state=detection.state, last_outcome=detection.last_outcome.value,
                               last_outcome_at=detection.last_outcome_at,
                               last_conclusive_at=detection.last_conclusive_at),
        remediation=remediation(record)[0], priority=record.priority,
    )


def finding_out(finding: Finding) -> FindingOut:
    return FindingOut(**_finding_fields(finding, FindingRecord.from_finding(finding)))


def finding_detail_out(finding: Finding, evidence: list[Evidence]) -> FindingDetailOut:
    record = FindingRecord.from_finding(finding)
    state, event = remediation(record)
    plain = record.to_dict()
    return FindingDetailOut(
        **_finding_fields(finding, record), confidence=record.confidence, cves=list(record.cves),
        rule_version=record.rule_version, occurrences=record.occurrences, recurrences=record.recurrences,
        retest_requested_at=record.retest_requested_at, remediation_event=_plain_event(event),
        history=plain["history"], evidence=[evidence_out(finding.project_id, item) for item in evidence],
    )


def _plain_event(event: dict[str, Any] | None) -> dict[str, Any] | None:
    if event is None:
        return None
    return {key: value.isoformat() if isinstance(value, datetime) else value for key, value in event.items()}


# -- runs and alerts ------------------------------------------------------


class StartRunIn(_In):
    targets: list[str] | None = Field(default=None, max_length=100)
    phases: list[RunPhase] | None = None
    reason: str = Field(default="", max_length=2000)


class CancelRunIn(_In):
    reason: str = Field(min_length=3, max_length=2000)


class PhaseStateOut(_Out):
    phase: str
    target: str
    status: str
    comparison: str


class RunOut(_Out):
    run_id: UUID
    kind: str
    status: Literal["queued", "running", "succeeded", "partial", "failed", "cancelled"]
    created_at: datetime
    finished_at: datetime | None
    scope_revision_id: UUID | None
    requested_by: str | None
    reason: str
    job_counts: dict[str, int]
    phases: list[PhaseStateOut]
    last_error: str | None


class JobOut(_Out):
    id: UUID
    kind: str
    status: str
    attempts: int
    max_attempts: int
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    cancel_requested: bool
    last_error: str | None
    result: dict[str, Any] | None


class SnapshotOut(_Out):
    id: UUID
    phase: str
    target: str
    status: str
    comparison: str
    changes: dict[str, Any]
    stats: dict[str, Any]
    pending: list[Any]
    created_at: datetime


class RunDetailOut(_Out):
    run: RunOut
    jobs: list[JobOut]
    snapshots: list[SnapshotOut]


class AlertOut(_Out):
    id: UUID
    channel: str
    event_type: str
    status: str
    attempts: int
    created_at: datetime
    sent_at: datetime | None
    last_error: str | None
    payload: dict[str, Any]


def _value(value: Any) -> Any:
    return getattr(value, "value", value)


def run_out(summary: Any) -> RunOut:
    return RunOut(
        run_id=summary.run_id, kind=summary.kind, status=summary.status, created_at=summary.created_at,
        finished_at=summary.finished_at, scope_revision_id=summary.scope_revision_id,
        requested_by=None if summary.requested_by is None else str(summary.requested_by),
        reason=summary.reason or "", job_counts={str(_value(k)): v for k, v in dict(summary.job_counts).items()},
        phases=[PhaseStateOut(phase=str(_value(p.phase)), target=p.target, status=str(_value(p.status)),
                              comparison=str(_value(p.comparison))) for p in summary.phases],
        last_error=summary.last_error,
    )


def job_out(job: Job) -> JobOut:
    return JobOut(
        id=job.id, kind=job.kind, status=job.status.value, attempts=job.attempts, max_attempts=job.max_attempts,
        created_at=job.created_at, started_at=job.started_at, finished_at=job.finished_at,
        cancel_requested=job.cancel_requested, last_error=job.last_error,
        result=dict(job.result) if job.result is not None else None,
    )


def snapshot_out(snapshot: PhaseSnapshot) -> SnapshotOut:
    return SnapshotOut(
        id=snapshot.id, phase=snapshot.phase.value, target=snapshot.target, status=snapshot.status.value,
        comparison=snapshot.comparison.value, changes=dict(snapshot.changes), stats=dict(snapshot.stats),
        pending=list(snapshot.pending), created_at=snapshot.created_at,
    )


def run_detail_out(detail: Any) -> RunDetailOut:
    return RunDetailOut(run=run_out(detail.summary), jobs=[job_out(job) for job in detail.jobs],
                        snapshots=[snapshot_out(snapshot) for snapshot in detail.snapshots])


def alert_out(notification: Notification) -> AlertOut:
    return AlertOut(
        id=notification.id, channel=notification.channel, event_type=notification.event_type,
        status=notification.status.value, attempts=notification.attempts, created_at=notification.created_at,
        sent_at=notification.sent_at, last_error=notification.last_error, payload=dict(notification.payload),
    )


# -- overview -------------------------------------------------------------


class RuleOut(_Out):
    id: str
    version: str
    kind: str
    title: str
    severity: str
    approved: bool


class OverviewOut(_Out):
    project: ProjectOut
    scope: ScopeRevisionOut | None
    counts: dict[str, Any]
    latest_runs: list[RunOut]
    runs_available: bool
    rules: list[RuleOut]
