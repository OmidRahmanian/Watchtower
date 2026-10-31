"""Finding deduplication, workflow, and retesting.

Five things are tracked separately on each finding:

* severity and confidence come from the rule that detected it;
* priority is set only by ``watchtower.services.prioritization``;
* workflow status (``FindingStatus``) is the human process;
* detection is the latest technical state of the endpoint.

Only a relevant, conclusive negative retest can resolve a finding. Routine
scan negatives, failed checks, and inconclusive checks are recorded but never
change the workflow status. A detection after resolution reopens the finding.

``FindingRecord`` holds the full state. ``to_new_finding`` and
``from_finding`` map it to and from the shared records, with everything the
shared schema has no column for kept under ``details``.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
import hashlib
from typing import Any
from uuid import UUID

from watchtower.adapters.checks.base import CheckResult, Endpoint, Outcome, utcnow
from watchtower.domain.models import AssetKind, Finding, FindingStatus, NewFinding, Severity
from watchtower.domain.repositories import ProjectUnitOfWork
from watchtower.domain.targets import parse_target
from watchtower.services.evidence import EvidenceStore

FINGERPRINT_VERSION = "v1"
RECENT_EVIDENCE = 5

OPEN = {FindingStatus.OPEN, FindingStatus.TRIAGED, FindingStatus.IN_PROGRESS}
# RESOLVED is reached only by a negative retest, and leaving it only by recurrence.
MANUAL_TRANSITIONS = {
    FindingStatus.OPEN: {FindingStatus.TRIAGED, FindingStatus.IN_PROGRESS, FindingStatus.ACCEPTED_RISK, FindingStatus.FALSE_POSITIVE},
    FindingStatus.TRIAGED: {FindingStatus.OPEN, FindingStatus.IN_PROGRESS, FindingStatus.ACCEPTED_RISK, FindingStatus.FALSE_POSITIVE},
    FindingStatus.IN_PROGRESS: {FindingStatus.OPEN, FindingStatus.TRIAGED, FindingStatus.ACCEPTED_RISK, FindingStatus.FALSE_POSITIVE},
    FindingStatus.ACCEPTED_RISK: {FindingStatus.TRIAGED},
    FindingStatus.FALSE_POSITIVE: {FindingStatus.TRIAGED},
    FindingStatus.RESOLVED: set(),
}
NEEDS_REASON = {FindingStatus.ACCEPTED_RISK, FindingStatus.FALSE_POSITIVE}


class FindingError(ValueError):
    pass


class IrrelevantRetest(FindingError):
    pass


def fingerprint(check_id: str, target: Endpoint, location: str, variant: str = "") -> str:
    """Stable identity: canonical rule id, hostname-based endpoint, location, and variant.

    Rule versions, resolved IPs, evidence, and severity are deliberately excluded.
    """
    key = "|".join((FINGERPRINT_VERSION, check_id, target.identity, location, variant))
    return hashlib.sha256(key.encode()).hexdigest()


@dataclass(slots=True)
class Detection:
    state: str = "present"
    last_outcome: Outcome = Outcome.DETECTED
    last_outcome_at: datetime | None = None
    last_conclusive_at: datetime | None = None


def _plain(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    return value


@dataclass(slots=True)
class FindingRecord:
    fingerprint: str
    check_id: str
    target: Endpoint
    location: str
    variant: str
    title: str
    severity: Severity
    confidence: str
    cves: tuple[str, ...]
    rule_version: str
    first_seen: datetime
    last_seen: datetime
    status: FindingStatus = FindingStatus.OPEN
    status_changed_at: datetime | None = None
    detection: Detection = field(default_factory=Detection)
    priority: dict | None = None
    occurrences: int = 1
    recurrences: int = 0
    first_evidence: str | None = None
    recent_evidence: list[str] = field(default_factory=list)
    resolution_evidence: str | None = None
    retest_requested_at: datetime | None = None
    history: list[dict] = field(default_factory=list)
    owner: str = ""
    remediation_notes: str = ""
    mitigation_notes: str = ""
    risk_expires_at: datetime | None = None
    priority_override: dict | None = None

    @property
    def is_open(self) -> bool:
        return self.status in OPEN

    def to_dict(self) -> dict:
        data = _plain(asdict(self))
        data["target"] = {"identity": self.target.identity, "host": self.target.host,
                          "scheme": self.target.scheme, "port": self.target.port,
                          "resolved_ip": self.target.resolved_ip}
        return data

    def to_new_finding(self, asset_id: UUID, scope_revision_id: UUID | None = None) -> NewFinding:
        """Map onto the shared record; status is applied separately with ``set_status``."""
        details = self.to_dict()
        for key in ("fingerprint", "title", "severity", "status"):
            details.pop(key)
        return NewFinding(asset_id=asset_id, fingerprint=self.fingerprint, title=self.title,
                          severity=self.severity, source=self.check_id, details=details,
                          observed_at=self.last_seen, scope_revision_id=scope_revision_id)


    @classmethod
    def from_finding(cls, finding: Finding) -> FindingRecord:
        """Rebuild the full record from a stored shared ``Finding``."""
        details = finding.details

        def moment(value: str | None) -> datetime | None:
            return datetime.fromisoformat(value) if value else None

        detection = details["detection"]
        target = details["target"]
        return cls(
            fingerprint=finding.fingerprint, check_id=details["check_id"],
            target=Endpoint(target["host"], target["scheme"], target["port"], target.get("resolved_ip")),
            location=details["location"], variant=details["variant"], title=finding.title,
            severity=finding.severity, confidence=details["confidence"], cves=tuple(details["cves"]),
            rule_version=details["rule_version"], first_seen=moment(details["first_seen"]),
            last_seen=moment(details["last_seen"]), status=finding.status,
            status_changed_at=finding.status_changed_at,
            detection=Detection(detection["state"], Outcome(detection["last_outcome"]),
                                moment(detection["last_outcome_at"]), moment(detection["last_conclusive_at"])),
            priority=details.get("priority"), occurrences=details["occurrences"],
            recurrences=details["recurrences"], first_evidence=details["first_evidence"],
            recent_evidence=list(details["recent_evidence"]), resolution_evidence=details["resolution_evidence"],
            retest_requested_at=moment(details["retest_requested_at"]), history=list(details["history"]),
            owner=details.get("owner", ""), remediation_notes=details.get("remediation_notes", ""),
            mitigation_notes=details.get("mitigation_notes", ""), risk_expires_at=moment(details.get("risk_expires_at")),
            priority_override=details.get("priority_override"),
        )


class InMemoryFindingStore:
    def __init__(self) -> None:
        self._items: dict[str, FindingRecord] = {}

    def get(self, key: str) -> FindingRecord | None:
        return self._items.get(key)

    def put(self, finding: FindingRecord) -> None:
        self._items[finding.fingerprint] = finding

    def __iter__(self) -> Iterator[FindingRecord]:
        return iter(list(self._items.values()))

    def __len__(self) -> int:
        return len(self._items)


class RepositoryFindingStore:
    """Keeps records in the shared ``FindingRepository``.

    ``upsert`` replaces details wholesale, so every write sends the complete
    record that was read back with ``get_by_fingerprint`` and changed here.
    """

    def __init__(self, uow: ProjectUnitOfWork, scope_revision_id: UUID | None = None,
                 asset_for: Callable[[Endpoint], UUID] | None = None) -> None:
        self.uow = uow
        self.scope_revision_id = scope_revision_id
        self.asset_for = asset_for or self._hostname_asset

    def _hostname_asset(self, target: Endpoint) -> UUID:
        kind = AssetKind.IP_ADDRESS if parse_target(target.host).is_ip else AssetKind.HOSTNAME
        asset, _ = self.uow.assets.upsert(kind, target.host, scope_revision_id=self.scope_revision_id)
        return asset.id

    def get(self, key: str) -> FindingRecord | None:
        found = self.uow.findings.get_by_fingerprint(key)
        return FindingRecord.from_finding(found) if found else None

    def put(self, finding: FindingRecord) -> None:
        stored, _ = self.uow.findings.upsert(finding.to_new_finding(self.asset_for(finding.target),
                                                                    self.scope_revision_id))
        if stored.status != finding.status:
            self.uow.findings.set_status(stored.id, finding.status)


class FindingService:
    def __init__(self, store: InMemoryFindingStore | RepositoryFindingStore | None = None, evidence: EvidenceStore | None = None,
                 canonical_id: Callable[[str], str] = lambda rule_id: rule_id) -> None:
        self.store = store if store is not None else InMemoryFindingStore()
        self.evidence = evidence if evidence is not None else EvidenceStore()
        self.canonical_id = canonical_id

    def fingerprint_for(self, result: CheckResult) -> str:
        return fingerprint(self.canonical_id(result.check_id), result.target, result.location, result.variant)

    def get(self, key: str) -> FindingRecord:
        finding = self.store.get(key)
        if finding is None:
            raise FindingError(f"unknown finding {key}")
        return finding

    def _event(self, finding: FindingRecord, at: datetime, kind: str, **details: Any) -> None:
        finding.history.append({"at": at, "event": kind, **details})

    def _set_status(self, finding: FindingRecord, status: FindingStatus, at: datetime, kind: str,
                    **details: Any) -> None:
        old, finding.status, finding.status_changed_at = finding.status, status, at
        self._event(finding, at, kind, old=old.value, new=status.value, **details)

    def _record_outcome(self, finding: FindingRecord, result: CheckResult) -> str | None:
        finding.detection.last_outcome = result.outcome
        finding.detection.last_outcome_at = result.observed_at
        if result.outcome.conclusive:
            finding.detection.state = "present" if result.outcome == Outcome.DETECTED else "absent"
            finding.detection.last_conclusive_at = result.observed_at
        return self.evidence.add(result.evidence) if result.evidence else None

    def _detected(self, finding: FindingRecord, result: CheckResult, evidence_id: str | None, source: str) -> None:
        finding.last_seen = max(finding.last_seen, result.observed_at)
        finding.target = result.target
        finding.occurrences += 1
        finding.rule_version = result.rule_version
        finding.confidence = result.confidence
        if finding.severity != result.severity:
            self._event(finding, result.observed_at, "severity_changed", old=finding.severity.value,
                        new=result.severity.value, rule_version=result.rule_version)
            finding.severity = result.severity
        if evidence_id:
            finding.recent_evidence = (finding.recent_evidence + [evidence_id])[-RECENT_EVIDENCE:]
        if finding.status == FindingStatus.RESOLVED:
            finding.recurrences += 1
            finding.resolution_evidence = None
            self._set_status(finding, FindingStatus.OPEN, result.observed_at, "reopened", source=source,
                             evidence=evidence_id)
        else:
            self._event(finding, result.observed_at, "detected", source=source, evidence=evidence_id)

    def ingest(self, result: CheckResult) -> FindingRecord | None:
        """Apply a routine scan result. Scan negatives never resolve a finding."""
        key = self.fingerprint_for(result)
        finding = self.store.get(key)
        if finding is None:
            if result.outcome != Outcome.DETECTED:
                return None
            evidence_id = self.evidence.add(result.evidence) if result.evidence else None
            finding = FindingRecord(
                fingerprint=key, check_id=self.canonical_id(result.check_id), target=result.target,
                location=result.location, variant=result.variant, title=result.title, severity=result.severity,
                confidence=result.confidence, cves=tuple(result.cves), rule_version=result.rule_version,
                first_seen=result.observed_at, last_seen=result.observed_at, status_changed_at=result.observed_at,
                first_evidence=evidence_id, recent_evidence=[evidence_id] if evidence_id else [],
                detection=Detection("present", result.outcome, result.observed_at, result.observed_at),
            )
            self._event(finding, result.observed_at, "created", evidence=evidence_id)
            self.store.put(finding)
            return finding
        evidence_id = self._record_outcome(finding, result)
        if result.outcome == Outcome.DETECTED:
            self._detected(finding, result, evidence_id, "scan")
        else:
            self._event(finding, result.observed_at, f"scan_{result.outcome.value}", evidence=evidence_id,
                        detail=result.detail)
        self.store.put(finding)
        return finding

    def request_retest(self, key: str, actor: str, now: datetime | None = None) -> FindingRecord:
        finding = self.get(key)
        now = now or utcnow()
        finding.retest_requested_at = now
        self._event(finding, now, "retest_requested", actor=actor)
        self.store.put(finding)
        return finding

    def apply_retest(self, key: str, result: CheckResult) -> FindingRecord:
        """Apply a retest. Only a conclusive negative from the same check and endpoint resolves."""
        finding = self.get(key)
        if self.canonical_id(result.check_id) != finding.check_id:
            raise IrrelevantRetest(f"retest ran {result.check_id}, finding needs {finding.check_id}")
        if self.fingerprint_for(result) != key:
            raise IrrelevantRetest("retest targeted a different endpoint, location, or variant")
        if result.observed_at < finding.last_seen:
            raise IrrelevantRetest("retest result predates the latest detection")
        evidence_id = self._record_outcome(finding, result)
        if result.outcome == Outcome.DETECTED:
            finding.retest_requested_at = None
            self._detected(finding, result, evidence_id, "retest")
        elif result.outcome == Outcome.NOT_DETECTED:
            finding.retest_requested_at = None
            if finding.status in (FindingStatus.RESOLVED, FindingStatus.FALSE_POSITIVE):
                self._event(finding, result.observed_at, "retest_not_detected", evidence=evidence_id)
            else:
                finding.resolution_evidence = evidence_id
                self._set_status(finding, FindingStatus.RESOLVED, result.observed_at, "resolved",
                                 evidence=evidence_id, rule_version=result.rule_version)
        else:
            # Failed or inconclusive retests keep the request pending and prove nothing.
            self._event(finding, result.observed_at, f"retest_{result.outcome.value}", evidence=evidence_id,
                        detail=result.detail)
        self.store.put(finding)
        return finding

    def transition(self, key: str, status: FindingStatus, actor: str, reason: str = "",
                   now: datetime | None = None, risk_expires_at: datetime | None = None) -> FindingRecord:
        finding = self.get(key)
        status = FindingStatus(status)
        if status not in MANUAL_TRANSITIONS[finding.status]:
            raise FindingError(f"cannot move from {finding.status.value} to {status.value} manually")
        if status in NEEDS_REASON and not reason.strip():
            raise FindingError(f"{status.value} requires a reason")
        moment = now or utcnow()
        if risk_expires_at is not None and (risk_expires_at.utcoffset() is None or risk_expires_at <= moment
                                            or status != FindingStatus.ACCEPTED_RISK):
            raise FindingError("risk expiry must be a future timezone-aware date for accepted risk")
        finding.risk_expires_at = risk_expires_at if status == FindingStatus.ACCEPTED_RISK else None
        self._set_status(finding, status, now or utcnow(), "status_changed", actor=actor, reason=reason)
        self.store.put(finding)
        return finding

    def annotate(self, key: str, actor: str, *, owner: str | None = None, remediation_notes: str | None = None,
                 mitigation_notes: str | None = None, priority: str | None = None, reason: str = "") -> FindingRecord:
        finding = self.get(key)
        changes = {}
        for name, value in (("owner", owner), ("remediation_notes", remediation_notes), ("mitigation_notes", mitigation_notes)):
            if value is not None:
                if len(value) > 4000:
                    raise FindingError("annotation exceeds 4000 characters")
                changes[name] = {"before": getattr(finding, name), "after": value.strip()}
                setattr(finding, name, value.strip())
        if priority is not None:
            if priority not in ("P1", "P2", "P3", "P4", "clear") or not reason.strip():
                raise FindingError("priority override requires P1-P4 (or clear) and a reason")
            finding.priority_override = None if priority == "clear" else {"level": priority, "reason": reason, "actor": actor,
                                                                         "at": utcnow().isoformat()}
            changes["priority_override"] = finding.priority_override
        self._event(finding, utcnow(), "annotated", actor=actor, changes=changes, reason=reason)
        self.store.put(finding)
        return finding

    def expire_risk(self, key: str, now: datetime | None = None) -> FindingRecord:
        finding = self.get(key)
        now = now or utcnow()
        if finding.status == FindingStatus.ACCEPTED_RISK and finding.risk_expires_at and finding.risk_expires_at <= now:
            self._set_status(finding, FindingStatus.TRIAGED, now, "risk_acceptance_expired", actor="policy")
            finding.risk_expires_at = None
            self.store.put(finding)
        return finding

    def set_priority(self, key: str, priority: dict) -> FindingRecord:
        finding = self.get(key)
        finding.priority = priority
        self.store.put(finding)
        return finding
