"""Records shared by every WatchTower component.

Each project-owned record carries ``project_id``. Records named ``New*`` are
inputs: the store assigns identifiers and timestamps. Timestamps are
timezone-aware UTC. ``Mapping`` fields hold JSON-compatible data only.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import UUID

from watchtower.domain.errors import InvalidTarget
from watchtower.domain.targets import canonical_hostname, canonical_ip, canonical_port, parse_target, parse_url

JSON = Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class Project:
    id: UUID
    slug: str
    name: str
    created_at: datetime
    archived_at: datetime | None = None

    @property
    def archived(self) -> bool:
        return self.archived_at is not None


class AssetKind(StrEnum):
    HOSTNAME = "hostname"
    IP_ADDRESS = "ip_address"
    SERVICE = "service"  # value: "<host>:<port>/<tcp|udp>", host canonical, IPv6 bracketed
    URL = "url"  # value: canonical absolute http(s) URL


def service_value(host: str, port: int | str, transport: str = "tcp") -> str:
    """Canonical value for a ``SERVICE`` asset, e.g. ``api.example.com:443/tcp``."""
    if transport not in {"tcp", "udp"}:
        raise InvalidTarget(f"unsupported transport: {transport!r}")
    return f"{parse_target(host).url_host}:{canonical_port(port)}/{transport}"


def canonical_asset_value(kind: AssetKind, value: str) -> str:
    """Canonicalize an asset value for ``kind``; raises ``InvalidTarget``."""
    kind = AssetKind(kind)
    if kind is AssetKind.HOSTNAME:
        return canonical_hostname(value)
    if kind is AssetKind.IP_ADDRESS:
        return str(canonical_ip(value))
    if kind is AssetKind.URL:
        return parse_url(value).geturl()
    host_port, slash, transport = value.rpartition("/")
    host, colon, port = host_port.rpartition(":")
    if not slash or not colon:
        raise InvalidTarget(f"service must look like host:port/tcp, got {value!r}")
    return service_value(host, port, transport)


@dataclass(frozen=True, slots=True)
class Asset:
    id: UUID
    project_id: UUID
    kind: AssetKind
    value: str
    first_seen_at: datetime
    last_seen_at: datetime
    attributes: JSON = field(default_factory=dict)
    scope_revision_id: UUID | None = None  # revision in force when last seen


class ObservationKind(StrEnum):
    DISCOVERY = "discovery"
    DNS_RESOLUTION = "dns_resolution"
    PORT_STATE = "port_state"
    HTTP_RESPONSE = "http_response"
    TLS_CERTIFICATE = "tls_certificate"
    TECHNOLOGY = "technology"


@dataclass(frozen=True, slots=True)
class NewObservation:
    asset_id: UUID
    kind: ObservationKind
    source: str  # tool or provider, e.g. "subfinder", "crtsh", "httpx"
    data: JSON
    observed_at: datetime | None = None  # defaults to now
    job_id: UUID | None = None
    scope_revision_id: UUID | None = None
    source_ref: str | None = None  # idempotency key, unique per project


@dataclass(frozen=True, slots=True)
class Observation:
    """Append-only: an observation is never updated after it is recorded."""

    id: UUID
    project_id: UUID
    asset_id: UUID
    kind: ObservationKind
    source: str
    data: JSON
    observed_at: datetime
    recorded_at: datetime
    job_id: UUID | None = None
    scope_revision_id: UUID | None = None
    source_ref: str | None = None


class JobStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass(frozen=True, slots=True)
class NewJob:
    """``scope_revision_id`` pins the job to the revision that authorized it.

    Workers must still re-check targets against the project's current policy
    when the job runs; a newer or revoked revision takes precedence.
    """

    kind: str
    scope_revision_id: UUID
    payload: JSON = field(default_factory=dict)
    priority: int = 0  # higher runs first
    run_after: datetime | None = None
    max_attempts: int = 3
    idempotency_key: str | None = None  # unique per project while the job exists


@dataclass(frozen=True, slots=True)
class Job:
    id: UUID
    project_id: UUID
    kind: str
    status: JobStatus
    scope_revision_id: UUID
    payload: JSON
    priority: int
    run_after: datetime
    attempts: int
    max_attempts: int
    created_at: datetime
    idempotency_key: str | None = None
    lease_owner: str | None = None
    lease_expires_at: datetime | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    result: JSON | None = None
    last_error: str | None = None


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingStatus(StrEnum):
    OPEN = "open"
    TRIAGED = "triaged"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"


@dataclass(frozen=True, slots=True)
class NewFinding:
    asset_id: UUID
    fingerprint: str  # stable identity for deduplication, unique per project
    title: str
    severity: Severity
    source: str
    details: JSON = field(default_factory=dict)
    observed_at: datetime | None = None
    scope_revision_id: UUID | None = None


@dataclass(frozen=True, slots=True)
class Finding:
    id: UUID
    project_id: UUID
    asset_id: UUID
    fingerprint: str
    title: str
    severity: Severity
    status: FindingStatus
    source: str
    details: JSON
    first_seen_at: datetime
    last_seen_at: datetime
    status_changed_at: datetime
    scope_revision_id: UUID | None = None


@dataclass(frozen=True, slots=True)
class StoredBlob:
    uri: str
    sha256: str
    size_bytes: int


@dataclass(frozen=True, slots=True)
class NewEvidence:
    blob: StoredBlob
    media_type: str
    description: str = ""
    finding_id: UUID | None = None
    observation_id: UUID | None = None


@dataclass(frozen=True, slots=True)
class Evidence:
    id: UUID
    project_id: UUID
    media_type: str
    sha256: str
    size_bytes: int
    storage_uri: str
    created_at: datetime
    description: str = ""
    finding_id: UUID | None = None
    observation_id: UUID | None = None


class NotificationStatus(StrEnum):
    PENDING = "pending"
    SENDING = "sending"
    SENT = "sent"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class NewNotification:
    channel: str  # e.g. "discord", "telegram"
    event_type: str  # e.g. "asset.discovered", "finding.opened"
    dedupe_key: str  # unique per project; re-enqueueing the same key is a no-op
    payload: JSON
    max_attempts: int = 5


@dataclass(frozen=True, slots=True)
class Notification:
    id: UUID
    project_id: UUID
    channel: str
    event_type: str
    dedupe_key: str
    payload: JSON
    status: NotificationStatus
    attempts: int
    max_attempts: int
    created_at: datetime
    next_attempt_at: datetime
    lease_owner: str | None = None
    lease_expires_at: datetime | None = None
    sent_at: datetime | None = None
    last_error: str | None = None
