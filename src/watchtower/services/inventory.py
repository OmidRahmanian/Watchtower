"""Hostname inventory built on the shared asset and observation repositories.

Assets are identified by their canonical hostname (`AssetKind.HOSTNAME`), so
repeated discoveries, DNS answers and HTTP results attach to the same asset.
Per-source provenance, ownership confidence and the latest authorization
snapshot live in asset attributes. The repository widens first/last seen to
cover every `seen_at` it is given, so historical imports move `first_seen_at`
back and only successful sightings move `last_seen_at` forward. Every sighting, DNS answer and HTTP or
TLS result is appended as an observation. Nothing here deletes an asset, and a
failed lookup or probe never clears what is already known.
"""
from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from watchtower.domain.models import Asset, AssetKind, NewObservation, ObservationKind
from watchtower.domain.repositories import ProjectUnitOfWork
from watchtower.domain.targets import canonical_hostname

# Baseline ownership confidence per source when the source does not supply one.
SOURCE_CONFIDENCE = {
    "manual": 1.0,
    "csv": 0.9,
    "dns": 0.7,
    "subfinder": 0.6,
}
DEFAULT_CONFIDENCE = 0.5


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def isoformat(moment: datetime) -> str:
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_time(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value.replace("Z", "+00:00")) if value else None


def normalize_hostname(value: str) -> str:
    """Canonical A-label hostname with at least two labels; raises ValueError otherwise."""
    name = canonical_hostname(str(value))
    if "." not in name:
        raise ValueError(f"expected a fully qualified hostname, got {value!r}")
    return name


def in_domain(hostname: str, root: str) -> bool:
    return hostname == root or hostname.endswith("." + root)


@dataclass
class DiscoveredName:
    """A hostname reported by a discovery source."""
    hostname: str
    source: str
    root_domain: str = ""
    observed_at: datetime | None = None
    confidence: float | None = None
    detail: dict[str, Any] = field(default_factory=dict)


@dataclass
class IngestStats:
    created: int = 0
    updated: int = 0
    rejected: int = 0
    wildcard_suppressed: int = 0
    errors: list[str] = field(default_factory=list)


def _merge_provenance(
    previous: Mapping[str, Any] | None, seen: str, confidence: float, detail: Mapping[str, Any], job_id: UUID | None,
) -> dict[str, Any]:
    """Fold one sighting into a source's provenance.

    `times_seen` counts sightings, except that repeats within one job (a retry,
    or a duplicate row) count once.
    """
    job = str(job_id) if job_id else None
    if not previous:
        return {"first_seen": seen, "last_seen": seen, "times_seen": 1, "confidence": confidence,
                "detail": dict(detail), "last_job_id": job}
    merged_detail = dict(previous.get("detail", {}))
    for key, value in detail.items():
        earlier = merged_detail.get(key)
        if isinstance(value, list) and isinstance(earlier, list):
            value = sorted(set(earlier) | set(value))
        merged_detail[key] = value
    return {
        "first_seen": min(previous["first_seen"], seen),
        "last_seen": max(previous["last_seen"], seen),
        "times_seen": previous.get("times_seen", 0) + (0 if job and previous.get("last_job_id") == job else 1),
        "confidence": max(previous.get("confidence", 0.0), confidence),
        "detail": merged_detail,
        "last_job_id": job,
    }


class InventoryService:
    """Hostname inventory for one project.

    `policy` is the project's `ScopePolicy` (or anything with `check_target`);
    it is only used to snapshot authorization status and to pin records to
    the scope revision in force. Adapters enforce scope before any traffic.
    """

    def __init__(
        self,
        uow: ProjectUnitOfWork,
        *,
        policy: Any = None,
        job_id: UUID | None = None,
        clock: Callable[[], datetime] = utcnow,
    ) -> None:
        self.uow = uow
        self.policy = policy
        self.job_id = job_id
        self.scope_revision_id: UUID | None = getattr(policy, "revision_id", None)
        self._clock = clock

    def get(self, hostname: str) -> Asset | None:
        return self.uow.assets.find(AssetKind.HOSTNAME, normalize_hostname(hostname))

    def assets(self) -> list[Asset]:
        found: list[Asset] = []
        after: str | None = None
        while True:
            page = list(self.uow.assets.list(kind=AssetKind.HOSTNAME, limit=500, after_value=after))
            found.extend(page)
            if len(page) < 500:
                return found
            after = page[-1].value

    def _authorization(self, hostname: str) -> dict[str, Any]:
        if self.policy is None:
            return {"status": "unknown", "checked_at": isoformat(self._clock())}
        decision = self.policy.check_target(hostname)
        reason = getattr(decision, "reason", "")
        return {
            "status": "authorized" if decision else "unauthorized",
            "reason": str(getattr(reason, "value", reason)),
            "detail": getattr(decision, "detail", ""),
            "revision_id": str(self.scope_revision_id) if self.scope_revision_id else None,
            "checked_at": isoformat(self._clock()),
        }

    def _record(self, asset: Asset, kind: ObservationKind, source: str, observed_at: datetime, data: Mapping[str, Any]) -> None:
        # Within a job, a retried write of the same result is deduplicated by source_ref.
        source_ref = f"{self.job_id}:{kind}:{source}:{asset.value}:{isoformat(observed_at)}" if self.job_id else None
        self.uow.observations.record(NewObservation(
            asset_id=asset.id,
            kind=kind,
            source=source,
            data=dict(data),
            observed_at=observed_at,
            job_id=self.job_id,
            scope_revision_id=self.scope_revision_id,
            source_ref=source_ref,
        ))

    def record_discovery(self, name: DiscoveredName) -> tuple[Asset, bool]:
        """Create or refresh the asset for a discovered name and record the sighting."""
        hostname = normalize_hostname(name.hostname)
        root = normalize_hostname(name.root_domain) if name.root_domain else hostname
        if not in_domain(hostname, root):
            raise ValueError(f"{hostname} is not within {root}")
        observed_at = name.observed_at or self._clock()
        seen = isoformat(observed_at)
        confidence = name.confidence if name.confidence is not None else SOURCE_CONFIDENCE.get(name.source, DEFAULT_CONFIDENCE)
        confidence = min(max(float(confidence), 0.0), 1.0)

        existing = self.uow.assets.find(AssetKind.HOSTNAME, hostname)
        attributes = dict(existing.attributes) if existing else {}
        provenance = dict(attributes.get("provenance", {}))
        provenance[name.source] = _merge_provenance(provenance.get(name.source), seen, confidence, name.detail, self.job_id)
        known_root = attributes.get("root_domain")
        if known_root and len(known_root) < len(root):
            root = known_root

        asset, created = self.uow.assets.upsert(
            AssetKind.HOSTNAME,
            hostname,
            seen_at=observed_at,
            attributes={
                "root_domain": root,
                "provenance": provenance,
                "ownership_confidence": max(entry["confidence"] for entry in provenance.values()),
                "authorization": self._authorization(hostname),
            },
            scope_revision_id=self.scope_revision_id,
        )
        self._record(asset, ObservationKind.DISCOVERY, name.source, observed_at,
                     {"root_domain": root, "confidence": confidence, **name.detail})
        return asset, created

    def ingest(self, names: Iterable[DiscoveredName]) -> IngestStats:
        stats = IngestStats()
        for name in names:
            try:
                _, created = self.record_discovery(name)
            except ValueError as exc:
                stats.rejected += 1
                stats.errors.append(str(exc))
                continue
            if created:
                stats.created += 1
            else:
                stats.updated += 1
        return stats

    def record_dns(self, observation: Mapping[str, Any], *, create_missing: bool = False, root_domain: str = "") -> tuple[Asset | None, bool]:
        """Append a DNS observation (see adapters.discovery.dns) to its asset.

        With `create_missing`, a name that resolves outside any wildcard becomes a
        new asset with "dns" provenance. A wildcard answer, or one whose wildcard
        check was inconclusive, never creates an asset. A failed lookup keeps the
        last known addresses.
        """
        hostname = normalize_hostname(observation["hostname"])
        observed_at = parse_time(observation.get("observed_at")) or self._clock()
        resolved = observation.get("status") == "resolved"
        asset = self.uow.assets.find(AssetKind.HOSTNAME, hostname)
        created = False
        if asset is None:
            if not (create_missing and resolved and not observation.get("wildcard") and not observation.get("wildcard_unknown")):
                return None, False
            asset, created = self.record_discovery(DiscoveredName(hostname, "dns", root_domain=root_domain, observed_at=observed_at))

        data = dict(observation)
        previous = list(asset.attributes.get("addresses", []))
        attributes: dict[str, Any] = {"dns_status": observation.get("status", "")}
        if resolved:
            addresses = sorted(set(observation.get("a", [])) | set(observation.get("aaaa", [])))
            data["previous_addresses"] = previous
            data["address_changed"] = bool(previous) and addresses != previous
            attributes["addresses"] = addresses
        asset, _ = self.uow.assets.upsert(
            AssetKind.HOSTNAME,
            hostname,
            seen_at=observed_at if resolved else asset.last_seen_at,
            attributes=attributes,
            scope_revision_id=self.scope_revision_id,
        )
        self._record(asset, ObservationKind.DNS_RESOLUTION, "dns", observed_at, data)
        return asset, created

    def ingest_dns(self, observations: Iterable[Mapping[str, Any]], *, create_missing: bool = False, root_domain: str = "") -> IngestStats:
        stats = IngestStats()
        for observation in observations:
            asset, created = self.record_dns(observation, create_missing=create_missing, root_domain=root_domain)
            if asset is None:
                if observation.get("wildcard") or observation.get("wildcard_unknown"):
                    stats.wildcard_suppressed += 1
                else:
                    stats.rejected += 1
            elif created:
                stats.created += 1
            else:
                stats.updated += 1
        return stats

    def record_http(self, observation: Mapping[str, Any]) -> Asset | None:
        """Append an HTTP probe result (see adapters.probing.http) to an existing asset.

        Errors and refusals are kept as observations; the asset stays in place
        and only a successful response counts as seeing it again.
        """
        asset = self.uow.assets.find(AssetKind.HOSTNAME, normalize_hostname(observation["hostname"]))
        if asset is None:
            return None
        observed_at = parse_time(observation.get("observed_at")) or self._clock()
        self._record(asset, ObservationKind.HTTP_RESPONSE, "http", observed_at, observation)
        tls = observation.get("tls")
        if tls:
            self._record(asset, ObservationKind.TLS_CERTIFICATE, "http", observed_at, {"url": observation.get("url"), **tls})
        summary = {key: observation.get(key) for key in ("url", "outcome", "status_code", "title", "ip", "body_sha256", "error")}
        ok = observation.get("outcome") == "ok"
        asset, _ = self.uow.assets.upsert(
            AssetKind.HOSTNAME,
            asset.value,
            seen_at=observed_at if ok else asset.last_seen_at,
            attributes={"last_http": {**summary, "observed_at": isoformat(observed_at)}},
            scope_revision_id=self.scope_revision_id,
        )
        return asset
