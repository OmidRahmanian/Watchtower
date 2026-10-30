"""Import the legacy MongoDB inventory into PostgreSQL.

The legacy deployment keeps one MongoDB database per target, named after the
target with dots replaced by hyphens (``example-com``), with three
collections:

* ``all``: discovered names ``{subdomain, date: "YYYY/MM/DD", provider}``
* ``resolve``: names that resolved ``{subdomain, date, resolver}``
* ``httpx``: the latest HTTP snapshot ``{subdomain, status_code, title, tech,
  bodymd5, last_change, action}``

Targets and exclusions come from the legacy ``targets.json``. Each target
becomes a project (slug ``legacy-<database name>``) whose first scope
revision includes the target and its subdomains and excludes the listed
out-of-scope hosts. That revision is recorded as a ``legacy_import``
authorization granted by the operator who runs the import, so the import
refuses to run without ``authorized_by``. If the project already has a
scope revision, it is reused.

Every record is checked against the project's scope: out-of-scope, excluded,
prohibited and malformed names are counted and skipped. Each record's Mongo
``_id`` becomes the observation's ``source_ref``, so re-running the import
adds nothing twice. ``dry_run`` reports the same counts without writing.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol
from uuid import UUID, uuid4

from watchtower.domain.errors import InvalidTarget
from watchtower.domain.models import AssetKind, NewObservation, ObservationKind
from watchtower.domain.scope import (
    AuthorizationKind,
    AuthorizationReference,
    NewScopeRevision,
    RuleEffect,
    ScopePolicy,
    ScopeRevision,
    ScopeRule,
)
from watchtower.domain.targets import PortSet, canonical_hostname
from watchtower.persistence.database import Database
from watchtower.security.destinations import DestinationPolicy

BATCH_SIZE = 500
SYSTEM_DATABASES = frozenset({"admin", "config", "local", "programs_watcher"})


class MongoClientLike(Protocol):
    def list_database_names(self) -> list[str]: ...

    def __getitem__(self, name: str) -> Any: ...


@dataclass(frozen=True)
class LegacyTarget:
    domain: str
    report_url: str = ""
    out_of_scope: tuple[str, ...] = ()

    @property
    def mongo_database(self) -> str:
        return self.domain.replace(".", "-")

    @property
    def project_slug(self) -> str:
        slug = f"legacy-{self.mongo_database}".replace("_", "-")
        if len(slug) > 63:
            digest = hashlib.sha256(self.domain.encode()).hexdigest()[:8]
            slug = f"{slug[:54].rstrip('-')}-{digest}"
        return slug


@dataclass
class TargetReport:
    domain: str
    project_slug: str
    project_id: UUID | None = None
    scope_revision: int | None = None
    scope_created: bool = False
    assets_created: int = 0
    observations_created: int = 0
    duplicates: int = 0
    out_of_scope: int = 0
    invalid: int = 0
    invalid_exclusions: list[str] = field(default_factory=list)


@dataclass
class ImportReport:
    dry_run: bool
    targets: list[TargetReport] = field(default_factory=list)
    unmapped_databases: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "dry_run": self.dry_run,
            "unmapped_databases": self.unmapped_databases,
            "targets": [
                {key: str(value) if isinstance(value, UUID) else value for key, value in vars(t).items()}
                for t in self.targets
            ],
        }


def load_legacy_targets(path: Path) -> list[LegacyTarget]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, Mapping):
        raise ValueError(f"{path} must contain a JSON object of targets")
    targets: list[LegacyTarget] = []
    for domain, options in raw.items():
        if not domain:
            continue
        options = options if isinstance(options, Mapping) else {}
        targets.append(
            LegacyTarget(
                domain=canonical_hostname(domain),
                report_url=str(options.get("report_url") or ""),
                out_of_scope=tuple(str(item) for item in options.get("out_of_scope") or ()),
            )
        )
    seen: dict[str, str] = {}
    for target in targets:
        other = seen.setdefault(target.mongo_database, target.domain)
        if other != target.domain:
            raise ValueError(
                f"{other} and {target.domain} share legacy database {target.mongo_database!r}; import them separately"
            )
    return targets


def legacy_scope(target: LegacyTarget, authorized_by: str, permitted_ports: str) -> tuple[NewScopeRevision, list[str]]:
    """The revision describing a legacy target, plus exclusions that could not be parsed."""
    rules = [ScopeRule.parse(target.domain), ScopeRule.parse(f"*.{target.domain}")]
    invalid: list[str] = []
    seen: set[str] = set()
    for entry in target.out_of_scope:
        try:
            rule = ScopeRule.parse(entry, effect=RuleEffect.EXCLUDE)
        except ValueError:
            invalid.append(entry)
            continue
        if rule.value not in seen:
            seen.add(rule.value)
            rules.append(rule)
    authorization = AuthorizationReference(
        kind=AuthorizationKind.LEGACY_IMPORT,
        reference=target.report_url or "legacy WatchTower targets.json",
        granted_by=authorized_by,
        notes="Imported from the legacy MongoDB deployment; confirm and republish with a current authorization.",
    )
    new = NewScopeRevision(tuple(rules), authorization, PortSet.parse(permitted_ports), notes="legacy import")
    return new, invalid


class MongoImporter:
    def __init__(
        self,
        database: Database | None,
        mongo: MongoClientLike,
        *,
        authorized_by: str | None,
        dry_run: bool = False,
        permitted_ports: str = "80,443",
        destinations: DestinationPolicy | None = None,
    ) -> None:
        if not dry_run and not (authorized_by or "").strip():
            raise ValueError("authorized_by is required: name the person attesting the legacy scope is authorized")
        if not dry_run and database is None:
            raise ValueError("a database is required unless dry_run is set")
        self._db = database
        self._mongo = mongo
        self._authorized_by = (authorized_by or "").strip() or "dry run"
        self._dry_run = dry_run
        self._ports = permitted_ports
        self._destinations = destinations or DestinationPolicy()

    def run(self, targets: Iterable[LegacyTarget]) -> ImportReport:
        targets = list(targets)
        report = ImportReport(dry_run=self._dry_run)
        available = set(self._mongo.list_database_names())
        mapped = {target.mongo_database for target in targets}
        report.unmapped_databases = sorted(available - mapped - SYSTEM_DATABASES)
        for target in targets:
            report.targets.append(self._import_target(target, present=target.mongo_database in available))
        return report

    def _import_target(self, target: LegacyTarget, *, present: bool) -> TargetReport:
        result = TargetReport(domain=target.domain, project_slug=target.project_slug)
        new_scope, result.invalid_exclusions = legacy_scope(target, self._authorized_by, self._ports)
        if self._dry_run:
            policy = self._preview_policy(new_scope)
            for _, record in self._records(target, present):
                if self._accept(policy, record, result):
                    result.observations_created += 1
            return result

        project_id, revision = self._ensure_project(target, new_scope, result)
        policy = ScopePolicy(project_id, revision, destinations=self._destinations)
        batch: list[tuple[str, dict[str, Any]]] = []
        for item in self._records(target, present):
            batch.append(item)
            if len(batch) >= BATCH_SIZE:
                self._write(target, project_id, policy, batch, result)
                batch.clear()
        if batch:
            self._write(target, project_id, policy, batch, result)
        return result

    def _preview_policy(self, new: NewScopeRevision) -> ScopePolicy:
        project_id = uuid4()
        revision = ScopeRevision(
            id=uuid4(),
            project_id=project_id,
            number=1,
            rules=new.rules,
            authorization=new.authorization,
            permitted_ports=new.permitted_ports,
            created_at=datetime.now(timezone.utc),
        )
        return ScopePolicy(project_id, revision, destinations=self._destinations)

    def _ensure_project(
        self, target: LegacyTarget, new_scope: NewScopeRevision, result: TargetReport
    ) -> tuple[UUID, ScopeRevision]:
        name = f"{target.domain} (legacy import)"
        with self._db.system() as system:
            project = system.projects.get_by_slug(target.project_slug)
            if project is None:
                project = system.projects.create(target.project_slug, name)
            elif project.name != name:
                raise ValueError(f"project {target.project_slug!r} already exists for {project.name!r}")
        result.project_id = project.id
        with self._db.project(project.id) as uow:
            revision = uow.scope.current()
            if revision is None:
                revision = uow.scope.publish(new_scope, created_by=None)
                result.scope_created = True
        result.scope_revision = revision.number
        return project.id, revision

    def _records(self, target: LegacyTarget, present: bool) -> Iterator[tuple[str, dict[str, Any]]]:
        if not present:
            return
        database = self._mongo[target.mongo_database]
        for collection in ("all", "resolve", "httpx"):
            for document in database[collection].find():
                yield collection, document

    def _accept(self, policy: ScopePolicy, document: Mapping[str, Any], result: TargetReport) -> str | None:
        try:
            hostname = canonical_hostname(str(document.get("subdomain", "")))
        except InvalidTarget:
            result.invalid += 1
            return None
        if not policy.check_target(hostname).allowed:
            result.out_of_scope += 1
            return None
        return hostname

    def _write(
        self,
        target: LegacyTarget,
        project_id: UUID,
        policy: ScopePolicy,
        batch: list[tuple[str, dict[str, Any]]],
        result: TargetReport,
    ) -> None:
        with self._db.project(project_id) as uow:
            for collection, document in batch:
                hostname = self._accept(policy, document, result)
                if hostname is None:
                    continue
                kind, source, data, observed_at = _translate(collection, document)
                asset, created = uow.assets.upsert(
                    AssetKind.HOSTNAME, hostname, seen_at=observed_at, scope_revision_id=policy.revision_id
                )
                result.assets_created += int(created)
                _, recorded = uow.observations.record(
                    NewObservation(
                        asset_id=asset.id,
                        kind=kind,
                        source=source,
                        data=data,
                        observed_at=observed_at,
                        scope_revision_id=policy.revision_id,
                        source_ref=f"mongo:{target.mongo_database}/{collection}/{document.get('_id')}",
                    )
                )
                if recorded:
                    result.observations_created += 1
                else:
                    result.duplicates += 1


def _translate(collection: str, document: Mapping[str, Any]) -> tuple[ObservationKind, str, dict[str, Any], datetime]:
    observed_at = _legacy_date(document.get("last_change") or document.get("date"), document.get("_id"))
    if collection == "all":
        provider = str(document.get("provider") or "unknown")
        return ObservationKind.DISCOVERY, provider.lower(), {"provider": provider, "legacy": True}, observed_at
    if collection == "resolve":
        resolver = str(document.get("resolver") or "unknown")
        return ObservationKind.DNS_RESOLUTION, resolver.lower(), {"resolver": resolver, "resolved": True, "legacy": True}, observed_at
    data = {
        "status_code": document.get("status_code"),
        "title": document.get("title"),
        "technologies": document.get("tech"),
        "body_md5": document.get("bodymd5"),
        "last_action": document.get("action"),
        "legacy": True,
    }
    return ObservationKind.HTTP_RESPONSE, "httpx", data, observed_at


def _legacy_date(value: Any, object_id: Any) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str):
        try:
            return datetime.strptime(value, "%Y/%m/%d").replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    generated = getattr(object_id, "generation_time", None)
    if isinstance(generated, datetime):
        return generated
    return datetime.now(timezone.utc)
