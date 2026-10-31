"""Paginated read queries for the API and CLI.

The shared repositories cover single-record access and short lists. Listings
that need stable keyset paging live here instead. Every query runs on a
``PgProjectUnitOfWork`` connection, so row-level security already confines it
to one project; the explicit ``project_id`` filter keeps that true even for a
role that bypasses RLS.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import and_, func, or_, select, tuple_

from watchtower.domain.models import Asset, AssetKind, Finding, FindingStatus, Notification, Severity
from watchtower.persistence.database import PgProjectUnitOfWork
from watchtower.persistence.repositories.queue import _notification
from watchtower.persistence.repositories.records import _asset, _finding
from watchtower.persistence.tables import assets, findings, notifications


def list_assets(
    uow: PgProjectUnitOfWork,
    *,
    limit: int,
    kind: AssetKind | None = None,
    search: str | None = None,
    after: tuple[str, str] | None = None,
    owner: str | None = None,
    tag: str | None = None,
    technology: str | None = None,
) -> list[Asset]:
    """Assets ordered by ``(kind, value)``; ``after`` is the last row's ``(kind, value)``."""
    query = select(assets).where(assets.c.project_id == uow.project_id)
    if kind is not None:
        query = query.where(assets.c.kind == AssetKind(kind).value)
    if search:
        query = query.where(assets.c.value.contains(search.lower(), autoescape=True))
    if owner is not None:
        query = query.where(assets.c.attributes["owner"].astext == owner)
    if tag is not None:
        query = query.where(assets.c.attributes["tags"].contains([tag]))
    if technology:
        query = query.where(assets.c.attributes["last_http"]["headers"]["server"].astext.ilike("%" + technology + "%"))
    if after is not None:
        query = query.where(tuple_(assets.c.kind, assets.c.value) > tuple_(*after))
    rows = uow.connection.execute(query.order_by(assets.c.kind, assets.c.value).limit(limit))
    return [_asset(row) for row in rows]


def list_findings(
    uow: PgProjectUnitOfWork,
    *,
    limit: int,
    statuses: Sequence[FindingStatus] = (),
    severities: Sequence[Severity] = (),
    asset_id: UUID | None = None,
    before: tuple[datetime, UUID] | None = None,
    owner: str | None = None,
    confidence: str | None = None,
    priority: str | None = None,
) -> list[Finding]:
    """Newest activity first, ordered by ``(last_seen_at, id)`` descending."""
    query = select(findings).where(findings.c.project_id == uow.project_id)
    if statuses:
        query = query.where(findings.c.status.in_([FindingStatus(s).value for s in statuses]))
    if severities:
        query = query.where(findings.c.severity.in_([Severity(s).value for s in severities]))
    if asset_id is not None:
        query = query.where(findings.c.asset_id == asset_id)
    if owner is not None:
        query = query.where(findings.c.details["owner"].astext == owner)
    if confidence:
        query = query.where(findings.c.details["confidence"].astext == confidence)
    if priority:
        query = query.where(func.coalesce(findings.c.details["priority_override"]["level"].astext,
                                          findings.c.details["priority"]["level"].astext) == priority)
    if before is not None:
        moment, finding_id = before
        query = query.where(
            or_(
                findings.c.last_seen_at < moment,
                and_(findings.c.last_seen_at == moment, findings.c.id < finding_id),
            )
        )
    query = query.order_by(findings.c.last_seen_at.desc(), findings.c.id.desc()).limit(limit)
    return [_finding(row) for row in uow.connection.execute(query)]


def list_alerts(
    uow: PgProjectUnitOfWork,
    *,
    limit: int,
    event_types: Sequence[str] = (),
    before: tuple[datetime, UUID] | None = None,
) -> list[Notification]:
    """The notification outbox, newest first."""
    query = select(notifications).where(notifications.c.project_id == uow.project_id)
    if event_types:
        query = query.where(notifications.c.event_type.in_(list(event_types)))
    if before is not None:
        moment, notification_id = before
        query = query.where(
            or_(
                notifications.c.created_at < moment,
                and_(notifications.c.created_at == moment, notifications.c.id < notification_id),
            )
        )
    query = query.order_by(notifications.c.created_at.desc(), notifications.c.id.desc()).limit(limit)
    return [_notification(row) for row in uow.connection.execute(query)]


def counts(uow: PgProjectUnitOfWork) -> dict[str, Any]:
    """Totals for the overview: assets by kind, findings by status and by open severity."""
    asset_rows = uow.connection.execute(
        select(assets.c.kind, func.count())
        .where(assets.c.project_id == uow.project_id)
        .group_by(assets.c.kind)
    )
    finding_rows = uow.connection.execute(
        select(findings.c.status, findings.c.severity, func.count())
        .where(findings.c.project_id == uow.project_id)
        .group_by(findings.c.status, findings.c.severity)
    )
    by_status: Counter[str] = Counter()
    open_by_severity: Counter[str] = Counter()
    for status, severity, count in finding_rows:
        by_status[status] += count
        if status in (FindingStatus.OPEN, FindingStatus.TRIAGED, FindingStatus.IN_PROGRESS):
            open_by_severity[severity] += count
    return {
        "assets": {kind: count for kind, count in asset_rows},
        "findings_by_status": {status.value: by_status.get(status.value, 0) for status in FindingStatus},
        "open_findings_by_severity": {s.value: open_by_severity.get(s.value, 0) for s in Severity},
    }
