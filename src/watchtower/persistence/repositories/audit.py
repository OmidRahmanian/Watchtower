"""Append-only audit trail for security-relevant changes."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any
from uuid import UUID

from sqlalchemy import Connection

from watchtower.persistence.tables import audit_events


def record_audit(
    connection: Connection,
    action: str,
    subject: str,
    *,
    project_id: UUID | None = None,
    actor: UUID | None = None,
    details: Mapping[str, Any] | None = None,
) -> None:
    connection.execute(
        audit_events.insert().values(
            project_id=project_id,
            actor_principal_id=actor,
            action=action,
            subject=subject,
            details=dict(details or {}),
        )
    )
