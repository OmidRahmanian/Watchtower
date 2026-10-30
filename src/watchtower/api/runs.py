"""The run and job service the API and CLI call.

Runs, jobs, phase snapshots and alerts belong to ``watchtower.services.jobs``
(``RunService``). This module only states the shape the interface layer
relies on, so routes can be tested with a stand-in and a missing runtime
degrades to "503 runs are not available" instead of an import error.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Any, Protocol
from uuid import UUID

from watchtower.domain.models import Notification, RunPhase
from watchtower.security.auth import ProjectContext

RUN_STATUSES = ("queued", "running", "succeeded", "partial", "failed", "cancelled")
# A run in one of these states will not change again.
FINISHED_RUN_STATUSES = frozenset({"succeeded", "partial", "failed", "cancelled"})


class RunsPort(Protocol):
    """What ``RunService`` provides. Every method checks the actor's permission itself."""

    def start_run(
        self,
        project_id: UUID,
        *,
        actor: ProjectContext,
        targets: list[str] | None = None,
        phases: list[RunPhase] | None = None,
        reason: str = "",
    ) -> Any: ...

    def cancel_run(self, project_id: UUID, run_id: UUID, *, actor: ProjectContext, reason: str) -> int: ...

    def list_runs(
        self,
        project_id: UUID,
        *,
        actor: ProjectContext,
        limit: int = 50,
        before: tuple[datetime, UUID] | None = None,
    ) -> Sequence[Any]: ...

    def get_run(self, project_id: UUID, run_id: UUID, *, actor: ProjectContext) -> Any: ...

    def request_retest(self, project_id: UUID, fingerprint: str, *, actor: ProjectContext, reason: str = "") -> Any: ...

    def list_notifications(
        self, project_id: UUID, *, actor: ProjectContext, run_id: UUID | None = None, limit: int = 50
    ) -> Sequence[Notification]: ...


def default_runs(database: Any, scope: Any) -> RunsPort | None:
    """``RunService`` when the runtime is installed, else ``None``."""
    try:
        from watchtower.services.jobs import RunService
    except ImportError:
        return None
    return RunService(database, scope)
