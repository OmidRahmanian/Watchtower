"""SQLAlchemy Core table definitions.

This module mirrors the schema the Alembic migrations create; a test compares
the two. Project-owned tables carry ``project_id`` and reference each other
through composite ``(project_id, id)`` foreign keys, so a row can never point
at a row in another project. Row-level security, append-only triggers and
check constraints on enum columns live in the migrations.
"""

from __future__ import annotations

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    Column,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    MetaData,
    PrimaryKeyConstraint,
    Table,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, TIMESTAMP, UUID

NAMING_CONVENTION = {
    "ix": "ix_%(table_name)s_%(column_0_N_name)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_N_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

metadata = MetaData(naming_convention=NAMING_CONVENTION)

# Tables protected by the ``project_isolation`` row-level security policy.
PROJECT_SCOPED_TABLES = (
    "scope_revisions",
    "scope_rules",
    "scope_revocations",
    "assets",
    "jobs",
    "observations",
    "findings",
    "evidence",
    "notifications",
    "run_cancellations",
    "phase_snapshots",
)


def _ts(name: str, *, nullable: bool = False, now: bool = False) -> Column:
    return Column(
        name,
        TIMESTAMP(timezone=True),
        nullable=nullable,
        server_default=text("now()") if now else None,
    )


def _id() -> Column:
    return Column("id", UUID(as_uuid=True), nullable=False)


def _project() -> Column:
    return Column("project_id", UUID(as_uuid=True), ForeignKey("projects.id"), nullable=False)


projects = Table(
    "projects",
    metadata,
    _id(),
    Column("slug", Text, nullable=False),
    Column("name", Text, nullable=False),
    _ts("created_at", now=True),
    _ts("archived_at", nullable=True),
    PrimaryKeyConstraint("id"),
    UniqueConstraint("slug"),
    CheckConstraint(r"slug ~ '^[a-z0-9][a-z0-9-]{0,62}$'", name="slug_format"),
)

principals = Table(
    "principals",
    metadata,
    _id(),
    Column("kind", Text, nullable=False),
    Column("display_name", Text, nullable=False),
    Column("email", Text, nullable=True),
    _ts("created_at", now=True),
    _ts("disabled_at", nullable=True),
    PrimaryKeyConstraint("id"),
    UniqueConstraint("email"),
    CheckConstraint("kind IN ('user', 'service')", name="kind"),
)

project_memberships = Table(
    "project_memberships",
    metadata,
    _project(),
    Column("principal_id", UUID(as_uuid=True), ForeignKey("principals.id"), nullable=False),
    Column("role", Text, nullable=False),
    _ts("created_at", now=True),
    PrimaryKeyConstraint("project_id", "principal_id"),
    CheckConstraint("role IN ('viewer', 'operator', 'owner')", name="role"),
)

api_tokens = Table(
    "api_tokens",
    metadata,
    _id(),
    Column("principal_id", UUID(as_uuid=True), ForeignKey("principals.id"), nullable=False),
    Column("project_id", UUID(as_uuid=True), ForeignKey("projects.id"), nullable=True),
    Column("name", Text, nullable=False),
    Column("prefix", Text, nullable=False),
    Column("token_hash", Text, nullable=False),
    _ts("created_at", now=True),
    _ts("expires_at", nullable=True),
    _ts("revoked_at", nullable=True),
    _ts("last_used_at", nullable=True),
    PrimaryKeyConstraint("id"),
    UniqueConstraint("prefix"),
    UniqueConstraint("token_hash"),
)

audit_events = Table(
    "audit_events",
    metadata,
    Column("id", BigInteger, primary_key=True, autoincrement=True),
    Column("project_id", UUID(as_uuid=True), ForeignKey("projects.id"), nullable=True),
    Column("actor_principal_id", UUID(as_uuid=True), ForeignKey("principals.id"), nullable=True),
    Column("action", Text, nullable=False),
    Column("subject", Text, nullable=False),
    Column("details", JSONB, nullable=False, server_default=text("'{}'::jsonb")),
    _ts("occurred_at", now=True),
    Index(None, "project_id", "occurred_at"),
)

scope_revisions = Table(
    "scope_revisions",
    metadata,
    _id(),
    _project(),
    Column("number", Integer, nullable=False),
    Column("authorization_kind", Text, nullable=False),
    Column("authorization_reference", Text, nullable=False),
    Column("granted_by", Text, nullable=False),
    _ts("valid_from", nullable=True),
    _ts("valid_until", nullable=True),
    Column("permitted_ports", Text, nullable=False),
    Column("notes", Text, nullable=False, server_default=""),
    _ts("created_at", now=True),
    Column("created_by", UUID(as_uuid=True), ForeignKey("principals.id"), nullable=True),
    PrimaryKeyConstraint("id"),
    UniqueConstraint("project_id", "number"),
    UniqueConstraint("project_id", "id"),
    CheckConstraint("number > 0", name="number_positive"),
    CheckConstraint("length(trim(authorization_reference)) > 0", name="reference_present"),
    CheckConstraint("length(trim(granted_by)) > 0", name="granted_by_present"),
    CheckConstraint("valid_until IS NULL OR valid_from IS NULL OR valid_until > valid_from", name="validity_window"),
)

scope_rules = Table(
    "scope_rules",
    metadata,
    _id(),
    _project(),
    Column("revision_id", UUID(as_uuid=True), nullable=False),
    Column("ordinal", Integer, nullable=False),
    Column("effect", Text, nullable=False),
    Column("kind", Text, nullable=False),
    Column("value", Text, nullable=False),
    Column("ports", Text, nullable=True),
    Column("note", Text, nullable=False, server_default=""),
    PrimaryKeyConstraint("id"),
    ForeignKeyConstraint(["project_id", "revision_id"], ["scope_revisions.project_id", "scope_revisions.id"]),
    UniqueConstraint("revision_id", "ordinal"),
    UniqueConstraint("revision_id", "effect", "kind", "value"),
    CheckConstraint("effect IN ('include', 'exclude')", name="effect"),
    CheckConstraint("kind IN ('host', 'subdomains', 'network')", name="kind"),
)

scope_revocations = Table(
    "scope_revocations",
    metadata,
    Column("revision_id", UUID(as_uuid=True), nullable=False),
    _project(),
    _ts("revoked_at", now=True),
    Column("revoked_by", UUID(as_uuid=True), ForeignKey("principals.id"), nullable=True),
    Column("reason", Text, nullable=False),
    PrimaryKeyConstraint("revision_id"),
    ForeignKeyConstraint(["project_id", "revision_id"], ["scope_revisions.project_id", "scope_revisions.id"]),
    CheckConstraint("length(trim(reason)) > 0", name="reason_present"),
)


def _revision_fk(column: str = "scope_revision_id") -> ForeignKeyConstraint:
    return ForeignKeyConstraint(["project_id", column], ["scope_revisions.project_id", "scope_revisions.id"])


assets = Table(
    "assets",
    metadata,
    _id(),
    _project(),
    Column("kind", Text, nullable=False),
    Column("value", Text, nullable=False),
    _ts("first_seen_at", now=True),
    _ts("last_seen_at", now=True),
    Column("attributes", JSONB, nullable=False, server_default=text("'{}'::jsonb")),
    Column("scope_revision_id", UUID(as_uuid=True), nullable=True),
    PrimaryKeyConstraint("id"),
    UniqueConstraint("project_id", "id"),
    UniqueConstraint("project_id", "kind", "value"),
    _revision_fk(),
    CheckConstraint("kind IN ('hostname', 'ip_address', 'service', 'url')", name="kind"),
)

jobs = Table(
    "jobs",
    metadata,
    _id(),
    _project(),
    Column("kind", Text, nullable=False),
    Column("status", Text, nullable=False, server_default="queued"),
    Column("scope_revision_id", UUID(as_uuid=True), nullable=False),
    Column("payload", JSONB, nullable=False, server_default=text("'{}'::jsonb")),
    Column("priority", Integer, nullable=False, server_default="0"),
    _ts("run_after", now=True),
    Column("attempts", Integer, nullable=False, server_default="0"),
    Column("max_attempts", Integer, nullable=False, server_default="3"),
    Column("idempotency_key", Text, nullable=True),
    Column("lease_owner", Text, nullable=True),
    _ts("lease_expires_at", nullable=True),
    _ts("created_at", now=True),
    _ts("started_at", nullable=True),
    _ts("finished_at", nullable=True),
    Column("result", JSONB, nullable=True),
    Column("last_error", Text, nullable=True),
    Column("run_id", UUID(as_uuid=True), nullable=True),
    _ts("cancel_requested_at", nullable=True),
    Column("cancel_reason", Text, nullable=True),
    Column("concurrency_key", Text, nullable=True),
    PrimaryKeyConstraint("id"),
    UniqueConstraint("project_id", "id"),
    UniqueConstraint("project_id", "idempotency_key"),
    _revision_fk(),
    CheckConstraint("status IN ('queued', 'running', 'succeeded', 'failed', 'cancelled')", name="status"),
    CheckConstraint("max_attempts > 0 AND attempts >= 0", name="attempts"),
    CheckConstraint(
        "(cancel_requested_at IS NULL AND cancel_reason IS NULL)"
        " OR (cancel_requested_at IS NOT NULL AND cancel_reason IS NOT NULL AND length(trim(cancel_reason)) > 0)",
        name="cancel_request",
    ),
    CheckConstraint("concurrency_key IS NULL OR length(concurrency_key) > 0", name="concurrency_key_present"),
    Index("ix_jobs_claimable", "priority", "run_after", postgresql_where=text("status IN ('queued', 'running')")),
    Index(None, "project_id", "run_id"),
    Index("ix_jobs_running_concurrency_key", "concurrency_key", postgresql_where=text("status = 'running'")),
)

# A run whose cancellation was requested; enqueueing more of its jobs is refused.
run_cancellations = Table(
    "run_cancellations",
    metadata,
    _project(),
    Column("run_id", UUID(as_uuid=True), nullable=False),
    Column("reason", Text, nullable=False),
    _ts("requested_at", now=True),
    PrimaryKeyConstraint("project_id", "run_id"),
    CheckConstraint("length(trim(reason)) > 0", name="reason_present"),
)

observations = Table(
    "observations",
    metadata,
    _id(),
    _project(),
    Column("asset_id", UUID(as_uuid=True), nullable=False),
    Column("kind", Text, nullable=False),
    Column("source", Text, nullable=False),
    Column("data", JSONB, nullable=False),
    _ts("observed_at", now=True),
    _ts("recorded_at", now=True),
    Column("job_id", UUID(as_uuid=True), nullable=True),
    Column("scope_revision_id", UUID(as_uuid=True), nullable=True),
    Column("source_ref", Text, nullable=True),
    PrimaryKeyConstraint("id"),
    UniqueConstraint("project_id", "id"),
    UniqueConstraint("project_id", "source_ref"),
    ForeignKeyConstraint(["project_id", "asset_id"], ["assets.project_id", "assets.id"]),
    ForeignKeyConstraint(["project_id", "job_id"], ["jobs.project_id", "jobs.id"]),
    _revision_fk(),
    CheckConstraint(
        "kind IN ('discovery', 'dns_resolution', 'port_state', 'http_response', 'tls_certificate', 'technology')",
        name="kind",
    ),
    Index(None, "project_id", "asset_id", "kind", "observed_at"),
)

findings = Table(
    "findings",
    metadata,
    _id(),
    _project(),
    Column("asset_id", UUID(as_uuid=True), nullable=False),
    Column("fingerprint", Text, nullable=False),
    Column("title", Text, nullable=False),
    Column("severity", Text, nullable=False),
    Column("status", Text, nullable=False, server_default="open"),
    Column("source", Text, nullable=False),
    Column("details", JSONB, nullable=False, server_default=text("'{}'::jsonb")),
    _ts("first_seen_at", now=True),
    _ts("last_seen_at", now=True),
    _ts("status_changed_at", now=True),
    Column("scope_revision_id", UUID(as_uuid=True), nullable=True),
    PrimaryKeyConstraint("id"),
    UniqueConstraint("project_id", "id"),
    UniqueConstraint("project_id", "fingerprint"),
    ForeignKeyConstraint(["project_id", "asset_id"], ["assets.project_id", "assets.id"]),
    _revision_fk(),
    CheckConstraint("severity IN ('info', 'low', 'medium', 'high', 'critical')", name="severity"),
    CheckConstraint(
        "status IN ('open', 'triaged', 'resolved', 'false_positive', 'accepted_risk')", name="status"
    ),
)

evidence = Table(
    "evidence",
    metadata,
    _id(),
    _project(),
    Column("finding_id", UUID(as_uuid=True), nullable=True),
    Column("observation_id", UUID(as_uuid=True), nullable=True),
    Column("media_type", Text, nullable=False),
    Column("sha256", Text, nullable=False),
    Column("size_bytes", BigInteger, nullable=False),
    Column("storage_uri", Text, nullable=False),
    Column("description", Text, nullable=False, server_default=""),
    _ts("created_at", now=True),
    PrimaryKeyConstraint("id"),
    ForeignKeyConstraint(["project_id", "finding_id"], ["findings.project_id", "findings.id"]),
    ForeignKeyConstraint(["project_id", "observation_id"], ["observations.project_id", "observations.id"]),
    CheckConstraint("sha256 ~ '^[0-9a-f]{64}$'", name="sha256_hex"),
    CheckConstraint("size_bytes >= 0", name="size_nonnegative"),
    Index(None, "project_id", "finding_id"),
)

notifications = Table(
    "notifications",
    metadata,
    _id(),
    _project(),
    Column("channel", Text, nullable=False),
    Column("event_type", Text, nullable=False),
    Column("dedupe_key", Text, nullable=False),
    Column("payload", JSONB, nullable=False),
    Column("status", Text, nullable=False, server_default="pending"),
    Column("attempts", Integer, nullable=False, server_default="0"),
    Column("max_attempts", Integer, nullable=False, server_default="5"),
    _ts("created_at", now=True),
    _ts("next_attempt_at", now=True),
    Column("lease_owner", Text, nullable=True),
    _ts("lease_expires_at", nullable=True),
    _ts("sent_at", nullable=True),
    Column("last_error", Text, nullable=True),
    PrimaryKeyConstraint("id"),
    UniqueConstraint("project_id", "dedupe_key"),
    CheckConstraint("status IN ('pending', 'sending', 'sent', 'failed')", name="status"),
    CheckConstraint("max_attempts > 0 AND attempts >= 0", name="attempts"),
    Index("ix_notifications_deliverable", "next_attempt_at", postgresql_where=text("status IN ('pending', 'sending')")),
)

phase_snapshots = Table(
    "phase_snapshots",
    metadata,
    _id(),
    _project(),
    Column("run_id", UUID(as_uuid=True), nullable=False),
    Column("job_id", UUID(as_uuid=True), nullable=True),
    Column("target", Text, nullable=False),
    Column("phase", Text, nullable=False),
    Column("status", Text, nullable=False),
    Column("comparison", Text, nullable=False),
    Column("items", JSONB, nullable=False, server_default=text("'[]'::jsonb")),
    Column("pending", JSONB, nullable=False, server_default=text("'[]'::jsonb")),
    Column("changes", JSONB, nullable=False, server_default=text("'{}'::jsonb")),
    Column("stats", JSONB, nullable=False, server_default=text("'{}'::jsonb")),
    _ts("created_at", now=True),
    PrimaryKeyConstraint("id"),
    UniqueConstraint("project_id", "id"),
    UniqueConstraint("project_id", "run_id", "phase", "target"),
    ForeignKeyConstraint(["project_id", "job_id"], ["jobs.project_id", "jobs.id"]),
    CheckConstraint("length(target) > 0", name="target_present"),
    CheckConstraint("phase IN ('discovery', 'dns', 'http', 'checks')", name="phase"),
    CheckConstraint("status IN ('completed', 'partial', 'failed', 'cancelled')", name="status"),
    CheckConstraint(
        "comparison IN ('baseline', 'unchanged', 'changed', 'partial', 'failed', 'uncertain')", name="comparison"
    ),
    CheckConstraint(
        "jsonb_typeof(items) = 'array' AND jsonb_typeof(pending) = 'array'"
        " AND jsonb_typeof(changes) = 'object' AND jsonb_typeof(stats) = 'object'",
        name="json_shapes",
    ),
    Index(None, "project_id", "target", "phase", "created_at"),
)
