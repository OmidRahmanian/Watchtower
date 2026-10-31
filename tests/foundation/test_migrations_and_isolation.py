"""Migrations on a fresh database, and the project boundary in PostgreSQL."""

from __future__ import annotations

from uuid import UUID, uuid4

import pytest
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL
from sqlalchemy.exc import DBAPIError, IntegrityError

from watchtower.domain.errors import NotFound
from watchtower.domain.models import AssetKind, NewJob, NewObservation, ObservationKind
from watchtower.persistence import Database, migrations
from watchtower.persistence.tables import PROJECT_SCOPED_TABLES, metadata

pytestmark = pytest.mark.postgres


def test_fresh_database_migrates_to_head_and_matches_metadata(migrated_url: URL) -> None:
    engine = create_engine(migrated_url)
    try:
        with engine.connect() as connection:
            context = MigrationContext.configure(connection, opts={"compare_type": True})
            assert context.get_current_revision() == "0003"
            assert compare_metadata(context, metadata) == []
            rls = connection.execute(
                text("SELECT relname FROM pg_class WHERE relrowsecurity AND relforcerowsecurity")
            ).scalars()
            assert set(PROJECT_SCOPED_TABLES) <= set(rls)
            superuser = connection.execute(text("SELECT rolsuper FROM pg_roles WHERE rolname = current_user"))
            assert superuser.scalar_one() is False
    finally:
        engine.dispose()


def test_downgrade_and_upgrade_round_trip(admin_url: URL) -> None:
    # A separate empty database so the shared schema stays intact.
    name = f"wt_roundtrip_{uuid4().hex[:8]}"
    admin = create_engine(admin_url, isolation_level="AUTOCOMMIT")
    with admin.connect() as connection:
        connection.execute(text(f"CREATE DATABASE {name}"))
    url = admin_url.set(database=name).render_as_string(hide_password=False)
    try:
        migrations.upgrade(url)
        migrations.downgrade(url, "base")
        engine = create_engine(url)
        with engine.connect() as connection:
            tables = connection.execute(
                text("SELECT count(*) FROM pg_tables WHERE schemaname = 'public' AND tablename <> 'alembic_version'")
            ).scalar_one()
        engine.dispose()
        assert tables == 0
        migrations.upgrade(url)
    finally:
        with admin.connect() as connection:
            connection.execute(text(f"DROP DATABASE IF EXISTS {name} WITH (FORCE)"))
        admin.dispose()


def _seed_asset(database: Database, project_id: UUID, value: str) -> UUID:
    with database.project(project_id) as uow:
        asset, _ = uow.assets.upsert(AssetKind.HOSTNAME, value)
        return asset.id


def test_projects_cannot_see_each_others_rows(database: Database, project_id: UUID, other_project_id: UUID) -> None:
    mine = _seed_asset(database, project_id, "a.example.com")
    theirs = _seed_asset(database, other_project_id, "b.example.com")
    with database.project(project_id) as uow:
        assert uow.assets.get(mine) is not None
        assert uow.assets.get(theirs) is None
        assert uow.assets.find(AssetKind.HOSTNAME, "b.example.com") is None
        assert [a.value for a in uow.assets.list()] == ["a.example.com"]


def test_row_level_security_blocks_raw_sql(database: Database, project_id: UUID, other_project_id: UUID) -> None:
    theirs = _seed_asset(database, other_project_id, "secret.example.com")
    with database.project(project_id) as uow:
        # Bypassing the repositories still cannot read the other project's rows.
        visible = uow.connection.execute(text("SELECT count(*) FROM assets WHERE id = :id"), {"id": theirs})
        assert visible.scalar_one() == 0
        updated = uow.connection.execute(text("UPDATE assets SET attributes = '{}' WHERE id = :id"), {"id": theirs})
        assert updated.rowcount == 0
    with pytest.raises(DBAPIError, match="row-level security"):
        with database.project(project_id) as uow:
            uow.connection.execute(
                text("INSERT INTO assets (id, project_id, kind, value) VALUES (:id, :p, 'hostname', 'x.example.com')"),
                {"id": uuid4(), "p": other_project_id},
            )


def test_connection_without_project_context_sees_nothing(
    database: Database, migrated_url: URL, project_id: UUID
) -> None:
    _seed_asset(database, project_id, "c.example.com")
    engine = create_engine(migrated_url)
    try:
        with engine.connect() as connection:
            assert connection.execute(text("SELECT count(*) FROM assets")).scalar_one() == 0
    finally:
        engine.dispose()


def test_system_context_sees_all_projects(database: Database, project_id: UUID, other_project_id: UUID) -> None:
    _seed_asset(database, project_id, "d.example.com")
    _seed_asset(database, other_project_id, "e.example.com")
    with database.system() as system:
        projects = system.connection.execute(
            text("SELECT count(DISTINCT project_id) FROM assets WHERE project_id IN (:a, :b)"),
            {"a": project_id, "b": other_project_id},
        ).scalar_one()
    assert projects == 2


def test_project_settings_do_not_leak_between_transactions(database: Database, project_id: UUID) -> None:
    with database.project(project_id):
        pass
    with database.engine.connect() as connection:
        setting = connection.execute(text("SELECT current_setting('watchtower.project_id', true)")).scalar_one()
    assert setting in (None, "")


def test_cross_project_references_are_rejected(
    database: Database, project_id: UUID, other_project_id: UUID
) -> None:
    theirs = _seed_asset(database, other_project_id, "f.example.com")
    with pytest.raises(IntegrityError):
        with database.project(project_id) as uow:
            uow.observations.record(NewObservation(theirs, ObservationKind.DISCOVERY, "subfinder", {}))


def test_job_must_reference_own_projects_scope_revision(
    database: Database, project_id: UUID, other_project_id: UUID, authorization
) -> None:
    from watchtower.domain.scope import NewScopeRevision, ScopeRule
    from watchtower.domain.targets import PortSet

    with database.project(other_project_id) as uow:
        foreign = uow.scope.publish(
            NewScopeRevision((ScopeRule.parse("example.com"),), authorization, PortSet.parse("443")), created_by=None
        )
    with pytest.raises(IntegrityError):
        with database.project(project_id) as uow:
            uow.jobs.enqueue(NewJob("probe", foreign.id))


def test_unknown_project_is_not_found(database: Database) -> None:
    with pytest.raises(NotFound):
        with database.project(uuid4()):
            pass
