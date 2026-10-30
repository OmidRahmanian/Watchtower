"""Fixtures for foundation tests.

Database tests need ``WATCHTOWER_TEST_DATABASE_URL``: a PostgreSQL URL for an
account that may create roles and databases (a local superuser is fine).
Each test session creates a fresh database owned by a new non-superuser role
and migrates it as that role, so row-level security applies exactly as in
production. Both are dropped afterwards.
"""

from __future__ import annotations

import os
import secrets
from collections.abc import Iterator
from uuid import UUID, uuid4

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL, make_url

from watchtower.domain.scope import AuthorizationKind, AuthorizationReference
from watchtower.persistence import Database, migrations

ADMIN_URL = os.environ.get("WATCHTOWER_TEST_DATABASE_URL")


def _psycopg(url: str) -> URL:
    parsed = make_url(url)
    return parsed.set(drivername="postgresql+psycopg")


@pytest.fixture(scope="session")
def admin_url() -> URL:
    if not ADMIN_URL:
        pytest.skip("WATCHTOWER_TEST_DATABASE_URL is not set")
    return _psycopg(ADMIN_URL)


@pytest.fixture(scope="session")
def fresh_database(admin_url: URL) -> Iterator[URL]:
    """Create an empty database owned by a new non-superuser role; yield its URL."""
    suffix = secrets.token_hex(4)
    role, name, password = f"wt_app_{suffix}", f"wt_test_{suffix}", secrets.token_hex(16)
    admin = create_engine(admin_url, isolation_level="AUTOCOMMIT")
    with admin.connect() as connection:
        connection.execute(text(f"CREATE ROLE {role} LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD '{password}'"))
        connection.execute(text(f"CREATE DATABASE {name} OWNER {role}"))
    try:
        yield admin_url.set(username=role, password=password, database=name)
    finally:
        with admin.connect() as connection:
            connection.execute(text(f"DROP DATABASE IF EXISTS {name} WITH (FORCE)"))
            connection.execute(text(f"DROP ROLE IF EXISTS {role}"))
        admin.dispose()


@pytest.fixture(scope="session")
def migrated_url(fresh_database: URL) -> URL:
    migrations.upgrade(fresh_database.render_as_string(hide_password=False))
    return fresh_database


@pytest.fixture(scope="session")
def database(migrated_url: URL) -> Iterator[Database]:
    db = Database(create_engine(migrated_url, pool_size=2), statement_timeout_ms=10_000)
    yield db
    db.dispose()


@pytest.fixture
def project_id(database: Database) -> UUID:
    with database.system() as system:
        return system.projects.create(f"p-{uuid4().hex[:12]}", "Test project").id


@pytest.fixture
def other_project_id(database: Database) -> UUID:
    with database.system() as system:
        return system.projects.create(f"p-{uuid4().hex[:12]}", "Other project").id


@pytest.fixture
def authorization() -> AuthorizationReference:
    return AuthorizationReference(
        kind=AuthorizationKind.ASSET_OWNER,
        reference="https://example.com/security/authorization",
        granted_by="Test Owner",
    )
