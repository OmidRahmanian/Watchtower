"""Fixtures for API tests: a migrated database, principals with tokens, and a client.

Database tests need ``WATCHTOWER_TEST_DATABASE_URL``; see tests/foundation/conftest.py.
"""

from __future__ import annotations

import importlib.util
import sys
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient

TESTS = Path(__file__).resolve().parents[1]
for _path in (TESTS, Path(__file__).resolve().parent):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

_spec = importlib.util.spec_from_file_location("_foundation_db_fixtures_api", TESTS / "foundation" / "conftest.py")
_foundation = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_foundation)
admin_url = _foundation.admin_url
fresh_database = _foundation.fresh_database
migrated_url = _foundation.migrated_url
database = _foundation.database
project_id = _foundation.project_id
other_project_id = _foundation.other_project_id
authorization = _foundation.authorization

from api_support import FakeRuns  # noqa: E402
from checks_support import approved_ruleset  # noqa: E402
from watchtower.api import create_app  # noqa: E402
from watchtower.security.auth import ProjectRole  # noqa: E402
from watchtower.services.evidence_store import FilesystemBlobStore  # noqa: E402


@dataclass
class Member:
    principal_id: UUID
    token: str

    @property
    def headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"}


@pytest.fixture
def member(database):
    """``member(project_id, role)`` creates a principal with that role and a token for it."""

    def make(project: UUID, role: ProjectRole, *, restrict: bool = False) -> Member:
        with database.system() as system:
            principal = system.auth.create_principal(f"{role.value}-{uuid4().hex[:6]}")
            system.auth.set_membership(project, principal.id, role)
            issued = system.auth.issue_token(principal.id, "test", project_id=project if restrict else None)
        return Member(principal.id, issued.secret)

    return make


@pytest.fixture
def blobs(tmp_path):
    return FilesystemBlobStore(tmp_path / "evidence")


@pytest.fixture
def runs():
    return FakeRuns()


@pytest.fixture
def client(database, blobs, runs):
    app = create_app(database, blobs=blobs, runs=runs, rules=approved_ruleset)
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def owner(member, project_id):
    return member(project_id, ProjectRole.OWNER)


@pytest.fixture
def operator(member, project_id):
    return member(project_id, ProjectRole.OPERATOR)


@pytest.fixture
def viewer(member, project_id):
    return member(project_id, ProjectRole.VIEWER)
