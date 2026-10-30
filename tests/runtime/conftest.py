import importlib.util
import sys
from pathlib import Path

TESTS = Path(__file__).resolve().parents[1]
SRC = TESTS.parent / "src"
for path in (SRC, TESTS, Path(__file__).resolve().parent):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

# The foundation PostgreSQL fixtures: a fresh non-superuser role and database,
# migrated, so row-level security applies as in production.
_spec = importlib.util.spec_from_file_location("_runtime_foundation_fixtures", TESTS / "foundation" / "conftest.py")
_foundation = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_foundation)
admin_url = _foundation.admin_url
fresh_database = _foundation.fresh_database
migrated_url = _foundation.migrated_url
database = _foundation.database
project_id = _foundation.project_id
authorization = _foundation.authorization

from runtime_support import lab, operator, runs, scope_service, viewer  # noqa: E402,F401

import pytest  # noqa: E402


@pytest.fixture(autouse=True)
def retire_leftover_work(request):
    """Workers lease across projects, so a test's unfinished jobs must not leak into the next test."""
    yield
    if "database" not in request.fixturenames:
        return
    db = request.getfixturevalue("database")
    with db.system() as system:
        system.connection.exec_driver_sql(
            "UPDATE jobs SET status = 'cancelled', finished_at = now(), lease_owner = NULL, lease_expires_at = NULL "
            "WHERE status IN ('queued', 'running')")
        system.connection.exec_driver_sql(
            "UPDATE notifications SET status = 'failed', lease_owner = NULL, lease_expires_at = NULL "
            "WHERE status IN ('pending', 'sending')")
