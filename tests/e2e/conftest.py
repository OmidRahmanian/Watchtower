"""Fixtures for end-to-end journeys: a migrated database and the in-process lab.

Database tests need ``WATCHTOWER_TEST_DATABASE_URL``; see tests/foundation/conftest.py.
The monitoring runtime's fake world (tests/runtime/runtime_support.py) answers
every outbound DNS, HTTP and webhook call, so these tests send no traffic.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

TESTS = Path(__file__).resolve().parents[1]
for _path in (TESTS, TESTS / "api", TESTS / "runtime"):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

_spec = importlib.util.spec_from_file_location("_foundation_db_fixtures_e2e", TESTS / "foundation" / "conftest.py")
_foundation = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_foundation)
admin_url = _foundation.admin_url
fresh_database = _foundation.fresh_database
migrated_url = _foundation.migrated_url
database = _foundation.database
