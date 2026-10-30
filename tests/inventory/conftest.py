import importlib.util
import sys
from pathlib import Path

TESTS = Path(__file__).resolve().parents[1]
SRC = TESTS.parent / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
sys.path.insert(0, str(Path(__file__).resolve().parent))

# Reuse the foundation PostgreSQL fixtures (fresh role + database, migrated, dropped
# afterwards). They skip unless WATCHTOWER_TEST_DATABASE_URL is set.
_spec = importlib.util.spec_from_file_location("_foundation_db_fixtures", TESTS / "foundation" / "conftest.py")
_foundation = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_foundation)
admin_url = _foundation.admin_url
fresh_database = _foundation.fresh_database
migrated_url = _foundation.migrated_url
database = _foundation.database
project_id = _foundation.project_id
authorization = _foundation.authorization
