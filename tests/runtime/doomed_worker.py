"""A worker process that tests kill with SIGKILL partway through a job.

    python doomed_worker.py <database-url> <marker-file> <hang-host>

It leases jobs and runs them against ``two_root_lab(changed=True)``,
in which check requests to ``hang-host`` never return; it touches the marker
file when it gets stuck there.
"""
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
for path in (HERE.parents[1] / "src", HERE.parent, HERE):
    sys.path.insert(0, str(path))

from sqlalchemy import create_engine  # noqa: E402

from runtime_support import settings, two_root_lab  # noqa: E402
from watchtower.config.settings import ScopeSettings  # noqa: E402
from watchtower.persistence import Database  # noqa: E402
from watchtower.services.scope import ScopeService  # noqa: E402
from watchtower.workers.runtime import Worker  # noqa: E402


def main() -> None:
    url, marker, host = sys.argv[1:4]
    lab = two_root_lab(changed=True)
    lab.hang_fetch = {host}
    lab.marker = marker
    database = Database(create_engine(url, pool_size=2))
    scope = ScopeService(database, ScopeSettings(policy_cache_seconds=0))
    worker = Worker(database, scope, settings=settings(), adapters=lab.adapters(), worker_id="doomed",
                    lease_seconds=60, heartbeat_seconds=0.5)
    while not Path(marker).exists():
        if not worker.run_once():
            time.sleep(0.05)


if __name__ == "__main__":
    main()
