"""Durable shared request caps. A database transaction reserves every permit.

Minute windows apply globally, per project and per hostname across projects.
A separate lifetime counter bounds each run across retries and worker restarts.
Only opaque hashes are stored. No transaction is held while waiting.
"""
from datetime import datetime, timezone
import hashlib

from sqlalchemy import select, text, func
from sqlalchemy.dialects.postgresql import insert

from watchtower.persistence.tables import request_counters

EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


class RequestLimiter:
    def __init__(self, database, settings, project_id, run_id, token, recheck):
        self.database, self.settings = database, settings
        self.project_id, self.run_id, self.token = project_id, run_id, token
        self.recheck = recheck

    def acquire(self, host):
        def key(value):
            return hashlib.sha256(value.encode()).hexdigest()
        settings = self.settings
        while True:
            self.token.check()
            if not self.recheck(host):
                return False
            with self.database.system() as system:
                connection = system.connection
                connection.execute(text("SELECT pg_advisory_xact_lock(817253941)"))
                now = connection.execute(select(func.now())).scalar_one()
                window = now.replace(second=0, microsecond=0)
                limits = [(key("global"), window, settings.global_requests_per_minute),
                          (key("project:" + str(self.project_id)), window, settings.per_project_requests_per_minute),
                          (key("host:" + str(host)), window, settings.per_host_requests_per_minute),
                          (key("run:" + str(self.project_id) + ":" + str(self.run_id)), EPOCH, settings.max_requests_per_run)]
                counts = []
                for name, at, maximum in limits:
                    count = connection.execute(select(request_counters.c.count).where(
                        request_counters.c.key == name, request_counters.c.window == at)).scalar_one_or_none() or 0
                    counts.append(count)
                if counts[-1] >= limits[-1][2]:
                    return False
                if all(count < entry[2] for count, entry in zip(counts, limits)):
                    for name, at, _ in limits:
                        query = insert(request_counters).values(key=name, window=at, count=1)
                        connection.execute(query.on_conflict_do_update(
                            index_elements=[request_counters.c.key, request_counters.c.window],
                            set_={"count": request_counters.c.count + 1}))
                    return True
            self.token.wait(0.5)
