"""Intelligence snapshots with freshness tracking.

A refresh replaces a feed's snapshot only when the new data parses cleanly,
is not empty, has not shrunk suspiciously, and is not older than the cached
copy. Any failure leaves the previous snapshot in place and records the error,
so a feed outage degrades to stale intelligence, never to missing intelligence.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
import json
import os
from pathlib import Path
import tempfile

from watchtower.adapters.checks.base import utcnow
from watchtower.adapters.intelligence.feeds import Feed, parse_time

MIN_RETAINED_RATIO = 0.5


class FreshnessState(StrEnum):
    FRESH = "fresh"
    STALE = "stale"
    MISSING = "missing"


@dataclass(frozen=True)
class Freshness:
    source: str
    state: FreshnessState
    fetched_at: datetime | None
    published_at: datetime | None
    last_attempt_at: datetime | None
    last_error: str | None
    reason: str

    def to_dict(self) -> dict:
        return {
            "source": self.source, "state": self.state.value, "reason": self.reason,
            "fetched_at": self.fetched_at and self.fetched_at.isoformat(),
            "published_at": self.published_at and self.published_at.isoformat(),
            "last_attempt_at": self.last_attempt_at and self.last_attempt_at.isoformat(),
            "last_error": self.last_error,
        }


@dataclass(frozen=True)
class RefreshReport:
    source: str
    updated: bool
    record_count: int
    error: str | None = None


def _write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(handle, "w") as stream:
            json.dump(data, stream, separators=(",", ":"))
        os.replace(temporary, path)
    except BaseException:
        os.unlink(temporary)
        raise


def _time(value: str | None) -> datetime | None:
    return parse_time(value) if value else None


class IntelligenceStore:
    def __init__(self, root: Path):
        self.root = Path(root)
        self._snapshots: dict[str, dict | None] = {}
        self._feeds: dict[str, Feed] = {}

    def _snapshot_path(self, source: str) -> Path:
        return self.root / f"{source}.json"

    def _status_path(self, source: str) -> Path:
        return self.root / f"{source}.status.json"

    def snapshot(self, source: str) -> dict | None:
        if source not in self._snapshots:
            path = self._snapshot_path(source)
            try:
                self._snapshots[source] = json.loads(path.read_text()) if path.exists() else None
            except ValueError:
                self._snapshots[source] = None
        return self._snapshots[source]

    def _status(self, source: str) -> dict:
        try:
            return json.loads(self._status_path(source).read_text())
        except (OSError, ValueError):
            return {}

    def refresh(self, feed: Feed, now: datetime | None = None) -> RefreshReport:
        now = now or utcnow()
        self._feeds[feed.name] = feed
        previous = self.snapshot(feed.name)
        previous_count = len(previous["records"]) if previous else 0
        error = None
        try:
            parsed = feed.fetch()
            count = len(parsed.records)
            previous_published = _time(previous and previous.get("published_at"))
            if count == 0:
                error = "feed returned no records"
            elif count < previous_count * MIN_RETAINED_RATIO:
                error = f"feed shrank from {previous_count} to {count} records"
            elif previous_published and parsed.published_at and parsed.published_at < previous_published:
                error = f"feed published {parsed.published_at.isoformat()} is older than cached data"
        except Exception as caught:
            error = f"{type(caught).__name__}: {caught}"[:500]
        status = {"last_attempt_at": now.isoformat(), "last_error": error}
        if error is None:
            snapshot = {
                "source": feed.name, "url": feed.url, "fetched_at": now.isoformat(),
                "published_at": parsed.published_at and parsed.published_at.isoformat(),
                "meta": parsed.meta, "records": parsed.records,
            }
            _write_json(self._snapshot_path(feed.name), snapshot)
            self._snapshots[feed.name] = snapshot
        _write_json(self._status_path(feed.name), status)
        if error:
            return RefreshReport(feed.name, False, previous_count, error)
        return RefreshReport(feed.name, True, len(parsed.records))

    def freshness(self, feed: Feed, now: datetime | None = None) -> Freshness:
        now = now or utcnow()
        snapshot = self.snapshot(feed.name)
        status = self._status(feed.name)
        attempt, error = _time(status.get("last_attempt_at")), status.get("last_error")
        if snapshot is None:
            return Freshness(feed.name, FreshnessState.MISSING, None, None, attempt, error, "no snapshot cached")
        fetched, published = _time(snapshot["fetched_at"]), _time(snapshot.get("published_at"))
        state, reason = FreshnessState.FRESH, f"fetched {fetched.isoformat()}"
        if now - fetched > feed.max_age:
            state, reason = FreshnessState.STALE, f"last successful fetch {fetched.isoformat()} exceeds {feed.max_age}"
        elif feed.max_published_age and published and now - published > feed.max_published_age:
            state, reason = FreshnessState.STALE, f"feed data dated {published.isoformat()} exceeds {feed.max_published_age}"
        return Freshness(feed.name, state, fetched, published, attempt, error, reason)

    def record(self, source: str, key: str) -> dict | None:
        snapshot = self.snapshot(source)
        return snapshot["records"].get(key) if snapshot else None

    def records(self, source: str) -> list[dict]:
        snapshot = self.snapshot(source)
        return list(snapshot["records"].values()) if snapshot else []
