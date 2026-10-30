"""Compare one phase of a run with the last comparable run, and turn changes into alerts.

Every phase reduces what it saw for one target to *items*: a key (a hostname,
a URL, a finding fingerprint) and a JSON value. ``compare`` sets them against
the accepted state of the previous comparable snapshot and returns the new
accepted state, the changes, and how much to trust the comparison:

* ``baseline``: nothing to compare with. The state is accepted silently, so a
  first run never floods anyone.
* ``unchanged`` / ``changed``: a complete phase compared with a baseline.
* ``partial``: this phase, or the one it is compared with, did not cover
  everything. Additions and modifications still count, removals do not.
* ``uncertain``: nothing changed for sure, but some items could not be
  observed (timeouts, refused scope, inconclusive checks) or a change is
  waiting for confirmation.
* ``failed``: the phase produced nothing usable: it crashed, its target was
  refused, or there was something to observe and none of it could be (every
  host unreachable). Its snapshot is not comparable, so the next run
  compares with the last good one, and the run reports ``failed``.

An item the phase could not observe keeps its previous value, so a flaky
probe never reads as a removal followed by a rediscovery. Debouncing: a
modified or removed value is held in ``pending`` until it has been seen on
``confirm`` consecutive runs; a value that flips back in between is dropped
without an alert.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from watchtower.domain.models import PhaseComparison, PhaseSnapshot, PhaseStatus, RunPhase

ABSENT = None  # pending value of a removal candidate


@dataclass(frozen=True, slots=True)
class Item:
    key: str
    value: Any = None
    uncertain: bool = False  # observed, but the observation proves nothing


@dataclass(frozen=True, slots=True)
class ChangeRules:
    """How one phase turns differences into changes."""

    confirm: int = 1  # runs a modification or removal must persist
    removals: bool = True  # whether a missing item can ever count as removed
    accumulate: bool = False  # keep items a complete run did not report (discovery)


DEFAULT_RULES: Mapping[RunPhase, ChangeRules] = {
    # Passive sources are lossy: a name they stop reporting is not gone.
    RunPhase.DISCOVERY: ChangeRules(removals=False, accumulate=True),
    RunPhase.DNS: ChangeRules(confirm=2),
    RunPhase.HTTP: ChangeRules(confirm=2),
    # Findings leave only through their own lifecycle (a relevant retest).
    RunPhase.CHECKS: ChangeRules(removals=False, accumulate=True),
}


def rules_for(phase: RunPhase, confirm: Mapping[str, int] | None = None) -> ChangeRules:
    base = DEFAULT_RULES[RunPhase(phase)]
    count = (confirm or {}).get(RunPhase(phase).value)
    if count is None:
        return base
    return ChangeRules(confirm=count, removals=base.removals, accumulate=base.accumulate)


@dataclass(frozen=True, slots=True)
class Observed:
    """What one phase saw for one target in this run."""

    items: Sequence[Item] = ()
    complete: bool = True  # False when part of the target could not be covered
    failed: bool = False  # nothing usable was produced
    stats: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class Outcome:
    status: PhaseStatus
    comparison: PhaseComparison
    items: list[dict[str, Any]]
    pending: list[dict[str, Any]]
    changes: dict[str, list[dict[str, Any]]]
    stats: dict[str, Any]

    @property
    def changed(self) -> bool:
        return any(self.changes.values())


def _as_map(entries: Iterable[Mapping[str, Any]]) -> dict[str, Mapping[str, Any]]:
    return {entry["key"]: entry for entry in entries}


def compare(previous: PhaseSnapshot | None, observed: Observed, rules: ChangeRules) -> Outcome:
    stats: dict[str, Any] = dict(observed.stats)
    if observed.items and all(item.uncertain for item in observed.items):
        # Something was there to observe and none of it could be: a failed scan, not a partial one.
        observed = Observed(failed=True, stats={**stats, "failure": "nothing could be observed"})
        stats = dict(observed.stats)
    if observed.failed:
        # Not comparable; keep the previous state on record for anyone reading the run.
        items = list(previous.items) if previous else []
        return Outcome(PhaseStatus.FAILED, PhaseComparison.FAILED, items, list(previous.pending) if previous else [],
                       {}, stats)

    status = PhaseStatus.COMPLETED if observed.complete else PhaseStatus.PARTIAL
    current: dict[str, Item] = {}
    for item in observed.items:
        # A certain observation of a key wins over an uncertain one in the same run.
        if item.key not in current or current[item.key].uncertain:
            current[item.key] = item
    uncertain = sum(1 for item in current.values() if item.uncertain)
    stats.update(observed=len(current), uncertain=uncertain)

    if previous is None:
        items = [{"key": k, "value": i.value} for k, i in sorted(current.items()) if not i.uncertain]
        return Outcome(status, PhaseComparison.BASELINE, items, [], {}, stats)

    before = {key: entry["value"] for key, entry in _as_map(previous.items).items()}
    waiting = _as_map(previous.pending)
    can_remove = rules.removals and observed.complete and previous.status is PhaseStatus.COMPLETED
    accepted: dict[str, Any] = {}
    pending: list[dict[str, Any]] = []
    changes: dict[str, list[dict[str, Any]]] = {"added": [], "modified": [], "removed": []}

    for key in sorted(set(before) | set(current)):
        item = current.get(key)
        known = key in before
        if item is None or item.uncertain:
            if known:
                accepted[key] = before[key]
                if item is None and can_remove and not rules.accumulate:
                    _candidate(key, ABSENT, before[key], waiting, rules, accepted, pending, changes)
                elif key in waiting:
                    pending.append(dict(waiting[key]))  # neither confirmed nor contradicted
            continue
        if not known:
            accepted[key] = item.value
            changes["added"].append({"key": key, "before": None, "after": item.value})
        elif item.value == before[key]:
            accepted[key] = before[key]  # any pending flip is dropped: it did not persist
        else:
            accepted[key] = before[key]
            _candidate(key, item.value, before[key], waiting, rules, accepted, pending, changes)

    if any(changes.values()):
        comparison = PhaseComparison.CHANGED
    elif uncertain or pending:
        comparison = PhaseComparison.UNCERTAIN
    else:
        comparison = PhaseComparison.UNCHANGED
    if status is PhaseStatus.PARTIAL or previous.status is PhaseStatus.PARTIAL:
        comparison = PhaseComparison.PARTIAL
    stats.update(pending=len(pending), **{name: len(entries) for name, entries in changes.items()})
    items = [{"key": key, "value": value} for key, value in sorted(accepted.items())]
    return Outcome(status, comparison, items, pending, changes, stats)


def _candidate(key: str, value: Any, old: Any, waiting: Mapping[str, Mapping[str, Any]], rules: ChangeRules,
               accepted: dict[str, Any], pending: list[dict[str, Any]], changes: dict[str, list]) -> None:
    earlier = waiting.get(key)
    seen = earlier["seen"] + 1 if earlier and earlier["value"] == value else 1
    if seen < rules.confirm:
        pending.append({"key": key, "value": value, "seen": seen})
        return
    if value is ABSENT:
        del accepted[key]
        changes["removed"].append({"key": key, "before": old, "after": None})
    else:
        accepted[key] = value
        changes["modified"].append({"key": key, "before": old, "after": value})


# -- alerts --------------------------------------------------------------

ALERT_EVENT = "monitor.changes"
RUN_FAILED_EVENT = "monitor.run_failed"


@dataclass(frozen=True, slots=True)
class Change:
    """One line of an alert."""

    type: str  # asset.discovered, dns.changed, http.changed, finding.opened, ...
    target: str
    phase: str
    key: str
    before: Any = None
    after: Any = None

    def as_dict(self) -> dict[str, Any]:
        return {"type": self.type, "target": self.target, "phase": self.phase, "key": self.key,
                "before": self.before, "after": self.after}


def _finding_change(entry: Mapping[str, Any], kind: str) -> str | None:
    after = entry["after"] or {}
    before = entry["before"] or {}
    if kind == "added":
        return "finding.reopened" if after.get("status") == "open" and after.get("recurrences") else "finding.opened"
    if before.get("status") == "resolved" and after.get("status") == "open":
        return "finding.reopened"
    if after.get("status") == "resolved" and before.get("status") != "resolved":
        return "finding.resolved"
    return None  # triage, severity drift and refreshed details are not news


def alertable(snapshot: PhaseSnapshot) -> list[Change]:
    """The changes in a snapshot that deserve a line in an alert.

    A new hostname is one alert (``asset.discovered``); its first DNS answer
    and first HTTP response are part of discovering it, not further changes.
    """
    phase = RunPhase(snapshot.phase)
    found: list[Change] = []
    for kind in ("added", "modified", "removed"):
        for entry in snapshot.changes.get(kind, []):
            if phase is RunPhase.DISCOVERY:
                kinds = {"added": "asset.discovered"}
                label = kinds.get(kind)
            elif phase is RunPhase.CHECKS:
                label = _finding_change(entry, kind)
            else:
                label = None if kind == "added" else f"{phase.value}.changed"
            if label:
                found.append(Change(label, snapshot.target, phase.value, entry["key"], entry["before"], entry["after"]))
    return found


def wanted(change_types: Iterable[str], event_type: str, events: Sequence[str]) -> list[str]:
    """Filter a destination's change types by its ``events`` (empty means all)."""
    types = list(change_types)
    if not events or event_type in events:
        return types
    return [kind for kind in types if kind in events]
