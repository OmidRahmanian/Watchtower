"""Change comparison: baseline, unchanged, changed, partial, failed and uncertain results."""
from datetime import datetime, timezone
from uuid import uuid4

from watchtower.domain.models import PhaseComparison as C, PhaseSnapshot, PhaseStatus as S, RunPhase
from watchtower.services.changes import ChangeRules, Item, Observed, alertable, compare, rules_for, wanted

NOW = datetime(2026, 10, 30, tzinfo=timezone.utc)
STRICT = ChangeRules(confirm=1)
DEBOUNCED = ChangeRules(confirm=2)


def snapshot(outcome, phase=RunPhase.HTTP, target="example.com"):
    return PhaseSnapshot(uuid4(), uuid4(), uuid4(), target, phase, outcome.status, outcome.comparison,
                         outcome.items, outcome.pending, outcome.changes, outcome.stats, NOW)


def observed(*pairs, complete=True, failed=False, uncertain=()):
    items = [Item(key, value) for key, value in pairs] + [Item(key, uncertain=True) for key in uncertain]
    return Observed(items=items, complete=complete, failed=failed)


def chain(rules, *observations):
    previous, outcomes = None, []
    for each in observations:
        outcome = compare(previous, each, rules)
        outcomes.append(outcome)
        if outcome.status in (S.COMPLETED, S.PARTIAL):
            previous = snapshot(outcome)
    return outcomes


A, B = {"status_code": 200}, {"status_code": 503}


def test_first_run_is_a_silent_baseline():
    [first] = chain(STRICT, observed(("x", A), ("y", A)))
    assert (first.status, first.comparison, first.changed) == (S.COMPLETED, C.BASELINE, False)
    assert [i["key"] for i in first.items] == ["x", "y"]


def test_identical_reruns_are_unchanged():
    outcomes = chain(STRICT, observed(("x", A)), observed(("x", A)), observed(("x", A)))
    assert [o.comparison for o in outcomes[1:]] == [C.UNCHANGED, C.UNCHANGED]
    assert not any(o.changed for o in outcomes)


def test_additions_modifications_and_removals():
    _, second = chain(STRICT, observed(("x", A), ("gone", A)), observed(("x", B), ("new", A)))
    assert second.comparison is C.CHANGED
    assert [c["key"] for c in second.changes["added"]] == ["new"]
    assert [(c["key"], c["before"], c["after"]) for c in second.changes["modified"]] == [("x", A, B)]
    assert [c["key"] for c in second.changes["removed"]] == ["gone"]
    assert [i["key"] for i in second.items] == ["new", "x"]


def test_a_modification_is_held_until_confirmed():
    _, held, confirmed, after = chain(DEBOUNCED, observed(("x", A)), observed(("x", B)), observed(("x", B)),
                                      observed(("x", B)))
    assert held.comparison is C.UNCERTAIN and not held.changed
    assert held.pending == [{"key": "x", "value": B, "seen": 1}]
    assert held.items == [{"key": "x", "value": A}]  # the accepted state is unchanged meanwhile
    assert confirmed.comparison is C.CHANGED and confirmed.changes["modified"][0]["after"] == B
    assert after.comparison is C.UNCHANGED and after.pending == []


def test_a_value_that_flips_back_is_never_reported():
    outcomes = chain(DEBOUNCED, observed(("x", A)), observed(("x", B)), observed(("x", A)), observed(("x", B)))
    assert not any(o.changed for o in outcomes)
    assert outcomes[2].pending == []  # the flip was dropped, so the next one starts over
    assert outcomes[3].pending[0]["seen"] == 1


def test_uncertain_items_keep_their_previous_value():
    _, unsure, back = chain(STRICT, observed(("x", A), ("y", A)), observed(("x", A), uncertain=["y"]),
                            observed(("x", A), ("y", A)))
    assert unsure.comparison is C.UNCERTAIN and not unsure.changed
    assert unsure.items == [{"key": "x", "value": A}, {"key": "y", "value": A}]
    assert back.comparison is C.UNCHANGED


def test_an_uncertain_item_neither_confirms_nor_cancels_a_pending_change():
    outcomes = chain(DEBOUNCED, observed(("x", A)), observed(("x", B)), observed(uncertain=["x"]), observed(("x", B)))
    assert outcomes[2].pending == outcomes[1].pending
    assert outcomes[3].changes["modified"][0]["after"] == B


def test_a_certain_observation_wins_over_an_uncertain_one_for_the_same_key():
    _, second = chain(STRICT, observed(("x", A)), Observed(items=[Item("x", uncertain=True), Item("x", B)]))
    assert second.changes["modified"][0]["after"] == B


def test_partial_runs_report_additions_but_never_removals():
    _, partial, complete = chain(STRICT, observed(("x", A), ("y", A)), observed(("x", A), ("z", A), complete=False),
                                 observed(("x", A), ("z", A)))
    assert (partial.status, partial.comparison) == (S.PARTIAL, C.PARTIAL)
    assert [c["key"] for c in partial.changes["added"]] == ["z"] and partial.changes["removed"] == []
    assert {i["key"] for i in partial.items} == {"x", "y", "z"}
    # Compared with a partial snapshot: still no removals, and the comparison says so.
    assert complete.comparison is C.PARTIAL and complete.changes["removed"] == []


def test_a_failed_phase_is_not_comparable():
    first = compare(None, observed(("x", A)), STRICT)
    failed = compare(snapshot(first), observed(failed=True), STRICT)
    assert (failed.status, failed.comparison, failed.changed) == (S.FAILED, C.FAILED, False)
    assert failed.items == first.items


def test_removals_can_be_debounced_and_disabled():
    outcomes = chain(DEBOUNCED, observed(("x", A), ("y", A)), observed(("x", A)), observed(("x", A)))
    assert not outcomes[1].changed and outcomes[1].pending == [{"key": "y", "value": None, "seen": 1}]
    assert [c["key"] for c in outcomes[2].changes["removed"]] == ["y"]
    never = chain(rules_for(RunPhase.DISCOVERY), observed(("x", True), ("y", True)), observed(("x", True)))
    assert never[1].comparison is C.UNCHANGED and {i["key"] for i in never[1].items} == {"x", "y"}


def test_confirmation_counts_come_from_settings():
    assert rules_for(RunPhase.HTTP).confirm == 2
    assert rules_for(RunPhase.HTTP, {"http": 1}).confirm == 1
    assert rules_for(RunPhase.DISCOVERY, {"http": 3}).removals is False


def alerts_for(phase, outcome):
    return [(c.type, c.key) for c in alertable(snapshot(outcome, phase=phase))]


def test_only_news_is_alertable():
    _, discovery = chain(rules_for(RunPhase.DISCOVERY), observed(("a.example.com", True)),
                         observed(("a.example.com", True), ("b.example.com", True)))
    assert alerts_for(RunPhase.DISCOVERY, discovery) == [("asset.discovered", "b.example.com")]
    _, http = chain(STRICT, observed(("https://a", A)), observed(("https://a", B), ("https://b", A)))
    assert alerts_for(RunPhase.HTTP, http) == [("http.changed", "https://a")]  # a new service is part of discovery

    opened = {"status": "open", "severity": "high", "recurrences": 0}
    resolved = {**opened, "status": "resolved"}
    reopened = {**opened, "recurrences": 1}
    triaged = {**opened, "status": "triaged"}
    _, found, fixed, back, human = chain(
        STRICT, observed(), observed(("f1", opened)), observed(("f1", resolved)), observed(("f1", reopened)),
        observed(("f1", triaged)))
    assert alerts_for(RunPhase.CHECKS, found) == [("finding.opened", "f1")]
    assert alerts_for(RunPhase.CHECKS, fixed) == [("finding.resolved", "f1")]
    assert alerts_for(RunPhase.CHECKS, back) == [("finding.reopened", "f1")]
    assert alerts_for(RunPhase.CHECKS, human) == []  # triage is not news


def test_destination_event_filters():
    kinds = ["asset.discovered", "finding.opened"]
    assert wanted(kinds, "monitor.changes", ()) == kinds
    assert wanted(kinds, "monitor.changes", ("monitor.changes",)) == kinds
    assert wanted(kinds, "monitor.changes", ("finding.opened",)) == ["finding.opened"]
    assert wanted(kinds, "monitor.changes", ("monitor.run_failed",)) == []
