"""Explainable prioritization.

Priority is computed from a finding's severity and confidence plus KEV and
EPSS data for its CVEs. Every point added or removed is listed as a factor
with a reason, and the freshness of each intelligence source is attached so a
reader can tell when a priority rests on stale or missing data. Priority never
changes severity, confidence, workflow status, or detection state.
"""

from __future__ import annotations

from datetime import datetime

from watchtower.adapters.checks.base import utcnow
from watchtower.adapters.intelligence.feeds import Feed
from watchtower.adapters.intelligence.store import FreshnessState, IntelligenceStore
from watchtower.services.findings import FindingRecord

SEVERITY_POINTS = {"info": 5, "low": 20, "medium": 45, "high": 70, "critical": 90}
CONFIDENCE_POINTS = {"tentative": -15, "firm": 0, "confirmed": 5}
LEVELS = ((85, "P1"), (60, "P2"), (35, "P3"), (0, "P4"))
ORDER = ["P1", "P2", "P3", "P4"]
EPSS_HIGH, EPSS_ELEVATED = 0.5, 0.1


def level_for(score: int) -> str:
    return next(name for floor, name in LEVELS if score >= floor)


def prioritize(finding: FindingRecord, intelligence: IntelligenceStore, kev: Feed, epss: Feed,
               now: datetime | None = None, importance: str = "normal") -> dict:
    now = now or utcnow()
    factors: list[dict] = []

    def factor(name: str, points: int, detail: str):
        factors.append({"factor": name, "points": points, "detail": detail})

    factor("severity", SEVERITY_POINTS[finding.severity], f"{finding.severity.value} severity from {finding.check_id}")
    if importance not in ("low", "normal", "high", "critical"):
        raise ValueError("invalid asset importance")
    if importance in ("high", "critical"):
        factor("asset_importance", 5 if importance == "high" else 10, f"asset importance is {importance}")
    if CONFIDENCE_POINTS[finding.confidence]:
        factor("confidence", CONFIDENCE_POINTS[finding.confidence], f"{finding.confidence} confidence")

    # Tentative component matches (for example backported vendor builds) are
    # only possibly affected, so they never reach P1 until a human confirms them.
    applicability = "possible" if finding.confidence == "tentative" else "affected"
    freshness = {feed.name: intelligence.freshness(feed, now) for feed in (kev, epss)}
    for source, state in freshness.items():
        if finding.cves and state.state != FreshnessState.FRESH:
            factor(f"{source}_freshness", 0, f"{source.upper()} data {state.state.value}: {state.reason}")

    floor = None
    kev_hits = [(cve, intelligence.record("kev", cve)) for cve in finding.cves]
    kev_hits = [(cve, entry) for cve, entry in kev_hits if entry]
    if kev_hits:
        cve, entry = kev_hits[0]
        points = 20 if applicability == "affected" else 10
        factor("kev", points, f"{cve} is in CISA KEV (added {entry['date_added']}); applicability {applicability}")
        floor = "P1" if applicability == "affected" else "P2"
        if any(entry.get("ransomware") == "Known" for _, entry in kev_hits):
            factor("kev_ransomware", 5, "KEV lists known ransomware campaign use")
    elif finding.cves and freshness["kev"].state != FreshnessState.MISSING:
        factor("kev", 0, f"none of {', '.join(finding.cves)} is in CISA KEV")

    scores = [(cve, intelligence.record("epss", cve)) for cve in finding.cves]
    scores = [(cve, score) for cve, score in scores if score]
    if scores:
        cve, score = max(scores, key=lambda item: item[1]["epss"])
        points = 15 if score["epss"] >= EPSS_HIGH else 8 if score["epss"] >= EPSS_ELEVATED else 0
        factor("epss", points, f"{cve} EPSS {score['epss']:.3f} (percentile {score['percentile']:.3f})")

    score = sum(item["points"] for item in factors)
    level = level_for(score)
    if floor and ORDER.index(floor) < ORDER.index(level):
        factors.append({"factor": "kev_floor", "points": 0,
                        "detail": f"KEV listing with {applicability} applicability raises priority to {floor}"})
        level = floor
    if finding.cves and applicability == "possible" and level == "P1":
        factors.append({"factor": "applicability_cap", "points": 0,
                        "detail": "the match is only possible (version may carry a backported fix), so it is capped at P2"})
        level = "P2"
    return {
        "level": level,
        "score": score,
        "computed_at": now.isoformat(),
        "applicability": applicability if finding.cves else None,
        "factors": factors,
        "intelligence": {source: state.to_dict() for source, state in freshness.items()},
    }
