"""Pinned rule manifests.

``rules/manifest.json`` lists every rule that may load, with the SHA-256 of
its definition and a review record. A rule file that is missing, unpinned,
unreviewed, or changed since it was pinned is refused. Rule ids are stable
finding keys: versions may change freely, and renamed rules list their old
ids as aliases so existing findings keep their fingerprints.

A pinned rule may be ``pending`` maintainer approval. Pending rules load, so
they can be listed and reviewed, but every check refuses to run them with
``RuleNotApproved``. Approval names a human maintainer and the exact hash
approved, so editing an approved rule returns it to an unrunnable state.

Verify pins:      python -m watchtower.adapters.checks
Show new hashes:  python -m watchtower.adapters.checks --hashes
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
import hashlib
import json
import os
from pathlib import Path
import re
import sys

import watchtower
from watchtower.domain.models import Severity



def default_rules_root() -> Path:
    """``WATCHTOWER_RULES_DIR``, else the rules packaged in the wheel, else the source checkout."""
    if os.environ.get("WATCHTOWER_RULES_DIR"):
        return Path(os.environ["WATCHTOWER_RULES_DIR"])
    packaged = Path(watchtower.__file__).resolve().parent / "_rules"
    return packaged if packaged.is_dir() else Path(__file__).resolve().parents[4] / "rules"


RULES_ROOT = default_rules_root()
RULE_ID = re.compile(r"^[a-z0-9][a-z0-9-]{1,63}$")
SEVERITIES = tuple(severity.value for severity in Severity)
CONFIDENCES = ("tentative", "firm", "confirmed")
METHODS = ("GET", "HEAD")
KINDS = ("http", "component")
REVIEW_STATUSES = ("pending", "approved")
APPROVAL_FIELDS = ("approved_by", "approved_at", "approved_sha256")
# Approval must come from a human maintainer. This refuses obvious automation
# identities; the real control is that manifest changes go through human review.
AUTOMATED_APPROVER = re.compile(
    r"(?i)(?:\bagent\b|agent[-_ ]?\d|claude|anthropic|openai|\bgpt|copilot|gemini|\bllm\b|\bai\b|"
    r"\bbot\b|\[bot\]|[-_]bot\b|automat|\bci\b)"
)


class RuleIntegrityError(ValueError):
    pass


class RuleNotApproved(PermissionError):
    """A pinned rule is still pending maintainer approval, so it must not run."""


@dataclass(frozen=True, slots=True)
class Rule:
    id: str
    version: str
    sha256: str
    definition: dict = field(compare=False, repr=False)
    aliases: tuple[str, ...] = ()
    review: dict = field(default_factory=dict, compare=False, repr=False)

    @property
    def kind(self) -> str:
        return self.definition["kind"]

    @property
    def severity(self) -> Severity:
        return Severity(self.definition["severity"])

    @property
    def confidence(self) -> str:
        return self.definition["confidence"]

    @property
    def title(self) -> str:
        return self.definition["title"]

    @property
    def cves(self) -> tuple[str, ...]:
        return tuple(self.definition.get("cves", ()))

    @property
    def approved(self) -> bool:
        review = self.review or {}
        return review.get("status") == "approved" and review.get("approved_sha256") == self.sha256

    def require_approved(self) -> None:
        """Raise ``RuleNotApproved`` unless a maintainer approved this exact rule content."""
        if not self.approved:
            raise RuleNotApproved(f"{self.id} {self.version} is pending maintainer approval and cannot run")


@dataclass(frozen=True, slots=True)
class RuleSet:
    rules: dict[str, Rule]
    aliases: dict[str, str]

    def canonical_id(self, rule_id: str) -> str:
        return self.aliases.get(rule_id, rule_id)

    def get(self, rule_id: str) -> Rule:
        return self.rules[self.canonical_id(rule_id)]

    def __iter__(self):
        return iter(self.rules.values())

    @property
    def pending(self) -> list[str]:
        return sorted(rule.id for rule in self if not rule.approved)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _require(condition: bool, message: str):
    if not condition:
        raise RuleIntegrityError(message)


def validate_definition(rule: dict) -> None:
    rule_id = rule.get("id", "?")
    _require(bool(RULE_ID.match(str(rule.get("id", "")))), f"{rule_id}: invalid id")
    _require(rule.get("kind") in KINDS, f"{rule_id}: unknown kind")
    _require(rule.get("severity") in SEVERITIES, f"{rule_id}: invalid severity")
    _require(rule.get("confidence") in CONFIDENCES, f"{rule_id}: invalid confidence")
    _require(bool(rule.get("title")), f"{rule_id}: missing title")
    execution = rule.get("execution_policy", {})
    _require(execution.get("engine") == "watchtower-native/1", f"{rule_id}: unsupported execution engine")
    _require(bool(execution.get("source") and execution.get("license") and execution.get("remediation")),
             f"{rule_id}: source, license and remediation metadata are required")
    _require(execution.get("requests_per_endpoint") == (1 if rule["kind"] == "http" else 0),
             f"{rule_id}: request budget does not match the native engine")
    for effect in ("writes_data", "browser", "executes_code", "external_callbacks", "credentials"):
        _require(execution.get(effect) is False, f"{rule_id}: unsupported execution effect {effect}")
    for cve in rule.get("cves", []):
        _require(bool(re.match(r"^CVE-\d{4}-\d{4,}$", cve)), f"{rule_id}: invalid CVE {cve}")
    if rule["kind"] == "http":
        request = rule.get("request", {})
        _require(request.get("method") in METHODS, f"{rule_id}: only GET and HEAD are allowed")
        path = str(request.get("path", ""))
        _require(path.startswith("/") and not path.startswith("//") and "://" not in path,
                 f"{rule_id}: path must be relative to the target")
        _require(set(rule.get("match", {})) <= {"status", "body_all", "body_any", "body_none", "headers"},
                 f"{rule_id}: unknown matcher")
        _require(bool(rule.get("negative_status")), f"{rule_id}: negative_status is required")
        patterns = list(rule["match"].get("body_all", [])) + list(rule["match"].get("body_any", []))
        patterns += list(rule["match"].get("body_none", [])) + list(rule["match"].get("headers", {}).values())
        for pattern in patterns:
            try:
                re.compile(pattern)
            except re.error as error:
                raise RuleIntegrityError(f"{rule_id}: bad pattern {pattern!r}: {error}") from error
    else:
        _require(bool(rule.get("source_rule")), f"{rule_id}: component rules need source_rule")
        _require(bool(rule.get("product_map")), f"{rule_id}: component rules need product_map")


def validate_review(rule_id: str, review: dict, sha256: str) -> None:
    _require(bool(review.get("reviewer") and review.get("date")), f"{rule_id}: rule has no review record")
    status = review.get("status")
    _require(status in REVIEW_STATUSES, f"{rule_id}: review status must be one of {', '.join(REVIEW_STATUSES)}")
    if status == "pending":
        _require(not any(review.get(name) for name in APPROVAL_FIELDS),
                 f"{rule_id}: a pending review must not carry approval fields")
        return
    approver = str(review.get("approved_by") or "").strip()
    _require(bool(approver), f"{rule_id}: an approved review needs approved_by")
    _require(not AUTOMATED_APPROVER.search(approver),
             f"{rule_id}: approved_by {approver!r} looks automated; only a human maintainer may approve")
    try:
        date.fromisoformat(str(review.get("approved_at") or ""))
    except ValueError as error:
        raise RuleIntegrityError(f"{rule_id}: an approved review needs approved_at as YYYY-MM-DD") from error
    _require(review.get("approved_sha256") == sha256,
             f"{rule_id}: approved_sha256 does not match the pinned hash; the approval covers other content")


def load_manifest(root: Path = RULES_ROOT) -> RuleSet:
    manifest = json.loads((root / "manifest.json").read_text())
    _require(manifest.get("manifest_version") == 1, "unsupported manifest_version")
    rules: dict[str, Rule] = {}
    aliases: dict[str, str] = {}
    pinned_paths = set()
    for entry in manifest["rules"]:
        rule_id = entry["id"]
        path = (root / entry["path"]).resolve()
        _require(root.resolve() in path.parents, f"{rule_id}: rule path escapes rules directory")
        _require(path.is_file(), f"{rule_id}: rule file missing")
        actual = digest(path)
        _require(actual == entry.get("sha256"),
                 f"{rule_id}: content hash {actual} does not match pinned {entry.get('sha256')}")
        review = entry.get("review") or {}
        validate_review(rule_id, review, actual)
        definition = json.loads(path.read_text())
        validate_definition(definition)
        _require(definition["id"] == rule_id and definition["version"] == entry["version"],
                 f"{rule_id}: manifest id/version disagree with rule file")
        _require(rule_id not in rules and rule_id not in aliases, f"{rule_id}: duplicate rule id")
        for alias in entry.get("aliases", []):
            _require(alias not in aliases and alias not in rules, f"{rule_id}: alias {alias} reused")
            aliases[alias] = rule_id
        rules[rule_id] = Rule(rule_id, entry["version"], actual, definition, tuple(entry.get("aliases", [])), review)
        pinned_paths.add(path)
    _require(not set(rules) & set(aliases), "an alias shadows a live rule id")
    for rule in rules.values():
        if rule.kind == "component":
            _require(rule.definition["source_rule"] in rules, f"{rule.id}: unknown source_rule")
    return RuleSet(rules, aliases)


def unpinned_files(root: Path = RULES_ROOT) -> list[Path]:
    manifest = json.loads((root / "manifest.json").read_text())
    pinned = {(root / entry["path"]).resolve() for entry in manifest["rules"]}
    return sorted(path for path in root.rglob("*.json")
                  if path.name != "manifest.json" and path.resolve() not in pinned)


def main(argv: list[str]) -> int:
    if "--hashes" in argv:
        for path in sorted(RULES_ROOT.rglob("*.json")):
            if path.name != "manifest.json":
                print(f"{digest(path)}  {path.relative_to(RULES_ROOT)}")
        return 0
    try:
        ruleset = load_manifest()
    except RuleIntegrityError as error:
        print(f"Rule manifest rejected: {error}", file=sys.stderr)
        return 1
    for path in unpinned_files():
        print(f"Unpinned rule ignored: {path.relative_to(RULES_ROOT)}", file=sys.stderr)
    pending = ruleset.pending
    print(f"{len(ruleset.rules)} pinned rules verified: {len(ruleset.rules) - len(pending)} approved, "
          f"{len(pending)} pending approval.")
    for rule_id in pending:
        print(f"Pending maintainer approval (will not run): {rule_id}")
    return 0
