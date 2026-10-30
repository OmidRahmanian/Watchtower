"""Test-only helpers for running checks.

The shipped rules are pending maintainer approval and refuse to run, so tests
that exercise check behavior load a temporary copy of the manifest in which a
test maintainer has approved every rule.
"""

from functools import cache
import json
from pathlib import Path
import shutil
import tempfile

from watchtower.adapters.checks import Authorization, RuleSet, load_manifest
from watchtower.adapters.checks.manifest import RULES_ROOT

TEST_APPROVER = "Test Maintainer <maintainer@example.com>"


def approve(manifest: dict, approver: str = TEST_APPROVER, when: str = "2026-10-30") -> dict:
    for entry in manifest["rules"]:
        entry["review"].update(status="approved", approved_by=approver, approved_at=when,
                               approved_sha256=entry["sha256"])
    return manifest


@cache
def approved_ruleset() -> RuleSet:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary) / "rules"
        shutil.copytree(RULES_ROOT, root)
        manifest = approve(json.loads((root / "manifest.json").read_text()))
        (root / "manifest.json").write_text(json.dumps(manifest))
        return load_manifest(root)


def allow(*addresses: str):
    """An authorizer that approves every URL for exactly ``addresses``."""
    return lambda url: Authorization(True, tuple(addresses))
