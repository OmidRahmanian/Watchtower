"""Where evidence blobs live, shared by the API and the CLI."""

from __future__ import annotations

from pathlib import Path
from typing import Any

DEFAULT_EVIDENCE_ROOT = "data/evidence"


def default_evidence_root(settings: Any) -> Path:
    """``pipeline.evidence_root`` from settings, the same store the workers write to."""
    pipeline = getattr(settings, "pipeline", None)
    return Path(getattr(pipeline, "evidence_root", None) or DEFAULT_EVIDENCE_ROOT)
