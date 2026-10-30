"""Manual entries and CSV imports. These make no network requests."""
from __future__ import annotations

import csv
import io
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone

from watchtower.services.inventory import DiscoveredName, in_domain, normalize_hostname

MAX_CSV_BYTES = 5 * 1024 * 1024
MAX_CSV_ROWS = 50_000


@dataclass
class ImportResult:
    names: list[DiscoveredName] = field(default_factory=list)
    errors: list[tuple[int, str]] = field(default_factory=list)


def _root_for(hostname: str, root: str, line: int, result: ImportResult) -> str | None:
    if not root:
        return hostname
    try:
        root = normalize_hostname(root)
    except ValueError as exc:
        result.errors.append((line, str(exc)))
        return None
    if not in_domain(hostname, root):
        result.errors.append((line, f"{hostname} is not within {root}"))
        return None
    return root


def manual_entries(hostnames: Iterable[str], *, root_domain: str = "", operator: str = "") -> ImportResult:
    result = ImportResult()
    detail = {"operator": operator} if operator else {}
    for line, value in enumerate(hostnames, start=1):
        try:
            hostname = normalize_hostname(value)
        except ValueError as exc:
            result.errors.append((line, str(exc)))
            continue
        root = _root_for(hostname, root_domain, line, result)
        if root:
            result.names.append(DiscoveredName(hostname, "manual", root, detail=dict(detail)))
    return result


def _timestamp(value: str) -> datetime:
    moment = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def import_csv(text: str, *, root_domain: str = "", source_file: str = "") -> ImportResult:
    """Parse CSV with a `hostname` column.

    Optional columns: `root_domain`, `ownership_confidence` (0-1),
    `discovered_at` (ISO 8601), and `note`. Bad rows are reported, not raised.
    """
    result = ImportResult()
    if len(text.encode()) > MAX_CSV_BYTES:
        result.errors.append((0, f"CSV exceeds {MAX_CSV_BYTES} bytes"))
        return result
    reader = csv.DictReader(io.StringIO(text))
    fields = {name.strip().lower() for name in reader.fieldnames or []}
    if "hostname" not in fields:
        result.errors.append((1, "CSV needs a hostname column"))
        return result

    for row_number, row in enumerate(reader, start=2):
        if row_number - 1 > MAX_CSV_ROWS:
            result.errors.append((row_number, f"stopped after {MAX_CSV_ROWS} rows"))
            break
        row = {(key or "").strip().lower(): (value or "").strip() for key, value in row.items() if key}
        if not any(row.values()):
            continue
        try:
            hostname = normalize_hostname(row["hostname"])
            confidence = float(row["ownership_confidence"]) if row.get("ownership_confidence") else None
            if confidence is not None and not 0.0 <= confidence <= 1.0:
                raise ValueError("ownership_confidence must be between 0 and 1")
            observed_at = _timestamp(row["discovered_at"]) if row.get("discovered_at") else None
        except ValueError as exc:
            result.errors.append((row_number, str(exc)))
            continue
        root = _root_for(hostname, row.get("root_domain") or root_domain, row_number, result)
        if not root:
            continue
        detail = {"row": row_number}
        if source_file:
            detail["file"] = source_file
        if row.get("note"):
            detail["note"] = row["note"]
        result.names.append(DiscoveredName(hostname, "csv", root, observed_at, confidence, detail))
    return result
