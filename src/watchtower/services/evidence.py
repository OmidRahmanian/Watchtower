"""Redacted, append-only evidence.

Raw response bodies are never stored. Evidence keeps a bounded excerpt around
the match after secrets are redacted, plus a digest of the redacted body so
later occurrences can be compared without keeping secret-derived values.
"""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime
import hashlib
import json
import re
from collections.abc import Iterable
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from uuid import UUID

from watchtower.domain.models import NewEvidence
from watchtower.domain.repositories import BlobStore

REDACTED = "[REDACTED]"
MEDIA_TYPE = "application/vnd.watchtower.evidence+json"
EXCERPT_LIMIT = 2048
SENSITIVE_HEADERS = {
    "authorization", "proxy-authorization", "cookie", "set-cookie",
    "x-api-key", "x-auth-token", "x-amz-security-token",
}
KEPT_HEADERS = {"server", "content-type", "content-length", "location", "x-powered-by", "www-authenticate"}
SENSITIVE_NAME = r"(?:pass(?:word|wd)?|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential|auth)"

PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)", re.S),
     REDACTED),
    (re.compile(r"(?<![A-Za-z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Za-z0-9])"), REDACTED),
    (re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"), REDACTED),
    (re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]{8,}"), r"\1" + REDACTED),
    (re.compile(r"(?i)(\b[a-z][a-z0-9+.-]*://)[^/\s:@]+:[^/\s@]+@"), r"\1" + REDACTED + "@"),
    (re.compile(r"(?i)([\"']?[A-Za-z0-9_.-]*" + SENSITIVE_NAME + r"[A-Za-z0-9_.-]*[\"']?\s*[:=]\s*)"
                r"(\"[^\"\n]*\"|'[^'\n]*'|[^\s,;&<]+)"), r"\1" + REDACTED),
]
# Every value of KEY=VALUE lines is redacted for files such as .env, where any
# value may be a credential. The key names stay because they are the evidence.
ENV_LINE = re.compile(r"(?m)^(\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_.]*\s*=[ \t]*)(\S.*)$")


def redact_text(text: str, profile: str = "default") -> tuple[str, int]:
    count = 0
    if profile == "env":
        text, count = ENV_LINE.subn(r"\1" + REDACTED, text)
    for pattern, replacement in PATTERNS:
        text, hits = pattern.subn(replacement, text)
        count += hits
    return text, count


def redact_url(url: str) -> str:
    parts = urlsplit(url)
    netloc = parts.netloc.rsplit("@", 1)[-1]
    query = urlencode([
        (key, REDACTED if re.search(SENSITIVE_NAME, key, re.I) else value)
        for key, value in parse_qsl(parts.query, keep_blank_values=True)
    ], safe="[]")
    return urlunsplit((parts.scheme, netloc, parts.path, query, ""))


def redact_headers(headers: Iterable[tuple[str, str]]) -> list[list[str]]:
    kept = []
    for key, value in headers:
        lower = key.lower()
        if lower in SENSITIVE_HEADERS:
            kept.append([key, REDACTED])
        elif lower in KEPT_HEADERS:
            kept.append([key, redact_text(value)[0]])
    return kept


def excerpt(text: str, span: tuple[int, int] | None, limit: int = EXCERPT_LIMIT) -> str:
    if len(text) <= limit:
        return text
    start = 0 if span is None else max(0, span[0] - limit // 4)
    return text[start:start + limit]


def http_evidence(url: str, method: str, response, *, observed_at: datetime, check_id: str,
                  rule_version: str, resolved_ip: str | None = None,
                  match_span: tuple[int, int] | None = None, profile: str = "default") -> dict:
    text = response.text
    redacted_body, body_hits = redact_text(text, profile)
    # Redact the full body before choosing the excerpt so a secret cannot be
    # cut in half at the excerpt boundary and slip past the patterns.
    if match_span is not None:
        prefix, _ = redact_text(text[:match_span[0]], profile)
        match_span = (len(prefix), len(prefix))
    return {
        "kind": "http",
        "check_id": check_id,
        "rule_version": rule_version,
        "observed_at": observed_at.isoformat(),
        "request": {"method": method, "url": redact_url(url)},
        "resolved_ip": resolved_ip,
        "response": {
            "status": response.status,
            "headers": redact_headers(response.headers),
            "body_excerpt": excerpt(redacted_body, match_span),
            "body_truncated": response.truncated,
            "redacted_body_sha256": hashlib.sha256(redacted_body.encode()).hexdigest(),
        },
        "redactions": body_hits,
    }


def canonical_bytes(evidence: dict) -> bytes:
    return json.dumps(evidence, sort_keys=True, separators=(",", ":"), default=str).encode()


def evidence_id(evidence: dict) -> str:
    return "ev_" + hashlib.sha256(canonical_bytes(evidence)).hexdigest()[:24]


def to_new_evidence(evidence: dict, blobs: BlobStore, project_id: UUID, *,
                    finding_id: UUID | None = None) -> NewEvidence:
    """Store already-redacted evidence as a blob and describe it with the shared record."""
    blob = blobs.put(project_id, canonical_bytes(evidence), media_type=MEDIA_TYPE)
    description = f"{evidence.get('check_id', '')} {evidence.get('rule_version', '')} at {evidence.get('observed_at', '')}"
    return NewEvidence(blob=blob, media_type=MEDIA_TYPE, description=description.strip(), finding_id=finding_id)


class EvidenceStore:
    """Append-only evidence keyed by content hash. Stored items are never mutated."""

    def __init__(self):
        self._items: dict[str, dict] = {}

    def add(self, evidence: dict) -> str:
        key = evidence_id(evidence)
        self._items.setdefault(key, deepcopy(evidence))
        return key

    def get(self, key: str) -> dict:
        return deepcopy(self._items[key])

    def __contains__(self, key: str) -> bool:
        return key in self._items

    def __len__(self) -> int:
        return len(self._items)
