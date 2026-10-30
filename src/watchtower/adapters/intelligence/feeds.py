"""Parsers for vulnerability intelligence feeds.

Each feed turns a raw download into ``ParsedFeed`` records keyed by id. A
parser raises ``FeedError`` on anything malformed, so the store can keep its
previous snapshot instead of saving partial data.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass, field
from datetime import datetime, timedelta, UTC
import gzip
import io
import json
import re
from collections.abc import Callable

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
MAX_DOWNLOAD = 128 * 1024 * 1024
CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")

Transport = Callable[[str], bytes]


class FeedError(ValueError):
    pass


@dataclass
class ParsedFeed:
    records: dict[str, dict]
    published_at: datetime | None = None
    meta: dict = field(default_factory=dict)


def requests_transport(url: str) -> bytes:
    import requests

    with requests.get(url, timeout=60, stream=True, headers={"User-Agent": "WatchTower-intel/1"}) as response:
        response.raise_for_status()
        body = b""
        for chunk in response.iter_content(1 << 20):
            body += chunk
            if len(body) > MAX_DOWNLOAD:
                raise FeedError("download exceeds size limit")
        return body


def parse_time(value: str) -> datetime:
    value = value.strip().replace("Z", "+00:00")
    # Python 3.9 accepts only 3 or 6 fractional digits; KEV uses others.
    value = re.sub(r"\.(\d+)", lambda found: "." + found.group(1)[:6].ljust(6, "0"), value)
    value = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", value)
    parsed = datetime.fromisoformat(value) if "T" in value else datetime.fromisoformat(value + "T00:00:00+00:00")
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


class Feed:
    name = ""
    max_age = timedelta(days=1)
    # Some feeds also carry their own publication date that must stay recent.
    max_published_age: timedelta | None = None

    def __init__(self, url: str, transport: Transport = requests_transport):
        self.url = url
        self.transport = transport

    def fetch(self) -> ParsedFeed:
        return self.parse(self.transport(self.url))

    def parse(self, raw: bytes) -> ParsedFeed:
        raise NotImplementedError


class KevFeed(Feed):
    name = "kev"
    max_age = timedelta(days=2)

    def __init__(self, url: str = KEV_URL, transport: Transport = requests_transport):
        super().__init__(url, transport)

    def parse(self, raw: bytes) -> ParsedFeed:
        try:
            data = json.loads(raw)
            items = data["vulnerabilities"]
            records = {}
            for item in items:
                cve = item["cveID"].strip()
                if not CVE.match(cve):
                    raise FeedError(f"invalid KEV id {cve!r}")
                records[cve] = {
                    "vendor": item.get("vendorProject", ""), "product": item.get("product", ""),
                    "name": item.get("vulnerabilityName", ""), "date_added": item.get("dateAdded", ""),
                    "due_date": item.get("dueDate", ""),
                    "ransomware": item.get("knownRansomwareCampaignUse", "Unknown"),
                }
            if "count" in data and int(data["count"]) != len(items):
                raise FeedError(f"KEV count {data['count']} does not match {len(items)} entries")
            published = parse_time(data["dateReleased"]) if data.get("dateReleased") else None
        except (KeyError, TypeError, ValueError) as error:
            raise FeedError(f"malformed KEV catalog: {error}") from error
        return ParsedFeed(records, published, {"catalog_version": data.get("catalogVersion", "")})


class EpssFeed(Feed):
    name = "epss"
    max_age = timedelta(days=2)
    max_published_age = timedelta(days=3)

    def __init__(self, url: str = EPSS_URL, transport: Transport = requests_transport):
        super().__init__(url, transport)

    def parse(self, raw: bytes) -> ParsedFeed:
        try:
            if raw[:2] == b"\x1f\x8b":
                raw = gzip.decompress(raw)
            lines = io.StringIO(raw.decode("utf-8"))
            meta = {}
            first = lines.readline()
            if first.startswith("#"):
                meta = dict(part.split(":", 1) for part in first[1:].strip().split(",") if ":" in part)
            else:
                lines.seek(0)
            records = {}
            for row in csv.DictReader(lines):
                cve, score, percentile = row["cve"].strip(), float(row["epss"]), float(row["percentile"])
                if not CVE.match(cve) or not 0 <= score <= 1 or not 0 <= percentile <= 1:
                    raise FeedError(f"invalid EPSS row for {cve!r}")
                records[cve] = {"epss": score, "percentile": percentile}
            published = parse_time(meta["score_date"]) if meta.get("score_date") else None
        except (KeyError, TypeError, ValueError, OSError, UnicodeDecodeError) as error:
            raise FeedError(f"malformed EPSS data: {error}") from error
        return ParsedFeed(records, published, {"model_version": meta.get("model_version", "")})


class AdvisoryFeed(Feed):
    """Curated advisories in WatchTower's normalized format (see rules/README.md)."""

    name = "advisories"
    max_age = timedelta(days=7)

    def parse(self, raw: bytes) -> ParsedFeed:
        try:
            data = json.loads(raw)
            records = {}
            for item in data["advisories"]:
                if not item.get("id") or not item.get("product") or not item.get("affected"):
                    raise FeedError(f"advisory missing id, product, or affected ranges: {item.get('id')!r}")
                if not all(CVE.match(cve) for cve in item.get("cves", [])):
                    raise FeedError(f"advisory {item['id']} has an invalid CVE")
                for affected in item["affected"]:
                    if not set(affected) <= {"introduced", "fixed", "last_affected"} or \
                            ("fixed" in affected and "last_affected" in affected):
                        raise FeedError(f"advisory {item['id']} has an invalid range")
                cvss = item.get("cvss")
                if cvss is not None and not 0 <= float(cvss) <= 10:
                    raise FeedError(f"advisory {item['id']} has an invalid CVSS score")
                records[item["id"]] = {
                    "id": item["id"], "cves": list(item.get("cves", [])), "product": item["product"].lower(),
                    "affected": item["affected"], "cvss": cvss, "summary": item.get("summary", ""),
                }
            published = parse_time(data["generated_at"]) if data.get("generated_at") else None
        except (KeyError, TypeError, ValueError) as error:
            raise FeedError(f"malformed advisories: {error}") from error
        return ParsedFeed(records, published)
