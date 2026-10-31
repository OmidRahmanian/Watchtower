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
import ssl
import time
from collections.abc import Callable
from urllib.parse import urlsplit, urlunsplit

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
    """HTTPS to one policy-approved address, without proxies or redirects.

    The historical function name is retained for callers; requests is no longer
    required. Error messages intentionally exclude the URL and its credentials.
    """
    from watchtower.adapters.probing.http import PinnedHTTPSConnection, system_resolve
    from watchtower.security.destinations import DestinationPolicy

    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname or parts.username or parts.password:
        raise FeedError("feed must be an HTTPS URL without credentials")
    policy = DestinationPolicy()
    host, port = parts.hostname, parts.port or 443
    if policy.check_hostname(host):
        raise FeedError("feed hostname is prohibited")
    addresses = list(system_resolve(host, port))
    if not addresses or any(policy.check_address(a) for a in addresses):
        raise FeedError("feed resolved to a prohibited destination")
    connection = PinnedHTTPSConnection(host, addresses[0], port, 20, ssl.create_default_context())
    try:
        connection.request("GET", urlunsplit(("", "", parts.path or "/", parts.query, "")),
                           headers={"User-Agent": "WatchTower-intel/1", "Connection": "close"})
        response = connection.getresponse()
        if response.status != 200:
            raise FeedError(f"feed returned HTTP {response.status}; redirects are not followed")
        deadline = time.monotonic() + 60
        body = bytearray()
        while len(body) <= MAX_DOWNLOAD:
            if time.monotonic() > deadline:
                raise FeedError("feed download timed out")
            chunk = response.read(min(1 << 20, MAX_DOWNLOAD + 1 - len(body)))
            if not chunk:
                return bytes(body)
            body.extend(chunk)
        raise FeedError("feed download exceeds size limit")
    finally:
        connection.close()


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
                with gzip.GzipFile(fileobj=io.BytesIO(raw)) as compressed:
                    raw = compressed.read(MAX_DOWNLOAD + 1)
                if len(raw) > MAX_DOWNLOAD:
                    raise FeedError("uncompressed feed exceeds size limit")
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
                    from watchtower.adapters.intelligence.applicability import parse_version, compare
                    bounds = {name: parse_version(value) for name, value in affected.items()}
                    if any(parsed is None or suffix for parsed, suffix in bounds.values()):
                        raise FeedError(f"advisory {item['id']} has an uncomparable version bound")
                    start = bounds.get("introduced", ((0,), ""))[0]
                    if ("fixed" in bounds and compare(bounds["fixed"][0], start) <= 0) or \
                            ("last_affected" in bounds and compare(bounds["last_affected"][0], start) < 0):
                        raise FeedError(f"advisory {item['id']} has reversed version bounds")
                cvss = item.get("cvss")
                if cvss is not None and not 0 <= float(cvss) <= 10:
                    raise FeedError(f"advisory {item['id']} has an invalid CVSS score")
                records[item["id"]] = {
                    "id": item["id"], "cves": list(item.get("cves", [])), "product": item["product"].lower(),
                    "affected": item["affected"], "cvss": cvss, "summary": item.get("summary", ""),
                    "prerequisites": item.get("prerequisites", []), "platforms": item.get("platforms", []),
                    "references": item.get("references", []), "source": item.get("source", ""),
                }
            published = parse_time(data["generated_at"]) if data.get("generated_at") else None
        except (KeyError, TypeError, ValueError) as error:
            raise FeedError(f"malformed advisories: {error}") from error
        return ParsedFeed(records, published)
