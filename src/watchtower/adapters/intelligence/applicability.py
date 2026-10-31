"""Careful advisory applicability matching.

A component is only *affected* when the product identity matches exactly and
a plain upstream version falls inside an affected range. Versions with vendor
suffixes (``2.4.49-1ubuntu1``, ``1.1.1k-fips``) may carry backported fixes, so
they are only *possible*. A missing version is *unknown*, never affected.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
import re

VERSION = re.compile(r"^v?(\d+(?:\.\d+){0,5})(.*)$")


class Applicability(StrEnum):
    AFFECTED = "affected"
    POSSIBLE = "possible"
    NOT_AFFECTED = "not_affected"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Match:
    applicability: Applicability
    reason: str


def parse_version(value: str) -> tuple[tuple[int, ...] | None, str]:
    found = VERSION.match(value.strip()) if value else None
    if not found:
        return None, value or ""
    return tuple(int(part) for part in found.group(1).split(".")), found.group(2)


def compare(left: tuple[int, ...], right: tuple[int, ...]) -> int:
    width = max(len(left), len(right))
    left, right = left + (0,) * (width - len(left)), right + (0,) * (width - len(right))
    return (left > right) - (left < right)


def in_range(version: tuple[int, ...], affected: dict) -> bool:
    introduced = parse_version(affected.get("introduced", "0"))[0] or (0,)
    if compare(version, introduced) < 0:
        return False
    if "fixed" in affected:
        return compare(version, parse_version(affected["fixed"])[0]) < 0
    if "last_affected" in affected:
        return compare(version, parse_version(affected["last_affected"])[0]) <= 0
    return True


def match_component(product: str, version: str | None, advisory: dict) -> Match:
    if product != advisory["product"]:
        return Match(Applicability.NOT_AFFECTED, f"advisory covers {advisory['product']}, not {product}")
    if not version:
        return Match(Applicability.UNKNOWN, "component version is not disclosed")
    parsed, suffix = parse_version(version)
    if parsed is None:
        return Match(Applicability.UNKNOWN, f"version {version!r} is not comparable")
    hit = next((affected for affected in advisory["affected"] if in_range(parsed, affected)), None)
    if hit is None:
        return Match(Applicability.NOT_AFFECTED, f"{product} {version} is outside every affected range")
    bound = hit.get("fixed") and f"fixed in {hit['fixed']}" or f"last affected {hit.get('last_affected', 'open')}"
    if advisory.get("prerequisites") or advisory.get("platforms"):
        return Match(Applicability.POSSIBLE,
                     f"{product} {version} is in range ({bound}), but platform/configuration prerequisites remain unverified")
    if suffix.strip():
        return Match(Applicability.POSSIBLE,
                     f"{product} {version} is in range ({bound}) but the vendor suffix may carry a backported fix")
    return Match(Applicability.AFFECTED, f"{product} {version} is in range introduced "
                                         f"{hit.get('introduced', '0')}, {bound}")
