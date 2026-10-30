"""Opaque keyset cursors.

A cursor is the sort key of the last row on a page, encoded as URL-safe
base64 JSON. It carries no authority: every query still runs inside the
caller's project, so a cursor copied from another project matches nothing.
"""

from __future__ import annotations

import base64
import binascii
import json
from datetime import datetime
from typing import Any
from uuid import UUID

from watchtower.domain.errors import WatchtowerError

DEFAULT_LIMIT = 50
MAX_LIMIT = 200
MAX_CURSOR_LENGTH = 1024


class InvalidCursor(WatchtowerError, ValueError):
    """A pagination cursor was malformed or belongs to a different listing."""


def _plain(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, UUID):
        return str(value)
    return value


def encode_cursor(kind: str, *values: Any) -> str:
    raw = json.dumps([kind, *(_plain(value) for value in values)], separators=(",", ":"))
    return base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")


def decode_cursor(cursor: str, kind: str, size: int) -> list[Any]:
    """Return the ``size`` sort-key values of a cursor made by ``encode_cursor(kind, ...)``."""
    if len(cursor) > MAX_CURSOR_LENGTH:
        raise InvalidCursor("cursor is too long")
    try:
        raw = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4))
        data = json.loads(raw)
    except (binascii.Error, ValueError, UnicodeDecodeError):
        raise InvalidCursor("cursor is malformed") from None
    if not isinstance(data, list) or len(data) != size + 1 or data[0] != kind:
        raise InvalidCursor("cursor does not belong to this listing")
    if not all(isinstance(value, (str, int)) for value in data[1:]):
        raise InvalidCursor("cursor is malformed")
    return data[1:]


def cursor_time(value: Any) -> datetime:
    try:
        moment = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        raise InvalidCursor("cursor is malformed") from None
    if moment.tzinfo is None:
        raise InvalidCursor("cursor is malformed")
    return moment


def cursor_uuid(value: Any) -> UUID:
    try:
        return UUID(str(value))
    except ValueError:
        raise InvalidCursor("cursor is malformed") from None
