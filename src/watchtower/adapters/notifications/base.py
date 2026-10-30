"""Notification delivery: rendering, senders per destination kind, and a pinned HTTPS transport.

Destination URLs embed credentials (webhook tokens, bot tokens), so errors
raised here never include them. Alert text quotes data from scanned hosts
(page titles, hostnames), which are not trusted: control characters are
stripped, lengths are capped, and mentions are disabled where the channel
supports it, so a hostile page title cannot ping a channel.

Delivery is at least once: a notifier that dies after sending but before
``mark_sent`` sends again. Every request carries the outbox ``dedupe_key``
(``Idempotency-Key`` and ``X-WatchTower-Delivery`` headers, and in the text
of chat messages) so receivers that support it, and readers, can tell a
redelivery from a new alert.
"""
from __future__ import annotations

import json
import logging
import re
import ssl
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import parse_qs, urlsplit, urlunsplit

from watchtower.adapters.probing.http import PinnedHTTPSConnection, ProbeError, system_resolve
from watchtower.domain.models import Notification
from watchtower.security.destinations import DestinationPolicy

USER_AGENT = "WatchTower-notifier/1"
log = logging.getLogger("watchtower.notifications")
TIMEOUT = 10.0
MAX_LINES = 25
_CONTROL = re.compile(r"[\x00-\x1f\x7f​-‏‪-‮⁦-⁩]")


class DeliveryError(Exception):
    """A send failed. ``retryable`` failures are retried with backoff; the rest fail the notification."""

    def __init__(self, message: str, *, retryable: bool, retry_after: float | None = None) -> None:
        super().__init__(message)
        self.retryable = retryable
        self.retry_after = retry_after


@dataclass(frozen=True, slots=True)
class Response:
    status: int
    headers: Mapping[str, str]
    body: bytes = b""


class Transport(Protocol):
    def post(self, url: str, body: bytes, headers: Mapping[str, str]) -> Response: ...


class PinnedTransport:
    """POST over HTTPS to an address that passed the destination policy, and only to that address.

    The name is resolved once; every address must pass ``DestinationPolicy``
    (no loopback, link-local, metadata or, unless allowed, private ranges),
    and the socket is opened to the approved IP with SNI and certificate
    checks for the hostname. Proxies and redirects are not followed.
    """

    def __init__(self, destinations: DestinationPolicy | None = None, *,
                 resolve: Callable[[str, int], Iterable[str]] = system_resolve, timeout: float = TIMEOUT,
                 context: ssl.SSLContext | None = None) -> None:
        self.destinations = destinations or DestinationPolicy()
        self.resolve = resolve
        self.timeout = timeout
        self.context = context or ssl.create_default_context()

    def post(self, url: str, body: bytes, headers: Mapping[str, str]) -> Response:
        parts = urlsplit(url)
        if parts.scheme != "https" or not parts.hostname:
            raise DeliveryError("destination must be an https:// URL", retryable=False)
        host, port = parts.hostname.lower(), parts.port or 443
        reason = self.destinations.check_hostname(host)
        if reason:
            raise DeliveryError(f"destination host refused: {reason}", retryable=False)
        try:
            addresses = list(self.resolve(host, port))
        except ProbeError as exc:
            raise DeliveryError(f"could not resolve {host}: {exc.kind}", retryable=True) from None
        refused = [r for r in (self.destinations.check_address(a) for a in addresses) if r]
        if not addresses or refused:
            raise DeliveryError(f"destination address refused: {refused[0] if refused else 'no address'}",
                                retryable=False)
        path = urlunsplit(("", "", parts.path or "/", parts.query, ""))
        connection = PinnedHTTPSConnection(host, addresses[0], port, self.timeout, self.context)
        try:
            connection.request("POST", path, body=body, headers={
                "User-Agent": USER_AGENT, "Content-Type": "application/json", "Connection": "close", **headers})
            response = connection.getresponse()
            return Response(response.status, {k.lower(): v for k, v in response.getheaders()}, response.read(65536))
        except (OSError, ssl.SSLError) as exc:
            raise DeliveryError(f"request to {host} failed: {type(exc).__name__}", retryable=True) from None
        finally:
            connection.close()


def _check(response: Response, host: str) -> None:
    if 200 <= response.status < 300:
        return
    retry_after = None
    try:
        retry_after = float(response.headers.get("retry-after", ""))
    except ValueError:
        pass
    retryable = response.status in (408, 425, 429) or response.status >= 500
    raise DeliveryError(f"{host} answered HTTP {response.status}", retryable=retryable, retry_after=retry_after)


# -- rendering ---------------------------------------------------------------


def clean(value: Any, limit: int = 120) -> str:
    text = _CONTROL.sub("", str(value if value is not None else "")).strip()
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _value(value: Any) -> str:
    if value is None:
        return "none"
    if isinstance(value, (int, float)):
        return str(value)
    return f"“{clean(value, 60)}”"


def _describe(change: Mapping[str, Any]) -> str:
    kind, key = change.get("type", ""), clean(change.get("key"), 200)
    before, after = change.get("before") or {}, change.get("after") or {}
    if kind == "asset.discovered":
        return f"New host: {key}"
    if kind.startswith("finding."):
        verb = {"finding.opened": "New finding", "finding.reopened": "Finding reopened",
                "finding.resolved": "Finding resolved"}.get(kind, kind)
        return f"{verb}: [{clean(after.get('severity'), 10)}] {clean(after.get('title'))} on {clean(after.get('host'))}"
    if kind == "dns.changed":
        if not after:
            return f"DNS removed: {key}"
        old = ", ".join(before.get("a", []) + before.get("aaaa", []) + before.get("cname", [])) or before.get("status")
        new = ", ".join(after.get("a", []) + after.get("aaaa", []) + after.get("cname", [])) or after.get("status")
        return f"DNS changed: {key}: {clean(old)} → {clean(new)}"
    if kind == "http.changed":
        if not after:
            return f"HTTP service gone: {key}"
        if after.get("reachable") is False:
            return f"HTTP service refused connections: {key}"
        parts = []
        for field in ("status_code", "title", "location"):
            if before.get(field) != after.get(field):
                parts.append(f"{field} {_value(before.get(field))} → {_value(after.get(field))}")
        return f"HTTP changed: {key}: " + ("; ".join(parts) or "response changed")
    return f"{clean(kind, 40)}: {key}"


def render(notification: Notification) -> tuple[str, list[str]]:
    """Return ``(title, lines)`` for a chat message."""
    payload = notification.payload
    run = str(payload.get("run_id", ""))[:8]
    targets = ", ".join(clean(t, 80) for t in payload.get("targets", []))
    if notification.event_type == "monitor.run_failed":
        lines = [f"{clean(j.get('kind'), 40)}{' ' + clean(j['target'], 80) if j.get('target') else ''}: "
                 f"{clean(j.get('error'), 200)}" for j in payload.get("failed_jobs", [])]
        return f"WatchTower run {run} failed ({targets})", lines
    found = payload.get("changes", [])
    lines = [_describe(change) for change in found[:MAX_LINES]]
    if len(found) > MAX_LINES:
        lines.append(f"…and {len(found) - MAX_LINES} more")
    noun = "change" if len(found) == 1 else "changes"
    return f"WatchTower: {len(found)} {noun} on {targets} (run {run})", lines


def _text(notification: Notification, limit: int) -> str:
    title, lines = render(notification)
    footer = f"delivery {notification.dedupe_key}"
    body = "\n".join([title, *(f"• {line}" for line in lines)])
    room = limit - len(footer) - 2
    return (body if len(body) <= room else body[: room - 1] + "…") + "\n" + footer


def _headers(notification: Notification) -> dict[str, str]:
    return {"Idempotency-Key": notification.dedupe_key, "X-WatchTower-Delivery": notification.dedupe_key,
            "X-WatchTower-Event": notification.event_type}


# -- senders ------------------------------------------------------------------


class Sender(Protocol):
    def send(self, url: str, notification: Notification, transport: Transport) -> None: ...


class DiscordSender:
    LIMIT = 2000

    def send(self, url: str, notification: Notification, transport: Transport) -> None:
        parts = urlsplit(url)
        query = "&".join(filter(None, [parts.query, "wait=true"]))
        body = {"content": _text(notification, self.LIMIT), "allowed_mentions": {"parse": []}}
        _check(transport.post(urlunsplit(parts._replace(query=query)), json.dumps(body).encode(),
                              _headers(notification)), "discord")


class SlackSender:
    LIMIT = 3000

    def send(self, url: str, notification: Notification, transport: Transport) -> None:
        text = _text(notification, self.LIMIT).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        body = {"text": text, "mrkdwn": False, "unfurl_links": False}
        _check(transport.post(url, json.dumps(body).encode(), _headers(notification)), "slack")


class TelegramSender:
    """URL form: ``https://api.telegram.org/bot<token>/sendMessage?chat_id=<chat>``."""

    LIMIT = 4096

    def send(self, url: str, notification: Notification, transport: Transport) -> None:
        parts = urlsplit(url)
        chat = parse_qs(parts.query).get("chat_id", [""])[0]
        if not chat:
            raise DeliveryError("telegram destination URL needs ?chat_id=", retryable=False)
        body = {"chat_id": chat, "text": _text(notification, self.LIMIT), "disable_web_page_preview": True}
        _check(transport.post(urlunsplit(parts._replace(query="")), json.dumps(body).encode(),
                              _headers(notification)), "telegram")


class WebhookSender:
    """Generic JSON webhook: the outbox row, with ``Idempotency-Key`` set to its dedupe key."""

    def send(self, url: str, notification: Notification, transport: Transport) -> None:
        title, lines = render(notification)
        body = {
            "id": str(notification.id), "dedupe_key": notification.dedupe_key,
            "event_type": notification.event_type, "project_id": str(notification.project_id),
            "created_at": notification.created_at.isoformat(), "attempt": notification.attempts,
            "summary": title, "lines": lines, "payload": notification.payload,
        }
        _check(transport.post(url, json.dumps(body, default=str).encode(), _headers(notification)), "webhook")


class LogSender:
    """Delivers nowhere: logs the alert so it is marked sent and stays readable in the outbox."""

    def send(self, url: str, notification: Notification, transport: Transport) -> None:
        title, lines = render(notification)
        log.info("%s [%s]", title, notification.dedupe_key)
        for line in lines:
            log.info("  %s", line)


SENDERS: dict[str, Sender] = {
    "discord": DiscordSender(), "slack": SlackSender(), "telegram": TelegramSender(), "webhook": WebhookSender(),
    "log": LogSender(),
}
