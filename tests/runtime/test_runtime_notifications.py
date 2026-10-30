"""Notification senders and the pinned HTTPS transport."""
from datetime import datetime, timezone
from uuid import uuid4

import pytest
from pydantic import ValidationError

from runtime_support import RecordingTransport
from watchtower.adapters.notifications import (
    DeliveryError, DiscordSender, LogSender, PinnedTransport, Response, SlackSender, TelegramSender, WebhookSender,
    render,
)
from watchtower.config.settings import NotificationDestination, Settings
from watchtower.domain.models import Notification, NotificationStatus

NOW = datetime(2026, 10, 30, tzinfo=timezone.utc)
SECRET = "https://discord.com/api/webhooks/123/very-secret-token"


def notification(changes=None, event="monitor.changes", **payload):
    body = {"run_id": "8f0c2a1e-0000-0000-0000-000000000000", "targets": ["example.com"],
            "changes": changes if changes is not None else [
                {"type": "asset.discovered", "target": "example.com", "phase": "discovery", "key": "api.example.com",
                 "before": None, "after": True}],
            **payload}
    return Notification(uuid4(), uuid4(), "ops", event, f"{event}:run:ops", body, NotificationStatus.SENDING, 1, 5,
                        NOW, NOW)


def sent(sender, url="https://hooks.example.net/x", item=None):
    transport = RecordingTransport()
    sender.send(url, item or notification(), transport)
    [request] = transport.requests
    return request


def test_discord_disables_mentions_and_waits_for_the_message():
    hostile = notification([{"type": "http.changed", "key": "https://shop.example.com", "target": "example.com",
                             "phase": "http", "before": {"title": "Shop"},
                             "after": {"title": "@everyone free ‮nitro\x07"}}])
    request = sent(DiscordSender(), SECRET, hostile)
    assert request["url"] == SECRET + "?wait=true"
    assert request["body"]["allowed_mentions"] == {"parse": []}
    content = request["body"]["content"]
    assert "‮" not in content and "\x07" not in content
    assert content.endswith("delivery monitor.changes:run:ops") and len(content) <= 2000
    assert request["headers"]["Idempotency-Key"] == "monitor.changes:run:ops"


def test_long_alerts_are_capped():
    many = [{"type": "asset.discovered", "key": f"host-{i}.example.com" + "x" * 150} for i in range(200)]
    content = sent(DiscordSender(), item=notification(many))["body"]["content"]
    assert len(content) <= 2000 and content.endswith("delivery monitor.changes:run:ops")
    assert render(notification(many))[1][-1] == "…and 175 more"


def test_telegram_moves_the_chat_id_into_the_body():
    request = sent(TelegramSender(), "https://api.telegram.org/bot123:abc/sendMessage?chat_id=-1001")
    assert request["url"] == "https://api.telegram.org/bot123:abc/sendMessage"
    assert request["body"]["chat_id"] == "-1001" and "parse_mode" not in request["body"]
    with pytest.raises(DeliveryError) as missing:
        TelegramSender().send("https://api.telegram.org/bot123:abc/sendMessage", notification(), RecordingTransport())
    assert not missing.value.retryable


def test_slack_escapes_control_sequences():
    item = notification([{"type": "asset.discovered", "key": "<!channel>.example.com"}])
    text = sent(SlackSender(), item=item)["body"]["text"]
    assert "<!channel>" not in text and "&lt;!channel&gt;" in text


def test_generic_webhook_sends_the_outbox_row():
    request = sent(WebhookSender())
    body = request["body"]
    assert body["dedupe_key"] == "monitor.changes:run:ops" and body["event_type"] == "monitor.changes"
    assert body["payload"]["changes"][0]["key"] == "api.example.com"
    assert body["summary"] == "WatchTower: 1 change on example.com (run 8f0c2a1e)"
    assert request["headers"]["X-WatchTower-Event"] == "monitor.changes"


def test_failed_runs_render_their_errors():
    item = notification(event="monitor.run_failed", changes=[],
                        failed_jobs=[{"kind": "monitor.http", "error": "RuntimeError: boom"}])
    title, lines = render(item)
    assert title.startswith("WatchTower run 8f0c2a1e failed") and lines == ["monitor.http: RuntimeError: boom"]


@pytest.mark.parametrize("status, retryable", [(500, True), (503, True), (429, True), (400, False), (404, False)])
def test_http_status_decides_retries(status, retryable):
    transport = RecordingTransport(status=status)
    with pytest.raises(DeliveryError) as failure:
        WebhookSender().send(SECRET, notification(), transport)
    assert failure.value.retryable is retryable
    assert "secret" not in str(failure.value)


@pytest.mark.parametrize("address, reason", [
    ("127.0.0.1", "prohibited"), ("169.254.169.254", "prohibited"), ("10.0.0.5", "private"),
    ("::ffff:127.0.0.1", "prohibited"),
])
def test_the_transport_refuses_prohibited_destinations(address, reason):
    transport = PinnedTransport(resolve=lambda host, port: [address])
    with pytest.raises(DeliveryError) as refused:
        transport.post("https://hooks.example.net/secret-token", b"{}", {})
    assert reason in str(refused.value) and not refused.value.retryable
    assert "secret-token" not in str(refused.value)


def test_the_transport_refuses_plain_http_and_prohibited_names():
    with pytest.raises(DeliveryError):
        PinnedTransport().post("http://hooks.example.net/x", b"{}", {})
    with pytest.raises(DeliveryError) as named:
        PinnedTransport(resolve=lambda h, p: ["93.184.216.34"]).post("https://metadata.google.internal/x", b"{}", {})
    assert "prohibited name" in str(named.value)


def test_the_transport_pins_the_approved_address(monkeypatch):
    opened = []

    class FakeConnection:
        def __init__(self, host, ip, port, timeout, context):
            opened.append((host, ip, port))

        def request(self, *args, **kwargs):
            pass

        def getresponse(self):
            class R:
                status = 204

                def getheaders(self):
                    return []

                def read(self, n):
                    return b""
            return R()

        def close(self):
            pass

    monkeypatch.setattr("watchtower.adapters.notifications.base.PinnedHTTPSConnection", FakeConnection)
    response = PinnedTransport(resolve=lambda h, p: ["93.184.216.34", "93.184.216.35"]).post(
        "https://hooks.example.net:8443/x?y=1", b"{}", {})
    assert response == Response(204, {}, b"") and opened == [("hooks.example.net", "93.184.216.34", 8443)]


def test_log_destinations_take_no_url_and_deliver_by_logging(caplog):
    settings = Settings.model_validate({"notifications": {"destinations": [{"name": "lab-console", "kind": "log"}]}})
    assert settings.notifications.destination("lab-console").url is None
    with pytest.raises(ValidationError):
        NotificationDestination(name="x", kind="log", url="https://example.net/")
    with pytest.raises(ValidationError):
        NotificationDestination(name="x", kind="webhook")
    with pytest.raises(ValidationError):
        NotificationDestination(name="x", kind="webhook", url="http://example.net/")
    with caplog.at_level("INFO", logger="watchtower.notifications"):
        LogSender().send("", notification(), RecordingTransport())
    assert "New host: api.example.com" in caplog.text
