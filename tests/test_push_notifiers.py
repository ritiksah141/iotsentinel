"""
Tests for alerts/push_notifiers.py
====================================
Covers:
  - NtfyNotifier
  - TelegramNotifier
  - DiscordNotifier
  - WebhookNotifier

Each notifier is tested for:
  - is_enabled() gating (missing required fields -> False)
  - send() builds the correct URL / payload and returns success
  - send() failure path returns NotificationResult(success=False)
  - send_report() produces a NotificationResult

Also covers the updated NotificationDispatcher fan-out behaviour:
  - critical/high alerts fan out to every registered handler
  - medium/low alerts are log-only
"""

import json
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import MagicMock, patch


from alerts.push_notifiers import (
    DiscordNotifier,
    NtfyNotifier,
    TelegramNotifier,
    WebhookNotifier,
)
from alerts.notification_dispatcher import (
    NotificationDispatcher,
    NotificationResult,
)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _fake_alert(severity="critical"):
    """Minimal alert object matching what push_notifiers._format_alert_text reads."""
    return SimpleNamespace(
        severity=severity,
        device_ip="192.168.1.42",
        device_name="Test Camera",
        anomaly_score=0.97,
        explanation="Unusual outbound traffic detected on port 4444.",
        timestamp=datetime(2026, 6, 7, 12, 0, 0),
    )


def _fake_report():
    return {
        "report_type": "weekly",
        "period": "2026-05-31 to 2026-06-07",
        "total_alerts": 5,
        "device_count": 12,
    }


def _cfg(section: str, key: str, default=None):
    """Config shim that returns a value only for the 'notifications' section."""
    if section != "notifications":
        return default
    return default  # subclasses override this


class _Config:
    """Fake config object — returns a dict of values for the 'notifications' section."""
    def __init__(self, values: dict):
        self._values = values

    def get(self, section, key, default=None):
        if section == "notifications":
            return self._values.get(key, default)
        return default


def _ok_response(status=200, text="OK"):
    resp = MagicMock()
    resp.status_code = status
    resp.text = text
    return resp


def _fail_response(status=500, text="Internal Server Error"):
    resp = MagicMock()
    resp.status_code = status
    resp.text = text
    return resp


# ---------------------------------------------------------------------------
# NtfyNotifier
# ---------------------------------------------------------------------------

class TestNtfyNotifier:

    def test_disabled_when_no_topic(self):
        cfg = _Config({"ntfy_enabled": "true", "ntfy_topic": ""})
        n = NtfyNotifier(cfg)
        assert n.is_enabled() is False

    def test_disabled_when_flag_false(self):
        cfg = _Config({"ntfy_enabled": "false", "ntfy_topic": "iotsentinel-abc"})
        n = NtfyNotifier(cfg)
        assert n.is_enabled() is False

    def test_enabled_with_topic(self):
        cfg = _Config({"ntfy_enabled": "true", "ntfy_topic": "iotsentinel-abc"})
        n = NtfyNotifier(cfg)
        assert n.is_enabled() is True

    def test_send_not_enabled_returns_failure(self):
        cfg = _Config({"ntfy_enabled": "false", "ntfy_topic": ""})
        n = NtfyNotifier(cfg)
        result = n.send(_fake_alert())
        assert isinstance(result, NotificationResult)
        assert result.success is False
        assert result.channel == "ntfy"

    @patch("alerts.push_notifiers.requests.post")
    def test_send_posts_to_correct_url(self, mock_post):
        mock_post.return_value = _ok_response()
        cfg = _Config({
            "ntfy_enabled": "true",
            "ntfy_topic": "my-topic",
            "ntfy_server": "https://ntfy.sh",
        })
        n = NtfyNotifier(cfg)
        result = n.send(_fake_alert("critical"))

        assert mock_post.called
        call_args = mock_post.call_args
        assert call_args[0][0] == "https://ntfy.sh/my-topic"
        headers = call_args[1]["headers"]
        assert headers["Priority"] == "urgent"        # critical -> urgent
        assert "rotating_light" in headers["Tags"]
        assert result.success is True
        assert result.channel == "ntfy"

    @patch("alerts.push_notifiers.requests.post")
    def test_send_uses_custom_server(self, mock_post):
        mock_post.return_value = _ok_response()
        cfg = _Config({
            "ntfy_enabled": "true",
            "ntfy_topic": "alerts",
            "ntfy_server": "https://self-hosted.example.com/",
        })
        n = NtfyNotifier(cfg)
        n.send(_fake_alert())
        url = mock_post.call_args[0][0]
        # trailing slash is stripped
        assert url == "https://self-hosted.example.com/alerts"

    @patch("alerts.push_notifiers.requests.post")
    def test_send_returns_failure_on_http_error(self, mock_post):
        mock_post.return_value = _fail_response(403)
        cfg = _Config({"ntfy_enabled": "true", "ntfy_topic": "topic"})
        n = NtfyNotifier(cfg)
        result = n.send(_fake_alert())
        assert result.success is False
        assert "403" in result.message

    @patch("alerts.push_notifiers.requests.post")
    def test_send_report(self, mock_post):
        mock_post.return_value = _ok_response()
        cfg = _Config({"ntfy_enabled": "true", "ntfy_topic": "topic"})
        n = NtfyNotifier(cfg)
        result = n.send_report(_fake_report())
        assert result.success is True
        assert result.channel == "ntfy"

    def test_channel_name(self):
        n = NtfyNotifier(_Config({}))
        assert n.channel_name == "ntfy"


# ---------------------------------------------------------------------------
# TelegramNotifier
# ---------------------------------------------------------------------------

class TestTelegramNotifier:

    def test_disabled_when_missing_token(self):
        cfg = _Config({"telegram_enabled": "true", "telegram_chat_id": "123"})
        n = TelegramNotifier(cfg)
        assert n.is_enabled() is False

    def test_disabled_when_missing_chat_id(self):
        cfg = _Config({"telegram_enabled": "true", "telegram_bot_token": "abc"})
        n = TelegramNotifier(cfg)
        assert n.is_enabled() is False

    def test_enabled_with_both_fields(self):
        cfg = _Config({
            "telegram_enabled": "true",
            "telegram_bot_token": "123456:ABC",
            "telegram_chat_id": "-1001234567890",
        })
        n = TelegramNotifier(cfg)
        assert n.is_enabled() is True

    @patch("alerts.push_notifiers.requests.post")
    def test_send_posts_to_telegram_api(self, mock_post):
        mock_post.return_value = _ok_response()
        cfg = _Config({
            "telegram_enabled": "true",
            "telegram_bot_token": "MYTOKEN",
            "telegram_chat_id": "MYCHAT",
        })
        n = TelegramNotifier(cfg)
        result = n.send(_fake_alert("high"))

        assert mock_post.called
        url = mock_post.call_args[0][0]
        assert "api.telegram.org/botMYTOKEN/sendMessage" in url
        payload = mock_post.call_args[1]["json"]
        assert payload["chat_id"] == "MYCHAT"
        assert "Markdown" in payload.get("parse_mode", "")
        assert result.success is True
        assert result.channel == "telegram"

    @patch("alerts.push_notifiers.requests.post")
    def test_send_failure_path(self, mock_post):
        mock_post.return_value = _fail_response(401)
        cfg = _Config({
            "telegram_enabled": "true",
            "telegram_bot_token": "BAD",
            "telegram_chat_id": "123",
        })
        n = TelegramNotifier(cfg)
        result = n.send(_fake_alert())
        assert result.success is False

    @patch("alerts.push_notifiers.requests.post")
    def test_send_report(self, mock_post):
        mock_post.return_value = _ok_response()
        cfg = _Config({
            "telegram_enabled": "true",
            "telegram_bot_token": "T",
            "telegram_chat_id": "C",
        })
        n = TelegramNotifier(cfg)
        result = n.send_report(_fake_report())
        assert result.success is True

    def test_channel_name(self):
        assert TelegramNotifier(_Config({})).channel_name == "telegram"


# ---------------------------------------------------------------------------
# DiscordNotifier
# ---------------------------------------------------------------------------

class TestDiscordNotifier:

    def test_disabled_when_no_webhook(self):
        cfg = _Config({"discord_enabled": "true", "discord_webhook_url": ""})
        n = DiscordNotifier(cfg)
        assert n.is_enabled() is False

    def test_enabled_with_webhook(self):
        cfg = _Config({
            "discord_enabled": "true",
            "discord_webhook_url": "https://discord.com/api/webhooks/123/abc",
        })
        n = DiscordNotifier(cfg)
        assert n.is_enabled() is True

    @patch("alerts.push_notifiers.requests.post")
    def test_send_posts_embed_with_correct_color(self, mock_post):
        mock_post.return_value = _ok_response(204)   # Discord returns 204
        cfg = _Config({
            "discord_enabled": "true",
            "discord_webhook_url": "https://discord.com/api/webhooks/1/x",
        })
        n = DiscordNotifier(cfg)
        result = n.send(_fake_alert("critical"))

        assert mock_post.called
        payload = mock_post.call_args[1]["json"]
        embed = payload["embeds"][0]
        assert embed["color"] == 0xD32F2F   # critical red
        assert "Alert" in embed["title"]
        assert result.success is True

    @patch("alerts.push_notifiers.requests.post")
    def test_send_failure(self, mock_post):
        mock_post.return_value = _fail_response(400)
        cfg = _Config({
            "discord_enabled": "true",
            "discord_webhook_url": "https://discord.com/api/webhooks/1/x",
        })
        n = DiscordNotifier(cfg)
        result = n.send(_fake_alert())
        assert result.success is False

    @patch("alerts.push_notifiers.requests.post")
    def test_send_report_has_embed(self, mock_post):
        mock_post.return_value = _ok_response(204)
        cfg = _Config({
            "discord_enabled": "true",
            "discord_webhook_url": "https://discord.com/api/webhooks/1/x",
        })
        n = DiscordNotifier(cfg)
        result = n.send_report(_fake_report())
        payload = mock_post.call_args[1]["json"]
        assert "embeds" in payload
        assert result.success is True

    def test_channel_name(self):
        assert DiscordNotifier(_Config({})).channel_name == "discord"


# ---------------------------------------------------------------------------
# WebhookNotifier
# ---------------------------------------------------------------------------

class TestWebhookNotifier:

    def test_disabled_when_no_url(self):
        cfg = _Config({"webhook_enabled": "true", "webhook_url": ""})
        n = WebhookNotifier(cfg)
        assert n.is_enabled() is False

    def test_enabled_with_url(self):
        cfg = _Config({
            "webhook_enabled": "true",
            "webhook_url": "https://example.com/hook",
        })
        n = WebhookNotifier(cfg)
        assert n.is_enabled() is True

    @patch("alerts.push_notifiers.requests.post")
    def test_send_posts_structured_payload(self, mock_post):
        mock_post.return_value = _ok_response(200)
        cfg = _Config({
            "webhook_enabled": "true",
            "webhook_url": "https://example.com/hook",
        })
        n = WebhookNotifier(cfg)
        alert = _fake_alert("high")
        result = n.send(alert)

        assert mock_post.called
        url = mock_post.call_args[0][0]
        assert url == "https://example.com/hook"
        payload = mock_post.call_args[1]["json"]
        assert payload["event"] == "alert"
        assert payload["severity"] == "high"
        assert payload["device_ip"] == "192.168.1.42"
        assert payload["device_name"] == "Test Camera"
        assert payload["source"] == "iotsentinel"
        assert result.success is True

    @patch("alerts.push_notifiers.requests.post")
    def test_send_failure(self, mock_post):
        mock_post.return_value = _fail_response(503)
        cfg = _Config({
            "webhook_enabled": "true",
            "webhook_url": "https://example.com/hook",
        })
        n = WebhookNotifier(cfg)
        result = n.send(_fake_alert())
        assert result.success is False

    @patch("alerts.push_notifiers.requests.post")
    def test_send_report_includes_report_data(self, mock_post):
        mock_post.return_value = _ok_response()
        cfg = _Config({
            "webhook_enabled": "true",
            "webhook_url": "https://example.com/hook",
        })
        n = WebhookNotifier(cfg)
        report = _fake_report()
        result = n.send_report(report)
        payload = mock_post.call_args[1]["json"]
        assert payload["event"] == "report"
        assert payload["total_alerts"] == 5
        assert result.success is True

    @patch("alerts.push_notifiers.requests.post")
    def test_network_error_returns_failure(self, mock_post):
        mock_post.side_effect = ConnectionError("timeout")
        cfg = _Config({
            "webhook_enabled": "true",
            "webhook_url": "https://example.com/hook",
        })
        n = WebhookNotifier(cfg)
        result = n.send(_fake_alert())
        assert result.success is False
        assert "timeout" in result.message

    def test_channel_name(self):
        assert WebhookNotifier(_Config({})).channel_name == "webhook"


# ---------------------------------------------------------------------------
# NotificationDispatcher fan-out routing
# ---------------------------------------------------------------------------

class TestDispatcherFanOut:
    """Verify that critical/high alerts reach all registered handlers,
    and medium/low are log-only."""

    def _make_dispatcher(self, *handlers):
        """Build a dispatcher with the given (already-enabled) handlers."""
        class _NullConfig:
            def get(self, *a, **kw):
                return None

        dispatcher = NotificationDispatcher(_NullConfig())
        for h in handlers:
            dispatcher._handlers[h.channel_name] = h
        return dispatcher

    def _handler(self, name, success=True):
        h = MagicMock()
        h.channel_name = name
        h.is_enabled.return_value = True
        h.send.return_value = NotificationResult(channel=name, success=success, message="ok")
        h.send_report.return_value = NotificationResult(channel=name, success=success, message="ok")
        return h

    def test_critical_fans_out_to_all_handlers(self):
        h1 = self._handler("ntfy")
        h2 = self._handler("telegram")
        dispatcher = self._make_dispatcher(h1, h2)

        alert = _fake_alert("critical")
        results = dispatcher.dispatch(alert)

        h1.send.assert_called_once_with(alert)
        h2.send.assert_called_once_with(alert)
        successes = [r.success for r in results]
        assert all(successes)

    def test_high_fans_out_to_all_handlers(self):
        h1 = self._handler("ntfy")
        h2 = self._handler("discord")
        dispatcher = self._make_dispatcher(h1, h2)

        alert = _fake_alert("high")
        dispatcher.dispatch(alert)

        h1.send.assert_called_once()
        h2.send.assert_called_once()

    def test_medium_is_log_only(self):
        h = self._handler("ntfy")
        dispatcher = self._make_dispatcher(h)

        alert = _fake_alert("medium")
        results = dispatcher.dispatch(alert)

        h.send.assert_not_called()
        assert any(r.channel == "log" for r in results)

    def test_low_is_log_only(self):
        h = self._handler("telegram")
        dispatcher = self._make_dispatcher(h)

        alert = _fake_alert("low")
        dispatcher.dispatch(alert)
        h.send.assert_not_called()

    def test_no_handlers_critical_still_returns_log_result(self):
        dispatcher = self._make_dispatcher()
        results = dispatcher.dispatch(_fake_alert("critical"))
        assert len(results) == 1
        assert results[0].channel == "log"

    def test_dispatch_report_sent_to_all_handlers(self):
        h1 = self._handler("ntfy")
        h2 = self._handler("email")
        dispatcher = self._make_dispatcher(h1, h2)

        dispatcher.dispatch_report(_fake_report())
        h1.send_report.assert_called_once()
        h2.send_report.assert_called_once()


# ---------------------------------------------------------------------------
# _format_report_text — weekly story digest
# ---------------------------------------------------------------------------

class TestFormatReportText:
    """Push digests carry the narrated weekly story, not just bare counts."""

    @staticmethod
    def _report(**extra):
        base = {
            "report_type": "weekly",
            "period": "June 5 - June 12, 2026",
            "summary": {"total": 7, "critical": 1, "high": 2},
            "network_stats": {"total_devices": 12},
        }
        base.update(extra)
        return base

    def test_weekly_story_preferred(self):
        from alerts.push_notifiers import _format_report_text
        text = _format_report_text(self._report(
            weekly_story="Your network had a calm week. One camera misbehaved on Tuesday.",
            ai_narrative="Short summary.",
        ))
        assert "calm week" in text
        assert "Short summary." not in text
        assert "Weekly Report" in text

    def test_ai_narrative_fallback(self):
        from alerts.push_notifiers import _format_report_text
        text = _format_report_text(self._report(ai_narrative="Short summary."))
        assert "Short summary." in text

    def test_stats_fallback_reads_real_structure(self):
        from alerts.push_notifiers import _format_report_text
        text = _format_report_text(self._report())
        assert "Alerts: 7" in text
        assert "Devices: 12" in text

    def test_long_story_truncated_for_channel_limits(self):
        from alerts.push_notifiers import _format_report_text
        text = _format_report_text(self._report(weekly_story="word " * 1000))
        assert len(text) < 1700
        assert text.count("...") >= 1

    def test_legacy_flat_keys_still_work(self):
        from alerts.push_notifiers import _format_report_text
        text = _format_report_text({"report_type": "weekly", "period": "x",
                                    "total_alerts": 3, "device_count": 5})
        assert "Alerts: 3" in text
        assert "Devices: 5" in text

    def test_story_rides_into_ntfy_report(self):
        from alerts.push_notifiers import NtfyNotifier
        cfg = _Config({"ntfy_enabled": "true", "ntfy_topic": "topic-x"})
        notifier = NtfyNotifier(cfg)
        with patch("alerts.push_notifiers.requests.post",
                   return_value=_ok_response()) as post:
            result = notifier.send_report(self._report(weekly_story="Story body here."))
        assert result.success
        assert b"Story body here." in post.call_args.kwargs["data"]
