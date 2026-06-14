"""
Push Notifiers for IoTSentinel
==============================
Four NotificationHandler implementations that complement the existing
EmailNotifier and are wired into the live NotificationDispatcher.

Each handler:
- Reads its config from the config_manager 'notifications' section, which the
  ConfigManager already overrides from NOTIFICATIONS_<KEY> environment variables.
- self-gates via is_enabled() — register_handler() silently skips disabled ones.
- send(alert) executes a single HTTP POST with a 10-second timeout and one
  bounded retry before returning a NotificationResult.
- send_report() sends a concise plain-text digest (push channels have no
  attachment support).

Channels provided:
  NtfyNotifier    — ntfy.sh (or self-hosted ntfy); zero-account phone push.
  TelegramNotifier — Telegram Bot API.
  DiscordNotifier  — Discord webhook.
  WebhookNotifier  — Generic JSON webhook (any endpoint).
"""

import logging
import time
from datetime import datetime
from typing import (Any, Dict)

import requests

from .notification_dispatcher import NotificationHandler, NotificationResult

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_SEVERITY_EMOJI = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🟢",
}

_NTFY_PRIORITY = {
    "critical": "urgent",   # ntfy priority 5
    "high":     "high",     # 4
    "medium":   "default",  # 3
    "low":      "low",      # 2
}

_NTFY_TAGS = {
    "critical": "rotating_light,warning",
    "high":     "warning",
    "medium":   "bell",
    "low":      "information_source",
}

_DISCORD_COLOR = {
    "critical": 0xD32F2F,
    "high":     0xFF5722,
    "medium":   0xFF9800,
    "low":      0x36A64F,
}


def _format_alert_text(alert) -> str:
    """One-paragraph plain-text summary suitable for push bodies."""
    sev = getattr(alert, "severity", "unknown")
    ip  = getattr(alert, "device_ip", "unknown")
    name = getattr(alert, "device_name", None) or ip
    score = getattr(alert, "anomaly_score", 0.0)
    explanation = getattr(alert, "explanation", None) or ""
    ts = getattr(alert, "timestamp", None) or datetime.now().isoformat()
    emoji = _SEVERITY_EMOJI.get(sev.lower(), "")
    lines = [
        f"{emoji} {sev.upper()} alert — {name} ({ip})",
        f"Anomaly score: {score:.3f}",
    ]
    if explanation:
        lines.append(explanation)
    lines.append(f"Time: {ts}")
    return "\n".join(lines)


def _format_report_text(report_data: Dict[str, Any]) -> str:
    """Digest text for send_report.

    Prefers the full "This Week on Your Network" narrative, then the short
    AI summary, then a plain stats line — so phones receive the same story
    the dashboard shows, not just bare counts.
    """
    report_type = report_data.get("report_type", "periodic")
    period = report_data.get("period", "unknown")
    header = f"IoTSentinel {report_type.capitalize()} Report ({period})"

    story = (report_data.get("weekly_story") or report_data.get("ai_narrative") or "").strip()
    if story:
        # Keep well inside every channel's limit (Telegram/Discord cap at 4096).
        if len(story) > 1500:
            story = story[:1500].rsplit(" ", 1)[0] + "..."
        return f"{header}\n\n{story}\n\nOpen the dashboard for the full report."

    summary = report_data.get("summary") or {}
    network_stats = report_data.get("network_stats") or {}
    n_alerts = summary.get("total",
                           report_data.get("total_alerts", report_data.get("alert_count", "?")))
    n_devices = network_stats.get("total_devices", report_data.get("device_count", "?"))
    return (
        f"{header}\n"
        f"Alerts: {n_alerts}  |  Devices: {n_devices}\n"
        f"Open the dashboard for details."
    )


# ---------------------------------------------------------------------------
# NtfyNotifier
# ---------------------------------------------------------------------------

class NtfyNotifier(NotificationHandler):
    """
    ntfy.sh (or self-hosted ntfy) notification handler.

    Zero-account phone push: the user just subscribes to their topic at
    https://ntfy.sh/<topic> or installs the ntfy app and scans the wizard QR.

    Config keys (section='notifications'):
        ntfy_enabled  — "true" / "false"
        ntfy_topic    — topic name, e.g. "iotsentinel-a7f3"   (required)
        ntfy_server   — base URL, default "https://ntfy.sh"   (optional)
    """

    def __init__(self, config):
        self._enabled = self._to_bool(config.get("notifications", "ntfy_enabled", default=False))
        self._topic   = (config.get("notifications", "ntfy_topic",  default="") or "").strip()
        self._server  = (
            config.get("notifications", "ntfy_server", default="https://ntfy.sh") or "https://ntfy.sh"
        ).rstrip("/")

    @staticmethod
    def _to_bool(value) -> bool:
        if isinstance(value, bool):
            return value
        return str(value).lower() in ("true", "1", "yes", "on")

    @property
    def channel_name(self) -> str:
        return "ntfy"

    def is_enabled(self) -> bool:
        return self._enabled and bool(self._topic)

    def send(self, alert) -> NotificationResult:
        if not self.is_enabled():
            return NotificationResult(channel="ntfy", success=False,
                                      message="ntfy not enabled or topic not set")
        sev = getattr(alert, "severity", "medium").lower()
        url = f"{self._server}/{self._topic}"
        headers = {
            "Title":    f"IoTSentinel {sev.capitalize()} Alert",
            "Priority": _NTFY_PRIORITY.get(sev, "default"),
            "Tags":     _NTFY_TAGS.get(sev, "bell"),
        }
        body = _format_alert_text(alert)
        return self._post(url, headers=headers, data=body.encode("utf-8"))

    def send_report(self, report_data: Dict[str, Any]) -> NotificationResult:
        if not self.is_enabled():
            return NotificationResult(channel="ntfy", success=False,
                                      message="ntfy not enabled or topic not set")
        url = f"{self._server}/{self._topic}"
        headers = {
            "Title":    "IoTSentinel Report",
            "Priority": "default",
            "Tags":     "bar_chart",
        }
        return self._post(url, headers=headers,
                          data=_format_report_text(report_data).encode("utf-8"))

    def _post(self, url: str, *, headers: dict, data: bytes,
              _attempt: int = 1) -> NotificationResult:
        try:
            resp = requests.post(url, headers=headers, data=data, timeout=10)
            if resp.status_code == 200:
                return NotificationResult(channel="ntfy", success=True,
                                          message=f"ntfy delivered to {self._topic}")
            if _attempt < 2:
                time.sleep(1)
                return self._post(url, headers=headers, data=data, _attempt=2)
            return NotificationResult(channel="ntfy", success=False,
                                      message=f"ntfy HTTP {resp.status_code}: {resp.text[:200]}")
        except Exception as exc:
            logger.error("ntfy send error: %s", exc)
            return NotificationResult(channel="ntfy", success=False, message=str(exc))


# ---------------------------------------------------------------------------
# TelegramNotifier
# ---------------------------------------------------------------------------

class TelegramNotifier(NotificationHandler):
    """
    Telegram Bot API notification handler.

    Config keys (section='notifications'):
        telegram_enabled   — "true" / "false"
        telegram_bot_token — Bot token from BotFather   (required)
        telegram_chat_id   — Chat / group ID             (required)
    """

    _API_BASE = "https://api.telegram.org"

    def __init__(self, config):
        self._enabled   = self._to_bool(config.get("notifications", "telegram_enabled", default=False))
        self._token     = (config.get("notifications", "telegram_bot_token", default="") or "").strip()
        self._chat_id   = (config.get("notifications", "telegram_chat_id",   default="") or "").strip()

    @staticmethod
    def _to_bool(value) -> bool:
        if isinstance(value, bool):
            return value
        return str(value).lower() in ("true", "1", "yes", "on")

    @property
    def channel_name(self) -> str:
        return "telegram"

    def is_enabled(self) -> bool:
        return self._enabled and bool(self._token) and bool(self._chat_id)

    def send(self, alert) -> NotificationResult:
        if not self.is_enabled():
            return NotificationResult(channel="telegram", success=False,
                                      message="Telegram not enabled or credentials missing")
        sev = getattr(alert, "severity", "medium").lower()
        emoji = _SEVERITY_EMOJI.get(sev, "")
        text = f"{emoji} *IoTSentinel {sev.capitalize()} Alert*\n\n{_format_alert_text(alert)}"
        return self._send_message(text)

    def send_report(self, report_data: Dict[str, Any]) -> NotificationResult:
        if not self.is_enabled():
            return NotificationResult(channel="telegram", success=False,
                                      message="Telegram not enabled or credentials missing")
        text = f"📊 *IoTSentinel Report*\n\n{_format_report_text(report_data)}"
        return self._send_message(text)

    def _send_message(self, text: str, _attempt: int = 1) -> NotificationResult:
        url = f"{self._API_BASE}/bot{self._token}/sendMessage"
        payload = {"chat_id": self._chat_id, "text": text, "parse_mode": "Markdown"}
        try:
            resp = requests.post(url, json=payload, timeout=10)
            if resp.status_code == 200:
                return NotificationResult(channel="telegram", success=True,
                                          message="Telegram message sent")
            if _attempt < 2:
                time.sleep(1)
                return self._send_message(text, _attempt=2)
            return NotificationResult(channel="telegram", success=False,
                                      message=f"Telegram HTTP {resp.status_code}: {resp.text[:200]}")
        except Exception as exc:
            logger.error("Telegram send error: %s", exc)
            return NotificationResult(channel="telegram", success=False, message=str(exc))


# ---------------------------------------------------------------------------
# DiscordNotifier
# ---------------------------------------------------------------------------

class DiscordNotifier(NotificationHandler):
    """
    Discord webhook notification handler.

    Config keys (section='notifications'):
        discord_enabled      — "true" / "false"
        discord_webhook_url  — Discord webhook URL  (required)
    """

    def __init__(self, config):
        self._enabled     = self._to_bool(config.get("notifications", "discord_enabled", default=False))
        self._webhook_url = (config.get("notifications", "discord_webhook_url", default="") or "").strip()

    @staticmethod
    def _to_bool(value) -> bool:
        if isinstance(value, bool):
            return value
        return str(value).lower() in ("true", "1", "yes", "on")

    @property
    def channel_name(self) -> str:
        return "discord"

    def is_enabled(self) -> bool:
        return self._enabled and bool(self._webhook_url)

    def send(self, alert) -> NotificationResult:
        if not self.is_enabled():
            return NotificationResult(channel="discord", success=False,
                                      message="Discord not enabled or webhook URL missing")
        sev = getattr(alert, "severity", "medium").lower()
        color = _DISCORD_COLOR.get(sev, 0x808080)
        description = _format_alert_text(alert)
        payload = {
            "embeds": [{
                "title":       f"IoTSentinel {sev.capitalize()} Alert",
                "description": description,
                "color":       color,
                "footer":      {"text": "IoTSentinel"},
                "timestamp":   datetime.utcnow().isoformat(),
            }]
        }
        return self._post(payload)

    def send_report(self, report_data: Dict[str, Any]) -> NotificationResult:
        if not self.is_enabled():
            return NotificationResult(channel="discord", success=False,
                                      message="Discord not enabled or webhook URL missing")
        payload = {
            "embeds": [{
                "title":       "IoTSentinel Periodic Report",
                "description": _format_report_text(report_data),
                "color":       0x2196F3,
                "footer":      {"text": "IoTSentinel"},
                "timestamp":   datetime.utcnow().isoformat(),
            }]
        }
        return self._post(payload)

    def _post(self, payload: dict, _attempt: int = 1) -> NotificationResult:
        try:
            resp = requests.post(self._webhook_url, json=payload, timeout=10)
            # Discord returns 204 No Content on success
            if resp.status_code in (200, 204):
                return NotificationResult(channel="discord", success=True,
                                          message="Discord embed delivered")
            if _attempt < 2:
                time.sleep(1)
                return self._post(payload, _attempt=2)
            return NotificationResult(channel="discord", success=False,
                                      message=f"Discord HTTP {resp.status_code}: {resp.text[:200]}")
        except Exception as exc:
            logger.error("Discord send error: %s", exc)
            return NotificationResult(channel="discord", success=False, message=str(exc))


# ---------------------------------------------------------------------------
# WebhookNotifier
# ---------------------------------------------------------------------------

class WebhookNotifier(NotificationHandler):
    """
    Generic JSON webhook notification handler.

    Posts a structured JSON payload to any HTTP endpoint — compatible with
    n8n, Zapier, Make (Integromat), Home Assistant, or any custom consumer.

    Config keys (section='notifications'):
        webhook_enabled — "true" / "false"
        webhook_url     — Full URL to POST to   (required)
    """

    def __init__(self, config):
        self._enabled     = self._to_bool(config.get("notifications", "webhook_enabled", default=False))
        self._webhook_url = (config.get("notifications", "webhook_url", default="") or "").strip()

    @staticmethod
    def _to_bool(value) -> bool:
        if isinstance(value, bool):
            return value
        return str(value).lower() in ("true", "1", "yes", "on")

    @property
    def channel_name(self) -> str:
        return "webhook"

    def is_enabled(self) -> bool:
        return self._enabled and bool(self._webhook_url)

    def send(self, alert) -> NotificationResult:
        if not self.is_enabled():
            return NotificationResult(channel="webhook", success=False,
                                      message="Webhook not enabled or URL missing")
        payload = {
            "event":        "alert",
            "severity":     getattr(alert, "severity", "unknown"),
            "device_ip":    getattr(alert, "device_ip",    "unknown"),
            "device_name":  getattr(alert, "device_name",  None),
            "anomaly_score":getattr(alert, "anomaly_score", 0.0),
            "explanation":  getattr(alert, "explanation",   ""),
            "timestamp":    str(getattr(alert, "timestamp", datetime.now().isoformat())),
            "source":       "iotsentinel",
        }
        return self._post(payload)

    def send_report(self, report_data: Dict[str, Any]) -> NotificationResult:
        if not self.is_enabled():
            return NotificationResult(channel="webhook", success=False,
                                      message="Webhook not enabled or URL missing")
        payload = {"event": "report", "source": "iotsentinel", **report_data}
        return self._post(payload)

    def _post(self, payload: dict, _attempt: int = 1) -> NotificationResult:
        try:
            resp = requests.post(self._webhook_url, json=payload, timeout=10)
            if 200 <= resp.status_code < 300:
                return NotificationResult(channel="webhook", success=True,
                                          message=f"Webhook delivered (HTTP {resp.status_code})")
            if _attempt < 2:
                time.sleep(1)
                return self._post(payload, _attempt=2)
            return NotificationResult(channel="webhook", success=False,
                                      message=f"Webhook HTTP {resp.status_code}: {resp.text[:200]}")
        except Exception as exc:
            logger.error("Webhook send error: %s", exc)
            return NotificationResult(channel="webhook", success=False, message=str(exc))
