"""
IntegrationHubNotifier — bridges the Integration Hub (encrypted DB credentials)
into the live NotificationDispatcher fan-out pipeline.

Runs alongside the env-based handlers in push_notifiers.py so that channels
configured via the API Hub page also fire on real critical/high alerts.
"""

import logging
from typing import Any, Dict

from .notification_dispatcher import NotificationHandler, NotificationResult

logger = logging.getLogger(__name__)

# Channels that live under the 'notifications' category in the Integration Hub.
_NOTIFICATION_CHANNELS = ('ntfy', 'telegram', 'discord', 'slack', 'pushover')


def _format_hub_alert(alert) -> str:
    severity = getattr(alert, 'severity', 'medium').upper()
    device = getattr(alert, 'device_name', None) or getattr(alert, 'device_ip', 'unknown')
    score = getattr(alert, 'anomaly_score', None)
    explanation = getattr(alert, 'explanation', '')
    ts = getattr(alert, 'timestamp', '')

    lines = [f"[{severity}] IoTSentinel Alert — {device}"]
    if score is not None:
        lines.append(f"Anomaly score: {score:.2f}")
    if explanation:
        lines.append(explanation)
    if ts:
        lines.append(f"Time: {ts}")
    return "\n".join(lines)


def _dispatch_alert(actions, channel: str, text: str, severity: str) -> bool:
    if channel == 'ntfy':
        return actions.send_ntfy_alert(text, severity)
    if channel == 'telegram':
        return actions.send_telegram_alert(text)
    if channel == 'discord':
        return actions.send_discord_alert(text, severity)
    if channel == 'slack':
        return actions.send_slack_alert(text, severity)
    if channel == 'pushover':
        priority = 1 if severity in ('critical', 'high') else 0
        return actions.send_pushover_alert(text, priority)
    return False


def _dispatch_report(actions, channel: str, text: str) -> bool:
    if channel == 'ntfy':
        return actions.send_ntfy_alert(text, 'low')
    if channel == 'telegram':
        return actions.send_telegram_alert(text)
    if channel == 'discord':
        return actions.send_discord_alert(text, 'low')
    if channel == 'slack':
        return actions.send_slack_alert(text, 'low')
    if channel == 'pushover':
        return actions.send_pushover_alert(text, -1)
    return False


class IntegrationHubNotifier(NotificationHandler):
    """Fan-out adapter: fires all configured Integration Hub notification channels.

    This is registered as a single handler with the NotificationDispatcher.
    On each alert it instantiates IntegrationActions, checks which Integration Hub
    notification channels have credentials, and delegates to the matching
    send_*_alert method. The env-based push_notifiers.py handlers remain
    independent — both paths fire simultaneously via the fan-out sentinel.
    """

    channel_name = "integration_hub"

    def __init__(self, db_manager):
        self._db = db_manager

    def is_enabled(self) -> bool:
        try:
            from alerts.integration_system import IntegrationManager
            mgr = IntegrationManager(self._db)
            return any(
                mgr.get_integration_credentials(ch) for ch in _NOTIFICATION_CHANNELS
            )
        except Exception as exc:
            logger.debug(f"IntegrationHubNotifier.is_enabled check failed: {exc}")
            return False

    def send(self, alert) -> NotificationResult:
        try:
            from alerts.integration_actions import IntegrationActions
            severity = getattr(alert, 'severity', 'medium')
            text = _format_hub_alert(alert)
            actions = IntegrationActions(self._db)

            fired, failed = [], []
            for ch in _NOTIFICATION_CHANNELS:
                if not actions.integration_mgr.get_integration_credentials(ch):
                    continue
                ok = _dispatch_alert(actions, ch, text, severity)
                (fired if ok else failed).append(ch)

            if not fired and not failed:
                return NotificationResult(
                    channel="integration_hub", success=False,
                    message="No Integration Hub notification channels configured"
                )

            if fired and failed:
                msg = f"Sent: {', '.join(fired)}; failed: {', '.join(failed)}"
            elif fired:
                msg = f"Sent via: {', '.join(fired)}"
            else:
                msg = f"All channels failed: {', '.join(failed)}"

            return NotificationResult(
                channel="integration_hub",
                success=len(failed) == 0,
                message=msg
            )

        except Exception as exc:
            logger.error(f"IntegrationHubNotifier.send failed: {exc}")
            return NotificationResult(
                channel="integration_hub", success=False, message=str(exc)
            )

    def send_report(self, report_data: Dict[str, Any]) -> NotificationResult:
        try:
            from alerts.integration_actions import IntegrationActions
            text = report_data.get('summary', 'IoTSentinel periodic security report')
            actions = IntegrationActions(self._db)

            fired = []
            for ch in _NOTIFICATION_CHANNELS:
                if not actions.integration_mgr.get_integration_credentials(ch):
                    continue
                if _dispatch_report(actions, ch, text):
                    fired.append(ch)

            return NotificationResult(
                channel="integration_hub",
                success=bool(fired),
                message=f"Report sent via: {', '.join(fired)}" if fired else "No channels configured"
            )

        except Exception as exc:
            logger.error(f"IntegrationHubNotifier.send_report failed: {exc}")
            return NotificationResult(
                channel="integration_hub", success=False, message=str(exc)
            )
