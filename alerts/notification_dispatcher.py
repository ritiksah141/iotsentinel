#!/usr/bin/env python3
"""
Notification Dispatcher for IoTSentinel

Routes alerts to appropriate notification channels based on:
- Alert severity
- User preferences
- Channel availability

Supports multiple notification channels:
- Email (immediate alerts + digest reports)
- Webhook (for integration with other systems)
- Future: Push notifications, SMS, etc.
"""

import logging
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class NotificationChannel(Enum):
    """Available notification channels."""
    EMAIL = "email"
    WEBHOOK = "webhook"
    LOG_ONLY = "log_only"


@dataclass
class NotificationResult:
    """Result of a notification attempt."""
    channel: str
    success: bool
    message: str
    timestamp: str = None

    def __post_init__(self):
        if self.timestamp is None:
            from datetime import datetime
            self.timestamp = datetime.now().isoformat()


class NotificationHandler(ABC):
    """Abstract base class for notification handlers."""

    @property
    @abstractmethod
    def channel_name(self) -> str:
        """Return the name of this notification channel."""
        pass

    @abstractmethod
    def is_enabled(self) -> bool:
        """Check if this handler is enabled and configured."""
        pass

    @abstractmethod
    def send(self, alert) -> NotificationResult:
        """
        Send a notification for the given alert.

        Args:
            alert: Alert object to send notification for

        Returns:
            NotificationResult indicating success or failure
        """
        pass

    @abstractmethod
    def send_report(self, report_data: Dict[str, Any]) -> NotificationResult:
        """
        Send a periodic report.

        Args:
            report_data: Dictionary containing report information

        Returns:
            NotificationResult indicating success or failure
        """
        pass


class NotificationDispatcher:
    """
    Central dispatcher for routing notifications.

    Manages multiple notification handlers and routes alerts
    based on severity and configuration.
    """

    def __init__(self, config):
        """
        Initialize the dispatcher.

        Args:
            config: Configuration manager instance
        """
        self.config = config
        self._handlers: Dict[str, NotificationHandler] = {}

        # Severity routing configuration
        # Maps severity to list of channels that should receive notifications
        self._severity_routing = {
            'critical': [NotificationChannel.EMAIL],
            'high': [NotificationChannel.EMAIL],
            'medium': [NotificationChannel.LOG_ONLY],  # Include in digest only
            'low': [NotificationChannel.LOG_ONLY]       # Include in digest only
        }

        logger.info("NotificationDispatcher initialized")

    def register_handler(self, handler: NotificationHandler):
        """
        Register a notification handler.

        Args:
            handler: NotificationHandler instance to register
        """
        channel_name = handler.channel_name

        if not handler.is_enabled():
            logger.info(f"Handler '{channel_name}' is disabled, skipping registration")
            return

        self._handlers[channel_name] = handler
        logger.info(f"Registered notification handler: {channel_name}")

    def unregister_handler(self, channel_name: str):
        """Remove a handler from the dispatcher."""
        if channel_name in self._handlers:
            del self._handlers[channel_name]
            logger.info(f"Unregistered notification handler: {channel_name}")

    def configure_severity_routing(self, severity: str, channels: List[NotificationChannel]):
        """
        Configure which channels receive notifications for a severity level.

        Args:
            severity: Severity level (critical, high, medium, low)
            channels: List of NotificationChannel enum values
        """
        self._severity_routing[severity.lower()] = channels
        logger.info(f"Updated routing for {severity}: {[c.value for c in channels]}")

    def dispatch(self, alert) -> List[NotificationResult]:
        """
        Dispatch an alert to appropriate channels.

        Args:
            alert: Alert object to dispatch

        Returns:
            List of NotificationResult for each channel attempted
        """
        results = []
        severity = alert.severity.lower()

        # Get channels for this severity
        channels = self._severity_routing.get(severity, [NotificationChannel.LOG_ONLY])

        # Always log the alert
        logger.info(
            f"Dispatching alert: Device={alert.device_ip}, "
            f"Severity={severity}, Score={alert.anomaly_score:.4f}"
        )

        for channel in channels:
            if channel == NotificationChannel.LOG_ONLY:
                # Log-only means no external notification
                results.append(NotificationResult(
                    channel="log",
                    success=True,
                    message="Alert logged (no notification sent)"
                ))
                continue

            handler = self._handlers.get(channel.value)
            if handler is None:
                logger.warning(f"No handler registered for channel: {channel.value}")
                results.append(NotificationResult(
                    channel=channel.value,
                    success=False,
                    message=f"No handler registered for {channel.value}"
                ))
                continue

            try:
                result = handler.send(alert)
                results.append(result)

                if result.success:
                    logger.info(f"Alert sent via {channel.value}")
                else:
                    logger.warning(f"Failed to send alert via {channel.value}: {result.message}")

            except Exception as e:
                logger.error(f"Error dispatching to {channel.value}: {e}")
                results.append(NotificationResult(
                    channel=channel.value,
                    success=False,
                    message=str(e)
                ))

        return results

    def dispatch_report(self, report_data: Dict[str, Any]) -> List[NotificationResult]:
        """
        Dispatch a periodic report to all configured channels.

        Args:
            report_data: Dictionary containing report information

        Returns:
            List of NotificationResult for each channel attempted
        """
        results = []

        logger.info(f"Dispatching report: {report_data.get('report_type', 'unknown')}")

        # Reports go to all enabled handlers
        for channel_name, handler in self._handlers.items():
            try:
                result = handler.send_report(report_data)
                results.append(result)

                if result.success:
                    logger.info(f"Report sent via {channel_name}")
                else:
                    logger.warning(f"Failed to send report via {channel_name}: {result.message}")

            except Exception as e:
                logger.error(f"Error dispatching report to {channel_name}: {e}")
                results.append(NotificationResult(
                    channel=channel_name,
                    success=False,
                    message=str(e)
                ))

        return results

    def get_handler_status(self) -> Dict[str, Dict[str, Any]]:
        """
        Get status of all registered handlers.

        Returns:
            Dictionary mapping channel names to their status
        """
        status = {}

        for channel_name, handler in self._handlers.items():
            status[channel_name] = {
                'enabled': handler.is_enabled(),
                'registered': True
            }

        # Also include disabled channels
        for channel in NotificationChannel:
            if channel.value not in status:
                status[channel.value] = {
                    'enabled': False,
                    'registered': False
                }

        return status
