#!/usr/bin/env python3
"""
Alert Service for IoTSentinel

Central service managing the complete alert lifecycle:
- Alert creation with deduplication
- Severity-based routing
- Rate limiting to prevent alert fatigue
- Integration with notification dispatchers

This is the main entry point for alert management in the system.
"""

import logging
import hashlib
import json
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Any
from dataclasses import dataclass, asdict
from enum import Enum

logger = logging.getLogger('alerts')  # Use dedicated alerts logger


class AlertSeverity(Enum):
    """Alert severity levels with numeric weights for comparison."""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class Alert:
    """Data class representing a security alert."""
    device_ip: str
    severity: str
    anomaly_score: float
    explanation: str
    top_features: Optional[str] = None
    timestamp: Optional[datetime] = None
    alert_id: Optional[int] = None
    device_name: Optional[str] = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()

    def to_dict(self) -> Dict[str, Any]:
        """Convert alert to dictionary for serialization."""
        data = asdict(self)
        if isinstance(data['timestamp'], datetime):
            data['timestamp'] = data['timestamp'].isoformat()
        return data

    def get_fingerprint(self) -> str:
        """
        Generate a unique fingerprint for deduplication.

        Alerts with the same device, severity, and similar explanation
        within a time window are considered duplicates.
        """
        content = f"{self.device_ip}:{self.severity}:{self.explanation[:50]}"
        return hashlib.md5(content.encode()).hexdigest()


class RateLimiter:
    """
    Rate limiter to prevent alert fatigue.

    Tracks alerts per device and globally to prevent notification flooding.
    """

    def __init__(
        self,
        max_per_device_per_hour: int = 5,
        max_global_per_hour: int = 20,
        cooldown_minutes: int = 15
    ):
        self.max_per_device = max_per_device_per_hour
        self.max_global = max_global_per_hour
        self.cooldown_minutes = cooldown_minutes

        # Track alert timestamps: {device_ip: [timestamps]}
        self._device_alerts: Dict[str, List[datetime]] = {}
        self._global_alerts: List[datetime] = []

        # Track last alert per fingerprint for deduplication
        self._fingerprints: Dict[str, datetime] = {}

    def _cleanup_old_entries(self, cutoff: datetime):
        """Remove entries older than cutoff."""
        # Clean device alerts
        for device_ip in list(self._device_alerts.keys()):
            self._device_alerts[device_ip] = [
                ts for ts in self._device_alerts[device_ip]
                if ts > cutoff
            ]
            if not self._device_alerts[device_ip]:
                del self._device_alerts[device_ip]

        # Clean global alerts
        self._global_alerts = [
            ts for ts in self._global_alerts
            if ts > cutoff
        ]

        # Clean fingerprints (use cooldown period)
        fingerprint_cutoff = datetime.now() - timedelta(minutes=self.cooldown_minutes)
        self._fingerprints = {
            fp: ts for fp, ts in self._fingerprints.items()
            if ts > fingerprint_cutoff
        }

    def should_send(self, alert: Alert) -> tuple[bool, str]:
        """
        Check if an alert should be sent based on rate limits.

        Returns:
            Tuple of (should_send: bool, reason: str)
        """
        now = datetime.now()
        hour_ago = now - timedelta(hours=1)

        # Cleanup old entries
        self._cleanup_old_entries(hour_ago)

        # Check for duplicate (same fingerprint within cooldown)
        fingerprint = alert.get_fingerprint()
        if fingerprint in self._fingerprints:
            last_sent = self._fingerprints[fingerprint]
            if now - last_sent < timedelta(minutes=self.cooldown_minutes):
                return False, f"Duplicate alert suppressed (cooldown: {self.cooldown_minutes}min)"

        # Check device rate limit
        device_count = len(self._device_alerts.get(alert.device_ip, []))
        if device_count >= self.max_per_device:
            return False, f"Device rate limit reached ({self.max_per_device}/hour)"

        # Check global rate limit
        if len(self._global_alerts) >= self.max_global:
            return False, f"Global rate limit reached ({self.max_global}/hour)"

        # Critical alerts always pass (but still tracked)
        # This ensures critical alerts are sent even if limits are close

        return True, "OK"

    def record_sent(self, alert: Alert):
        """Record that an alert was sent."""
        now = datetime.now()

        # Record for device
        if alert.device_ip not in self._device_alerts:
            self._device_alerts[alert.device_ip] = []
        self._device_alerts[alert.device_ip].append(now)

        # Record globally
        self._global_alerts.append(now)

        # Record fingerprint
        self._fingerprints[alert.get_fingerprint()] = now


class AlertService:
    """
    Central alert management service.

    Coordinates alert creation, deduplication, rate limiting,
    and dispatching to notification channels.
    """

    def __init__(self, db_manager, config):
        """
        Initialize the alert service.

        Args:
            db_manager: Database manager instance for storing alerts
            config: Configuration manager instance
        """
        self.db = db_manager
        self.config = config

        # Initialize rate limiter with config values
        self.rate_limiter = RateLimiter(
            max_per_device_per_hour=config.get('alerting', 'max_per_device_per_hour', default=5),
            max_global_per_hour=config.get('alerting', 'max_global_per_hour', default=20),
            cooldown_minutes=config.get('alerting', 'cooldown_minutes', default=15)
        )

        # Notification dispatcher will be set up separately
        self._dispatcher = None

        logger.info("AlertService initialized")

    def set_dispatcher(self, dispatcher):
        """Set the notification dispatcher."""
        self._dispatcher = dispatcher

    def create_alert(
        self,
        device_ip: str,
        severity: str,
        anomaly_score: float,
        explanation: str,
        top_features: Optional[str] = None,
        send_notification: bool = True
    ) -> Optional[int]:
        """
        Create a new alert and optionally send notifications.

        Args:
            device_ip: IP address of the affected device
            severity: Alert severity (low, medium, high, critical)
            anomaly_score: ML model anomaly score
            explanation: Human-readable explanation of the anomaly
            top_features: JSON string of top contributing features
            send_notification: Whether to send notifications

        Returns:
            Alert ID if created, None if suppressed
        """
        # Get device name for better alerts
        device_name = self._get_device_name(device_ip)

        # Create alert object
        alert = Alert(
            device_ip=device_ip,
            severity=severity.lower(),
            anomaly_score=anomaly_score,
            explanation=explanation,
            top_features=top_features,
            device_name=device_name
        )

        # Check rate limits
        should_send, reason = self.rate_limiter.should_send(alert)

        # Always store in database regardless of rate limits
        alert_id = self.db.create_alert(
            device_ip=device_ip,
            severity=severity,
            anomaly_score=anomaly_score,
            explanation=explanation,
            top_features=top_features
        )
        alert.alert_id = alert_id

        logger.info(
            f"Alert created: ID={alert_id}, Device={device_ip}, "
            f"Severity={severity}, Score={anomaly_score:.4f}"
        )

        # Send notification if allowed
        if send_notification and should_send:
            self._send_notification(alert)
            self.rate_limiter.record_sent(alert)
        elif not should_send:
            logger.info(f"Notification suppressed for alert {alert_id}: {reason}")

        return alert_id

    def _get_device_name(self, device_ip: str) -> str:
        """Get the friendly name for a device."""
        try:
            device = self.db.get_device(device_ip)
            if device and device.get('device_name'):
                return device['device_name']
        except Exception as e:
            logger.warning(f"Could not get device name for {device_ip}: {e}")
        return device_ip

    def _send_notification(self, alert: Alert):
        """Send notification through the dispatcher."""
        if self._dispatcher is None:
            logger.warning("No notification dispatcher configured")
            return

        try:
            self._dispatcher.dispatch(alert)
        except Exception as e:
            logger.error(f"Failed to dispatch notification for alert {alert.alert_id}: {e}")

    def acknowledge_alert(self, alert_id: int) -> bool:
        """
        Mark an alert as acknowledged.

        Args:
            alert_id: ID of the alert to acknowledge

        Returns:
            True if successful, False otherwise
        """
        try:
            self.db.acknowledge_alert(alert_id)
            logger.info(f"Alert {alert_id} acknowledged")
            return True
        except Exception as e:
            logger.error(f"Failed to acknowledge alert {alert_id}: {e}")
            return False

    def get_unacknowledged_alerts(self, hours: int = 24) -> List[Dict]:
        """Get all unacknowledged alerts within the time window."""
        try:
            alerts = self.db.get_recent_alerts(hours=hours)
            return [a for a in alerts if not a.get('acknowledged', False)]
        except Exception as e:
            logger.error(f"Failed to get unacknowledged alerts: {e}")
            return []

    def get_alert_summary(self, hours: int = 24) -> Dict[str, Any]:
        """
        Get a summary of alerts for reporting.

        Returns:
            Dictionary with alert statistics
        """
        try:
            alerts = self.db.get_recent_alerts(hours=hours)

            summary = {
                'total': len(alerts),
                'by_severity': {
                    'critical': 0,
                    'high': 0,
                    'medium': 0,
                    'low': 0
                },
                'by_device': {},
                'acknowledged': 0,
                'unacknowledged': 0,
                'time_period_hours': hours
            }

            for alert in alerts:
                severity = alert.get('severity', 'low')
                device = alert.get('device_ip', 'unknown')

                summary['by_severity'][severity] = summary['by_severity'].get(severity, 0) + 1
                summary['by_device'][device] = summary['by_device'].get(device, 0) + 1

                if alert.get('acknowledged'):
                    summary['acknowledged'] += 1
                else:
                    summary['unacknowledged'] += 1

            return summary

        except Exception as e:
            logger.error(f"Failed to get alert summary: {e}")
            return {'error': str(e)}
