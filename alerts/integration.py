#!/usr/bin/env python3
"""
Alerting System Integration for IoTSentinel

This module provides the integration layer between the alerting system
and the main orchestrator. It initializes and manages all alerting components.

Usage in orchestrator.py:
    from alerts.integration import AlertingSystem

    # In IoTSentinelOrchestrator.__init__():
    self.alerting = AlertingSystem(self.db, config)

    # In start():
    self.alerting.start()

    # In stop():
    self.alerting.stop()

    # When creating alerts (in inference_engine.py):
    self.alerting.create_alert(
        device_ip='192.168.1.100',
        severity='high',
        anomaly_score=0.95,
        explanation='Unusual data transfer pattern detected'
    )
"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)


class AlertingSystem:
    """
    Unified alerting system integration.

    Manages the complete alerting pipeline:
    - AlertService for creating and managing alerts
    - NotificationDispatcher for routing to channels
    - EmailNotifier for email notifications
    - ReportScheduler for weekly/monthly reports
    """

    def __init__(self, db_manager, config):
        """
        Initialize the alerting system.

        Args:
            db_manager: Database manager instance
            config: Configuration manager instance
        """
        self.db = db_manager
        self.config = config
        self._initialized = False
        self._running = False

        # Components (lazy initialized)
        self._alert_service = None
        self._dispatcher = None
        self._email_handler = None
        self._report_scheduler = None

        # Check if alerting is enabled
        self._enabled = config.get('alerting', 'enabled', default=True)

        if self._enabled:
            self._initialize_components()
        else:
            logger.info("Alerting system is disabled in configuration")

    def _initialize_components(self):
        """Initialize all alerting components."""
        try:
            from .alert_service import AlertService
            from .notification_dispatcher import NotificationDispatcher
            from .email_notifier import EmailNotifier
            from .report_scheduler import ReportScheduler

            # Create notification dispatcher
            self._dispatcher = NotificationDispatcher(self.config)

            # Create and register email handler
            self._email_handler = EmailNotifier(self.config)
            if self._email_handler.is_enabled():
                self._dispatcher.register_handler(self._email_handler)
                logger.info("Email notifications enabled")
            else:
                logger.info("Email notifications disabled (not configured)")

            # Create alert service
            self._alert_service = AlertService(self.db, self.config)
            self._alert_service.set_dispatcher(self._dispatcher)

            # Create report scheduler
            self._report_scheduler = ReportScheduler(
                self.db,
                self._alert_service,
                self._dispatcher
            )

            self._initialized = True
            logger.info("Alerting system initialized successfully")

        except ImportError as e:
            logger.error(f"Failed to import alerting components: {e}")
            self._enabled = False
        except Exception as e:
            logger.error(f"Failed to initialize alerting system: {e}", exc_info=True)
            self._enabled = False

    def start(self):
        """Start the alerting system (report scheduler)."""
        if not self._enabled or not self._initialized:
            logger.warning("Alerting system not enabled or initialized")
            return

        if self._running:
            logger.warning("Alerting system already running")
            return

        try:
            # Start report scheduler
            if self._report_scheduler:
                self._report_scheduler.start()

            self._running = True
            logger.info("Alerting system started")

        except Exception as e:
            logger.error(f"Failed to start alerting system: {e}")

    def stop(self):
        """Stop the alerting system."""
        if not self._running:
            return

        try:
            if self._report_scheduler:
                self._report_scheduler.stop()

            self._running = False
            logger.info("Alerting system stopped")

        except Exception as e:
            logger.error(f"Error stopping alerting system: {e}")

    def create_alert(
        self,
        device_ip: str,
        severity: str,
        anomaly_score: float,
        explanation: str,
        top_features: Optional[str] = None
    ) -> Optional[int]:
        """
        Create a new alert.

        This is the main entry point for the inference engine to create alerts.

        Args:
            device_ip: IP address of the affected device
            severity: Alert severity (low, medium, high, critical)
            anomaly_score: ML model anomaly score
            explanation: Human-readable explanation
            top_features: JSON string of contributing features

        Returns:
            Alert ID if created, None otherwise
        """
        if not self._enabled or not self._alert_service:
            # Fall back to direct database insert if alerting system is disabled
            try:
                return self.db.create_alert(
                    device_ip=device_ip,
                    severity=severity,
                    anomaly_score=anomaly_score,
                    explanation=explanation,
                    top_features=top_features
                )
            except Exception as e:
                logger.error(f"Failed to create alert: {e}")
                return None

        return self._alert_service.create_alert(
            device_ip=device_ip,
            severity=severity,
            anomaly_score=anomaly_score,
            explanation=explanation,
            top_features=top_features
        )

    def acknowledge_alert(self, alert_id: int) -> bool:
        """Mark an alert as acknowledged."""
        if not self._enabled or not self._alert_service:
            try:
                self.db.acknowledge_alert(alert_id)
                return True
            except Exception as e:
                logger.error(f"Failed to acknowledge alert: {e}")
                return False

        return self._alert_service.acknowledge_alert(alert_id)

    def get_alert_summary(self, hours: int = 24) -> dict:
        """Get alert summary for the specified time period."""
        if not self._enabled or not self._alert_service:
            return {'error': 'Alerting system not enabled'}

        return self._alert_service.get_alert_summary(hours=hours)

    def send_report_now(self, report_type: str = 'weekly') -> bool:
        """
        Manually trigger a report (for testing).

        Args:
            report_type: 'weekly' or 'monthly'

        Returns:
            True if successful
        """
        if not self._enabled or not self._report_scheduler:
            logger.warning("Cannot send report: alerting system not enabled")
            return False

        return self._report_scheduler.send_report_now(report_type)

    def send_test_email(self) -> bool:
        """
        Send a test email to verify configuration.

        Returns:
            True if email sent successfully
        """
        if not self._enabled or not self._email_handler:
            logger.warning("Cannot send test email: email handler not configured")
            return False

        if not self._email_handler.is_enabled():
            logger.warning("Email notifications are not enabled")
            return False

        try:
            from .alert_service import Alert

            test_alert = Alert(
                device_ip='127.0.0.1',
                severity='low',
                anomaly_score=0.0,
                explanation='This is a test alert to verify email configuration. No action required.',
                device_name='Test Device'
            )

            result = self._email_handler.send(test_alert)

            if result.success:
                logger.info("Test email sent successfully")
            else:
                logger.error(f"Test email failed: {result.message}")

            return result.success

        except Exception as e:
            logger.error(f"Error sending test email: {e}")
            return False

    @property
    def is_enabled(self) -> bool:
        """Check if alerting system is enabled."""
        return self._enabled

    @property
    def is_running(self) -> bool:
        """Check if alerting system is running."""
        return self._running

    def get_status(self) -> dict:
        """Get alerting system status."""
        status = {
            'enabled': self._enabled,
            'initialized': self._initialized,
            'running': self._running,
            'components': {
                'alert_service': self._alert_service is not None,
                'dispatcher': self._dispatcher is not None,
                'email_handler': self._email_handler is not None and self._email_handler.is_enabled(),
                'report_scheduler': self._report_scheduler is not None
            }
        }

        if self._dispatcher:
            status['notification_channels'] = self._dispatcher.get_handler_status()

        return status
