"""
IoTSentinel Alerts Module

Production-ready alerting system with:
- Central alert service with deduplication and rate limiting
- Multi-channel notification dispatcher
- Email notifications with HTML templates
- Scheduled weekly and monthly reports

Usage:
    from alerts import AlertService, NotificationDispatcher, EmailNotifier, ReportScheduler

    # Initialize components
    alert_service = AlertService(db_manager, config)
    dispatcher = NotificationDispatcher(config)
    email_handler = EmailNotifier(config)

    # Register handlers
    dispatcher.register_handler(email_handler)
    alert_service.set_dispatcher(dispatcher)

    # Start report scheduler
    scheduler = ReportScheduler(db_manager, alert_service, dispatcher)
    scheduler.start()

    # Create an alert
    alert_service.create_alert(
        device_ip='192.168.1.100',
        severity='high',
        anomaly_score=0.95,
        explanation='Unusual outbound data transfer detected'
    )
"""

from .alert_service import AlertService, Alert, AlertSeverity, RateLimiter
from .notification_dispatcher import (
    NotificationDispatcher,
    NotificationHandler,
    NotificationResult,
    NotificationChannel
)
from .email_notifier import EmailNotifier
from .report_scheduler import ReportScheduler, ReportGenerator
from .integration import AlertingSystem

__all__ = [
    # Core service
    'AlertService',
    'Alert',
    'AlertSeverity',
    'RateLimiter',

    # Notification system
    'NotificationDispatcher',
    'NotificationHandler',
    'NotificationResult',
    'NotificationChannel',

    # Email
    'EmailNotifier',

    # Scheduling
    'ReportScheduler',
    'ReportGenerator',

    # Integration
    'AlertingSystem'
]

__version__ = '1.0.0'
