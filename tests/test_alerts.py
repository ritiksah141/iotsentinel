#!/usr/bin/env python3
"""
Unit Tests for Alerting Subsystem

Test Coverage:
- EmailNotifier class (new API)
- Alert sending
- Report generation
- Configuration handling
"""

import pytest
from unittest.mock import patch, MagicMock, Mock
import smtplib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from alerts.email_notifier import EmailNotifier
from alerts.notification_dispatcher import NotificationResult


class MockAlert:
    """Mock alert object for testing."""
    def __init__(self, device_ip='192.168.1.100', device_name='Test Device',
                 severity='high', anomaly_score=0.95, explanation='Test explanation',
                 timestamp=None):
        self.device_ip = device_ip
        self.device_name = device_name
        self.severity = severity
        self.anomaly_score = anomaly_score
        self.explanation = explanation
        self.timestamp = timestamp


@pytest.fixture
def mock_config():
    """Fixture to provide mock email configuration."""
    config = Mock()
    config.get = Mock(side_effect=lambda section, key, default=None: {
        ('email', 'enabled'): True,
        ('email', 'smtp_host'): 'smtp.test.com',
        ('email', 'smtp_port'): 587,
        ('email', 'smtp_user'): 'user@test.com',
        ('email', 'smtp_password'): 'password123',
        ('email', 'sender_email'): 'sender@test.com',
        ('email', 'recipient_email'): 'recipient@test.com'
    }.get((section, key), default))
    return config


@pytest.fixture
def email_notifier(mock_config):
    """Fixture to provide EmailNotifier instance."""
    return EmailNotifier(mock_config)


class TestEmailNotifierInitialization:
    """Test suite for EmailNotifier initialization."""

    def test_init_with_valid_config(self, mock_config):
        """TC-ALRT-001: Verify successful initialization with valid config."""
        # Act
        notifier = EmailNotifier(mock_config)

        # Assert
        assert notifier.is_enabled() is True
        assert notifier.channel_name == 'email'

    def test_init_with_disabled_config(self):
        """TC-ALRT-002: Verify initialization with disabled config."""
        # Arrange
        config = Mock()
        config.get = Mock(side_effect=lambda section, key, default=None: {
            ('email', 'enabled'): False
        }.get((section, key), default))

        # Act
        notifier = EmailNotifier(config)

        # Assert
        assert notifier.is_enabled() is False

    def test_init_with_incomplete_config(self):
        """TC-ALRT-003: Verify initialization with incomplete config."""
        # Arrange
        config = Mock()
        config.get = Mock(side_effect=lambda section, key, default=None: {
            ('email', 'enabled'): True,
            ('email', 'smtp_host'): None  # Missing required field
        }.get((section, key), default))

        # Act
        notifier = EmailNotifier(config)

        # Assert
        assert notifier.is_enabled() is False


class TestEmailSending:
    """Test suite for email sending functionality."""

    @patch('smtplib.SMTP')
    def test_send_alert_email_success(self, mock_smtp_class, email_notifier):
        """TC-ALRT-004: Verify successful alert email sending."""
        # Arrange
        mock_server = MagicMock()
        mock_smtp_class.return_value = mock_server

        alert = MockAlert(
            device_ip='192.168.1.100',
            severity='critical',
            anomaly_score=0.98,
            explanation='Unusual traffic pattern detected'
        )

        # Act
        result = email_notifier.send(alert)

        # Assert
        assert isinstance(result, NotificationResult)
        assert result.success is True
        assert result.channel == 'email'
        mock_server.send_message.assert_called_once()
        mock_server.quit.assert_called_once()

    @patch('smtplib.SMTP')
    def test_send_alert_email_auth_failure(self, mock_smtp_class, email_notifier):
        """TC-ALRT-005: Verify handling of SMTP authentication failure."""
        # Arrange
        mock_server = MagicMock()
        mock_smtp_class.return_value = mock_server
        mock_server.login.side_effect = smtplib.SMTPAuthenticationError(535, 'Authentication failed')

        alert = MockAlert()

        # Act
        result = email_notifier.send(alert)

        # Assert
        assert isinstance(result, NotificationResult)
        assert result.success is False
        assert 'Authentication failed' in result.message

    @patch('smtplib.SMTP')
    def test_send_alert_email_retry(self, mock_smtp_class, email_notifier):
        """TC-ALRT-006: Verify retry logic on transient errors."""
        # Arrange
        mock_server = MagicMock()
        mock_smtp_class.return_value = mock_server

        # First attempt fails, second succeeds
        mock_server.send_message.side_effect = [
            smtplib.SMTPException('Temporary error'),
            None  # Success
        ]

        alert = MockAlert()

        # Act
        with patch('time.sleep'):  # Speed up test by mocking sleep
            result = email_notifier.send(alert)

        # Assert
        assert isinstance(result, NotificationResult)
        assert result.success is True
        assert mock_server.send_message.call_count == 2

    def test_send_alert_disabled(self):
        """TC-ALRT-007: Verify email not sent when disabled."""
        # Arrange
        config = Mock()
        config.get = Mock(side_effect=lambda section, key, default=None: {
            ('email', 'enabled'): False
        }.get((section, key), default))

        notifier = EmailNotifier(config)
        alert = MockAlert()

        # Act
        with patch('smtplib.SMTP') as mock_smtp:
            result = notifier.send(alert)

            # Assert
            assert result.success is False
            assert 'not enabled' in result.message
            mock_smtp.assert_not_called()


class TestReportSending:
    """Test suite for report email sending."""

    @patch('smtplib.SMTP')
    def test_send_report_success(self, mock_smtp_class, email_notifier):
        """TC-ALRT-008: Verify successful report email sending."""
        # Arrange
        mock_server = MagicMock()
        mock_smtp_class.return_value = mock_server

        report_data = {
            'report_type': 'weekly',
            'period': 'Jan 1-7, 2025',
            'summary': {
                'total': 15,
                'by_severity': {'critical': 2, 'high': 5, 'medium': 5, 'low': 3},
                'acknowledged': 10,
                'unacknowledged': 5,
                'by_device': {'192.168.1.100': 5, '192.168.1.101': 10}
            },
            'network_stats': {
                'total_devices': 25,
                'total_connections': 5000,
                'data_transferred': '2.5 GB'
            },
            'top_alerts': []
        }

        # Act
        result = email_notifier.send_report(report_data)

        # Assert
        assert isinstance(result, NotificationResult)
        assert result.success is True
        mock_server.send_message.assert_called_once()

    def test_send_report_disabled(self):
        """TC-ALRT-009: Verify report not sent when disabled."""
        # Arrange
        config = Mock()
        config.get = Mock(side_effect=lambda section, key, default=None: {
            ('email', 'enabled'): False
        }.get((section, key), default))

        notifier = EmailNotifier(config)
        report_data = {'report_type': 'weekly'}

        # Act
        with patch('smtplib.SMTP') as mock_smtp:
            result = notifier.send_report(report_data)

            # Assert
            assert result.success is False
            mock_smtp.assert_not_called()


class TestEmailFormatting:
    """Test suite for email formatting."""

    def test_format_alert_subject(self, email_notifier):
        """TC-ALRT-010: Verify alert subject formatting."""
        # Arrange
        alert = MockAlert(device_ip='192.168.1.100', device_name='Living Room Camera', severity='critical')

        # Act
        subject = email_notifier._format_alert_subject(alert)

        # Assert
        assert 'IoTSentinel' in subject
        assert 'CRITICAL' in subject
        assert 'Living Room Camera' in subject

    def test_format_alert_html_contains_details(self, email_notifier):
        """TC-ALRT-011: Verify HTML email contains all alert details."""
        # Arrange
        alert = MockAlert(
            device_ip='192.168.1.100',
            device_name='Test Device',
            severity='high',
            anomaly_score=0.92,
            explanation='Test explanation'
        )

        # Act
        html = email_notifier._format_alert_html(alert)

        # Assert
        assert '192.168.1.100' in html
        assert 'Test Device' in html
        assert '0.9200' in html
        assert 'Test explanation' in html

    def test_format_report_subject(self, email_notifier):
        """TC-ALRT-012: Verify report subject formatting."""
        # Arrange
        report_data = {
            'report_type': 'weekly',
            'period': 'Jan 1-7, 2025'
        }

        # Act
        subject = email_notifier._format_report_subject(report_data)

        # Assert
        assert 'Weekly' in subject
        assert 'Jan 1-7, 2025' in subject


class TestSeverityHelpers:
    """Test suite for severity helper methods."""

    def test_get_severity_color(self, email_notifier):
        """TC-ALRT-013: Verify severity color mapping."""
        # Act & Assert
        assert '#dc3545' in email_notifier._get_severity_color('critical')
        assert '#fd7e14' in email_notifier._get_severity_color('high')
        assert '#ffc107' in email_notifier._get_severity_color('medium')
        assert '#17a2b8' in email_notifier._get_severity_color('low')

    def test_get_severity_explanation(self, email_notifier):
        """TC-ALRT-014: Verify severity explanations exist."""
        # Act & Assert
        assert len(email_notifier._get_severity_explanation('critical')) > 50
        assert len(email_notifier._get_severity_explanation('high')) > 50
        assert len(email_notifier._get_severity_explanation('medium')) > 50
        assert len(email_notifier._get_severity_explanation('low')) > 50

    def test_get_recommended_actions(self, email_notifier):
        """TC-ALRT-015: Verify recommended actions exist."""
        # Act & Assert
        assert 'Review' in email_notifier._get_recommended_actions('critical')
        assert 'Review' in email_notifier._get_recommended_actions('high')
        assert 'Review' in email_notifier._get_recommended_actions('medium')
        assert 'Review' in email_notifier._get_recommended_actions('low')
