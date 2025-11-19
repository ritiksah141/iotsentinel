#!/usr/bin/env python3
"""
Unit Tests for Alerting Subsystem

Test Coverage:
- Email Notifier
"""

import pytest
from unittest.mock import patch, MagicMock
import smtplib

from alerts.email_notifier import send_email, send_alert_email
from config.config_manager import config

@pytest.fixture(autouse=True)
def mock_config():
    """Fixture to mock email configuration for tests."""
    with patch('alerts.email_notifier.config') as mock_conf:
        mock_conf.get.side_effect = lambda *args, **kwargs: {
            ("email", "enabled"): True,
            ("email", "smtp_host"): "smtp.test.com",
            ("email", "smtp_port"): 587,
            ("email", "smtp_user"): "user",
            ("email", "smtp_password"): "password",
            ("email", "sender_email"): "sender@test.com",
            ("email", "recipient_email"): "recipient@test.com"
        }.get(args, kwargs.get('default'))
        yield mock_conf

class TestEmailNotifier:
    """Test suite for the email notifier."""

    @patch('smtplib.SMTP')
    def test_send_email_success(self, mock_smtp, mock_config):
        """TC-ALRT-001: Verify successful email sending."""
        # Arrange
        mock_server = MagicMock()
        mock_smtp.return_value.__enter__.return_value = mock_server

        subject = "Test Subject"
        html_body = "<h1>Hello</h1>"

        # Act
        send_email(subject, html_body)

        # Assert
        mock_smtp.assert_called_with("smtp.test.com", 587)
        mock_server.starttls.assert_called_once()
        mock_server.login.assert_called_with("user", "password")
        mock_server.sendmail.assert_called_once()

        # Check that the email content is correct
        args, _ = mock_server.sendmail.call_args
        assert args[0] == "sender@test.com"
        assert args[1] == "recipient@test.com"
        assert "Subject: Test Subject" in args[2]
        assert "Content-Type: text/html" in args[2]
        assert "<h1>Hello</h1>" in args[2]

    @patch('smtplib.SMTP')
    def test_send_email_failure(self, mock_smtp, mock_config):
        """TC-ALRT-002: Verify failure handling in email sending."""
        # Arrange
        mock_smtp.side_effect = smtplib.SMTPException("Test error")

        # Act & Assert
        with patch('alerts.email_notifier.logger') as mock_logger:
            send_email("Subject", "Body")
            mock_logger.error.assert_called_once()
            args, kwargs = mock_logger.error.call_args
            assert args[0] == "Failed to send email: %s"
            assert isinstance(args[1], smtplib.SMTPException)

    @patch('alerts.email_notifier.send_email')
    def test_send_alert_email(self, mock_send_email):
        """TC-ALRT-003: Verify alert email formatting and sending."""
        # Arrange
        alert_details = {
            'device_ip': '192.168.1.101',
            'severity': 'High',
            'anomaly_score': 0.98,
            'explanation': 'Unusual traffic pattern',
            'timestamp': '2025-01-01 12:00:00'
        }

        # Act
        send_alert_email(alert_details)

        # Assert
        mock_send_email.assert_called_once()

        args, _ = mock_send_email.call_args
        subject = args[0]
        html_body = args[1]

        assert "Critical Alert: 192.168.1.101" in subject
        assert "<strong>Device:</strong> 192.168.1.101" in html_body
        assert "<strong>Anomaly Score:</strong> 0.9800" in html_body

    @patch('smtplib.SMTP')
    def test_send_email_disabled(self, mock_smtp, mock_config):
        """TC-ALRT-004: Verify email is not sent when disabled."""
        # Arrange
        mock_config.get.side_effect = lambda *args, **kwargs: False if args == ("email", "enabled") else "value"

        # Act
        send_email("Subject", "Body")

        # Assert
        mock_smtp.assert_not_called()

    @patch('smtplib.SMTP')
    def test_send_email_incomplete_config(self, mock_smtp, mock_config):
        """TC-ALRT-005: Verify email is not sent with incomplete config."""
        # Arrange
        mock_config.get.side_effect = lambda *args, **kwargs: "" if args[1] == "smtp_host" else "value"

        # Act
        with patch('alerts.email_notifier.logger') as mock_logger:
            send_email("Subject", "Body")

            # Assert
            mock_smtp.assert_not_called()
            mock_logger.warning.assert_called_with("Email configuration is incomplete. Skipping email notification.")
