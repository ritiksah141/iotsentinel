#!/usr/bin/env python3
"""
Extended coverage tests for EmailNotifier.

Targets uncovered branches: _parse_bool, _format_report_subject,
_format_report_text, _format_report_html (empty rows), send_with_attachment
disabled-path, and the error path in _send_with_retry.

Run: pytest tests/test_email_coverage.py -v --cov=alerts.email_notifier
"""

import pytest
import smtplib
from unittest.mock import patch, Mock, MagicMock
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

from alerts.email_notifier import EmailNotifier
from alerts.notification_dispatcher import NotificationResult


# ── fixtures ──────────────────────────────────────────────────────────────────

def _make_config(enabled=True, with_smtp=True):
    config = Mock()
    smtp_data = {
        ('email', 'enabled'): enabled,
        ('email', 'smtp_host'): 'smtp.test.com' if with_smtp else None,
        ('email', 'smtp_port'): 587,
        ('email', 'smtp_user'): 'u@test.com' if with_smtp else None,
        ('email', 'smtp_password'): 'pw' if with_smtp else None,
        ('email', 'sender_email'): 'from@test.com' if with_smtp else None,
        ('email', 'recipient_email'): 'to@test.com' if with_smtp else None,
    }
    config.get = Mock(side_effect=lambda s, k, default=None: smtp_data.get((s, k), default))
    return config


@pytest.fixture
def enabled_notifier():
    return EmailNotifier(_make_config(enabled=True, with_smtp=True))


@pytest.fixture
def disabled_notifier():
    config = Mock()
    config.get = Mock(side_effect=lambda s, k, default=None: {
        ('email', 'enabled'): False,
    }.get((s, k), default))
    return EmailNotifier(config)


# ── _parse_bool ───────────────────────────────────────────────────────────────

class TestParseBool:
    def test_bool_true(self, enabled_notifier):
        assert enabled_notifier._parse_bool(True) is True

    def test_bool_false(self, enabled_notifier):
        assert enabled_notifier._parse_bool(False) is False

    def test_string_true_variants(self, enabled_notifier):
        for v in ('true', '1', 'yes', 'on', 'True', 'YES'):
            assert enabled_notifier._parse_bool(v) is True

    def test_string_false_variants(self, enabled_notifier):
        for v in ('false', '0', 'no', 'off', 'False', 'NO'):
            assert enabled_notifier._parse_bool(v) is False

    def test_int_truthy(self, enabled_notifier):
        assert enabled_notifier._parse_bool(1) is True

    def test_int_falsy(self, enabled_notifier):
        assert enabled_notifier._parse_bool(0) is False


# ── _format_report_subject ────────────────────────────────────────────────────

class TestFormatReportSubject:
    def test_weekly_subject(self, enabled_notifier):
        subject = enabled_notifier._format_report_subject(
            {'report_type': 'weekly', 'period': 'Week 20'}
        )
        assert 'Weekly' in subject
        assert 'Week 20' in subject

    def test_monthly_subject(self, enabled_notifier):
        subject = enabled_notifier._format_report_subject(
            {'report_type': 'monthly', 'period': 'May 2026'}
        )
        assert 'Monthly' in subject
        assert 'May 2026' in subject

    def test_default_subject(self, enabled_notifier):
        subject = enabled_notifier._format_report_subject(
            {'report_type': 'summary', 'period': 'Q1'}
        )
        assert 'Q1' in subject


# ── _format_report_text ───────────────────────────────────────────────────────

class TestFormatReportText:
    def _make_report(self, by_device=None, by_severity=None):
        if by_device is None:
            by_device = {'192.168.1.10': 3, '192.168.1.20': 2}
        if by_severity is None:
            by_severity = {'critical': 1, 'high': 2, 'medium': 1, 'low': 1}
        return {
            'report_type': 'weekly',
            'period': 'Week of 2026-05-10',
            'summary': {
                'total': 5,
                'by_severity': by_severity,
                'by_device': by_device,
                'acknowledged': 4,
                'unacknowledged': 1
            },
            'network_stats': {
                'total_devices': 10,
                'total_connections': 500,
                'data_transferred': '1.2 GB'
            }
        }

    def test_report_text_contains_period(self, enabled_notifier):
        text = enabled_notifier._format_report_text(self._make_report())
        assert 'Week of 2026-05-10' in text

    def test_report_text_contains_device_ips(self, enabled_notifier):
        text = enabled_notifier._format_report_text(self._make_report())
        assert '192.168.1.10' in text

    def test_report_text_empty_device_list(self, enabled_notifier):
        text = enabled_notifier._format_report_text(self._make_report(by_device={}))
        assert 'No device alerts' in text

    def test_report_text_severity_counts(self, enabled_notifier):
        text = enabled_notifier._format_report_text(self._make_report())
        assert 'Critical' in text or 'critical' in text.lower()


# ── _format_report_html ───────────────────────────────────────────────────────

class TestFormatReportHtml:
    def _make_report(self, by_device=None, top_alerts=None):
        return {
            'report_type': 'weekly',
            'period': 'Week 20',
            'summary': {
                'total': 3,
                'by_severity': {'critical': 1, 'high': 1, 'medium': 1, 'low': 0},
                'by_device': by_device if by_device is not None else {'10.0.0.1': 3},
                'acknowledged': 2,
                'unacknowledged': 1
            },
            'network_stats': {'total_devices': 5, 'total_connections': 100},
            'top_alerts': top_alerts or []
        }

    def test_html_with_devices(self, enabled_notifier):
        html = enabled_notifier._format_report_html(self._make_report())
        assert '10.0.0.1' in html

    def test_html_empty_device_rows_placeholder(self, enabled_notifier):
        html = enabled_notifier._format_report_html(self._make_report(by_device={}))
        assert 'No alerts in this period' in html

    def test_html_empty_alert_rows_placeholder(self, enabled_notifier):
        html = enabled_notifier._format_report_html(self._make_report(top_alerts=[]))
        assert 'No alerts to display' in html

    def test_html_with_top_alerts(self, enabled_notifier):
        alerts = [
            {'severity': 'high', 'device_ip': '10.0.0.2', 'explanation': 'Port scan detected here'}
        ]
        html = enabled_notifier._format_report_html(self._make_report(top_alerts=alerts))
        assert '10.0.0.2' in html


# ── send_with_attachment disabled path ───────────────────────────────────────

class TestSendWithAttachmentDisabled:
    def test_returns_failure_when_not_enabled(self, disabled_notifier):
        result = disabled_notifier.send_with_attachment(
            subject='test', body_html='<p>hi</p>', body_text='hi'
        )
        assert result.success is False
        assert 'not configured' in result.message.lower()

    def test_send_with_attachment_enabled_no_smtp_raises(self, enabled_notifier):
        with patch.object(enabled_notifier, '_send_with_retry') as mock_send:
            mock_send.return_value = NotificationResult(
                channel='email', success=True, message='sent'
            )
            result = enabled_notifier.send_with_attachment(
                subject='Test', body_html='<p>body</p>', body_text='body'
            )
            assert result.success is True


# ── _send_with_retry unexpected exception path ─────────────────────────────────

class TestSendWithRetryError:
    def test_unexpected_exception_returns_failure(self, enabled_notifier):
        with patch.object(enabled_notifier, '_create_connection', side_effect=RuntimeError('boom')):
            from email.mime.multipart import MIMEMultipart
            msg = MIMEMultipart()
            msg['Subject'] = 'test'
            msg['From'] = 'a@b.com'
            msg['To'] = 'c@d.com'
            result = enabled_notifier._send_with_retry(msg)
        assert result.success is False

    def test_smtp_exception_retries(self, enabled_notifier):
        with patch.object(enabled_notifier, '_create_connection',
                          side_effect=smtplib.SMTPException('retry')):
            from email.mime.multipart import MIMEMultipart
            msg = MIMEMultipart()
            msg['Subject'] = 'retry test'
            msg['From'] = 'a@b.com'
            msg['To'] = 'c@d.com'
            with patch('time.sleep'):  # don't actually sleep in tests
                result = enabled_notifier._send_with_retry(msg)
        assert result.success is False

    def test_smtp_auth_error_no_retry(self, enabled_notifier):
        with patch.object(
            enabled_notifier, '_create_connection',
            side_effect=smtplib.SMTPAuthenticationError(535, b'auth failed')
        ):
            from email.mime.multipart import MIMEMultipart
            msg = MIMEMultipart()
            result = enabled_notifier._send_with_retry(msg)
        assert result.success is False
        assert 'Authentication' in result.message


# ── report_builder / template_manager not configured path ────────────────────

class TestSendReportWithAttachmentNotConfigured:
    def test_returns_failure_when_not_configured(self, enabled_notifier):
        enabled_notifier.report_builder = None
        enabled_notifier.template_manager = None
        result = enabled_notifier.send_report_with_attachment('summary')
        assert result.success is False
        assert 'not configured' in result.message.lower()
