#!/usr/bin/env python3
"""
Email Notifier for IoTSentinel

Production-ready email notification handler with:
- Individual alert emails
- Weekly/monthly digest reports
- Retry logic with exponential backoff
- HTML and plain text formatting
- Template-based email generation
"""

import smtplib
import logging
import time
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from typing import Dict, Any, Optional, List

from .notification_dispatcher import NotificationHandler, NotificationResult

logger = logging.getLogger(__name__)


class EmailNotifier(NotificationHandler):
    """
    Email notification handler for IoTSentinel.

    Sends formatted HTML emails for:
    - Individual critical/high severity alerts
    - Weekly summary reports
    - Monthly trend reports
    """

    def __init__(self, config):
        """
        Initialize the email notifier.

        Args:
            config: Configuration manager instance
        """
        self.config = config

        # Load email configuration
        self._enabled = self._parse_bool(config.get('email', 'enabled', default=False))
        self._smtp_host = config.get('email', 'smtp_host')
        self._smtp_port = int(config.get('email', 'smtp_port', default=587))
        self._smtp_user = config.get('email', 'smtp_user')
        self._smtp_password = config.get('email', 'smtp_password')
        self._sender_email = config.get('email', 'sender_email')
        self._recipient_email = config.get('email', 'recipient_email')

        # Retry configuration
        self._max_retries = 3
        self._retry_delay = 5  # seconds

        if self._enabled:
            logger.info("EmailNotifier initialized and enabled")
        else:
            logger.info("EmailNotifier initialized but disabled")

    def _parse_bool(self, value) -> bool:
        """Parse boolean from various formats."""
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.lower() in ('true', '1', 'yes', 'on')
        return bool(value)

    @property
    def channel_name(self) -> str:
        return "email"

    def is_enabled(self) -> bool:
        """Check if email notifications are properly configured."""
        if not self._enabled:
            return False

        required = [
            self._smtp_host,
            self._smtp_port,
            self._smtp_user,
            self._smtp_password,
            self._sender_email,
            self._recipient_email
        ]

        return all(required)

    def _create_connection(self) -> smtplib.SMTP:
        """Create and authenticate SMTP connection."""
        server = smtplib.SMTP(self._smtp_host, self._smtp_port, timeout=30)
        server.ehlo()
        server.starttls()
        server.ehlo()
        server.login(self._smtp_user, self._smtp_password)
        return server

    def _send_with_retry(self, message: MIMEMultipart) -> NotificationResult:
        """
        Send email with retry logic.

        Args:
            message: Email message to send

        Returns:
            NotificationResult indicating success or failure
        """
        last_error = None

        for attempt in range(1, self._max_retries + 1):
            try:
                server = self._create_connection()
                server.send_message(message)
                server.quit()

                return NotificationResult(
                    channel="email",
                    success=True,
                    message=f"Email sent to {self._recipient_email}"
                )

            except smtplib.SMTPAuthenticationError as e:
                logger.error(f"SMTP authentication failed: {e}")
                return NotificationResult(
                    channel="email",
                    success=False,
                    message=f"Authentication failed: {e}"
                )

            except smtplib.SMTPException as e:
                last_error = e
                logger.warning(f"SMTP error (attempt {attempt}/{self._max_retries}): {e}")

                if attempt < self._max_retries:
                    delay = self._retry_delay * (2 ** (attempt - 1))  # Exponential backoff
                    logger.info(f"Retrying in {delay} seconds...")
                    time.sleep(delay)

            except Exception as e:
                last_error = e
                logger.error(f"Unexpected error sending email: {e}")
                break

        return NotificationResult(
            channel="email",
            success=False,
            message=f"Failed after {self._max_retries} attempts: {last_error}"
        )

    def send(self, alert) -> NotificationResult:
        """
        Send an alert notification email.

        Args:
            alert: Alert object to send notification for

        Returns:
            NotificationResult indicating success or failure
        """
        if not self.is_enabled():
            return NotificationResult(
                channel="email",
                success=False,
                message="Email notifications are not enabled or configured"
            )

        # Create email message
        message = MIMEMultipart("alternative")
        message["Subject"] = self._format_alert_subject(alert)
        message["From"] = self._sender_email
        message["To"] = self._recipient_email

        # Generate email content
        text_body = self._format_alert_text(alert)
        html_body = self._format_alert_html(alert)

        message.attach(MIMEText(text_body, "plain"))
        message.attach(MIMEText(html_body, "html"))

        return self._send_with_retry(message)

    def send_report(self, report_data: Dict[str, Any]) -> NotificationResult:
        """
        Send a periodic report email.

        Args:
            report_data: Dictionary containing report information

        Returns:
            NotificationResult indicating success or failure
        """
        if not self.is_enabled():
            return NotificationResult(
                channel="email",
                success=False,
                message="Email notifications are not enabled or configured"
            )

        report_type = report_data.get('report_type', 'summary')

        # Create email message
        message = MIMEMultipart("alternative")
        message["Subject"] = self._format_report_subject(report_data)
        message["From"] = self._sender_email
        message["To"] = self._recipient_email

        # Generate report content
        text_body = self._format_report_text(report_data)
        html_body = self._format_report_html(report_data)

        message.attach(MIMEText(text_body, "plain"))
        message.attach(MIMEText(html_body, "html"))

        return self._send_with_retry(message)

    # --- Formatting Methods ---

    def _format_alert_subject(self, alert) -> str:
        """Format email subject for an alert."""
        severity_emoji = {
            'critical': '🚨',
            'high': '⚠️',
            'medium': '📢',
            'low': 'ℹ️'
        }
        emoji = severity_emoji.get(alert.severity.lower(), '📢')
        device_name = alert.device_name or alert.device_ip

        return f"{emoji} IoTSentinel {alert.severity.upper()} Alert: {device_name}"

    def _format_alert_text(self, alert) -> str:
        """Format plain text alert email."""
        device_name = alert.device_name or alert.device_ip
        timestamp = alert.timestamp.strftime('%Y-%m-%d %H:%M:%S') if alert.timestamp else 'N/A'

        return f"""
IoTSentinel Security Alert
==========================

Severity: {alert.severity.upper()}
Device: {device_name} ({alert.device_ip})
Anomaly Score: {alert.anomaly_score:.4f}
Time: {timestamp}

What Happened:
{alert.explanation}

What This Means:
{self._get_severity_explanation(alert.severity)}

Recommended Actions:
{self._get_recommended_actions(alert.severity)}

---
This alert was generated by IoTSentinel Network Security Monitor.
View your dashboard for more details.
"""

    def _format_alert_html(self, alert) -> str:
        """Format HTML alert email."""
        device_name = alert.device_name or alert.device_ip
        timestamp = alert.timestamp.strftime('%Y-%m-%d %H:%M:%S') if alert.timestamp else 'N/A'
        severity_color = self._get_severity_color(alert.severity)

        return f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5;">
    <div style="max-width: 600px; margin: 0 auto; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">

        <!-- Header -->
        <div style="background: {severity_color}; padding: 20px; text-align: center;">
            <h1 style="color: white; margin: 0; font-size: 24px;">
                🛡️ IoTSentinel Alert
            </h1>
        </div>

        <!-- Severity Badge -->
        <div style="padding: 20px; text-align: center; border-bottom: 1px solid #eee;">
            <span style="display: inline-block; background: {severity_color}; color: white; padding: 8px 16px; border-radius: 20px; font-weight: bold; text-transform: uppercase;">
                {alert.severity}
            </span>
        </div>

        <!-- Alert Details -->
        <div style="padding: 20px;">
            <table style="width: 100%; border-collapse: collapse;">
                <tr>
                    <td style="padding: 10px 0; border-bottom: 1px solid #eee; color: #666;">Device</td>
                    <td style="padding: 10px 0; border-bottom: 1px solid #eee; font-weight: bold;">{device_name}</td>
                </tr>
                <tr>
                    <td style="padding: 10px 0; border-bottom: 1px solid #eee; color: #666;">IP Address</td>
                    <td style="padding: 10px 0; border-bottom: 1px solid #eee; font-family: monospace;">{alert.device_ip}</td>
                </tr>
                <tr>
                    <td style="padding: 10px 0; border-bottom: 1px solid #eee; color: #666;">Anomaly Score</td>
                    <td style="padding: 10px 0; border-bottom: 1px solid #eee; font-weight: bold;">{alert.anomaly_score:.4f}</td>
                </tr>
                <tr>
                    <td style="padding: 10px 0; border-bottom: 1px solid #eee; color: #666;">Time</td>
                    <td style="padding: 10px 0; border-bottom: 1px solid #eee;">{timestamp}</td>
                </tr>
            </table>
        </div>

        <!-- Explanation -->
        <div style="padding: 20px; background: #f8f9fa; margin: 0 20px; border-radius: 8px;">
            <h3 style="margin: 0 0 10px 0; color: #333;">📋 What Happened</h3>
            <p style="margin: 0; color: #555; line-height: 1.6;">{alert.explanation}</p>
        </div>

        <!-- What This Means -->
        <div style="padding: 20px;">
            <h3 style="margin: 0 0 10px 0; color: #333;">🔍 What This Means</h3>
            <p style="margin: 0; color: #555; line-height: 1.6;">{self._get_severity_explanation(alert.severity)}</p>
        </div>

        <!-- Recommended Actions -->
        <div style="padding: 20px; background: #fff3cd; margin: 0 20px 20px 20px; border-radius: 8px; border-left: 4px solid #ffc107;">
            <h3 style="margin: 0 0 10px 0; color: #856404;">⚡ Recommended Actions</h3>
            <p style="margin: 0; color: #856404; line-height: 1.6;">{self._get_recommended_actions(alert.severity)}</p>
        </div>

        <!-- Footer -->
        <div style="padding: 20px; background: #f8f9fa; text-align: center; color: #666; font-size: 12px;">
            <p style="margin: 0;">This alert was generated by IoTSentinel Network Security Monitor</p>
            <p style="margin: 10px 0 0 0;">View your dashboard for more details and to manage alerts</p>
        </div>

    </div>
</body>
</html>
"""

    def _format_report_subject(self, report_data: Dict[str, Any]) -> str:
        """Format email subject for a report."""
        report_type = report_data.get('report_type', 'summary')
        period = report_data.get('period', '')

        if report_type == 'weekly':
            return f"📊 IoTSentinel Weekly Security Report - {period}"
        elif report_type == 'monthly':
            return f"📈 IoTSentinel Monthly Security Report - {period}"
        else:
            return f"📋 IoTSentinel Security Report - {period}"

    def _format_report_text(self, report_data: Dict[str, Any]) -> str:
        """Format plain text report email."""
        summary = report_data.get('summary', {})
        period = report_data.get('period', 'Unknown Period')
        report_type = report_data.get('report_type', 'summary').title()

        by_severity = summary.get('by_severity', {})
        by_device = summary.get('by_device', {})

        device_list = '\n'.join([f"  - {ip}: {count} alerts" for ip, count in by_device.items()]) or '  No device alerts'

        return f"""
IoTSentinel {report_type} Security Report
{'=' * 50}

Period: {period}

ALERT SUMMARY
-------------
Total Alerts: {summary.get('total', 0)}

By Severity:
  - Critical: {by_severity.get('critical', 0)}
  - High: {by_severity.get('high', 0)}
  - Medium: {by_severity.get('medium', 0)}
  - Low: {by_severity.get('low', 0)}

Acknowledged: {summary.get('acknowledged', 0)}
Unacknowledged: {summary.get('unacknowledged', 0)}

ALERTS BY DEVICE
----------------
{device_list}

NETWORK STATISTICS
------------------
Total Devices: {report_data.get('network_stats', {}).get('total_devices', 'N/A')}
Total Connections: {report_data.get('network_stats', {}).get('total_connections', 'N/A')}
Data Transferred: {report_data.get('network_stats', {}).get('data_transferred', 'N/A')}

---
This report was generated by IoTSentinel Network Security Monitor.
"""

    def _format_report_html(self, report_data: Dict[str, Any]) -> str:
        """Format HTML report email."""
        summary = report_data.get('summary', {})
        period = report_data.get('period', 'Unknown Period')
        report_type = report_data.get('report_type', 'summary').title()

        by_severity = summary.get('by_severity', {})
        by_device = summary.get('by_device', {})
        network_stats = report_data.get('network_stats', {})
        top_alerts = report_data.get('top_alerts', [])

        # Generate device rows
        device_rows = ""
        for ip, count in by_device.items():
            device_rows += f"""
            <tr>
                <td style="padding: 8px; border-bottom: 1px solid #eee; font-family: monospace;">{ip}</td>
                <td style="padding: 8px; border-bottom: 1px solid #eee; text-align: center;">{count}</td>
            </tr>
            """
        if not device_rows:
            device_rows = '<tr><td colspan="2" style="padding: 8px; text-align: center; color: #666;">No alerts in this period</td></tr>'

        # Generate top alerts rows
        alert_rows = ""
        for alert in top_alerts[:5]:
            severity_color = self._get_severity_color(alert.get('severity', 'low'))
            alert_rows += f"""
            <tr>
                <td style="padding: 8px; border-bottom: 1px solid #eee;">
                    <span style="display: inline-block; background: {severity_color}; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px;">{alert.get('severity', 'N/A').upper()}</span>
                </td>
                <td style="padding: 8px; border-bottom: 1px solid #eee; font-family: monospace; font-size: 13px;">{alert.get('device_ip', 'N/A')}</td>
                <td style="padding: 8px; border-bottom: 1px solid #eee; font-size: 13px;">{alert.get('explanation', 'N/A')[:50]}...</td>
            </tr>
            """
        if not alert_rows:
            alert_rows = '<tr><td colspan="3" style="padding: 8px; text-align: center; color: #666;">No alerts to display</td></tr>'

        return f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5;">
    <div style="max-width: 700px; margin: 0 auto; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">

        <!-- Header -->
        <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; text-align: center;">
            <h1 style="color: white; margin: 0; font-size: 28px;">📊 IoTSentinel</h1>
            <p style="color: rgba(255,255,255,0.9); margin: 10px 0 0 0; font-size: 16px;">{report_type} Security Report</p>
            <p style="color: rgba(255,255,255,0.7); margin: 5px 0 0 0; font-size: 14px;">{period}</p>
        </div>

        <!-- Summary Stats -->
        <div style="display: flex; padding: 20px; background: #f8f9fa; justify-content: space-around; flex-wrap: wrap;">
            <div style="text-align: center; padding: 10px;">
                <div style="font-size: 32px; font-weight: bold; color: #333;">{summary.get('total', 0)}</div>
                <div style="font-size: 12px; color: #666; text-transform: uppercase;">Total Alerts</div>
            </div>
            <div style="text-align: center; padding: 10px;">
                <div style="font-size: 32px; font-weight: bold; color: #dc3545;">{by_severity.get('critical', 0)}</div>
                <div style="font-size: 12px; color: #666; text-transform: uppercase;">Critical</div>
            </div>
            <div style="text-align: center; padding: 10px;">
                <div style="font-size: 32px; font-weight: bold; color: #fd7e14;">{by_severity.get('high', 0)}</div>
                <div style="font-size: 12px; color: #666; text-transform: uppercase;">High</div>
            </div>
            <div style="text-align: center; padding: 10px;">
                <div style="font-size: 32px; font-weight: bold; color: #28a745;">{summary.get('acknowledged', 0)}</div>
                <div style="font-size: 12px; color: #666; text-transform: uppercase;">Acknowledged</div>
            </div>
        </div>

        <!-- Alerts by Device -->
        <div style="padding: 20px;">
            <h2 style="margin: 0 0 15px 0; color: #333; font-size: 18px;">📱 Alerts by Device</h2>
            <table style="width: 100%; border-collapse: collapse;">
                <thead>
                    <tr style="background: #f8f9fa;">
                        <th style="padding: 10px; text-align: left; border-bottom: 2px solid #dee2e6;">Device IP</th>
                        <th style="padding: 10px; text-align: center; border-bottom: 2px solid #dee2e6;">Alert Count</th>
                    </tr>
                </thead>
                <tbody>
                    {device_rows}
                </tbody>
            </table>
        </div>

        <!-- Recent Critical Alerts -->
        <div style="padding: 20px; background: #f8f9fa;">
            <h2 style="margin: 0 0 15px 0; color: #333; font-size: 18px;">🚨 Recent High-Priority Alerts</h2>
            <table style="width: 100%; border-collapse: collapse; background: white; border-radius: 4px;">
                <thead>
                    <tr>
                        <th style="padding: 10px; text-align: left; border-bottom: 2px solid #dee2e6;">Severity</th>
                        <th style="padding: 10px; text-align: left; border-bottom: 2px solid #dee2e6;">Device</th>
                        <th style="padding: 10px; text-align: left; border-bottom: 2px solid #dee2e6;">Description</th>
                    </tr>
                </thead>
                <tbody>
                    {alert_rows}
                </tbody>
            </table>
        </div>

        <!-- Network Stats -->
        <div style="padding: 20px;">
            <h2 style="margin: 0 0 15px 0; color: #333; font-size: 18px;">📈 Network Statistics</h2>
            <div style="display: flex; flex-wrap: wrap; gap: 15px;">
                <div style="flex: 1; min-width: 150px; background: #e3f2fd; padding: 15px; border-radius: 8px; text-align: center;">
                    <div style="font-size: 24px; font-weight: bold; color: #1976d2;">{network_stats.get('total_devices', 'N/A')}</div>
                    <div style="font-size: 12px; color: #666;">Active Devices</div>
                </div>
                <div style="flex: 1; min-width: 150px; background: #e8f5e9; padding: 15px; border-radius: 8px; text-align: center;">
                    <div style="font-size: 24px; font-weight: bold; color: #388e3c;">{network_stats.get('total_connections', 'N/A')}</div>
                    <div style="font-size: 12px; color: #666;">Connections</div>
                </div>
                <div style="flex: 1; min-width: 150px; background: #fff3e0; padding: 15px; border-radius: 8px; text-align: center;">
                    <div style="font-size: 24px; font-weight: bold; color: #f57c00;">{network_stats.get('data_transferred', 'N/A')}</div>
                    <div style="font-size: 12px; color: #666;">Data Transferred</div>
                </div>
            </div>
        </div>

        <!-- Footer -->
        <div style="padding: 20px; background: #333; text-align: center; color: #999; font-size: 12px;">
            <p style="margin: 0;">Generated by IoTSentinel Network Security Monitor</p>
            <p style="margin: 10px 0 0 0;">View your dashboard for detailed analysis</p>
        </div>

    </div>
</body>
</html>
"""

    def _get_severity_color(self, severity: str) -> str:
        """Get color for severity level."""
        colors = {
            'critical': '#dc3545',
            'high': '#fd7e14',
            'medium': '#ffc107',
            'low': '#17a2b8'
        }
        return colors.get(severity.lower(), '#6c757d')

    def _get_severity_explanation(self, severity: str) -> str:
        """Get educational explanation for severity level."""
        explanations = {
            'critical': "This is a severe anomaly that requires immediate attention. The detected behavior significantly deviates from normal patterns and may indicate an active security threat, such as a compromised device or data exfiltration attempt.",
            'high': "This anomaly shows behavior that is notably different from your network's baseline. While not necessarily malicious, it warrants investigation to ensure your network security is not compromised.",
            'medium': "This anomaly represents moderate deviation from normal patterns. It could be caused by software updates, new device behavior, or legitimate changes in network usage. Review when convenient.",
            'low': "This is a minor anomaly that slightly deviates from normal patterns. It's likely benign but has been logged for your awareness and historical tracking."
        }
        return explanations.get(severity.lower(), "Unknown severity level.")

    def _get_recommended_actions(self, severity: str) -> str:
        """Get recommended actions based on severity."""
        actions = {
            'critical': "1. Check if the affected device is behaving normally. 2. Review the device's recent activity on your dashboard. 3. Consider temporarily isolating the device if suspicious. 4. Check for unauthorized access or malware.",
            'high': "1. Review the device's activity on your IoTSentinel dashboard. 2. Verify the device is running expected software. 3. Check if any new applications were installed. 4. Monitor for recurring alerts.",
            'medium': "1. Review the alert details on your dashboard when convenient. 2. Check if the device recently updated or changed behavior. 3. Mark as acknowledged if expected behavior.",
            'low': "1. Review at your convenience through the dashboard. 2. No immediate action required. 3. Consider marking as acknowledged to clear the alert."
        }
        return actions.get(severity.lower(), "Review the alert on your dashboard.")
