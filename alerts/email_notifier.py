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
from email.mime.base import MIMEBase
from email import encoders
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List, Tuple

from .notification_dispatcher import NotificationHandler, NotificationResult

logger = logging.getLogger(__name__)


class EmailNotifier(NotificationHandler):
    """
    Email notification handler for IoTSentinel.

    Sends formatted HTML emails for:
    - Individual critical/high severity alerts
    - Weekly summary reports
    - Monthly trend reports
    - PDF/Excel report attachments
    - Daily digest emails
    - Scheduled report delivery
    """

    def __init__(self, config, db_path: str = None):
        """
        Initialize the email notifier.

        Args:
            config: Configuration manager instance
            db_path: Path to database for report generation (optional)
        """
        self.config = config
        self.db_path = db_path

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

        # Initialize report components for attachments
        self.report_builder = None
        self.template_manager = None
        if db_path:
            try:
                from utils.report_builder import ReportBuilder
                from utils.report_templates import ReportTemplateManager
                self.report_builder = ReportBuilder(db_path)
                self.template_manager = ReportTemplateManager()
                logger.info("Email notifier initialized with report generation support")
            except Exception as e:
                logger.warning(f"Could not initialize report components: {e}")

        # Log initialization status with proper configuration check
        if self._enabled and self.is_enabled():
            logger.info("EmailNotifier initialized and fully configured")
        elif self._enabled:
            logger.warning("EmailNotifier enabled but SMTP credentials not configured")
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

    # ============================================================================
    # ADVANCED EMAIL FEATURES - Attachments & Scheduled Reports
    # ============================================================================

    def send_with_attachment(
        self,
        subject: str,
        body_html: str,
        body_text: str,
        attachments: List[Tuple[str, bytes, str]] = None,
        recipient: str = None
    ) -> NotificationResult:
        """
        Send email with one or more attachments.

        Args:
            subject: Email subject
            body_html: HTML body content
            body_text: Plain text body content
            attachments: List of (filename, content_bytes, mime_type) tuples
            recipient: Override recipient email (optional)

        Returns:
            NotificationResult with success/failure status
        """
        if not self.is_enabled():
            return NotificationResult(
                success=False,
                channel="email",
                message="Email notifications not configured"
            )

        try:
            # Create message
            message = MIMEMultipart('alternative')
            message['Subject'] = subject
            message['From'] = self._sender_email
            message['To'] = recipient or self._recipient_email
            message['Date'] = datetime.now().strftime("%a, %d %b %Y %H:%M:%S %z")

            # Add text and HTML parts
            text_part = MIMEText(body_text, 'plain')
            html_part = MIMEText(body_html, 'html')
            message.attach(text_part)
            message.attach(html_part)

            # Add attachments
            if attachments:
                for filename, content, mime_type in attachments:
                    # Create attachment part
                    part = MIMEBase('application', mime_type)
                    part.set_payload(content)
                    encoders.encode_base64(part)
                    part.add_header(
                        'Content-Disposition',
                        f'attachment; filename= {filename}'
                    )
                    message.attach(part)
                    logger.debug(f"Attached {filename} ({len(content)} bytes)")

            # Send with retry
            return self._send_with_retry(message)

        except Exception as e:
            logger.error(f"Error sending email with attachments: {e}")
            return NotificationResult(
                success=False,
                channel="email",
                message=f"Failed to send email: {str(e)}"
            )

    def send_report_with_attachment(
        self,
        template_name: str,
        format: str = 'pdf',
        days: int = 7,
        recipient: str = None
    ) -> NotificationResult:
        """
        Generate and send a report as an email attachment.

        Args:
            template_name: Report template to use
            format: Report format ('pdf' or 'excel')
            days: Number of days to include in report
            recipient: Override recipient email

        Returns:
            NotificationResult with success/failure status
        """
        if not self.report_builder or not self.template_manager:
            return NotificationResult(
                success=False,
                channel="email",
                message="Report generation not configured"
            )

        try:
            # Get template display name
            template_names = {
                'executive_summary': 'Executive Summary',
                'security_audit': 'Security Audit',
                'network_activity': 'Network Activity',
                'device_inventory': 'Device Inventory',
                'threat_analysis': 'Threat Analysis'
            }
            display_name = template_names.get(template_name, template_name)

            # Generate report
            logger.info(f"Generating {format} report: {template_name}")
            report = self.report_builder.build_report(
                template_name=template_name,
                format=format,
                parameters={'days': days}
            )

            if not report:
                return NotificationResult(
                    success=False,
                    channel="email",
                    message="Failed to generate report"
                )

            # Prepare email content
            subject = f"IoTSentinel {display_name} Report"

            body_text = f"""
IoTSentinel Security Report

Report Type: {display_name}
Period: Last {days} days
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

The detailed report is attached as {report['filename']}.

---
IoTSentinel - Network Security Monitoring
"""

            body_html = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                   color: white; padding: 30px; text-align: center; }}
        .content {{ padding: 30px; }}
        .info-box {{ background: #f8f9fa; border-left: 4px solid #667eea;
                     padding: 15px; margin: 20px 0; }}
        .footer {{ background: #f8f9fa; padding: 20px; text-align: center;
                   font-size: 12px; color: #666; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ IoTSentinel Security Report</h1>
        <p style="margin: 0; opacity: 0.9;">Network Security Monitoring</p>
    </div>
    <div class="content">
        <h2>📊 {display_name}</h2>
        <div class="info-box">
            <p><strong>Report Period:</strong> Last {days} days</p>
            <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p><strong>Format:</strong> {format.upper()}</p>
        </div>
        <p>The detailed security report has been attached to this email as
           <strong>{report['filename']}</strong>.</p>
        <p>This report provides comprehensive insights into your network security status,
           including alerts, device activity, and potential threats.</p>
    </div>
    <div class="footer">
        <p>IoTSentinel - Automated Security Monitoring</p>
        <p>This is an automated email. Please do not reply.</p>
    </div>
</body>
</html>
"""

            # Determine MIME type
            mime_types = {
                'pdf': 'pdf',
                'excel': 'vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                'json': 'json',
                'html': 'html'
            }
            mime_type = mime_types.get(format, 'octet-stream')

            # Send email with attachment
            attachments = [(report['filename'], report['content'], mime_type)]

            return self.send_with_attachment(
                subject=subject,
                body_html=body_html,
                body_text=body_text,
                attachments=attachments,
                recipient=recipient
            )

        except Exception as e:
            logger.error(f"Error sending report email: {e}")
            return NotificationResult(
                success=False,
                channel="email",
                message=f"Failed to send report: {str(e)}"
            )

    def send_daily_digest(
        self,
        recipient: str = None
    ) -> NotificationResult:
        """
        Send daily security digest email with summary and trends.

        Args:
            recipient: Override recipient email

        Returns:
            NotificationResult with success/failure status
        """
        if not self.report_builder:
            return NotificationResult(
                success=False,
                channel="email",
                message="Report generation not configured for digests"
            )

        try:
            # Generate executive summary report for last 24 hours
            logger.info("Generating daily digest")
            report = self.report_builder.build_report(
                template_name='executive_summary',
                format='pdf',
                parameters={'days': 1}
            )

            if not report:
                logger.warning("Could not generate daily digest report")
                return self._send_digest_without_attachment(recipient)

            # Prepare email
            subject = f"IoTSentinel Daily Digest - {datetime.now().strftime('%Y-%m-%d')}"

            body_text = f"""
IoTSentinel Daily Security Digest

Date: {datetime.now().strftime('%Y-%m-%d')}

This email contains your daily security summary for the past 24 hours.

The detailed executive summary report is attached.

---
IoTSentinel - Network Security Monitoring
"""

            body_html = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                   color: white; padding: 30px; text-align: center; }}
        .content {{ padding: 30px; }}
        .highlight-box {{ background: #fff3cd; border: 1px solid #ffc107;
                         padding: 15px; margin: 20px 0; border-radius: 5px; }}
        .footer {{ background: #f8f9fa; padding: 20px; text-align: center;
                   font-size: 12px; color: #666; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>📬 Daily Security Digest</h1>
        <p style="margin: 0; opacity: 0.9;">{datetime.now().strftime('%A, %B %d, %Y')}</p>
    </div>
    <div class="content">
        <h2>🛡️ 24-Hour Security Summary</h2>
        <p>Your IoTSentinel system has monitored your network for the past 24 hours.</p>

        <div class="highlight-box">
            <p><strong>📊 Detailed Report Attached</strong></p>
            <p>A comprehensive executive summary report has been attached to this email
               with detailed metrics, trends, and insights.</p>
        </div>

        <h3>What's Included:</h3>
        <ul>
            <li>Security alerts and trends</li>
            <li>Network activity patterns</li>
            <li>Device status updates</li>
            <li>Top security concerns</li>
        </ul>
    </div>
    <div class="footer">
        <p>IoTSentinel - Automated Security Monitoring</p>
        <p>Delivered daily at {datetime.now().strftime('%H:%M')}</p>
    </div>
</body>
</html>
"""

            # Send with attachment
            attachments = [(report['filename'], report['content'], 'pdf')]

            return self.send_with_attachment(
                subject=subject,
                body_html=body_html,
                body_text=body_text,
                attachments=attachments,
                recipient=recipient
            )

        except Exception as e:
            logger.error(f"Error sending daily digest: {e}")
            return NotificationResult(
                success=False,
                channel="email",
                message=f"Failed to send digest: {str(e)}"
            )

    def _send_digest_without_attachment(self, recipient: str = None) -> NotificationResult:
        """Send a basic digest email without report attachment."""
        subject = f"IoTSentinel Daily Digest - {datetime.now().strftime('%Y-%m-%d')}"

        body_text = """
IoTSentinel Daily Security Digest

Your network monitoring is active.

Note: Detailed report could not be generated. Check system logs for details.

---
IoTSentinel - Network Security Monitoring
"""

        body_html = """
<!DOCTYPE html>
<html>
<body>
    <h2>IoTSentinel Daily Digest</h2>
    <p>Your network monitoring is active.</p>
    <p><em>Note: Detailed report could not be generated.</em></p>
</body>
</html>
"""

        message = MIMEMultipart('alternative')
        message['Subject'] = subject
        message['From'] = self._sender_email
        message['To'] = recipient or self._recipient_email
        message['Date'] = datetime.now().strftime("%a, %d %b %Y %H:%M:%S %z")

        message.attach(MIMEText(body_text, 'plain'))
        message.attach(MIMEText(body_html, 'html'))

        return self._send_with_retry(message)
    def send_verification_code_email(self, email: str, code: str, base_url: str = "http://localhost:8050") -> NotificationResult:
        """
        Send email verification code to user.

        Args:
            email: Recipient email address
            code: 6-digit verification code
            base_url: Base URL for verification link (default: http://localhost:8050)

        Returns:
            NotificationResult indicating success or failure
        """
        if not self.is_enabled():
            return NotificationResult(
                channel="email",
                success=False,
                message="Email notifications are not enabled or configured"
            )

        subject = "IoTSentinel - Email Verification Code"

        # Plain text version
        verification_link = f"{base_url}/verify/{code}"
        body_text = f"""
IoTSentinel Email Verification

Your verification code is: {code}

Or click this link to verify your email:
{verification_link}

This code will expire in 10 minutes.

If you didn't request this code, please ignore this email.

---
IoTSentinel - Network Security Monitoring
"""

        # HTML version
        body_html = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                   color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }}
        .content {{ background: white; padding: 30px; border: 1px solid #e0e0e0; }}
        .code-box {{ background: #f8f9fa; border: 2px dashed #60a5fa;
                     padding: 20px; margin: 20px 0; text-align: center;
                     border-radius: 8px; }}
        .code {{ font-size: 32px; font-weight: bold; letter-spacing: 8px;
                 color: #60a5fa; font-family: 'Courier New', monospace; }}
        .footer {{ background: #f8f9fa; padding: 20px; text-align: center;
                   font-size: 12px; color: #666; border-radius: 0 0 10px 10px; }}
        .warning {{ color: #856404; background: #fff3cd; padding: 10px;
                    border-radius: 5px; margin-top: 20px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 Email Verification</h1>
            <p style="margin: 0; opacity: 0.9;">IoTSentinel Security</p>
        </div>
        <div class="content">
            <h2>Verify Your Email Address</h2>
            <p>Thank you for registering with IoTSentinel. To complete your registration,
               please use the verification code below:</p>

            <div class="code-box">
                <div class="code">{code}</div>
            </div>

            <p>Enter this code in the registration form to verify your email address.</p>

            <p style="text-align: center; margin: 20px 0;">
                <strong>Or click the button below to auto-fill the code:</strong>
            </p>

            <p style="text-align: center;">
                <a href="{base_url}/verify/{code}"
                   style="display: inline-block; padding: 12px 30px; background: #667eea;
                          color: white; text-decoration: none; border-radius: 5px;
                          font-weight: bold;">Go to Verification Page</a>
            </p>

            <p style="text-align: center; font-size: 13px; color: #888; margin-top: 10px;">
                (You will still need to enter the code shown above)
            </p>

            <div class="warning">
                <strong>⏰ Important:</strong> This code will expire in 10 minutes.
            </div>

            <p style="margin-top: 20px; font-size: 14px; color: #666;">
                If you didn't request this code, please ignore this email.
                Your account will not be created without verification.
            </p>
        </div>
        <div class="footer">
            <p>IoTSentinel - Network Security Monitoring</p>
            <p>This is an automated message, please do not reply.</p>
        </div>
    </div>
</body>
</html>
"""

        # Create email message
        message = MIMEMultipart("alternative")
        message["Subject"] = subject
        message["From"] = self._sender_email
        message["To"] = email
        message['Date'] = datetime.now().strftime("%a, %d %b %Y %H:%M:%S %z")

        message.attach(MIMEText(body_text, "plain"))
        message.attach(MIMEText(body_html, "html"))

        return self._send_with_retry(message)
