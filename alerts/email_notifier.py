#!/usr/bin/env python3
"""
Email Notifier for IoTSentinel

Sends email alerts and reports.
"""

import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from config.config_manager import config

logger = logging.getLogger(__name__)


def send_email(subject: str, html_body: str, text_body: str = ""):
    """
    Send a formatted email.

    Args:
        subject: The subject of the email.
        html_body: The HTML content of the email.
        text_body: Optional plain text version of the content.
    """
    if not config.get("email", "enabled", default=False):
        return

    smtp_host = config.get("email", "smtp_host")
    smtp_port = config.get("email", "smtp_port")
    smtp_user = config.get("email", "smtp_user")
    smtp_password = config.get("email", "smtp_password")
    sender_email = config.get("email", "sender_email")
    recipient_email = config.get("email", "recipient_email")

    if not all(
        [smtp_host, smtp_port, smtp_user, smtp_password, sender_email, recipient_email]
    ):
        logger.warning("Email configuration is incomplete. Skipping email notification.")
        return

    # Create the email message
    message = MIMEMultipart("alternative")
    message["Subject"] = subject
    message["From"] = sender_email
    message["To"] = recipient_email

    # Attach parts
    if text_body:
        message.attach(MIMEText(text_body, "plain"))
    message.attach(MIMEText(html_body, "html"))

    # Send the email
    try:
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_password)
            server.sendmail(sender_email, recipient_email, message.as_string())
            logger.info("Sent email to %s with subject: %s", recipient_email, subject)
    except smtplib.SMTPException as e:
        logger.error("Failed to send email: %s", e)


def send_alert_email(alert_details: dict):
    """
    Send a formatted email alert.

    Args:
        alert_details: A dictionary containing alert information.
    """
    subject = f"IoTSentinel Critical Alert: {alert_details.get('device_ip')}"

    html_body = f"""
    <html>
    <body>
        <h2 style="color: #d9534f;">IoTSentinel Critical Alert</h2>
        <p><strong>Device:</strong> {alert_details.get('device_ip')}</p>
        <p><strong>Severity:</strong> {alert_details.get('severity')}</p>
        <p><strong>Anomaly Score:</strong> {alert_details.get('anomaly_score'):.4f}</p>
        <p><strong>Explanation:</strong> {alert_details.get('explanation')}</p>
        <p><strong>Timestamp:</strong> {alert_details.get('timestamp')}</p>
    </body>
    </html>
    """

    text_body = f"""
    IoTSentinel Critical Alert
    ==========================
    Device: {alert_details.get('device_ip')}
    Severity: {alert_details.get('severity')}
    Score: {alert_details.get('anomaly_score'):.4f}
    Explanation: {alert_details.get('explanation')}
    Timestamp: {alert_details.get('timestamp')}
    """

    send_email(subject, html_body, text_body)
