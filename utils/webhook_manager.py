#!/usr/bin/env python3
"""
Webhook Integration Manager for IoTSentinel

Provides webhook delivery for reports and alerts to external services like:
- Slack
- Microsoft Teams
- Discord
- Custom HTTP webhooks
"""

import logging
import json
import requests
from typing import Dict, Any, Optional, List
from datetime import datetime
from pathlib import Path
import base64

logger = logging.getLogger(__name__)


class WebhookManager:
    """
    Manages webhook integrations for report delivery.

    Supports multiple webhook types and formats.
    """

    def __init__(self):
        """Initialize webhook manager."""
        self.webhooks: Dict[str, Dict[str, Any]] = {}
        self.timeout = 30  # seconds

    def register_webhook(
        self,
        name: str,
        webhook_type: str,
        url: str,
        enabled: bool = True,
        **kwargs
    ):
        """
        Register a webhook endpoint.

        Args:
            name: Unique webhook name
            webhook_type: Type (slack, teams, discord, generic)
            url: Webhook URL
            enabled: Whether webhook is enabled
            **kwargs: Additional webhook-specific configuration
        """
        self.webhooks[name] = {
            'type': webhook_type,
            'url': url,
            'enabled': enabled,
            'config': kwargs
        }
        logger.info(f"Registered webhook: {name} ({webhook_type})")

    def remove_webhook(self, name: str):
        """
        Remove a webhook endpoint.

        Args:
            name: Webhook name to remove
        """
        if name in self.webhooks:
            del self.webhooks[name]
            logger.info(f"Removed webhook: {name}")

    def send_report_notification(
        self,
        report_data: Dict[str, Any],
        webhook_names: Optional[List[str]] = None,
        include_attachment: bool = False
    ) -> Dict[str, bool]:
        """
        Send report notification to webhooks.

        Args:
            report_data: Report data with content, filename, metadata
            webhook_names: List of webhook names (None = all enabled)
            include_attachment: Whether to include report as attachment

        Returns:
            Dictionary mapping webhook names to success status
        """
        results = {}

        # Determine which webhooks to use
        if webhook_names:
            targets = {k: v for k, v in self.webhooks.items()
                      if k in webhook_names and v.get('enabled', True)}
        else:
            targets = {k: v for k, v in self.webhooks.items()
                      if v.get('enabled', True)}

        # Send to each webhook
        for name, webhook in targets.items():
            try:
                success = self._send_to_webhook(webhook, report_data, include_attachment)
                results[name] = success

            except Exception as e:
                logger.error(f"Error sending to webhook {name}: {e}")
                results[name] = False

        return results

    def _send_to_webhook(
        self,
        webhook: Dict[str, Any],
        report_data: Dict[str, Any],
        include_attachment: bool
    ) -> bool:
        """
        Send data to a specific webhook.

        Args:
            webhook: Webhook configuration
            report_data: Report data
            include_attachment: Include report attachment

        Returns:
            True if successful
        """
        webhook_type = webhook['type']

        if webhook_type == 'slack':
            return self._send_to_slack(webhook, report_data, include_attachment)
        elif webhook_type == 'teams':
            return self._send_to_teams(webhook, report_data, include_attachment)
        elif webhook_type == 'discord':
            return self._send_to_discord(webhook, report_data, include_attachment)
        elif webhook_type == 'generic':
            return self._send_to_generic(webhook, report_data, include_attachment)
        else:
            logger.warning(f"Unknown webhook type: {webhook_type}")
            return False

    def _send_to_slack(
        self,
        webhook: Dict[str, Any],
        report_data: Dict[str, Any],
        include_attachment: bool
    ) -> bool:
        """Send notification to Slack webhook."""
        try:
            # Build Slack message
            filename = report_data.get('filename', 'report')
            template_name = report_data.get('template_name', 'Unknown Template')
            format_type = report_data.get('format', 'PDF').upper()

            message = {
                "text": f"*IoTSentinel Report Generated*",
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": "IoTSentinel Security Report"
                        }
                    },
                    {
                        "type": "section",
                        "fields": [
                            {
                                "type": "mrkdwn",
                                "text": f"*Report Type:*\n{template_name}"
                            },
                            {
                                "type": "mrkdwn",
                                "text": f"*Format:*\n{format_type}"
                            },
                            {
                                "type": "mrkdwn",
                                "text": f"*Generated:*\n{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                            },
                            {
                                "type": "mrkdwn",
                                "text": f"*Filename:*\n{filename}"
                            }
                        ]
                    }
                ]
            }

            # Add report summary if available
            if 'summary' in report_data:
                message["blocks"].append({
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Summary:*\n{report_data['summary']}"
                    }
                })

            response = requests.post(
                webhook['url'],
                json=message,
                timeout=self.timeout
            )

            if response.status_code == 200:
                logger.info("Report notification sent to Slack")
                return True
            else:
                logger.error(f"Slack webhook failed: {response.status_code} - {response.text}")
                return False

        except Exception as e:
            logger.error(f"Error sending to Slack: {e}")
            return False

    def _send_to_teams(
        self,
        webhook: Dict[str, Any],
        report_data: Dict[str, Any],
        include_attachment: bool
    ) -> bool:
        """Send notification to Microsoft Teams webhook."""
        try:
            filename = report_data.get('filename', 'report')
            template_name = report_data.get('template_name', 'Unknown Template')
            format_type = report_data.get('format', 'PDF').upper()

            # Build Teams Adaptive Card
            message = {
                "@type": "MessageCard",
                "@context": "https://schema.org/extensions",
                "summary": "IoTSentinel Report Generated",
                "themeColor": "0072C6",
                "title": "IoTSentinel Security Report",
                "sections": [
                    {
                        "activityTitle": "New Report Available",
                        "activitySubtitle": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        "facts": [
                            {
                                "name": "Report Type:",
                                "value": template_name
                            },
                            {
                                "name": "Format:",
                                "value": format_type
                            },
                            {
                                "name": "Filename:",
                                "value": filename
                            }
                        ]
                    }
                ]
            }

            # Add summary if available
            if 'summary' in report_data:
                message["sections"].append({
                    "text": report_data['summary']
                })

            response = requests.post(
                webhook['url'],
                json=message,
                timeout=self.timeout
            )

            if response.status_code == 200:
                logger.info("Report notification sent to Microsoft Teams")
                return True
            else:
                logger.error(f"Teams webhook failed: {response.status_code} - {response.text}")
                return False

        except Exception as e:
            logger.error(f"Error sending to Teams: {e}")
            return False

    def _send_to_discord(
        self,
        webhook: Dict[str, Any],
        report_data: Dict[str, Any],
        include_attachment: bool
    ) -> bool:
        """Send notification to Discord webhook."""
        try:
            filename = report_data.get('filename', 'report')
            template_name = report_data.get('template_name', 'Unknown Template')
            format_type = report_data.get('format', 'PDF').upper()

            # Build Discord embed
            message = {
                "embeds": [
                    {
                        "title": "IoTSentinel Security Report",
                        "description": "New security report generated",
                        "color": 3447003,  # Blue color
                        "fields": [
                            {
                                "name": "Report Type",
                                "value": template_name,
                                "inline": True
                            },
                            {
                                "name": "Format",
                                "value": format_type,
                                "inline": True
                            },
                            {
                                "name": "Filename",
                                "value": filename,
                                "inline": False
                            }
                        ],
                        "timestamp": datetime.now().isoformat(),
                        "footer": {
                            "text": "IoTSentinel"
                        }
                    }
                ]
            }

            # Add summary if available
            if 'summary' in report_data:
                message["embeds"][0]["fields"].append({
                    "name": "Summary",
                    "value": report_data['summary'][:1024],  # Discord limit
                    "inline": False
                })

            response = requests.post(
                webhook['url'],
                json=message,
                timeout=self.timeout
            )

            if response.status_code in [200, 204]:
                logger.info("Report notification sent to Discord")
                return True
            else:
                logger.error(f"Discord webhook failed: {response.status_code} - {response.text}")
                return False

        except Exception as e:
            logger.error(f"Error sending to Discord: {e}")
            return False

    def _send_to_generic(
        self,
        webhook: Dict[str, Any],
        report_data: Dict[str, Any],
        include_attachment: bool
    ) -> bool:
        """Send notification to generic HTTP webhook."""
        try:
            # Build generic payload
            payload = {
                "event": "report_generated",
                "timestamp": datetime.now().isoformat(),
                "report": {
                    "filename": report_data.get('filename', 'report'),
                    "template": report_data.get('template_name', 'Unknown'),
                    "format": report_data.get('format', 'PDF'),
                    "generated_at": report_data.get('generated_at', datetime.now().isoformat())
                }
            }

            # Add content as base64 if requested
            if include_attachment and 'content' in report_data:
                content = report_data['content']
                if isinstance(content, bytes):
                    payload['report']['content_base64'] = base64.b64encode(content).decode('utf-8')
                elif isinstance(content, str):
                    payload['report']['content_base64'] = base64.b64encode(content.encode('utf-8')).decode('utf-8')

            # Send POST request
            headers = webhook.get('config', {}).get('headers', {})
            headers.setdefault('Content-Type', 'application/json')

            response = requests.post(
                webhook['url'],
                json=payload,
                headers=headers,
                timeout=self.timeout
            )

            if response.status_code in range(200, 300):
                logger.info(f"Report notification sent to generic webhook: {response.status_code}")
                return True
            else:
                logger.error(f"Generic webhook failed: {response.status_code} - {response.text}")
                return False

        except Exception as e:
            logger.error(f"Error sending to generic webhook: {e}")
            return False

    def test_webhook(self, name: str) -> bool:
        """
        Test a webhook connection.

        Args:
            name: Webhook name to test

        Returns:
            True if test successful
        """
        if name not in self.webhooks:
            logger.error(f"Webhook not found: {name}")
            return False

        test_data = {
            'filename': 'test_report.pdf',
            'template_name': 'Test Report',
            'format': 'PDF',
            'generated_at': datetime.now().isoformat(),
            'summary': 'This is a test notification from IoTSentinel webhook integration.'
        }

        result = self.send_report_notification(
            report_data=test_data,
            webhook_names=[name],
            include_attachment=False
        )

        return result.get(name, False)

    def list_webhooks(self) -> List[Dict[str, Any]]:
        """
        List all registered webhooks.

        Returns:
            List of webhook configurations
        """
        return [
            {
                'name': name,
                'type': config['type'],
                'url': config['url'],
                'enabled': config.get('enabled', True)
            }
            for name, config in self.webhooks.items()
        ]

    def get_webhook_stats(self) -> Dict[str, Any]:
        """
        Get webhook statistics.

        Returns:
            Dictionary with webhook stats
        """
        total = len(self.webhooks)
        enabled = sum(1 for w in self.webhooks.values() if w.get('enabled', True))
        by_type = {}

        for webhook in self.webhooks.values():
            webhook_type = webhook['type']
            by_type[webhook_type] = by_type.get(webhook_type, 0) + 1

        return {
            'total_webhooks': total,
            'enabled_webhooks': enabled,
            'disabled_webhooks': total - enabled,
            'by_type': by_type
        }


# Global webhook manager instance
_webhook_manager = None


def get_webhook_manager() -> WebhookManager:
    """
    Get global webhook manager instance.

    Returns:
        WebhookManager instance
    """
    global _webhook_manager
    if _webhook_manager is None:
        _webhook_manager = WebhookManager()
    return _webhook_manager
