#!/usr/bin/env python3
"""
Integration System for IoTSentinel

Manages 28 free-tier external API integrations across 5 categories:
- Threat Intelligence (8): AbuseIPDB, VirusTotal, OTX, GreyNoise, IPQualityScore, ThreatFox, Shodan, NVD
- Geolocation (3): IPinfo, IP-API, IPGeolocation
- Notifications (5): Slack, Discord, Telegram, Pushover, Email (SMTP)
- Ticketing (4): GitHub Issues, GitLab Issues, Trello, Linear
- Webhooks (4): Custom webhook, Zapier, IFTTT, n8n

All integrations use encrypted credential storage and have real-time health checks.

Usage:
    from alerts.integration_system import IntegrationManager

    mgr = IntegrationManager(db_manager)

    # Configure an integration
    mgr.configure_integration('abuseipdb', api_key='your-key', enabled=True) # pragma: allowlist secret

    # Test an integration
    status = mgr.test_integration('abuseipdb')
"""

import logging
import json
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from pathlib import Path
import sys

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.credential_manager import get_credential_manager

logger = logging.getLogger(__name__)


# Integration definitions with free tier limits
INTEGRATIONS = {
    # =================================================================
    # THREAT INTELLIGENCE (6 integrations)
    # =================================================================
    'abuseipdb': {
        'name': 'AbuseIPDB',
        'category': 'threat_intel',
        'priority': 'high',
        'description': 'IP reputation database with abuse reports',
        'free_tier': '1,000 requests/day',
        'rate_limit_day': 1000,
        'rate_limit_month': 30000,
        'api_endpoint': 'https://api.abuseipdb.com/api/v2/check',
        'docs_url': 'https://docs.abuseipdb.com/',
        'setup_fields': ['api_key'],
        'test_method': 'check_ip',
        'icon': 'shield-alt'
    },
    'virustotal': {
        'name': 'VirusTotal',
        'category': 'threat_intel',
        'priority': 'high',
        'description': 'Multi-engine malware scanner and threat intelligence',
        'free_tier': '500 requests/day',
        'rate_limit_day': 500,
        'rate_limit_month': 15000,
        'api_endpoint': 'https://www.virustotal.com/api/v3/ip_addresses/',
        'docs_url': 'https://developers.virustotal.com/',
        'setup_fields': ['api_key'],
        'test_method': 'check_ip',
        'icon': 'virus'
    },
    'alienvault_otx': {
        'name': 'AlienVault OTX',
        'category': 'threat_intel',
        'priority': 'high',
        'description': 'Open threat intelligence community',
        'free_tier': 'Unlimited (free)',
        'rate_limit_day': None,
        'rate_limit_month': None,
        'api_endpoint': 'https://otx.alienvault.com/api/v1/indicators/IPv4/',
        'docs_url': 'https://otx.alienvault.com/api',
        'setup_fields': ['api_key'],
        'test_method': 'check_ip',
        'icon': 'satellite-dish'
    },
    'greynoise': {
        'name': 'GreyNoise',
        'category': 'threat_intel',
        'priority': 'medium',
        'description': 'Internet scanning and mass exploitation detection',
        'free_tier': 'Community API (limited)',
        'rate_limit_day': 1000,
        'rate_limit_month': 30000,
        'api_endpoint': 'https://api.greynoise.io/v3/community/',
        'docs_url': 'https://docs.greynoise.io/',
        'setup_fields': ['api_key'],
        'test_method': 'check_ip',
        'icon': 'search'
    },
    'ipqualityscore': {
        'name': 'IPQualityScore',
        'category': 'threat_intel',
        'priority': 'medium',
        'description': 'IP reputation, proxy/VPN detection, fraud prevention',
        'free_tier': '5,000 requests/month',
        'rate_limit_day': 200,
        'rate_limit_month': 5000,
        'api_endpoint': 'https://ipqualityscore.com/api/json/ip/',
        'docs_url': 'https://www.ipqualityscore.com/documentation/overview',
        'setup_fields': ['api_key'],
        'test_method': 'check_ip',
        'icon': 'fingerprint'
    },
    'threatfox': {
        'name': 'ThreatFox',
        'category': 'threat_intel',
        'priority': 'medium',
        'description': 'Malware indicators of compromise (IOCs) sharing platform',
        'free_tier': 'Unlimited (free)',
        'rate_limit_day': None,
        'rate_limit_month': None,
        'api_endpoint': 'https://threatfox-api.abuse.ch/api/v1/',
        'docs_url': 'https://threatfox.abuse.ch/api/',
        'setup_fields': [],  # No API key required
        'test_method': 'search_ioc',
        'icon': 'biohazard'
    },
    'shodan': {
        'name': 'Shodan',
        'category': 'threat_intel',
        'priority': 'medium',
        'description': 'Internet-connected devices search engine',
        'free_tier': '100 query credits/month',
        'rate_limit_day': 10,
        'rate_limit_month': 100,
        'api_endpoint': 'https://api.shodan.io/shodan/host/',
        'docs_url': 'https://developer.shodan.io/',
        'setup_fields': ['api_key'],
        'test_method': 'host_lookup',
        'icon': 'search-location'
    },
    'nvd': {
        'name': 'NVD (National Vulnerability Database)',
        'category': 'threat_intel',
        'priority': 'high',
        'description': 'CVE vulnerability database from NIST',
        'free_tier': '50 requests/30s with key',
        'rate_limit_day': 5000,
        'rate_limit_month': 150000,
        'api_endpoint': 'https://services.nvd.nist.gov/rest/json/cves/2.0',
        'docs_url': 'https://nvd.nist.gov/developers',
        'setup_fields': ['api_key'],
        'test_method': 'search_cve',
        'icon': 'shield-virus'
    },

    # =================================================================
    # GEOLOCATION (3 integrations)
    # =================================================================
    'ipinfo': {
        'name': 'IPinfo',
        'category': 'geolocation',
        'priority': 'high',
        'description': 'IP geolocation, ASN, and company information',
        'free_tier': '50,000 requests/month',
        'rate_limit_day': 2000,
        'rate_limit_month': 50000,
        'api_endpoint': 'https://ipinfo.io/',
        'docs_url': 'https://ipinfo.io/developers',
        'setup_fields': ['api_key'],
        'test_method': 'lookup_ip',
        'icon': 'globe'
    },
    'ip_api': {
        'name': 'IP-API',
        'category': 'geolocation',
        'priority': 'medium',
        'description': 'Free IP geolocation API',
        'free_tier': '45 requests/minute (unlimited)',
        'rate_limit_day': None,
        'rate_limit_month': None,
        'api_endpoint': 'http://ip-api.com/json/',
        'docs_url': 'https://ip-api.com/docs',
        'setup_fields': [],  # No API key required
        'test_method': 'lookup_ip',
        'icon': 'map-marker-alt'
    },
    'ipgeolocation': {
        'name': 'IPGeolocation',
        'category': 'geolocation',
        'priority': 'low',
        'description': 'IP geolocation with timezone and currency info',
        'free_tier': '1,000 requests/day',
        'rate_limit_day': 1000,
        'rate_limit_month': 30000,
        'api_endpoint': 'https://api.ipgeolocation.io/ipgeo',
        'docs_url': 'https://ipgeolocation.io/documentation.html',
        'setup_fields': ['api_key'],
        'test_method': 'lookup_ip',
        'icon': 'compass'
    },

    # =================================================================
    # NOTIFICATIONS (5 integrations)
    # =================================================================
    'slack': {
        'name': 'Slack',
        'category': 'notifications',
        'priority': 'high',
        'description': 'Team messaging and collaboration platform',
        'free_tier': 'Unlimited (webhook)',
        'rate_limit_day': None,
        'rate_limit_month': None,
        'api_endpoint': 'webhook_url',
        'docs_url': 'https://api.slack.com/messaging/webhooks',
        'setup_fields': ['webhook_url'],
        'test_method': 'send_message',
        'icon': 'slack'
    },
    'discord': {
        'name': 'Discord',
        'category': 'notifications',
        'priority': 'high',
        'description': 'Voice, video and text communication platform',
        'free_tier': 'Unlimited (webhook)',
        'rate_limit_day': None,
        'rate_limit_month': None,
        'api_endpoint': 'webhook_url',
        'docs_url': 'https://discord.com/developers/docs/resources/webhook',
        'setup_fields': ['webhook_url'],
        'test_method': 'send_message',
        'icon': 'discord'
    },
    'telegram': {
        'name': 'Telegram',
        'category': 'notifications',
        'priority': 'high',
        'description': 'Cloud-based instant messaging service',
        'free_tier': 'Unlimited (bot API)',
        'rate_limit_day': None,
        'rate_limit_month': None,
        'api_endpoint': 'https://api.telegram.org/bot',
        'docs_url': 'https://core.telegram.org/bots/api',
        'setup_fields': ['bot_token', 'chat_id'],
        'test_method': 'send_message',
        'icon': 'telegram'
    },
    'pushover': {
        'name': 'Pushover',
        'category': 'notifications',
        'priority': 'medium',
        'description': 'Simple notifications for Android and iOS',
        'free_tier': '7,500 messages/month',
        'rate_limit_day': 250,
        'rate_limit_month': 7500,
        'api_endpoint': 'https://api.pushover.net/1/messages.json',
        'docs_url': 'https://pushover.net/api',
        'setup_fields': ['user_key', 'api_token'],
        'test_method': 'send_message',
        'icon': 'mobile-alt'
    },
    'email_smtp': {
        'name': 'Email (SMTP)',
        'category': 'notifications',
        'priority': 'high',
        'description': 'Standard email notifications via SMTP',
        'free_tier': 'Unlimited (depends on provider)',
        'rate_limit_day': None,
        'rate_limit_month': None,
        'api_endpoint': 'smtp_server',
        'docs_url': 'https://en.wikipedia.org/wiki/Simple_Mail_Transfer_Protocol',
        'setup_fields': ['smtp_server', 'smtp_port', 'username', 'password', 'from_email', 'to_email'],
        'test_method': 'send_email',
        'icon': 'envelope'
    },

    # =================================================================
    # TICKETING (4 integrations)
    # =================================================================
    'github_issues': {
        'name': 'GitHub Issues',
        'category': 'ticketing',
        'priority': 'high',
        'description': 'Create issues in GitHub repositories',
        'free_tier': 'Unlimited (free tier)',
        'rate_limit_day': 5000,
        'rate_limit_month': 150000,
        'api_endpoint': 'https://api.github.com/repos/',
        'docs_url': 'https://docs.github.com/en/rest/issues',
        'setup_fields': ['personal_access_token', 'repo_owner', 'repo_name'],
        'test_method': 'create_issue',
        'icon': 'github'
    },
    'gitlab_issues': {
        'name': 'GitLab Issues',
        'category': 'ticketing',
        'priority': 'high',
        'description': 'Create issues in GitLab projects',
        'free_tier': 'Unlimited (free tier)',
        'rate_limit_day': None,
        'rate_limit_month': None,
        'api_endpoint': 'https://gitlab.com/api/v4/projects/',
        'docs_url': 'https://docs.gitlab.com/ee/api/issues.html',
        'setup_fields': ['personal_access_token', 'project_id'],
        'test_method': 'create_issue',
        'icon': 'gitlab'
    },
    'trello': {
        'name': 'Trello',
        'category': 'ticketing',
        'priority': 'medium',
        'description': 'Create cards in Trello boards',
        'free_tier': 'Unlimited (free tier)',
        'rate_limit_day': 300,
        'rate_limit_month': 9000,
        'api_endpoint': 'https://api.trello.com/1/cards',
        'docs_url': 'https://developer.atlassian.com/cloud/trello/rest/',
        'setup_fields': ['api_key', 'api_token', 'board_id', 'list_id'],
        'test_method': 'create_card',
        'icon': 'trello'
    },
    'linear': {
        'name': 'Linear',
        'category': 'ticketing',
        'priority': 'medium',
        'description': 'Create issues in Linear project management',
        'free_tier': 'Unlimited (free tier)',
        'rate_limit_day': None,
        'rate_limit_month': None,
        'api_endpoint': 'https://api.linear.app/graphql',
        'docs_url': 'https://developers.linear.app/docs/graphql/working-with-the-graphql-api',
        'setup_fields': ['api_key', 'team_id'],
        'test_method': 'create_issue',
        'icon': 'tasks'
    },

    # =================================================================
    # WEBHOOKS (4 integrations)
    # =================================================================
    'custom_webhook': {
        'name': 'Custom Webhook',
        'category': 'webhooks',
        'priority': 'high',
        'description': 'Send data to any custom HTTP endpoint',
        'free_tier': 'Unlimited (depends on endpoint)',
        'rate_limit_day': None,
        'rate_limit_month': None,
        'api_endpoint': 'custom_url',
        'docs_url': 'https://en.wikipedia.org/wiki/Webhook',
        'setup_fields': ['webhook_url', 'http_method'],
        'test_method': 'send_webhook',
        'icon': 'plug'
    },
    'zapier': {
        'name': 'Zapier',
        'category': 'webhooks',
        'priority': 'medium',
        'description': 'Automation platform connecting 5,000+ apps',
        'free_tier': '100 tasks/month',
        'rate_limit_day': 5,
        'rate_limit_month': 100,
        'api_endpoint': 'webhook_url',
        'docs_url': 'https://zapier.com/app/webhooks',
        'setup_fields': ['webhook_url'],
        'test_method': 'trigger_zap',
        'icon': 'bolt'
    },
    'ifttt': {
        'name': 'IFTTT',
        'category': 'webhooks',
        'priority': 'medium',
        'description': 'If This Then That automation service',
        'free_tier': 'Unlimited (webhook)',
        'rate_limit_day': None,
        'rate_limit_month': None,
        'api_endpoint': 'https://maker.ifttt.com/trigger/',
        'docs_url': 'https://ifttt.com/maker_webhooks',
        'setup_fields': ['webhook_key', 'event_name'],
        'test_method': 'trigger_applet',
        'icon': 'link'
    },
    'n8n': {
        'name': 'n8n',
        'category': 'webhooks',
        'priority': 'low',
        'description': 'Open-source workflow automation',
        'free_tier': 'Unlimited (self-hosted)',
        'rate_limit_day': None,
        'rate_limit_month': None,
        'api_endpoint': 'webhook_url',
        'docs_url': 'https://docs.n8n.io/integrations/builtin/core-nodes/n8n-nodes-base.webhook/',
        'setup_fields': ['webhook_url'],
        'test_method': 'trigger_workflow',
        'icon': 'project-diagram'
    },
}


class IntegrationManager:
    """Manages external API integrations with encrypted credential storage."""

    def __init__(self, db_manager):
        """
        Initialize the integration manager.

        Args:
            db_manager: Database manager instance
        """
        self.db = db_manager
        self.cred_mgr = get_credential_manager()
        self._ensure_integrations_initialized()

    def _ensure_integrations_initialized(self):
        """Ensure all integrations are in the database."""
        try:
            cursor = self.db.conn.cursor()

            # Check if integrations already exist
            cursor.execute('SELECT COUNT(*) FROM api_integrations')
            existing_count = cursor.fetchone()[0]

            inserted_count = 0
            for integration_id, integration_info in INTEGRATIONS.items():
                cursor.execute('''
                    INSERT OR IGNORE INTO api_integrations
                    (integration_name, integration_type, category, priority, rate_limit_per_day, rate_limit_per_month)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    integration_id,
                    integration_info['name'],
                    integration_info['category'],
                    integration_info['priority'],
                    integration_info.get('rate_limit_day'),
                    integration_info.get('rate_limit_month')
                ))
                if cursor.rowcount > 0:
                    inserted_count += 1

            self.db.conn.commit()

            # Only log if new integrations were added
            if inserted_count > 0:
                logger.info(f"Initialized {inserted_count} new integrations in database")
            elif existing_count == 0:
                logger.debug(f"All {len(INTEGRATIONS)} integrations already initialized")

        except Exception as e:
            logger.error(f"Failed to initialize integrations: {e}")

    def get_all_integrations(self) -> List[Dict[str, Any]]:
        """
        Get all available integrations with their configurations.

        Returns:
            List of integration dictionaries
        """
        integrations = []
        cursor = self.db.conn.cursor()

        for integration_id, integration_info in INTEGRATIONS.items():
            # Get database info
            cursor.execute('''
                SELECT is_enabled, health_status, last_health_check,
                       total_requests, successful_requests, failed_requests, last_error
                FROM api_integrations
                WHERE integration_name = ?
            ''', (integration_id,))

            row = cursor.fetchone()

            integration = {
                'id': integration_id,
                **integration_info,
                'is_enabled': bool(row[0]) if row else False,
                'health_status': row[1] if row else 'untested',
                'last_health_check': row[2] if row else None,
                'total_requests': row[3] if row else 0,
                'successful_requests': row[4] if row else 0,
                'failed_requests': row[5] if row else 0,
                'last_error': row[6] if row else None,
            }

            integrations.append(integration)

        return integrations

    def get_integration(self, integration_name: str) -> Optional[Dict[str, Any]]:
        """
        Get a specific integration by name.

        Args:
            integration_name: Name of the integration

        Returns:
            Integration dictionary or None
        """
        if integration_name not in INTEGRATIONS:
            return None

        integrations = self.get_all_integrations()
        for integration in integrations:
            if integration['id'] == integration_name:
                return integration

        return None

    def configure_integration(self, integration_name: str, enabled: bool = True, **credentials) -> bool:
        """
        Configure an integration with encrypted credentials.

        Args:
            integration_name: Name of the integration
            enabled: Whether to enable the integration
            **credentials: API keys and other credentials (will be encrypted)

        Returns:
            True if successful, False otherwise
        """
        if integration_name not in INTEGRATIONS:
            logger.error(f"Unknown integration: {integration_name}")
            return False

        try:
            cursor = self.db.conn.cursor()

            # Prepare encrypted credentials
            config_json = {}
            api_key_encrypted = None
            api_secret_encrypted = None

            for key, value in credentials.items():
                if key in ['api_key', 'personal_access_token', 'bot_token', 'user_key', 'api_token', 'webhook_key']:
                    # Encrypt sensitive API keys
                    api_key_encrypted = self.cred_mgr.encrypt(str(value))
                elif key in ['api_secret', 'password']:
                    # Encrypt secrets separately
                    api_secret_encrypted = self.cred_mgr.encrypt(str(value))
                elif key in ['webhook_url'] and value:
                    # Encrypt webhook URLs as they may contain secrets
                    config_json[key] = self.cred_mgr.encrypt(str(value))
                else:
                    # Store non-sensitive config in JSON
                    config_json[key] = value

            # Update database
            cursor.execute('''
                UPDATE api_integrations
                SET is_enabled = ?,
                    api_key_encrypted = ?,
                    api_secret_encrypted = ?,
                    config_json = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE integration_name = ?
            ''', (
                1 if enabled else 0,
                api_key_encrypted,
                api_secret_encrypted,
                json.dumps(config_json) if config_json else None,
                integration_name
            ))

            self.db.conn.commit()
            logger.info(f"Configured integration: {integration_name}")
            return True

        except Exception as e:
            logger.error(f"Failed to configure integration {integration_name}: {e}")
            return False

    def get_integration_credentials(self, integration_name: str) -> Optional[Dict[str, Any]]:
        """
        Get decrypted credentials for an integration.

        Args:
            integration_name: Name of the integration

        Returns:
            Dictionary of credentials or None
        """
        try:
            cursor = self.db.conn.cursor()
            cursor.execute('''
                SELECT api_key_encrypted, api_secret_encrypted, config_json
                FROM api_integrations
                WHERE integration_name = ?
            ''', (integration_name,))

            row = cursor.fetchone()
            if not row:
                return None

            credentials = {}

            # Decrypt API key
            if row[0]:
                credentials['api_key'] = self.cred_mgr.decrypt(row[0])

            # Decrypt API secret
            if row[1]:
                credentials['api_secret'] = self.cred_mgr.decrypt(row[1])

            # Decrypt config JSON
            if row[2]:
                config = json.loads(row[2])
                for key, value in config.items():
                    if key == 'webhook_url' and value:
                        # Decrypt webhook URLs
                        credentials[key] = self.cred_mgr.decrypt(value)
                    else:
                        credentials[key] = value

            return credentials

        except Exception as e:
            logger.error(f"Failed to get credentials for {integration_name}: {e}")
            return None

    def update_health_status(self, integration_name: str, status: str, error: Optional[str] = None):
        """
        Update the health status of an integration.

        Args:
            integration_name: Name of the integration
            status: Health status (healthy/degraded/error/untested)
            error: Error message if status is error
        """
        try:
            cursor = self.db.conn.cursor()
            cursor.execute('''
                UPDATE api_integrations
                SET health_status = ?,
                    last_health_check = CURRENT_TIMESTAMP,
                    last_error = ?
                WHERE integration_name = ?
            ''', (status, error, integration_name))

            self.db.conn.commit()

        except Exception as e:
            logger.error(f"Failed to update health status for {integration_name}: {e}")

    def log_request(self, integration_name: str, request_type: str, success: bool,
                    response_time_ms: Optional[int] = None, error: Optional[str] = None):
        """
        Log an API request for tracking and rate limiting.

        Args:
            integration_name: Name of the integration
            request_type: Type of request
            success: Whether the request was successful
            response_time_ms: Response time in milliseconds
            error: Error message if failed
        """
        try:
            cursor = self.db.conn.cursor()

            # Get integration ID
            cursor.execute('SELECT id FROM api_integrations WHERE integration_name = ?', (integration_name,))
            row = cursor.fetchone()
            if not row:
                return

            integration_id = row[0]

            # Log the request
            cursor.execute('''
                INSERT INTO api_integration_logs
                (integration_id, request_type, success, response_time_ms, error_message)
                VALUES (?, ?, ?, ?, ?)
            ''', (integration_id, request_type, 1 if success else 0, response_time_ms, error))

            # Update integration statistics
            if success:
                cursor.execute('''
                    UPDATE api_integrations
                    SET total_requests = total_requests + 1,
                        successful_requests = successful_requests + 1,
                        last_used = CURRENT_TIMESTAMP
                    WHERE id = ?
                ''', (integration_id,))
            else:
                cursor.execute('''
                    UPDATE api_integrations
                    SET total_requests = total_requests + 1,
                        failed_requests = failed_requests + 1,
                        last_error = ?
                    WHERE id = ?
                ''', (error, integration_id))

            self.db.conn.commit()

        except Exception as e:
            logger.error(f"Failed to log request for {integration_name}: {e}")

    def get_integrations_by_category(self, category: str) -> List[Dict[str, Any]]:
        """
        Get all integrations in a specific category.

        Args:
            category: Category name (threat_intel, geolocation, notifications, ticketing, webhooks)

        Returns:
            List of integration dictionaries
        """
        all_integrations = self.get_all_integrations()
        return [i for i in all_integrations if i['category'] == category]

    def get_enabled_integrations(self) -> List[Dict[str, Any]]:
        """
        Get all enabled integrations.

        Returns:
            List of enabled integration dictionaries
        """
        all_integrations = self.get_all_integrations()
        return [i for i in all_integrations if i['is_enabled']]

    def disable_integration(self, integration_name: str) -> bool:
        """
        Disable an integration.

        Args:
            integration_name: Name of the integration

        Returns:
            True if successful, False otherwise
        """
        try:
            cursor = self.db.conn.cursor()
            cursor.execute('''
                UPDATE api_integrations
                SET is_enabled = 0,
                    updated_at = CURRENT_TIMESTAMP
                WHERE integration_name = ?
            ''', (integration_name,))

            self.db.conn.commit()
            logger.info(f"Disabled integration: {integration_name}")
            return True

        except Exception as e:
            logger.error(f"Failed to disable integration {integration_name}: {e}")
            return False
