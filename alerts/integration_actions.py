#!/usr/bin/env python3
"""
Integration Actions for IoTSentinel

Provides action functions for all 26 free-tier integrations:
- Send notifications (Slack, Discord, Telegram, Email, Pushover)
- Create tickets (GitHub, GitLab, Trello, Linear)
- Query threat intelligence (AbuseIPDB, VirusTotal, OTX, GreyNoise, etc.)
- Get geolocation data (IPinfo, IP-API, IPGeolocation)
- Trigger webhooks (Zapier, IFTTT, n8n, Custom)

Usage:
    from alerts.integration_actions import IntegrationActions

    actions = IntegrationActions(db_manager)

    # Send a Slack alert
    actions.send_slack_alert("Critical alert detected!")

    # Query threat intelligence
    threat_data = actions.query_threat_intel("8.8.8.8")
"""

import logging
import requests
import json
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, List, Optional, Any
from datetime import datetime
import time
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

from alerts.integration_system import IntegrationManager

logger = logging.getLogger(__name__)


class IntegrationActions:
    """Provides action functions for all integrations."""

    def __init__(self, db_manager):
        """
        Initialize integration actions.

        Args:
            db_manager: Database manager instance
        """
        self.db = db_manager
        self.integration_mgr = IntegrationManager(db_manager)

    # =================================================================
    # NOTIFICATIONS - Send alerts to various platforms
    # =================================================================

    def send_slack_alert(self, message: str, severity: str = "medium") -> bool:
        """Send alert to Slack via webhook."""
        start_time = time.time()

        try:
            creds = self.integration_mgr.get_integration_credentials('slack')
            if not creds or not creds.get('webhook_url'):
                logger.warning("Slack not configured")
                return False

            color_map = {"low": "#36a64f", "medium": "#ff9800", "high": "#ff5722", "critical": "#d32f2f"}

            payload = {
                "text": f"🚨 *IoTSentinel Alert*",
                "attachments": [{
                    "color": color_map.get(severity, "#808080"),
                    "text": message,
                    "footer": "IoTSentinel",
                    "ts": int(datetime.now().timestamp())
                }]
            }

            response = requests.post(creds['webhook_url'], json=payload, timeout=10)
            response_time = int((time.time() - start_time) * 1000)

            success = response.status_code == 200
            self.integration_mgr.log_request('slack', 'send_alert', success, response_time,
                                            None if success else response.text)

            if success:
                self.integration_mgr.update_health_status('slack', 'healthy')

            return success

        except Exception as e:
            logger.error(f"Slack alert failed: {e}")
            self.integration_mgr.log_request('slack', 'send_alert', False, None, str(e))
            self.integration_mgr.update_health_status('slack', 'error', str(e))
            return False

    def send_discord_alert(self, message: str, severity: str = "medium") -> bool:
        """Send alert to Discord via webhook."""
        start_time = time.time()

        try:
            creds = self.integration_mgr.get_integration_credentials('discord')
            if not creds or not creds.get('webhook_url'):
                logger.warning("Discord not configured")
                return False

            color_map = {"low": 0x36a64f, "medium": 0xff9800, "high": 0xff5722, "critical": 0xd32f2f}

            payload = {
                "embeds": [{
                    "title": "🚨 IoTSentinel Alert",
                    "description": message,
                    "color": color_map.get(severity, 0x808080),
                    "footer": {"text": "IoTSentinel"},
                    "timestamp": datetime.utcnow().isoformat()
                }]
            }

            response = requests.post(creds['webhook_url'], json=payload, timeout=10)
            response_time = int((time.time() - start_time) * 1000)

            success = response.status_code == 204
            self.integration_mgr.log_request('discord', 'send_alert', success, response_time,
                                            None if success else response.text)

            if success:
                self.integration_mgr.update_health_status('discord', 'healthy')

            return success

        except Exception as e:
            logger.error(f"Discord alert failed: {e}")
            self.integration_mgr.log_request('discord', 'send_alert', False, None, str(e))
            self.integration_mgr.update_health_status('discord', 'error', str(e))
            return False

    def send_telegram_alert(self, message: str) -> bool:
        """Send alert to Telegram via bot API."""
        start_time = time.time()

        try:
            creds = self.integration_mgr.get_integration_credentials('telegram')
            if not creds or not creds.get('bot_token') or not creds.get('chat_id'):
                logger.warning("Telegram not configured")
                return False

            url = f"https://api.telegram.org/bot{creds['bot_token']}/sendMessage"
            payload = {
                "chat_id": creds['chat_id'],
                "text": f"🚨 *IoTSentinel Alert*\n\n{message}",
                "parse_mode": "Markdown"
            }

            response = requests.post(url, json=payload, timeout=10)
            response_time = int((time.time() - start_time) * 1000)

            success = response.status_code == 200
            self.integration_mgr.log_request('telegram', 'send_alert', success, response_time,
                                            None if success else response.text)

            if success:
                self.integration_mgr.update_health_status('telegram', 'healthy')

            return success

        except Exception as e:
            logger.error(f"Telegram alert failed: {e}")
            self.integration_mgr.log_request('telegram', 'send_alert', False, None, str(e))
            self.integration_mgr.update_health_status('telegram', 'error', str(e))
            return False

    def send_email_alert(self, subject: str, message: str) -> bool:
        """Send alert via SMTP email."""
        start_time = time.time()

        try:
            creds = self.integration_mgr.get_integration_credentials('email_smtp')
            if not creds:
                logger.warning("Email SMTP not configured")
                return False

            msg = MIMEMultipart()
            msg['From'] = creds['from_email']
            msg['To'] = creds['to_email']
            msg['Subject'] = f"🚨 IoTSentinel: {subject}"

            body = f"<html><body><h2>IoTSentinel Alert</h2><p>{message}</p></body></html>"
            msg.attach(MIMEText(body, 'html'))

            with smtplib.SMTP(creds['smtp_server'], int(creds.get('smtp_port', 587))) as server:
                server.starttls()
                server.login(creds['username'], creds['password'])
                server.send_message(msg)

            response_time = int((time.time() - start_time) * 1000)
            self.integration_mgr.log_request('email_smtp', 'send_alert', True, response_time)
            self.integration_mgr.update_health_status('email_smtp', 'healthy')
            return True

        except Exception as e:
            logger.error(f"Email alert failed: {e}")
            self.integration_mgr.log_request('email_smtp', 'send_alert', False, None, str(e))
            self.integration_mgr.update_health_status('email_smtp', 'error', str(e))
            return False

    def send_pushover_alert(self, message: str, priority: int = 0) -> bool:
        """Send alert via Pushover."""
        start_time = time.time()

        try:
            creds = self.integration_mgr.get_integration_credentials('pushover')
            if not creds:
                logger.warning("Pushover not configured")
                return False

            payload = {
                "token": creds['api_token'],
                "user": creds['user_key'],
                "message": message,
                "title": "IoTSentinel Alert",
                "priority": priority
            }

            response = requests.post('https://api.pushover.net/1/messages.json', data=payload, timeout=10)
            response_time = int((time.time() - start_time) * 1000)

            success = response.status_code == 200
            self.integration_mgr.log_request('pushover', 'send_alert', success, response_time,
                                            None if success else response.text)

            if success:
                self.integration_mgr.update_health_status('pushover', 'healthy')

            return success

        except Exception as e:
            logger.error(f"Pushover alert failed: {e}")
            self.integration_mgr.log_request('pushover', 'send_alert', False, None, str(e))
            self.integration_mgr.update_health_status('pushover', 'error', str(e))
            return False

    # =================================================================
    # TICKETING - Create issues/cards
    # =================================================================

    def create_github_issue(self, title: str, body: str, labels: Optional[List[str]] = None) -> Optional[str]:
        """Create issue in GitHub repository."""
        start_time = time.time()

        try:
            creds = self.integration_mgr.get_integration_credentials('github_issues')
            if not creds:
                logger.warning("GitHub Issues not configured")
                return None

            url = f"https://api.github.com/repos/{creds['repo_owner']}/{creds['repo_name']}/issues"
            headers = {
                "Authorization": f"token {creds['personal_access_token']}",
                "Accept": "application/vnd.github.v3+json"
            }
            payload = {
                "title": title,
                "body": body,
                "labels": labels or ["iotsentinel", "security-alert"]
            }

            response = requests.post(url, headers=headers, json=payload, timeout=10)
            response_time = int((time.time() - start_time) * 1000)

            if response.status_code == 201:
                issue_url = response.json().get('html_url')
                self.integration_mgr.log_request('github_issues', 'create_issue', True, response_time)
                self.integration_mgr.update_health_status('github_issues', 'healthy')
                return issue_url
            else:
                self.integration_mgr.log_request('github_issues', 'create_issue', False, response_time, response.text)
                return None

        except Exception as e:
            logger.error(f"GitHub issue creation failed: {e}")
            self.integration_mgr.log_request('github_issues', 'create_issue', False, None, str(e))
            self.integration_mgr.update_health_status('github_issues', 'error', str(e))
            return None

    def create_gitlab_issue(self, title: str, description: str) -> Optional[str]:
        """Create issue in GitLab project."""
        start_time = time.time()

        try:
            creds = self.integration_mgr.get_integration_credentials('gitlab_issues')
            if not creds:
                logger.warning("GitLab Issues not configured")
                return None

            url = f"https://gitlab.com/api/v4/projects/{creds['project_id']}/issues"
            headers = {"PRIVATE-TOKEN": creds['personal_access_token']}
            payload = {
                "title": title,
                "description": description,
                "labels": "iotsentinel,security-alert"
            }

            response = requests.post(url, headers=headers, json=payload, timeout=10)
            response_time = int((time.time() - start_time) * 1000)

            if response.status_code == 201:
                issue_url = response.json().get('web_url')
                self.integration_mgr.log_request('gitlab_issues', 'create_issue', True, response_time)
                self.integration_mgr.update_health_status('gitlab_issues', 'healthy')
                return issue_url
            else:
                self.integration_mgr.log_request('gitlab_issues', 'create_issue', False, response_time, response.text)
                return None

        except Exception as e:
            logger.error(f"GitLab issue creation failed: {e}")
            self.integration_mgr.log_request('gitlab_issues', 'create_issue', False, None, str(e))
            self.integration_mgr.update_health_status('gitlab_issues', 'error', str(e))
            return None

    def create_trello_card(self, name: str, desc: str) -> Optional[str]:
        """Create card in Trello board."""
        start_time = time.time()

        try:
            creds = self.integration_mgr.get_integration_credentials('trello')
            if not creds:
                logger.warning("Trello not configured")
                return None

            url = "https://api.trello.com/1/cards"
            params = {
                "key": creds['api_key'],
                "token": creds['api_token'],
                "idList": creds['list_id'],
                "name": name,
                "desc": desc
            }

            response = requests.post(url, params=params, timeout=10)
            response_time = int((time.time() - start_time) * 1000)

            if response.status_code == 200:
                card_url = response.json().get('shortUrl')
                self.integration_mgr.log_request('trello', 'create_card', True, response_time)
                self.integration_mgr.update_health_status('trello', 'healthy')
                return card_url
            else:
                self.integration_mgr.log_request('trello', 'create_card', False, response_time, response.text)
                return None

        except Exception as e:
            logger.error(f"Trello card creation failed: {e}")
            self.integration_mgr.log_request('trello', 'create_card', False, None, str(e))
            self.integration_mgr.update_health_status('trello', 'error', str(e))
            return None

    # =================================================================
    # THREAT INTELLIGENCE - Query multiple sources
    # =================================================================

    def query_threat_intel(self, ip_address: str) -> Dict[str, Any]:
        """
        Query multiple threat intelligence sources for an IP.

        Args:
            ip_address: IP address to check

        Returns:
            Aggregated threat intelligence data
        """
        results = {
            'ip': ip_address,
            'is_malicious': False,
            'confidence': 0,
            'sources': {},
            'categories': [],
            'last_seen': None
        }

        # Try each enabled threat intel integration
        enabled = self.integration_mgr.get_enabled_integrations()
        threat_intel = [i for i in enabled if i['category'] == 'threat_intel']

        for integration in threat_intel:
            try:
                data = None

                if integration['id'] == 'abuseipdb':
                    data = self._check_abuseipdb(ip_address)
                elif integration['id'] == 'virustotal':
                    data = self._check_virustotal(ip_address)
                elif integration['id'] == 'alienvault_otx':
                    data = self._check_otx(ip_address)
                elif integration['id'] == 'greynoise':
                    data = self._check_greynoise(ip_address)

                if data:
                    results['sources'][integration['name']] = data
                    if data.get('is_malicious'):
                        results['is_malicious'] = True
                        results['confidence'] = max(results['confidence'], data.get('confidence', 0))

            except Exception as e:
                logger.error(f"Failed to query {integration['name']}: {e}")

        return results

    def _check_abuseipdb(self, ip: str) -> Optional[Dict]:
        """Check IP against AbuseIPDB."""
        start_time = time.time()

        try:
            creds = self.integration_mgr.get_integration_credentials('abuseipdb')
            if not creds:
                return None

            headers = {"Key": creds['api_key'], "Accept": "application/json"}
            params = {"ipAddress": ip, "maxAgeInDays": 90}

            response = requests.get('https://api.abuseipdb.com/api/v2/check',
                                   headers=headers, params=params, timeout=10)
            response_time = int((time.time() - start_time) * 1000)

            if response.status_code == 200:
                data = response.json().get('data', {})
                result = {
                    'is_malicious': data.get('abuseConfidenceScore', 0) > 50,
                    'confidence': data.get('abuseConfidenceScore', 0),
                    'reports': data.get('totalReports', 0),
                    'last_seen': data.get('lastReportedAt')
                }

                self.integration_mgr.log_request('abuseipdb', 'check_ip', True, response_time)
                self.integration_mgr.update_health_status('abuseipdb', 'healthy')
                return result
            else:
                self.integration_mgr.log_request('abuseipdb', 'check_ip', False, response_time, response.text)
                return None

        except Exception as e:
            logger.error(f"AbuseIPDB check failed: {e}")
            self.integration_mgr.log_request('abuseipdb', 'check_ip', False, None, str(e))
            return None

    def _check_virustotal(self, ip: str) -> Optional[Dict]:
        """Check IP against VirusTotal."""
        start_time = time.time()

        try:
            creds = self.integration_mgr.get_integration_credentials('virustotal')
            if not creds:
                return None

            headers = {"x-apikey": creds['api_key']}
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"

            response = requests.get(url, headers=headers, timeout=10)
            response_time = int((time.time() - start_time) * 1000)

            if response.status_code == 200:
                data = response.json().get('data', {}).get('attributes', {})
                stats = data.get('last_analysis_stats', {})
                malicious = stats.get('malicious', 0)
                total = sum(stats.values())

                result = {
                    'is_malicious': malicious > 0,
                    'confidence': int((malicious / total * 100)) if total > 0 else 0,
                    'detections': f"{malicious}/{total}",
                    'categories': data.get('categories', {})
                }

                self.integration_mgr.log_request('virustotal', 'check_ip', True, response_time)
                self.integration_mgr.update_health_status('virustotal', 'healthy')
                return result
            else:
                self.integration_mgr.log_request('virustotal', 'check_ip', False, response_time, response.text)
                return None

        except Exception as e:
            logger.error(f"VirusTotal check failed: {e}")
            self.integration_mgr.log_request('virustotal', 'check_ip', False, None, str(e))
            return None

    def _check_otx(self, ip: str) -> Optional[Dict]:
        """Check IP against AlienVault OTX."""
        start_time = time.time()

        try:
            creds = self.integration_mgr.get_integration_credentials('alienvault_otx')
            if not creds:
                return None

            headers = {"X-OTX-API-KEY": creds['api_key']}
            url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"

            response = requests.get(url, headers=headers, timeout=10)
            response_time = int((time.time() - start_time) * 1000)

            if response.status_code == 200:
                data = response.json()
                pulse_count = data.get('pulse_info', {}).get('count', 0)

                result = {
                    'is_malicious': pulse_count > 0,
                    'confidence': min(pulse_count * 10, 100),
                    'pulses': pulse_count
                }

                self.integration_mgr.log_request('alienvault_otx', 'check_ip', True, response_time)
                self.integration_mgr.update_health_status('alienvault_otx', 'healthy')
                return result
            else:
                self.integration_mgr.log_request('alienvault_otx', 'check_ip', False, response_time, response.text)
                return None

        except Exception as e:
            logger.error(f"OTX check failed: {e}")
            self.integration_mgr.log_request('alienvault_otx', 'check_ip', False, None, str(e))
            return None

    def _check_greynoise(self, ip: str) -> Optional[Dict]:
        """Check IP against GreyNoise."""
        start_time = time.time()

        try:
            creds = self.integration_mgr.get_integration_credentials('greynoise')
            if not creds:
                return None

            headers = {"key": creds['api_key']}
            url = f"https://api.greynoise.io/v3/community/{ip}"

            response = requests.get(url, headers=headers, timeout=10)
            response_time = int((time.time() - start_time) * 1000)

            if response.status_code == 200:
                data = response.json()

                result = {
                    'is_malicious': data.get('classification') == 'malicious',
                    'confidence': 80 if data.get('classification') == 'malicious' else 20,
                    'classification': data.get('classification'),
                    'name': data.get('name')
                }

                self.integration_mgr.log_request('greynoise', 'check_ip', True, response_time)
                self.integration_mgr.update_health_status('greynoise', 'healthy')
                return result
            else:
                self.integration_mgr.log_request('greynoise', 'check_ip', False, response_time, response.text)
                return None

        except Exception as e:
            logger.error(f"GreyNoise check failed: {e}")
            self.integration_mgr.log_request('greynoise', 'check_ip', False, None, str(e))
            return None

    # =================================================================
    # GEOLOCATION - Get IP location data
    # =================================================================

    def get_ip_geolocation(self, ip: str) -> Optional[Dict[str, Any]]:
        """
        Get geolocation data for an IP address.

        Args:
            ip: IP address to lookup

        Returns:
            Geolocation data dictionary
        """
        # Try IPinfo first (high priority)
        result = self._lookup_ipinfo(ip)
        if result:
            return result

        # Fallback to IP-API (free, no key required)
        result = self._lookup_ip_api(ip)
        if result:
            return result

        return None

    def _lookup_ipinfo(self, ip: str) -> Optional[Dict]:
        """Lookup IP using IPinfo."""
        start_time = time.time()

        try:
            creds = self.integration_mgr.get_integration_credentials('ipinfo')
            if not creds:
                return None

            url = f"https://ipinfo.io/{ip}?token={creds['api_key']}"
            response = requests.get(url, timeout=10)
            response_time = int((time.time() - start_time) * 1000)

            if response.status_code == 200:
                data = response.json()
                self.integration_mgr.log_request('ipinfo', 'lookup_ip', True, response_time)
                self.integration_mgr.update_health_status('ipinfo', 'healthy')
                return data
            else:
                self.integration_mgr.log_request('ipinfo', 'lookup_ip', False, response_time, response.text)
                return None

        except Exception as e:
            logger.error(f"IPinfo lookup failed: {e}")
            self.integration_mgr.log_request('ipinfo', 'lookup_ip', False, None, str(e))
            return None

    def _lookup_ip_api(self, ip: str) -> Optional[Dict]:
        """Lookup IP using IP-API (free, no key)."""
        start_time = time.time()

        try:
            url = f"http://ip-api.com/json/{ip}"
            response = requests.get(url, timeout=10)
            response_time = int((time.time() - start_time) * 1000)

            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    self.integration_mgr.log_request('ip_api', 'lookup_ip', True, response_time)
                    self.integration_mgr.update_health_status('ip_api', 'healthy')
                    return data

            self.integration_mgr.log_request('ip_api', 'lookup_ip', False, response_time, response.text)
            return None

        except Exception as e:
            logger.error(f"IP-API lookup failed: {e}")
            self.integration_mgr.log_request('ip_api', 'lookup_ip', False, None, str(e))
            return None

    # =================================================================
    # WEBHOOKS - Trigger automation workflows
    # =================================================================

    def trigger_zapier_zap(self, data: Dict[str, Any]) -> bool:
        """Trigger a Zapier zap via webhook."""
        start_time = time.time()

        try:
            creds = self.integration_mgr.get_integration_credentials('zapier')
            if not creds or not creds.get('webhook_url'):
                logger.warning("Zapier not configured")
                return False

            response = requests.post(creds['webhook_url'], json=data, timeout=10)
            response_time = int((time.time() - start_time) * 1000)

            success = response.status_code in [200, 201]
            self.integration_mgr.log_request('zapier', 'trigger_zap', success, response_time,
                                            None if success else response.text)

            if success:
                self.integration_mgr.update_health_status('zapier', 'healthy')

            return success

        except Exception as e:
            logger.error(f"Zapier trigger failed: {e}")
            self.integration_mgr.log_request('zapier', 'trigger_zap', False, None, str(e))
            self.integration_mgr.update_health_status('zapier', 'error', str(e))
            return False

    def trigger_ifttt_applet(self, event_name: str, values: Optional[List[str]] = None) -> bool:
        """Trigger an IFTTT applet."""
        start_time = time.time()

        try:
            creds = self.integration_mgr.get_integration_credentials('ifttt')
            if not creds:
                logger.warning("IFTTT not configured")
                return False

            event = creds.get('event_name', event_name)
            url = f"https://maker.ifttt.com/trigger/{event}/with/key/{creds['webhook_key']}"

            payload = {}
            if values:
                for i, value in enumerate(values[:3], 1):  # IFTTT supports up to 3 values
                    payload[f'value{i}'] = value

            response = requests.post(url, json=payload, timeout=10)
            response_time = int((time.time() - start_time) * 1000)

            success = response.status_code == 200
            self.integration_mgr.log_request('ifttt', 'trigger_applet', success, response_time,
                                            None if success else response.text)

            if success:
                self.integration_mgr.update_health_status('ifttt', 'healthy')

            return success

        except Exception as e:
            logger.error(f"IFTTT trigger failed: {e}")
            self.integration_mgr.log_request('ifttt', 'trigger_applet', False, None, str(e))
            self.integration_mgr.update_health_status('ifttt', 'error', str(e))
            return False
