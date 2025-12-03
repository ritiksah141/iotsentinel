#!/usr/bin/env python3
"""
Threat Intelligence Module for IoTSentinel
Provides IP reputation lookups using AbuseIPDB API with local caching
"""

import logging
import sqlite3
import requests
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from pathlib import Path

logger = logging.getLogger(__name__)


class ThreatIntelligence:
    """
    IP reputation lookup service with caching.
    Uses AbuseIPDB API (free tier: 1,000 lookups/day)
    """

    def __init__(self, api_key: str, db_path: str, cache_hours: int = 24):
        """
        Initialize threat intelligence service.

        Args:
            api_key: AbuseIPDB API key
            db_path: Path to SQLite database for caching
            cache_hours: Hours to cache results (default 24)
        """
        self.api_key = api_key
        self.db_path = db_path
        self.cache_hours = cache_hours
        self.api_url = "https://api.abuseipdb.com/api/v2/check"
        self.enabled = bool(api_key and api_key != "your_api_key_here")

        if self.enabled:
            self._init_database()
            logger.info("Threat Intelligence enabled with AbuseIPDB")
        else:
            logger.warning("Threat Intelligence disabled - no valid API key")

    def _init_database(self):
        """Create ip_reputation table if it doesn't exist"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS ip_reputation (
                    ip_address TEXT PRIMARY KEY,
                    abuse_confidence_score INTEGER,
                    country_code TEXT,
                    usage_type TEXT,
                    isp TEXT,
                    domain TEXT,
                    total_reports INTEGER,
                    num_distinct_users INTEGER,
                    last_reported_at TEXT,
                    categories TEXT,
                    is_whitelisted INTEGER,
                    reputation_level TEXT,
                    last_checked TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()
            conn.close()
            logger.info("IP reputation cache table initialized")
        except sqlite3.Error as e:
            logger.error(f"Error initializing ip_reputation table: {e}")

    def _get_cached_reputation(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """
        Check if IP reputation is cached and still valid.

        Args:
            ip_address: IP address to check

        Returns:
            Cached reputation data or None if expired/missing
        """
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            # Check if we have recent data
            cutoff_time = datetime.now() - timedelta(hours=self.cache_hours)
            cursor.execute("""
                SELECT * FROM ip_reputation
                WHERE ip_address = ? AND last_checked > ?
            """, (ip_address, cutoff_time.isoformat()))

            row = cursor.fetchone()
            conn.close()

            if row:
                return dict(row)
            return None

        except sqlite3.Error as e:
            logger.error(f"Error checking cache for {ip_address}: {e}")
            return None

    def _cache_reputation(self, ip_address: str, data: Dict[str, Any]):
        """
        Cache IP reputation data.

        Args:
            ip_address: IP address
            data: Reputation data from API
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute("""
                INSERT OR REPLACE INTO ip_reputation (
                    ip_address, abuse_confidence_score, country_code, usage_type,
                    isp, domain, total_reports, num_distinct_users,
                    last_reported_at, categories, is_whitelisted, reputation_level,
                    last_checked
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                ip_address,
                data.get('abuse_confidence_score', 0),
                data.get('country_code', 'Unknown'),
                data.get('usage_type', 'Unknown'),
                data.get('isp', 'Unknown'),
                data.get('domain', ''),
                data.get('total_reports', 0),
                data.get('num_distinct_users', 0),
                data.get('last_reported_at', ''),
                data.get('categories', ''),
                data.get('is_whitelisted', 0),
                data.get('reputation_level', 'unknown'),
                datetime.now().isoformat()
            ))

            conn.commit()
            conn.close()

        except sqlite3.Error as e:
            logger.error(f"Error caching reputation for {ip_address}: {e}")

    def _query_abuseipdb(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """
        Query AbuseIPDB API for IP reputation.

        Args:
            ip_address: IP address to check

        Returns:
            Reputation data or None on error
        """
        try:
            headers = {
                'Key': self.api_key,
                'Accept': 'application/json'
            }

            params = {
                'ipAddress': ip_address,
                'maxAgeInDays': 90,  # Check reports from last 90 days
                'verbose': ''
            }

            response = requests.get(
                self.api_url,
                headers=headers,
                params=params,
                timeout=5
            )

            if response.status_code == 200:
                result = response.json()
                if 'data' in result:
                    return result['data']
                else:
                    logger.warning(f"Unexpected API response for {ip_address}")
                    return None

            elif response.status_code == 429:
                logger.warning("AbuseIPDB rate limit reached")
                return None

            else:
                logger.error(f"AbuseIPDB API error {response.status_code}: {response.text}")
                return None

        except requests.exceptions.Timeout:
            logger.warning(f"AbuseIPDB API timeout for {ip_address}")
            return None
        except requests.exceptions.RequestException as e:
            logger.error(f"Error querying AbuseIPDB for {ip_address}: {e}")
            return None

    def get_ip_reputation(self, ip_address: str) -> Dict[str, Any]:
        """
        Get IP reputation with caching.

        Args:
            ip_address: IP address to check

        Returns:
            Dictionary with reputation data:
            {
                'ip_address': str,
                'reputation_level': 'safe'|'suspicious'|'malicious'|'unknown',
                'abuse_confidence_score': int (0-100),
                'country_code': str,
                'isp': str,
                'total_reports': int,
                'categories': list,
                'last_reported_at': str,
                'is_cached': bool,
                'recommendation': str
            }
        """
        if not self.enabled:
            return self._create_disabled_response(ip_address)

        # Check if IP is private (RFC 1918)
        if self._is_private_ip(ip_address):
            return self._create_private_ip_response(ip_address)

        # Check cache first
        cached = self._get_cached_reputation(ip_address)
        if cached:
            logger.debug(f"Using cached reputation for {ip_address}")
            return self._format_response(cached, is_cached=True)

        # Query API
        logger.info(f"Querying AbuseIPDB for {ip_address}")
        api_data = self._query_abuseipdb(ip_address)

        if api_data:
            # Determine reputation level
            score = api_data.get('abuseConfidenceScore', 0)
            reputation_level = self._calculate_reputation_level(score)
            api_data['reputation_level'] = reputation_level

            # Parse categories
            categories = api_data.get('reports', [])
            category_list = []
            if categories:
                for report in categories[:5]:  # Top 5 most recent
                    cats = report.get('categories', [])
                    category_list.extend(cats)
            api_data['categories'] = ','.join(map(str, set(category_list)))

            # Cache the result
            self._cache_reputation(ip_address, api_data)

            return self._format_response(api_data, is_cached=False)

        else:
            # API failed, return unknown status
            return self._create_unknown_response(ip_address)

    def _calculate_reputation_level(self, score: int) -> str:
        """Calculate reputation level from abuse confidence score"""
        if score >= 75:
            return 'malicious'
        elif score >= 25:
            return 'suspicious'
        elif score > 0:
            return 'low_risk'
        else:
            return 'safe'

    def _format_response(self, data: Dict[str, Any], is_cached: bool) -> Dict[str, Any]:
        """Format reputation data for consistent output"""
        score = data.get('abuse_confidence_score', 0)
        level = data.get('reputation_level', 'unknown')

        # Parse categories
        categories_str = data.get('categories', '')
        category_list = []
        if categories_str:
            category_ids = [int(c) for c in categories_str.split(',') if c.strip().isdigit()]
            category_list = [self._get_category_name(c) for c in category_ids]

        # Generate recommendation
        recommendation = self._get_recommendation(level, score)

        return {
            'ip_address': data.get('ip_address', 'Unknown'),
            'reputation_level': level,
            'abuse_confidence_score': score,
            'country_code': data.get('country_code', 'Unknown'),
            'isp': data.get('isp', 'Unknown'),
            'domain': data.get('domain', ''),
            'total_reports': data.get('total_reports', 0),
            'num_distinct_users': data.get('num_distinct_users', 0),
            'last_reported_at': data.get('last_reported_at', ''),
            'categories': category_list,
            'is_whitelisted': bool(data.get('is_whitelisted', 0)),
            'is_cached': is_cached,
            'recommendation': recommendation
        }

    def _get_category_name(self, category_id: int) -> str:
        """Map AbuseIPDB category ID to name"""
        categories = {
            3: "Fraud Orders",
            4: "DDoS Attack",
            5: "FTP Brute-Force",
            6: "Ping of Death",
            7: "Phishing",
            8: "Fraud VoIP",
            9: "Open Proxy",
            10: "Web Spam",
            11: "Email Spam",
            12: "Blog Spam",
            13: "VPN IP",
            14: "Port Scan",
            15: "Hacking",
            16: "SQL Injection",
            17: "Spoofing",
            18: "Brute-Force",
            19: "Bad Web Bot",
            20: "Exploited Host",
            21: "Web App Attack",
            22: "SSH",
            23: "IoT Targeted"
        }
        return categories.get(category_id, f"Category {category_id}")

    def _get_recommendation(self, level: str, score: int) -> str:
        """Generate security recommendation based on reputation"""
        if level == 'malicious':
            return f"⛔ BLOCK IMMEDIATELY - High abuse score ({score}/100). This IP is known for malicious activity."
        elif level == 'suspicious':
            return f"⚠️ INVESTIGATE - Moderate abuse score ({score}/100). Monitor this connection closely."
        elif level == 'low_risk':
            return f"ℹ️ CAUTION - Low abuse score ({score}/100). Minimal reports, likely safe but monitor."
        else:
            return "✅ SAFE - No abuse reports found. This IP appears clean."

    def _is_private_ip(self, ip_address: str) -> bool:
        """Check if IP is in private range (RFC 1918)"""
        parts = ip_address.split('.')
        if len(parts) != 4:
            return False

        try:
            first = int(parts[0])
            second = int(parts[1])

            # 10.0.0.0/8
            if first == 10:
                return True
            # 172.16.0.0/12
            if first == 172 and 16 <= second <= 31:
                return True
            # 192.168.0.0/16
            if first == 192 and second == 168:
                return True

            return False
        except ValueError:
            return False

    def _create_private_ip_response(self, ip_address: str) -> Dict[str, Any]:
        """Create response for private IP addresses"""
        return {
            'ip_address': ip_address,
            'reputation_level': 'private',
            'abuse_confidence_score': 0,
            'country_code': 'Local',
            'isp': 'Private Network',
            'domain': '',
            'total_reports': 0,
            'num_distinct_users': 0,
            'last_reported_at': '',
            'categories': [],
            'is_whitelisted': True,
            'is_cached': False,
            'recommendation': '🏠 LOCAL - Private IP address on your network'
        }

    def _create_disabled_response(self, ip_address: str) -> Dict[str, Any]:
        """Create response when threat intelligence is disabled"""
        return {
            'ip_address': ip_address,
            'reputation_level': 'unknown',
            'abuse_confidence_score': 0,
            'country_code': 'Unknown',
            'isp': 'Unknown',
            'domain': '',
            'total_reports': 0,
            'num_distinct_users': 0,
            'last_reported_at': '',
            'categories': [],
            'is_whitelisted': False,
            'is_cached': False,
            'recommendation': 'ℹ️ Threat Intelligence disabled - Configure AbuseIPDB API key to enable'
        }

    def _create_unknown_response(self, ip_address: str) -> Dict[str, Any]:
        """Create response when API query fails"""
        return {
            'ip_address': ip_address,
            'reputation_level': 'unknown',
            'abuse_confidence_score': 0,
            'country_code': 'Unknown',
            'isp': 'Unknown',
            'domain': '',
            'total_reports': 0,
            'num_distinct_users': 0,
            'last_reported_at': '',
            'categories': [],
            'is_whitelisted': False,
            'is_cached': False,
            'recommendation': '❓ UNKNOWN - Unable to check reputation (API error or rate limit)'
        }


# Convenience function for quick lookups
def check_ip(ip_address: str, api_key: str, db_path: str) -> Dict[str, Any]:
    """
    Quick IP reputation check.

    Args:
        ip_address: IP to check
        api_key: AbuseIPDB API key
        db_path: Database path for caching

    Returns:
        Reputation data dictionary
    """
    intel = ThreatIntelligence(api_key, db_path)
    return intel.get_ip_reputation(ip_address)
