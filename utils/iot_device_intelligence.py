#!/usr/bin/env python3
"""
IoT Device Intelligence Module

Provides advanced device fingerprinting, classification, and vulnerability detection
specifically designed for IoT devices.

Features:
- Multi-signal device fingerprinting (OS, firmware, services)
- CVE vulnerability matching
- Device behavior profiling
- IoT-specific threat detection
"""

import json
import logging
import re
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import sqlite3

logger = logging.getLogger(__name__)


class IoTDeviceIntelligence:
    """Advanced IoT device intelligence and fingerprinting."""

    def __init__(self, db_manager):
        """
        Initialize IoT Device Intelligence.

        Args:
            db_manager: DatabaseManager instance
        """
        self.db = db_manager

        # OS fingerprint patterns
        self.os_patterns = {
            'Linux': [
                r'Linux/(\d+\.\d+)',
                r'GNU/Linux',
                r'busybox',
                r'dropbear'
            ],
            'Android': [
                r'Android[/ ](\d+\.\d+)',
                r'dalvik'
            ],
            'iOS': [
                r'iOS[/ ](\d+\.\d+)',
                r'iPhone OS'
            ],
            'RTOS': [
                r'FreeRTOS',
                r'ThreadX',
                r'VxWorks',
                r'Contiki'
            ],
            'Windows IoT': [
                r'Windows IoT',
                r'Windows Embedded'
            ]
        }

        # Known IoT device families by manufacturer + model
        self.device_families = {
            'Ring': ['Camera', 'Doorbell', 'Alarm'],
            'Nest': ['Thermostat', 'Camera', 'Hub'],
            'Philips Hue': ['Bulb', 'Bridge', 'Motion Sensor'],
            'TP-Link': ['Plug', 'Bulb', 'Camera'],
            'Amazon Echo': ['Speaker', 'Display'],
            'Google Home': ['Speaker', 'Display', 'Chromecast'],
            'Sonos': ['Speaker'],
            'Wyze': ['Camera', 'Plug', 'Lock'],
            'Arlo': ['Camera', 'Doorbell'],
            'Ecobee': ['Thermostat', 'Sensor']
        }

        # Critical CVE database for common IoT vulnerabilities
        self.critical_cves = {
            'Mirai_RCE': {
                'cve_id': 'CVE-2016-10401',
                'title': 'Mirai Botnet Vulnerability',
                'severity': 'critical',
                'affected_vendors': ['Various IoT manufacturers'],
                'description': 'Default credentials and telnet exploitation'
            },
            'UPnP_RCE': {
                'cve_id': 'CVE-2020-12695',
                'title': 'CallStranger UPnP Vulnerability',
                'severity': 'high',
                'affected_vendors': ['Various UPnP implementations'],
                'description': 'UPnP SUBSCRIBE vulnerability allowing RCE and DDoS'
            }
        }

    def fingerprint_device(self, device_ip: str, **signals) -> Dict:
        """
        Create comprehensive device fingerprint using multiple signals.

        Args:
            device_ip: Device IP address
            **signals: Various fingerprinting signals
                - http_user_agent: User agent string from HTTP traffic
                - dhcp_fingerprint: DHCP fingerprint
                - open_ports: List of open ports
                - services: List of detected services
                - mdns_services: mDNS advertised services
                - upnp_services: UPnP advertised services
                - tls_fingerprint: JA3 fingerprint

        Returns:
            Dict with fingerprint results
        """
        fingerprint = {
            'device_ip': device_ip,
            'timestamp': datetime.now().isoformat(),
            'os_detected': None,
            'os_version': None,
            'os_confidence': 0.0,
            'device_family': None,
            'hardware_model': None,
            'open_ports': signals.get('open_ports', []),
            'services_detected': signals.get('services', []),
            'http_user_agent': signals.get('http_user_agent'),
            'dhcp_fingerprint': signals.get('dhcp_fingerprint'),
            'mdns_services': signals.get('mdns_services', []),
            'upnp_services': signals.get('upnp_services', []),
            'tls_fingerprint': signals.get('tls_fingerprint')
        }

        # Detect OS from user agent
        if signals.get('http_user_agent'):
            os_info = self._detect_os(signals['http_user_agent'])
            fingerprint['os_detected'] = os_info['os']
            fingerprint['os_version'] = os_info['version']
            fingerprint['os_confidence'] = os_info['confidence']

        # Detect device family from services/ports
        device_family = self._detect_device_family(
            mdns_services=signals.get('mdns_services', []),
            upnp_services=signals.get('upnp_services', []),
            open_ports=signals.get('open_ports', [])
        )
        fingerprint['device_family'] = device_family

        # Save fingerprint to database
        self._save_fingerprint(fingerprint)

        return fingerprint

    def _detect_os(self, user_agent: str) -> Dict:
        """Detect operating system from user agent string."""
        for os_name, patterns in self.os_patterns.items():
            for pattern in patterns:
                match = re.search(pattern, user_agent, re.IGNORECASE)
                if match:
                    version = match.group(1) if match.groups() else None
                    return {
                        'os': os_name,
                        'version': version,
                        'confidence': 0.9
                    }

        return {'os': 'Unknown', 'version': None, 'confidence': 0.0}

    def _detect_device_family(self, mdns_services: List[str],
                              upnp_services: List[str],
                              open_ports: List[int]) -> Optional[str]:
        """Detect device family from advertised services."""
        # Check mDNS services
        for service in mdns_services:
            if 'hue' in service.lower():
                return 'Philips Hue'
            elif 'sonos' in service.lower():
                return 'Sonos'
            elif 'airplay' in service.lower():
                return 'Apple HomeKit'
            elif 'googlecast' in service.lower():
                return 'Google Home'

        # Check UPnP services
        for service in upnp_services:
            if 'ring' in service.lower():
                return 'Ring'
            elif 'nest' in service.lower():
                return 'Nest'
            elif 'wemo' in service.lower():
                return 'Belkin WeMo'

        # Check ports for common IoT services
        if 1883 in open_ports or 8883 in open_ports:
            return 'MQTT Device'
        if 5683 in open_ports:
            return 'CoAP Device'

        return None

    def _save_fingerprint(self, fingerprint: Dict):
        """Save device fingerprint to database."""
        try:
            cursor = self.db.conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO device_fingerprints (
                    device_ip, os_detected, os_version, os_confidence,
                    device_family, hardware_model, open_ports,
                    services_detected, http_user_agent, dhcp_fingerprint,
                    mdns_services, upnp_services, tls_fingerprint,
                    last_fingerprint_update
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """, (
                fingerprint['device_ip'],
                fingerprint['os_detected'],
                fingerprint['os_version'],
                fingerprint['os_confidence'],
                fingerprint['device_family'],
                fingerprint.get('hardware_model'),
                json.dumps(fingerprint['open_ports']),
                json.dumps(fingerprint['services_detected']),
                fingerprint.get('http_user_agent'),
                fingerprint.get('dhcp_fingerprint'),
                json.dumps(fingerprint['mdns_services']),
                json.dumps(fingerprint['upnp_services']),
                fingerprint.get('tls_fingerprint')
            ))
            self.db.conn.commit()
            logger.info(f"Saved fingerprint for {fingerprint['device_ip']}")
        except Exception as e:
            logger.error(f"Failed to save fingerprint: {e}")

    def check_vulnerabilities(self, device_ip: str) -> List[Dict]:
        """
        Check device for known CVE vulnerabilities based on fingerprint.

        Args:
            device_ip: Device IP address

        Returns:
            List of detected vulnerabilities
        """
        vulnerabilities = []

        try:
            # Get device information
            cursor = self.db.conn.cursor()

            # Get device metadata
            cursor.execute("""
                SELECT manufacturer, device_type, firmware_version, model
                FROM devices WHERE device_ip = ?
            """, (device_ip,))
            device_info = cursor.fetchone()

            if not device_info:
                return vulnerabilities

            manufacturer = device_info['manufacturer'] if device_info else None
            device_type = device_info['device_type'] if device_info else None
            firmware = device_info['firmware_version'] if device_info else None

            # Get device fingerprint
            cursor.execute("""
                SELECT os_detected, open_ports, services_detected
                FROM device_fingerprints WHERE device_ip = ?
            """, (device_ip,))
            fingerprint = cursor.fetchone()

            if fingerprint:
                open_ports = json.loads(fingerprint['open_ports']) if fingerprint['open_ports'] else []

                # Check for Mirai vulnerability (open telnet)
                if 23 in open_ports or 2323 in open_ports:
                    vuln = self._check_mirai_vulnerability(device_ip, manufacturer)
                    if vuln:
                        vulnerabilities.append(vuln)

                # Check for UPnP vulnerability
                if 1900 in open_ports:
                    vuln = self._check_upnp_vulnerability(device_ip)
                    if vuln:
                        vulnerabilities.append(vuln)

            # Query IoT vulnerabilities database
            cursor.execute("""
                SELECT * FROM iot_vulnerabilities
                WHERE (affected_vendors LIKE ? OR affected_vendors LIKE '%Various%')
                AND severity IN ('high', 'critical')
            """, (f'%{manufacturer}%' if manufacturer else '%',))

            cve_vulns = cursor.fetchall()
            for cve in cve_vulns:
                vulnerabilities.append({
                    'cve_id': cve['cve_id'],
                    'title': cve['title'],
                    'severity': cve['severity'],
                    'cvss_score': cve['cvss_score'],
                    'description': cve['description']
                })

            # Save detected vulnerabilities
            for vuln in vulnerabilities:
                self._save_vulnerability_detection(device_ip, vuln)

        except Exception as e:
            logger.error(f"Error checking vulnerabilities: {e}")

        return vulnerabilities

    def _check_mirai_vulnerability(self, device_ip: str, manufacturer: Optional[str]) -> Optional[Dict]:
        """Check for Mirai botnet vulnerability."""
        # Devices with open telnet are susceptible to Mirai
        risk_score = 9.5  # High risk for IoT devices

        return {
            'cve_id': 'CVE-2016-10401',
            'title': 'Mirai Botnet Susceptibility',
            'severity': 'critical',
            'cvss_score': risk_score,
            'description': 'Device has open Telnet port and may be vulnerable to Mirai-style attacks using default credentials',
            'mitigation': 'Disable Telnet, change default passwords, enable SSH with key-based auth'
        }

    def _check_upnp_vulnerability(self, device_ip: str) -> Optional[Dict]:
        """Check for UPnP vulnerabilities."""
        return {
            'cve_id': 'CVE-2020-12695',
            'title': 'UPnP CallStranger Vulnerability',
            'severity': 'high',
            'cvss_score': 7.5,
            'description': 'Device uses UPnP which may be vulnerable to CallStranger attacks',
            'mitigation': 'Disable UPnP if not needed, update firmware, isolate device on separate VLAN'
        }

    def _save_vulnerability_detection(self, device_ip: str, vulnerability: Dict):
        """Save detected vulnerability to database."""
        try:
            cursor = self.db.conn.cursor()

            # Ensure CVE exists in vulnerabilities table
            cursor.execute("""
                INSERT OR IGNORE INTO iot_vulnerabilities (
                    cve_id, title, severity, cvss_score, description
                ) VALUES (?, ?, ?, ?, ?)
            """, (
                vulnerability['cve_id'],
                vulnerability['title'],
                vulnerability['severity'],
                vulnerability.get('cvss_score', 0.0),
                vulnerability.get('description', '')
            ))

            # Link vulnerability to device
            cursor.execute("""
                INSERT OR IGNORE INTO device_vulnerabilities_detected (
                    device_ip, cve_id, risk_score, auto_detected
                ) VALUES (?, ?, ?, 1)
            """, (
                device_ip,
                vulnerability['cve_id'],
                vulnerability.get('cvss_score', 0.0)
            ))

            self.db.conn.commit()
            logger.info(f"Saved vulnerability {vulnerability['cve_id']} for {device_ip}")
        except Exception as e:
            logger.error(f"Failed to save vulnerability: {e}")

    def analyze_behavior(self, device_ip: str, window_hours: int = 24) -> Dict:
        """
        Analyze device behavior patterns over time window.

        Args:
            device_ip: Device IP address
            window_hours: Analysis window in hours

        Returns:
            Dict with behavior analysis
        """
        try:
            cursor = self.db.conn.cursor()

            # Get connection patterns
            cursor.execute("""
                SELECT
                    COUNT(*) as total_connections,
                    COUNT(DISTINCT dest_ip) as unique_destinations,
                    COUNT(DISTINCT dest_port) as unique_ports,
                    SUM(bytes_sent) as total_bytes_sent,
                    SUM(bytes_received) as total_bytes_received,
                    AVG(duration) as avg_duration
                FROM connections
                WHERE device_ip = ?
                AND timestamp >= datetime('now', '-{} hours')
            """.format(window_hours), (device_ip,))

            stats = cursor.fetchone()

            # Get protocol distribution
            cursor.execute("""
                SELECT protocol, COUNT(*) as count
                FROM connections
                WHERE device_ip = ?
                AND timestamp >= datetime('now', '-{} hours')
                GROUP BY protocol
            """.format(window_hours), (device_ip,))

            protocols = {row['protocol']: row['count'] for row in cursor.fetchall()}

            # Get top destinations
            cursor.execute("""
                SELECT dest_ip, COUNT(*) as count
                FROM connections
                WHERE device_ip = ?
                AND timestamp >= datetime('now', '-{} hours')
                GROUP BY dest_ip
                ORDER BY count DESC
                LIMIT 5
            """.format(window_hours), (device_ip,))

            top_destinations = [
                {'ip': row['dest_ip'], 'count': row['count']}
                for row in cursor.fetchall()
            ]

            behavior = {
                'device_ip': device_ip,
                'window_hours': window_hours,
                'total_connections': stats['total_connections'] or 0,
                'unique_destinations': stats['unique_destinations'] or 0,
                'unique_ports': stats['unique_ports'] or 0,
                'total_bytes_sent': stats['total_bytes_sent'] or 0,
                'total_bytes_received': stats['total_bytes_received'] or 0,
                'avg_connection_duration': stats['avg_duration'] or 0,
                'protocols': protocols,
                'top_destinations': top_destinations
            }

            return behavior

        except Exception as e:
            logger.error(f"Error analyzing behavior: {e}")
            return {}

    def calculate_iot_security_score(self, device_ip: str) -> Dict:
        """
        Calculate comprehensive IoT security score (0-100).

        Args:
            device_ip: Device IP address

        Returns:
            Dict with score and breakdown
        """
        score = 100  # Start with perfect score
        deductions = []

        try:
            cursor = self.db.conn.cursor()

            # Get device info
            cursor.execute("""
                SELECT is_trusted, firmware_version, device_type
                FROM devices WHERE device_ip = ?
            """, (device_ip,))
            device = cursor.fetchone()

            if not device:
                return {'score': 0, 'deductions': ['Device not found']}

            # Check for known vulnerabilities (-30 points each, up to -60)
            cursor.execute("""
                SELECT COUNT(*) as vuln_count
                FROM device_vulnerabilities_detected
                WHERE device_ip = ? AND status = 'active'
            """, (device_ip,))
            vuln_count = cursor.fetchone()['vuln_count']

            if vuln_count > 0:
                deduction = min(vuln_count * 30, 60)
                score -= deduction
                deductions.append(f"Active vulnerabilities: -{deduction}")

            # Check firmware version (-15 if unknown)
            if not device['firmware_version']:
                score -= 15
                deductions.append("Unknown firmware version: -15")

            # Check if device is isolated (-20 if not)
            cursor.execute("""
                SELECT segment_id FROM device_segments
                WHERE device_ip = ? AND current_segment = 1
            """, (device_ip,))
            segment = cursor.fetchone()

            if not segment:
                score -= 20
                deductions.append("Not on isolated network: -20")

            # Check for encryption usage (-10 if no encryption)
            cursor.execute("""
                SELECT encryption_used FROM protocol_stats
                WHERE device_ip = ? AND encryption_used = 1
            """, (device_ip,))
            has_encryption = cursor.fetchone()

            if not has_encryption:
                score -= 10
                deductions.append("No encrypted protocols detected: -10")

            # Check trust status (+5 if trusted)
            if device['is_trusted']:
                score += 5

            # Ensure score stays in bounds
            score = max(0, min(100, score))

            return {
                'device_ip': device_ip,
                'score': score,
                'deductions': deductions,
                'grade': self._score_to_grade(score),
                'timestamp': datetime.now().isoformat()
            }

        except Exception as e:
            logger.error(f"Error calculating security score: {e}")
            return {'score': 0, 'deductions': ['Error calculating score']}

    def _score_to_grade(self, score: int) -> str:
        """Convert numeric score to letter grade."""
        if score >= 90:
            return 'A'
        elif score >= 80:
            return 'B'
        elif score >= 70:
            return 'C'
        elif score >= 60:
            return 'D'
        else:
            return 'F'


# Singleton instance
_intelligence_instance = None


def get_intelligence(db_manager) -> IoTDeviceIntelligence:
    """Get or create IoT Device Intelligence singleton."""
    global _intelligence_instance
    if _intelligence_instance is None:
        _intelligence_instance = IoTDeviceIntelligence(db_manager)
    return _intelligence_instance
