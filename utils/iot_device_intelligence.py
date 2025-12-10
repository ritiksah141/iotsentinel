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

    def learn_baseline(self, device_ip: str, learning_period_days: int = 7) -> Dict:
        """
        Learn device behavior baseline from historical data.

        Calculates baseline metrics from the specified learning period and stores
        them in device_behavior_baselines table. These baselines are used for
        anomaly detection.

        Args:
            device_ip: Device IP address
            learning_period_days: Number of days of historical data to analyze

        Returns:
            Dict with learned baselines for various metrics
        """
        try:
            cursor = self.db.conn.cursor()

            # Minimum data requirement: at least 100 connections
            cursor.execute("""
                SELECT COUNT(*) as count FROM connections
                WHERE device_ip = ?
                AND timestamp >= datetime('now', '-{} days')
            """.format(learning_period_days), (device_ip,))

            total_connections = cursor.fetchone()['count']

            if total_connections < 100:
                logger.warning(
                    f"Insufficient data for baseline learning on {device_ip}: "
                    f"only {total_connections} connections (need 100+)"
                )
                return {'status': 'insufficient_data', 'connections': total_connections}

            baselines = {}

            # 1. Connections per hour metric
            cursor.execute("""
                SELECT
                    strftime('%Y-%m-%d %H', timestamp) as hour,
                    COUNT(*) as hourly_count
                FROM connections
                WHERE device_ip = ?
                AND timestamp >= datetime('now', '-{} days')
                GROUP BY hour
            """.format(learning_period_days), (device_ip,))

            hourly_data = [row['hourly_count'] for row in cursor.fetchall()]

            if hourly_data:
                baselines['hourly_connections'] = self._calculate_baseline_stats(hourly_data)

            # 2. Bytes sent per connection
            cursor.execute("""
                SELECT bytes_sent FROM connections
                WHERE device_ip = ?
                AND timestamp >= datetime('now', '-{} days')
                AND bytes_sent IS NOT NULL
            """.format(learning_period_days), (device_ip,))

            bytes_sent_data = [row['bytes_sent'] for row in cursor.fetchall() if row['bytes_sent'] > 0]

            if bytes_sent_data:
                baselines['bytes_sent_per_connection'] = self._calculate_baseline_stats(bytes_sent_data)

            # 3. Bytes received per connection
            cursor.execute("""
                SELECT bytes_received FROM connections
                WHERE device_ip = ?
                AND timestamp >= datetime('now', '-{} days')
                AND bytes_received IS NOT NULL
            """.format(learning_period_days), (device_ip,))

            bytes_recv_data = [row['bytes_received'] for row in cursor.fetchall() if row['bytes_received'] > 0]

            if bytes_recv_data:
                baselines['bytes_received_per_connection'] = self._calculate_baseline_stats(bytes_recv_data)

            # 4. Unique destinations per hour
            cursor.execute("""
                SELECT
                    strftime('%Y-%m-%d %H', timestamp) as hour,
                    COUNT(DISTINCT dest_ip) as unique_dests
                FROM connections
                WHERE device_ip = ?
                AND timestamp >= datetime('now', '-{} days')
                GROUP BY hour
            """.format(learning_period_days), (device_ip,))

            unique_dests_data = [row['unique_dests'] for row in cursor.fetchall()]

            if unique_dests_data:
                baselines['unique_destinations_per_hour'] = self._calculate_baseline_stats(unique_dests_data)

            # 5. Connection duration
            cursor.execute("""
                SELECT duration FROM connections
                WHERE device_ip = ?
                AND timestamp >= datetime('now', '-{} days')
                AND duration IS NOT NULL AND duration > 0
            """.format(learning_period_days), (device_ip,))

            duration_data = [row['duration'] for row in cursor.fetchall()]

            if duration_data:
                baselines['connection_duration_seconds'] = self._calculate_baseline_stats(duration_data)

            # Save all baselines to database
            for metric_name, stats in baselines.items():
                self._save_baseline(device_ip, metric_name, stats)

            logger.info(
                f"Learned {len(baselines)} baseline metrics for {device_ip} "
                f"from {total_connections} connections over {learning_period_days} days"
            )

            return {
                'status': 'success',
                'device_ip': device_ip,
                'baselines': baselines,
                'learning_period_days': learning_period_days,
                'sample_connections': total_connections,
                'timestamp': datetime.now().isoformat()
            }

        except Exception as e:
            logger.error(f"Error learning baseline for {device_ip}: {e}")
            return {'status': 'error', 'error': str(e)}

    def _calculate_baseline_stats(self, data: List[float]) -> Dict:
        """
        Calculate statistical baseline from a list of values.

        Args:
            data: List of numeric values

        Returns:
            Dict with baseline, std_deviation, min, max, sample_count
        """
        if not data:
            return {}

        import statistics

        baseline = statistics.mean(data)
        std_dev = statistics.stdev(data) if len(data) > 1 else 0
        min_val = min(data)
        max_val = max(data)

        return {
            'baseline_value': round(baseline, 2),
            'std_deviation': round(std_dev, 2),
            'min_value': round(min_val, 2),
            'max_value': round(max_val, 2),
            'sample_count': len(data)
        }

    def _save_baseline(self, device_ip: str, metric_name: str, stats: Dict):
        """Save baseline to database."""
        try:
            cursor = self.db.conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO device_behavior_baselines (
                    device_ip, metric_name, baseline_value, std_deviation,
                    min_value, max_value, sample_count, last_updated
                ) VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """, (
                device_ip,
                metric_name,
                stats.get('baseline_value', 0),
                stats.get('std_deviation', 0),
                stats.get('min_value', 0),
                stats.get('max_value', 0),
                stats.get('sample_count', 0)
            ))
            self.db.conn.commit()
        except Exception as e:
            logger.error(f"Failed to save baseline {metric_name} for {device_ip}: {e}")

    def get_baselines(self, device_ip: str) -> Dict:
        """
        Get learned baselines for a device.

        Args:
            device_ip: Device IP address

        Returns:
            Dict mapping metric names to baseline stats
        """
        try:
            cursor = self.db.conn.cursor()
            cursor.execute("""
                SELECT metric_name, baseline_value, std_deviation,
                       min_value, max_value, sample_count, last_updated
                FROM device_behavior_baselines
                WHERE device_ip = ?
            """, (device_ip,))

            baselines = {}
            for row in cursor.fetchall():
                baselines[row['metric_name']] = {
                    'baseline_value': row['baseline_value'],
                    'std_deviation': row['std_deviation'],
                    'min_value': row['min_value'],
                    'max_value': row['max_value'],
                    'sample_count': row['sample_count'],
                    'last_updated': row['last_updated']
                }

            return baselines

        except Exception as e:
            logger.error(f"Error getting baselines for {device_ip}: {e}")
            return {}

    def get_device_type_rules(self, device_type: str) -> Dict:
        """
        Get behavioral rules specific to device type.

        Different IoT device types have different expected behaviors.
        These rules define normal behavior patterns and security thresholds.

        Args:
            device_type: Device type (e.g., 'IP Camera', 'Smart Speaker')

        Returns:
            Dict with device type-specific rules and thresholds
        """
        # Define device type-specific behavioral rules
        device_rules = {
            'IP Camera': {
                'expected_behavior': 'High continuous upload, low download',
                'typical_upload_ratio': 0.8,  # 80% upload vs download
                'max_hourly_connections': 50,
                'max_unique_destinations': 5,  # Should only talk to NVR/cloud
                'expected_protocols': ['http', 'https', 'rtsp'],
                'suspicious_ports': [23, 22, 3389],  # Telnet, SSH, RDP suspicious
                'data_sensitivity': 'high',
                'security_priority': 'critical'
            },
            'DVR/NVR': {
                'expected_behavior': 'High upload/download, moderate connections',
                'typical_upload_ratio': 0.6,
                'max_hourly_connections': 100,
                'max_unique_destinations': 10,
                'expected_protocols': ['http', 'https', 'rtsp'],
                'suspicious_ports': [23, 22],
                'data_sensitivity': 'high',
                'security_priority': 'critical'
            },
            'Smart Speaker': {
                'expected_behavior': 'Moderate bidirectional traffic, cloud-dependent',
                'typical_upload_ratio': 0.4,  # More download (music streaming)
                'max_hourly_connections': 200,
                'max_unique_destinations': 20,
                'expected_protocols': ['https', 'http', 'mdns'],
                'suspicious_ports': [23, 22, 3389],
                'data_sensitivity': 'high',  # Voice recordings
                'security_priority': 'high'
            },
            'Smart Lock': {
                'expected_behavior': 'Very low traffic, event-driven only',
                'typical_upload_ratio': 0.5,
                'max_hourly_connections': 10,  # Very few connections
                'max_unique_destinations': 3,
                'expected_protocols': ['https'],
                'suspicious_ports': [23, 22, 80],  # Unencrypted suspicious
                'data_sensitivity': 'critical',
                'security_priority': 'critical'
            },
            'Thermostat': {
                'expected_behavior': 'Low periodic traffic',
                'typical_upload_ratio': 0.5,
                'max_hourly_connections': 20,
                'max_unique_destinations': 5,
                'expected_protocols': ['https', 'http'],
                'suspicious_ports': [23, 22],
                'data_sensitivity': 'low',
                'security_priority': 'medium'
            },
            'Smart Plug': {
                'expected_behavior': 'Very low traffic, command-response only',
                'typical_upload_ratio': 0.5,
                'max_hourly_connections': 15,
                'max_unique_destinations': 3,
                'expected_protocols': ['https', 'http', 'mqtt'],
                'suspicious_ports': [23, 22],
                'data_sensitivity': 'low',
                'security_priority': 'medium'
            },
            'Router': {
                'expected_behavior': 'High bidirectional traffic, gateway role',
                'typical_upload_ratio': 0.5,
                'max_hourly_connections': 1000,
                'max_unique_destinations': 100,
                'expected_protocols': ['http', 'https', 'dns', 'dhcp'],
                'suspicious_ports': [23],  # Telnet suspicious
                'data_sensitivity': 'critical',  # Network gateway
                'security_priority': 'critical'
            },
            'Smart TV': {
                'expected_behavior': 'High download (streaming), moderate upload',
                'typical_upload_ratio': 0.2,  # Mostly download
                'max_hourly_connections': 300,
                'max_unique_destinations': 30,
                'expected_protocols': ['https', 'http', 'mdns'],
                'suspicious_ports': [23, 22],
                'data_sensitivity': 'medium',  # Viewing habits
                'security_priority': 'medium'
            },
            'Printer': {
                'expected_behavior': 'Low sporadic traffic',
                'typical_upload_ratio': 0.3,  # Receiving print jobs
                'max_hourly_connections': 30,
                'max_unique_destinations': 10,
                'expected_protocols': ['http', 'https', 'ipp', 'mdns'],
                'suspicious_ports': [23, 22],
                'data_sensitivity': 'medium',  # Document content
                'security_priority': 'medium'
            }
        }

        # Return rules for specific device type, or generic rules
        return device_rules.get(device_type, {
            'expected_behavior': 'Generic IoT device',
            'typical_upload_ratio': 0.5,
            'max_hourly_connections': 50,
            'max_unique_destinations': 10,
            'expected_protocols': ['https', 'http'],
            'suspicious_ports': [23, 22],
            'data_sensitivity': 'medium',
            'security_priority': 'medium'
        })

    def check_device_type_compliance(self, device_ip: str) -> Dict:
        """
        Check if device behavior complies with device type-specific rules.

        Args:
            device_ip: Device IP address

        Returns:
            Dict with compliance results and violations
        """
        try:
            cursor = self.db.conn.cursor()

            # Get device type
            cursor.execute("""
                SELECT device_type, device_name FROM devices
                WHERE device_ip = ?
            """, (device_ip,))

            device = cursor.fetchone()
            if not device:
                return {'status': 'error', 'message': 'Device not found'}

            device_type = device['device_type']
            rules = self.get_device_type_rules(device_type)

            violations = []

            # Check 1: Connection count compliance
            cursor.execute("""
                SELECT COUNT(*) as hourly_count
                FROM connections
                WHERE device_ip = ?
                AND timestamp >= datetime('now', '-1 hour')
            """, (device_ip,))

            hourly_conns = cursor.fetchone()['hourly_count']
            if hourly_conns > rules['max_hourly_connections']:
                violations.append({
                    'rule': 'max_hourly_connections',
                    'expected': rules['max_hourly_connections'],
                    'actual': hourly_conns,
                    'severity': 'medium',
                    'message': f"Exceeds expected connection rate for {device_type}"
                })

            # Check 2: Unique destinations compliance
            cursor.execute("""
                SELECT COUNT(DISTINCT dest_ip) as unique_dests
                FROM connections
                WHERE device_ip = ?
                AND timestamp >= datetime('now', '-1 hour')
            """, (device_ip,))

            unique_dests = cursor.fetchone()['unique_dests']
            if unique_dests > rules['max_unique_destinations']:
                violations.append({
                    'rule': 'max_unique_destinations',
                    'expected': rules['max_unique_destinations'],
                    'actual': unique_dests,
                    'severity': 'high',
                    'message': f"Contacting too many destinations for {device_type} (possible scanning)"
                })

            # Check 3: Suspicious port usage
            if rules['suspicious_ports']:
                cursor.execute("""
                    SELECT DISTINCT dest_port
                    FROM connections
                    WHERE device_ip = ?
                    AND dest_port IN ({})
                    AND timestamp >= datetime('now', '-24 hours')
                """.format(','.join('?' * len(rules['suspicious_ports']))),
                    [device_ip] + rules['suspicious_ports']
                )

                suspicious = [row['dest_port'] for row in cursor.fetchall()]
                if suspicious:
                    violations.append({
                        'rule': 'suspicious_ports',
                        'expected': 'No suspicious ports',
                        'actual': suspicious,
                        'severity': 'critical',
                        'message': f"{device_type} using suspicious ports (possible compromise)"
                    })

            compliance_score = max(0, 100 - (len(violations) * 25))

            return {
                'device_ip': device_ip,
                'device_type': device_type,
                'compliance_score': compliance_score,
                'violations': violations,
                'rules_checked': ['connections', 'destinations', 'ports'],
                'security_priority': rules['security_priority'],
                'timestamp': datetime.now().isoformat()
            }

        except Exception as e:
            logger.error(f"Error checking device type compliance: {e}")
            return {'status': 'error', 'message': str(e)}


# Singleton instance
_intelligence_instance = None


def get_intelligence(db_manager) -> IoTDeviceIntelligence:
    """Get or create IoT Device Intelligence singleton."""
    global _intelligence_instance
    if _intelligence_instance is None:
        _intelligence_instance = IoTDeviceIntelligence(db_manager)
    return _intelligence_instance
