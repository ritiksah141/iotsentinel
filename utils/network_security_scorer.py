#!/usr/bin/env python3
"""
Network Security Scorer for IoTSentinel

Calculates aggregate network security score based on:
1. Device Health (firmware status, connectivity)
2. Vulnerabilities (active CVEs, CVSS scores)
3. Encryption (protocol usage, TLS versions)
4. Network Segmentation (device isolation)

Score range: 0-100 (consumer-friendly)
"""

import logging
import sqlite3
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


# Device criticality multipliers
DEVICE_CRITICALITY = {
    'smart_lock': 3.0,
    'router': 3.0,
    'camera': 2.5,
    'smart_speaker': 2.0,
    'thermostat': 1.5,
    'smart_plug': 1.0,
    'smart_bulb': 1.0,
    'tv': 1.0,
    'unknown': 1.0
}


class NetworkSecurityScorer:
    """
    Calculates comprehensive network security score.

    Provides both overall score and breakdown by dimension.
    """

    def __init__(self, db_path: str = 'data/iot_monitor.db'):
        """
        Initialize network security scorer.

        Args:
            db_path: Path to database
        """
        self.db_path = db_path

        logger.info("Network security scorer initialized")

    def calculate_network_score(self) -> Dict[str, Any]:
        """
        Calculate overall network security score.

        Returns:
            Dictionary with overall score and dimensional breakdown
        """
        try:
            # Get all 4 dimensional scores
            device_health = self._calculate_device_health_score()
            vulnerabilities = self._calculate_vulnerabilities_score()
            encryption = self._calculate_encryption_score()
            segmentation = self._calculate_segmentation_score()

            # Calculate weighted overall score
            # All dimensions equally weighted (25% each)
            overall_score = (
                device_health['score'] * 0.25 +
                vulnerabilities['score'] * 0.25 +
                encryption['score'] * 0.25 +
                segmentation['score'] * 0.25
            )

            # Get device count
            device_count = self._get_device_count()

            # Determine grade
            grade = self._score_to_grade(overall_score)

            result = {
                'overall_score': round(overall_score, 1),
                'grade': grade,
                'device_count': device_count,
                'dimensions': {
                    'device_health': device_health,
                    'vulnerabilities': vulnerabilities,
                    'encryption': encryption,
                    'segmentation': segmentation
                },
                'calculated_at': datetime.now().isoformat()
            }

            logger.info(f"Network security score calculated: {overall_score:.1f}/100 ({grade})")

            return result

        except Exception as e:
            logger.error(f"Error calculating network score: {e}")
            return {
                'overall_score': 0,
                'grade': 'F',
                'error': str(e)
            }

    def _calculate_device_health_score(self) -> Dict[str, Any]:
        """
        Calculate device health score based on firmware status and connectivity.

        Returns:
            Dictionary with score and details
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Get all devices
            cursor.execute("SELECT COUNT(*) FROM devices")
            total_devices = cursor.fetchone()[0]

            if total_devices == 0:
                conn.close()
                return {'score': 100, 'details': 'No devices to evaluate'}

            # Get devices with outdated firmware
            # (simplified: check if firmware_version is empty or very old)
            cursor.execute('''
                SELECT COUNT(*) FROM devices
                WHERE firmware_version IS NULL OR firmware_version = ''
            ''')
            no_firmware_info = cursor.fetchone()[0]

            # Get devices last seen recently (within 24 hours)
            cutoff_time = (datetime.now() - timedelta(hours=24)).isoformat()
            cursor.execute('''
                SELECT COUNT(*) FROM devices
                WHERE last_seen > ?
            ''', (cutoff_time,))
            recently_seen = cursor.fetchone()[0]

            conn.close()

            # Calculate score
            firmware_score = ((total_devices - no_firmware_info) / total_devices) * 100
            connectivity_score = (recently_seen / total_devices) * 100

            # Weighted average (firmware 60%, connectivity 40%)
            health_score = firmware_score * 0.6 + connectivity_score * 0.4

            return {
                'score': round(health_score, 1),
                'firmware_score': round(firmware_score, 1),
                'connectivity_score': round(connectivity_score, 1),
                'devices_with_firmware': total_devices - no_firmware_info,
                'devices_online': recently_seen,
                'total_devices': total_devices
            }

        except Exception as e:
            logger.error(f"Error calculating device health score: {e}")
            return {'score': 0, 'error': str(e)}

    def _calculate_vulnerabilities_score(self) -> Dict[str, Any]:
        """
        Calculate vulnerabilities score based on active CVEs.

        Returns:
            Dictionary with score and details
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Get total devices
            cursor.execute("SELECT COUNT(*) FROM devices")
            total_devices = cursor.fetchone()[0]

            if total_devices == 0:
                conn.close()
                return {'score': 100, 'details': 'No devices to evaluate'}

            # Get vulnerability counts by severity (JOIN with iot_vulnerabilities to get severity)
            cursor.execute('''
                SELECT v.severity, COUNT(DISTINCT dv.device_ip)
                FROM device_vulnerabilities_detected dv
                JOIN iot_vulnerabilities v ON dv.cve_id = v.cve_id
                WHERE dv.status = 'active'
                GROUP BY v.severity
            ''')

            vuln_counts = dict(cursor.fetchall())

            # Get devices with high-risk vulnerabilities
            cursor.execute('''
                SELECT dv.device_ip, d.device_type, v.cvss_score
                FROM device_vulnerabilities_detected dv
                JOIN iot_vulnerabilities v ON dv.cve_id = v.cve_id
                LEFT JOIN devices d ON d.device_ip = dv.device_ip
                WHERE v.cvss_score > 7.0 AND dv.status = 'active'
            ''')
            high_risk_devices = cursor.fetchall()

            conn.close()

            # Calculate penalty based on severity
            critical_count = vuln_counts.get('critical', 0)
            high_count = vuln_counts.get('high', 0)
            medium_count = vuln_counts.get('medium', 0)
            low_count = vuln_counts.get('low', 0)

            # Penalty: critical=20pts, high=10pts, medium=5pts, low=2pts per device
            penalty = (
                critical_count * 20 +
                high_count * 10 +
                medium_count * 5 +
                low_count * 2
            )

            # Normalize penalty by device count
            max_penalty = total_devices * 20  # Max if all devices have critical vulns
            normalized_penalty = min(penalty / max_penalty * 100 if max_penalty > 0 else 0, 100)

            # Score = 100 - penalty
            vuln_score = max(0, 100 - normalized_penalty)

            return {
                'score': round(vuln_score, 1),
                'critical_vulns': critical_count,
                'high_vulns': high_count,
                'medium_vulns': medium_count,
                'low_vulns': low_count,
                'high_risk_devices_count': len(set([d[0] for d in high_risk_devices])),
                'total_devices': total_devices
            }

        except Exception as e:
            logger.error(f"Error calculating vulnerabilities score: {e}")
            return {'score': 0, 'error': str(e)}

    def _calculate_encryption_score(self) -> Dict[str, Any]:
        """
        Calculate encryption score based on protocol usage.

        Returns:
            Dictionary with score and details
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Get protocol usage from recent connections
            cutoff_time = (datetime.now() - timedelta(days=7)).isoformat()

            cursor.execute('''
                SELECT protocol, COUNT(*) as count
                FROM connections
                WHERE timestamp > ?
                GROUP BY protocol
            ''', (cutoff_time,))

            protocol_counts = dict(cursor.fetchall())
            conn.close()

            if not protocol_counts:
                return {'score': 50, 'details': 'No recent connection data'}

            total_connections = sum(protocol_counts.values())

            # Calculate weighted score based on protocol security
            secure_protocols = ['https', 'ssh', 'tls', 'ssl']
            insecure_protocols = ['http', 'telnet', 'ftp']

            secure_count = sum(protocol_counts.get(p, 0) for p in secure_protocols)
            insecure_count = sum(protocol_counts.get(p, 0) for p in insecure_protocols)

            # Score based on secure protocol ratio
            secure_ratio = secure_count / total_connections if total_connections > 0 else 0

            # Penalty for insecure protocols
            insecure_penalty = (insecure_count / total_connections * 30) if total_connections > 0 else 0

            encryption_score = max(0, secure_ratio * 100 - insecure_penalty)

            return {
                'score': round(encryption_score, 1),
                'secure_connections': secure_count,
                'insecure_connections': insecure_count,
                'total_connections': total_connections,
                'secure_ratio': round(secure_ratio * 100, 1),
                'protocol_breakdown': protocol_counts
            }

        except Exception as e:
            logger.error(f"Error calculating encryption score: {e}")
            return {'score': 0, 'error': str(e)}

    def _calculate_segmentation_score(self) -> Dict[str, Any]:
        """
        Calculate segmentation score based on device isolation.

        Returns:
            Dictionary with score and details
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Get devices and their subnets
            cursor.execute('''
                SELECT device_ip, device_type, category
                FROM devices
            ''')

            devices = cursor.fetchall()
            conn.close()

            if not devices:
                return {'score': 100, 'details': 'No devices to evaluate'}

            # Analyze network segmentation
            # Group devices by subnet (first 3 octets)
            subnets = {}
            iot_devices = []
            critical_devices = []

            for device in devices:
                ip = device[0]
                device_type = device[1]
                category = device[2]

                # Extract subnet
                subnet = '.'.join(ip.split('.')[:3]) if ip else 'unknown'

                if subnet not in subnets:
                    subnets[subnet] = []
                subnets[subnet].append((ip, device_type, category))

                # Track IoT and critical devices
                if category in ['smart_home', 'security']:
                    iot_devices.append(ip)
                if device_type in ['smart_lock', 'router', 'camera']:
                    critical_devices.append(ip)

            # Score calculation
            # Ideal: IoT devices on separate subnet, critical devices isolated
            # Simplified scoring:
            total_devices = len(devices)

            # Check if IoT devices are on separate subnet from computers
            # (This is simplified - real implementation would be more sophisticated)
            subnet_count = len(subnets)

            if subnet_count > 1:
                # Multiple subnets = better segmentation
                segmentation_score = min(100, 60 + (subnet_count - 1) * 20)
            else:
                # All on one subnet = poor segmentation
                segmentation_score = 40

            # Bonus for having critical devices isolated
            if len(critical_devices) > 0 and subnet_count > 1:
                segmentation_score = min(100, segmentation_score + 10)

            return {
                'score': round(segmentation_score, 1),
                'subnet_count': subnet_count,
                'iot_devices_count': len(iot_devices),
                'critical_devices_count': len(critical_devices),
                'total_devices': total_devices,
                'recommendation': 'Consider using VLANs to isolate IoT devices' if subnet_count == 1 else 'Good network segmentation'
            }

        except Exception as e:
            logger.error(f"Error calculating segmentation score: {e}")
            return {'score': 0, 'error': str(e)}

    def _get_device_count(self) -> int:
        """Get total device count."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM devices")
            count = cursor.fetchone()[0]
            conn.close()
            return count
        except Exception as e:
            logger.error(f"Error getting device count: {e}")
            return 0

    def _score_to_grade(self, score: float) -> str:
        """
        Convert numeric score to letter grade.

        Args:
            score: Score (0-100)

        Returns:
            Letter grade (A-F)
        """
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

    def save_score_to_history(self, score_data: Dict[str, Any]):
        """
        Save security score to history table.

        Args:
            score_data: Score data from calculate_network_score()
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            dimensions = score_data.get('dimensions', {})

            cursor.execute('''
                INSERT INTO security_score_history
                (overall_score, device_health_score, vulnerabilities_score,
                 encryption_score, segmentation_score, device_count, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                score_data.get('overall_score', 0),
                dimensions.get('device_health', {}).get('score', 0),
                dimensions.get('vulnerabilities', {}).get('score', 0),
                dimensions.get('encryption', {}).get('score', 0),
                dimensions.get('segmentation', {}).get('score', 0),
                score_data.get('device_count', 0),
                datetime.now().isoformat()
            ))

            conn.commit()
            conn.close()

            logger.debug("Saved security score to history")

        except Exception as e:
            logger.error(f"Error saving score to history: {e}")

    def get_score_history(self, days: int = 7) -> List[Dict[str, Any]]:
        """
        Get security score history.

        Args:
            days: Number of days to retrieve

        Returns:
            List of historical score records
        """
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cutoff_date = (datetime.now() - timedelta(days=days)).isoformat()

            cursor.execute('''
                SELECT * FROM security_score_history
                WHERE timestamp > ?
                ORDER BY timestamp ASC
            ''', (cutoff_date,))

            history = [dict(row) for row in cursor.fetchall()]
            conn.close()

            return history

        except Exception as e:
            logger.error(f"Error getting score history: {e}")
            return []


# Global security scorer instance
_security_scorer = None


def get_security_scorer(db_path: str = 'data/iot_monitor.db') -> NetworkSecurityScorer:
    """
    Get global security scorer instance.

    Args:
        db_path: Path to database

    Returns:
        NetworkSecurityScorer instance
    """
    global _security_scorer
    if _security_scorer is None:
        _security_scorer = NetworkSecurityScorer(db_path=db_path)
    return _security_scorer
