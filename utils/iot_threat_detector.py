#!/usr/bin/env python3
"""
IoT-Specific Threat Detection Engine

Detects IoT-specific threats including:
- Botnet infections (Mirai, Gafgyt, Bashlite)
- DDoS participation and victimization
- Malicious scanning behavior
- Command & Control (C2) communication

Uses signature-based and behavior-based detection methods.
"""

import json
import logging
import re
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from collections import defaultdict

logger = logging.getLogger(__name__)


class IoTThreatDetector:
    """Detector for IoT-specific threats and attacks."""

    def __init__(self, db_manager):
        """
        Initialize IoT Threat Detector.

        Args:
            db_manager: DatabaseManager instance
        """
        self.db = db_manager

        # Mirai-specific ports (telnet and alt-telnet)
        self.mirai_scan_ports = {23, 2323, 7547, 80, 8080, 5555, 5358}

        # Common C2 ports
        self.c2_ports = {6667, 6668, 6669, 8080, 443, 53}

        # DDoS attack signatures
        self.ddos_packet_thresholds = {
            'syn_flood': 1000,  # packets per minute
            'udp_flood': 1000,
            'http_flood': 500
        }

    def detect_mirai_infection(self, device_ip: str, time_window_minutes: int = 10) -> Optional[Dict]:
        """
        Detect Mirai botnet infection patterns.

        Indicators:
        1. Rapid scanning of telnet ports (23, 2323)
        2. Connection attempts to multiple destinations
        3. Small packet sizes (scan probes)
        4. High connection failure rate

        Args:
            device_ip: Device IP to analyze
            time_window_minutes: Analysis time window

        Returns:
            Dict with detection results if infected, None otherwise
        """
        try:
            cursor = self.db.conn.cursor()

            # Get recent connection attempts
            cursor.execute("""
                SELECT dest_ip, dest_port, conn_state, COUNT(*) as count
                FROM connections
                WHERE device_ip = ?
                AND timestamp >= datetime('now', '-{} minutes')
                AND dest_port IN (23, 2323, 80, 8080, 7547)
                GROUP BY dest_ip, dest_port
            """.format(time_window_minutes), (device_ip,))

            scan_attempts = cursor.fetchall()

            if not scan_attempts:
                return None

            # Calculate indicators
            total_attempts = sum(row['count'] for row in scan_attempts)
            unique_targets = len(scan_attempts)
            failed_connections = sum(
                row['count'] for row in scan_attempts
                if row['conn_state'] in ('REJ', 'RST', 'S0')
            )

            # Mirai detection thresholds
            is_scanning = unique_targets > 10  # Scanning multiple targets
            is_rapid = total_attempts > 50  # High connection rate
            high_failure_rate = (failed_connections / total_attempts) > 0.7 if total_attempts > 0 else False

            if is_scanning and is_rapid and high_failure_rate:
                # Get targeted ports distribution
                port_distribution = {}
                for row in scan_attempts:
                    port = row['dest_port']
                    port_distribution[port] = port_distribution.get(port, 0) + row['count']

                indicators = {
                    'total_scan_attempts': total_attempts,
                    'unique_targets': unique_targets,
                    'failed_connections': failed_connections,
                    'failure_rate': failed_connections / total_attempts,
                    'port_distribution': port_distribution,
                    'time_window_minutes': time_window_minutes
                }

                # Calculate confidence score
                confidence = min(
                    (unique_targets / 50.0) * 0.4 +  # Target diversity
                    (total_attempts / 200.0) * 0.3 +  # Volume
                    ((failed_connections / total_attempts) * 0.3),  # Failure rate
                    1.0
                )

                detection = {
                    'device_ip': device_ip,
                    'botnet_name': 'Mirai',
                    'detection_method': 'behavior',
                    'confidence_score': confidence,
                    'severity': 'critical',
                    'indicators': json.dumps(indicators),
                    'timestamp': datetime.now().isoformat()
                }

                self._save_botnet_detection(detection)
                return detection

        except Exception as e:
            logger.error(f"Error detecting Mirai infection: {e}")

        return None

    def detect_ddos_participation(self, device_ip: str, time_window_minutes: int = 5) -> Optional[Dict]:
        """
        Detect if device is participating in DDoS attack.

        Indicators:
        1. High packet rate to single destination
        2. Uniform packet sizes
        3. Sustained high bandwidth
        4. SYN flood pattern (no ACKs)

        Args:
            device_ip: Device IP to analyze
            time_window_minutes: Analysis time window

        Returns:
            Dict with DDoS detection results if detected, None otherwise
        """
        try:
            cursor = self.db.conn.cursor()

            # Get connection patterns
            cursor.execute("""
                SELECT
                    dest_ip,
                    dest_port,
                    protocol,
                    COUNT(*) as packet_count,
                    SUM(bytes_sent) as total_bytes,
                    SUM(CASE WHEN conn_state LIKE 'S%' THEN 1 ELSE 0 END) as syn_count,
                    AVG(duration) as avg_duration
                FROM connections
                WHERE device_ip = ?
                AND timestamp >= datetime('now', '-{} minutes')
                GROUP BY dest_ip, dest_port, protocol
                HAVING packet_count > 100
                ORDER BY packet_count DESC
                LIMIT 1
            """.format(time_window_minutes), (device_ip,))

            top_target = cursor.fetchone()

            if not top_target:
                return None

            packet_count = top_target['packet_count']
            total_bytes = top_target['total_bytes'] or 0
            syn_count = top_target['syn_count']
            avg_duration = top_target['avg_duration'] or 0
            packets_per_second = packet_count / (time_window_minutes * 60)

            # Detect attack type
            attack_type = None
            confidence = 0.0

            # SYN Flood detection
            if syn_count > packet_count * 0.8 and avg_duration < 1:
                attack_type = 'SYN Flood'
                confidence = min((syn_count / packet_count), 1.0)

            # UDP Flood detection
            elif top_target['protocol'] == 'udp' and packets_per_second > 50:
                attack_type = 'UDP Flood'
                confidence = min((packets_per_second / 200.0), 1.0)

            # HTTP Flood detection
            elif top_target['dest_port'] in (80, 443, 8080) and packets_per_second > 10:
                attack_type = 'HTTP Flood'
                confidence = min((packets_per_second / 50.0), 1.0)

            if attack_type and confidence > 0.5:
                ddos_event = {
                    'device_ip': device_ip,
                    'attack_type': attack_type,
                    'target_ip': top_target['dest_ip'],
                    'target_port': top_target['dest_port'],
                    'packet_count': packet_count,
                    'bytes_sent': total_bytes,
                    'duration_seconds': time_window_minutes * 60,
                    'packets_per_second': packets_per_second,
                    'confidence_score': confidence,
                    'is_victim': False,  # This device is attacker
                    'timestamp': datetime.now().isoformat()
                }

                self._save_ddos_activity(ddos_event)
                return ddos_event

        except Exception as e:
            logger.error(f"Error detecting DDoS participation: {e}")

        return None

    def detect_ddos_victimization(self, device_ip: str, time_window_minutes: int = 5) -> Optional[Dict]:
        """
        Detect if device is victim of DDoS attack.

        Args:
            device_ip: Device IP to analyze
            time_window_minutes: Analysis time window

        Returns:
            Dict with victimization details if detected, None otherwise
        """
        try:
            cursor = self.db.conn.cursor()

            # Count incoming connections
            cursor.execute("""
                SELECT
                    protocol,
                    dest_port,
                    COUNT(*) as connection_count,
                    COUNT(DISTINCT device_ip) as unique_sources,
                    SUM(bytes_received) as total_bytes_received
                FROM connections
                WHERE dest_ip = ?
                AND timestamp >= datetime('now', '-{} minutes')
                GROUP BY protocol, dest_port
                HAVING connection_count > 500
            """.format(time_window_minutes), (device_ip,))

            attacks = cursor.fetchall()

            for attack in attacks:
                connections_per_second = attack['connection_count'] / (time_window_minutes * 60)

                if connections_per_second > 10:
                    # Likely DDoS victim
                    ddos_event = {
                        'device_ip': device_ip,
                        'attack_type': f"{attack['protocol'].upper()} Flood",
                        'target_port': attack['dest_port'],
                        'packet_count': attack['connection_count'],
                        'bytes_sent': attack['total_bytes_received'] or 0,
                        'duration_seconds': time_window_minutes * 60,
                        'packets_per_second': connections_per_second,
                        'confidence_score': min(connections_per_second / 50.0, 1.0),
                        'is_victim': True,
                        'unique_attackers': attack['unique_sources'],
                        'timestamp': datetime.now().isoformat()
                    }

                    self._save_ddos_activity(ddos_event)
                    return ddos_event

        except Exception as e:
            logger.error(f"Error detecting DDoS victimization: {e}")

        return None

    def detect_c2_communication(self, device_ip: str, time_window_hours: int = 1) -> Optional[Dict]:
        """
        Detect potential Command & Control (C2) communication.

        Indicators:
        1. Periodic beaconing behavior
        2. Connections to suspicious ports
        3. Low data volume (command/response)
        4. Consistent connection intervals

        Args:
            device_ip: Device IP to analyze
            time_window_hours: Analysis time window

        Returns:
            Dict with C2 detection results if detected, None otherwise
        """
        try:
            cursor = self.db.conn.cursor()

            # Get connection timeline
            cursor.execute("""
                SELECT
                    dest_ip,
                    dest_port,
                    timestamp,
                    bytes_sent,
                    bytes_received,
                    strftime('%s', timestamp) as unix_time
                FROM connections
                WHERE device_ip = ?
                AND timestamp >= datetime('now', '-{} hours')
                AND dest_port IN (6667, 6668, 6669, 8080, 443, 53)
                ORDER BY dest_ip, timestamp
            """.format(time_window_hours), (device_ip,))

            connections = cursor.fetchall()

            if len(connections) < 5:
                return None

            # Analyze connection patterns by destination
            dest_patterns = defaultdict(list)
            for conn in connections:
                dest_key = (conn['dest_ip'], conn['dest_port'])
                dest_patterns[dest_key].append({
                    'unix_time': int(conn['unix_time']),
                    'bytes_sent': conn['bytes_sent'] or 0,
                    'bytes_received': conn['bytes_received'] or 0
                })

            # Check for periodic beaconing
            for dest_key, conn_list in dest_patterns.items():
                if len(conn_list) < 5:
                    continue

                # Calculate intervals between connections
                intervals = []
                for i in range(1, len(conn_list)):
                    interval = conn_list[i]['unix_time'] - conn_list[i-1]['unix_time']
                    intervals.append(interval)

                if not intervals:
                    continue

                # Check if intervals are consistent (beaconing)
                avg_interval = sum(intervals) / len(intervals)
                interval_variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
                interval_std_dev = interval_variance ** 0.5

                # Beaconing detected if low variance in intervals
                is_periodic = (interval_std_dev / avg_interval) < 0.3 if avg_interval > 0 else False

                # Check for low data volume (typical of C2)
                avg_bytes = sum(c['bytes_sent'] + c['bytes_received'] for c in conn_list) / len(conn_list)
                is_low_volume = avg_bytes < 1000

                if is_periodic and is_low_volume:
                    indicators = {
                        'dest_ip': dest_key[0],
                        'dest_port': dest_key[1],
                        'connection_count': len(conn_list),
                        'avg_interval_seconds': avg_interval,
                        'interval_consistency': 1.0 - (interval_std_dev / avg_interval) if avg_interval > 0 else 0,
                        'avg_bytes_per_connection': avg_bytes
                    }

                    detection = {
                        'device_ip': device_ip,
                        'botnet_name': 'Unknown C2',
                        'detection_method': 'behavior',
                        'confidence_score': 0.7,
                        'severity': 'high',
                        'indicators': json.dumps(indicators),
                        'timestamp': datetime.now().isoformat()
                    }

                    self._save_botnet_detection(detection)
                    return detection

        except Exception as e:
            logger.error(f"Error detecting C2 communication: {e}")

        return None

    def check_botnet_signatures(self, device_ip: str) -> List[Dict]:
        """
        Check device against known botnet signatures.

        Args:
            device_ip: Device IP to check

        Returns:
            List of matched botnet signatures
        """
        matches = []

        try:
            cursor = self.db.conn.cursor()

            # Get all active botnet signatures
            cursor.execute("""
                SELECT * FROM botnet_signatures
                WHERE active = 1
            """)

            signatures = cursor.fetchall()

            for sig in signatures:
                # Check port scan patterns
                if sig['port_scan_patterns']:
                    scan_ports = json.loads(sig['port_scan_patterns'])
                    if self._check_port_scan_pattern(device_ip, scan_ports):
                        matches.append({
                            'botnet_name': sig['botnet_name'],
                            'match_type': 'port_scan_pattern',
                            'severity': sig['severity']
                        })

                # Check default credentials usage
                if sig['default_credentials']:
                    # This would require auth attempt logging
                    pass

        except Exception as e:
            logger.error(f"Error checking botnet signatures: {e}")

        return matches

    def _check_port_scan_pattern(self, device_ip: str, target_ports: List[str]) -> bool:
        """Check if device is scanning specific ports."""
        try:
            cursor = self.db.conn.cursor()

            # Convert string ports to integers
            port_list = [int(p) for p in target_ports]

            cursor.execute("""
                SELECT COUNT(DISTINCT dest_port) as scanned_ports
                FROM connections
                WHERE device_ip = ?
                AND dest_port IN ({})
                AND timestamp >= datetime('now', '-1 hour')
            """.format(','.join('?' * len(port_list))),
                [device_ip] + port_list
            )

            result = cursor.fetchone()
            scanned_ports = result['scanned_ports'] if result else 0

            # If device scanned 50%+ of signature ports, it's a match
            return scanned_ports >= (len(port_list) * 0.5)

        except Exception as e:
            logger.error(f"Error checking port scan pattern: {e}")
            return False

    def _save_botnet_detection(self, detection: Dict):
        """Save botnet detection to database."""
        try:
            cursor = self.db.conn.cursor()
            cursor.execute("""
                INSERT INTO botnet_detections (
                    device_ip, botnet_name, detection_method,
                    confidence_score, indicators, severity
                ) VALUES (?, ?, ?, ?, ?, ?)
            """, (
                detection['device_ip'],
                detection['botnet_name'],
                detection['detection_method'],
                detection['confidence_score'],
                detection['indicators'],
                detection['severity']
            ))
            self.db.conn.commit()
            logger.warning(f"Botnet detection saved: {detection['botnet_name']} on {detection['device_ip']}")
        except Exception as e:
            logger.error(f"Failed to save botnet detection: {e}")

    def _save_ddos_activity(self, ddos_event: Dict):
        """Save DDoS activity to database."""
        try:
            cursor = self.db.conn.cursor()
            cursor.execute("""
                INSERT INTO ddos_activity (
                    device_ip, attack_type, target_ip, target_port,
                    packet_count, bytes_sent, duration_seconds,
                    packets_per_second, confidence_score, is_victim
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                ddos_event['device_ip'],
                ddos_event['attack_type'],
                ddos_event.get('target_ip'),
                ddos_event.get('target_port'),
                ddos_event['packet_count'],
                ddos_event['bytes_sent'],
                ddos_event['duration_seconds'],
                ddos_event['packets_per_second'],
                ddos_event['confidence_score'],
                ddos_event['is_victim']
            ))
            self.db.conn.commit()
            logger.warning(f"DDoS activity saved: {ddos_event['attack_type']} - Device: {ddos_event['device_ip']}")
        except Exception as e:
            logger.error(f"Failed to save DDoS activity: {e}")

    def get_threat_summary(self, hours: int = 24) -> Dict:
        """
        Get summary of detected threats.

        Args:
            hours: Time window in hours

        Returns:
            Dict with threat statistics
        """
        try:
            cursor = self.db.conn.cursor()

            # Botnet detections
            cursor.execute("""
                SELECT botnet_name, COUNT(*) as count, AVG(confidence_score) as avg_confidence
                FROM botnet_detections
                WHERE timestamp >= datetime('now', '-{} hours')
                GROUP BY botnet_name
            """.format(hours))

            botnet_stats = {row['botnet_name']: dict(row) for row in cursor.fetchall()}

            # DDoS events
            cursor.execute("""
                SELECT attack_type, COUNT(*) as count,
                       SUM(CASE WHEN is_victim THEN 1 ELSE 0 END) as victim_count,
                       SUM(CASE WHEN NOT is_victim THEN 1 ELSE 0 END) as attacker_count
                FROM ddos_activity
                WHERE timestamp >= datetime('now', '-{} hours')
                GROUP BY attack_type
            """.format(hours))

            ddos_stats = {row['attack_type']: dict(row) for row in cursor.fetchall()}

            return {
                'time_window_hours': hours,
                'botnet_detections': botnet_stats,
                'ddos_events': ddos_stats,
                'total_threats': len(botnet_stats) + len(ddos_stats)
            }

        except Exception as e:
            logger.error(f"Error getting threat summary: {e}")
            return {}


# Singleton instance
_threat_detector_instance = None


def get_threat_detector(db_manager) -> IoTThreatDetector:
    """Get or create IoT Threat Detector singleton."""
    global _threat_detector_instance
    if _threat_detector_instance is None:
        _threat_detector_instance = IoTThreatDetector(db_manager)
    return _threat_detector_instance
