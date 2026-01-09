#!/usr/bin/env python3
"""
Custom Alert Rule Engine for IoTSentinel

Evaluates user-defined alert rules against network activity.
"""

import sqlite3
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)


class RuleEngine:
    """Evaluates custom alert rules against device activity"""

    def __init__(self, db_path: str = None, db_manager=None):
        """Initialize with db_manager (preferred) or db_path (legacy)."""
        if db_manager is not None:
            self.db_manager = db_manager
            self.db_path = None
        else:
            from database.db_manager import DatabaseManager
            self.db_manager = DatabaseManager(db_path=db_path)
        """
        Initialize rule engine.

        Args:
            db_path: Path to SQLite database
        """
        self.db_path = db_path

    def get_active_rules(self) -> List[Dict[str, Any]]:
        """
        Get all active (enabled) alert rules.

        Returns:
            List of active rules
        """
        try:
            conn = self.db_manager.conn

            cursor = conn.cursor()

            cursor.execute("""
                SELECT * FROM alert_rules
                WHERE is_enabled = 1
                ORDER BY severity DESC, id ASC
            """)

            rules = [dict(row) for row in cursor.fetchall()]

            return rules

        except sqlite3.Error as e:
            logger.error(f"Error fetching active rules: {e}")
            return []

    def evaluate_rule(self, rule: Dict[str, Any], device_ip: str) -> Optional[Dict[str, Any]]:
        """
        Evaluate a single rule for a device.

        Args:
            rule: Rule dictionary from database
            device_ip: Device IP address to check

        Returns:
            Alert dictionary if rule triggered, None otherwise
        """
        try:
            rule_type = rule['rule_type']

            # Check device filter
            if rule['device_filter']:
                device_filter = rule['device_filter'].split(',')
                if device_ip not in device_filter:
                    return None

            # Route to appropriate evaluation method
            if rule_type == 'data_volume':
                return self._evaluate_data_volume(rule, device_ip)
            elif rule_type == 'connection_count':
                return self._evaluate_connection_count(rule, device_ip)
            elif rule_type == 'port_activity':
                return self._evaluate_port_activity(rule, device_ip)
            elif rule_type == 'time_based':
                return self._evaluate_time_based(rule, device_ip)
            elif rule_type == 'destination_ip':
                return self._evaluate_destination_ip(rule, device_ip)
            elif rule_type == 'protocol':
                return self._evaluate_protocol(rule, device_ip)
            else:
                logger.warning(f"Unknown rule type: {rule_type}")
                return None

        except Exception as e:
            logger.error(f"Error evaluating rule {rule['id']} for device {device_ip}: {e}")
            return None

    def _evaluate_data_volume(self, rule: Dict, device_ip: str) -> Optional[Dict]:
        """Evaluate data volume rule"""
        try:
            conn = self.db_manager.conn
            cursor = conn.cursor()

            # Calculate time window
            cutoff_time = datetime.now() - timedelta(hours=rule['time_window_hours'])

            # Get total bytes sent in time window
            cursor.execute("""
                SELECT SUM(bytes_sent + bytes_received) as total_bytes
                FROM connections
                WHERE device_ip = ?
                AND timestamp > ?
            """, (device_ip, cutoff_time.isoformat()))

            result = cursor.fetchone()

            if not result or result[0] is None:
                return None

            total_mb = result[0] / (1024 * 1024)  # Convert to MB
            threshold_mb = rule['threshold_value']

            if self._check_condition(total_mb, rule['condition_operator'], threshold_mb):
                return {
                    'device_ip': device_ip,
                    'rule_id': rule['id'],
                    'rule_name': rule['name'],
                    'severity': rule['severity'],
                    'explanation': f"Device transferred {total_mb:.2f} MB in {rule['time_window_hours']} hour(s), exceeding threshold of {threshold_mb} MB",
                    'actual_value': total_mb,
                    'threshold_value': threshold_mb
                }

            return None

        except sqlite3.Error as e:
            logger.error(f"Database error in data volume check: {e}")
            return None

    def _evaluate_connection_count(self, rule: Dict, device_ip: str) -> Optional[Dict]:
        """Evaluate connection count rule"""
        try:
            conn = self.db_manager.conn
            cursor = conn.cursor()

            cutoff_time = datetime.now() - timedelta(hours=rule['time_window_hours'])

            cursor.execute("""
                SELECT COUNT(*) as conn_count
                FROM connections
                WHERE device_ip = ?
                AND timestamp > ?
            """, (device_ip, cutoff_time.isoformat()))

            result = cursor.fetchone()

            if not result:
                return None

            conn_count = result[0]
            threshold = rule['threshold_value']

            if self._check_condition(conn_count, rule['condition_operator'], threshold):
                return {
                    'device_ip': device_ip,
                    'rule_id': rule['id'],
                    'rule_name': rule['name'],
                    'severity': rule['severity'],
                    'explanation': f"Device made {conn_count} connections in {rule['time_window_hours']} hour(s), exceeding threshold of {int(threshold)}",
                    'actual_value': conn_count,
                    'threshold_value': threshold
                }

            return None

        except sqlite3.Error as e:
            logger.error(f"Database error in connection count check: {e}")
            return None

    def _evaluate_port_activity(self, rule: Dict, device_ip: str) -> Optional[Dict]:
        """Evaluate port activity rule"""
        try:
            if not rule['port_filter']:
                return None

            suspicious_ports = [int(p.strip()) for p in rule['port_filter'].split(',')]

            conn = self.db_manager.conn
            cursor = conn.cursor()

            cutoff_time = datetime.now() - timedelta(hours=rule['time_window_hours'])

            placeholders = ','.join('?' * len(suspicious_ports))
            cursor.execute(f"""
                SELECT dest_port, COUNT(*) as count
                FROM connections
                WHERE device_ip = ?
                AND timestamp > ?
                AND dest_port IN ({placeholders})
                GROUP BY dest_port
            """, (device_ip, cutoff_time.isoformat(), *suspicious_ports))

            results = cursor.fetchall()

            if results:
                ports_hit = [str(r[0]) for r in results]
                total_conns = sum(r[1] for r in results)

                return {
                    'device_ip': device_ip,
                    'rule_id': rule['id'],
                    'rule_name': rule['name'],
                    'severity': rule['severity'],
                    'explanation': f"Device connected to suspicious ports: {', '.join(ports_hit)} ({total_conns} connection(s))",
                    'actual_value': ', '.join(ports_hit),
                    'threshold_value': rule['port_filter']
                }

            return None

        except (sqlite3.Error, ValueError) as e:
            logger.error(f"Error in port activity check: {e}")
            return None

    def _evaluate_time_based(self, rule: Dict, device_ip: str) -> Optional[Dict]:
        """Evaluate time-based rule (e.g., after-hours activity)"""
        try:
            if not rule['time_filter']:
                return None

            # Parse time filter (format: "HH:MM-HH:MM")
            start_time_str, end_time_str = rule['time_filter'].split('-')
            start_hour = int(start_time_str.split(':')[0])
            end_hour = int(end_time_str.split(':')[0])

            conn = self.db_manager.conn
            cursor = conn.cursor()

            cutoff_time = datetime.now() - timedelta(hours=rule['time_window_hours'])

            # Get recent connections
            cursor.execute("""
                SELECT timestamp, COUNT(*) as count
                FROM connections
                WHERE device_ip = ?
                AND timestamp > ?
                GROUP BY strftime('%Y-%m-%d %H', timestamp)
                HAVING CAST(strftime('%H', timestamp) AS INTEGER) >= ?
                OR CAST(strftime('%H', timestamp) AS INTEGER) < ?
            """, (device_ip, cutoff_time.isoformat(), start_hour, end_hour))

            results = cursor.fetchall()

            if results:
                total_conns = sum(r[1] for r in results)

                return {
                    'device_ip': device_ip,
                    'rule_id': rule['id'],
                    'rule_name': rule['name'],
                    'severity': rule['severity'],
                    'explanation': f"Device showed {total_conns} connection(s) during unusual hours ({rule['time_filter']})",
                    'actual_value': total_conns,
                    'threshold_value': rule['time_filter']
                }

            return None

        except (sqlite3.Error, ValueError) as e:
            logger.error(f"Error in time-based check: {e}")
            return None

    def _evaluate_destination_ip(self, rule: Dict, device_ip: str) -> Optional[Dict]:
        """Evaluate destination IP rule"""
        try:
            # This would check connections to specific IPs or IP ranges
            # Implementation depends on how destination IPs are filtered
            # For now, return None (placeholder)
            return None

        except Exception as e:
            logger.error(f"Error in destination IP check: {e}")
            return None

    def _evaluate_protocol(self, rule: Dict, device_ip: str) -> Optional[Dict]:
        """Evaluate protocol-based rule"""
        try:
            if not rule['protocol_filter']:
                return None

            protocols = [p.strip().upper() for p in rule['protocol_filter'].split(',')]

            conn = self.db_manager.conn
            cursor = conn.cursor()

            cutoff_time = datetime.now() - timedelta(hours=rule['time_window_hours'])

            placeholders = ','.join('?' * len(protocols))
            cursor.execute(f"""
                SELECT protocol, COUNT(*) as count
                FROM connections
                WHERE device_ip = ?
                AND timestamp > ?
                AND UPPER(protocol) IN ({placeholders})
                GROUP BY protocol
            """, (device_ip, cutoff_time.isoformat(), *protocols))

            results = cursor.fetchall()

            if results:
                protocols_hit = [r[0] for r in results]
                total_conns = sum(r[1] for r in results)

                return {
                    'device_ip': device_ip,
                    'rule_id': rule['id'],
                    'rule_name': rule['name'],
                    'severity': rule['severity'],
                    'explanation': f"Device used monitored protocol(s): {', '.join(protocols_hit)} ({total_conns} connection(s))",
                    'actual_value': ', '.join(protocols_hit),
                    'threshold_value': rule['protocol_filter']
                }

            return None

        except (sqlite3.Error, ValueError) as e:
            logger.error(f"Error in protocol check: {e}")
            return None

    def _check_condition(self, actual: float, operator: str, threshold: float, threshold_2: float = None) -> bool:
        """
        Check if condition is met.

        Args:
            actual: Actual value
            operator: Comparison operator
            threshold: Threshold value
            threshold_2: Second threshold (for range checks)

        Returns:
            True if condition met, False otherwise
        """
        if operator == 'gt':
            return actual > threshold
        elif operator == 'gte':
            return actual >= threshold
        elif operator == 'lt':
            return actual < threshold
        elif operator == 'lte':
            return actual <= threshold
        elif operator == 'eq':
            return actual == threshold
        elif operator == 'in_range' and threshold_2 is not None:
            return threshold <= actual <= threshold_2
        else:
            return False

    def update_rule_stats(self, rule_id: int):
        """
        Update rule statistics after trigger.

        Args:
            rule_id: Rule ID
        """
        try:
            conn = self.db_manager.conn
            cursor = conn.cursor()

            cursor.execute("""
                UPDATE alert_rules
                SET last_triggered = ?,
                    trigger_count = trigger_count + 1
                WHERE id = ?
            """, (datetime.now().isoformat(), rule_id))

            conn.commit()

            logger.info(f"Updated stats for rule {rule_id}")

        except sqlite3.Error as e:
            logger.error(f"Error updating rule stats: {e}")

    def evaluate_all_rules_for_device(self, device_ip: str) -> List[Dict[str, Any]]:
        """
        Evaluate all active rules for a specific device.

        Args:
            device_ip: Device IP address

        Returns:
            List of triggered alerts
        """
        active_rules = self.get_active_rules()
        triggered_alerts = []

        for rule in active_rules:
            alert = self.evaluate_rule(rule, device_ip)
            if alert:
                triggered_alerts.append(alert)
                self.update_rule_stats(rule['id'])
                logger.info(f"Rule '{rule['name']}' triggered for device {device_ip}")

        return triggered_alerts
