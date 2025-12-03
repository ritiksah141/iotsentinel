#!/usr/bin/env python3
"""
Professional Database Manager for IoTSentinel

Handles all database operations with:
- Connection pooling
- Transaction support
- Error handling
- Prepared statements

100% Compatible with init_database.py schema
"""

import sqlite3
import logging
from pathlib import Path
from datetime import datetime, timedelta
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)


class DatabaseManager:
    """SQLite database manager for IoTSentinel."""

    def __init__(self, db_path: str):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self.conn = None
        self._connect()

        logger.info(f"Database manager initialized: {self.db_path}")

    def _connect(self):
        """Establish database connection with optimizations."""
        self.conn = sqlite3.connect(
            str(self.db_path),
            check_same_thread=False,
            timeout=30.0  # 30 second timeout for busy database
        )
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.execute("PRAGMA journal_mode = WAL")  # Write-Ahead Logging
        self.conn.execute("PRAGMA synchronous = NORMAL")  # Balance safety/speed

    def add_device(self, device_ip: str, **kwargs) -> bool:
        """
        Add or update device.

        Args:
            device_ip: Device IP address (PRIMARY KEY)
            **kwargs: Optional fields (device_name, device_type, mac_address, manufacturer)

        Returns:
            True if successful, False otherwise
        """
        try:
            cursor = self.conn.cursor()

            cursor.execute("""
                INSERT INTO devices (device_ip, device_name, mac_address, manufacturer, first_seen, last_seen)
                VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                ON CONFLICT(device_ip) DO UPDATE SET
                    device_name = COALESCE(excluded.device_name, devices.device_name),
                    mac_address = COALESCE(excluded.mac_address, devices.mac_address),
                    manufacturer = COALESCE(excluded.manufacturer, devices.manufacturer),
                    last_seen = CURRENT_TIMESTAMP
            """, (
                device_ip,
                kwargs.get('device_name'),
                kwargs.get('mac_address'),
                kwargs.get('manufacturer')
            ))

            self.conn.commit()
            return True

        except sqlite3.Error as e:
            logger.error(f"Error adding device {device_ip}: {e}")
            return False

    def add_connection(self, device_ip: str, dest_ip: str, dest_port: int,
                       protocol: str, **kwargs) -> Optional[int]:
        """
        Add network connection record.

        Args:
            device_ip: Source device IP
            dest_ip: Destination IP
            dest_port: Destination port
            protocol: Protocol (tcp/udp/icmp)
            **kwargs: Optional fields (service, duration, bytes_sent, etc.)

        Returns:
            Connection ID if successful, None otherwise
        """
        try:
            # Ensure device exists first
            self.add_device(device_ip)

            cursor = self.conn.cursor()

            cursor.execute("""
                INSERT INTO connections
                (device_ip, dest_ip, dest_port, protocol, service, duration,
                 bytes_sent, bytes_received, packets_sent, packets_received, conn_state)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                device_ip,
                dest_ip,
                dest_port,
                protocol,
                kwargs.get('service'),
                kwargs.get('duration', 0),
                kwargs.get('bytes_sent', 0),
                kwargs.get('bytes_received', 0),
                kwargs.get('packets_sent', 0),
                kwargs.get('packets_received', 0),
                kwargs.get('conn_state')
            ))

            self.conn.commit()
            return cursor.lastrowid

        except sqlite3.Error as e:
            logger.error(f"Error adding connection from {device_ip}: {e}")
            return None

    def get_unprocessed_connections(self, limit: int = 100) -> List[Dict]:
        """
        Get connections not yet processed by ML engine.

        Args:
            limit: Maximum number of connections to return

        Returns:
            List of connection dictionaries
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT * FROM connections
                WHERE processed = 0
                ORDER BY timestamp ASC
                LIMIT ?
            """, (limit,))

            return [dict(row) for row in cursor.fetchall()]
        except sqlite3.Error as e:
            logger.error(f"Error fetching unprocessed connections: {e}")
            return []

    def mark_connections_processed(self, connection_ids: List[int]):
        """
        Mark connections as processed by ML engine.

        Args:
            connection_ids: List of connection IDs to mark as processed
        """
        if not connection_ids:
            return

        try:
            cursor = self.conn.cursor()
            placeholders = ','.join(['?'] * len(connection_ids))
            cursor.execute(f"""
                UPDATE connections
                SET processed = 1
                WHERE id IN ({placeholders})
            """, connection_ids)
            self.conn.commit()
            logger.debug(f"Marked {len(connection_ids)} connections as processed")
        except sqlite3.Error as e:
            logger.error(f"Error marking connections processed: {e}")

    def store_prediction(self, connection_id: int, is_anomaly: bool,
                        anomaly_score: float, model_type: str):
        """
        Store ML model prediction.

        Args:
            connection_id: Connection ID this prediction is for
            is_anomaly: True if anomalous, False if normal
            anomaly_score: Anomaly score from model
            model_type: Model used (autoencoder/isolation_forest)
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                INSERT INTO ml_predictions
                (connection_id, is_anomaly, anomaly_score, model_type, model_version)
                VALUES (?, ?, ?, ?, ?)
            """, (connection_id, int(is_anomaly), anomaly_score, model_type, 'v1'))
            self.conn.commit()
        except sqlite3.Error as e:
            logger.error(f"Error storing prediction for connection {connection_id}: {e}")

    def create_alert(self, device_ip: str, severity: str, anomaly_score: float,
                     explanation: str, top_features: str) -> Optional[int]:
        """
        Create security alert.

        Args:
            device_ip: Device that triggered alert
            severity: Alert severity (low/medium/high/critical)
            anomaly_score: Anomaly score that triggered alert
            explanation: Plain English explanation
            top_features: JSON string of top contributing features

        Returns:
            Alert ID if successful, None otherwise
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                INSERT INTO alerts
                (device_ip, severity, anomaly_score, explanation, top_features)
                VALUES (?, ?, ?, ?, ?)
            """, (device_ip, severity, anomaly_score, explanation, top_features))

            self.conn.commit()
            logger.info(f"Created {severity} alert for {device_ip}")
            return cursor.lastrowid
        except sqlite3.Error as e:
            logger.error(f"Error creating alert for {device_ip}: {e}")
            return None

    def get_recent_alerts(self, hours: int = 24) -> List[Dict]:
        """
        Get recent alerts with device names.

        Args:
            hours: Look back this many hours

        Returns:
            List of alert dictionaries
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT a.*, d.device_name
                FROM alerts a
                LEFT JOIN devices d ON a.device_ip = d.device_ip
                WHERE a.timestamp > datetime('now', ? || ' hours')
                ORDER BY a.timestamp DESC
            """, (f'-{hours}',))

            return [dict(row) for row in cursor.fetchall()]
        except sqlite3.Error as e:
            logger.error(f"Error fetching alerts: {e}")
            return []

    def get_active_devices(self, minutes: int = 5) -> List[Dict]:
        """
        Get recently active devices.

        Args:
            minutes: Consider devices active if seen within this many minutes

        Returns:
            List of device dictionaries
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT * FROM devices
                WHERE last_seen > datetime('now', ? || ' minutes')
                ORDER BY last_seen DESC
            """, (f'-{minutes}',))

            return [dict(row) for row in cursor.fetchall()]
        except sqlite3.Error as e:
            logger.error(f"Error fetching active devices: {e}")
            return []

    def get_device_stats(self, device_ip: str, hours: int = 24) -> Dict:
        """
        Get statistics for a specific device.

        Args:
            device_ip: Device IP to get stats for
            hours: Look back this many hours

        Returns:
            Dictionary of statistics
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT
                    COUNT(*) as connection_count,
                    SUM(bytes_sent) as total_bytes_sent,
                    SUM(bytes_received) as total_bytes_received,
                    COUNT(DISTINCT dest_ip) as unique_destinations
                FROM connections
                WHERE device_ip = ?
                AND timestamp > datetime('now', ? || ' hours')
            """, (device_ip, f'-{hours}'))

            row = cursor.fetchone()
            return dict(row) if row else {}
        except sqlite3.Error as e:
            logger.error(f"Error fetching device stats for {device_ip}: {e}")
            return {}

    def get_all_devices(self) -> List[Dict]:
        """Get all devices ever seen."""
        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT * FROM devices ORDER BY last_seen DESC")
            return [dict(row) for row in cursor.fetchall()]
        except sqlite3.Error as e:
            logger.error(f"Error fetching all devices: {e}")
            return []

    def get_device(self, device_ip: str) -> Optional[Dict]:
        """Get a single device by IP address."""
        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT * FROM devices WHERE device_ip = ?", (device_ip,))
            row = cursor.fetchone()
            return dict(row) if row else None
        except sqlite3.Error as e:
            logger.error(f"Error fetching device {device_ip}: {e}")
            return None

    def update_device_name(self, device_ip: str, device_name: str) -> bool:
        """Update device friendly name."""
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                UPDATE devices
                SET device_name = ?
                WHERE device_ip = ?
            """, (device_name, device_ip))
            self.conn.commit()
            return True
        except sqlite3.Error as e:
            logger.error(f"Error updating device name: {e}")
            return False

    def acknowledge_alert(self, alert_id: int) -> bool:
        """Mark alert as acknowledged."""
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                UPDATE alerts
                SET acknowledged = 1, acknowledged_at = CURRENT_TIMESTAMP
                WHERE id = ?
            """, (alert_id,))
            self.conn.commit()
            return True
        except sqlite3.Error as e:
            logger.error(f"Error acknowledging alert {alert_id}: {e}")
            return False

    def get_connection_count(self, hours: int = 24) -> int:
        """Get total connection count."""
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT COUNT(*) FROM connections
                WHERE timestamp > datetime('now', ? || ' hours')
            """, (f'-{hours}',))
            return cursor.fetchone()[0]
        except sqlite3.Error as e:
            logger.error(f"Error getting connection count: {e}")
            return 0

    def add_model_performance_metric(self, model_type: str, precision: float, recall: float, f1_score: float) -> bool:
        """
        Store model performance metrics.

        Args:
            model_type: Model identifier (e.g., 'combined')
            precision: Precision score
            recall: Recall score
            f1_score: F1-score

        Returns:
            True if successful, False otherwise
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                INSERT INTO model_performance
                (model_type, precision, recall, f1_score)
                VALUES (?, ?, ?, ?)
            """, (model_type, precision, recall, f1_score))
            self.conn.commit()
            return True
        except sqlite3.Error as e:
            logger.error(f"Error storing model performance metric: {e}")
            return False

    def get_model_performance_metrics(self, days: int = 30) -> List[Dict]:
        """
        Get recent model performance metrics.

        Args:
            days: Look back this many days

        Returns:
            List of metric dictionaries
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT * FROM model_performance
                WHERE timestamp > datetime('now', ? || ' days')
                ORDER BY timestamp ASC
            """, (f'-{days}',))

            return [dict(row) for row in cursor.fetchall()]
        except sqlite3.Error as e:
            logger.error(f"Error fetching model performance metrics: {e}")
            return []

    def set_device_trust(self, device_ip: str, is_trusted: bool) -> bool:
        """Set the trust status for a device."""
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                UPDATE devices
                SET is_trusted = ?
                WHERE device_ip = ?
            """, (int(is_trusted), device_ip))
            self.conn.commit()
            logger.info(f"Set device {device_ip} trust to {is_trusted}")
            return True
        except sqlite3.Error as e:
            logger.error(f"Error setting trust for device {device_ip}: {e}")
            return False

    def set_device_blocked(self, device_ip: str, is_blocked: bool) -> bool:
        """Set the blocked status for a device."""
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                UPDATE devices
                SET is_blocked = ?
                WHERE device_ip = ?
            """, (int(is_blocked), device_ip))
            self.conn.commit()
            logger.info(f"Set device {device_ip} blocked to {is_blocked}")
            return True
        except sqlite3.Error as e:
            logger.error(f"Error setting blocked status for device {device_ip}: {e}")
            return False

    def get_blocked_devices(self):
        """Get all blocked devices with their MAC addresses."""
        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT * FROM devices WHERE is_blocked = 1")
            return [dict(row) for row in cursor.fetchall()]
        except sqlite3.Error as e:
            logger.error(f"Error fetching blocked devices: {e}")
            return []

    def get_trusted_devices(self) -> List[Dict]:
        """Get all trusted devices."""
        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT * FROM devices WHERE is_trusted = 1")
            return [dict(row) for row in cursor.fetchall()]
        except sqlite3.Error as e:
            logger.error(f"Error fetching trusted devices: {e}")
            return []

    def get_bandwidth_stats(self, hours: int = 24) -> List[Dict]:
        """
        Get bandwidth usage stats per device.

        Args:
            hours: Look back this many hours.

        Returns:
            List of dictionaries with device_ip and total_bytes.
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT
                    device_ip,
                    SUM(bytes_sent + bytes_received) as total_bytes
                FROM connections
                WHERE timestamp > datetime('now', ? || ' hours')
                GROUP BY device_ip
                ORDER BY total_bytes DESC
                LIMIT 10
            """, (f'-{hours}',))
            return [dict(row) for row in cursor.fetchall()]
        except sqlite3.Error as e:
            logger.error(f"Error fetching bandwidth stats: {e}")
            return []

    def add_malicious_ips(self, ips: List[str], source: str):
        """
        Add a list of malicious IPs to the database.

        Args:
            ips: A list of IP addresses.
            source: The source of the threat intelligence feed.
        """
        try:
            cursor = self.conn.cursor()
            data = [(ip, source) for ip in ips]
            cursor.executemany("INSERT OR IGNORE INTO malicious_ips (ip, source) VALUES (?, ?)", data)
            self.conn.commit()
            logger.info(f"Added {len(ips)} new malicious IPs from {source}")
        except sqlite3.Error as e:
            logger.error(f"Error adding malicious IPs: {e}")

    def is_ip_malicious(self, ip: str) -> bool:
        """
        Check if an IP address is in the malicious list.

        Args:
            ip: The IP address to check.

        Returns:
            True if the IP is malicious, False otherwise.
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT 1 FROM malicious_ips WHERE ip = ?", (ip,))
            return cursor.fetchone() is not None
        except sqlite3.Error as e:
            logger.error(f"Error checking malicious IP {ip}: {e}")
            return False

    def get_recent_connections(self, hours: int = 1) -> List[Dict]:
        """
        Get recent connections for the network graph.

        Args:
            hours: Look back this many hours.

        Returns:
            List of connection dictionaries.
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT device_ip, dest_ip FROM connections
                WHERE timestamp > datetime('now', ? || ' hours')
                AND dest_ip IS NOT NULL
            """, (f'-{hours}',))
            return [dict(row) for row in cursor.fetchall()]
        except sqlite3.Error as e:
            logger.error(f"Error fetching recent connections: {e}")
            return []

    def get_traffic_timeline(self, hours: int = 24) -> List[Dict]:
        """Get traffic data for the timeline chart."""
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT
                    strftime('%Y-%m-%d %H:00:00', timestamp) as hour,
                    SUM(bytes_sent + bytes_received) as total_bytes
                FROM connections
                WHERE timestamp > datetime('now', ? || ' hours')
                GROUP BY hour
                ORDER BY hour
            """, (f'-{hours}',))
            return [dict(row) for row in cursor.fetchall()]
        except sqlite3.Error as e:
            logger.error(f"Error fetching traffic timeline: {e}")
            return []

    def get_protocol_distribution(self, hours: int = 24) -> List[Dict]:
        """Get protocol distribution for the pie chart."""
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT protocol, COUNT(*) as count
                FROM connections
                WHERE timestamp > datetime('now', ? || ' hours')
                GROUP BY protocol
            """, (f'-{hours}',))
            return [dict(row) for row in cursor.fetchall()]
        except sqlite3.Error as e:
            logger.error(f"Error fetching protocol distribution: {e}")
            return []

    def get_device_activity_heatmap(self, hours: int = 24) -> List[Dict]:
        """Get data for the device activity heatmap."""
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT
                    device_ip,
                    strftime('%H', timestamp) as hour,
                    COUNT(*) as count
                FROM connections
                WHERE timestamp > datetime('now', ? || ' hours')
                GROUP BY device_ip, hour
            """, (f'-{hours}',))
            return [dict(row) for row in cursor.fetchall()]
        except sqlite3.Error as e:
            logger.error(f"Error fetching device activity heatmap: {e}")
            return []

    def get_alert_timeline(self, days: int = 7) -> List[Dict]:
        """Get data for the alert timeline chart."""
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT
                    date(timestamp) as day,
                    severity,
                    COUNT(*) as count
                FROM alerts
                WHERE timestamp > datetime('now', ? || ' days')
                GROUP BY day, severity
                ORDER BY day
            """, (f'-{days}',))
            return [dict(row) for row in cursor.fetchall()]
        except sqlite3.Error as e:
            logger.error(f"Error fetching alert timeline: {e}")
            return []

    def get_anomaly_distribution(self, hours: int = 24) -> List[Dict]:
        """Get the distribution of anomaly scores."""
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT anomaly_score
                FROM ml_predictions
                WHERE is_anomaly = 1
                AND timestamp > datetime('now', ? || ' hours')
            """, (f'-{hours}',))
            return [dict(row) for row in cursor.fetchall()]
        except sqlite3.Error as e:
            logger.error(f"Error fetching anomaly distribution: {e}")
            return []

    def get_new_devices_count(self, days: int = 7) -> int:
        """Get the count of new devices seen in the last N days."""
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT COUNT(*) FROM devices
                WHERE first_seen > datetime('now', ? || ' days')
            """, (f'-{days}',))
            return cursor.fetchone()[0]
        except sqlite3.Error as e:
            logger.error(f"Error getting new devices count: {e}")
            return 0

    def cleanup_old_data(self, days: int = 30):
        """
        Delete data older than specified days and reclaim disk space.

        Args:
            days: Number of days to retain (default: 30)
        """
        cutoff_date = datetime.now() - timedelta(days=days)
        logger.info(f"Cleaning up data older than {cutoff_date}...")

        try:
            cursor = self.conn.cursor()

            # Delete old ML predictions
            cursor.execute(
                "DELETE FROM ml_predictions WHERE timestamp < ?",
                (cutoff_date,)
            )
            predictions_deleted = cursor.rowcount
            logger.info(f"{predictions_deleted} ML predictions deleted.")

            # Delete old connections
            cursor.execute(
                "DELETE FROM connections WHERE timestamp < ?",
                (cutoff_date,)
            )
            connections_deleted = cursor.rowcount
            logger.info(f"{connections_deleted} connections deleted.")

            # Delete old alerts
            cursor.execute(
                "DELETE FROM alerts WHERE timestamp < ?",
                (cutoff_date,)
            )
            alerts_deleted = cursor.rowcount
            logger.info(f"{alerts_deleted} alerts deleted.")

            self.conn.commit()
            cursor.close()

            # VACUUM must be run outside of a transaction
            # Temporarily enable autocommit mode
            logger.info("Reclaiming disk space (VACUUM)...")
            old_isolation = self.conn.isolation_level
            self.conn.isolation_level = None  # Enable autocommit mode

            try:
                cursor = self.conn.cursor()
                cursor.execute("VACUUM")
                cursor.close()
                logger.info("VACUUM completed successfully.")
            finally:
                # Restore original isolation level
                self.conn.isolation_level = old_isolation

            logger.info("Database cleanup completed successfully.")

        except sqlite3.Error as e:
            logger.error(f"Database cleanup failed: {e}")
            self.conn.rollback()

    def close(self):
        """Close database connection."""
        if self.conn:
            self.conn.close()
            logger.info("Database connection closed")


if __name__ == '__main__':
    # Quick test
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from config.config_manager import config

    logging.basicConfig(level=logging.INFO)

    db = DatabaseManager(config.get('database', 'path'))

    # Test operations
    print("Testing database operations...")

    # Add device
    success = db.add_device('192.168.1.100', device_name='Test Device', device_type='Laptop')
    print(f"Add device: {'✓' if success else '✗'}")

    # Add connection
    conn_id = db.add_connection('192.168.1.100', '8.8.8.8', 443, 'tcp', bytes_sent=1024)
    print(f"Add connection: {'✓' if conn_id else '✗'}")

    # Get devices
    devices = db.get_active_devices(minutes=60)
    print(f"Active devices: {len(devices)}")

    db.close()
    print("Database test complete!")
