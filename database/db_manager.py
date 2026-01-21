#!/usr/bin/env python3
"""
Professional Database Manager for IoTSentinel

Handles all database operations with:
- Connection pooling
- Transaction support
- Error handling
- Prepared statements
- Input validation
- Security best practices

100% Compatible with init_database.py schema
"""

import sqlite3
import logging
import re
from pathlib import Path
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Union
from utils.device_classifier import classifier

logger = logging.getLogger('database')  # Use dedicated database logger


class DatabaseError(Exception):
    """Custom exception for database errors."""
    pass


class ValidationError(Exception):
    """Custom exception for validation errors."""
    pass


class DatabaseManager:
    """
    SQLite database manager for IoTSentinel.

    Security features:
    - Parameterized queries (SQL injection prevention)
    - Input validation
    - Transaction management
    - Connection pooling via singleton
    - Error handling with rollback
    """

    # Validation patterns
    IP_PATTERN = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    MAC_PATTERN = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
    VALID_PROTOCOLS = {'tcp', 'udp', 'icmp', 'http', 'https', 'dns', 'mqtt', 'coap'}
    VALID_SEVERITIES = {'low', 'medium', 'high', 'critical'}

    @staticmethod
    def validate_ip(ip: str) -> bool:
        """Validate IP address format."""
        if not ip or not isinstance(ip, str):
            return False
        if not DatabaseManager.IP_PATTERN.match(ip):
            return False
        # Check each octet is 0-255
        octets = ip.split('.')
        return all(0 <= int(octet) <= 255 for octet in octets)

    @staticmethod
    def validate_mac(mac: str) -> bool:
        """Validate MAC address format."""
        if not mac or not isinstance(mac, str):
            return False
        return DatabaseManager.MAC_PATTERN.match(mac) is not None

    @staticmethod
    def validate_port(port: int) -> bool:
        """Validate port number."""
        return isinstance(port, int) and 0 <= port <= 65535

    @staticmethod
    def sanitize_string(value: str, max_length: int = 255) -> str:
        """Sanitize string input to prevent issues."""
        if not value:
            return ''
        # Remove null bytes and limit length
        sanitized = str(value).replace('\x00', '').strip()
        return sanitized[:max_length]

    _instances = {}  # Singleton instances per db_path
    _lock = None  # Thread lock for singleton pattern

    def __new__(cls, db_path: str):
        """Implement singleton pattern - one instance per db_path."""
        # Normalize path for comparison
        normalized_path = str(Path(db_path).resolve())

        if normalized_path not in cls._instances:
            instance = super(DatabaseManager, cls).__new__(cls)
            cls._instances[normalized_path] = instance
            instance._initialized = False  # Track if __init__ was called

        return cls._instances[normalized_path]

    def __init__(self, db_path: str):
        # Only initialize once per instance
        if self._initialized:
            return

        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self.conn = None
        self._connect()

        # Run schema migrations if needed
        self.migrate_schema()

        self._initialized = True
        logger.info(f"Database manager initialized: {self.db_path}")

    def _connect(self):
        """Establish database connection with optimizations and security."""
        try:
            self.conn = sqlite3.connect(
                str(self.db_path),
                check_same_thread=False,
                timeout=30.0,  # 30 second timeout for busy database
                isolation_level='DEFERRED'  # Explicit transaction control
            )
            self.conn.row_factory = sqlite3.Row

            # Security and performance pragmas
            self.conn.execute("PRAGMA foreign_keys = ON")  # Enforce referential integrity
            self.conn.execute("PRAGMA journal_mode = WAL")  # Write-Ahead Logging for concurrency
            self.conn.execute("PRAGMA synchronous = NORMAL")  # Balance safety/speed
            self.conn.execute("PRAGMA busy_timeout = 30000")  # 30 second busy timeout
            self.conn.execute("PRAGMA temp_store = MEMORY")  # Faster temp operations

            # Security: Prevent recursive triggers
            self.conn.execute("PRAGMA recursive_triggers = OFF")

        except sqlite3.Error as e:
            logger.critical(f"Failed to connect to database: {e}")
            raise DatabaseError(f"Database connection failed: {e}")

    def transaction(self):
        """Context manager for explicit transactions with automatic rollback on error."""
        class Transaction:
            def __init__(self, conn):
                self.conn = conn

            def __enter__(self):
                self.conn.execute("BEGIN")
                return self.conn

            def __exit__(self, exc_type, exc_val, exc_tb):
                if exc_type is not None:
                    self.conn.rollback()
                    logger.error(f"Transaction rolled back due to: {exc_val}")
                    return False  # Re-raise exception
                else:
                    self.conn.commit()
                    return True

        return Transaction(self.conn)

    def add_device(self, device_ip: str, **kwargs) -> bool:
        """
        Add or update device with automatic classification.

        Args:
            device_ip: Device IP address (PRIMARY KEY)
            **kwargs: Optional fields (device_name, device_type, mac_address, manufacturer, hostname)

        Returns:
            True if successful, False otherwise

        Raises:
            ValidationError: If input validation fails
        """
        # Input validation
        if not self.validate_ip(device_ip):
            raise ValidationError(f"Invalid IP address: {device_ip}")

        mac_address = kwargs.get('mac_address')
        if mac_address and not self.validate_mac(mac_address):
            raise ValidationError(f"Invalid MAC address: {mac_address}")

        try:
            with self.transaction():
                cursor = self.conn.cursor()

            # Auto-classify device if we have MAC address
            mac_address = kwargs.get('mac_address')
            hostname = kwargs.get('device_name') or kwargs.get('hostname')

            device_type = kwargs.get('device_type')
            manufacturer = kwargs.get('manufacturer')
            icon = kwargs.get('icon')
            category = kwargs.get('category')
            confidence = kwargs.get('confidence')

            # Automatically classify if not already classified
            if mac_address and (not device_type or device_type == 'unknown'):
                classification = classifier.classify_device(
                    mac_address=mac_address,
                    hostname=hostname,
                    ip_address=device_ip
                )

                device_type = classification['device_type']
                manufacturer = classification['manufacturer'] or manufacturer
                icon = classification['icon']
                category = classification['category']
                confidence = classification['confidence']

            cursor.execute("""
                INSERT INTO devices (
                    device_ip, device_name, mac_address, manufacturer,
                    device_type, icon, category, confidence,
                    first_seen, last_seen
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                ON CONFLICT(device_ip) DO UPDATE SET
                    device_name = COALESCE(excluded.device_name, devices.device_name),
                    mac_address = COALESCE(excluded.mac_address, devices.mac_address),
                    manufacturer = COALESCE(excluded.manufacturer, devices.manufacturer),
                    device_type = COALESCE(excluded.device_type, devices.device_type),
                    icon = COALESCE(excluded.icon, devices.icon),
                    category = COALESCE(excluded.category, devices.category),
                    confidence = COALESCE(excluded.confidence, devices.confidence),
                    last_seen = CURRENT_TIMESTAMP
            """, (
                device_ip,
                hostname,
                mac_address,
                manufacturer,
                device_type,
                icon,
                category,
                confidence
            ))

            self.conn.commit()
            return True

        except sqlite3.Error as e:
            logger.error(f"Error adding device {device_ip}: {e}")
            return False

    def add_connection(self, device_ip: str, dest_ip: str, dest_port: int,
                       protocol: str, **kwargs) -> Optional[int]:
        """
        Add network connection record with validation.

        Args:
            device_ip: Source device IP
            dest_ip: Destination IP
            dest_port: Destination port
            protocol: Protocol (tcp/udp/icmp)
            **kwargs: Optional fields (service, duration, bytes_sent, etc.)

        Returns:
            Connection ID if successful, None otherwise

        Raises:
            ValidationError: If input validation fails
        """
        # Input validation
        if not self.validate_ip(device_ip):
            raise ValidationError(f"Invalid source IP: {device_ip}")
        if not self.validate_ip(dest_ip):
            raise ValidationError(f"Invalid destination IP: {dest_ip}")
        if not self.validate_port(dest_port):
            raise ValidationError(f"Invalid port: {dest_port}")

        protocol_lower = protocol.lower() if protocol else ''
        if protocol_lower not in self.VALID_PROTOCOLS:
            logger.warning(f"Unusual protocol: {protocol}")

        try:
            with self.transaction():
                # Ensure device exists first
                self.add_device(device_ip)

                cursor = self.conn.cursor()

                # Sanitize string inputs
                service = self.sanitize_string(kwargs.get('service', ''), max_length=50)
                conn_state = self.sanitize_string(kwargs.get('conn_state', ''), max_length=20)

                cursor.execute("""
                    INSERT INTO connections
                    (device_ip, dest_ip, dest_port, protocol, service, duration,
                     bytes_sent, bytes_received, packets_sent, packets_received, conn_state)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    device_ip,
                    dest_ip,
                    dest_port,
                    protocol_lower,
                    service,
                    max(0, int(kwargs.get('duration', 0))),  # Ensure non-negative
                    max(0, int(kwargs.get('bytes_sent', 0))),
                    max(0, int(kwargs.get('bytes_received', 0))),
                    max(0, int(kwargs.get('packets_sent', 0))),
                    max(0, int(kwargs.get('packets_received', 0))),
                    conn_state
                ))

                return cursor.lastrowid

        except ValidationError:
            raise  # Re-raise validation errors
        except sqlite3.Error as e:
            logger.error(f"Database error adding connection from {device_ip}: {e}")
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
            model_type: Model used (river/legacy)
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

    def update_device_metadata(self, device_ip: str, **kwargs) -> bool:
        """
        Update device metadata fields.

        Args:
            device_ip: Device IP address
            **kwargs: Fields to update (custom_name, notes, firmware_version, model, etc.)

        Returns:
            True if successful
        """
        try:
            # Build dynamic UPDATE query
            fields = []
            values = []

            allowed_fields = ['custom_name', 'notes', 'firmware_version', 'model',
                            'device_type', 'manufacturer', 'category']

            for field, value in kwargs.items():
                if field in allowed_fields:
                    fields.append(f"{field} = ?")
                    values.append(value)

            if not fields:
                return True

            values.append(device_ip)

            cursor = self.conn.cursor()
            query = f"UPDATE devices SET {', '.join(fields)} WHERE device_ip = ?"
            cursor.execute(query, values)
            self.conn.commit()
            return True

        except sqlite3.Error as e:
            logger.error(f"Error updating device metadata: {e}")
            return False

    def add_device_to_group(self, device_ip: str, group_id: int, added_by: int = None) -> bool:
        """Add device to a group."""
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                INSERT OR IGNORE INTO device_group_members (device_ip, group_id, added_by)
                VALUES (?, ?, ?)
            """, (device_ip, group_id, added_by))
            self.conn.commit()
            return True
        except sqlite3.Error as e:
            logger.error(f"Error adding device to group: {e}")
            return False

    def remove_device_from_group(self, device_ip: str, group_id: int) -> bool:
        """Remove device from a group."""
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                DELETE FROM device_group_members
                WHERE device_ip = ? AND group_id = ?
            """, (device_ip, group_id))
            self.conn.commit()
            return True
        except sqlite3.Error as e:
            logger.error(f"Error removing device from group: {e}")
            return False

    def get_device_groups(self, device_ip: str) -> List[Dict]:
        """Get all groups a device belongs to."""
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT g.* FROM device_groups g
                JOIN device_group_members m ON g.id = m.group_id
                WHERE m.device_ip = ?
            """, (device_ip,))
            return [dict(row) for row in cursor.fetchall()]
        except sqlite3.Error as e:
            logger.error(f"Error fetching device groups: {e}")
            return []

    def get_all_groups(self) -> List[Dict]:
        """Get all device groups."""
        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT * FROM device_groups ORDER BY name")
            return [dict(row) for row in cursor.fetchall()]
        except sqlite3.Error as e:
            logger.error(f"Error fetching all groups: {e}")
            return []

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

    def _ensure_connection(self):
        """Ensure database connection is alive, reconnect if needed."""
        try:
            self.conn.execute("SELECT 1")
        except sqlite3.Error:
            logger.warning("Connection lost, reconnecting...")
            self._connect()

    def health_check(self) -> Dict:
        """
        Perform comprehensive database health check.

        Returns:
            Dictionary with health status and metrics
        """
        import time

        try:
            start = time.time()
            self._ensure_connection()
            cursor = self.conn.cursor()

            # Test query execution
            cursor.execute("SELECT COUNT(*) FROM devices")
            device_count = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM connections")
            connection_count = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM alerts WHERE acknowledged = 0")
            unacked_alerts = cursor.fetchone()[0]

            # Check WAL mode status
            cursor.execute("PRAGMA journal_mode")
            journal_mode = cursor.fetchone()[0]

            # Check foreign keys
            cursor.execute("PRAGMA foreign_keys")
            foreign_keys = cursor.fetchone()[0]

            # Get database size
            db_size = self.db_path.stat().st_size

            # Check WAL file size if exists
            wal_size = 0
            wal_path = Path(str(self.db_path) + '-wal')
            if wal_path.exists():
                wal_size = wal_path.stat().st_size

            query_time = time.time() - start

            # Determine health status
            status = 'healthy'
            warnings = []

            if wal_size > 10 * 1024 * 1024:  # 10MB
                warnings.append('WAL file is large, consider checkpoint')

            if db_size > 100 * 1024 * 1024:  # 100MB
                warnings.append('Database size growing, consider archiving')

            if unacked_alerts > 100:
                warnings.append(f'{unacked_alerts} unacknowledged alerts')

            if warnings:
                status = 'warning'

            return {
                'status': status,
                'timestamp': datetime.now().isoformat(),
                'metrics': {
                    'devices': device_count,
                    'connections': connection_count,
                    'unacknowledged_alerts': unacked_alerts,
                    'db_size_mb': round(db_size / 1024 / 1024, 2),
                    'wal_size_mb': round(wal_size / 1024 / 1024, 2),
                    'query_time_ms': round(query_time * 1000, 2)
                },
                'configuration': {
                    'journal_mode': journal_mode,
                    'foreign_keys': 'enabled' if foreign_keys else 'disabled',
                    'db_path': str(self.db_path)
                },
                'warnings': warnings
            }

        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return {
                'status': 'unhealthy',
                'timestamp': datetime.now().isoformat(),
                'error': str(e)
            }

    def backup_database(self, backup_dir: str = 'data/backups') -> Optional[str]:
        """
        Create a backup of the database with timestamp.

        Args:
            backup_dir: Directory to store backups

        Returns:
            Path to backup file if successful, None otherwise
        """
        import shutil

        try:
            backup_path = Path(backup_dir)
            backup_path.mkdir(parents=True, exist_ok=True)

            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_file = backup_path / f"iotsentinel_{timestamp}.db"

            # Use SQLite's native backup API - it's 100% safe on live databases
            # It pauses writes momentarily, copies chunks, and resumes writes
            logger.info(f"Creating backup using SQLite Backup API: {backup_file}")

            backup_conn = sqlite3.connect(str(backup_file))
            try:
                with backup_conn:
                    # Copy database using native backup API
                    # This is safe even if writes are happening
                    self.conn.backup(backup_conn, pages=100, progress=None)

                logger.info("✓ Backup completed successfully")

                # Verify backup
                backup_size = backup_file.stat().st_size
                original_size = self.db_path.stat().st_size

                if backup_size == 0:
                    logger.error("Backup file is empty!")
                    backup_file.unlink()
                    return None

                logger.info(f"✓ Backup created: {backup_file} ({backup_size / 1024 / 1024:.2f} MB)")
                return str(backup_file)

            finally:
                backup_conn.close()

        except Exception as e:
            logger.error(f"Backup failed: {e}")
            if backup_file.exists():
                backup_file.unlink()  # Clean up failed backup
            return None

    def get_schema_version(self) -> int:
        """
        Get current schema version from database.

        Returns:
            Schema version number (0 if not set)
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute("PRAGMA user_version")
            version = cursor.fetchone()[0]
            return version
        except Exception as e:
            logger.error(f"Failed to get schema version: {e}")
            return 0

    def set_schema_version(self, version: int) -> bool:
        """
        Set schema version in database.

        Args:
            version: Schema version number to set

        Returns:
            True if successful, False otherwise
        """
        try:
            self.conn.execute(f"PRAGMA user_version = {version}")
            self.conn.commit()
            logger.info(f"Schema version set to {version}")
            return True
        except Exception as e:
            logger.error(f"Failed to set schema version: {e}")
            return False

    def migrate_schema(self) -> bool:
        """
        Apply schema migrations based on current version.

        This method checks the current schema version and applies
        any necessary migrations to bring it up to date.

        Returns:
            True if migrations successful or not needed, False on error
        """
        CURRENT_SCHEMA_VERSION = 1  # Increment when you add migrations

        try:
            current_version = self.get_schema_version()

            if current_version == CURRENT_SCHEMA_VERSION:
                logger.debug(f"Schema already at version {current_version}")
                return True

            if current_version > CURRENT_SCHEMA_VERSION:
                logger.warning(f"Database schema version {current_version} is newer than expected {CURRENT_SCHEMA_VERSION}")
                return True

            logger.info(f"Migrating schema from v{current_version} to v{CURRENT_SCHEMA_VERSION}")

            # Apply migrations in order
            # Example: if current_version < 1:
            #     self._migrate_to_v1()
            # if current_version < 2:
            #     self._migrate_to_v2()

            # Future migration example:
            # def _migrate_to_v2(self):
            #     """Add firewall_status column to devices table."""
            #     with self.transaction():
            #         self.conn.execute("""
            #             ALTER TABLE devices
            #             ADD COLUMN firewall_status TEXT DEFAULT 'unknown'
            #         """)
            #         self.set_schema_version(2)

            # Set to current version if no migrations needed
            if current_version == 0:
                self.set_schema_version(CURRENT_SCHEMA_VERSION)

            return True

        except Exception as e:
            logger.error(f"Schema migration failed: {e}")
            return False

    def cleanup_old_backups(self, backup_dir: str = 'data/backups', keep_days: int = 7) -> int:
        """
        Remove backup files older than specified days.

        Args:
            backup_dir: Directory containing backups
            keep_days: Number of days to retain backups

        Returns:
            Number of backups deleted
        """
        try:
            backup_path = Path(backup_dir)
            if not backup_path.exists():
                return 0

            cutoff_time = datetime.now() - timedelta(days=keep_days)
            deleted_count = 0

            for backup_file in backup_path.glob('iotsentinel_*.db'):
                if backup_file.stat().st_mtime < cutoff_time.timestamp():
                    logger.info(f"Deleting old backup: {backup_file}")
                    backup_file.unlink()
                    deleted_count += 1

            logger.info(f"Cleaned up {deleted_count} old backups")
            return deleted_count

        except Exception as e:
            logger.error(f"Backup cleanup failed: {e}")
            return 0

    def add_connections_batch(self, connections: List[Dict]) -> int:
        """
        Add multiple connections in a single transaction for better performance.

        OPTIMIZATION: Data validation/preparation happens OUTSIDE the transaction.
        Transaction is opened only for the split second needed to write.
        This prevents blocking other writers in WAL mode.

        Args:
            connections: List of connection dictionaries with keys:
                        device_ip, dest_ip, dest_port, protocol, service, etc.

        Returns:
            Number of connections successfully inserted
        """
        if not connections:
            return 0

        # STEP 1: Validate and prepare ALL data BEFORE opening transaction
        # This keeps the transaction time minimal
        validated_data = []
        failed = 0

        for conn_data in connections:
            try:
                # Validate required fields
                device_ip = conn_data.get('device_ip')
                dest_ip = conn_data.get('dest_ip')
                dest_port = conn_data.get('dest_port', 0)
                protocol = conn_data.get('protocol', 'tcp').lower()

                if not device_ip or not dest_ip:
                    failed += 1
                    continue

                # Validate inputs
                if not self.validate_ip(device_ip) or not self.validate_ip(dest_ip):
                    failed += 1
                    continue

                if not self.validate_port(dest_port):
                    failed += 1
                    continue

                # Sanitize strings
                service = self.sanitize_string(conn_data.get('service', ''), 50)
                conn_state = self.sanitize_string(conn_data.get('conn_state', ''), 20)

                # Prepare tuple for insertion
                validated_data.append((
                    device_ip,
                    dest_ip,
                    dest_port,
                    protocol,
                    service,
                    max(0, int(conn_data.get('duration', 0))),
                    max(0, int(conn_data.get('bytes_sent', 0))),
                    max(0, int(conn_data.get('bytes_received', 0))),
                    max(0, int(conn_data.get('packets_sent', 0))),
                    max(0, int(conn_data.get('packets_received', 0))),
                    conn_state
                ))

            except (ValueError, KeyError) as e:
                logger.debug(f"Failed to validate connection: {e}")
                failed += 1
                continue

        if not validated_data:
            logger.warning(f"No valid connections to insert ({failed} failed validation)")
            return 0

        # STEP 2: Open transaction for MINIMAL time - only for writes
        inserted = 0
        try:
            cursor = self.conn.cursor()
            cursor.execute("BEGIN")

            # Get unique device IPs
            device_ips = set(row[0] for row in validated_data)

            # Batch insert devices
            cursor.executemany("""
                INSERT OR IGNORE INTO devices (device_ip, first_seen, last_seen)
                VALUES (?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            """, [(ip,) for ip in device_ips])

            # Batch insert connections
            cursor.executemany("""
                INSERT INTO connections
                (device_ip, dest_ip, dest_port, protocol, service, duration,
                 bytes_sent, bytes_received, packets_sent, packets_received, conn_state)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, validated_data)

            inserted = len(validated_data)
            self.conn.commit()

            if failed > 0:
                logger.warning(f"Batch insert: {inserted} successful, {failed} failed")
            else:
                logger.info(f"Batch insert: {inserted} connections added")

            return inserted

        except Exception as e:
            logger.error(f"Batch connection insert failed: {e}")
            self.conn.rollback()
            return 0

    def create_indexes(self):
        """
        Create performance indexes if they don't exist.
        Should be called after database initialization.
        """
        indexes = [
            # Connections table indexes
            ("idx_connections_device_ip", "connections", "device_ip"),
            ("idx_connections_timestamp", "connections", "timestamp"),
            ("idx_connections_dest_ip", "connections", "dest_ip"),
            ("idx_connections_protocol", "connections", "protocol"),

            # Alerts table indexes
            ("idx_alerts_device_ip", "alerts", "device_ip"),
            ("idx_alerts_timestamp", "alerts", "timestamp"),
            ("idx_alerts_severity", "alerts", "severity"),
            ("idx_alerts_acknowledged", "alerts", "acknowledged"),

            # Devices table indexes
            ("idx_devices_last_seen", "devices", "last_seen"),
            ("idx_devices_device_type", "devices", "device_type"),
            ("idx_devices_is_blocked", "devices", "is_blocked"),
            ("idx_devices_is_trusted", "devices", "is_trusted"),

            # ML predictions indexes
            ("idx_ml_predictions_connection_id", "ml_predictions", "connection_id"),
            ("idx_ml_predictions_timestamp", "ml_predictions", "timestamp"),
            ("idx_ml_predictions_is_anomaly", "ml_predictions", "is_anomaly"),
        ]

        try:
            cursor = self.conn.cursor()
            created = 0

            for index_name, table, column in indexes:
                try:
                    cursor.execute(f"""
                        CREATE INDEX IF NOT EXISTS {index_name}
                        ON {table}({column})
                    """)
                    created += 1
                except sqlite3.Error as e:
                    logger.warning(f"Could not create index {index_name}: {e}")

            self.conn.commit()
            logger.info(f"✓ Created/verified {created} database indexes")

        except sqlite3.Error as e:
            logger.error(f"Index creation failed: {e}")

    def optimize_database(self):
        """
        Perform database optimization operations.
        Run this periodically (e.g., weekly) to maintain performance.
        """
        try:
            logger.info("Starting database optimization...")

            # Analyze tables to update query optimizer statistics
            cursor = self.conn.cursor()
            cursor.execute("ANALYZE")
            logger.info("✓ Updated query statistics")

            # Checkpoint WAL
            cursor.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            logger.info("✓ Checkpointed WAL")

            # Vacuum to reclaim space (if not too large)
            db_size_mb = self.db_path.stat().st_size / 1024 / 1024
            if db_size_mb < 100:  # Only vacuum if DB < 100MB
                old_isolation = self.conn.isolation_level
                self.conn.isolation_level = None
                try:
                    cursor.execute("VACUUM")
                    logger.info("✓ Vacuumed database")
                finally:
                    self.conn.isolation_level = old_isolation
            else:
                logger.info("⊘ Skipped VACUUM (database too large)")

            self.conn.commit()
            logger.info("✓ Database optimization complete")

        except sqlite3.Error as e:
            logger.error(f"Database optimization failed: {e}")

    def get_database_stats(self) -> Dict:
        """
        Get comprehensive database statistics.

        Returns:
            Dictionary with various database metrics
        """
        try:
            cursor = self.conn.cursor()

            # Table row counts
            tables = {}
            for table in ['devices', 'connections', 'alerts', 'ml_predictions',
                         'users', 'device_groups', 'malicious_ips']:
                try:
                    cursor.execute(f"SELECT COUNT(*) FROM {table}")
                    tables[table] = cursor.fetchone()[0]
                except sqlite3.Error:
                    tables[table] = 0

            # Storage metrics
            db_size = self.db_path.stat().st_size

            wal_size = 0
            wal_path = Path(str(self.db_path) + '-wal')
            if wal_path.exists():
                wal_size = wal_path.stat().st_size

            # Recent activity
            cursor.execute("""
                SELECT COUNT(*) FROM connections
                WHERE timestamp > datetime('now', '-1 hour')
            """)
            recent_connections = cursor.fetchone()[0]

            cursor.execute("""
                SELECT COUNT(*) FROM alerts
                WHERE timestamp > datetime('now', '-24 hours')
            """)
            recent_alerts = cursor.fetchone()[0]

            return {
                'tables': tables,
                'storage': {
                    'database_size_mb': round(db_size / 1024 / 1024, 2),
                    'wal_size_mb': round(wal_size / 1024 / 1024, 2),
                    'total_size_mb': round((db_size + wal_size) / 1024 / 1024, 2)
                },
                'activity': {
                    'connections_last_hour': recent_connections,
                    'alerts_last_24h': recent_alerts
                },
                'timestamp': datetime.now().isoformat()
            }

        except Exception as e:
            logger.error(f"Failed to get database stats: {e}")
            return {}

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
