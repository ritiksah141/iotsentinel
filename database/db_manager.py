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

import json
import sqlite3
import logging
import re
import threading
import time
from pathlib import Path
from datetime import datetime, timedelta
from typing import (List, Dict, Optional)
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
    _singleton_lock = threading.Lock()  # Guards singleton creation

    def __new__(cls, db_path: str):
        """Implement singleton pattern - one instance per db_path."""
        # Normalize path for comparison
        normalized_path = str(Path(db_path).resolve())

        with cls._singleton_lock:
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

        # Per-instance write lock — serialises all mutating operations across threads.
        # Reads are left unlocked: WAL mode allows concurrent readers alongside writes.
        self._write_lock = threading.RLock()

        self.conn = None
        self.degraded = False       # True when WAL could not be enabled (disk problem)
        self.journal_mode = 'WAL'   # actual journal mode in use ('WAL' or 'DELETE')
        self._connect()

        # Run schema migrations if needed
        self.migrate_schema()

        self._initialized = True
        logger.info(f"Database manager initialized: {self.db_path}")

    def _connect(self):
        """Establish the database connection, resilient to disk/WAL failures.

        A full or failing SD card makes `PRAGMA journal_mode = WAL` raise
        sqlite3.OperationalError ("disk I/O error"). Crashing here is fatal in
        production: on the Pi both backend and dashboard build a DatabaseManager
        at import, so the exception kills the process; systemd restarts it, the
        crash repeats, and after ~5 restarts in 10s systemd's start-limit leaves
        the service dead -> the dashboard is permanently unreachable. To avoid
        that we degrade instead of dying:
          1. retry a few times for transient contention at boot,
          2. clear a stale -wal/-shm sidecar left by an unclean power-off,
          3. fall back to journal_mode=DELETE (rollback journal, no -shm/mmap),
          4. only raise if even a bare connect + trivial query is impossible.
        `self.degraded` records that WAL could not be enabled so the health UI
        can surface a real disk problem instead of silently limping.
        """
        self.degraded = False
        self.journal_mode = 'WAL'

        last_err = None
        for attempt in range(3):
            try:
                self._open_connection()
                self._apply_base_pragmas()
                if self._enable_wal():
                    self.journal_mode = 'WAL'
                    self.degraded = False
                else:
                    self.journal_mode = 'DELETE'
                    self.degraded = True
                return
            except sqlite3.OperationalError as e:
                last_err = e
                logger.warning(
                    f"DB connect attempt {attempt + 1}/3 failed: {e}")
                self._close_quietly()
                # A wedged WAL is unreadable anyway; clearing the sidecars lets
                # the next attempt re-create them on a healthy filesystem.
                self._remove_stale_wal_files()
                time.sleep(0.5 * (attempt + 1))
            except sqlite3.Error as e:
                last_err = e
                break

        # Last resort: a bare rollback-journal connection so the app can still
        # boot in degraded mode and report the disk problem to the operator.
        try:
            self._open_connection()
            self.conn.execute("PRAGMA journal_mode = DELETE")
            self.conn.execute("PRAGMA busy_timeout = 30000")
            self.conn.execute("SELECT 1")
            self.journal_mode = 'DELETE'
            self.degraded = True
            logger.error(
                "Database opened in DEGRADED mode (rollback journal). The "
                "storage device is likely full or failing -- check `df -h` and "
                f"`dmesg`. WAL was unavailable: {last_err}")
            return
        except sqlite3.Error as e:
            logger.critical(f"Failed to connect to database: {e}")
            raise DatabaseError(f"Database connection failed: {e}")

    def _open_connection(self):
        """Open the raw sqlite3 connection (no WAL/-shm-touching pragmas)."""
        self.conn = sqlite3.connect(
            str(self.db_path),
            check_same_thread=False,
            timeout=30.0,  # 30 second timeout for busy database
            isolation_level='DEFERRED'  # Explicit transaction control
        )
        self.conn.row_factory = sqlite3.Row

    def _apply_base_pragmas(self):
        """Pragmas that do NOT create the -wal/-shm sidecars, so they are safe
        even on a filesystem that can no longer support WAL."""
        self.conn.execute("PRAGMA foreign_keys = ON")  # Enforce referential integrity
        self.conn.execute("PRAGMA busy_timeout = 30000")  # 30 second busy timeout
        self.conn.execute("PRAGMA temp_store = MEMORY")  # Faster temp operations
        self.conn.execute("PRAGMA recursive_triggers = OFF")  # Prevent recursive triggers

    def _enable_wal(self) -> bool:
        """Switch to WAL for concurrency. Returns False (without raising) when
        the filesystem cannot support it, so the caller falls back gracefully."""
        try:
            cur = self.conn.execute("PRAGMA journal_mode = WAL")  # Write-Ahead Logging
            mode = (cur.fetchone() or [''])[0]
            if str(mode).upper() != 'WAL':
                logger.warning(
                    f"WAL not enabled (mode={mode!r}); using rollback journal.")
                return False
            self.conn.execute("PRAGMA synchronous = NORMAL")  # Balance safety/speed
            # Checkpoint WAL automatically every 1000 pages (~4 MB) so it does
            # not grow unbounded between manual checkpoints.
            self.conn.execute("PRAGMA wal_autocheckpoint = 1000")
            return True
        except sqlite3.OperationalError as e:
            logger.warning(
                f"Could not enable WAL ({e}); using rollback journal.")
            return False

    def _remove_stale_wal_files(self):
        """Delete -wal/-shm sidecars left by an unclean shutdown. Only called
        after a failed open (no live connection holds them), and only matters
        when the WAL is already unreadable -- so no committed data is at risk."""
        for suffix in ('-wal', '-shm'):
            side = Path(str(self.db_path) + suffix)
            try:
                if side.exists():
                    side.unlink()
                    logger.warning(f"Removed stale WAL sidecar {side.name}")
            except OSError as e:
                logger.warning(f"Could not remove {side.name}: {e}")

    def _close_quietly(self):
        """Close the connection, swallowing any error (used between retries)."""
        try:
            if self.conn is not None:
                self.conn.close()
        except Exception:
            pass
        self.conn = None

    def transaction(self):
        """Context manager for explicit transactions with automatic rollback on error.

        Acquires the write lock for the duration of the transaction so that
        concurrent threads cannot interleave BEGIN/COMMIT sequences on the
        shared SQLite connection.
        """
        lock = self._write_lock

        class Transaction:
            def __init__(self, conn):
                self.conn = conn

            def __enter__(self):
                lock.acquire()
                self.conn.execute("BEGIN")
                return self.conn

            def __exit__(self, exc_type, exc_val, exc_tb):
                try:
                    if exc_type is not None:
                        self.conn.rollback()
                        logger.error(f"Transaction rolled back due to: {exc_val}")
                        return False  # Re-raise exception
                    else:
                        self.conn.commit()
                        return True
                finally:
                    lock.release()

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
            # Classification is CPU-bound — run it BEFORE acquiring the write lock
            # so we don't hold the lock while waiting for network/OUI lookups.
            hostname = kwargs.get('device_name') or kwargs.get('hostname')
            device_type = kwargs.get('device_type')
            manufacturer = kwargs.get('manufacturer')
            icon = kwargs.get('icon')
            category = kwargs.get('category')
            confidence = kwargs.get('confidence')

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

            # Write section — serialised by RLock (re-entrant, so safe when
            # called from inside add_connection's transaction() context).
            with self._write_lock:
                cursor = self.conn.cursor()
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
            with self._write_lock:
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
            with self._write_lock:
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
                     explanation: str, top_features: str,
                     plain_explanation: Optional[str] = None,
                     mitre_tactic: Optional[str] = None) -> Optional[int]:
        """
        Create security alert.

        Args:
            device_ip: Device that triggered alert
            severity: Alert severity (low/medium/high/critical)
            anomaly_score: Anomaly score that triggered alert
            explanation: Technical explanation (kept for security_admin view)
            top_features: JSON string of top contributing features
            plain_explanation: Non-technical one-sentence summary (home_user view)
            mitre_tactic: MITRE ATT&CK tactic string for the Attack Path Sankey

        Returns:
            Alert ID if successful, None otherwise
        """
        # Suppress-check: skip alert if device is currently muted
        if self.is_alert_suppressed(device_ip):
            logger.debug(f"Alert suppressed for {device_ip} — skipping insert")
            return None

        try:
            with self._write_lock:
                cursor = self.conn.cursor()
                cursor.execute("""
                    INSERT INTO alerts
                    (device_ip, severity, anomaly_score, explanation, top_features, plain_explanation, mitre_tactic)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (device_ip, severity, anomaly_score, explanation, top_features, plain_explanation, mitre_tactic))
                self.conn.commit()
            alert_id = cursor.lastrowid
            logger.info(f"Created {severity} alert for {device_ip}")

            # Correlate into an incident (best-effort — never blocks alert creation)
            try:
                self.correlate_alert_to_incident(alert_id, device_ip, severity)
            except Exception:
                pass

            return alert_id
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
            with self._write_lock:
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

            with self._write_lock:
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
            with self._write_lock:
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
            with self._write_lock:
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

    # ------------------------------------------------------------------
    # Smart-home room CRUD
    # ------------------------------------------------------------------

    def get_all_rooms(self) -> List[Dict]:
        """Return all smart-home rooms with their device count."""
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT r.id, r.room_name, r.room_type, r.floor_level, r.icon, r.created_at,
                       COUNT(a.device_ip) as device_count
                FROM smart_home_rooms r
                LEFT JOIN device_room_assignments a ON r.id = a.room_id
                GROUP BY r.id
                ORDER BY r.floor_level, r.room_name
            """)
            return [dict(row) for row in cursor.fetchall()]
        except sqlite3.Error as e:
            logger.error(f"Error fetching rooms: {e}")
            return []

    def add_room(self, room_name: str, room_type: str = None, icon: str = None,
                 floor_level: int = 0) -> Optional[int]:
        """Create a new smart-home room; returns new row id or None."""
        try:
            with self._write_lock:
                cursor = self.conn.cursor()
                cursor.execute("""
                    INSERT OR IGNORE INTO smart_home_rooms (room_name, room_type, icon, floor_level)
                    VALUES (?, ?, ?, ?)
                """, (room_name, room_type, icon, floor_level))
                self.conn.commit()
                return cursor.lastrowid
        except sqlite3.Error as e:
            logger.error(f"Error adding room: {e}")
            return None

    def delete_room(self, room_id: int) -> bool:
        """Delete a room and its device assignments."""
        try:
            with self._write_lock:
                cursor = self.conn.cursor()
                cursor.execute("DELETE FROM device_room_assignments WHERE room_id = ?", (room_id,))
                cursor.execute("DELETE FROM smart_home_rooms WHERE id = ?", (room_id,))
                self.conn.commit()
            return True
        except sqlite3.Error as e:
            logger.error(f"Error deleting room: {e}")
            return False

    def add_device_to_room(self, device_ip: str, room_id: int) -> bool:
        """Assign a device to a room."""
        try:
            with self._write_lock:
                cursor = self.conn.cursor()
                cursor.execute("""
                    INSERT OR IGNORE INTO device_room_assignments (device_ip, room_id)
                    VALUES (?, ?)
                """, (device_ip, room_id))
                self.conn.commit()
            return True
        except sqlite3.Error as e:
            logger.error(f"Error adding device to room: {e}")
            return False

    def remove_device_from_room(self, device_ip: str, room_id: int) -> bool:
        """Remove a device from a room."""
        try:
            with self._write_lock:
                cursor = self.conn.cursor()
                cursor.execute("""
                    DELETE FROM device_room_assignments
                    WHERE device_ip = ? AND room_id = ?
                """, (device_ip, room_id))
                self.conn.commit()
            return True
        except sqlite3.Error as e:
            logger.error(f"Error removing device from room: {e}")
            return False

    def get_room_devices(self, room_id: int) -> List[Dict]:
        """Return all devices assigned to a room."""
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT d.* FROM devices d
                JOIN device_room_assignments a ON d.device_ip = a.device_ip
                WHERE a.room_id = ?
                ORDER BY d.device_name
            """, (room_id,))
            return [dict(row) for row in cursor.fetchall()]
        except sqlite3.Error as e:
            logger.error(f"Error fetching room devices: {e}")
            return []

    # ------------------------------------------------------------------
    # Smart-home automation CRUD
    # ------------------------------------------------------------------

    def get_all_automations(self) -> List[Dict]:
        """Return all smart-home automations."""
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT * FROM smart_home_automations ORDER BY created_at DESC
            """)
            return [dict(row) for row in cursor.fetchall()]
        except sqlite3.Error as e:
            logger.error(f"Error fetching automations: {e}")
            return []

    def save_automation(self, name: str, trigger_type: str, condition_text: str,
                        action_text: str) -> Optional[int]:
        """Persist a new automation; returns new row id or None."""
        try:
            with self._write_lock:
                cursor = self.conn.cursor()
                cursor.execute("""
                    INSERT INTO smart_home_automations
                        (name, trigger_type, condition_text, action_text)
                    VALUES (?, ?, ?, ?)
                """, (name, trigger_type, condition_text, action_text))
                self.conn.commit()
                return cursor.lastrowid
        except sqlite3.Error as e:
            logger.error(f"Error saving automation: {e}")
            return None

    def delete_automation(self, automation_id: int) -> bool:
        """Delete an automation by id."""
        try:
            with self._write_lock:
                cursor = self.conn.cursor()
                cursor.execute("DELETE FROM smart_home_automations WHERE id = ?", (automation_id,))
                self.conn.commit()
            return True
        except sqlite3.Error as e:
            logger.error(f"Error deleting automation: {e}")
            return False

    def toggle_automation(self, automation_id: int, enabled: bool) -> bool:
        """Enable or disable an automation."""
        try:
            with self._write_lock:
                cursor = self.conn.cursor()
                cursor.execute(
                    "UPDATE smart_home_automations SET is_enabled = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                    (1 if enabled else 0, automation_id)
                )
                self.conn.commit()
            return True
        except sqlite3.Error as e:
            logger.error(f"Error toggling automation: {e}")
            return False

    def acknowledge_alert(self, alert_id: int) -> bool:
        """Mark alert as acknowledged."""
        try:
            with self._write_lock:
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

    # ------------------------------------------------------------------
    # Alert suppression helpers
    # ------------------------------------------------------------------

    def suppress_device_alerts(self, device_ip: str, hours: Optional[int], created_by: str) -> bool:
        """
        Suppress future alerts for *device_ip* for *hours* hours.

        Pass hours=None to suppress indefinitely.
        Old suppressions for the same device are deleted first (one active rule per device).
        """
        try:
            expires_at = None
            if hours is not None:
                expires_at = (datetime.now() + timedelta(hours=hours)).strftime('%Y-%m-%d %H:%M:%S')
            with self._write_lock:
                cursor = self.conn.cursor()
                # Remove any previous suppression for this device
                cursor.execute("DELETE FROM alert_suppressions WHERE device_ip = ?", (device_ip,))
                cursor.execute(
                    "INSERT INTO alert_suppressions (device_ip, expires_at, created_by) VALUES (?, ?, ?)",
                    (device_ip, expires_at, created_by),
                )
                self.conn.commit()
            label = f"{hours}h" if hours else "indefinitely"
            logger.info(f"Alert suppression set for {device_ip} ({label}) by {created_by}")
            return True
        except sqlite3.Error as e:
            logger.error(f"Error setting suppression for {device_ip}: {e}")
            return False

    def is_alert_suppressed(self, device_ip: str) -> bool:
        """Return True if there is an active (non-expired) suppression for device_ip."""
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                """
                SELECT 1 FROM alert_suppressions
                WHERE device_ip = ?
                  AND (expires_at IS NULL OR expires_at > datetime('now'))
                LIMIT 1
                """,
                (device_ip,),
            )
            return cursor.fetchone() is not None
        except sqlite3.Error as e:
            logger.error(f"Error checking suppression for {device_ip}: {e}")
            return False

    def get_active_suppressions(self) -> list:
        """Return all active suppressions (unexpired or indefinite)."""
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                """
                SELECT s.*, d.device_name
                FROM alert_suppressions s
                LEFT JOIN devices d ON s.device_ip = d.device_ip
                WHERE s.expires_at IS NULL OR s.expires_at > datetime('now')
                ORDER BY s.created_at DESC
                """
            )
            return [dict(row) for row in cursor.fetchall()]
        except sqlite3.Error as e:
            logger.error(f"Error fetching active suppressions: {e}")
            return []

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
            with self._write_lock:
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
            with self._write_lock:
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
            with self._write_lock:
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
            data = [(ip, source) for ip in ips]
            with self._write_lock:
                cursor = self.conn.cursor()
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
        Delete data older than per-table retention windows and reclaim WAL space.

        Retention is read from config['database']['retention'] (a dict of
        table → days).  The ``days`` parameter is used as the fallback for any
        table not listed there, preserving backward-compatibility with callers
        that pass an explicit value.

        Tables pruned:
          connections, ml_predictions, alerts, audit_log, security_audit_log,
          agent_actions, rate_limit_log, api_integration_logs, toast_history,
          discovery_events, security_score_history, sustainability_metrics,
          device_energy_estimates, model_performance, model_drift_history,
          dns_queries (7 days — prevents unbounded SD card growth),
          alert_suppressions (expired rows only — no time-window needed)
        """
        from config.config_manager import config as _cfg

        # Per-table retention windows (days)
        _defaults = {
            'connections':              days,
            'ml_predictions':           days,
            'alerts':                   90,
            'audit_log':               180,
            'security_audit_log':      180,
            'agent_actions':           180,
            'rate_limit_log':            7,
            'api_integration_logs':     30,
            'toast_history':            30,
            'discovery_events':         30,
            'security_score_history':   90,
            'sustainability_metrics':   90,
            'device_energy_estimates':  90,
            'model_performance':        90,
            'model_drift_history':      90,
            'dns_queries':               7,  # DNS logs: 7 days (Pi SD card protection)
        }
        retention_cfg = _cfg.get('database', 'retention', default={}) or {}
        # Merge: config overrides defaults, keeping fallback = ``days`` param
        retention = {t: retention_cfg.get(t, d) for t, d in _defaults.items()}

        # (table, timestamp_column) pairs
        _table_ts = [
            ('connections',             'timestamp'),
            ('ml_predictions',          'timestamp'),
            ('alerts',                  'timestamp'),
            ('audit_log',               'timestamp'),
            ('security_audit_log',      'timestamp'),
            ('agent_actions',           'created_at'),
            ('rate_limit_log',          'timestamp'),
            ('api_integration_logs',    'timestamp'),
            ('toast_history',           'timestamp'),
            ('discovery_events',        'timestamp'),
            ('security_score_history',  'timestamp'),
            ('sustainability_metrics',  'timestamp'),
            ('device_energy_estimates', 'date'),
            ('model_performance',       'timestamp'),
            ('model_drift_history',     'timestamp'),
            ('dns_queries',             'timestamp'),
        ]

        logger.info("Starting tiered database cleanup…")
        total_deleted = 0

        try:
            with self._write_lock:
                cursor = self.conn.cursor()
                cursor.execute("BEGIN")

                for table, ts_col in _table_ts:
                    keep_days = retention.get(table, days)
                    cutoff = (datetime.now() - timedelta(days=keep_days)).strftime('%Y-%m-%d %H:%M:%S')
                    try:
                        cursor.execute(
                            f"DELETE FROM {table} WHERE {ts_col} < ?",  # noqa: S608
                            (cutoff,)
                        )
                        n = cursor.rowcount
                        if n:
                            logger.info(f"  {table}: deleted {n} rows older than {keep_days}d")
                        total_deleted += n
                    except sqlite3.OperationalError as e:
                        # Table may not exist on older installs; log and continue
                        logger.debug(f"  {table}: skipped ({e})")

                # Remove expired suppressions (not time-window based — just past expiry)
                cursor.execute(
                    "DELETE FROM alert_suppressions "
                    "WHERE expires_at IS NOT NULL AND expires_at < datetime('now')"
                )
                expired_sup = cursor.rowcount
                if expired_sup:
                    logger.info(f"  alert_suppressions: removed {expired_sup} expired rows")

                self.conn.commit()

            logger.info(f"Cleanup complete: {total_deleted} total rows removed.")

            # WAL checkpoint — flush WAL frames back to the main DB file.
            # This keeps the WAL from growing indefinitely between autocheckpoints.
            with self._write_lock:
                self.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            logger.info("WAL checkpoint done.")

            # VACUUM only when the DB is small enough that it won't block for
            # a long time.  On a busy Pi the DB can exceed 100 MB within months;
            # above that threshold we skip VACUUM (WAL checkpoint is sufficient
            # to reclaim space from deleted rows in WAL mode).
            vacuum_threshold_mb = _cfg.get('database', 'vacuum_threshold_mb', default=100)
            try:
                db_size_mb = self.db_path.stat().st_size / 1024 / 1024
            except (FileNotFoundError, OSError):
                db_size_mb = 0  # in-memory / missing file → allow VACUUM
            if db_size_mb < vacuum_threshold_mb:
                logger.info(f"Running VACUUM (DB {db_size_mb:.1f} MB < {vacuum_threshold_mb} MB)…")
                with self._write_lock:
                    old_isolation = self.conn.isolation_level
                    self.conn.isolation_level = None
                    try:
                        self.conn.execute("VACUUM")
                        logger.info("VACUUM complete.")
                    finally:
                        self.conn.isolation_level = old_isolation
            else:
                logger.info(
                    f"Skipping VACUUM (DB {db_size_mb:.1f} MB ≥ {vacuum_threshold_mb} MB); "
                    "WAL checkpoint is sufficient."
                )

        except sqlite3.Error as e:
            logger.error(f"Database cleanup failed: {e}")
            try:
                self.conn.rollback()
            except Exception:
                pass

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
        CURRENT_SCHEMA_VERSION = 10  # Increment when you add migrations

        try:
            current_version = self.get_schema_version()

            if current_version == CURRENT_SCHEMA_VERSION:
                logger.debug(f"Schema already at version {current_version}")
                return True

            if current_version > CURRENT_SCHEMA_VERSION:
                logger.warning(f"Database schema version {current_version} is newer than expected {CURRENT_SCHEMA_VERSION}")
                return True

            logger.info(f"Migrating schema from v{current_version} to v{CURRENT_SCHEMA_VERSION}")

            if current_version < 1:
                self.set_schema_version(1)
                current_version = 1

            # v1 → v2: plain_explanation column for home-user plain-English alert cards
            if current_version < 2:
                self._migrate_to_v2()
                current_version = 2

            # v2 → v3: agent_actions table for autonomous security agent
            if current_version < 3:
                self._migrate_to_v3()
                current_version = 3

            # v3 → v4: alert_suppressions + system_settings tables
            if current_version < 4:
                self._migrate_to_v4()
                current_version = 4

            # v4 → v5: must_change_password on users + smart_home_automations table
            if current_version < 5:
                self._migrate_to_v5()
                current_version = 5

            # v5 → v6: agent_actions.investigation for visible reasoning timeline
            if current_version < 6:
                self._migrate_to_v6()
                current_version = 6

            # v6 → v7: plain_explanation_ai flag — tracks which alerts have LLM-rewritten text
            if current_version < 7:
                self._migrate_to_v7()
                current_version = 7

            # v7 → v8: incidents table for correlated alert grouping
            if current_version < 8:
                self._migrate_to_v8()
                current_version = 8

            # v8 → v9: ai_source column on alerts + agent_actions — persists which
            #           provider (groq/openai/ollama/rules) wrote each plain-English text
            if current_version < 9:
                self._migrate_to_v9()
                current_version = 9

            # v9 → v10: mitre_tactic column on alerts — persists the kill-chain tactic
            #            so the Attack Path Sankey can group by real MITRE stage
            if current_version < 10:
                self._migrate_to_v10()
                current_version = 10

            return True

        except Exception as e:
            logger.error(f"Schema migration failed: {e}")
            return False

    def _migrate_to_v2(self):
        """Add plain_explanation column to alerts table."""
        try:
            self.conn.execute("ALTER TABLE alerts ADD COLUMN plain_explanation TEXT")
            self.conn.commit()
        except sqlite3.OperationalError:
            pass  # Column already exists — idempotent
        self.set_schema_version(2)
        logger.info("Migration v2 complete: alerts.plain_explanation added")

    def _migrate_to_v3(self):
        """Create agent_actions table for the autonomous security agent."""
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS agent_actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id INTEGER,
                device_ip TEXT NOT NULL,
                action_type TEXT NOT NULL,
                params TEXT,
                risk_level TEXT DEFAULT 'low',
                rationale TEXT,
                plain_report TEXT,
                status TEXT DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                resolved_at TIMESTAMP,
                resolved_by TEXT,
                FOREIGN KEY (alert_id) REFERENCES alerts(id) ON DELETE SET NULL
            )
        ''')
        self.conn.execute(
            'CREATE INDEX IF NOT EXISTS idx_agent_actions_status '
            'ON agent_actions(status, created_at DESC)'
        )
        self.conn.execute(
            'CREATE INDEX IF NOT EXISTS idx_agent_actions_device '
            'ON agent_actions(device_ip, created_at DESC)'
        )
        self.conn.commit()
        self.set_schema_version(3)
        logger.info("Migration v3 complete: agent_actions table created")

    def _migrate_to_v4(self):
        """Create alert_suppressions and system_settings tables."""
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS alert_suppressions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_ip TEXT NOT NULL,
                expires_at TIMESTAMP,
                created_by TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        self.conn.execute(
            'CREATE INDEX IF NOT EXISTS idx_suppressions_device '
            'ON alert_suppressions(device_ip, expires_at)'
        )
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS system_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        self.conn.commit()
        self.set_schema_version(4)
        logger.info("Migration v4 complete: alert_suppressions + system_settings created")

    def _migrate_to_v5(self):
        """
        v5 migration — three additions:
          1. users.must_change_password column
          2. smart_home_rooms + device_room_assignments tables (rooms feature)
          3. smart_home_automations table (new schema)

        Every statement is idempotent (IF NOT EXISTS / try-except on ALTER TABLE).
        """
        # 1. users.must_change_password
        try:
            self.conn.execute(
                "ALTER TABLE users ADD COLUMN must_change_password INTEGER DEFAULT 0"
            )
        except sqlite3.OperationalError:
            pass  # Column already exists

        # 2a. smart_home_rooms — needed by the room-assignment feature.
        #     DBs created before this table existed (pre-smart-home) will get it here.
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS smart_home_rooms (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                room_name TEXT UNIQUE NOT NULL,
                room_type TEXT,
                floor_level INTEGER,
                icon TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # 2b. device_room_assignments
        #     Note: SQLite cannot ADD a foreign key to an existing table via ALTER,
        #     so upgraded DBs that already have this table do not gain the CASCADE FK.
        #     This is safe because delete_room() always manually deletes child rows
        #     before deleting the parent room (db_manager.py delete_room).
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS device_room_assignments (
                device_ip TEXT,
                room_id INTEGER,
                assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (device_ip, room_id),
                FOREIGN KEY (room_id) REFERENCES smart_home_rooms(id) ON DELETE CASCADE
            )
        """)

        # 3. smart_home_automations — create with new schema.
        #    An older version of this table had different columns (automation_name,
        #    trigger_device_ip, …).  If that old table exists, drop and recreate it —
        #    safe only because the old table was always empty.
        cursor = self.conn.cursor()
        cursor.execute("PRAGMA table_info(smart_home_automations)")
        existing_cols = {row[1] for row in cursor.fetchall()}
        if existing_cols and 'name' not in existing_cols:
            self.conn.execute("DROP TABLE smart_home_automations")
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS smart_home_automations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                trigger_type TEXT NOT NULL,
                condition_text TEXT,
                action_text TEXT NOT NULL,
                is_enabled INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        self.conn.commit()
        self.set_schema_version(5)
        logger.info("Migration v5 complete: must_change_password + smart_home tables")

    def _migrate_to_v6(self):
        """
        v6 migration — agent_actions.investigation TEXT (JSON steps for the
        visible reasoning timeline). Fresh DBs already have this column via
        init_database.py, so the ALTER is wrapped in a try/except.
        """
        try:
            self.conn.execute(
                "ALTER TABLE agent_actions ADD COLUMN investigation TEXT"
            )
        except Exception:
            pass  # Column already exists
        self.conn.commit()
        self.set_schema_version(6)
        logger.info("Migration v6 complete: agent_actions.investigation column added")

    def _migrate_to_v7(self):
        """
        v7 migration — alerts.plain_explanation_ai INTEGER DEFAULT 0.

        Tracks whether the plain_explanation was written by an LLM (1) or is
        still the initial rule/MITRE template (0). The background plain-English
        rewrite worker uses this flag to find alerts that still need rewrites.
        Fresh DBs get the column in init_database.py so the ALTER is idempotent.
        """
        try:
            self.conn.execute(
                "ALTER TABLE alerts ADD COLUMN plain_explanation_ai INTEGER DEFAULT 0"
            )
        except Exception:
            pass  # Column already exists
        self.conn.commit()
        self.set_schema_version(7)
        logger.info("Migration v7 complete: alerts.plain_explanation_ai flag added")

    def _migrate_to_v8(self):
        """v8 migration — incidents table for correlated alert grouping."""
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                device_ip TEXT NOT NULL,
                title TEXT NOT NULL,
                max_severity TEXT DEFAULT 'low',
                status TEXT DEFAULT 'open',
                alert_count INTEGER DEFAULT 1,
                alert_ids TEXT NOT NULL,
                FOREIGN KEY (device_ip) REFERENCES devices(device_ip)
            )
        ''')
        self.conn.execute(
            'CREATE INDEX IF NOT EXISTS idx_incidents_device_status '
            'ON incidents(device_ip, status, updated_at)'
        )
        self.conn.commit()
        self.set_schema_version(8)
        logger.info("Migration v8 complete: incidents table created")

    def _migrate_to_v9(self):
        """v9 migration — ai_source TEXT on alerts and agent_actions.

        Records which AI provider (groq/openai/ollama/rules) wrote each
        plain-English explanation so the UI can show 'Explained by Groq AI'
        etc. on alert cards and agent action cards.
        Fresh DBs get this column via init_database.py so ALTERs are idempotent.
        """
        for stmt in (
            "ALTER TABLE alerts ADD COLUMN ai_source TEXT",
            "ALTER TABLE agent_actions ADD COLUMN ai_source TEXT",
        ):
            try:
                self.conn.execute(stmt)
            except Exception:
                pass  # Column already exists
        self.conn.commit()
        self.set_schema_version(9)
        logger.info("Migration v9 complete: ai_source column added to alerts + agent_actions")

    def _migrate_to_v10(self):
        """v10 migration — mitre_tactic TEXT on alerts.

        Persists the MITRE ATT&CK tactic (e.g. "Exfiltration (TA0010) - ...")
        for each alert at insert time so the Attack Path & Kill Chain Sankey can
        group alerts by real kill-chain stage instead of trying to match the full
        free-text explanation against a small keyword dictionary (which never hit,
        leaving the chart blank). Fresh DBs get this column via init_database.py so
        the ALTER is idempotent.
        """
        try:
            self.conn.execute("ALTER TABLE alerts ADD COLUMN mitre_tactic TEXT")
        except Exception:
            pass  # Column already exists
        self.conn.commit()
        self.set_schema_version(10)
        logger.info("Migration v10 complete: mitre_tactic column added to alerts")

    # ------------------------------------------------------------------
    # Incident correlation
    # ------------------------------------------------------------------

    _INCIDENT_SEVERITY_RANK = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}

    def _incident_title(self, max_severity: str, alert_count: int) -> str:
        """Generate a human-readable incident title based on severity and alert count."""
        if alert_count == 1:
            return {
                'critical': 'Critical threat detected',
                'high': 'High-priority alert',
                'medium': 'Suspicious activity detected',
                'low': 'Unusual activity detected',
            }.get(max_severity, 'Unusual activity detected')
        if alert_count < 5:
            return {
                'critical': 'Critical: repeated threat activity',
                'high': 'Repeated high-priority alerts',
                'medium': 'Pattern of suspicious behaviour',
                'low': 'Repeated unusual activity',
            }.get(max_severity, 'Repeated unusual activity')
        return {
            'critical': 'Active critical incident',
            'high': 'Ongoing security incident',
            'medium': 'Ongoing suspicious behaviour',
            'low': 'Ongoing unusual activity',
        }.get(max_severity, 'Ongoing security incident')

    def correlate_alert_to_incident(self, alert_id: int, device_ip: str, severity: str) -> int:
        """Add alert_id to an open recent incident for device_ip, or create a new one.

        An open incident is any incident for the same device with status='open'
        and updated_at within the last 30 minutes.  Returns the incident ID.
        """
        try:
            with self._write_lock:
                cur = self.conn.cursor()

                # Find most recent open incident for this device within 30 min
                cur.execute(
                    """SELECT id, alert_ids, max_severity, alert_count
                       FROM incidents
                       WHERE device_ip = ? AND status = 'open'
                         AND updated_at >= datetime('now', '-30 minutes')
                       ORDER BY updated_at DESC
                       LIMIT 1""",
                    (device_ip,)
                )
                row = cur.fetchone()

                if row:
                    inc_id, alert_ids_json, cur_max_sev, cur_count = row
                    try:
                        ids = json.loads(alert_ids_json)
                    except Exception:
                        ids = []
                    if alert_id not in ids:
                        ids.append(alert_id)

                    new_count = len(ids)
                    new_max = (
                        severity
                        if self._INCIDENT_SEVERITY_RANK.get(severity, 0)
                        > self._INCIDENT_SEVERITY_RANK.get(cur_max_sev, 0)
                        else cur_max_sev
                    )
                    new_title = self._incident_title(new_max, new_count)

                    cur.execute(
                        """UPDATE incidents
                           SET alert_ids = ?, max_severity = ?, alert_count = ?,
                               title = ?, updated_at = CURRENT_TIMESTAMP
                           WHERE id = ?""",
                        (json.dumps(ids), new_max, new_count, new_title, inc_id),
                    )
                    self.conn.commit()
                    return inc_id

                # No recent open incident — create a new one
                new_title = self._incident_title(severity, 1)
                cur.execute(
                    """INSERT INTO incidents
                       (device_ip, title, max_severity, status, alert_count, alert_ids)
                       VALUES (?, ?, ?, 'open', 1, ?)""",
                    (device_ip, new_title, severity, json.dumps([alert_id])),
                )
                self.conn.commit()
                return cur.lastrowid

        except Exception as exc:
            logger.warning(f"Incident correlation failed for alert {alert_id}: {exc}")
            return 0

    def get_open_incidents(self, limit: int = 20) -> List[Dict]:
        """Return open incidents ordered by severity then recency, joined with device name."""
        try:
            cur = self.conn.cursor()
            cur.execute(
                """SELECT i.id, i.created_at, i.updated_at, i.device_ip,
                          COALESCE(d.device_name, i.device_ip) AS device_name,
                          i.title, i.max_severity, i.status, i.alert_count, i.alert_ids
                   FROM incidents i
                   LEFT JOIN devices d ON i.device_ip = d.device_ip
                   WHERE i.status = 'open'
                   ORDER BY
                       CASE i.max_severity
                           WHEN 'critical' THEN 1 WHEN 'high' THEN 2
                           WHEN 'medium' THEN 3 ELSE 4
                       END,
                       i.updated_at DESC
                   LIMIT ?""",
                (limit,)
            )
            cols = ['id', 'created_at', 'updated_at', 'device_ip', 'device_name',
                    'title', 'max_severity', 'status', 'alert_count', 'alert_ids']
            return [dict(zip(cols, row)) for row in cur.fetchall()]
        except Exception as exc:
            logger.warning(f"get_open_incidents failed: {exc}")
            return []

    def resolve_incident(self, incident_id: int) -> bool:
        """Mark an incident as resolved."""
        try:
            with self._write_lock:
                self.conn.execute(
                    "UPDATE incidents SET status='resolved', updated_at=CURRENT_TIMESTAMP WHERE id=?",
                    (incident_id,)
                )
                self.conn.commit()
            return True
        except Exception:
            return False

    # ------------------------------------------------------------------
    # System settings KV store
    # ------------------------------------------------------------------

    def get_setting(self, key: str, default=None):
        """Read a system setting by key; returns *default* if not found."""
        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT value FROM system_settings WHERE key = ?", (key,))
            row = cursor.fetchone()
            return row[0] if row else default
        except sqlite3.Error:
            return default

    def set_setting(self, key: str, value) -> bool:
        """Upsert a system setting."""
        try:
            with self._write_lock:
                self.conn.execute(
                    """INSERT INTO system_settings (key, value, updated_at)
                       VALUES (?, ?, datetime('now'))
                       ON CONFLICT(key) DO UPDATE SET value = excluded.value,
                                                      updated_at = excluded.updated_at""",
                    (key, str(value)),
                )
                self.conn.commit()
            return True
        except sqlite3.Error as e:
            logger.error(f"Error setting '{key}': {e}")
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
        device_ips = set(row[0] for row in validated_data)
        try:
            with self._write_lock:
                cursor = self.conn.cursor()
                cursor.execute("BEGIN")

                # Insert new devices (no-op for known IPs)
                cursor.executemany("""
                    INSERT OR IGNORE INTO devices (device_ip, first_seen, last_seen)
                    VALUES (?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                """, [(ip,) for ip in device_ips])

                # Bump last_seen for devices already in the table
                placeholders = ','.join('?' * len(device_ips))
                cursor.execute(
                    f"UPDATE devices SET last_seen = CURRENT_TIMESTAMP "
                    f"WHERE device_ip IN ({placeholders})",
                    list(device_ips)
                )

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
                logger.debug(f"Batch insert: {inserted} connections added")

            return inserted

        except Exception as e:
            logger.error(f"Batch connection insert failed: {e}")
            try:
                self.conn.rollback()
            except Exception:
                pass
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
            with self._write_lock:
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

            with self._write_lock:
                # Analyze tables to update query optimizer statistics
                self.conn.execute("ANALYZE")
                logger.info("✓ Updated query statistics")

                # Checkpoint WAL
                self.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                logger.info("✓ Checkpointed WAL")

                # Vacuum to reclaim space (if not too large)
                db_size_mb = self.db_path.stat().st_size / 1024 / 1024
                if db_size_mb < 100:  # Only vacuum if DB < 100 MB
                    old_isolation = self.conn.isolation_level
                    self.conn.isolation_level = None
                    try:
                        self.conn.execute("VACUUM")
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

    # -------------------------------------------------------------------------
    # AI Agent Actions
    # -------------------------------------------------------------------------

    def create_agent_action(self, device_ip: str, action_type: str,
                            risk_level: str = 'low', rationale: str = '',
                            plain_report: str = '', status: str = 'pending',
                            alert_id: Optional[int] = None,
                            params: Optional[str] = None,
                            investigation: Optional[str] = None,
                            ai_source: Optional[str] = None) -> Optional[int]:
        """Record an AI agent remediation decision."""
        try:
            with self._write_lock:
                cursor = self.conn.cursor()
                cursor.execute('''
                    INSERT INTO agent_actions
                        (alert_id, device_ip, action_type, params, risk_level,
                         rationale, plain_report, status, investigation, ai_source)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (alert_id, device_ip, action_type, params or '{}',
                      risk_level, rationale, plain_report, status, investigation,
                      ai_source))
                self.conn.commit()
            return cursor.lastrowid
        except sqlite3.Error as e:
            logger.error(f"Error creating agent action: {e}")
            return None

    def get_new_devices(self, since_minutes: int = 10) -> list:
        """Return devices first seen within the last `since_minutes` minutes."""
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                """SELECT device_ip, device_name, device_type, manufacturer,
                          mac_address, icon, category, confidence, first_seen
                   FROM devices
                   WHERE first_seen >= datetime('now', ?)
                   ORDER BY first_seen DESC""",
                (f"-{since_minutes} minutes",)
            )
            return [dict(row) for row in cursor.fetchall()]
        except sqlite3.Error as e:
            logger.error(f"Error fetching new devices: {e}")
            return []

    def get_pending_agent_actions(self) -> List[Dict]:
        """Return all agent actions that are awaiting user approval."""
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                SELECT aa.*, d.device_name, d.mac_address,
                       a.severity, a.plain_explanation
                FROM agent_actions aa
                LEFT JOIN devices d ON aa.device_ip = d.device_ip
                LEFT JOIN alerts a ON aa.alert_id = a.id
                WHERE aa.status = 'pending'
                ORDER BY aa.created_at DESC
            ''')
            return [dict(row) for row in cursor.fetchall()]
        except sqlite3.Error as e:
            logger.error(f"Error fetching pending agent actions: {e}")
            return []

    def get_agent_actions(self, limit: int = 50) -> List[Dict]:
        """Return recent agent actions (all statuses)."""
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                SELECT aa.*, d.device_name, d.mac_address,
                       a.severity, a.plain_explanation
                FROM agent_actions aa
                LEFT JOIN devices d ON aa.device_ip = d.device_ip
                LEFT JOIN alerts a ON aa.alert_id = a.id
                ORDER BY aa.created_at DESC
                LIMIT ?
            ''', (limit,))
            return [dict(row) for row in cursor.fetchall()]
        except sqlite3.Error as e:
            logger.error(f"Error fetching agent actions: {e}")
            return []

    def update_agent_action_status(self, action_id: int, status: str,
                                   resolved_by: Optional[str] = None) -> bool:
        """Update action status (approved / executed / rejected)."""
        try:
            with self._write_lock:
                cursor = self.conn.cursor()
                cursor.execute('''
                    UPDATE agent_actions
                    SET status = ?, resolved_at = CURRENT_TIMESTAMP, resolved_by = ?
                    WHERE id = ?
                ''', (status, resolved_by or '', action_id))
                self.conn.commit()
            return cursor.rowcount > 0
        except sqlite3.Error as e:
            logger.error(f"Error updating agent action {action_id}: {e}")
            return False

    def action_already_queued(self, device_ip: str, action_type: str,
                              hours: int = 24) -> bool:
        """Return True if an identical action is already pending/executed within window."""
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                SELECT COUNT(*) as cnt FROM agent_actions
                WHERE device_ip = ?
                  AND action_type = ?
                  AND status IN ('pending','approved','executed','auto')
                  AND created_at > datetime('now', ? || ' hours')
            ''', (device_ip, action_type, f'-{hours}'))
            row = cursor.fetchone()
            return (row['cnt'] if row else 0) > 0
        except sqlite3.Error as e:
            logger.error(f"Error checking duplicate agent action: {e}")
            return False

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
