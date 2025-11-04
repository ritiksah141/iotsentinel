#!/usr/bin/env python3
"""
Professional Database Manager for IoTSentinel

Handles all database operations with:
- Connection pooling
- Transaction support
- Error handling
- Prepared statements
"""

import sqlite3
import logging
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)


class DatabaseManager:
    """SQLite database manager."""
    
    def __init__(self, db_path: str):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        self.conn = None
        self._connect()
        
        logger.info(f"Database manager initialized: {self.db_path}")
    
    def _connect(self):
        """Establish database connection."""
        self.conn = sqlite3.connect(
            str(self.db_path),
            check_same_thread=False
        )
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.execute("PRAGMA journal_mode = WAL")
    
    def add_device(self, device_ip: str, **kwargs) -> bool:
        """Add or update device."""
        try:
            cursor = self.conn.cursor()
            
            cursor.execute("""
                INSERT INTO devices (device_ip, device_name, device_type, mac_address, manufacturer)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(device_ip) DO UPDATE SET
                    device_name = COALESCE(excluded.device_name, devices.device_name),
                    device_type = COALESCE(excluded.device_type, devices.device_type),
                    mac_address = COALESCE(excluded.mac_address, devices.mac_address),
                    manufacturer = COALESCE(excluded.manufacturer, devices.manufacturer),
                    last_seen = CURRENT_TIMESTAMP
            """, (
                device_ip,
                kwargs.get('device_name'),
                kwargs.get('device_type'),
                kwargs.get('mac_address'),
                kwargs.get('manufacturer')
            ))
            
            self.conn.commit()
            return True
            
        except sqlite3.Error as e:
            logger.error(f"Error adding device: {e}")
            return False
    
    def add_connection(self, device_ip: str, dest_ip: str, dest_port: int,
                       protocol: str, **kwargs) -> Optional[int]:
        """Add network connection."""
        try:
            # Ensure device exists
            self.add_device(device_ip)
            
            cursor = self.conn.cursor()
            
            cursor.execute("""
                INSERT INTO connections 
                (device_ip, dest_ip, dest_port, protocol, service, duration,
                 bytes_sent, bytes_received, packets_sent, packets_received, conn_state)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                device_ip, dest_ip, dest_port, protocol,
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
            logger.error(f"Error adding connection: {e}")
            return None
    
    def get_unprocessed_connections(self, limit: int = 100) -> List[Dict]:
        """Get connections not yet processed by ML."""
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
            logger.error(f"Error fetching connections: {e}")
            return []
    
    def mark_connections_processed(self, connection_ids: List[int]):
        """Mark connections as processed."""
        try:
            cursor = self.conn.cursor()
            placeholders = ','.join(['?'] * len(connection_ids))
            cursor.execute(f"""
                UPDATE connections
                SET processed = 1
                WHERE id IN ({placeholders})
            """, connection_ids)
            self.conn.commit()
        except sqlite3.Error as e:
            logger.error(f"Error marking processed: {e}")
    
    def store_prediction(self, connection_id: int, is_anomaly: bool,
                        anomaly_score: float, model_type: str):
        """Store ML prediction."""
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                INSERT INTO ml_predictions 
                (connection_id, is_anomaly, anomaly_score, model_type, model_version)
                VALUES (?, ?, ?, ?, ?)
            """, (connection_id, int(is_anomaly), anomaly_score, model_type, 'v1'))
            self.conn.commit()
        except sqlite3.Error as e:
            logger.error(f"Error storing prediction: {e}")
    
    def create_alert(self, device_ip: str, severity: str, anomaly_score: float,
                     explanation: str, top_features: str) -> Optional[int]:
        """Create security alert."""
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                INSERT INTO alerts
                (device_ip, severity, anomaly_score, explanation, top_features)
                VALUES (?, ?, ?, ?, ?)
            """, (device_ip, severity, anomaly_score, explanation, top_features))
            
            self.conn.commit()
            return cursor.lastrowid
        except sqlite3.Error as e:
            logger.error(f"Error creating alert: {e}")
            return None
    
    def get_recent_alerts(self, hours: int = 24) -> List[Dict]:
        """Get recent alerts."""
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
        """Get recently active devices."""
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT * FROM devices
                WHERE last_seen > datetime('now', ? || ' minutes')
                ORDER BY last_seen DESC
            """, (f'-{minutes}',))
            
            return [dict(row) for row in cursor.fetchall()]
        except sqlite3.Error as e:
            logger.error(f"Error fetching devices: {e}")
            return []
    
    def get_device_stats(self, device_ip: str, hours: int = 24) -> Dict:
        """Get statistics for a specific device."""
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
            logger.error(f"Error fetching device stats: {e}")
            return {}
    
    def close(self):
        """Close database connection."""
        if self.conn:
            self.conn.close()
            logger.info("Database connection closed")