#!/usr/bin/env python3
"""
Database Initialization for IoTSentinel

Creates all required tables with proper schema.
Run this once during setup.
"""

import sqlite3
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from config.config_manager import config


def init_database():
    """Create all necessary tables."""
    
    db_path = config.get('database', 'path')
    
    print(f"Initializing database: {db_path}")
    
    # Create parent directory
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Devices table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS devices (
            device_ip TEXT PRIMARY KEY,
            device_name TEXT,
            device_type TEXT,
            mac_address TEXT,
            manufacturer TEXT,
            first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_trusted INTEGER DEFAULT 0,
            is_blocked INTEGER DEFAULT 0
        )
    ''')
    
    # Connections table (from Zeek)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS connections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            device_ip TEXT NOT NULL,
            dest_ip TEXT,
            dest_port INTEGER,
            protocol TEXT,
            service TEXT,
            duration REAL,
            bytes_sent INTEGER DEFAULT 0,
            bytes_received INTEGER DEFAULT 0,
            packets_sent INTEGER DEFAULT 0,
            packets_received INTEGER DEFAULT 0,
            conn_state TEXT,
            processed INTEGER DEFAULT 0,
            FOREIGN KEY (device_ip) REFERENCES devices(device_ip)
        )
    ''')
    
    # Indexes
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_conn_timestamp ON connections(timestamp)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_conn_device ON connections(device_ip)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_conn_processed ON connections(processed)')
    
    # Alerts table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            device_ip TEXT NOT NULL,
            severity TEXT CHECK(severity IN ('low', 'medium', 'high', 'critical')),
            anomaly_score REAL,
            explanation TEXT,
            top_features TEXT,
            acknowledged INTEGER DEFAULT 0,
            acknowledged_at TIMESTAMP,
            FOREIGN KEY (device_ip) REFERENCES devices(device_ip)
        )
    ''')
    
    # ML predictions
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ml_predictions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            connection_id INTEGER,
            is_anomaly INTEGER,
            anomaly_score REAL,
            model_type TEXT,
            model_version TEXT,
            FOREIGN KEY (connection_id) REFERENCES connections(id)
        )
    ''')
    
    conn.commit()
    conn.close()
    
    print(f"✓ Database initialized: {db_path}")
    print("Tables created:")
    print("  - devices")
    print("  - connections")
    print("  - alerts")
    print("  - ml_predictions")


if __name__ == "__main__":
    init_database()