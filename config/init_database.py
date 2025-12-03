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

    # Model performance metrics
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS model_performance (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            model_type TEXT,
            precision REAL,
            recall REAL,
            f1_score REAL
        )
    ''')

    # Malicious IPs table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS malicious_ips (
            ip TEXT PRIMARY KEY,
            source TEXT
        )
    ''')

    # Users table for authentication
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT CHECK(role IN ('admin', 'viewer')) DEFAULT 'viewer',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            is_active INTEGER DEFAULT 1
        )
    ''')

    # Create default admin user (password: from env var or fallback to 'admin')
    # Password hash for 'admin' using bcrypt
    import bcrypt
    import os
    default_password = os.environ.get("IOTSENTINEL_ADMIN_PASSWORD", "admin")  # pragma: allowlist secret

    if default_password == "admin": # pragma: allowlist secret
        print("  ⚠️  Using default admin password. For production, set the IOTSENTINEL_ADMIN_PASSWORD environment variable.")

    password_hash = bcrypt.hashpw(default_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    cursor.execute('''
        INSERT OR IGNORE INTO users (username, password_hash, role)
        VALUES (?, ?, ?)
    ''', ('admin', password_hash, 'admin'))

    # Alert Rules table for custom user-defined rules
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alert_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            rule_type TEXT CHECK(rule_type IN ('data_volume', 'connection_count', 'port_activity', 'time_based', 'destination_ip', 'protocol')) NOT NULL,
            condition_operator TEXT CHECK(condition_operator IN ('gt', 'lt', 'eq', 'gte', 'lte', 'contains', 'in_range')) NOT NULL,
            threshold_value REAL,
            threshold_value_2 REAL,
            time_window_hours INTEGER DEFAULT 1,
            severity TEXT CHECK(severity IN ('low', 'medium', 'high', 'critical')) DEFAULT 'medium',
            device_filter TEXT,
            port_filter TEXT,
            protocol_filter TEXT,
            time_filter TEXT,
            is_enabled INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            created_by INTEGER,
            last_triggered TIMESTAMP,
            trigger_count INTEGER DEFAULT 0,
            FOREIGN KEY (created_by) REFERENCES users(id)
        )
    ''')

    # Create default alert rules
    default_rules = [
        # High data volume rule
        ('High Data Transfer', 'Alert when device sends more than 1 GB in 1 hour', 'data_volume', 'gt', 1000.0, None, 1, 'high', None, None, None, None, 1),
        # Excessive connections
        ('Excessive Connections', 'Alert when device makes more than 500 connections in 1 hour', 'connection_count', 'gt', 500.0, None, 1, 'medium', None, None, None, None, 1),
        # Unusual port activity
        ('Suspicious Port Activity', 'Alert on connections to commonly exploited ports', 'port_activity', 'contains', None, None, 1, 'high', None, '22,23,3389,445,135', None, None, 1),
        # After-hours activity
        ('After-Hours Activity', 'Alert on network activity during unusual hours (11 PM - 6 AM)', 'time_based', 'in_range', 23.0, 6.0, 1, 'low', None, None, None, '23:00-06:00', 1),
    ]

    cursor.executemany('''
        INSERT OR IGNORE INTO alert_rules (
            name, description, rule_type, condition_operator, threshold_value, threshold_value_2,
            time_window_hours, severity, device_filter, port_filter, protocol_filter, time_filter, is_enabled
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', default_rules)

    # Device Groups table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS device_groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            description TEXT,
            color TEXT DEFAULT '#0dcaf0',
            icon TEXT DEFAULT 'fa-folder',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            created_by INTEGER,
            FOREIGN KEY (created_by) REFERENCES users(id)
        )
    ''')

    # Device-Group mapping table (many-to-many relationship)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS device_group_members (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_ip TEXT NOT NULL,
            group_id INTEGER NOT NULL,
            added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            added_by INTEGER,
            FOREIGN KEY (device_ip) REFERENCES devices(device_ip) ON DELETE CASCADE,
            FOREIGN KEY (group_id) REFERENCES device_groups(id) ON DELETE CASCADE,
            FOREIGN KEY (added_by) REFERENCES users(id),
            UNIQUE(device_ip, group_id)
        )
    ''')

    # Create default device groups
    default_groups = [
        ('IoT Devices', 'Smart home devices and IoT sensors', '#17a2b8', 'fa-lightbulb'),
        ('Computers', 'Laptops, desktops, and workstations', '#007bff', 'fa-laptop'),
        ('Mobile Devices', 'Smartphones and tablets', '#28a745', 'fa-mobile-alt'),
        ('Network Infrastructure', 'Routers, switches, and access points', '#6c757d', 'fa-network-wired'),
        ('Security Devices', 'Cameras, sensors, and security systems', '#dc3545', 'fa-shield-alt'),
        ('Media Devices', 'TVs, streaming devices, and speakers', '#fd7e14', 'fa-tv'),
        ('Printers & Peripherals', 'Printers, scanners, and other peripherals', '#6f42c1', 'fa-print'),
        ('Unknown Devices', 'Uncategorized or unidentified devices', '#6c757d', 'fa-question-circle'),
    ]

    cursor.executemany('''
        INSERT OR IGNORE INTO device_groups (name, description, color, icon)
        VALUES (?, ?, ?, ?)
    ''', default_groups)

    conn.commit()
    conn.close()

    print(f"✓ Database initialized: {db_path}")
    print("Tables created:")
    print("  - devices")
    print("  - connections")
    print("  - alerts")
    print("  - ml_predictions")
    print("  - model_performance")
    print("  - malicious_ips")
    print("  - users")
    print("  - alert_rules")
    print("  - device_groups")
    print("  - device_group_members")
    print("\n✓ Default admin user created:")
    print("  Username: admin")
    if default_password == "admin": # pragma: allowlist secret
        print("  Password: admin")
        print("  ⚠️  CHANGE THIS PASSWORD AFTER FIRST LOGIN!")
    else:
        print("  Password: [set from IOTSENTINEL_ADMIN_PASSWORD environment variable]")
    print("\n✓ Default alert rules created:")
    print("  - High Data Transfer (1 GB/hour)")
    print("  - Excessive Connections (500/hour)")
    print("  - Suspicious Port Activity (common exploit ports)")
    print("  - After-Hours Activity (11 PM - 6 AM)")
    print("\n✓ Default device groups created:")
    print("  - IoT Devices")
    print("  - Computers")
    print("  - Mobile Devices")
    print("  - Network Infrastructure")
    print("  - Security Devices")
    print("  - Media Devices")
    print("  - Printers & Peripherals")
    print("  - Unknown Devices")


if __name__ == "__main__":
    init_database()
