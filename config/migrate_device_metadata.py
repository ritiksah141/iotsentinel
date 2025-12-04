#!/usr/bin/env python3
"""
Database Migration: Add IoT Device Metadata Fields
Adds fields for device classification, icons, and management
"""

import sqlite3
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from config.config_manager import config


def migrate_database():
    """Add new device metadata fields"""

    db_path = config.get('database', 'path')

    print(f"Migrating database: {db_path}")

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Check if columns already exist
    cursor.execute("PRAGMA table_info(devices)")
    existing_columns = [row[1] for row in cursor.fetchall()]

    migrations = []

    # Add device metadata columns if they don't exist
    new_columns = {
        'custom_name': 'TEXT',  # User-defined device name
        'notes': 'TEXT',  # User notes about device
        'icon': 'TEXT DEFAULT "❓"',  # Device icon emoji
        'category': 'TEXT DEFAULT "other"',  # Device category (security, smart_home, etc.)
        'confidence': 'TEXT DEFAULT "low"',  # Classification confidence (low, medium, high)
        'firmware_version': 'TEXT',  # Firmware/software version
        'model': 'TEXT',  # Device model
        'total_connections': 'INTEGER DEFAULT 0',  # Total connection count
        'last_activity': 'TIMESTAMP',  # Last network activity
    }

    for column_name, column_type in new_columns.items():
        if column_name not in existing_columns:
            sql = f"ALTER TABLE devices ADD COLUMN {column_name} {column_type}"
            migrations.append((column_name, sql))

    # Execute migrations
    if migrations:
        print(f"\nAdding {len(migrations)} new columns...")
        for column_name, sql in migrations:
            try:
                cursor.execute(sql)
                print(f"  ✓ Added column: {column_name}")
            except sqlite3.OperationalError as e:
                print(f"  ⚠ Skipped column {column_name}: {e}")

        conn.commit()
        print(f"\n✓ Migration complete! Added {len(migrations)} columns.")
    else:
        print("\n✓ Database already up to date. No migrations needed.")

    # Create user_preferences table if it doesn't exist
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_preferences (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            preference_key TEXT NOT NULL,
            preference_value TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            UNIQUE(user_id, preference_key)
        )
    ''')

    # Create IoT protocols table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS iot_protocols (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_ip TEXT NOT NULL,
            protocol TEXT NOT NULL,
            topic TEXT,  -- For MQTT
            resource TEXT,  -- For CoAP
            payload_size INTEGER,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (device_ip) REFERENCES devices(device_ip) ON DELETE CASCADE
        )
    ''')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_iot_proto_device ON iot_protocols(device_ip)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_iot_proto_timestamp ON iot_protocols(timestamp)')

    # Create device vulnerabilities table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS device_vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_ip TEXT NOT NULL,
            cve_id TEXT,
            vulnerability_type TEXT,  -- default_password, outdated_firmware, known_exploit
            severity TEXT CHECK(severity IN ('low', 'medium', 'high', 'critical')) DEFAULT 'medium',
            description TEXT,
            detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            resolved INTEGER DEFAULT 0,
            resolved_at TIMESTAMP,
            FOREIGN KEY (device_ip) REFERENCES devices(device_ip) ON DELETE CASCADE
        )
    ''')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_vuln_device ON device_vulnerabilities(device_ip)')

    conn.commit()

    print("\n✓ Created additional tables:")
    print("  - user_preferences (for dashboard settings)")
    print("  - iot_protocols (for MQTT/CoAP tracking)")
    print("  - device_vulnerabilities (for security checks)")

    conn.close()

    print(f"\n✓ Database migration successful!")


if __name__ == "__main__":
    migrate_database()
