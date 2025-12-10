"""
Global fixtures for the IoTSentinel test suite.
"""
import pytest
import sqlite3
from pathlib import Path
import sys

# Add project root to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from database.db_manager import DatabaseManager

def create_test_schema(db_manager: DatabaseManager):
    """
    Creates all required tables with the correct schema for testing.
    This uses the exact schema from the production database initializer.
    """
    cursor = db_manager.conn.cursor()

    # Schema definition extracted directly from config/init_database.py
    schema = [
        '''
        CREATE TABLE IF NOT EXISTS devices (
            device_ip TEXT PRIMARY KEY, device_name TEXT, device_type TEXT, mac_address TEXT,
            manufacturer TEXT, model TEXT, firmware_version TEXT,
            first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP, last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_activity TIMESTAMP, is_trusted INTEGER DEFAULT 0, is_blocked INTEGER DEFAULT 0,
            custom_name TEXT, notes TEXT, icon TEXT DEFAULT "❓", category TEXT DEFAULT "other",
            confidence TEXT DEFAULT "low", total_connections INTEGER DEFAULT 0
        )
        ''',
        '''
        CREATE TABLE IF NOT EXISTS connections (
            id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            device_ip TEXT NOT NULL, dest_ip TEXT, dest_port INTEGER, protocol TEXT,
            service TEXT, duration REAL, bytes_sent INTEGER DEFAULT 0, bytes_received INTEGER DEFAULT 0,
            packets_sent INTEGER DEFAULT 0, packets_received INTEGER DEFAULT 0, conn_state TEXT,
            processed INTEGER DEFAULT 0, FOREIGN KEY (device_ip) REFERENCES devices(device_ip)
        )
        ''',
        'CREATE INDEX IF NOT EXISTS idx_conn_timestamp ON connections(timestamp)',
        'CREATE INDEX IF NOT EXISTS idx_conn_device ON connections(device_ip)',
        'CREATE INDEX IF NOT EXISTS idx_conn_processed ON connections(processed)',
        '''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            device_ip TEXT NOT NULL, severity TEXT CHECK(severity IN ('low', 'medium', 'high', 'critical')),
            anomaly_score REAL, explanation TEXT, top_features TEXT, acknowledged INTEGER DEFAULT 0,
            acknowledged_at TIMESTAMP, FOREIGN KEY (device_ip) REFERENCES devices(device_ip)
        )
        ''',
        '''
        CREATE TABLE IF NOT EXISTS ml_predictions (
            id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            connection_id INTEGER, is_anomaly INTEGER, anomaly_score REAL,
            model_type TEXT, model_version TEXT,
            FOREIGN KEY (connection_id) REFERENCES connections(id)
        )
        '''
    ]

    for statement in schema:
        cursor.execute(statement)

    db_manager.conn.commit()


@pytest.fixture
def db():
    """
    Shared fixture to create a clean, in-memory database with the correct
    schema for each test function.
    """
    # Use :memory: for a clean, fast in-memory database for each test
    db_manager = DatabaseManager(':memory:')
    create_test_schema(db_manager)
    yield db_manager
    db_manager.close()
