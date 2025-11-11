import pytest
import tempfile
import json
import gzip
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

from capture.zeek_log_parser import ZeekLogParser
from database.db_manager import DatabaseManager
from config.config_manager import config
from unittest.mock import patch

# Helper to create a schema for the in-memory database
def create_test_schema(db_manager: DatabaseManager):
    try:
        cursor = db_manager.conn.cursor()
        cursor.execute("""
        CREATE TABLE devices (
            device_ip TEXT PRIMARY KEY, device_name TEXT, device_type TEXT,
            mac_address TEXT, manufacturer TEXT, first_seen TIMESTAMP, last_seen TIMESTAMP
        );
        """)
        cursor.execute("""
        CREATE TABLE connections (
            id INTEGER PRIMARY KEY AUTOINCREMENT, device_ip TEXT, timestamp TIMESTAMP,
            dest_ip TEXT, dest_port INTEGER, protocol TEXT, service TEXT, duration REAL,
            bytes_sent INTEGER, bytes_received INTEGER, packets_sent INTEGER,
            packets_received INTEGER, conn_state TEXT, processed INTEGER DEFAULT 0,
            FOREIGN KEY (device_ip) REFERENCES devices (device_ip)
        );
        """)
        db_manager.conn.commit()
    except Exception as e:
        print(f"Error creating schema: {e}")
        raise

@pytest.fixture
def temp_db():
    """Create in-memory database for testing."""
    db_manager = DatabaseManager(':memory:')
    create_test_schema(db_manager)
    yield db_manager
    db_manager.close()

@pytest.fixture
def temp_log_file():
    """Create a temporary log file with sample data."""
    log_data = [
        {"ts": 1672531200.0, "id.orig_h": "192.168.1.10", "id.resp_h": "8.8.8.8", "id.resp_p": 53, "proto": "udp"},
        {"ts": 1672531201.0, "id.orig_h": "192.168.1.11", "id.resp_h": "8.8.4.4", "id.resp_p": 53, "proto": "udp"},
    ]
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.log') as f:
        for entry in log_data:
            f.write(json.dumps(entry) + '\n')
        filepath = f.name
    yield Path(filepath)
    Path(filepath).unlink()

@pytest.fixture
def temp_gzipped_log_file():
    """Create a temporary gzipped log file."""
    log_data = [
        {"ts": 1672531202.0, "id.orig_h": "192.168.1.12", "id.resp_h": "1.1.1.1", "id.resp_p": 443, "proto": "tcp"},
    ]
    with tempfile.NamedTemporaryFile(delete=False, suffix='.log.gz') as f:
        filepath = f.name
    with gzip.open(filepath, 'wt') as f:
        for entry in log_data:
            f.write(json.dumps(entry) + '\n')
    yield Path(filepath)
    Path(filepath).unlink()

@pytest.fixture
def corrupt_log_file():
    """Create a log file with a corrupt entry."""
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.log') as f:
        f.write('{"ts": 1672531203.0, "id.orig_h": "192.168.1.13", "id.resp_h": "208.67.222.222", "id.resp_p": 53, "proto": "udp"}\n')
        f.write('this is not valid json\n')
        f.write('{"ts": 1672531204.0, "id.orig_h": "192.168.1.14", "id.resp_h": "208.67.220.220", "id.resp_p": 53, "proto": "udp"}\n')
        filepath = f.name
    yield Path(filepath)
    Path(filepath).unlink()


def test_parse_conn_log(temp_db, temp_log_file):
    """TC-CAP-001: Test parsing a standard conn.log file."""
    with patch.object(config, 'get', return_value=temp_db.db_path):
        parser = ZeekLogParser()
        parser.db = temp_db # Override db manager
        records = parser.parse_conn_log(temp_log_file)
        assert records == 2
        conns = temp_db.get_unprocessed_connections(limit=5)
        assert len(conns) == 2

def test_parse_gzipped_log(temp_db, temp_gzipped_log_file):
    """TC-CAP-002: Test parsing a gzipped conn.log file."""
    with patch.object(config, 'get', return_value=temp_db.db_path):
        parser = ZeekLogParser()
        parser.db = temp_db
        records = parser.parse_conn_log(temp_gzipped_log_file)
        assert records == 1
        conns = temp_db.get_unprocessed_connections(limit=5)
        assert len(conns) == 1
        assert conns[0]['device_ip'] == '192.168.1.12'

def test_handle_corrupt_log_entry(temp_db, corrupt_log_file):
    """TC-CAP-003: Test that the parser handles corrupt log entries gracefully."""
    with patch.object(config, 'get', return_value=temp_db.db_path):
        parser = ZeekLogParser()
        parser.db = temp_db
        records = parser.parse_conn_log(corrupt_log_file)
        assert records == 2 # Should skip the corrupt line and parse the other two
        conns = temp_db.get_unprocessed_connections(limit=5)
        assert len(conns) == 2

def test_data_extraction(temp_db, temp_log_file):
    """TC-CAP-004: Test correct data extraction from log entries."""
    with patch.object(config, 'get', return_value=temp_db.db_path):
        parser = ZeekLogParser()
        parser.db = temp_db
        parser.parse_conn_log(temp_log_file)
        conns = temp_db.get_unprocessed_connections(limit=5)
        # Assuming order is preserved
        assert conns[0]['device_ip'] == '192.168.1.10'
        assert conns[0]['dest_ip'] == '8.8.8.8'
        assert conns[0]['dest_port'] == 53
        assert conns[0]['protocol'] == 'udp'
