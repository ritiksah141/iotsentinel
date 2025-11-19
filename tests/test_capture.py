import pytest
import tempfile
import json
import gzip
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).parent.parent))

from capture.zeek_log_parser import ZeekLogParser, main as zeek_main
from database.db_manager import DatabaseManager
from config.config_manager import config
from unittest.mock import patch, MagicMock

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
def temp_log_dir():
    """Create a temporary directory for log files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)

@pytest.fixture
def zeek_parser(temp_db, temp_log_dir):
    """Fixture to create a ZeekLogParser instance with mocked dependencies."""
    with patch.object(config, 'get') as mock_config:
        mock_config.side_effect = lambda *args, **kwargs: {
            ('database', 'path'): temp_db.db_path,
            ('network', 'zeek_log_path'): str(temp_log_dir),
            ('system', 'status_file_path'): str(temp_log_dir / 'status.json')
        }.get(args, kwargs.get('default'))

        parser = ZeekLogParser()
        parser.db = temp_db
        yield parser

def write_log_file(dir_path: Path, filename: str, data: list, gzipped: bool = False):
    """Helper to write log data to a file."""
    log_path = dir_path / filename
    if gzipped:
        log_path = log_path.with_suffix('.log.gz')
        f = gzip.open(log_path, 'wt')
    else:
        f = open(log_path, 'w')

    with f:
        for entry in data:
            f.write(json.dumps(entry) + '\n')
    return log_path


def test_parse_conn_log(zeek_parser, temp_log_dir):
    """TC-CAP-001: Test parsing a standard conn.log file."""
    log_data = [
        {"ts": 1672531200.0, "id.orig_h": "192.168.1.10", "id.resp_h": "8.8.8.8", "id.resp_p": 53, "proto": "udp"},
        {"ts": 1672531201.0, "id.orig_h": "192.168.1.11", "id.resp_h": "8.8.4.4", "id.resp_p": 53, "proto": "udp"},
    ]
    log_file = write_log_file(temp_log_dir, 'conn.log', log_data)

    records = zeek_parser.parse_conn_log(log_file)
    assert records == 2
    conns = zeek_parser.db.get_unprocessed_connections(limit=5)
    assert len(conns) == 2

def test_parse_gzipped_log(zeek_parser, temp_log_dir):
    """TC-CAP-002: Test parsing a gzipped conn.log file."""
    log_data = [
        {"ts": 1672531202.0, "id.orig_h": "192.168.1.12", "id.resp_h": "1.1.1.1", "id.resp_p": 443, "proto": "tcp"},
    ]
    log_file = write_log_file(temp_log_dir, 'conn.log', log_data, gzipped=True)

    records = zeek_parser.parse_conn_log(log_file)
    assert records == 1
    conns = zeek_parser.db.get_unprocessed_connections(limit=5)
    assert len(conns) == 1
    assert conns[0]['device_ip'] == '192.168.1.12'

def test_handle_corrupt_log_entry(zeek_parser, temp_log_dir):
    """TC-CAP-003: Test that the parser handles corrupt log entries gracefully."""
    log_path = temp_log_dir / 'conn.log'
    with open(log_path, 'w') as f:
        f.write('{"ts": 1672531203.0, "id.orig_h": "192.168.1.13"}\n')
        f.write('this is not valid json\n')
        f.write('{"ts": 1672531204.0, "id.orig_h": "192.168.1.14"}\n')

    records = zeek_parser.parse_conn_log(log_path)
    assert records == 2
    conns = zeek_parser.db.get_unprocessed_connections(limit=5)
    assert len(conns) == 2

def test_data_extraction(zeek_parser, temp_log_dir):
    """TC-CAP-004: Test correct data extraction from log entries."""
    log_data = [{"ts": 1672531200.0, "id.orig_h": "192.168.1.10", "id.resp_h": "8.8.8.8", "id.resp_p": 53, "proto": "udp"}]
    log_file = write_log_file(temp_log_dir, 'conn.log', log_data)

    zeek_parser.parse_conn_log(log_file)

    conns = zeek_parser.db.get_unprocessed_connections(limit=5)
    assert conns[0]['device_ip'] == '192.168.1.10'
    assert conns[0]['dest_ip'] == '8.8.8.8'
    assert conns[0]['dest_port'] == 53
    assert conns[0]['protocol'] == 'udp'

def test_parse_http_log(zeek_parser, temp_log_dir):
    """TC-CAP-005: Test parsing of http.log."""
    log_data = [
        {"method": "GET", "host": "example.com", "uri": "/"},
        {"method": "POST", "host": "test.com", "uri": "/api"},
    ]
    log_file = write_log_file(temp_log_dir, 'http.log', log_data)
    records = zeek_parser.parse_http_log(log_file)
    assert records == 2
    assert zeek_parser.stats['http_records'] == 2

def test_parse_dns_log(zeek_parser, temp_log_dir):
    """TC-CAP-006: Test parsing of dns.log."""
    log_data = [{"query": "google.com"}, {"query": "facebook.com"}]
    log_file = write_log_file(temp_log_dir, 'dns.log', log_data)
    records = zeek_parser.parse_dns_log(log_file)
    assert records == 2
    assert zeek_parser.stats['dns_records'] == 2

@patch('time.sleep', side_effect=KeyboardInterrupt) # Stop after first loop
def test_watch_and_parse(mock_sleep, zeek_parser, temp_log_dir):
    """TC-CAP-007: Test the continuous log watching loop."""
    current_dir = temp_log_dir / 'current'
    current_dir.mkdir()
    write_log_file(current_dir, 'conn.log', [{"id.orig_h": "1.2.3.4"}])

    with patch.object(zeek_parser, 'parse_conn_log') as mock_parse:
        zeek_parser.watch_and_parse(interval=1)
        mock_parse.assert_called_once()

def test_is_monitoring_paused(zeek_parser, temp_log_dir):
    """TC-CAP-008: Test the pause monitoring functionality."""
    status_file = temp_log_dir / 'status.json'

    # Test not paused
    assert not zeek_parser._is_monitoring_paused()

    # Test paused
    with open(status_file, 'w') as f:
        json.dump({'status': 'paused'}, f)
    assert zeek_parser._is_monitoring_paused()

    # Test invalid json
    with open(status_file, 'w') as f:
        f.write("invalid json")
    assert not zeek_parser._is_monitoring_paused()

def test_parse_once(zeek_parser, temp_log_dir):
    """TC-CAP-009: Test the parse_once functionality."""
    current_dir = temp_log_dir / 'current'
    current_dir.mkdir()
    write_log_file(current_dir, 'conn.log', [{"id.orig_h": "1.1.1.1"}])

    zeek_parser.parse_once()
    assert zeek_parser.stats['conn_records'] == 1

@patch('argparse.ArgumentParser')
def test_main_watch(mock_argparse, temp_log_dir):
    """TC-CAP-010: Test main function with --watch argument."""
    # Mock args
    mock_args = MagicMock()
    mock_args.watch = True
    mock_args.once = False
    mock_args.interval = 1
    mock_argparse.return_value.parse_args.return_value = mock_args

    with patch('capture.zeek_log_parser.ZeekLogParser') as mock_parser:
        zeek_main()
        mock_parser.return_value.watch_and_parse.assert_called_with(interval=1)

@patch('argparse.ArgumentParser')
def test_main_once(mock_argparse, temp_log_dir):
    """TC-CAP-011: Test main function with --once argument."""
    mock_args = MagicMock()
    mock_args.watch = False
    mock_args.once = True
    mock_argparse.return_value.parse_args.return_value = mock_args

    with patch('capture.zeek_log_parser.ZeekLogParser') as mock_parser:
        zeek_main()
        mock_parser.return_value.parse_once.assert_called_once()
