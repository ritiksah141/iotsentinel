#!/usr/bin/env python3
"""
Extended coverage tests for ZeekLogParser.

Targets uncovered methods: parse_dhcp_log, parse_http_log, parse_dns_log,
_is_monitoring_paused, parse_once.

Run: pytest tests/test_capture_coverage.py -v --cov=capture.zeek_log_parser
"""

import json
import gzip
from pathlib import Path
import sys

import pytest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from capture.zeek_log_parser import ZeekLogParser
from database.db_manager import DatabaseManager
from config.config_manager import config
from tests.conftest import create_test_schema


# ── fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def tmp_dir(tmp_path):
    return tmp_path


@pytest.fixture
def test_db(tmp_path):
    db_path = str(tmp_path / 'test.db')
    db_manager = DatabaseManager(db_path)
    create_test_schema(db_manager)
    yield db_manager
    db_manager.close()
    normalized = str(Path(db_path).resolve())
    DatabaseManager._instances.pop(normalized, None)


@pytest.fixture
def parser(test_db, tmp_dir):
    with patch.object(config, 'get') as mock_cfg:
        mock_cfg.side_effect = lambda *args, **kwargs: {
            ('database', 'path'): test_db.db_path,
            ('network', 'zeek_log_path'): str(tmp_dir),
            ('system', 'status_file_path'): str(tmp_dir / 'status.json'),
        }.get(args, kwargs.get('default'))
        p = ZeekLogParser()
        p.db = test_db
        p.zeek_log_path = tmp_dir
        p.status_file_path = tmp_dir / 'status.json'
        yield p


def _write_log(path: Path, records: list, gzipped: bool = False):
    lines = [json.dumps(r) + '\n' for r in records]
    if gzipped:
        with gzip.open(path, 'wt') as f:
            f.write('# zeek comment\n')
            f.writelines(lines)
    else:
        with open(path, 'w') as f:
            f.write('# zeek comment\n')
            f.writelines(lines)


# ── parse_dhcp_log ─────────────────────────────────────────────────────────────

class TestParseDhcpLog:
    def test_parses_valid_dhcp_record(self, parser, tmp_dir):
        log = tmp_dir / 'dhcp.log'
        _write_log(log, [{'mac': 'AA:BB:CC:DD:EE:FF', 'assigned_addr': '192.168.1.50',
                          'host_name': 'my-device'}])
        count = parser.parse_dhcp_log(log)
        assert count == 1

    def test_parses_dhcp_without_hostname(self, parser, tmp_dir):
        log = tmp_dir / 'dhcp_nh.log'
        _write_log(log, [{'mac': '11:22:33:44:55:66', 'assigned_addr': '10.0.0.5'}])
        count = parser.parse_dhcp_log(log)
        assert count == 1

    def test_skips_record_without_mac(self, parser, tmp_dir):
        log = tmp_dir / 'dhcp_nomac.log'
        _write_log(log, [{'assigned_addr': '10.0.0.5'}])
        count = parser.parse_dhcp_log(log)
        assert count == 0

    def test_skips_record_without_ip(self, parser, tmp_dir):
        log = tmp_dir / 'dhcp_noip.log'
        _write_log(log, [{'mac': 'AA:BB:CC:DD:EE:FF'}])
        count = parser.parse_dhcp_log(log)
        assert count == 0

    def test_skips_invalid_json_lines(self, parser, tmp_dir):
        log = tmp_dir / 'dhcp_bad.log'
        with open(log, 'w') as f:
            f.write('# comment\nnot json\n')
        count = parser.parse_dhcp_log(log)
        assert count == 0

    def test_returns_zero_for_missing_file(self, parser, tmp_dir):
        count = parser.parse_dhcp_log(tmp_dir / 'nonexistent_dhcp.log')
        assert count == 0

    def test_parses_gzipped_dhcp(self, parser, tmp_dir):
        log = tmp_dir / 'dhcp.log.gz'
        _write_log(log, [{'mac': 'AA:BB:CC:DD:EE:FF', 'assigned_addr': '10.0.0.1'}],
                   gzipped=True)
        count = parser.parse_dhcp_log(log)
        assert count == 1

    def test_updates_dhcp_stats(self, parser, tmp_dir):
        log = tmp_dir / 'dhcp_stats.log'
        _write_log(log, [{'mac': 'AA:BB:CC:DD:EE:FF', 'assigned_addr': '10.0.0.2'}])
        parser.parse_dhcp_log(log)
        assert parser.stats['dhcp_records'] >= 1


# ── parse_http_log ─────────────────────────────────────────────────────────────

class TestParseHttpLog:
    def test_parses_http_records(self, parser, tmp_dir):
        log = tmp_dir / 'http.log'
        _write_log(log, [
            {'method': 'GET', 'host': 'example.com', 'uri': '/'},
            {'method': 'POST', 'host': 'api.example.com', 'uri': '/data'},
        ])
        count = parser.parse_http_log(log)
        assert count == 2

    def test_skips_bad_json(self, parser, tmp_dir):
        log = tmp_dir / 'http_bad.log'
        with open(log, 'w') as f:
            f.write('not json\n')
        count = parser.parse_http_log(log)
        assert count == 0

    def test_returns_zero_for_missing_file(self, parser, tmp_dir):
        count = parser.parse_http_log(tmp_dir / 'nonexistent_http.log')
        assert count == 0

    def test_parses_gzipped_http(self, parser, tmp_dir):
        log = tmp_dir / 'http.log.gz'
        _write_log(log, [{'method': 'GET', 'host': 'x.com', 'uri': '/'}], gzipped=True)
        count = parser.parse_http_log(log)
        assert count == 1

    def test_updates_http_stats(self, parser, tmp_dir):
        log = tmp_dir / 'http2.log'
        _write_log(log, [{'method': 'GET', 'host': 'x.com', 'uri': '/'}])
        parser.parse_http_log(log)
        assert parser.stats['http_records'] >= 1


# ── parse_dns_log ──────────────────────────────────────────────────────────────

class TestParseDnsLog:
    def test_parses_dns_records(self, parser, tmp_dir):
        log = tmp_dir / 'dns.log'
        _write_log(log, [
            {'query': 'example.com', 'qtype': 'A'},
            {'query': 'google.com', 'qtype': 'AAAA'},
        ])
        count = parser.parse_dns_log(log)
        assert count == 2

    def test_returns_zero_for_missing_file(self, parser, tmp_dir):
        count = parser.parse_dns_log(tmp_dir / 'nonexistent_dns.log')
        assert count == 0

    def test_skips_bad_json(self, parser, tmp_dir):
        log = tmp_dir / 'dns_bad.log'
        with open(log, 'w') as f:
            f.write('bad line\n')
        count = parser.parse_dns_log(log)
        assert count == 0

    def test_parses_gzipped_dns(self, parser, tmp_dir):
        log = tmp_dir / 'dns.log.gz'
        _write_log(log, [{'query': 'test.com'}], gzipped=True)
        count = parser.parse_dns_log(log)
        assert count == 1

    def test_updates_dns_stats(self, parser, tmp_dir):
        log = tmp_dir / 'dns2.log'
        _write_log(log, [{'query': 'a.com'}])
        parser.parse_dns_log(log)
        assert parser.stats['dns_records'] >= 1


# ── _is_monitoring_paused ─────────────────────────────────────────────────────

class TestIsMonitoringPaused:
    def test_not_paused_when_no_status_file(self, parser, tmp_dir):
        parser.status_file_path = tmp_dir / 'nonexistent_status.json'
        assert parser._is_monitoring_paused() is False

    def test_paused_when_status_says_paused(self, parser, tmp_dir):
        parser.status_file_path = tmp_dir / 'status.json'
        parser.status_file_path.write_text(json.dumps({'status': 'paused'}))
        assert parser._is_monitoring_paused() is True

    def test_not_paused_when_status_is_active(self, parser, tmp_dir):
        parser.status_file_path = tmp_dir / 'status.json'
        parser.status_file_path.write_text(json.dumps({'status': 'active'}))
        assert parser._is_monitoring_paused() is False

    def test_not_paused_when_status_file_invalid_json(self, parser, tmp_dir):
        parser.status_file_path = tmp_dir / 'status.json'
        parser.status_file_path.write_text('not json')
        assert parser._is_monitoring_paused() is False


# ── parse_once ────────────────────────────────────────────────────────────────

class TestParseOnce:
    def test_parse_once_missing_dir(self, parser, tmp_dir):
        # zeek_log_path is tmp_dir; 'current/' sub-dir doesn't exist
        parser.parse_once()  # should log error and return

    def test_parse_once_with_log_files(self, parser, tmp_dir):
        current_dir = tmp_dir / 'current'
        current_dir.mkdir()
        _write_log(current_dir / 'conn.log', [
            {'ts': 1672531200.0, 'id.orig_h': '192.168.1.10',
             'id.resp_h': '8.8.8.8', 'id.resp_p': 443, 'proto': 'tcp'}
        ])
        _write_log(current_dir / 'http.log', [{'method': 'GET', 'host': 'x.com', 'uri': '/'}])
        _write_log(current_dir / 'dns.log', [{'query': 'example.com'}])

        parser.parse_once()

        assert parser.stats['conn_records'] >= 1
        assert parser.stats['http_records'] >= 1
        assert parser.stats['dns_records'] >= 1

    def test_parse_once_with_dhcp_log(self, parser, tmp_dir):
        current_dir = tmp_dir / 'current'
        current_dir.mkdir()
        _write_log(current_dir / 'dhcp.log', [
            {'mac': 'AA:BB:CC:DD:EE:FF', 'assigned_addr': '192.168.1.20'}
        ])
        parser.parse_once()
        assert parser.stats['dhcp_records'] >= 1
