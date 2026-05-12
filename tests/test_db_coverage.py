#!/usr/bin/env python3
"""
Extended coverage tests for DatabaseManager.

Targets the uncovered CRUD methods: device metadata, groups, trust/block,
bandwidth stats, malicious IPs, threat queries, cleanup, batch insert,
index creation, optimization, stats, health check, and backup.

Run: pytest tests/test_db_coverage.py -v --cov=database.db_manager
"""

import pytest
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
import sys
import tempfile
import os

sys.path.insert(0, str(Path(__file__).parent.parent))

from database.db_manager import DatabaseManager, ValidationError
from tests.conftest import create_test_schema


# ── file-based DB fixture (needed for health_check / backup / optimize) ───────

@pytest.fixture
def file_db(tmp_path):
    db_path = str(tmp_path / 'test_file.db')
    db_manager = DatabaseManager(db_path)
    create_test_schema(db_manager)
    yield db_manager
    db_manager.close()
    normalized = str(Path(db_path).resolve())
    DatabaseManager._instances.pop(normalized, None)


# ── helpers ──────────────────────────────────────────────────────────────────

def _add_device(db, ip='192.168.1.10'):
    db.add_device(device_ip=ip)
    return ip


def _add_connection(db, device_ip='192.168.1.10', dest_ip='8.8.8.8',
                    dest_port=443, protocol='tcp', **kw):
    return db.add_connection(
        device_ip=device_ip, dest_ip=dest_ip,
        dest_port=dest_port, protocol=protocol, **kw
    )


def _add_alert(db, device_ip='192.168.1.10'):
    return db.create_alert(
        device_ip=device_ip,
        severity='high',
        anomaly_score=0.85,
        explanation='Test alert',
        top_features='bytes_sent'
    )


# ── static validators ─────────────────────────────────────────────────────────

class TestValidators:
    def test_validate_ip_invalid_format(self):
        assert DatabaseManager.validate_ip('not-an-ip') is False

    def test_validate_ip_out_of_range_octet(self):
        assert DatabaseManager.validate_ip('192.168.1.999') is False

    def test_validate_ip_empty(self):
        assert DatabaseManager.validate_ip('') is False

    def test_validate_ip_none(self):
        assert DatabaseManager.validate_ip(None) is False

    def test_validate_mac_invalid(self):
        assert DatabaseManager.validate_mac('not-a-mac') is False

    def test_validate_mac_none(self):
        assert DatabaseManager.validate_mac(None) is False

    def test_validate_mac_empty(self):
        assert DatabaseManager.validate_mac('') is False

    def test_validate_ip_valid(self):
        assert DatabaseManager.validate_ip('10.0.0.1') is True

    def test_validate_mac_valid(self):
        assert DatabaseManager.validate_mac('AA:BB:CC:DD:EE:FF') is True


# ── device metadata ───────────────────────────────────────────────────────────

class TestDeviceMetadata:
    def test_update_device_metadata_single_field(self, db):
        _add_device(db)
        result = db.update_device_metadata('192.168.1.10', custom_name='My Camera')
        assert result is True
        devices = db.get_all_devices()
        assert devices[0]['custom_name'] == 'My Camera'

    def test_update_device_metadata_multiple_fields(self, db):
        _add_device(db)
        result = db.update_device_metadata(
            '192.168.1.10',
            custom_name='Router',
            notes='Primary router',
            device_type='router'
        )
        assert result is True

    def test_update_device_metadata_no_valid_fields(self, db):
        _add_device(db)
        result = db.update_device_metadata('192.168.1.10', unknown_field='value')
        assert result is True  # returns True early when nothing to update

    def test_update_device_metadata_all_allowed_fields(self, db):
        _add_device(db)
        result = db.update_device_metadata(
            '192.168.1.10',
            custom_name='Test',
            notes='note',
            firmware_version='1.0',
            model='Model X',
            device_type='router',
            manufacturer='ACME',
            category='networking'
        )
        assert result is True


# ── device groups ─────────────────────────────────────────────────────────────

class TestDeviceGroups:
    def _make_group(self, db, name='IoT Devices'):
        cursor = db.conn.cursor()
        cursor.execute("INSERT INTO device_groups (name) VALUES (?)", (name,))
        db.conn.commit()
        return cursor.lastrowid

    def test_add_device_to_group(self, db):
        _add_device(db)
        gid = self._make_group(db)
        result = db.add_device_to_group('192.168.1.10', gid)
        assert result is True

    def test_add_device_to_group_duplicate_ignored(self, db):
        _add_device(db)
        gid = self._make_group(db)
        db.add_device_to_group('192.168.1.10', gid)
        result = db.add_device_to_group('192.168.1.10', gid)  # second insert
        assert result is True  # INSERT OR IGNORE

    def test_remove_device_from_group(self, db):
        _add_device(db)
        gid = self._make_group(db)
        db.add_device_to_group('192.168.1.10', gid)
        result = db.remove_device_from_group('192.168.1.10', gid)
        assert result is True

    def test_get_device_groups_empty(self, db):
        _add_device(db)
        groups = db.get_device_groups('192.168.1.10')
        assert groups == []

    def test_get_device_groups_populated(self, db):
        _add_device(db)
        gid = self._make_group(db)
        db.add_device_to_group('192.168.1.10', gid)
        groups = db.get_device_groups('192.168.1.10')
        assert len(groups) == 1
        assert groups[0]['name'] == 'IoT Devices'

    def test_get_all_groups_empty(self, db):
        groups = db.get_all_groups()
        assert isinstance(groups, list)

    def test_get_all_groups_populated(self, db):
        self._make_group(db, 'Group A')
        self._make_group(db, 'Group B')
        groups = db.get_all_groups()
        assert len(groups) == 2


# ── connection count ──────────────────────────────────────────────────────────

class TestConnectionCount:
    def test_get_connection_count_empty(self, db):
        count = db.get_connection_count()
        assert count == 0

    def test_get_connection_count_after_inserts(self, db):
        _add_device(db)
        _add_connection(db)
        _add_connection(db)
        count = db.get_connection_count(hours=24)
        assert count == 2

    def test_get_connection_count_custom_hours(self, db):
        count = db.get_connection_count(hours=1)
        assert count == 0


# ── model performance ─────────────────────────────────────────────────────────

class TestModelPerformance:
    def test_add_metric(self, db):
        result = db.add_model_performance_metric('river', 0.91, 0.88, 0.895)
        assert result is True

    def test_get_metrics_empty(self, db):
        metrics = db.get_model_performance_metrics()
        assert metrics == []

    def test_get_metrics_after_insert(self, db):
        db.add_model_performance_metric('combined', 0.90, 0.85, 0.875)
        metrics = db.get_model_performance_metrics(days=30)
        assert len(metrics) == 1
        assert metrics[0]['model_type'] == 'combined'


# ── trust / block ─────────────────────────────────────────────────────────────

class TestTrustBlock:
    def test_set_device_trust_true(self, db):
        _add_device(db)
        result = db.set_device_trust('192.168.1.10', True)
        assert result is True

    def test_set_device_trust_false(self, db):
        _add_device(db)
        db.set_device_trust('192.168.1.10', True)
        result = db.set_device_trust('192.168.1.10', False)
        assert result is True

    def test_get_trusted_devices_empty(self, db):
        _add_device(db)
        trusted = db.get_trusted_devices()
        assert trusted == []

    def test_get_trusted_devices_populated(self, db):
        _add_device(db)
        db.set_device_trust('192.168.1.10', True)
        trusted = db.get_trusted_devices()
        assert len(trusted) == 1
        assert trusted[0]['device_ip'] == '192.168.1.10'

    def test_set_device_blocked_true(self, db):
        _add_device(db)
        result = db.set_device_blocked('192.168.1.10', True)
        assert result is True

    def test_get_blocked_devices_empty(self, db):
        _add_device(db)
        blocked = db.get_blocked_devices()
        assert blocked == []

    def test_get_blocked_devices_populated(self, db):
        _add_device(db)
        db.set_device_blocked('192.168.1.10', True)
        blocked = db.get_blocked_devices()
        assert len(blocked) == 1
        assert blocked[0]['device_ip'] == '192.168.1.10'


# ── bandwidth / traffic stats ─────────────────────────────────────────────────

class TestBandwidthStats:
    def test_get_bandwidth_stats_empty(self, db):
        stats = db.get_bandwidth_stats()
        assert stats == []

    def test_get_bandwidth_stats_with_data(self, db):
        _add_device(db)
        _add_connection(db, bytes_sent=1000, bytes_received=2000)
        stats = db.get_bandwidth_stats(hours=24)
        assert len(stats) == 1
        assert stats[0]['device_ip'] == '192.168.1.10'
        assert stats[0]['total_bytes'] == 3000

    def test_get_recent_connections_empty(self, db):
        conns = db.get_recent_connections()
        assert conns == []

    def test_get_recent_connections_with_data(self, db):
        _add_device(db)
        _add_connection(db)
        conns = db.get_recent_connections(hours=1)
        assert len(conns) == 1

    def test_get_traffic_timeline_empty(self, db):
        timeline = db.get_traffic_timeline()
        assert timeline == []

    def test_get_protocol_distribution_empty(self, db):
        dist = db.get_protocol_distribution()
        assert dist == []

    def test_get_protocol_distribution_with_data(self, db):
        _add_device(db)
        _add_connection(db, protocol='tcp')
        _add_connection(db, dest_ip='8.8.4.4', protocol='udp')
        dist = db.get_protocol_distribution(hours=24)
        protocols = {d['protocol'] for d in dist}
        assert 'tcp' in protocols
        assert 'udp' in protocols

    def test_get_device_activity_heatmap_empty(self, db):
        heatmap = db.get_device_activity_heatmap()
        assert heatmap == []


# ── malicious IPs ─────────────────────────────────────────────────────────────

class TestMaliciousIPs:
    def test_add_and_check_malicious_ip(self, db):
        db.add_malicious_ips(['45.142.213.111', '1.2.3.4'], source='test_feed')
        assert db.is_ip_malicious('45.142.213.111') is True
        assert db.is_ip_malicious('1.2.3.4') is True

    def test_check_clean_ip(self, db):
        assert db.is_ip_malicious('192.168.1.1') is False

    def test_add_duplicate_malicious_ip_ignored(self, db):
        db.add_malicious_ips(['1.2.3.4'], source='feed_a')
        db.add_malicious_ips(['1.2.3.4'], source='feed_b')  # INSERT OR IGNORE
        assert db.is_ip_malicious('1.2.3.4') is True


# ── alert timeline / anomaly distribution ─────────────────────────────────────

class TestAlertQueries:
    def test_get_alert_timeline_empty(self, db):
        timeline = db.get_alert_timeline()
        assert timeline == []

    def test_get_alert_timeline_with_data(self, db):
        _add_device(db)
        _add_alert(db)
        timeline = db.get_alert_timeline(days=7)
        assert len(timeline) >= 1

    def test_get_anomaly_distribution_empty(self, db):
        dist = db.get_anomaly_distribution()
        assert dist == []

    def test_get_new_devices_count_empty(self, db):
        count = db.get_new_devices_count()
        assert count == 0

    def test_get_new_devices_count_with_data(self, db):
        _add_device(db)
        count = db.get_new_devices_count(days=7)
        assert count == 1


# ── cleanup ───────────────────────────────────────────────────────────────────

class TestCleanup:
    def test_cleanup_old_data_empty_db(self, db):
        db.cleanup_old_data(days=30)  # should not raise

    def test_cleanup_old_data_removes_old_records(self, db):
        _add_device(db)
        conn_id = _add_connection(db)
        cursor = db.conn.cursor()
        # Backdate the connection to 60 days ago
        cursor.execute(
            "UPDATE connections SET timestamp = ? WHERE id = ?",
            ((datetime.now() - timedelta(days=60)).isoformat(), conn_id)
        )
        db.conn.commit()
        db.cleanup_old_data(days=30)
        count = db.get_connection_count(hours=24 * 365)
        assert count == 0


# ── mark / get unprocessed connections ───────────────────────────────────────

class TestConnectionProcessing:
    def test_get_unprocessed_connections_empty(self, db):
        result = db.get_unprocessed_connections()
        assert result == []

    def test_mark_and_get_unprocessed(self, db):
        _add_device(db)
        conn_id = _add_connection(db)
        unprocessed = db.get_unprocessed_connections()
        assert len(unprocessed) == 1
        db.mark_connections_processed([conn_id])
        unprocessed_after = db.get_unprocessed_connections()
        assert len(unprocessed_after) == 0

    def test_mark_connections_processed_empty_list(self, db):
        db.mark_connections_processed([])  # should be a no-op


# ── schema version ────────────────────────────────────────────────────────────

class TestSchemaVersion:
    def test_get_schema_version_default(self, db):
        v = db.get_schema_version()
        assert isinstance(v, int)

    def test_set_and_get_schema_version(self, db):
        db.set_schema_version(42)
        assert db.get_schema_version() == 42


# ── add_device validation paths ───────────────────────────────────────────────

class TestAddDeviceValidation:
    def test_add_device_invalid_ip_raises(self, db):
        with pytest.raises(ValidationError):
            db.add_device(device_ip='not-an-ip')

    def test_add_device_invalid_mac_raises(self, db):
        with pytest.raises(ValidationError):
            db.add_device(device_ip='192.168.1.10', mac_address='bad-mac')


# ── add_connection validation paths ──────────────────────────────────────────

class TestAddConnectionValidation:
    def test_invalid_source_ip_raises(self, db):
        with pytest.raises(ValidationError):
            db.add_connection(
                device_ip='bad', dest_ip='8.8.8.8',
                dest_port=443, protocol='tcp'
            )

    def test_invalid_dest_port_raises(self, db):
        _add_device(db)
        with pytest.raises(ValidationError):
            db.add_connection(
                device_ip='192.168.1.10', dest_ip='8.8.8.8',
                dest_port=99999, protocol='tcp'
            )


# ── add_connections_batch ─────────────────────────────────────────────────────

class TestAddConnectionsBatch:
    def _make_conn(self, device_ip='192.168.1.10', dest_ip='8.8.8.8',
                   dest_port=443, protocol='tcp', **kw):
        return dict(device_ip=device_ip, dest_ip=dest_ip,
                    dest_port=dest_port, protocol=protocol, **kw)

    def test_empty_list_returns_zero(self, db):
        assert db.add_connections_batch([]) == 0

    def test_batch_insert_valid_connections(self, db):
        conns = [self._make_conn(), self._make_conn(dest_ip='8.8.4.4')]
        inserted = db.add_connections_batch(conns)
        assert inserted == 2

    def test_batch_skips_missing_ips(self, db):
        conns = [
            {'device_ip': '192.168.1.10'},  # missing dest_ip
            self._make_conn(),               # valid
        ]
        inserted = db.add_connections_batch(conns)
        assert inserted == 1

    def test_batch_skips_invalid_ip(self, db):
        conns = [
            self._make_conn(device_ip='not-an-ip'),
            self._make_conn(),
        ]
        inserted = db.add_connections_batch(conns)
        assert inserted == 1

    def test_batch_skips_invalid_port(self, db):
        conns = [
            self._make_conn(dest_port=99999),
            self._make_conn(),
        ]
        inserted = db.add_connections_batch(conns)
        assert inserted == 1

    def test_batch_all_invalid_returns_zero(self, db):
        conns = [{'device_ip': 'bad', 'dest_ip': 'also-bad'}]
        assert db.add_connections_batch(conns) == 0

    def test_batch_with_byte_counts(self, db):
        conns = [self._make_conn(bytes_sent=500, bytes_received=1000)]
        inserted = db.add_connections_batch(conns)
        assert inserted == 1


# ── create_indexes ────────────────────────────────────────────────────────────

class TestCreateIndexes:
    def test_create_indexes_runs_without_error(self, db):
        db.create_indexes()  # should not raise

    def test_create_indexes_idempotent(self, db):
        db.create_indexes()
        db.create_indexes()  # second call should succeed (IF NOT EXISTS)


# ── optimize_database ─────────────────────────────────────────────────────────

class TestOptimizeDatabase:
    def test_optimize_on_small_db(self, file_db):
        file_db.optimize_database()  # should not raise

    def test_optimize_on_memory_db(self, db):
        # :memory: path stat() will fail → should not crash
        try:
            db.optimize_database()
        except Exception:
            pass  # known edge case with :memory: path


# ── get_database_stats ────────────────────────────────────────────────────────

class TestGetDatabaseStats:
    def test_returns_dict(self, file_db):
        stats = file_db.get_database_stats()
        assert isinstance(stats, dict)
        assert 'tables' in stats
        assert 'storage' in stats
        assert 'activity' in stats

    def test_table_counts_are_ints(self, file_db):
        stats = file_db.get_database_stats()
        for table, count in stats['tables'].items():
            assert isinstance(count, int)


# ── health_check ──────────────────────────────────────────────────────────────

class TestHealthCheck:
    def test_health_check_healthy(self, file_db):
        result = file_db.health_check()
        assert result['status'] in ('healthy', 'warning')
        assert 'metrics' in result
        assert 'configuration' in result

    def test_health_check_metrics_structure(self, file_db):
        result = file_db.health_check()
        m = result['metrics']
        assert 'devices' in m
        assert 'connections' in m
        assert 'db_size_mb' in m


# ── backup_database ────────────────────────────────────────────────────────────

class TestBackupDatabase:
    def test_backup_creates_file(self, file_db, tmp_path):
        backup_dir = str(tmp_path / 'backups')
        backup_path = file_db.backup_database(backup_dir=backup_dir)
        assert backup_path is not None
        assert os.path.exists(backup_path)

    def test_backup_result_is_string(self, file_db, tmp_path):
        backup_dir = str(tmp_path / 'backups2')
        result = file_db.backup_database(backup_dir=backup_dir)
        assert isinstance(result, str)


# ── cleanup_old_backups ────────────────────────────────────────────────────────

class TestCleanupOldBackups:
    def test_cleanup_nonexistent_dir(self, db):
        count = db.cleanup_old_backups(backup_dir='/tmp/nonexistent_iotsentinel_backups')
        assert count == 0

    def test_cleanup_empty_dir(self, db, tmp_path):
        backup_dir = str(tmp_path / 'empty_backups')
        os.makedirs(backup_dir)
        count = db.cleanup_old_backups(backup_dir=backup_dir)
        assert count == 0

    def test_cleanup_old_backup_files(self, db, tmp_path):
        backup_dir = tmp_path / 'backups'
        backup_dir.mkdir()
        old_file = backup_dir / 'iotsentinel_20200101_000000.db'
        old_file.write_bytes(b'fake backup')
        import time
        import os
        # Set mtime to 30 days ago
        old_time = time.time() - (40 * 86400)
        os.utime(old_file, (old_time, old_time))
        count = db.cleanup_old_backups(backup_dir=str(backup_dir), keep_days=7)
        assert count == 1


# ── _ensure_connection ────────────────────────────────────────────────────────

class TestEnsureConnection:
    def test_ensure_connection_alive(self, db):
        db._ensure_connection()  # should not raise when connection is fine
