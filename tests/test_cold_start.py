#!/usr/bin/env python3
"""
Unit tests for the InferenceEngine cold-start and baseline-sigma features.

Covers:
- _is_learning_period: connection-count gate, first_seen gate, TTL cache,
  empty device, DB-error safety
- _SEVERITY_DAMP map + the still-learning note appended by _create_alert
- threat-intel (malicious IP) alerts are NEVER damped
- _sigma_sentence: 2-sigma threshold, zero-std guard
- _baseline_stats: reads device_behavior_baselines, missing table is safe
- _baseline_diff_sentence Signal 5 sigma qualification end-to-end

Run: pytest tests/test_cold_start.py -v
"""
import sys
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from ml.inference_engine import InferenceEngine
from tests.conftest import create_test_schema


DEVICE = '192.168.1.50'


def make_engine(db, damping=True, min_conn=100, days=2):
    """Lightweight engine without running the heavy __init__."""
    eng = InferenceEngine.__new__(InferenceEngine)
    eng.db = db
    eng.alerting = None
    eng.cold_start_damping = damping
    eng.learning_min_connections = min_conn
    eng.learning_period_days = days
    eng._learning_cache = {}
    eng._LEARNING_CACHE_TTL = 600
    return eng


@pytest.fixture
def baseline_db(db):
    """In-memory DB with the device_behavior_baselines table added."""
    db.conn.execute('''
        CREATE TABLE IF NOT EXISTS device_behavior_baselines (
            device_ip TEXT, metric_name TEXT, baseline_value REAL,
            std_deviation REAL, min_value REAL, max_value REAL,
            sample_count INTEGER, last_updated TIMESTAMP,
            PRIMARY KEY (device_ip, metric_name)
        )
    ''')
    db.conn.commit()
    return db


def _add_device(db, ip=DEVICE, first_seen_offset_days=10):
    db.conn.execute(
        "INSERT OR REPLACE INTO devices (device_ip, device_name, first_seen) "
        f"VALUES (?, ?, datetime('now', '-{first_seen_offset_days} days'))",
        (ip, 'Test Device'),
    )
    db.conn.commit()


def _add_connections(db, count, ip=DEVICE, bytes_sent=1000,
                     dest_ip='1.2.3.4', timestamp_expr="datetime('now')"):
    for _ in range(count):
        db.conn.execute(
            f"INSERT INTO connections (device_ip, dest_ip, bytes_sent, timestamp) "
            f"VALUES (?, ?, ?, {timestamp_expr})",
            (ip, dest_ip, bytes_sent),
        )
    db.conn.commit()


# ---------------------------------------------------------------------------
# _is_learning_period
# ---------------------------------------------------------------------------

class TestIsLearningPeriod:

    def test_new_device_few_connections_is_learning(self, db):
        _add_device(db)
        _add_connections(db, 5)
        eng = make_engine(db)
        assert eng._is_learning_period(DEVICE) is True

    def test_established_device_not_learning(self, db):
        _add_device(db, first_seen_offset_days=10)
        _add_connections(db, 120)
        eng = make_engine(db)
        assert eng._is_learning_period(DEVICE) is False

    def test_recently_seen_device_still_learning_despite_volume(self, db):
        _add_device(db, first_seen_offset_days=0)  # first seen today
        _add_connections(db, 200)
        eng = make_engine(db)
        assert eng._is_learning_period(DEVICE) is True

    def test_threshold_boundary(self, db):
        _add_device(db, first_seen_offset_days=10)
        _add_connections(db, 99)
        eng = make_engine(db)
        assert eng._is_learning_period(DEVICE) is True

    def test_empty_device_ip_false(self, db):
        assert make_engine(db)._is_learning_period('') is False

    def test_result_cached(self, db):
        _add_device(db)
        _add_connections(db, 5)
        eng = make_engine(db)
        assert eng._is_learning_period(DEVICE) is True
        # Device crosses the threshold, but cache still answers True
        _add_connections(db, 200)
        assert eng._is_learning_period(DEVICE) is True
        # Expire the cache entry -> fresh lookup flips to False
        learning, checked_at = eng._learning_cache[DEVICE]
        eng._learning_cache[DEVICE] = (learning, checked_at - 601)
        assert eng._is_learning_period(DEVICE) is False

    def test_db_error_returns_false(self):
        broken = MagicMock()
        broken.conn.cursor.side_effect = RuntimeError("locked")
        eng = make_engine(broken)
        assert eng._is_learning_period(DEVICE) is False

    def test_configurable_thresholds(self, db):
        _add_device(db, first_seen_offset_days=10)
        _add_connections(db, 50)
        assert make_engine(db, min_conn=10)._is_learning_period(DEVICE) is False
        assert make_engine(db, min_conn=60)._is_learning_period(DEVICE) is True


# ---------------------------------------------------------------------------
# Severity damping + learning note
# ---------------------------------------------------------------------------

class TestSeverityDamping:

    @pytest.mark.parametrize("severity,expected", [
        ('critical', 'high'),
        ('high', 'medium'),
        ('medium', 'low'),
        ('low', 'low'),
    ])
    def test_damp_map(self, severity, expected):
        assert InferenceEngine._SEVERITY_DAMP[severity] == expected

    def test_learning_note_appended(self, db):
        eng = make_engine(db)
        eng.alerting = MagicMock()
        with patch.object(InferenceEngine, '_generate_plain_explanation',
                          return_value="Device did something odd."):
            eng._create_alert(DEVICE, 'medium', 0.8, 'tech detail',
                              connection={'device_ip': DEVICE}, learning_note=True)
        plain = eng.alerting.create_alert.call_args.kwargs['plain_explanation']
        assert plain.startswith("Device did something odd.")
        assert "still learning" in plain
        assert "—" not in plain  # no em dashes in AI-facing output

    def test_no_note_when_not_learning(self, db):
        eng = make_engine(db)
        eng.alerting = MagicMock()
        with patch.object(InferenceEngine, '_generate_plain_explanation',
                          return_value="Device did something odd."):
            eng._create_alert(DEVICE, 'medium', 0.8, 'tech detail',
                              connection={'device_ip': DEVICE}, learning_note=False)
        plain = eng.alerting.create_alert.call_args.kwargs['plain_explanation']
        assert "still learning" not in plain

    def test_malicious_ip_alert_never_damped(self, db):
        """Threat-intel hits stay critical even while the device is learning."""
        _add_device(db)
        _add_connections(db, 1)  # brand-new device -> learning period
        eng = make_engine(db)
        eng.db = MagicMock()
        eng.db.get_unprocessed_connections.return_value = [
            {'id': 1, 'device_ip': DEVICE, 'dest_ip': '203.0.113.9'}
        ]
        eng.db.is_ip_malicious.return_value = True
        captured = {}

        with patch.object(InferenceEngine, '_create_alert',
                          side_effect=lambda *a, **kw: captured.update(kw) or 1), \
             patch.object(InferenceEngine, '_generate_malicious_ip_explanation',
                          return_value="Contacted a known-malicious IP."):
            eng.process_connections()

        assert captured['severity'] == 'critical'
        assert 'learning_note' not in captured or not captured['learning_note']


# ---------------------------------------------------------------------------
# Sigma helpers
# ---------------------------------------------------------------------------

class TestSigmaSentence:

    def test_two_sigma_fires(self):
        note = InferenceEngine._sigma_sentence(10.0, 2.0, 4.0)  # sigma = 2
        assert "more than 2 times outside its normal range" in note

    def test_large_sigma_floor(self):
        note = InferenceEngine._sigma_sentence(25_000_000, 1_000_000, 4_000_000)  # 6
        assert "more than 6 times" in note

    def test_below_two_sigma_empty(self):
        assert InferenceEngine._sigma_sentence(5.0, 2.0, 4.0) == ''

    def test_zero_std_empty(self):
        assert InferenceEngine._sigma_sentence(10.0, 2.0, 0.0) == ''

    def test_negative_deviation_uses_abs(self):
        note = InferenceEngine._sigma_sentence(0.0, 10.0, 4.0)  # |0-10|/4 = 2.5
        assert "more than 2 times" in note


class TestBaselineStats:

    def test_reads_metrics(self, baseline_db):
        baseline_db.conn.execute(
            "INSERT INTO device_behavior_baselines "
            "(device_ip, metric_name, baseline_value, std_deviation) VALUES (?, ?, ?, ?)",
            (DEVICE, 'bytes_sent_per_connection', 1_000_000.0, 4_000_000.0),
        )
        baseline_db.conn.commit()
        stats = make_engine(baseline_db)._baseline_stats(DEVICE)
        assert stats['bytes_sent_per_connection'] == (1_000_000.0, 4_000_000.0)

    def test_zero_std_rows_excluded(self, baseline_db):
        baseline_db.conn.execute(
            "INSERT INTO device_behavior_baselines "
            "(device_ip, metric_name, baseline_value, std_deviation) VALUES (?, ?, ?, ?)",
            (DEVICE, 'connection_duration_seconds', 5.0, 0.0),
        )
        baseline_db.conn.commit()
        assert make_engine(baseline_db)._baseline_stats(DEVICE) == {}

    def test_missing_table_safe(self, db):
        # plain `db` fixture has no device_behavior_baselines table
        assert make_engine(db)._baseline_stats(DEVICE) == {}


# ---------------------------------------------------------------------------
# Signal 5 sigma qualification end-to-end
# ---------------------------------------------------------------------------

class TestSignalFiveSigma:

    def _setup_bytes_spike(self, db):
        """Today: 25 MB to a known destination. Baseline window: 2 MB/day."""
        _add_device(db)
        _add_connections(db, 1, bytes_sent=2_000_000, dest_ip='8.8.8.8',
                         timestamp_expr="datetime('now', '-2 days')")
        _add_connections(db, 1, bytes_sent=25_000_000, dest_ip='8.8.8.8')

    def test_sigma_note_present_with_baseline(self, baseline_db):
        self._setup_bytes_spike(baseline_db)
        baseline_db.conn.execute(
            "INSERT INTO device_behavior_baselines "
            "(device_ip, metric_name, baseline_value, std_deviation) VALUES (?, ?, ?, ?)",
            (DEVICE, 'bytes_sent_per_connection', 1_000_000.0, 4_000_000.0),
        )
        baseline_db.conn.commit()
        sentence = make_engine(baseline_db)._baseline_diff_sentence(
            {'device_ip': DEVICE, 'dest_ip': '8.8.8.8', 'bytes_sent': 25_000_000})
        assert "MB of data today" in sentence
        assert "outside its normal range" in sentence

    def test_no_sigma_note_without_baseline_row(self, baseline_db):
        self._setup_bytes_spike(baseline_db)
        sentence = make_engine(baseline_db)._baseline_diff_sentence(
            {'device_ip': DEVICE, 'dest_ip': '8.8.8.8', 'bytes_sent': 25_000_000})
        assert "MB of data today" in sentence
        assert "outside its normal range" not in sentence

    def test_no_sigma_note_when_within_range(self, baseline_db):
        self._setup_bytes_spike(baseline_db)
        baseline_db.conn.execute(
            "INSERT INTO device_behavior_baselines "
            "(device_ip, metric_name, baseline_value, std_deviation) VALUES (?, ?, ?, ?)",
            (DEVICE, 'bytes_sent_per_connection', 20_000_000.0, 50_000_000.0),
        )
        baseline_db.conn.commit()
        sentence = make_engine(baseline_db)._baseline_diff_sentence(
            {'device_ip': DEVICE, 'dest_ip': '8.8.8.8', 'bytes_sent': 25_000_000})
        assert "MB of data today" in sentence
        assert "outside its normal range" not in sentence
