"""
Tests for get_device_baseline() in dashboard/shared.py.

Verifies:
  - Returns None when no baseline rows exist (fresh device / insufficient data).
  - Returns a dict with `has_baseline=True` and correctly mapped keys when rows exist.
  - Handles multiple metrics in one call.
  - Unknown / unmapped metric names are ignored gracefully.
"""

import sqlite3
from unittest.mock import patch


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS device_behavior_baselines (
    device_ip TEXT,
    metric_name TEXT,
    baseline_value REAL,
    std_deviation REAL,
    min_value REAL,
    max_value REAL,
    sample_count INTEGER,
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (device_ip, metric_name)
)
"""


def _make_conn():
    """Return an in-memory SQLite connection with the baselines table."""
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute(_CREATE_TABLE)
    conn.commit()
    return conn


def _seed(conn, device_ip, rows):
    """Insert (metric_name, baseline_value) pairs for device_ip."""
    conn.executemany(
        "INSERT INTO device_behavior_baselines (device_ip, metric_name, baseline_value) VALUES (?,?,?)",
        [(device_ip, name, value) for name, value in rows],
    )
    conn.commit()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestGetDeviceBaseline:

    def test_returns_none_when_no_rows(self):
        """No baseline rows → None (shown as 'No baseline data yet' in UI)."""
        conn = _make_conn()
        with patch("dashboard.shared.get_db_connection", return_value=conn):
            from dashboard.shared import get_device_baseline
            result = get_device_baseline("192.168.1.100")
        assert result is None

    def test_has_baseline_flag_set_when_rows_exist(self):
        """Any stored row → has_baseline is True."""
        conn = _make_conn()
        _seed(conn, "192.168.1.10", [("hourly_connections", 5.0)])
        with patch("dashboard.shared.get_db_connection", return_value=conn):
            from dashboard.shared import get_device_baseline
            result = get_device_baseline("192.168.1.10")
        assert result is not None
        assert result["has_baseline"] is True

    def test_avg_connections_mapped_from_hourly_connections(self):
        """hourly_connections.baseline_value → avg_connections."""
        conn = _make_conn()
        _seed(conn, "10.0.0.1", [("hourly_connections", 12.5)])
        with patch("dashboard.shared.get_db_connection", return_value=conn):
            from dashboard.shared import get_device_baseline
            result = get_device_baseline("10.0.0.1")
        assert result["avg_connections"] == 12.5

    def test_avg_bytes_sent_mapped(self):
        """bytes_sent_per_connection.baseline_value → avg_bytes_sent."""
        conn = _make_conn()
        _seed(conn, "10.0.0.2", [("bytes_sent_per_connection", 1024.0)])
        with patch("dashboard.shared.get_db_connection", return_value=conn):
            from dashboard.shared import get_device_baseline
            result = get_device_baseline("10.0.0.2")
        assert result["avg_bytes_sent"] == 1024.0

    def test_avg_bytes_received_mapped(self):
        """bytes_received_per_connection.baseline_value → avg_bytes_received."""
        conn = _make_conn()
        _seed(conn, "10.0.0.3", [("bytes_received_per_connection", 2048.0)])
        with patch("dashboard.shared.get_db_connection", return_value=conn):
            from dashboard.shared import get_device_baseline
            result = get_device_baseline("10.0.0.3")
        assert result["avg_bytes_received"] == 2048.0

    def test_all_five_standard_metrics_mapped(self):
        """All five known metrics are mapped to their expected output keys."""
        conn = _make_conn()
        _seed(conn, "10.0.0.9", [
            ("hourly_connections",            7.0),
            ("bytes_sent_per_connection",    512.0),
            ("bytes_received_per_connection", 256.0),
            ("unique_destinations_per_hour",   3.0),
            ("connection_duration_seconds",   45.0),
        ])
        with patch("dashboard.shared.get_db_connection", return_value=conn):
            from dashboard.shared import get_device_baseline
            result = get_device_baseline("10.0.0.9")

        assert result["has_baseline"] is True
        assert result["avg_connections"] == 7.0
        assert result["avg_bytes_sent"] == 512.0
        assert result["avg_bytes_received"] == 256.0
        assert result["avg_unique_destinations"] == 3.0
        assert result["avg_connection_duration"] == 45.0

    def test_unknown_metric_names_ignored(self):
        """An unrecognised metric name is silently ignored; has_baseline still True."""
        conn = _make_conn()
        _seed(conn, "172.16.0.1", [
            ("hourly_connections", 4.0),
            ("some_future_metric", 99.9),  # unknown — should not raise
        ])
        with patch("dashboard.shared.get_db_connection", return_value=conn):
            from dashboard.shared import get_device_baseline
            result = get_device_baseline("172.16.0.1")

        assert result is not None
        assert result["has_baseline"] is True
        assert "avg_connections" in result
        # unknown metric must not bleed into the output
        assert "some_future_metric" not in result

    def test_device_isolation(self):
        """Rows for device A don't contaminate lookups for device B."""
        conn = _make_conn()
        _seed(conn, "192.168.0.1", [("hourly_connections", 10.0)])
        with patch("dashboard.shared.get_db_connection", return_value=conn):
            from dashboard.shared import get_device_baseline
            assert get_device_baseline("192.168.0.2") is None
