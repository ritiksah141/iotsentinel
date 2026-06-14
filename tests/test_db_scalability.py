"""
End-to-end tests for the long-run scalability changes introduced in
the v1.0.0 pre-release hardening pass:

  1. Batch ingestion  — parse_conn_log collects rows and calls add_connections_batch
  2. Tiered retention — cleanup_old_data prunes all unbounded tables
  3. Thread safety    — concurrent writes don't corrupt the DB or raise sqlite3 errors
  4. WAL / VACUUM     — size-guarded VACUUM, always-checkpoint behaviour
  5. last_seen bump   — add_connections_batch updates existing devices' last_seen
"""

import json
import sqlite3
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import sys

sys.path.insert(0, str(Path(__file__).parent.parent))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_db(tmp_path):
    from database.db_manager import DatabaseManager
    from tests.conftest import create_test_schema

    # Reset the singleton so each test gets a fresh instance
    normalized = str(Path(tmp_path / "test.db").resolve())
    DatabaseManager._instances.pop(normalized, None)

    db = DatabaseManager(str(tmp_path / "test.db"))
    create_test_schema(db)  # creates devices, connections, alerts, etc.

    # Extra tables created by init_database.py but not in the minimal test schema
    db.conn.execute("""
        CREATE TABLE IF NOT EXISTS alert_suppressions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_ip TEXT NOT NULL,
            expires_at TIMESTAMP,
            created_by TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    db.conn.execute("""
        CREATE TABLE IF NOT EXISTS agent_actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id INTEGER, device_ip TEXT NOT NULL,
            action_type TEXT NOT NULL, params TEXT,
            risk_level TEXT DEFAULT 'low', rationale TEXT,
            plain_report TEXT, status TEXT DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            resolved_at TIMESTAMP, resolved_by TEXT
        )
    """)
    db.conn.execute("""
        CREATE TABLE IF NOT EXISTS system_settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    # Create base tables needed by tests
    db.conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            user_id INTEGER, username TEXT NOT NULL,
            action_type TEXT NOT NULL, action_description TEXT,
            target_resource TEXT, ip_address TEXT, user_agent TEXT,
            success INTEGER DEFAULT 1, error_message TEXT
        )
    """)
    db.conn.execute("""
        CREATE TABLE IF NOT EXISTS security_audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            user_id INTEGER, username TEXT, event_type TEXT NOT NULL,
            event_category TEXT, severity TEXT DEFAULT 'info',
            ip_address TEXT, user_agent TEXT, resource_type TEXT,
            resource_id TEXT, details TEXT, result TEXT,
            failure_reason TEXT, session_id TEXT, request_id TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    db.conn.execute("""
        CREATE TABLE IF NOT EXISTS rate_limit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            identifier TEXT NOT NULL, action_type TEXT NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            ip_address TEXT, success INTEGER DEFAULT 1
        )
    """)
    db.conn.execute("""
        CREATE TABLE IF NOT EXISTS api_integration_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            integration_id INTEGER NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            request_type TEXT, request_params TEXT,
            response_status INTEGER, response_time_ms INTEGER,
            success INTEGER DEFAULT 1, error_message TEXT
        )
    """)
    db.conn.execute("""
        CREATE TABLE IF NOT EXISTS toast_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            toast_id TEXT UNIQUE NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            toast_type TEXT NOT NULL, category TEXT DEFAULT 'general',
            header TEXT, message TEXT NOT NULL, detail_message TEXT,
            user_id INTEGER, session_id TEXT, dismissed INTEGER DEFAULT 0,
            dismissed_at TIMESTAMP, duration INTEGER,
            action_taken TEXT, metadata TEXT
        )
    """)
    db.conn.execute("""
        CREATE TABLE IF NOT EXISTS discovery_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_ip TEXT NOT NULL, discovery_method TEXT,
            device_info_json TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    db.conn.execute("""
        CREATE TABLE IF NOT EXISTS security_score_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            overall_score INTEGER, device_health_score INTEGER,
            vulnerabilities_score INTEGER, encryption_score INTEGER,
            segmentation_score INTEGER, device_count INTEGER,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    db.conn.execute("""
        CREATE TABLE IF NOT EXISTS sustainability_metrics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            period_start TIMESTAMP, period_end TIMESTAMP,
            total_data_gb REAL DEFAULT 0, estimated_energy_kwh REAL DEFAULT 0,
            carbon_footprint_kg REAL DEFAULT 0, device_count INTEGER DEFAULT 0,
            active_device_hours REAL DEFAULT 0, notes TEXT
        )
    """)
    db.conn.execute("""
        CREATE TABLE IF NOT EXISTS device_energy_estimates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_ip TEXT NOT NULL, device_type TEXT,
            date DATE NOT NULL, estimated_power_watts REAL DEFAULT 0,
            active_hours REAL DEFAULT 0, estimated_energy_kwh REAL DEFAULT 0,
            data_transferred_gb REAL DEFAULT 0,
            UNIQUE(device_ip, date)
        )
    """)
    db.conn.execute("""
        CREATE TABLE IF NOT EXISTS model_drift_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            model_type TEXT NOT NULL, drift_score REAL, metric_type TEXT,
            baseline_value REAL, current_value REAL,
            alert_triggered INTEGER DEFAULT 0,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    db.conn.commit()
    return db


def _old_timestamp(days_ago: int) -> str:
    return (datetime.now() - timedelta(days=days_ago)).strftime('%Y-%m-%d %H:%M:%S')


def _count(db, table: str) -> int:
    return db.conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]  # noqa: S608


# ---------------------------------------------------------------------------
# 1. Batch ingestion — parse_conn_log uses add_connections_batch
# ---------------------------------------------------------------------------

class TestBatchIngestion:

    def _write_conn_log(self, path: Path, n: int):
        """Write n synthetic conn.log JSON lines."""
        with open(path, "w") as f:
            for i in range(n):
                record = {
                    "id.orig_h": f"192.168.1.{(i % 200) + 1}",
                    "id.resp_h": f"8.8.{i % 256}.{i % 256}",
                    "id.resp_p": 443,
                    "proto": "tcp",
                    "service": "https",
                    "duration": 0.1,
                    "orig_bytes": 1024,
                    "resp_bytes": 2048,
                    "orig_pkts": 5,
                    "resp_pkts": 8,
                    "conn_state": "SF",
                }
                f.write(json.dumps(record) + "\n")

    def test_parse_conn_log_inserts_all_rows(self, tmp_path):
        from database.db_manager import DatabaseManager
        DatabaseManager._instances.clear()

        from capture.zeek_log_parser import ZeekLogParser
        with patch("capture.zeek_log_parser.config") as mock_cfg:
            mock_cfg.get.side_effect = lambda *a, **kw: {
                ("network", "zeek_log_path"): str(tmp_path),
                ("database", "path"): str(tmp_path / "test.db"),
                ("system", "status_file_path", None): str(tmp_path / "status.json"),
            }.get(tuple(a), kw.get("default"))

            parser = ZeekLogParser.__new__(ZeekLogParser)
            DatabaseManager._instances.clear()
            parser.db = _make_db(tmp_path)
            parser.file_positions = {}
            parser.stats = {k: 0 for k in
                            ("conn_records", "http_records", "dns_records",
                             "dhcp_records", "total_records", "start_time")}
            parser.stats["start_time"] = time.time()

            N = 12_000  # more than one batch
            log_path = tmp_path / "conn.log"
            self._write_conn_log(log_path, N)

            inserted = parser.parse_conn_log(log_path)

        assert inserted == N, f"Expected {N} rows, got {inserted}"
        assert _count(parser.db, "connections") == N

    def test_parse_conn_log_skips_bad_lines(self, tmp_path):
        from database.db_manager import DatabaseManager
        DatabaseManager._instances.clear()

        from capture.zeek_log_parser import ZeekLogParser
        parser = ZeekLogParser.__new__(ZeekLogParser)
        DatabaseManager._instances.clear()
        parser.db = _make_db(tmp_path)
        parser.file_positions = {}
        parser.stats = {k: 0 for k in
                        ("conn_records", "http_records", "dns_records",
                         "dhcp_records", "total_records", "start_time")}
        parser.stats["start_time"] = time.time()

        log_path = tmp_path / "conn.log"
        with open(log_path, "w") as f:
            # 3 valid rows
            for ip in ["192.168.1.10", "192.168.1.11", "192.168.1.12"]:
                f.write(json.dumps({
                    "id.orig_h": ip, "id.resp_h": "8.8.8.8",
                    "id.resp_p": 80, "proto": "tcp",
                }) + "\n")
            # malformed + missing IPs (should be skipped)
            f.write("not-json\n")
            f.write(json.dumps({"id.resp_h": "8.8.8.8"}) + "\n")  # no orig_h

        inserted = parser.parse_conn_log(log_path)
        assert inserted == 3

    def test_batch_last_seen_updated_for_existing_devices(self, tmp_path):
        """add_connections_batch must bump last_seen for devices already in the table."""
        db = _make_db(tmp_path)

        # Pre-insert device with an old last_seen
        old_ts = _old_timestamp(10)
        db.conn.execute(
            "INSERT INTO devices (device_ip, first_seen, last_seen) VALUES (?, ?, ?)",
            ("192.168.1.99", old_ts, old_ts)
        )
        db.conn.commit()

        batch = [{
            "device_ip": "192.168.1.99",
            "dest_ip": "8.8.8.8",
            "dest_port": 443,
            "protocol": "tcp",
        }]
        db.add_connections_batch(batch)

        row = db.conn.execute(
            "SELECT last_seen FROM devices WHERE device_ip = ?",
            ("192.168.1.99",)
        ).fetchone()
        # last_seen must be newer than the seeded old timestamp
        assert row["last_seen"] > old_ts


# ---------------------------------------------------------------------------
# 2. Tiered retention
# ---------------------------------------------------------------------------

class TestTieredRetention:

    def _seed_old_rows(self, db, table: str, ts_col: str, n: int = 5, days_ago: int = 60):
        """Insert n rows with a timestamp far in the past."""
        old = _old_timestamp(days_ago)
        for i in range(n):
            if table == "audit_log":
                db.conn.execute(
                    f"INSERT INTO {table} ({ts_col}, username, action_type) VALUES (?, ?, ?)",
                    (old, "testuser", "test_action")
                )
            elif table == "security_audit_log":
                db.conn.execute(
                    f"INSERT INTO {table} ({ts_col}, event_type) VALUES (?, ?)",
                    (old, "login")
                )
            elif table == "rate_limit_log":
                db.conn.execute(
                    f"INSERT INTO {table} ({ts_col}, identifier, action_type) VALUES (?, ?, ?)",
                    (old, f"user{i}", "login")
                )
            elif table == "api_integration_logs":
                db.conn.execute(
                    f"INSERT INTO {table} ({ts_col}, integration_id) VALUES (?, ?)",
                    (old, 1)
                )
            elif table == "toast_history":
                db.conn.execute(
                    f"INSERT INTO {table} ({ts_col}, toast_id, toast_type, message) VALUES (?, ?, ?, ?)",
                    (old, f"t{i}", "info", "msg")
                )
            elif table == "discovery_events":
                db.conn.execute(
                    f"INSERT INTO {table} ({ts_col}, device_ip) VALUES (?, ?)",
                    (old, f"192.168.1.{i}")
                )
            elif table == "security_score_history":
                db.conn.execute(
                    f"INSERT INTO {table} ({ts_col}, overall_score) VALUES (?, ?)",
                    (old, 75)
                )
            elif table == "sustainability_metrics":
                db.conn.execute(
                    f"INSERT INTO {table} ({ts_col}) VALUES (?)",
                    (old,)
                )
            elif table == "device_energy_estimates":
                db.conn.execute(
                    f"INSERT INTO {table} ({ts_col}, device_ip) VALUES (?, ?)",
                    (old[:10], f"192.168.1.{i}")  # DATE only
                )
            elif table == "model_drift_history":
                db.conn.execute(
                    f"INSERT INTO {table} ({ts_col}, model_type) VALUES (?, ?)",
                    (old, "river")
                )
            else:
                db.conn.execute(
                    f"INSERT INTO {table} ({ts_col}) VALUES (?)", (old,)
                )
        db.conn.commit()

    # config is imported inside cleanup_old_data; patch it at the source module.
    _CFG_PATH = "config.config_manager.config"

    def test_cleanup_prunes_audit_log(self, tmp_path):
        db = _make_db(tmp_path)
        self._seed_old_rows(db, "audit_log", "timestamp", n=3, days_ago=200)
        assert _count(db, "audit_log") == 3

        with patch(self._CFG_PATH) as mock_cfg:
            mock_cfg.get.side_effect = lambda *a, **kw: kw.get("default")
            db.cleanup_old_data(days=30)

        # audit_log default retention = 180 days; 200-day-old rows must be gone
        assert _count(db, "audit_log") == 0

    def test_cleanup_prunes_rate_limit_log(self, tmp_path):
        db = _make_db(tmp_path)
        self._seed_old_rows(db, "rate_limit_log", "timestamp", n=5, days_ago=10)
        assert _count(db, "rate_limit_log") == 5

        with patch(self._CFG_PATH) as mock_cfg:
            mock_cfg.get.side_effect = lambda *a, **kw: kw.get("default")
            db.cleanup_old_data(days=30)

        # rate_limit_log default retention = 7 days; 10-day-old rows must be gone
        assert _count(db, "rate_limit_log") == 0

    def test_cleanup_keeps_recent_rows(self, tmp_path):
        db = _make_db(tmp_path)
        # Insert a fresh connection (today)
        db.add_connections_batch([{
            "device_ip": "192.168.1.1",
            "dest_ip": "8.8.8.8",
            "dest_port": 443,
            "protocol": "tcp",
        }])
        assert _count(db, "connections") == 1

        with patch(self._CFG_PATH) as mock_cfg:
            mock_cfg.get.side_effect = lambda *a, **kw: kw.get("default")
            db.cleanup_old_data(days=30)

        assert _count(db, "connections") == 1  # recent row preserved

    def test_cleanup_removes_expired_suppressions(self, tmp_path):
        db = _make_db(tmp_path)
        expired = _old_timestamp(1)
        db.conn.execute(
            "INSERT INTO alert_suppressions (device_ip, expires_at, created_by) VALUES (?, ?, ?)",
            ("192.168.1.50", expired, "admin")
        )
        # Indefinite suppression — must NOT be removed
        db.conn.execute(
            "INSERT INTO alert_suppressions (device_ip, expires_at, created_by) VALUES (?, ?, ?)",
            ("192.168.1.51", None, "admin")
        )
        db.conn.commit()
        assert _count(db, "alert_suppressions") == 2

        with patch(self._CFG_PATH) as mock_cfg:
            mock_cfg.get.side_effect = lambda *a, **kw: kw.get("default")
            db.cleanup_old_data(days=30)

        remaining = db.conn.execute(
            "SELECT device_ip FROM alert_suppressions"
        ).fetchall()
        ips = [r["device_ip"] for r in remaining]
        assert "192.168.1.50" not in ips     # expired → removed
        assert "192.168.1.51" in ips         # indefinite → kept

    def test_vacuum_skipped_when_db_large(self, tmp_path):
        """Cleanup must not raise when the DB is too large for VACUUM."""
        db = _make_db(tmp_path)
        # Patch the vacuum_threshold_mb to 0 so VACUUM is always skipped,
        # regardless of actual DB size — simulates a "large" DB without
        # needing to actually create a multi-MB file.
        def _get_side(*a, **kw):
            if len(a) >= 2 and a[1] == "vacuum_threshold_mb":
                return 0  # threshold = 0 → VACUUM always skipped
            return kw.get("default")

        with patch(self._CFG_PATH) as mock_cfg:
            mock_cfg.get.side_effect = _get_side
            db.cleanup_old_data(days=30)  # must not raise


# ---------------------------------------------------------------------------
# 3. Thread safety
# ---------------------------------------------------------------------------

class TestThreadSafety:

    def test_concurrent_writes_no_corruption(self, tmp_path):
        """N threads each inserting M connections — total count must be exact."""
        db = _make_db(tmp_path)

        N_THREADS = 10
        ROWS_PER_THREAD = 50
        errors = []

        def worker(thread_id: int):
            try:
                for i in range(ROWS_PER_THREAD):
                    db.add_connections_batch([{
                        "device_ip": f"10.0.{thread_id}.{i % 255 + 1}",
                        "dest_ip": "8.8.8.8",
                        "dest_port": 443,
                        "protocol": "tcp",
                    }])
            except Exception as e:
                errors.append(str(e))

        threads = [threading.Thread(target=worker, args=(t,)) for t in range(N_THREADS)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)

        assert not errors, f"Thread errors: {errors}"
        count = _count(db, "connections")
        assert count == N_THREADS * ROWS_PER_THREAD, (
            f"Expected {N_THREADS * ROWS_PER_THREAD} rows, found {count}"
        )

    def test_cleanup_during_writes_no_error(self, tmp_path):
        """cleanup_old_data must not raise sqlite3 errors while writers are active."""
        db = _make_db(tmp_path)
        stop = threading.Event()
        errors = []

        def writer():
            i = 0
            while not stop.is_set():
                try:
                    db.add_connections_batch([{
                        "device_ip": f"10.1.1.{(i % 200) + 1}",
                        "dest_ip": "1.1.1.1",
                        "dest_port": 80,
                        "protocol": "tcp",
                    }])
                    i += 1
                    time.sleep(0.001)
                except Exception as e:
                    errors.append(str(e))

        t = threading.Thread(target=writer, daemon=True)
        t.start()
        time.sleep(0.05)  # let writer get started

        try:
            with patch("config.config_manager.config") as mock_cfg:
                mock_cfg.get.side_effect = lambda *a, **kw: kw.get("default")
                db.cleanup_old_data(days=30)
        finally:
            stop.set()
            t.join(timeout=5)

        assert not errors, f"Writer errors during cleanup: {errors}"

    def test_write_lock_is_reentrant(self, tmp_path):
        """Calling add_device from inside add_connection must not deadlock."""
        db = _make_db(tmp_path)
        # add_connection internally calls add_device via the transaction context;
        # both acquire _write_lock (RLock) — must not deadlock.
        conn_id = db.add_connection(
            "192.168.1.1", "8.8.8.8", 443, "tcp",
            bytes_sent=512, bytes_received=1024
        )
        assert conn_id is not None


# ---------------------------------------------------------------------------
# 4. WAL / VACUUM behaviour
# ---------------------------------------------------------------------------

class TestWalAndVacuum:

    def test_wal_autocheckpoint_pragma_set(self, tmp_path):
        db = _make_db(tmp_path)
        row = db.conn.execute("PRAGMA wal_autocheckpoint").fetchone()
        assert row[0] == 1000

    def test_optimize_database_does_not_raise(self, tmp_path):
        db = _make_db(tmp_path)
        db.optimize_database()  # must not raise

    def test_create_indexes_idempotent(self, tmp_path):
        db = _make_db(tmp_path)
        db.create_indexes()
        db.create_indexes()  # second call must not raise
