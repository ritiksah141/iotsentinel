#!/usr/bin/env python3
"""
Tests for database connect resilience + boot disk-safety hardening.

These guard the rc12 failure where a full/failing SD card made
`PRAGMA journal_mode = WAL` raise "disk I/O error", which crashed both the
backend and the dashboard at import. systemd's default start-limit then left
the services dead -> the dashboard was permanently unreachable.

Run: pytest tests/test_db_resilience.py -v
"""

import logging
import sqlite3
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from database.db_manager import DatabaseManager, DatabaseError


def _fresh_manager(path):
    """Build a DatabaseManager at a unique path, clearing any singleton cache."""
    normalized = str(Path(path).resolve())
    DatabaseManager._instances.pop(normalized, None)
    return DatabaseManager(str(path))


def _cleanup(path):
    normalized = str(Path(path).resolve())
    inst = DatabaseManager._instances.pop(normalized, None)
    if inst is not None:
        try:
            inst.close()
        except Exception:
            pass


class TestConnectResilience:
    def test_normal_connect_uses_wal(self, tmp_path):
        """Healthy filesystem: WAL is enabled and not degraded."""
        p = tmp_path / "ok.db"
        db = _fresh_manager(p)
        try:
            assert db.journal_mode == "WAL"
            assert db.degraded is False
            mode = db.conn.execute("PRAGMA journal_mode").fetchone()[0]
            assert str(mode).lower() == "wal"
            # connection is usable
            assert db.conn.execute("SELECT 1").fetchone()[0] == 1
        finally:
            _cleanup(p)

    def test_falls_back_to_delete_journal_when_wal_unavailable(self, tmp_path, monkeypatch):
        """If WAL can't be enabled, we degrade to a rollback journal instead of
        crashing -- the app must still come up so the dashboard stays reachable."""
        monkeypatch.setattr(DatabaseManager, "_enable_wal", lambda self: False)
        p = tmp_path / "degraded.db"
        db = _fresh_manager(p)
        try:
            assert db.journal_mode == "DELETE"
            assert db.degraded is True
            # still a working connection
            assert db.conn.execute("SELECT 1").fetchone()[0] == 1
        finally:
            _cleanup(p)

    def test_disk_io_error_on_wal_recovers_via_fallback(self, tmp_path, monkeypatch):
        """Simulate the exact rc12 failure: WAL raises disk I/O error every
        attempt. We must NOT raise -- we open degraded and flag it."""
        def boom(self):
            raise sqlite3.OperationalError("disk I/O error")

        monkeypatch.setattr(DatabaseManager, "_enable_wal", boom)
        p = tmp_path / "ioerr.db"
        db = _fresh_manager(p)
        try:
            assert db.degraded is True
            assert db.journal_mode == "DELETE"
            assert db.conn.execute("SELECT 1").fetchone()[0] == 1
        finally:
            _cleanup(p)

    def test_remove_stale_wal_files(self, tmp_path):
        """Stale -wal/-shm sidecars (from an unclean power-off) are cleared."""
        p = tmp_path / "stale.db"
        db = _fresh_manager(p)
        try:
            wal = Path(str(p) + "-wal")
            shm = Path(str(p) + "-shm")
            wal.write_text("junk")
            shm.write_text("junk")
            db._remove_stale_wal_files()
            assert not wal.exists()
            assert not shm.exists()
        finally:
            _cleanup(p)

    def test_truly_unusable_path_still_raises(self, tmp_path, monkeypatch):
        """If even a bare connect is impossible, we raise DatabaseError so the
        failure is loud (rather than silently returning a broken manager)."""
        def cannot_open(self):
            raise sqlite3.OperationalError("unable to open database file")

        monkeypatch.setattr(DatabaseManager, "_open_connection", cannot_open)
        p = tmp_path / "nope.db"
        normalized = str(Path(p).resolve())
        DatabaseManager._instances.pop(normalized, None)
        with pytest.raises(DatabaseError):
            DatabaseManager(str(p))
        DatabaseManager._instances.pop(normalized, None)


class TestNetDetectHelpers:
    def test_get_default_gateway_parses_proc_route(self, tmp_path, monkeypatch):
        """get_default_gateway() decodes the little-endian hex gateway from a
        /proc/net/route-style table (default route = destination 00000000)."""
        import utils.net_detect as nd

        # Gateway 192.168.0.1 -> little-endian hex 0100A8C0
        route = (
            "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n"
            "wlan0\t00000000\t0100A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n"
            "wlan0\t0000A8C0\t00000000\t0001\t0\t0\t600\t00FFFFFF\t0\t0\t0\n"
        )
        fake = tmp_path / "route"
        fake.write_text(route)
        real_open = open  # capture before patching to avoid infinite recursion
        monkeypatch.setattr("builtins.open", lambda *a, **k: real_open(fake))
        assert nd.get_default_gateway() == "192.168.0.1"

    def test_get_default_gateway_returns_none_on_error(self, monkeypatch):
        import utils.net_detect as nd

        def boom(*a, **k):
            raise OSError("no /proc here")

        monkeypatch.setattr("builtins.open", boom)
        assert nd.get_default_gateway() is None


class TestInfrastructureSeeding:
    def test_seeded_devices_count_as_online(self, db):
        """Seeding the gateway + host marks them online in the 30-min window so
        the dashboard never shows 0/N at first boot."""
        db.add_device("192.168.0.1", device_name="Router / Gateway", device_type="router")
        db.add_device("192.168.0.50", device_name="IoTSentinel (this device)",
                      device_type="raspberry_pi")
        cur = db.conn.cursor()
        cur.execute("SELECT COUNT(*) FROM devices WHERE last_seen > datetime('now','-30 minutes')")
        assert cur.fetchone()[0] == 2


class TestLogRotation:
    def test_security_audit_logger_rotates(self):
        import utils.security_audit_logger as s
        handlers = s.security_audit_file_logger.handlers
        assert any(isinstance(h, RotatingFileHandler) for h in handlers), \
            "security audit log must rotate so it cannot fill the SD card"

    def test_dashboard_loggers_rotate(self):
        # importing shared configures the rotating handlers
        import dashboard.shared  # noqa: F401
        for name in ("audit", "ml", "alerts", "database", "errors", "api"):
            handlers = logging.getLogger(name).handlers
            if handlers:  # the logger is configured at import
                assert any(isinstance(h, RotatingFileHandler) for h in handlers), \
                    f"logger {name!r} must use a RotatingFileHandler"


class TestSystemdHardening:
    @pytest.mark.parametrize("svc", [
        "iotsentinel-dashboard.service",
        "iotsentinel-backend.service",
    ])
    def test_start_limit_disabled(self, svc):
        """Units must disable the start-limit so a transient disk hiccup cannot
        permanently brick the service (the rc12 'restart counter is at 6' death)."""
        text = (Path(__file__).parent.parent / "services" / svc).read_text()
        active = [ln for ln in text.splitlines() if not ln.strip().startswith("#")]
        assert any("StartLimitIntervalSec=0" in ln for ln in active)
        # No ACTIVE MemoryMax directive: cgroup memory is disabled on the Pi 5
        # kernel cmdline, so a MemoryMax= would be a silent no-op. (A comment
        # explaining this is fine; an actual directive is not.)
        assert not any(ln.strip().startswith("MemoryMax") for ln in active)


class TestImageDiskSafety:
    def test_journald_capped_in_image_build(self):
        text = (Path(__file__).parent.parent / "scripts" / "build_pi_image.sh").read_text()
        assert "SystemMaxUse" in text and "journald.conf.d" in text

    def test_journald_capped_in_setup(self):
        text = (Path(__file__).parent.parent / "scripts" / "setup_pi.sh").read_text()
        assert "SystemMaxUse" in text and "journald.conf.d" in text
