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


class TestSelfSignedCert:
    def test_generates_loadable_cert_with_sans(self, tmp_path):
        """The self-signed cert must load into an SSL context and cover the
        requested hostnames + IPs (so https://iotsentinel.local works)."""
        import ssl
        from utils.self_signed_cert import ensure_self_signed_cert
        pair = ensure_self_signed_cert(
            tmp_path / "certs",
            hostnames=["localhost", "iotsentinel.local"],
            ips=["127.0.0.1", "10.42.0.1"],
        )
        assert pair is not None
        cert, key = pair
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)  # raises if cert/key are invalid

    def test_reuses_existing_cert(self, tmp_path):
        """A second call with the same SANs reuses the cert (no churn each boot)."""
        from utils.self_signed_cert import ensure_self_signed_cert
        args = dict(hostnames=["localhost", "iotsentinel.local"], ips=["127.0.0.1"])
        first = ensure_self_signed_cert(tmp_path / "c", **args)
        second = ensure_self_signed_cert(tmp_path / "c", **args)
        assert first == second

    def test_https_serving_wired_with_http_fallback(self):
        """app.py must pass certfile/keyfile to socketio.run when HTTPS is enabled
        and downgrade the Secure cookie flags if cert generation fails."""
        app_src = (Path(__file__).parent.parent / "dashboard" / "app.py").read_text()
        assert "ensure_self_signed_cert" in app_src
        assert "certfile" in app_src and "keyfile" in app_src
        assert "REMEMBER_COOKIE_SECURE'] = False" in app_src, \
            "must downgrade Secure cookies when falling back to HTTP"


class TestHttpsDefaultAndSetup:
    def test_https_enabled_by_default(self):
        """The shipped config serves HTTPS by default so biometrics + PWA work."""
        import json
        cfg = json.loads((Path(__file__).parent.parent / "config" / "default_config.json").read_text())
        assert cfg["security"]["https_enabled"] is True

    def test_setup_messaging_uses_https(self):
        """Setup messaging must point users at https:// (the dashboard is HTTPS)."""
        root = Path(__file__).parent.parent
        hotspot = (root / "scripts" / "setup_hotspot.sh").read_text()
        assert "https://10.42.0.1" in hotspot
        start_here = (root / "docs" / "START_HERE.md").read_text()
        assert "https://iotsentinel.local:8050" in start_here


class TestSshAlwaysEnabled:
    def test_ssh_enabled_in_image_build(self):
        """SSH must be enabled three ways so a headless user is never locked out."""
        build = (Path(__file__).parent.parent / "scripts" / "build_pi_image.sh").read_text()
        assert "systemctl enable ssh" in build
        assert "/boot/firmware/ssh" in build or "/boot/ssh" in build
        setup = (Path(__file__).parent.parent / "scripts" / "setup_pi.sh").read_text()
        assert "systemctl enable ssh" in setup


class TestHttpsRedirect:
    def test_redirector_and_capability_wired(self):
        """An HTTP->HTTPS redirector on :80 must exist, redirect to https, and the
        dashboard unit must grant CAP_NET_BIND_SERVICE so the service user can bind 80."""
        app_src = (Path(__file__).parent.parent / "dashboard" / "app.py").read_text()
        assert "_spawn_https_redirector" in app_src
        assert "307" in app_src and 'f"https://{host}:{target_port}' in app_src
        unit = (Path(__file__).parent.parent / "services" / "iotsentinel-dashboard.service").read_text()
        assert "AmbientCapabilities=CAP_NET_BIND_SERVICE" in unit

    def test_no_capability_bounding_set_breaks_sudo(self):
        """Regression: a CapabilityBoundingSet=CAP_NET_BIND_SERVICE line caps the whole
        process tree to that single capability, stripping sudo of CAP_SETUID/SETGID/
        AUDIT_WRITE. The final wizard step shells out to `sudo -n` (Wi-Fi join, hotspot
        teardown, backend restart); under the restricted bounding set those fail with
        'unable to change to root gid' and 'error initializing audit plugin sudoers_audit',
        so the home-Wi-Fi join and the IoTSentinel-Setup hotspot teardown never happen.
        The ambient grant alone (default full bounding set) keeps the :80 bind working."""
        unit = (Path(__file__).parent.parent / "services" / "iotsentinel-dashboard.service").read_text()
        active = [ln.strip() for ln in unit.splitlines()
                  if ln.strip() and not ln.lstrip().startswith("#")]
        assert not any(ln.startswith("CapabilityBoundingSet=") for ln in active), (
            "CapabilityBoundingSet on the dashboard unit breaks sudo in the setup wizard")

    def test_setup_reach_urls_are_scheme_aware(self):
        """HTTPS-on-LAN is default-on, so the first-boot wizard's reach/handoff URLs must
        not be hardcoded http. The dynamic links derive the scheme from _dashboard_scheme()
        and the static handoff line uses https."""
        cb = (Path(__file__).parent.parent / "dashboard" / "callbacks" / "callbacks_setup.py").read_text()
        assert "_dashboard_scheme" in cb
        assert "f\"http://{addr['mdns']}" not in cb and 'f"http://{addr[\'ip\']}' not in cb
        wiz = (Path(__file__).parent.parent / "dashboard" / "layouts" / "setup_wizard.py").read_text()
        assert "https://iotsentinel.local:8050" in wiz
        assert "http://iotsentinel.local:8050" not in wiz

    def test_no_hardcoded_http_dashboard_url_log(self):
        """The startup 'Dashboard URL' log must be scheme-aware, not hardcoded http."""
        app_src = (Path(__file__).parent.parent / "dashboard" / "app.py").read_text()
        assert 'Dashboard URL: http://{host}' not in app_src

    def test_tls_handshake_noise_is_suppressed(self):
        """Self-signed TLS makes browsers/probes abort handshakes; eventlet would dump
        a traceback per dropped connection. A filter must wrap squelch_exception (which
        prints unconditionally) so the journal is not flooded."""
        app_src = (Path(__file__).parent.parent / "dashboard" / "app.py").read_text()
        assert "_quiet_eventlet_tls_noise" in app_src
        assert "squelch_exception" in app_src and "SSLError" in app_src

    def test_tailscale_funnel_uses_https_insecure_backend(self):
        """Regression: `tailscale funnel --bg <port>` assumes an HTTP backend; since
        rc14 the dashboard serves HTTPS on that port, which returns 502 at the ts.net
        URL. The funnel helper must use `tailscale serve https+insecure://` so Tailscale
        connects to the local HTTPS backend without rejecting the self-signed cert."""
        src = (Path(__file__).parent.parent / "dashboard" / "callbacks" /
               "callbacks_setup.py").read_text()
        assert "https+insecure://" in src, (
            "_enable_tailscale_funnel must use https+insecure:// backend; the old "
            "tailscale funnel --bg <port> shorthand assumes HTTP and returns 502 "
            "when the dashboard serves HTTPS")

    def test_webauthn_cert_error_hint_present(self):
        """Regression: WebAuthn registration throws NotAllowedError with 'TLS certificate
        errors' when the browser does not trust the self-signed cert. The error handler
        must surface a clear message directing the user to the Tailscale ts.net URL which
        has a browser-trusted certificate."""
        src = (Path(__file__).parent.parent / "dashboard" / "callbacks" /
               "callbacks_auth.py").read_text()
        assert "tls certificate" in src.lower() or "certificate error" in src.lower(), (
            "callbacks_auth.py must contain a cert-error hint in the WebAuthn error handler")
        assert ".ts.net" in src, (
            "The WebAuthn cert-error handler must suggest the Tailscale ts.net URL")


class TestTailscaleRelink:
    def test_relink_worker_and_callback_exist(self):
        """A UI re-link path (logout + up) must exist so a Pi deleted from the
        tailnet can be re-added as a fresh device without SSH."""
        import inspect
        from dashboard.callbacks import callbacks_setup as cs
        worker = inspect.getsource(cs._tailscale_relink_worker)
        assert "logout" in worker and "_tailscale_up_worker" in worker
        app_src = (Path(__file__).parent.parent / "dashboard" / "app.py").read_text()
        assert "settings-remote-relink-btn" in app_src

    def test_sudoers_allows_tailscale_logout(self):
        """sudo -n tailscale logout must be permitted (the relink path needs it)."""
        setup = (Path(__file__).parent.parent / "scripts" / "setup_pi.sh").read_text()
        assert "tailscale logout" in setup


class TestWebAuthnRequestOrigin:
    def test_origin_and_rp_id_follow_the_request(self):
        """The ceremony must use the browser's actual host/origin so biometrics
        work on whatever HTTPS URL the user is on (not a fixed env value)."""
        import os
        from unittest.mock import patch
        from flask import Flask
        import utils.webauthn_handler as wh

        app = Flask(__name__)
        with patch.dict(os.environ, {"WEBAUTHN_RP_ID": "", "WEBAUTHN_ORIGIN": "",
                                     "IOTSENTINEL_PUBLIC_URL": ""}):
            with app.test_request_context(
                "/", base_url="https://iotsentinel.local:8050",
                headers={"Origin": "https://iotsentinel.local:8050"},
            ):
                assert wh._effective_rp_id() == "iotsentinel.local"
                assert wh._effective_origin() == "https://iotsentinel.local:8050"

    def test_falls_back_to_env_outside_request(self):
        """Outside a request (no browser), fall back to the configured public URL."""
        import os
        from unittest.mock import patch
        import utils.webauthn_handler as wh
        with patch.dict(os.environ, {"WEBAUTHN_RP_ID": "", "WEBAUTHN_ORIGIN": "",
                                     "IOTSENTINEL_PUBLIC_URL": "https://abc.ts.net"}):
            assert wh._effective_rp_id() == "abc.ts.net"
            assert wh._effective_origin() == "https://abc.ts.net"
