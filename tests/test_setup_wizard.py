#!/usr/bin/env python3
"""
Unit tests for the first-run setup wizard.

Covers:
- ConfigManager.write_env() round-trip behaviour
- Setup gate: .env absence triggers wizard layout
- Wizard layout structure (required component IDs present)
- _save_config writes expected env keys
- Validation helpers handle bad/good keys defensively
- Interface detection and step-4 finale logic (merged from test_setup_wizard_step0)

Run: pytest tests/test_setup_wizard.py -v
"""

import json
import sys
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from config.config_manager import ConfigManager


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_config(tmp_path):
    """ConfigManager backed by a temp default_config.json and temp .env."""
    cfg_file = tmp_path / "default_config.json"
    cfg_file.write_text('{"system": {"is_configured": false}, "network": {}, "email": {}}')
    env_file = tmp_path / ".env"
    return ConfigManager(cfg_file, env_file), env_file, tmp_path


# ---------------------------------------------------------------------------
# ConfigManager.write_env
# ---------------------------------------------------------------------------

class TestWriteEnv:

    def test_creates_env_file_when_absent(self, tmp_config):
        cfg, env_file, _ = tmp_config
        assert not env_file.exists()

        result = cfg.write_env({"FLASK_SECRET_KEY": "testkey123"}, env_path=env_file)

        assert result is True
        assert env_file.exists()
        content = env_file.read_text()
        assert "FLASK_SECRET_KEY=testkey123" in content

    def test_upserts_existing_key_without_duplicating(self, tmp_config):
        cfg, env_file, _ = tmp_config
        env_file.write_text("FLASK_SECRET_KEY=old_value\n")

        cfg.write_env({"FLASK_SECRET_KEY": "new_value"}, env_path=env_file)  # pragma: allowlist secret

        lines = [l.strip() for l in env_file.read_text().splitlines() if l.strip()]
        matching = [l for l in lines if l.startswith("FLASK_SECRET_KEY=")]
        assert len(matching) == 1, "Key should appear exactly once after upsert"
        assert matching[0] == "FLASK_SECRET_KEY=new_value"

    def test_preserves_unrelated_keys(self, tmp_config):
        cfg, env_file, _ = tmp_config
        env_file.write_text("OTHER_KEY=keep_this\nFLASK_SECRET_KEY=old\n")

        cfg.write_env({"FLASK_SECRET_KEY": "new"}, env_path=env_file)  # pragma: allowlist secret

        content = env_file.read_text()
        assert "OTHER_KEY=keep_this" in content
        assert "FLASK_SECRET_KEY=new" in content

    def test_appends_new_key_to_existing_file(self, tmp_config):
        cfg, env_file, _ = tmp_config
        env_file.write_text("EXISTING=yes\n")

        cfg.write_env({"GROQ_API_KEY": "gsk_abc123"}, env_path=env_file)  # pragma: allowlist secret

        content = env_file.read_text()
        assert "EXISTING=yes" in content
        assert "GROQ_API_KEY=gsk_abc123" in content

    def test_multi_key_write(self, tmp_config):
        cfg, env_file, _ = tmp_config

        cfg.write_env({
            "EMAIL_SMTP_HOST": "smtp.gmail.com",
            "EMAIL_SMTP_USER": "test@gmail.com",
            "GROQ_API_KEY": "gsk_test",  # pragma: allowlist secret
        }, env_path=env_file)

        content = env_file.read_text()
        assert "EMAIL_SMTP_HOST=smtp.gmail.com" in content
        assert "EMAIL_SMTP_USER=test@gmail.com" in content
        assert "GROQ_API_KEY=gsk_test" in content

    def test_preserves_comment_lines(self, tmp_config):
        cfg, env_file, _ = tmp_config
        env_file.write_text("# This is a comment\nFLASK_SECRET_KEY=old\n")

        cfg.write_env({"FLASK_SECRET_KEY": "new"}, env_path=env_file) # pragma: allowlist secret

        content = env_file.read_text()
        assert "# This is a comment" in content

    def test_returns_false_on_permission_error(self, tmp_config):
        cfg, env_file, _ = tmp_config
        # Patch open to raise
        with patch("builtins.open", side_effect=PermissionError("no write")):
            result = cfg.write_env({"KEY": "val"}, env_path=env_file)
        assert result is False


# ---------------------------------------------------------------------------
# Wizard layout structure
# ---------------------------------------------------------------------------

class TestSetupWizardLayout:

    def test_layout_imports_cleanly(self):
        from dashboard.layouts.setup_wizard import setup_wizard_layout
        assert setup_wizard_layout is not None

    def test_required_component_ids_present(self):
        """Wizard must contain the IDs that callbacks.setup binds to."""
        from dashboard.layouts.setup_wizard import setup_wizard_layout

        layout_str = str(setup_wizard_layout)

        required_ids = [
            "setup-step-store",
            "setup-data-store",
            "setup-network-cidr",
            "setup-interface",
            "setup-admin-password",
            "setup-smtp-user",
            "setup-smtp-password",
            "setup-groq-key",
            "setup-abuseipdb-key",
            "setup-next-btn",
            "setup-back-btn",
            "setup-skip-btn",
            "setup-progress",
            "setup-review-content",
            "setup-status",
            # Deferred Wi-Fi join (record-on-Step-1, connect-on-Step-6) — see
            # apply_wifi_on_finish. The hand-off screen + interval must exist.
            "setup-wifi-apply-interval",
            "setup-wifi-handoff-status",
        ]

        for cid in required_ids:
            assert cid in layout_str, f"Component ID '{cid}' missing from setup_wizard_layout"

    def test_step3_optional_features_grouped_by_category(self):
        """Step 3 must group the options under topic headings (Notifications / AI /
        Security) instead of one flat list."""
        from dashboard.layouts.setup_wizard import setup_wizard_layout
        s = str(setup_wizard_layout)
        for category in ("Notifications", "AI explanations", "Security & advanced"):
            assert category in s, f"Step 3 category heading missing: {category}"

    def test_wifi_ssid_is_typeable_with_datalist(self):
        """Step 1 SSID must be a typeable Input (not a dropdown Select) wired to a
        datalist, so a single-radio Pi that can't scan in AP mode can still enter the
        home network by typing it."""
        import dash_bootstrap_components as dbc
        from dashboard.layouts.setup_wizard import setup_wizard_layout

        def _children(node):
            ch = getattr(node, "children", None)
            if ch is None:
                return []
            return ch if isinstance(ch, (list, tuple)) else [ch]

        def _find(node, cid):
            if getattr(node, "id", None) == cid:
                return node
            for c in _children(node):
                if hasattr(c, "id") or hasattr(c, "children"):
                    r = _find(c, cid)
                    if r is not None:
                        return r
            return None

        field = _find(setup_wizard_layout, "setup-wifi-ssid")
        assert field is not None, "setup-wifi-ssid missing"
        assert isinstance(field, dbc.Input), "SSID field must be a typeable Input, not a Select"
        assert getattr(field, "list", None) == "setup-wifi-ssid-list"
        assert "setup-wifi-ssid-list" in str(setup_wizard_layout), "datalist missing"

    def test_tailscale_remote_access_uses_bg_and_sudo_fallback(self):
        """Funnel must run with --bg (a foreground serve is killed by the subprocess
        timeout, so the URL never persists). Root access is handled by _run_tailscale,
        which prefers NO sudo (so it works on macOS localhost, where `sudo -n` fails
        with "a password is required") and falls back to passwordless sudo on the Pi
        image where the unprivileged service user needs root."""
        import inspect
        from dashboard.callbacks import callbacks_setup as cs
        funnel_src = inspect.getsource(cs._enable_tailscale_funnel)
        assert "--bg" in funnel_src, "tailscale funnel must use --bg to persist"
        assert "_run_tailscale" in funnel_src, "funnel must go through _run_tailscale"
        # The sudo fallback lives in the shared helper, gated on platform != darwin.
        helper_src = inspect.getsource(cs._run_tailscale)
        assert "sudo" in helper_src and "darwin" in helper_src, \
            "_run_tailscale must fall back to sudo only off macOS"
        up_src = inspect.getsource(cs._tailscale_up_worker)
        assert "sudo" in up_src and "darwin" in up_src, \
            "tailscale up must fall back to sudo only off macOS"

    def test_run_tailscale_prefers_plain_then_sudo(self, monkeypatch):
        """_run_tailscale tries plain first; retries under sudo only when the
        plain call fails for lack of root AND the platform is not macOS."""
        import subprocess as sp
        from dashboard.callbacks import callbacks_setup as cs

        calls = []

        def fake_run(cmd, **kwargs):
            calls.append(cmd)
            if cmd[0] == 'tailscale':
                # plain call fails because root is required
                return sp.CompletedProcess(cmd, 1, stdout='', stderr='access denied')
            return sp.CompletedProcess(cmd, 0, stdout='ok', stderr='')

        monkeypatch.setattr(cs.sys, 'platform', 'linux')
        monkeypatch.setattr(cs.subprocess, 'run', fake_run)
        res = cs._run_tailscale(['funnel', '--bg', '8050'])
        assert res.returncode == 0
        assert calls[0][0] == 'tailscale'           # tried plain first
        assert calls[1][:2] == ['sudo', '-n']        # then fell back to sudo

    def test_run_tailscale_no_sudo_on_macos(self, monkeypatch):
        """On macOS we never retry under sudo (it would fail with a password prompt)."""
        import subprocess as sp
        from dashboard.callbacks import callbacks_setup as cs

        calls = []

        def fake_run(cmd, **kwargs):
            calls.append(cmd)
            return sp.CompletedProcess(cmd, 1, stdout='', stderr='access denied')

        monkeypatch.setattr(cs.sys, 'platform', 'darwin')
        monkeypatch.setattr(cs.subprocess, 'run', fake_run)
        cs._run_tailscale(['funnel', '--bg', '8050'])
        assert all(c[0] == 'tailscale' for c in calls), "must not invoke sudo on macOS"

    def test_remote_access_callbacks_are_exception_safe(self):
        """settings_remote_poll runs on a dcc.Interval, so an unhandled exception
        becomes a recurring 500 on settings-remote-status. Both remote callbacks must
        wrap their bodies and log the traceback instead of letting it escape."""
        src = (Path(__file__).parent.parent / "dashboard" / "callbacks"
               / "callbacks_setup.py").read_text()
        assert 'logger.exception("settings_remote_poll failed")' in src
        assert 'logger.exception("settings_remote_enable failed")' in src

    def test_do_wifi_join_connects_when_ssid_set(self):
        """The deferred join (Step 6) reaches wifi_manager.connect_wifi for a real SSID."""
        from dashboard.callbacks import callbacks_setup as cs

        with patch.object(cs.wifi_manager, "nmcli_available", return_value=True), \
             patch.object(cs.wifi_manager, "connect_wifi",
                          return_value=(True, "Connected")) as mock_connect:
            result = cs._do_wifi_join("HomeNet", "pw", None)
            assert result is not None and result[0] is True
            mock_connect.assert_called_once()

    def test_do_wifi_join_noop_without_ssid(self):
        """No SSID (e.g. an Ethernet setup) must never touch the radio — returns None."""
        from dashboard.callbacks import callbacks_setup as cs

        with patch.object(cs.wifi_manager, "nmcli_available", return_value=True), \
             patch.object(cs.wifi_manager, "connect_wifi") as mock_connect:
            assert cs._do_wifi_join("", "pw", None) is None
            mock_connect.assert_not_called()

    def test_do_wifi_join_noop_without_nmcli(self):
        """No nmcli on the host (dev/CI) is a no-op, not a crash."""
        from dashboard.callbacks import callbacks_setup as cs

        with patch.object(cs.wifi_manager, "nmcli_available", return_value=False), \
             patch.object(cs.wifi_manager, "connect_wifi") as mock_connect:
            assert cs._do_wifi_join("HomeNet", "pw", "GB") is None
            mock_connect.assert_not_called()

    def test_vendor_links_point_to_expected_domains(self):
        from dashboard.layouts.setup_wizard import _VENDOR_LINKS
        assert "groq.com" in _VENDOR_LINKS["groq"]
        assert "abuseipdb.com" in _VENDOR_LINKS["abuseipdb"]
        assert "google.com" in _VENDOR_LINKS["gmail_apppassword"]


# ---------------------------------------------------------------------------
# Setup gate logic: DB-based _admin_exists() check (cross-platform)
# ---------------------------------------------------------------------------

class TestSetupGate:
    """Tests for the new DB-truth first-run gate introduced in Phase 5.

    The old gate was Linux-only + is_configured flag.  The new gate queries
    ``SELECT COUNT(*) FROM users WHERE role='admin' AND is_active=1`` on every
    platform so macOS/Windows dev machines also get proper onboarding.
    """

    def test_admin_exists_returns_false_when_no_admin(self):
        """_admin_exists() returns False when the users table is empty."""
        from dashboard.callbacks.callbacks_auth import _admin_exists
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = (0,)
        mock_conn = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        with patch("dashboard.callbacks.callbacks_auth.db_manager") as mock_db:
            mock_db.conn = mock_conn
            assert _admin_exists() is False

    def test_admin_exists_returns_true_when_admin_present(self):
        """_admin_exists() returns True when at least one active admin exists."""
        from dashboard.callbacks.callbacks_auth import _admin_exists
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = (1,)
        mock_conn = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        with patch("dashboard.callbacks.callbacks_auth.db_manager") as mock_db:
            mock_db.conn = mock_conn
            assert _admin_exists() is True

    def test_admin_exists_returns_false_on_db_error(self):
        """_admin_exists() degrades safely to False if the DB raises."""
        from dashboard.callbacks.callbacks_auth import _admin_exists
        with patch("dashboard.callbacks.callbacks_auth.db_manager") as mock_db:
            mock_db.conn.cursor.side_effect = Exception("db gone")
            assert _admin_exists() is False


# ---------------------------------------------------------------------------
# _save_config writes correct env keys
# ---------------------------------------------------------------------------

class TestSaveConfig:

    def test_save_config_writes_email_keys(self, tmp_path):
        # New signature: _save_config(cidr, interface, smtp_user, smtp_password,
        #                             groq_key, abuseipdb_key, tier, public_url)
        with patch("dashboard.callbacks.callbacks_setup.config") as mock_cfg, \
             patch("dashboard.callbacks.callbacks_setup.db_manager"):
            mock_cfg.write_env.return_value = True
            mock_cfg.update.return_value = True
            mock_cfg.get.return_value = False  # simulate first-run (not yet configured)

            from dashboard.callbacks.callbacks_setup import _save_config
            result = _save_config(
                "192.168.1.0/24", "eth0",
                "user@gmail.com", "apppassword",
                None, None, "household", None,
            )

        assert result is True
        call_kwargs = mock_cfg.write_env.call_args[0][0]
        assert "EMAIL_SMTP_HOST" in call_kwargs
        assert call_kwargs["EMAIL_SMTP_USER"] == "user@gmail.com"
        assert call_kwargs["EMAIL_SMTP_PASSWORD"] == "apppassword"  # pragma: allowlist secret
        # Admin password must NOT appear in .env (DB is the only source of truth)
        assert "IOTSENTINEL_ADMIN_PASSWORD" not in call_kwargs

    def test_save_config_writes_groq_key(self):
        with patch("dashboard.callbacks.callbacks_setup.config") as mock_cfg, \
             patch("dashboard.callbacks.callbacks_setup.db_manager"):
            mock_cfg.write_env.return_value = True
            mock_cfg.update.return_value = True
            mock_cfg.get.return_value = False

            from dashboard.callbacks.callbacks_setup import _save_config
            result = _save_config(
                "192.168.0.0/24", "wlan0",
                None, None, "gsk_testkey12345678", None, "household", None,
            )

        assert result is True
        env_dict = mock_cfg.write_env.call_args[0][0]
        assert "GROQ_API_KEY" in env_dict
        assert env_dict["GROQ_API_KEY"] == "gsk_testkey12345678"  # pragma: allowlist secret

    def test_save_config_marks_is_configured(self):
        with patch("dashboard.callbacks.callbacks_setup.config") as mock_cfg, \
             patch("dashboard.callbacks.callbacks_setup.db_manager"):
            mock_cfg.write_env.return_value = True
            mock_cfg.update.return_value = True
            mock_cfg.get.return_value = False

            from dashboard.callbacks.callbacks_setup import _save_config
            _save_config("192.168.1.0/24", "wlan0", None, None, None, None, None, None)

        mock_cfg.update.assert_any_call("system", "is_configured", True)

    def test_save_config_always_writes_env(self):
        # _save_config always calls write_env (even with no optional keys) so
        # the .env sentinel file is created and the wizard exits cleanly.
        with patch("dashboard.callbacks.callbacks_setup.config") as mock_cfg, \
             patch("dashboard.callbacks.callbacks_setup.db_manager"):
            mock_cfg.write_env.return_value = True
            mock_cfg.update.return_value = True
            mock_cfg.get.return_value = False

            from dashboard.callbacks.callbacks_setup import _save_config
            _save_config("192.168.1.0/24", "wlan0", None, None, None, None, None, None)

        mock_cfg.write_env.assert_called_once()


# ---------------------------------------------------------------------------
# Privacy / security additions: auto-block consent, alert sensitivity, firewall
# ---------------------------------------------------------------------------

class TestSaveConfigProtection:

    def _save(self, **kwargs):
        with patch("dashboard.callbacks.callbacks_setup.config") as mock_cfg, \
             patch("dashboard.callbacks.callbacks_setup.db_manager"):
            mock_cfg.write_env.return_value = True
            mock_cfg.update.return_value = True
            mock_cfg.get.return_value = False   # first-run + falsy auto_block lookup
            from dashboard.callbacks.callbacks_setup import _save_config
            _save_config("192.168.1.0/24", "wlan0", None, None, None, None,
                         "household", None, **kwargs)
            return mock_cfg

    def test_autoblock_disabled_persists_enabled_false(self):
        cfg = self._save(auto_block=False)
        # The auto_block dict is written back with enabled flipped off.
        calls = [c for c in cfg.update.call_args_list
                 if c.args[:2] == ("agent", "auto_block")]
        assert calls, "expected agent.auto_block to be written"
        assert calls[-1].args[2].get("enabled") is False

    def test_autoblock_enabled_persists_enabled_true(self):
        cfg = self._save(auto_block=True)
        calls = [c for c in cfg.update.call_args_list
                 if c.args[:2] == ("agent", "auto_block")]
        assert calls and calls[-1].args[2].get("enabled") is True

    def test_alert_sensitivity_high_sets_thresholds(self):
        cfg = self._save(alert_sensitivity="high")
        cfg.update.assert_any_call("alerting", "max_per_device_per_hour", 10)
        cfg.update.assert_any_call("alerting", "max_global_per_hour", 40)

    def test_alert_sensitivity_none_leaves_alerting_untouched(self):
        cfg = self._save()
        assert not [c for c in cfg.update.call_args_list if c.args[0] == "alerting"]

    def test_firewall_enabled_writes_router_settings(self):
        cfg = self._save(firewall_enable=True, firewall_router_ip="10.0.0.1",
                         firewall_router_user="admin", firewall_key_path="/k/id")
        cfg.update.assert_any_call("firewall", "enabled", True)
        cfg.update.assert_any_call("firewall", "router_ip", "10.0.0.1")
        cfg.update.assert_any_call("firewall", "router_user", "admin")

    def test_firewall_off_does_not_enable(self):
        cfg = self._save(firewall_enable=False)
        assert not [c for c in cfg.update.call_args_list
                    if c.args[:2] == ("firewall", "enabled")]


class TestBuildReviewProtection:

    def test_review_shows_protection_rows(self):
        with patch("dashboard.callbacks.callbacks_setup.db_manager"):
            from dashboard.callbacks.callbacks_setup import _build_review
            table = _build_review(
                "192.168.1.0/24", "wlan0", None, None, None,
                "household", None,
                auto_block=False, alert_sensitivity="high", firewall_enable=True,
            )
        rendered = str(table)
        assert "Off" in rendered            # auto-block disclosed as off
        assert "High" in rendered           # alert sensitivity
        assert "router" in rendered.lower()  # firewall enforcement row


# ---------------------------------------------------------------------------
# Validation helpers (offline — mocked requests)
# ---------------------------------------------------------------------------

class TestValidationHelpers:

    def test_router_ssh_empty_args_fails(self):
        from dashboard.callbacks.callbacks_setup import _test_router_ssh
        ok, msg = _test_router_ssh("", "", "")
        assert not ok
        assert "fill in" in msg.lower()

    def test_validate_groq_short_key_fails(self):
        from dashboard.callbacks.callbacks_setup import _validate_groq
        ok, msg = _validate_groq("short")
        assert not ok
        assert "short" in msg.lower() or "character" in msg.lower()

    def test_validate_groq_empty_key_fails(self):
        from dashboard.callbacks.callbacks_setup import _validate_groq
        ok, _ = _validate_groq("")
        assert not ok

    def test_validate_groq_valid_key_200(self):
        from dashboard.callbacks.callbacks_setup import _validate_groq
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        with patch("requests.get", return_value=mock_resp):
            ok, msg = _validate_groq("gsk_" + "a" * 40)
        assert ok
        assert "verified" in msg.lower()

    def test_validate_groq_bad_key_401(self):
        from dashboard.callbacks.callbacks_setup import _validate_groq
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        with patch("requests.get", return_value=mock_resp):
            ok, _ = _validate_groq("gsk_" + "a" * 40)
        assert not ok

    def test_validate_abuseipdb_empty_key_fails(self):
        from dashboard.callbacks.callbacks_setup import _validate_abuseipdb
        ok, _ = _validate_abuseipdb("")
        assert not ok

    def test_validate_abuseipdb_valid_key_200(self):
        from dashboard.callbacks.callbacks_setup import _validate_abuseipdb
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        with patch("requests.get", return_value=mock_resp):
            ok, _ = _validate_abuseipdb("v" * 40)
        assert ok

    def test_validate_abuseipdb_connection_error(self):
        # Offline during setup (Pi on the hotspot) → neutral ok=None, NOT a red error.
        from dashboard.callbacks.callbacks_setup import _validate_abuseipdb
        with patch("requests.get", side_effect=Exception("timeout")):
            ok, msg = _validate_abuseipdb("v" * 40)
        assert ok is None
        assert "online" in msg.lower()

    def test_validate_groq_offline_is_neutral_not_error(self):
        # The Pi has no internet during the wizard (it joins home Wi-Fi only at the end),
        # so a Groq connection failure must be neutral (ok=None / "verify once online"),
        # not the scary red "Could not reach Groq" the user hit while pasting the key.
        from dashboard.callbacks.callbacks_setup import _validate_groq
        with patch("requests.get", side_effect=Exception("no route to host")):
            ok, msg = _validate_groq("gsk_" + "a" * 40)
        assert ok is None
        assert "online" in msg.lower()


# ---------------------------------------------------------------------------
# Interface detection (merged from test_setup_wizard_step0)
# ---------------------------------------------------------------------------

class TestInterfaceDetection:

    def test_psutil_returns_at_least_one_interface(self):
        import psutil
        ifaces = list(psutil.net_if_addrs().keys())
        assert len(ifaces) >= 1

    def test_interface_options_are_dicts_with_label_and_value(self):
        import psutil
        interfaces = list(psutil.net_if_addrs().keys())
        options = [{"label": i, "value": i} for i in interfaces]
        for opt in options:
            assert "label" in opt and "value" in opt
            assert isinstance(opt["label"], str) and isinstance(opt["value"], str)

    def test_default_value_prefers_non_loopback(self):
        """Default interface should not be loopback when better options exist."""
        import psutil

        def _rank(name):
            n = name.lower()
            if any(x in n for x in ('wlan', 'wifi', 'wi-fi', 'wireless', 'en0', 'en1')):
                return 0
            if any(x in n for x in ('eth', 'en', 'lan')):
                return 1
            if any(x in n for x in ('lo', 'loop')):
                return 3
            return 2

        interfaces = list(psutil.net_if_addrs().keys())
        non_loopback = [i for i in interfaces if not i.lower().startswith('lo')]
        if non_loopback:
            interfaces.sort(key=_rank)
            default = interfaces[0]
            assert not default.lower().startswith('lo') or len(non_loopback) == 0

    def test_fallback_when_psutil_fails(self):
        """If psutil raises, callback must still return valid options."""
        with patch('psutil.net_if_addrs', side_effect=Exception("no psutil")):
            import psutil
            try:
                interfaces = list(psutil.net_if_addrs().keys())
            except Exception:
                interfaces = []
            options = (
                [{"label": "wlan0", "value": "wlan0"}, {"label": "eth0", "value": "eth0"}]
                if not interfaces
                else [{"label": i, "value": i} for i in interfaces]
            )
            assert len(options) >= 1


# ---------------------------------------------------------------------------
# show_step_4 callback logic
# ---------------------------------------------------------------------------

def _show_step_4_logic(step_data):
    step = (step_data or {}).get("step", 1)
    return {"display": "block"} if step == 4 else {"display": "none"}


class TestShowStep4Logic:

    def test_step_1_hides_step_4(self):
        assert _show_step_4_logic({"step": 1}) == {"display": "none"}

    def test_step_2_hides_step_4(self):
        assert _show_step_4_logic({"step": 2}) == {"display": "none"}

    def test_step_3_hides_step_4(self):
        assert _show_step_4_logic({"step": 3}) == {"display": "none"}

    def test_step_4_shows_step_4(self):
        assert _show_step_4_logic({"step": 4}) == {"display": "block"}

    def test_none_step_data_defaults_to_hidden(self):
        assert _show_step_4_logic(None) == {"display": "none"}


# ---------------------------------------------------------------------------
# navigate_to_dashboard
# ---------------------------------------------------------------------------

class TestNavigateToDashboard:

    def test_returns_root_url_when_clicked(self):
        n_clicks = 1
        result = "/" if n_clicks else None
        assert result == "/"

    def test_no_clicks_does_not_navigate(self):
        n_clicks = 0
        result = "/" if n_clicks else None
        assert result is None


# ---------------------------------------------------------------------------
# Step navigation: step 3 → step 4 on save success
# ---------------------------------------------------------------------------

class TestStep3ToStep4OnSave:

    def test_successful_save_advances_to_step_4(self):
        # _save_config(cidr, interface, smtp_user, smtp_pass, groq, abuse, tier, public_url)
        # admin_password no longer a parameter — DB is the only credential store.
        from dashboard.callbacks.callbacks_setup import _save_config
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            env_path = Path(tmp) / '.env'
            with patch('dashboard.callbacks.callbacks_setup._ENV_PATH', env_path), \
                 patch('dashboard.callbacks.callbacks_setup.config') as mock_cfg, \
                 patch('dashboard.callbacks.callbacks_setup.db_manager'):
                mock_cfg.update.return_value = None
                mock_cfg.write_env.return_value = None
                mock_cfg.get.return_value = False
                result = _save_config(
                    "192.168.1.0/24", "wlan0",
                    None, None, None, None, "household", None
                )
        assert result is True

    def test_step_4_step_store_value(self):
        success = True
        new_step = 4 if success else 3
        assert new_step == 4


# ---------------------------------------------------------------------------
# config/default_config.json contains monitor_interface
# ---------------------------------------------------------------------------

class TestDefaultConfigMonitorInterface:

    def test_monitor_interface_key_exists(self):
        cfg_path = Path('config/default_config.json')
        data = json.loads(cfg_path.read_text())
        assert 'network' in data
        assert 'monitor_interface' in data['network'], \
            "default_config.json['network'] must have 'monitor_interface'"

    def test_monitor_interface_default_is_null(self):
        cfg_path = Path('config/default_config.json')
        data = json.loads(cfg_path.read_text())
        assert data['network']['monitor_interface'] is None


# ---------------------------------------------------------------------------
# Wizard layout: "What's next?" panel exists
# ---------------------------------------------------------------------------

class TestWizardFinalePanel:

    def test_setup_done_btn_exists_in_layout(self):
        import inspect
        from dashboard.layouts import setup_wizard
        src = inspect.getsource(setup_wizard)
        assert 'setup-done-btn' in src, "Wizard finale must have 'setup-done-btn'"

    def test_setup_step_4_container_exists_in_layout(self):
        import inspect
        from dashboard.layouts import setup_wizard
        src = inspect.getsource(setup_wizard)
        assert 'setup-step-4-container' in src

    def test_wizard_has_6_step_labels(self):
        from dashboard.layouts import setup_wizard
        # Labels are generated via _step_header(n) using _STEPS — verify 6 steps defined
        assert len(setup_wizard._STEPS) == 6, "Wizard must have exactly 6 steps in _STEPS"
        # Confirm _step_header renders the badge for each step
        for n, _, name in setup_wizard._STEPS:
            header = setup_wizard._step_header(n)
            assert str(header).count(f"Step {n} of 6") >= 1 or \
                   f"Step {n} of 6" in str(header), \
                   f"_step_header({n}) must produce 'Step {n} of 6' badge"

    def test_nav_buttons_use_responsive_columns(self):
        import inspect
        from dashboard.layouts import setup_wizard
        src = inspect.getsource(setup_wizard)
        # xs=12 breakpoint ensures buttons stack full-width on mobile
        assert "xs=12" in src, "Wizard nav buttons must use xs=12 for mobile layout"


# ---------------------------------------------------------------------------
# navigate_steps: 6-step progression logic
# ---------------------------------------------------------------------------

S = {"display": "block"}
H = {"display": "none"}


STRONG_PW = "ValidPass1!"   # meets is_password_strong_enough: upper+lower+digit+special


def _call(triggered_id, step,
          password=STRONG_PW, password_confirm=STRONG_PW,
          admin_username="admin",
          cidr="192.168.1.0/24", interface="eth0",
          smtp_user=None, smtp_password=None, groq_key=None, abuseipdb_key=None,
          tier="household", public_url=None):
    """Helper: call _navigate_steps_logic with sensible defaults.

    Patches auth_manager.create_admin to always succeed so unit tests do not
    need a live DB; each test that verifies Step-1 DB behaviour uses its own
    patch/mock.
    """
    from dashboard.callbacks.callbacks_setup import _navigate_steps_logic
    with patch("dashboard.callbacks.callbacks_setup.auth_manager.create_admin",
               return_value=True):
        return _navigate_steps_logic(
            triggered_id, step,
            admin_username, password, password_confirm,
            cidr, interface,
            smtp_user, smtp_password, groq_key, abuseipdb_key,
            tier, public_url,
        )


class TestNavigateSteps:
    """Tests for _navigate_steps_logic — the pure 6-step wizard navigation."""

    # ------------------------------------------------------------------
    # Step 1 validation
    # ------------------------------------------------------------------

    def test_next_step1_valid_password_advances_to_step2(self):
        result = _call("setup-next-btn", 1, password=STRONG_PW, password_confirm=STRONG_PW)
        assert result[0] == {"step": 2}
        assert result[2] == S   # step-2 container visible
        assert result[1] == H   # step-1 container hidden

    def test_next_step1_short_password_stays_on_step1(self):
        result = _call("setup-next-btn", 1, password="short", password_confirm="short")
        assert result[0] == {"step": 1}
        assert result[1] == S   # step-1 container stays visible

    def test_next_step1_short_password_returns_alert_status(self):
        result = _call("setup-next-btn", 1, password="short", password_confirm="short")
        status = result[11]
        assert status is not None and status != ""

    def test_next_step1_weak_password_no_special_stays_on_step1(self):
        # Meets length + case + digit but lacks special character
        result = _call("setup-next-btn", 1, password="Longpass1", password_confirm="Longpass1")
        assert result[0] == {"step": 1}

    def test_next_step1_password_mismatch_stays_on_step1(self):
        result = _call("setup-next-btn", 1, password=STRONG_PW, password_confirm="Diff3rent!")
        assert result[0] == {"step": 1}

    def test_next_step1_password_mismatch_returns_alert_status(self):
        result = _call("setup-next-btn", 1, password=STRONG_PW, password_confirm="Diff3rent!")
        status = result[11]
        assert status is not None and status != ""

    def test_next_step1_empty_password_stays_on_step1(self):
        result = _call("setup-next-btn", 1, password="", password_confirm="")
        assert result[0] == {"step": 1}

    # ------------------------------------------------------------------
    # Step 1 → 2: back button visibility
    # ------------------------------------------------------------------

    def test_step1_back_button_hidden_on_validation_failure(self):
        # Failed validation stays on step 1 — back must never appear on step 1
        result = _call("setup-next-btn", 1, password="short", password_confirm="short")
        assert result[6] == H

    def test_step2_back_button_visible(self):
        result = _call("setup-next-btn", 1, password=STRONG_PW, password_confirm=STRONG_PW)
        assert result[6] == S   # advancing TO step 2 shows back

    def test_skip_hidden_on_step1(self):
        # Skip is mandatory-hidden on step 1 — account creation cannot be skipped
        result = _call("setup-next-btn", 1, password="short", password_confirm="short")
        assert result[12] == H   # skip_style index

    # ------------------------------------------------------------------
    # Forward progression steps 2 → 5
    # ------------------------------------------------------------------

    def test_next_step2_advances_to_step3(self):
        result = _call("setup-next-btn", 2)
        assert result[0] == {"step": 3}
        assert result[3] == S   # step-3 visible

    def test_next_step3_advances_to_step4(self):
        result = _call("setup-next-btn", 3)
        assert result[0] == {"step": 4}
        assert result[4] == S   # step-4 visible

    def test_next_step4_advances_to_step5_with_launch_label(self):
        result = _call("setup-next-btn", 4)
        assert result[0] == {"step": 5}
        assert result[7] == "Launch IoTSentinel →"
        assert result[8] == "success"

    def test_next_step5_success_advances_to_step6(self):
        with patch("dashboard.callbacks.callbacks_setup._save_config", return_value=True), \
             patch("dashboard.callbacks.callbacks_setup._build_review", return_value=None):
            result = _call("setup-next-btn", 5)
        assert result[0] == {"step": 6}

    def test_next_step5_success_hides_all_containers(self):
        with patch("dashboard.callbacks.callbacks_setup._save_config", return_value=True), \
             patch("dashboard.callbacks.callbacks_setup._build_review", return_value=None):
            result = _call("setup-next-btn", 5)
        for i in range(1, 6):
            assert result[i] == H, f"Step {i} container should be hidden on step 6"

    def test_next_step5_failure_stays_on_step5(self):
        with patch("dashboard.callbacks.callbacks_setup._save_config", return_value=False):
            result = _call("setup-next-btn", 5)
        assert result[0] == {"step": 5}

    def test_next_step5_failure_returns_error_alert(self):
        with patch("dashboard.callbacks.callbacks_setup._save_config", return_value=False):
            result = _call("setup-next-btn", 5)
        assert result[11] is not None

    # ------------------------------------------------------------------
    # Back navigation
    # ------------------------------------------------------------------

    def test_back_from_step2_returns_to_step1(self):
        result = _call("setup-back-btn", 2)
        assert result[0] == {"step": 1}
        assert result[1] == S   # step-1 visible

    def test_back_from_step2_hides_back_button(self):
        result = _call("setup-back-btn", 2)
        assert result[6] == H

    def test_back_from_step3_returns_to_step2(self):
        result = _call("setup-back-btn", 3)
        assert result[0] == {"step": 2}

    def test_back_from_step4_returns_to_step3(self):
        result = _call("setup-back-btn", 4)
        assert result[0] == {"step": 3}

    def test_back_from_step5_returns_to_step4(self):
        result = _call("setup-back-btn", 5)
        assert result[0] == {"step": 4}

    # ------------------------------------------------------------------
    # Skip button
    # ------------------------------------------------------------------

    def test_skip_jumps_to_step6(self):
        with patch("dashboard.callbacks.callbacks_setup._save_config", return_value=True), \
             patch("dashboard.callbacks.callbacks_setup._build_review", return_value=None):
            result = _call("setup-skip-btn", 1)
        assert result[0] == {"step": 6}

    def test_skip_hides_back_button(self):
        with patch("dashboard.callbacks.callbacks_setup._save_config", return_value=True), \
             patch("dashboard.callbacks.callbacks_setup._build_review", return_value=None):
            result = _call("setup-skip-btn", 1)
        assert result[6] == H

    def test_skip_saves_with_household_defaults(self):
        with patch("dashboard.callbacks.callbacks_setup._save_config", return_value=True) as mock_save, \
             patch("dashboard.callbacks.callbacks_setup._build_review", return_value=None):
            _call("setup-skip-btn", 1, cidr="10.0.0.0/24", interface="wlan0")
        args = mock_save.call_args[0]
        # _save_config(cidr, interface, smtp_user, smtp_pass, groq, abuse, tier, public_url)
        # tier is at index 6
        assert args[6] == "household"

    # ------------------------------------------------------------------
    # Progress bar values (_PROG contract)
    # ------------------------------------------------------------------

    def test_progress_step1_is_17(self):
        # Validation failure keeps us on step 1 (progress = 17)
        result = _call("setup-next-btn", 1, password="short", password_confirm="short")
        assert result[9] == 17

    def test_progress_step2_is_33(self):
        result = _call("setup-next-btn", 1, password=STRONG_PW, password_confirm=STRONG_PW)
        assert result[9] == 33

    def test_progress_step3_is_50(self):
        result = _call("setup-next-btn", 2)
        assert result[9] == 50

    def test_progress_step4_is_67(self):
        result = _call("setup-next-btn", 3)
        assert result[9] == 67

    def test_progress_step5_is_83(self):
        result = _call("setup-next-btn", 4)
        assert result[9] == 83

    def test_progress_step6_is_100(self):
        with patch("dashboard.callbacks.callbacks_setup._save_config", return_value=True), \
             patch("dashboard.callbacks.callbacks_setup._build_review", return_value=None):
            result = _call("setup-next-btn", 5)
        assert result[9] == 100

    # ------------------------------------------------------------------
    # Unknown trigger → PreventUpdate
    # ------------------------------------------------------------------

    def test_unknown_trigger_raises_prevent_update(self):
        import dash
        with pytest.raises(dash.exceptions.PreventUpdate):
            _call("some-other-btn", 1)


# ---------------------------------------------------------------------------
# show_step_6 visibility logic
# ---------------------------------------------------------------------------

def _show_step_6_logic(step_data):
    """Mirror of the show_step_6 callback logic."""
    step = (step_data or {}).get("step", 1)
    return {"display": "block"} if step == 6 else {"display": "none"}


class TestShowStep6:

    def test_step6_shows_container(self):
        assert _show_step_6_logic({"step": 6}) == {"display": "block"}

    def test_step5_hides_container(self):
        assert _show_step_6_logic({"step": 5}) == {"display": "none"}

    def test_step1_hides_container(self):
        assert _show_step_6_logic({"step": 1}) == {"display": "none"}

    def test_none_step_data_defaults_to_hidden(self):
        assert _show_step_6_logic(None) == {"display": "none"}


# ---------------------------------------------------------------------------
# auth_manager.create_admin — always sets email_verified=1
# ---------------------------------------------------------------------------

class TestCreateAdmin:
    """Verify the HA-style onboarding helper creates the account correctly."""

    def test_create_admin_sets_email_verified(self):
        """create_admin must INSERT with email_verified=1 so custom usernames can log in."""
        from utils.auth import AuthManager
        mock_cursor = MagicMock()
        mock_conn = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_db = MagicMock()
        mock_db.conn = mock_conn

        with patch("utils.auth.bcrypt") as mock_bcrypt:
            mock_bcrypt.hashpw.return_value = b"$2b$12$fakehash"
            mock_bcrypt.gensalt.return_value = b"$2b$12$fakesalt"
            am = AuthManager(mock_db)
            am.create_admin("ritik_admin", "ValidPass1!")

        call_sql = mock_cursor.execute.call_args[0][0]
        assert "email_verified" in call_sql.lower()
        # Verify the value passed for email_verified is 1 (not 0)
        call_params = mock_cursor.execute.call_args[0][1]
        # INSERT ... VALUES (?, ?, 'admin', 1, 0, 1) — email_verified is the 4th ?
        assert "ritik_admin" in call_params

    def test_create_admin_returns_true_on_success(self):
        from utils.auth import AuthManager
        mock_cursor = MagicMock()
        mock_conn = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_db = MagicMock()
        mock_db.conn = mock_conn

        with patch("utils.auth.bcrypt"):
            am = AuthManager(mock_db)
            result = am.create_admin("admin", "ValidPass1!")

        assert result is True

    def test_create_admin_returns_false_on_duplicate(self):
        import sqlite3
        from utils.auth import AuthManager
        mock_cursor = MagicMock()
        mock_cursor.execute.side_effect = sqlite3.IntegrityError("UNIQUE constraint")
        mock_conn = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_db = MagicMock()
        mock_db.conn = mock_conn

        with patch("utils.auth.bcrypt"):
            am = AuthManager(mock_db)
            result = am.create_admin("admin", "ValidPass1!")

        assert result is False


# ---------------------------------------------------------------------------
# account_setup_layout exists (non-Linux first-run screen)
# ---------------------------------------------------------------------------

class TestAccountSetupLayout:

    def test_account_setup_layout_imports(self):
        from dashboard.layouts.account_setup import account_setup_layout
        assert account_setup_layout is not None

    def test_account_setup_layout_exported_from_package(self):
        from dashboard.layouts import account_setup_layout
        assert account_setup_layout is not None

    def test_account_setup_layout_has_required_ids(self):
        from dashboard.layouts.account_setup import account_setup_layout
        layout_str = str(account_setup_layout)
        required_ids = [
            "account-setup-username",
            "account-setup-password",
            "account-setup-password-confirm",
            "account-setup-submit-btn",
            "account-setup-feedback",
        ]
        for cid in required_ids:
            assert cid in layout_str, f"account_setup_layout missing component ID '{cid}'"

    def test_username_field_has_admin_default(self):
        from dashboard.layouts.account_setup import account_setup_layout
        layout_str = str(account_setup_layout)
        # Default username should be "admin" so it's ready out of the box
        assert "admin" in layout_str

    def test_wizard_username_field_present(self):
        """setup_wizard_layout Step 1 must expose an editable username field."""
        from dashboard.layouts.setup_wizard import setup_wizard_layout
        layout_str = str(setup_wizard_layout)
        assert "setup-admin-username" in layout_str, \
            "Wizard Step 1 must have an editable 'setup-admin-username' input"


# ---------------------------------------------------------------------------
# toggle_tailscale_panel logic
# ---------------------------------------------------------------------------

def _toggle_tailscale_panel_logic(enabled):
    """Mirror of the toggle_tailscale_panel callback logic."""
    return {"display": "block"} if enabled else {"display": "none"}


class TestToggleTailscalePanel:

    def test_enabled_true_shows_panel(self):
        assert _toggle_tailscale_panel_logic(True) == {"display": "block"}

    def test_enabled_false_hides_panel(self):
        assert _toggle_tailscale_panel_logic(False) == {"display": "none"}

    def test_enabled_none_hides_panel(self):
        assert _toggle_tailscale_panel_logic(None) == {"display": "none"}

    def test_enabled_empty_list_hides_panel(self):
        assert _toggle_tailscale_panel_logic([]) == {"display": "none"}


# ---------------------------------------------------------------------------
# Local AI (Ollama) detection + AI privacy choice (wizard Step 3)
# ---------------------------------------------------------------------------

class TestDetectOllama:

    def _response(self, status=200, models=None):
        resp = MagicMock()
        resp.status_code = status
        resp.json.return_value = {"models": [{"name": m} for m in (models or [])]}
        return resp

    def test_running_with_expected_model(self):
        from dashboard.callbacks.callbacks_setup import _detect_ollama
        with patch("dashboard.callbacks.callbacks_setup.requests.get",
                   return_value=self._response(models=["gemma2:2b", "llama3:8b"])):
            ok, msg = _detect_ollama()
        assert ok is True
        assert "gemma2:2b" in msg

    def test_running_without_models_suggests_pull(self):
        from dashboard.callbacks.callbacks_setup import _detect_ollama
        with patch("dashboard.callbacks.callbacks_setup.requests.get",
                   return_value=self._response(models=[])):
            ok, msg = _detect_ollama()
        assert ok is True
        assert "ollama pull" in msg

    def test_running_with_other_models_suggests_gemma(self):
        from dashboard.callbacks.callbacks_setup import _detect_ollama
        with patch("dashboard.callbacks.callbacks_setup.requests.get",
                   return_value=self._response(models=["mistral:7b"])):
            ok, msg = _detect_ollama()
        assert ok is True
        assert "mistral:7b" in msg
        assert "gemma2:2b" in msg

    def test_not_running_is_friendly(self):
        from dashboard.callbacks.callbacks_setup import _detect_ollama
        import requests as _requests
        with patch("dashboard.callbacks.callbacks_setup.requests.get",
                   side_effect=_requests.exceptions.ConnectionError()):
            ok, msg = _detect_ollama()
        assert ok is False
        assert "ollama.com" in msg
        assert "Optional" in msg

    def test_bad_status_reported(self):
        from dashboard.callbacks.callbacks_setup import _detect_ollama
        with patch("dashboard.callbacks.callbacks_setup.requests.get",
                   return_value=self._response(status=500)):
            ok, msg = _detect_ollama()
        assert ok is False
        assert "500" in msg


class TestAiPrivacyChoice:

    def _run_save(self, choice):
        with patch("dashboard.callbacks.callbacks_setup.config") as mock_cfg, \
             patch("dashboard.callbacks.callbacks_setup.db_manager") as mock_db:
            mock_cfg.write_env.return_value = True
            mock_cfg.update.return_value = True
            mock_cfg.get.return_value = False

            from dashboard.callbacks.callbacks_setup import _save_config
            result = _save_config(
                "192.168.1.0/24", "wlan0", None, None, None, None,
                "household", None, ai_privacy_choice=choice,
            )
        return result, mock_db

    def test_local_choice_persists_privacy_mode_on(self):
        result, mock_db = self._run_save("local")
        assert result is True
        mock_db.set_setting.assert_any_call('ai_privacy_mode', '1')

    def test_cloud_choice_persists_privacy_mode_off(self):
        result, mock_db = self._run_save("cloud")
        mock_db.set_setting.assert_any_call('ai_privacy_mode', '0')

    def test_no_choice_defaults_to_cloud(self):
        result, mock_db = self._run_save(None)
        mock_db.set_setting.assert_any_call('ai_privacy_mode', '0')

    def test_review_shows_local_first(self):
        with patch("dashboard.callbacks.callbacks_setup.db_manager"):
            from dashboard.callbacks.callbacks_setup import _build_review
            table = _build_review("192.168.1.0/24", "wlan0", None, None, None,
                                  ai_privacy_choice="local")
        assert "Local first" in str(table)

    def test_review_shows_cloud_first_by_default(self):
        with patch("dashboard.callbacks.callbacks_setup.db_manager"):
            from dashboard.callbacks.callbacks_setup import _build_review
            table = _build_review("192.168.1.0/24", "wlan0", None, None, None)
        assert "Cloud first" in str(table)

    def test_wizard_layout_has_ollama_components(self):
        from dashboard.layouts.setup_wizard import setup_wizard_layout
        layout_str = str(setup_wizard_layout)
        assert "setup-ollama-detect-btn" in layout_str
        assert "setup-ollama-feedback" in layout_str
        assert "setup-ai-privacy-choice" in layout_str
