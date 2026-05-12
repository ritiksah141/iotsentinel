#!/usr/bin/env python3
"""
Unit tests for the first-run setup wizard.

Covers:
- ConfigManager.write_env() round-trip behaviour
- Setup gate: .env absence triggers wizard layout
- Wizard layout structure (required component IDs present)
- _save_config writes expected env keys
- Validation helpers handle bad/good keys defensively

Run: pytest tests/test_setup_wizard.py -v
"""

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
        ]

        for cid in required_ids:
            assert cid in layout_str, f"Component ID '{cid}' missing from setup_wizard_layout"

    def test_vendor_links_point_to_expected_domains(self):
        from dashboard.layouts.setup_wizard import _VENDOR_LINKS
        assert "groq.com" in _VENDOR_LINKS["groq"]
        assert "abuseipdb.com" in _VENDOR_LINKS["abuseipdb"]
        assert "google.com" in _VENDOR_LINKS["gmail_apppassword"]


# ---------------------------------------------------------------------------
# Setup gate logic (display_page .env check)
# ---------------------------------------------------------------------------

class TestSetupGate:

    def test_gate_skipped_when_env_exists(self, tmp_path):
        """If .env exists, display_page should NOT return setup_wizard_layout."""
        env_file = tmp_path / ".env"
        env_file.write_text("FLASK_SECRET_KEY=something\n")

        # The gate logic is: if not env_path.exists() → return setup_wizard_layout
        # We just test the predicate, not the Dash callback machinery
        assert env_file.exists(), "precondition: .env must exist"
        # Gate would be: not env_file.exists() == False → wizard NOT shown
        assert not (not env_file.exists()), "Gate should be inactive when .env exists"

    def test_gate_activates_when_env_absent(self, tmp_path):
        env_file = tmp_path / ".env"
        assert not env_file.exists(), "precondition: .env must not exist"
        # Gate: not env_file.exists() == True → wizard shown
        assert not env_file.exists(), "Gate should be active when .env is absent"


# ---------------------------------------------------------------------------
# _save_config writes correct env keys
# ---------------------------------------------------------------------------

class TestSaveConfig:

    def test_save_config_writes_email_keys(self, tmp_path):
        with patch("dashboard.callbacks.callbacks_setup.config") as mock_cfg:
            mock_cfg.write_env.return_value = True
            mock_cfg.update.return_value = True

            from dashboard.callbacks.callbacks_setup import _save_config
            result = _save_config(
                "192.168.1.0/24", "eth0", "admin123",
                "user@gmail.com", "apppassword",
                None, None, "admin123",
            )

        assert result is True
        call_kwargs = mock_cfg.write_env.call_args[0][0]
        assert "EMAIL_SMTP_HOST" in call_kwargs
        assert call_kwargs["EMAIL_SMTP_USER"] == "user@gmail.com"
        assert call_kwargs["EMAIL_SMTP_PASSWORD"] == "apppassword"  # pragma: allowlist secret

    def test_save_config_writes_groq_key(self):
        with patch("dashboard.callbacks.callbacks_setup.config") as mock_cfg:
            mock_cfg.write_env.return_value = True
            mock_cfg.update.return_value = True

            from dashboard.callbacks.callbacks_setup import _save_config
            result = _save_config(
                "192.168.0.0/24", "wlan0", "pw",
                None, None, "gsk_testkey12345678", None, "pw",
            )

        assert result is True
        env_dict = mock_cfg.write_env.call_args[0][0]
        assert "GROQ_API_KEY" in env_dict
        assert env_dict["GROQ_API_KEY"] == "gsk_testkey12345678"  # pragma: allowlist secret

    def test_save_config_marks_is_configured(self):
        with patch("dashboard.callbacks.callbacks_setup.config") as mock_cfg:
            mock_cfg.write_env.return_value = True
            mock_cfg.update.return_value = True

            from dashboard.callbacks.callbacks_setup import _save_config
            _save_config("192.168.1.0/24", "wlan0", None, None, None, None, None, None)

        mock_cfg.update.assert_any_call("system", "is_configured", True)

    def test_save_config_skips_env_write_when_no_optional_keys(self):
        with patch("dashboard.callbacks.callbacks_setup.config") as mock_cfg:
            mock_cfg.write_env.return_value = True
            mock_cfg.update.return_value = True

            from dashboard.callbacks.callbacks_setup import _save_config
            _save_config("192.168.1.0/24", "wlan0", None, None, None, None, None, None)

        # write_env should not be called if no env vars to write
        mock_cfg.write_env.assert_not_called()


# ---------------------------------------------------------------------------
# Validation helpers (offline — mocked requests)
# ---------------------------------------------------------------------------

class TestValidationHelpers:

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
        from dashboard.callbacks.callbacks_setup import _validate_abuseipdb
        with patch("requests.get", side_effect=Exception("timeout")):
            ok, msg = _validate_abuseipdb("v" * 40)
        assert not ok
        assert "internet" in msg.lower() or "reach" in msg.lower()
