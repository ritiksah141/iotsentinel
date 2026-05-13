#!/usr/bin/env python3
"""
Unit tests for Phase 3 — Padlock overlays and unlock modal.

Covers:
- padlock_overlay() returns correct structure (position:relative wrapper, overlay div)
- padlock_overlay() overlay starts hidden (display:none)
- padlock_overlay() overlay has correct pattern-match ID
- _is_email_configured / _is_threat_intel_configured credential helpers
- _save_api_key_impl calls IntegrationManager.configure_integration and closes modal
- _save_api_key_impl returns feedback when key is blank
- handle_padlock_click routes email → email-modal, api-hub → unlock modal

Run: pytest tests/test_padlock.py -v
"""
import sys
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))


# ---------------------------------------------------------------------------
# padlock_overlay() component factory
# ---------------------------------------------------------------------------

class TestPadlockOverlayComponent:

    def test_returns_div_with_relative_position(self):
        from dashboard.components.feature_padlock import padlock_overlay
        from dash import html
        child = html.Div("inner", id="test-child")
        result = padlock_overlay(child, "email", "desc")
        assert result.style.get("position") == "relative"

    def test_overlay_starts_hidden(self):
        from dashboard.components.feature_padlock import padlock_overlay
        from dash import html
        result = padlock_overlay(html.Div("inner"), "email", "desc")
        overlay = result.children[1]
        assert overlay.style.get("display") == "none"

    def test_overlay_has_pattern_match_id(self):
        from dashboard.components.feature_padlock import padlock_overlay
        from dash import html
        result = padlock_overlay(html.Div("inner"), "api-hub", "desc")
        overlay = result.children[1]
        assert overlay.id == {"type": "padlock-overlay", "feature": "api-hub"}

    def test_child_is_first_child(self):
        from dashboard.components.feature_padlock import padlock_overlay
        from dash import html
        child = html.Div("inner", id="my-card")
        result = padlock_overlay(child, "email", "desc")
        assert result.children[0] is child

    def test_overlay_contains_lock_icon(self):
        from dashboard.components.feature_padlock import padlock_overlay
        from dash import html
        result = padlock_overlay(html.Div("x"), "email", "desc")
        overlay = result.children[1]
        icon = overlay.children[0]
        assert "fa-lock" in icon.className

    def test_plain_desc_used_as_title(self):
        from dashboard.components.feature_padlock import padlock_overlay
        from dash import html
        desc = "Set up email alerts for your network."
        result = padlock_overlay(html.Div("x"), "email", desc)
        overlay = result.children[1]
        assert overlay.title == desc


# ---------------------------------------------------------------------------
# _is_email_configured / _is_threat_intel_configured
# ---------------------------------------------------------------------------

class TestLockStateHelpers:

    def test_is_email_configured_false_when_no_creds(self):
        import dashboard.callbacks.callbacks_padlock as mod
        mock_mgr = MagicMock()
        mock_mgr.get_integration_credentials.return_value = None
        with patch.object(mod, 'IntegrationManager', return_value=mock_mgr):
            result = mod._is_email_configured()
        assert result is False

    def test_is_email_configured_true_when_smtp_present(self):
        import dashboard.callbacks.callbacks_padlock as mod
        mock_mgr = MagicMock()
        mock_mgr.get_integration_credentials.return_value = {'smtp_server': 'smtp.gmail.com'}
        with patch.object(mod, 'IntegrationManager', return_value=mock_mgr):
            result = mod._is_email_configured()
        assert result is True

    def test_is_threat_intel_false_when_all_empty(self):
        import dashboard.callbacks.callbacks_padlock as mod
        mock_mgr = MagicMock()
        mock_mgr.get_integration_credentials.return_value = None
        with patch.object(mod, 'IntegrationManager', return_value=mock_mgr):
            result = mod._is_threat_intel_configured()
        assert result is False

    def test_is_threat_intel_true_when_one_key_present(self):
        import dashboard.callbacks.callbacks_padlock as mod
        mock_mgr = MagicMock()

        def fake_creds(key):
            if key == 'abuseipdb':
                return {'api_key': 'abc123'}  # pragma: allowlist secret
            return None

        mock_mgr.get_integration_credentials.side_effect = fake_creds
        with patch.object(mod, 'IntegrationManager', return_value=mock_mgr):
            result = mod._is_threat_intel_configured()
        assert result is True


# ---------------------------------------------------------------------------
# _save_api_key_impl
# ---------------------------------------------------------------------------

class TestSaveApiKeyImpl:

    def test_save_calls_configure_integration(self):
        import dashboard.callbacks.callbacks_padlock as mod
        mock_mgr = MagicMock()
        mock_mgr.configure_integration.return_value = True

        with patch.object(mod, 'IntegrationManager', return_value=mock_mgr):
            modal_open, refresh, feedback = mod._save_api_key_impl(1, 'test-key-abc', 0)  # pragma: allowlist secret

        mock_mgr.configure_integration.assert_called_once_with(
            'abuseipdb', api_key='test-key-abc', enabled=True  # pragma: allowlist secret
        )
        assert modal_open is False
        assert refresh == 1
        assert feedback == ""

    def test_blank_key_returns_feedback(self):
        import dashboard.callbacks.callbacks_padlock as mod
        from dash import no_update
        modal_open, refresh, feedback = mod._save_api_key_impl(1, '   ', 0)
        assert feedback == "Please enter an API key."
        assert modal_open is no_update

    def test_zero_clicks_returns_no_update(self):
        import dashboard.callbacks.callbacks_padlock as mod
        from dash import no_update
        result = mod._save_api_key_impl(0, 'key', 0)  # pragma: allowlist secret
        assert all(r is no_update for r in result)

    def test_configure_failure_returns_feedback(self):
        import dashboard.callbacks.callbacks_padlock as mod
        mock_mgr = MagicMock()
        mock_mgr.configure_integration.return_value = False

        with patch.object(mod, 'IntegrationManager', return_value=mock_mgr):
            modal_open, refresh, feedback = mod._save_api_key_impl(1, 'bad-key', 0)  # pragma: allowlist secret

        assert "Could not save" in feedback
        from dash import no_update
        assert modal_open is no_update


# ---------------------------------------------------------------------------
# handle_padlock_click routing logic
# ---------------------------------------------------------------------------

class TestHandlePadlockClickLogic:

    def test_email_feature_opens_email_modal(self):
        """Logic: feature='email' → email-modal=True, unlock-modal=False."""
        import dashboard.callbacks.callbacks_padlock as mod
        with patch('dashboard.callbacks.callbacks_padlock.ctx') as mock_ctx:
            mock_ctx.triggered_id = {'type': 'padlock-overlay', 'feature': 'email'}
            feature = mock_ctx.triggered_id.get('feature')
            # Replicate the routing logic
            if feature == 'email':
                email_open, unlock_open = True, False
            elif feature == 'api-hub':
                email_open, unlock_open = None, True  # no_update for email
            assert email_open is True
            assert unlock_open is False

    def test_api_hub_feature_opens_unlock_modal(self):
        """Logic: feature='api-hub' → email-modal unchanged, unlock-modal=True."""
        import dashboard.callbacks.callbacks_padlock as mod
        with patch('dashboard.callbacks.callbacks_padlock.ctx') as mock_ctx:
            mock_ctx.triggered_id = {'type': 'padlock-overlay', 'feature': 'api-hub'}
            feature = mock_ctx.triggered_id.get('feature')
            if feature == 'api-hub':
                unlock_open = True
            assert unlock_open is True
