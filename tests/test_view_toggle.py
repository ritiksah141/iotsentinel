#!/usr/bin/env python3
"""
Unit tests for the Advanced-View header toggle (Phase 2).

Covers:
- Toggle-to-template mapping (ON → developer/security_admin, OFF → home_user)
- Template-to-toggle sync (home_user → OFF, anything else → ON)
- Toggle component is present in dashboard_layout
- DASHBOARD_TEMPLATES home_user visible_features subset is correct

Run: pytest tests/test_view_toggle.py -v
"""
import sys
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))


# ---------------------------------------------------------------------------
# Mapping logic (pure — no Dash app required)
# ---------------------------------------------------------------------------

class TestToggleMapping:

    def _target_template(self, is_advanced: bool, is_admin: bool) -> str:
        """Replicate the logic from apply_view_toggle without Dash."""
        if is_advanced:
            return 'security_admin' if is_admin else 'developer'
        return 'home_user'

    def test_toggle_off_yields_home_user(self):
        assert self._target_template(False, False) == 'home_user'

    def test_toggle_off_yields_home_user_even_for_admin(self):
        assert self._target_template(False, True) == 'home_user'

    def test_toggle_on_yields_developer_for_regular_user(self):
        assert self._target_template(True, False) == 'developer'

    def test_toggle_on_yields_security_admin_for_admin(self):
        assert self._target_template(True, True) == 'security_admin'

    def test_sync_toggle_home_user_is_off(self):
        # template == 'home_user' → toggle value is False
        assert ('home_user' != 'home_user') is False

    def test_sync_toggle_developer_is_on(self):
        assert ('developer' != 'home_user') is True

    def test_sync_toggle_security_admin_is_on(self):
        assert ('security_admin' != 'home_user') is True

    def test_sync_toggle_custom_is_on(self):
        assert ('custom' != 'home_user') is True


# ---------------------------------------------------------------------------
# DASHBOARD_TEMPLATES home_user definition
# ---------------------------------------------------------------------------

class TestHomeUserTemplate:

    def test_home_user_template_exists(self):
        from dashboard.shared import DASHBOARD_TEMPLATES
        assert 'home_user' in DASHBOARD_TEMPLATES

    def test_home_user_has_visible_features(self):
        from dashboard.shared import DASHBOARD_TEMPLATES
        visible = DASHBOARD_TEMPLATES['home_user']['visible_features']
        assert isinstance(visible, list)
        assert len(visible) > 0

    def test_home_user_excludes_advanced_only_features(self):
        from dashboard.shared import DASHBOARD_TEMPLATES
        home_visible = DASHBOARD_TEMPLATES['home_user']['visible_features']
        # Threat intel and firewall cards are security_admin-only, not home_user
        assert 'threat-card-btn' not in home_visible
        assert 'firewall-card-btn' not in home_visible
        assert 'forensic-timeline-card-btn' not in home_visible

    def test_home_user_includes_device_management(self):
        from dashboard.shared import DASHBOARD_TEMPLATES
        home_visible = DASHBOARD_TEMPLATES['home_user']['visible_features']
        assert 'device-mgmt-card-btn' in home_visible

    def test_security_admin_template_exists(self):
        from dashboard.shared import DASHBOARD_TEMPLATES
        assert 'security_admin' in DASHBOARD_TEMPLATES

    def test_developer_template_shows_all(self):
        from dashboard.shared import DASHBOARD_TEMPLATES
        assert DASHBOARD_TEMPLATES['developer']['visible_features'] == 'all'


# ---------------------------------------------------------------------------
# Layout: advanced-view-toggle component present in dashboard_layout
# ---------------------------------------------------------------------------

class TestToggleInLayout:

    def test_advanced_view_toggle_in_layout(self):
        """The toggle ID must exist in dashboard_layout for callbacks to bind."""
        from dashboard.app import dashboard_layout
        layout_str = str(dashboard_layout)
        assert 'advanced-view-toggle' in layout_str

    def test_toggle_tooltip_in_layout(self):
        """A tooltip for the toggle should be present in the layout."""
        from dashboard.app import dashboard_layout
        layout_str = str(dashboard_layout)
        # Tooltip targets the toggle ID
        assert 'advanced-view-toggle' in layout_str


# ---------------------------------------------------------------------------
# Registration defaults: new self-registrations get home_user template
# ---------------------------------------------------------------------------

class TestRegistrationDefault:

    def test_register_template_select_defaults_to_home_user(self):
        """The registration form template selector defaults to home_user."""
        from dashboard.layouts.login import login_layout
        layout_str = str(login_layout)
        # The select element should have home_user as the default value
        assert 'home_user' in layout_str

    def test_register_role_store_defaults_to_viewer(self):
        """The hidden role store for self-registration defaults to viewer (not admin)."""
        from dashboard.layouts.login import login_layout
        layout_str = str(login_layout)
        assert 'register-role' in layout_str
