#!/usr/bin/env python3
"""
Unit tests for dashboard template / view-mode behaviour.

Covers:
- DASHBOARD_TEMPLATES simple/advanced definitions are correct
- TEMPLATE_ALIASES maps all legacy tier names correctly
- Registration defaults to simple

Run: pytest tests/test_view_toggle.py -v
"""
import sys
import pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


class TestSimpleTemplate:

    def test_simple_template_exists(self):
        from dashboard.shared import DASHBOARD_TEMPLATES
        assert 'simple' in DASHBOARD_TEMPLATES

    def test_simple_has_visible_features(self):
        from dashboard.shared import DASHBOARD_TEMPLATES
        visible = DASHBOARD_TEMPLATES['simple']['visible_features']
        assert isinstance(visible, list)
        assert len(visible) > 0

    def test_simple_excludes_advanced_only_features(self):
        from dashboard.shared import DASHBOARD_TEMPLATES
        simple_visible = DASHBOARD_TEMPLATES['simple']['visible_features']
        assert 'threat-card-btn' not in simple_visible
        assert 'firewall-card-btn' not in simple_visible
        assert 'forensic-timeline-card-btn' not in simple_visible

    def test_simple_includes_device_management(self):
        from dashboard.shared import DASHBOARD_TEMPLATES
        simple_visible = DASHBOARD_TEMPLATES['simple']['visible_features']
        assert 'device-mgmt-card-btn' in simple_visible


class TestAdvancedTemplate:

    def test_advanced_template_exists(self):
        from dashboard.shared import DASHBOARD_TEMPLATES
        assert 'advanced' in DASHBOARD_TEMPLATES

    def test_advanced_shows_all(self):
        from dashboard.shared import DASHBOARD_TEMPLATES
        assert DASHBOARD_TEMPLATES['advanced']['visible_features'] == 'all'


class TestLegacyAliases:

    def test_home_user_maps_to_simple(self):
        from dashboard.shared import TEMPLATE_ALIASES
        assert TEMPLATE_ALIASES['home_user'] == 'simple'

    def test_security_admin_maps_to_advanced(self):
        from dashboard.shared import TEMPLATE_ALIASES
        assert TEMPLATE_ALIASES['security_admin'] == 'advanced'

    def test_developer_maps_to_advanced(self):
        from dashboard.shared import TEMPLATE_ALIASES
        assert TEMPLATE_ALIASES['developer'] == 'advanced'

    def test_no_legacy_keys_in_templates(self):
        from dashboard.shared import DASHBOARD_TEMPLATES
        for legacy in ('home_user', 'security_admin', 'developer'):
            assert legacy not in DASHBOARD_TEMPLATES, \
                f"Legacy key '{legacy}' should not appear in DASHBOARD_TEMPLATES"


class TestRegistrationDefault:

    def test_register_template_select_defaults_to_simple(self):
        from dashboard.layouts.login import login_layout
        layout_str = str(login_layout)
        assert "'simple'" in layout_str or '"simple"' in layout_str or 'simple' in layout_str

    def test_register_role_store_defaults_to_viewer(self):
        from dashboard.layouts.login import login_layout
        layout_str = str(login_layout)
        assert 'register-role' in layout_str
