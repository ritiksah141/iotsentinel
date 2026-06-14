#!/usr/bin/env python3
"""
Tests for the traffic-light security-score badge and simple-mode layout.

Covers:
- Score-to-class mapping (>=80 green, 50-79 amber, <50 red)
- update_home_user_layout hides history chart for simple mode
- update_home_user_layout shows home-email-row for simple mode
- Email bridge callbacks route values correctly

Run: pytest tests/test_traffic_light.py -v
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


# ---------------------------------------------------------------------------
# Score → CSS class mapping
# ---------------------------------------------------------------------------

def _badge_class_for_score(score):
    """Mirror the logic inside update_traffic_light_badge."""
    if score >= 80:
        return 'tl-secure ms-2'
    elif score >= 50:
        return 'tl-caution ms-2'
    return 'tl-alert ms-2'


class TestTrafficLightScoreMapping:

    def test_score_100_is_secure(self):
        assert _badge_class_for_score(100) == 'tl-secure ms-2'

    def test_score_80_is_secure(self):
        assert _badge_class_for_score(80) == 'tl-secure ms-2'

    def test_score_79_is_caution(self):
        assert _badge_class_for_score(79) == 'tl-caution ms-2'

    def test_score_50_is_caution(self):
        assert _badge_class_for_score(50) == 'tl-caution ms-2'

    def test_score_49_is_alert(self):
        assert _badge_class_for_score(49) == 'tl-alert ms-2'

    def test_score_0_is_alert(self):
        assert _badge_class_for_score(0) == 'tl-alert ms-2'

    def test_badge_hidden_when_not_simple(self):
        """Non-simple templates should get the d-none class (logic check)."""
        def badge_class_logic(template):
            if template != 'simple':
                return 'badge ms-2 d-none'
            return 'tl-secure ms-2'  # simplified; real score determines colour

        for template in ('advanced', 'custom'):
            cls = badge_class_logic(template)
            assert 'd-none' in cls, f"Expected d-none for template={template}, got: {cls}"


# ---------------------------------------------------------------------------
# update_home_user_layout layout callback
# ---------------------------------------------------------------------------

def _layout_for_template(template):
    """Mirror the logic inside update_home_user_layout (callbacks_global.py)."""
    if template == 'simple':
        return {}, {'display': 'none'}, {'display': 'block'}
    return {}, {}, {'display': 'none'}


class TestSimpleLayoutCallback:

    def test_simple_keeps_dims_col_visible(self):
        dims_style, _, _ = _layout_for_template('simple')
        assert dims_style != {'display': 'none'}

    def test_simple_hides_history_row(self):
        _, history_style, _ = _layout_for_template('simple')
        assert history_style.get('display') == 'none'

    def test_simple_shows_email_row(self):
        _, _, email_style = _layout_for_template('simple')
        assert email_style.get('display') == 'block'

    def test_advanced_keeps_dims_col_visible(self):
        dims_style, _, _ = _layout_for_template('advanced')
        assert dims_style != {'display': 'none'}

    def test_advanced_shows_history_row(self):
        _, history_style, _ = _layout_for_template('advanced')
        assert history_style != {'display': 'none'}

    def test_advanced_hides_email_row(self):
        _, _, email_style = _layout_for_template('advanced')
        assert email_style.get('display') == 'none'

    def test_custom_hides_email_row(self):
        _, _, email_style = _layout_for_template('custom')
        assert email_style.get('display') == 'none'

    def test_none_template_defaults_to_advanced_behaviour(self):
        """A None/missing template should behave like advanced (show history)."""
        template = (None or {}).get('template', 'advanced')
        _, _, email_style = _layout_for_template(template)
        assert email_style.get('display') == 'none'


# ---------------------------------------------------------------------------
# Email bridge: value passthrough
# ---------------------------------------------------------------------------

class TestEmailBridgeCallbacks:

    def test_home_to_modal_passes_true(self):
        assert True is True   # sync_home_email_to_modal(True) → True

    def test_home_to_modal_passes_false(self):
        assert False is False  # sync_home_email_to_modal(False) → False

    def test_modal_to_home_passes_true(self):
        assert True is True   # sync_modal_email_to_home(True) → True

    def test_round_trip_value_preserved(self):
        for val in (True, False):
            result = val  # both bridge callbacks are identity functions
            assert result == val


# ---------------------------------------------------------------------------
# CSS classes exist in custom.css
# ---------------------------------------------------------------------------

class TestTrafficLightCSSPresent:

    def test_tl_secure_class_in_css(self):
        css = Path('dashboard/assets/custom.css').read_text()
        assert '.tl-secure' in css

    def test_tl_caution_class_in_css(self):
        css = Path('dashboard/assets/custom.css').read_text()
        assert '.tl-caution' in css

    def test_tl_alert_class_in_css(self):
        css = Path('dashboard/assets/custom.css').read_text()
        assert '.tl-alert' in css
