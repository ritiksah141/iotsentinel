"""Tests for dashboard/asset_build.py — boot-time CSS minification.

Why this exists: app.py serves <name>.min.css instead of the readable
sources, so a minifier bug would silently break every page's styling.
These tests pin the safety guarantees (strings untouched, selector
semantics preserved) and the staleness/fallback logic.
"""

import os
import time

import pytest

from dashboard.asset_build import (
    ASSETS_IGNORE_REGEX,
    MINIFY_TARGETS,
    ensure_minified_css,
    minify_css,
)


class TestMinifyCss:
    def test_strips_comments(self):
        assert minify_css("/* header */ .a { color: red; }") == ".a{color:red}"

    def test_collapses_whitespace(self):
        assert minify_css(".a  {\n  color :  red ;\n}") == ".a{color :red}"

    def test_drops_semicolon_before_brace(self):
        assert minify_css(".a { color: red; }") == ".a{color:red}"

    def test_keeps_semicolon_between_declarations(self):
        assert minify_css(".a { color: red; top: 0; }") == ".a{color:red;top:0}"

    def test_string_content_untouched(self):
        css = '.a { content: "  /* not a comment */  "; }'
        assert '"  /* not a comment */  "' in minify_css(css)

    def test_attribute_selector_string_untouched(self):
        css = 'img[src="/assets/logo.png"] { padding: 12px; }'
        assert minify_css(css) == 'img[src="/assets/logo.png"]{padding:12px}'

    def test_escaped_quote_inside_string(self):
        css = '.a { content: "say \\"hi\\""; }'
        assert '\\"hi\\"' in minify_css(css)

    def test_calc_spaces_preserved(self):
        css = ".a { width: calc(100% - 20px); }"
        assert minify_css(css) == ".a{width:calc(100% - 20px)}"

    def test_media_query_and_space_preserved(self):
        css = "@media screen and (max-width: 768px) { .a { top: 0; } }"
        assert minify_css(css) == "@media screen and (max-width:768px){.a{top:0}}"

    def test_descendant_pseudo_selector_space_preserved(self):
        # ".foo :hover" (descendant) must not become ".foo:hover"
        assert minify_css(".foo :hover { top: 0; }") == ".foo :hover{top:0}"

    def test_space_removed_after_combinators_and_commas(self):
        assert minify_css(".a , .b > .c { top: 0; }") == ".a,.b>.c{top:0}"

    def test_unclosed_comment_consumed(self):
        assert minify_css(".a { top: 0; } /* trailing") == ".a{top:0}"

    def test_css_variables_preserved(self):
        css = ":root { --glass-blur-sm: blur(8px) saturate(140%); }"
        assert minify_css(css) == ":root{--glass-blur-sm:blur(8px) saturate(140%)}"

    def test_comment_between_tokens_keeps_separation(self):
        assert minify_css("a/* x */b { top: 0; }") == "a b{top:0}"


class TestRealStylesheets:
    """Run the minifier over the actual shipped CSS and sanity-check output."""

    ASSETS = os.path.join(os.path.dirname(__file__), '..', 'dashboard', 'assets')

    @pytest.mark.parametrize("name", MINIFY_TARGETS)
    def test_braces_balanced_and_smaller(self, name):
        path = os.path.join(self.ASSETS, name)
        with open(path, encoding='utf-8') as fh:
            src = fh.read()
        out = minify_css(src)
        assert out.count('{') == out.count('}')
        assert out.count('{') == _brace_count_outside_strings_and_comments(src)
        assert len(out) < len(src)
        assert '/*' not in _strip_strings(out)

    @pytest.mark.parametrize("name", MINIFY_TARGETS)
    def test_parens_balanced(self, name):
        # Braces can balance while the sheet is still unparseable — e.g. a
        # truncated "cubic-bezier(0.4, 0, 0.2{" once silently disabled ALL
        # styling past :root. Unbalanced parens are the signature of that
        # failure mode, so pin it at the source level.
        path = os.path.join(self.ASSETS, name)
        with open(path, encoding='utf-8') as fh:
            text = _strip_strings(fh.read())
        assert text.count('(') == text.count(')')


class TestEnsureMinifiedCss:
    def _make_assets(self, tmp_path):
        for name in MINIFY_TARGETS:
            (tmp_path / name).write_text(".a { color: red; }", encoding='utf-8')
        return str(tmp_path)

    def test_generates_min_files_and_returns_regex(self, tmp_path):
        assets = self._make_assets(tmp_path)
        assert ensure_minified_css(assets) == ASSETS_IGNORE_REGEX
        for name in MINIFY_TARGETS:
            min_path = tmp_path / name.replace('.css', '.min.css')
            assert min_path.read_text(encoding='utf-8') == ".a{color:red}"

    def test_fresh_files_not_regenerated(self, tmp_path):
        assets = self._make_assets(tmp_path)
        ensure_minified_css(assets)
        min_path = tmp_path / MINIFY_TARGETS[0].replace('.css', '.min.css')
        before = os.path.getmtime(min_path)
        ensure_minified_css(assets)
        assert os.path.getmtime(min_path) == before

    def test_stale_min_file_regenerated(self, tmp_path):
        assets = self._make_assets(tmp_path)
        ensure_minified_css(assets)
        src = tmp_path / MINIFY_TARGETS[0]
        min_path = tmp_path / MINIFY_TARGETS[0].replace('.css', '.min.css')
        time.sleep(0.05)
        src.write_text(".b { top: 0; }", encoding='utf-8')
        os.utime(src)  # ensure mtime advances past the min file
        ensure_minified_css(assets)
        assert min_path.read_text(encoding='utf-8') == ".b{top:0}"

    def test_missing_source_returns_none(self, tmp_path):
        assets = self._make_assets(tmp_path)
        os.remove(tmp_path / MINIFY_TARGETS[0])
        assert ensure_minified_css(assets) is None

    def test_ignore_regex_matches_sources_not_min(self):
        import re
        pat = re.compile(ASSETS_IGNORE_REGEX)
        for name in MINIFY_TARGETS:
            assert pat.search(name)
            assert not pat.search(name.replace('.css', '.min.css'))
        # vendored minified assets must never be ignored
        assert not pat.search('bootstrap.min.css')
        assert not pat.search('fontawesome.min.css')


def _strip_strings(css):
    """Remove string literals and comments in one pass (an apostrophe inside
    a comment must not open a string, and vice versa)."""
    out, in_str, i = [], None, 0
    while i < len(css):
        c = css[i]
        if in_str:
            if c == '\\':
                i += 2
                continue
            if c == in_str:
                in_str = None
        elif css[i:i + 2] == '/*':
            end = css.find('*/', i + 2)
            i = len(css) if end == -1 else end + 2
            continue
        elif c in '"\'':
            in_str = c
        else:
            out.append(c)
        i += 1
    return ''.join(out)


def _brace_count_outside_strings_and_comments(css):
    return _strip_strings(css).count('{')


def test_no_dbc_table_uses_dark_kwarg():
    """dash_bootstrap_components 2.0.4's Table dropped the `dark` argument; any
    `dbc.Table(... dark=...)` raises at render time (hit on Network Segmentation's
    Device Ecosystems). Guard so it can't creep back into any callback."""
    from pathlib import Path
    import re
    repo = Path(__file__).resolve().parent.parent
    offenders = []
    for py in (repo / "dashboard").rglob("*.py"):
        text = py.read_text()
        # crude but effective: a dbc.Table(...) call carrying a dark= kwarg
        for m in re.finditer(r"dbc\.Table\((.*?)\)", text, re.DOTALL):
            if re.search(r"\bdark\s*=", m.group(1)):
                offenders.append(py.name)
    assert not offenders, f"dbc.Table(dark=...) is invalid in dbc 2.0.4: {set(offenders)}"


def test_no_dbc_spinner_uses_classname():
    """dash_bootstrap_components 2.0.4's Spinner has no `className` (only
    spinner_class_name); `dbc.Spinner(className=...)` raises at render time — it broke the
    remote-access status poll. Guard so it can't creep back into any callback."""
    from pathlib import Path
    import re
    repo = Path(__file__).resolve().parent.parent
    offenders = []
    for py in (repo / "dashboard").rglob("*.py"):
        for m in re.finditer(r"dbc\.Spinner\((.*?)\)", py.read_text(), re.DOTALL):
            if re.search(r"\bclassName\s*=", m.group(1)):
                offenders.append(py.name)
    assert not offenders, f"dbc.Spinner(className=...) is invalid in dbc 2.0.4: {set(offenders)}"


def test_no_plotly_colorbar_titleside():
    """Plotly moved colorbar `titleside` under `title.side`; a bare `titleside` raises at
    render time — it broke the device activity heatmap. Guard the chart code + callbacks."""
    from pathlib import Path
    repo = Path(__file__).resolve().parent.parent
    offenders = [py.name for d in ("dashboard", "utils")
                 for py in (repo / d).rglob("*.py") if "titleside" in py.read_text()]
    assert not offenders, f"plotly colorbar 'titleside' is invalid; use title.side: {set(offenders)}"


def test_protocol_stats_table_is_created():
    """iot_protocol_analyzer upserts into protocol_stats; init_database must create it or
    the dashboard's protocol summary errors every cycle ('no such table: protocol_stats')."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "config" / "init_database.py").read_text()
    assert "CREATE TABLE IF NOT EXISTS protocol_stats" in src


def test_no_invalid_component_keywords():
    """Run scripts/check_component_props.py: no dbc/dcc/html component is passed a keyword it
    doesn't accept. This is the class of bug that broke Remote Access (dbc.Spinner(className=))
    and the device badge (dbc.Badge(size=)) — invisible to the suite because callbacks aren't
    rendered, so this static AST check guards it."""
    import importlib.util
    from pathlib import Path
    repo = Path(__file__).resolve().parent.parent
    spec = importlib.util.spec_from_file_location(
        "check_component_props", repo / "scripts" / "check_component_props.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    offenders = [o for f in sorted((repo / "dashboard").rglob("*.py")) for o in mod.scan_file(f)]
    assert not offenders, "Invalid component keywords (crash at render):\n" + "\n".join(offenders)


def test_touch_target_rule_excludes_switches():
    """The mobile touch-target sizing must NOT hit .form-check-input: a 44px min-height
    overrides the Apple switch's 31px height (min-height beats height even with !important),
    turning the compact pill into a circle on mobile. Guard the exclusion."""
    from pathlib import Path
    css = (Path(__file__).resolve().parent.parent / "dashboard" / "assets"
           / "mobile-responsive.css").read_text()
    assert "input:not(.form-check-input)" in css, \
        "touch-target min-height rule must exclude .form-check-input (switches)"


# ---------------------------------------------------------------------------
# rc11 hardware-gate fix guards
# ---------------------------------------------------------------------------

def test_agent_trust_updates_badge_immediately():
    """trust_device must output to agent-panel-content / agent-pending-badge so
    the notification clears instantly (not on the next 30-second interval)."""
    import ast
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboard" / "callbacks"
           / "callbacks_agent.py").read_text()
    # Both outputs must appear inside the callback that also outputs agent-action-result
    assert "agent-panel-content" in src and "agent-pending-badge" in src, \
        "trust_device/block_triaged_device must output badge + panel for immediate update"
    assert "_build_panel_content" in src, \
        "_build_panel_content helper must be extracted from refresh_agent_panel"


def test_api_hub_shows_saved_key_indicator():
    """Integration Hub configure dialog must signal when a key is already saved
    so users can tell save succeeded without re-entering the key."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboard" / "callbacks"
           / "callbacks_integrations.py").read_text()
    assert "has_saved_key" in src, \
        "handle_integration_config must use has_api_key to show saved-key placeholder"
    assert "has_api_key" in src, \
        "get_all_integrations must expose has_api_key field"


def test_api_hub_configure_integration_checks_rowcount():
    """configure_integration must verify cursor.rowcount after UPDATE so a
    zero-match is surfaced as a failure rather than a silent success."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "alerts"
           / "integration_system.py").read_text()
    assert "cursor.rowcount" in src, \
        "configure_integration must check cursor.rowcount after UPDATE"


def test_webauthn_availability_requires_secure_origin():
    """is_webauthn_available must reject plain HTTP mDNS names (iotsentinel.local)
    and only allow https:// or http://localhost / http://127.0.0.1."""
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from unittest.mock import patch
    from utils.webauthn_handler import is_webauthn_available

    with patch.dict('os.environ', {'IOTSENTINEL_PUBLIC_URL': 'http://iotsentinel.local:8050',
                                   'WEBAUTHN_ORIGIN': ''}):
        assert not is_webauthn_available(), "HTTP mDNS must not be allowed"

    with patch.dict('os.environ', {'IOTSENTINEL_PUBLIC_URL': 'https://abc.ts.net',
                                   'WEBAUTHN_ORIGIN': ''}):
        assert is_webauthn_available(), "HTTPS must be allowed"

    with patch.dict('os.environ', {'IOTSENTINEL_PUBLIC_URL': '',
                                   'WEBAUTHN_ORIGIN': 'http://localhost:8050'}):
        assert is_webauthn_available(), "http://localhost must be allowed"


def test_biometric_username_uses_dcc_store():
    """biometric-username-store must be a dcc.Store (not an html.Div with data-*
    attribute) so Dash can track it as a reactive property."""
    from pathlib import Path
    app_src = (Path(__file__).resolve().parent.parent / "dashboard" / "app.py").read_text()
    assert "biometric-username-store" in app_src
    assert 'data-username' not in app_src, \
        "biometric-username-store must not use data-* attribute (use dcc.Store instead)"


def test_2fa_disk_check_before_setup():
    """2FA setup callback must check available disk space before attempting a DB
    write, to give a human-readable message instead of raw SQLite FULL error."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboard" / "callbacks"
           / "callbacks_auth.py").read_text()
    assert "disk_usage" in src, \
        "enable_totp_setup must call shutil.disk_usage before totp_manager.setup_totp"
