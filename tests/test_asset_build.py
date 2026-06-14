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
