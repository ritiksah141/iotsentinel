#!/usr/bin/env python3
"""
Unit tests for utils/alert_explainer.py.

Covers:
- clean_ai_text: em-dash / bold stripping
- source_label, source_badge_class, source_icon: known keys + fallbacks
- build_prompt: format markers, device/severity interpolation, recs branch
- parse_ai_text: all three section prefixes, worry-level separators, fallback
- rewrite_alert: None ai_assistant / empty text / exception / success paths
- persist: UPDATE contents, 500-char truncation, error path
- build_followup_prompt: context lines, history bounding, chip question passthrough

Run: pytest tests/test_alert_explainer.py -v
"""
import sys
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.alert_explainer import (
    clean_ai_text,
    source_label,
    source_badge_class,
    source_icon,
    build_prompt,
    parse_ai_text,
    rewrite_alert,
    persist,
    build_followup_prompt,
)
from tests.conftest import create_test_schema


# ---------------------------------------------------------------------------
# clean_ai_text
# ---------------------------------------------------------------------------

class TestCleanAiText:

    def test_removes_em_dash(self):
        assert '—' not in clean_ai_text("hello — world")

    def test_removes_en_dash(self):
        assert '–' not in clean_ai_text("step–by–step")

    def test_removes_bold_markers(self):
        assert '**' not in clean_ai_text("**important**")

    def test_replaces_em_dash_with_hyphen(self):
        assert clean_ai_text("a—b") == "a-b"

    def test_none_safe(self):
        assert clean_ai_text(None) == ''

    def test_empty_string(self):
        assert clean_ai_text('') == ''


# ---------------------------------------------------------------------------
# source_label / source_badge_class / source_icon
# ---------------------------------------------------------------------------

class TestSourceHelpers:

    @pytest.mark.parametrize("key,expected", [
        ('groq',      'Groq AI'),
        ('openai',    'OpenAI'),
        ('anthropic', 'Claude AI'),
        ('gemini',    'Gemini AI'),
        ('ollama',    'Local AI'),
        ('rules',     'Smart Template'),
        ('database',  'Data Query'),
    ])
    def test_source_label_known_keys(self, key, expected):
        assert source_label(key) == expected

    def test_source_label_unknown_returns_key(self):
        assert source_label('unknown_thing') == 'unknown_thing'

    def test_source_label_empty_returns_empty(self):
        assert source_label('') == ''

    def test_source_label_none_returns_empty(self):
        assert source_label(None) == ''

    @pytest.mark.parametrize("key,color", [
        ('groq',      'info'),
        ('openai',    'primary'),
        ('anthropic', 'dark'),
        ('gemini',    'success'),
        ('ollama',    'secondary'),
        ('rules',     'smart-template'),
    ])
    def test_source_badge_class_contains_color(self, key, color):
        cls = source_badge_class(key)
        assert f"bg-{color}" in cls

    def test_source_badge_class_unknown_uses_secondary(self):
        assert 'bg-secondary' in source_badge_class('unknown')

    def test_source_icon_known_key(self):
        assert source_icon('groq') == 'fa-bolt'
        assert source_icon('ollama') == 'fa-microchip'
        assert source_icon('anthropic') == 'fa-comment-dots'
        assert source_icon('gemini') == 'fa-gem'

    def test_source_icon_unknown_falls_back(self):
        assert source_icon('mystery') == 'fa-robot'


# ---------------------------------------------------------------------------
# build_prompt
# ---------------------------------------------------------------------------

class TestBuildPrompt:

    def test_contains_format_markers(self):
        result = build_prompt('MyDevice', 'high', 2, 'suspicious traffic')
        assert 'WHAT HAPPENED:' in result
        assert 'WORRY LEVEL:' in result
        assert 'TOP ACTION:' in result

    def test_interpolates_device_name(self):
        result = build_prompt('Smart Fridge', 'low', 0, 'normal traffic')
        assert 'Smart Fridge' in result

    def test_interpolates_severity(self):
        result = build_prompt('Device', 'critical', 5, 'exfiltration')
        assert 'critical' in result

    def test_no_recs_no_recs_section(self):
        result = build_prompt('D', 'low', 0, 'ping', recs=None)
        assert 'Available actions' not in result

    def test_recs_included_up_to_3(self):
        recs = [
            {'action': 'action one',   'confidence': 0.9},
            {'action': 'action two',   'confidence': 0.8},
            {'action': 'action three', 'confidence': 0.7},
            {'action': 'action four',  'confidence': 0.6},
        ]
        result = build_prompt('D', 'medium', 1, 'desc', recs=recs)
        assert 'action one' in result
        assert 'action two' in result
        assert 'action three' in result
        assert 'action four' not in result

    def test_recs_confidence_formatted_as_percent(self):
        recs = [{'action': 'block it', 'confidence': 0.75}]
        result = build_prompt('D', 'high', 0, 'desc', recs=recs)
        assert '75%' in result


# ---------------------------------------------------------------------------
# parse_ai_text
# ---------------------------------------------------------------------------

class TestParseAiText:

    def _make_text(self, what="Something happened", worry="Worth a quick check",
                   reason="Because of XYZ.", action="Check the logs."):
        return (
            f"WHAT HAPPENED: {what}\n"
            f"WORRY LEVEL: {worry}. {reason}\n"
            f"TOP ACTION: {action}"
        )

    def test_parses_what_happened(self):
        result = parse_ai_text(self._make_text())
        assert result['what_happened'] == 'Something happened'

    def test_parses_worry_level(self):
        result = parse_ai_text(self._make_text())
        assert result['worry_level'] == 'Worth a quick check'

    def test_parses_worry_reason(self):
        result = parse_ai_text(self._make_text(reason="Because of XYZ."))
        assert result['worry_reason'] == 'Because of XYZ.'

    def test_parses_top_action(self):
        result = parse_ai_text(self._make_text())
        assert result['top_action'] == 'Check the logs.'

    def test_worry_level_comma_separator(self):
        text = "WHAT HAPPENED: x\nWORRY LEVEL: Nothing to worry about, Your device is fine.\nTOP ACTION: y"
        result = parse_ai_text(text)
        assert result['worry_level'] == 'Nothing to worry about'
        assert result['worry_reason'] == 'Your device is fine.'

    def test_worry_level_dash_separator(self):
        text = "WHAT HAPPENED: x\nWORRY LEVEL: Take action now - Block immediately.\nTOP ACTION: y"
        result = parse_ai_text(text)
        assert result['worry_level'] == 'Take action now'

    def test_missing_what_happened_falls_back_to_ai_text(self):
        result = parse_ai_text("Some raw text without sections", tech_explanation="tech")
        assert result['what_happened'] == 'Some raw text without sections'

    def test_missing_all_sections_falls_back_to_tech_explanation(self):
        result = parse_ai_text("", tech_explanation="technical description")
        assert result['what_happened'] == 'technical description'

    def test_em_dashes_stripped_from_sections(self):
        text = "WHAT HAPPENED: a—b\nWORRY LEVEL: x\nTOP ACTION: y"
        result = parse_ai_text(text)
        assert '—' not in result['what_happened']


# ---------------------------------------------------------------------------
# rewrite_alert
# ---------------------------------------------------------------------------

class TestRewriteAlert:

    def _mock_ai(self, response_text="WHAT HAPPENED: x\nWORRY LEVEL: y\nTOP ACTION: z",
                 source="groq"):
        mock = MagicMock()
        mock.get_response.return_value = (response_text, source)
        return mock

    def _alert_row(self):
        return {
            'id': 1,
            'device_ip': '192.168.1.1',
            'device_name': 'Test Device',
            'severity': 'medium',
            'explanation': 'suspicious traffic',
        }

    def test_none_ai_returns_none(self):
        assert rewrite_alert(self._alert_row(), 1, [], None) is None

    def test_empty_ai_text_returns_none(self):
        mock = self._mock_ai(response_text='')
        assert rewrite_alert(self._alert_row(), 1, [], mock) is None

    def test_exception_returns_none(self):
        mock = MagicMock()
        mock.get_response.side_effect = RuntimeError("network error")
        assert rewrite_alert(self._alert_row(), 1, [], mock) is None

    def test_success_returns_sections_dict(self):
        mock = self._mock_ai()
        result = rewrite_alert(self._alert_row(), 1, [], mock)
        assert result is not None
        assert 'what_happened' in result
        assert 'top_action' in result

    def test_source_included_in_result(self):
        mock = self._mock_ai(source='ollama')
        result = rewrite_alert(self._alert_row(), 1, [], mock)
        assert result['_source'] == 'ollama'

    def test_prompt_uses_device_name(self):
        mock = self._mock_ai()
        rewrite_alert(self._alert_row(), 2, [], mock)
        call_kwargs = mock.get_response.call_args
        prompt_arg = call_kwargs[1].get('prompt') or call_kwargs[0][0]
        assert 'Test Device' in prompt_arg


# ---------------------------------------------------------------------------
# persist
# ---------------------------------------------------------------------------

class TestPersist:

    @pytest.fixture
    def db(self, tmp_path):
        from database.db_manager import DatabaseManager
        db_file = tmp_path / "test.db"
        mgr = DatabaseManager(str(db_file))
        create_test_schema(mgr)
        mgr._migrate_to_v2()
        # Add columns added by v7 and v9 migrations
        for stmt in [
            "ALTER TABLE alerts ADD COLUMN plain_explanation_ai INTEGER DEFAULT 0",
            "ALTER TABLE alerts ADD COLUMN ai_source TEXT",
        ]:
            try:
                mgr.conn.execute(stmt)
            except Exception:
                pass
        mgr.conn.execute(
            "INSERT OR IGNORE INTO devices (device_ip) VALUES (?)", ('192.168.1.1',))
        mgr.conn.commit()
        yield mgr
        mgr.close()
        DatabaseManager._instances.pop(str(Path(db_file).resolve()), None)

    def test_persist_writes_plain_explanation(self, db):
        aid = db.create_alert(
            device_ip='192.168.1.1', severity='low', anomaly_score=0.3,
            explanation='tech', top_features='{}',
        )
        persist(db, aid, 'plain text here', source='groq')
        row = db.conn.execute(
            "SELECT plain_explanation, plain_explanation_ai, ai_source "
            "FROM alerts WHERE id = ?", (aid,)
        ).fetchone()
        assert row[0] == 'plain text here'
        assert row[1] == 1
        assert row[2] == 'groq'

    def test_persist_truncates_to_500_chars(self, db):
        aid = db.create_alert(
            device_ip='192.168.1.1', severity='low', anomaly_score=0.3,
            explanation='tech', top_features='{}',
        )
        long_text = 'x' * 600
        persist(db, aid, long_text, source='rules')
        row = db.conn.execute(
            "SELECT plain_explanation FROM alerts WHERE id = ?", (aid,)
        ).fetchone()
        assert len(row[0]) == 500

    def test_persist_returns_true_on_success(self, db):
        aid = db.create_alert(
            device_ip='192.168.1.1', severity='low', anomaly_score=0.2,
            explanation='t', top_features='{}',
        )
        assert persist(db, aid, 'ok', source='rules') is True

    def test_persist_returns_false_on_error(self):
        mock_db = MagicMock()
        mock_db.conn.cursor.side_effect = Exception("db gone")
        assert persist(mock_db, 99, 'text') is False


# ---------------------------------------------------------------------------
# build_followup_prompt
# ---------------------------------------------------------------------------

class TestBuildFollowupPrompt:

    def _alert(self, **kw):
        base = {
            'device_name': 'Smart TV',
            'device_ip': '192.168.1.50',
            'severity': 'high',
            'explanation': 'unusual outbound traffic',
            'plain_explanation': 'Your Smart TV was sending lots of data.',
        }
        base.update(kw)
        return base

    def test_context_contains_device_name(self):
        prompt, ctx = build_followup_prompt(
            self._alert(), 3, [], [], [], "Why is this bad?"
        )
        assert 'Smart TV' in ctx

    def test_context_contains_severity(self):
        prompt, ctx = build_followup_prompt(
            self._alert(), 3, [], [], [], "What should I do?"
        )
        assert 'high' in ctx

    def test_context_contains_trigger_text(self):
        prompt, ctx = build_followup_prompt(
            self._alert(), 1, [], [], [], "Is my data safe?"
        )
        assert 'Your Smart TV was sending lots of data.' in ctx

    def test_context_includes_destinations_when_present(self):
        dests = ['8.8.8.8', '1.1.1.1']
        prompt, ctx = build_followup_prompt(
            self._alert(), 2, dests, [], [], "Why?"
        )
        assert '8.8.8.8' in ctx

    def test_context_omits_destinations_when_empty(self):
        prompt, ctx = build_followup_prompt(
            self._alert(), 1, [], [], [], "Why?"
        )
        assert 'Recent destinations' not in ctx

    def test_context_includes_recs(self):
        recs = [{'action': 'Block device'}, {'action': 'Check firewall'}]
        prompt, ctx = build_followup_prompt(
            self._alert(), 1, [], recs, [], "What to do?"
        )
        assert 'Block device' in ctx

    def test_prompt_contains_question(self):
        prompt, _ = build_followup_prompt(
            self._alert(), 1, [], [], [], "Is my data safe?"
        )
        assert 'Is my data safe?' in prompt

    def test_history_bounded_to_last_4(self):
        history = [
            {'role': 'user',      'content': f'question {i}', 'timestamp': ''}
            for i in range(10)
        ]
        prompt, _ = build_followup_prompt(
            self._alert(), 1, [], [], history, "new question"
        )
        # Only last 4 history turns should feed into the prompt
        assert 'question 9' in prompt or 'question 8' in prompt
        assert 'question 0' not in prompt

    def test_system_role_excluded_from_history(self):
        history = [
            {'role': 'system',    'content': 'sys prompt', 'timestamp': ''},
            {'role': 'user',      'content': 'user msg',   'timestamp': ''},
            {'role': 'assistant', 'content': 'ai reply',   'timestamp': ''},
        ]
        prompt, _ = build_followup_prompt(
            self._alert(), 1, [], [], history, "q"
        )
        assert 'sys prompt' not in prompt

    def test_returns_two_strings(self):
        result = build_followup_prompt(self._alert(), 1, [], [], [], "q")
        assert len(result) == 2
        assert all(isinstance(s, str) for s in result)
