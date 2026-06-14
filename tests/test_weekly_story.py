#!/usr/bin/env python3
"""
Unit tests for utils/weekly_story.py.

Covers:
- _facts_to_text: bandwidth pct math, conditional lines (ai_exp, auto, busiest)
- _template_fallback: mood thresholds (<3, <10, ≥10), singular/plural, conditional paragraphs
- generate_story: None ai / no-provider / source=='rules' / success / exception paths
- build_facts: queries run against a test DB (partial schema tolerance)

Run: pytest tests/test_weekly_story.py -v
"""
import sys
import pytest
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.weekly_story import (
    _facts_to_text,
    _template_fallback,
    generate_story,
    build_facts,
)
from tests.conftest import create_test_schema


# ---------------------------------------------------------------------------
# _facts_to_text
# ---------------------------------------------------------------------------

class TestFactsToText:

    def _base_facts(self):
        return {
            'alerts_total': 5, 'alerts_critical': 1, 'alerts_high': 2,
            'alerts_handled': 3, 'alerts_ai_explained': 2,
            'agent_actions_auto': 1, 'new_devices': 2, 'active_devices': 8,
            'bytes_this_week': 0, 'bytes_prev_week': 0, 'busiest_device': None,
        }

    def test_total_alerts_included(self):
        text = _facts_to_text(self._base_facts())
        assert '5' in text

    def test_ai_explained_line_appears_when_nonzero(self):
        text = _facts_to_text(self._base_facts())
        assert 'plain English' in text.lower() or 'AI' in text

    def test_ai_explained_line_absent_when_zero(self):
        facts = self._base_facts()
        facts['alerts_ai_explained'] = 0
        text = _facts_to_text(facts)
        assert 'explained by AI' not in text

    def test_auto_actions_line_appears_when_nonzero(self):
        text = _facts_to_text(self._base_facts())
        assert 'automatically' in text.lower() or 'agent' in text.lower()

    def test_bandwidth_line_with_prev_week(self):
        facts = self._base_facts()
        facts['bytes_this_week'] = 200_000_000   # 200 MB
        facts['bytes_prev_week'] = 100_000_000   # 100 MB → +100%
        text = _facts_to_text(facts)
        assert '200' in text
        assert '+100%' in text

    def test_bandwidth_line_no_prev_week(self):
        facts = self._base_facts()
        facts['bytes_this_week'] = 50_000_000
        facts['bytes_prev_week'] = 0
        text = _facts_to_text(facts)
        assert '50' in text
        assert '%' not in text

    def test_bandwidth_line_absent_when_zero(self):
        facts = self._base_facts()
        facts['bytes_this_week'] = 0
        text = _facts_to_text(facts)
        assert 'MB' not in text

    def test_busiest_device_included(self):
        facts = self._base_facts()
        facts['busiest_device'] = 'Smart TV'
        facts['busiest_device_conns'] = 42
        text = _facts_to_text(facts)
        assert 'Smart TV' in text
        assert '42' in text


# ---------------------------------------------------------------------------
# _template_fallback
# ---------------------------------------------------------------------------

class TestTemplateFallback:

    def _facts(self, **kw):
        base = {
            'alerts_total': 0, 'alerts_critical': 0, 'alerts_handled': 0,
            'new_devices': 0, 'agent_actions_auto': 0, 'bytes_this_week': 0,
        }
        base.update(kw)
        return base

    def test_mood_quiet_for_low_alerts(self):
        text = _template_fallback(self._facts(alerts_total=2))
        assert 'quiet' in text.lower()

    def test_mood_moderately_active(self):
        text = _template_fallback(self._facts(alerts_total=5))
        assert 'moderately active' in text.lower()

    def test_mood_busy_for_many_alerts(self):
        text = _template_fallback(self._facts(alerts_total=15))
        assert 'busy' in text.lower()

    def test_no_critical_note(self):
        text = _template_fallback(self._facts(alerts_total=3, alerts_critical=0))
        assert 'none were critical' in text

    def test_critical_count_shown(self):
        text = _template_fallback(self._facts(alerts_total=3, alerts_critical=2))
        assert '2 needed immediate attention' in text

    def test_new_device_singular(self):
        text = _template_fallback(self._facts(new_devices=1))
        assert '1 new device joined' in text

    def test_new_device_plural(self):
        text = _template_fallback(self._facts(new_devices=3))
        assert '3 new devices joined' in text

    def test_auto_actions_paragraph_when_nonzero(self):
        text = _template_fallback(self._facts(agent_actions_auto=2))
        assert '2 situations' in text or '2 situation' in text

    def test_bandwidth_note_when_present(self):
        text = _template_fallback(self._facts(bytes_this_week=100_000_000))
        assert '100 MB' in text

    def test_closes_with_monitoring_sentence(self):
        text = _template_fallback(self._facts())
        assert 'monitored' in text.lower()


# ---------------------------------------------------------------------------
# generate_story
# ---------------------------------------------------------------------------

class TestGenerateStory:

    def _mock_ai(self, response_text="Great week.", source="groq",
                 has_llm=True, raise_exc=False):
        mock = MagicMock()
        mock.has_llm_provider.return_value = has_llm
        if raise_exc:
            mock.get_response.side_effect = RuntimeError("timeout")
        else:
            mock.get_response.return_value = (response_text, source)
        return mock

    def _facts(self):
        return {'alerts_total': 2, 'alerts_critical': 0, 'alerts_high': 0,
                'alerts_handled': 1, 'alerts_ai_explained': 0,
                'agent_actions_auto': 0, 'new_devices': 0, 'active_devices': 4,
                'bytes_this_week': 0, 'bytes_prev_week': 0, 'busiest_device': None}

    def test_none_ai_returns_template_fallback(self):
        text, source = generate_story(self._facts(), None)
        assert text
        assert source == 'rules'

    def test_no_llm_provider_returns_template_fallback(self):
        mock = self._mock_ai(has_llm=False)
        text, source = generate_story(self._facts(), mock)
        assert source == 'rules'

    def test_source_rules_response_returns_template_fallback(self):
        mock = self._mock_ai(response_text="some text", source='rules')
        text, source = generate_story(self._facts(), mock)
        assert source == 'rules'

    def test_empty_llm_response_returns_template_fallback(self):
        mock = self._mock_ai(response_text='')
        text, source = generate_story(self._facts(), mock)
        assert source == 'rules'

    def test_exception_returns_template_fallback(self):
        mock = self._mock_ai(raise_exc=True)
        text, source = generate_story(self._facts(), mock)
        assert source == 'rules'
        assert text

    def test_success_returns_llm_text(self):
        mock = self._mock_ai(response_text="Everything was fine this week.", source='groq')
        text, source = generate_story(self._facts(), mock)
        assert 'Everything was fine' in text
        assert source == 'groq'

    def test_em_dashes_stripped_from_llm_response(self):
        mock = self._mock_ai(response_text="Good week — no issues.", source='groq')
        text, _ = generate_story(self._facts(), mock)
        assert '—' not in text

    def test_bold_stripped_from_llm_response(self):
        mock = self._mock_ai(response_text="**Critical** week.", source='openai')
        text, _ = generate_story(self._facts(), mock)
        assert '**' not in text

    def test_always_returns_nonempty_text(self):
        text, _ = generate_story(self._facts(), None)
        assert len(text) > 10


# ---------------------------------------------------------------------------
# build_facts — real DB queries
# ---------------------------------------------------------------------------

class TestBuildFacts:

    @pytest.fixture
    def db(self, tmp_path):
        from database.db_manager import DatabaseManager
        db_file = tmp_path / "test.db"
        mgr = DatabaseManager(str(db_file))
        create_test_schema(mgr)
        # Add the extra column build_facts needs
        try:
            mgr.conn.execute(
                "ALTER TABLE alerts ADD COLUMN plain_explanation_ai INTEGER DEFAULT 0"
            )
        except Exception:
            pass
        mgr.conn.execute(
            "INSERT OR IGNORE INTO devices (device_ip) VALUES (?)", ('10.0.0.1',))
        mgr.conn.commit()
        yield mgr
        mgr.close()
        DatabaseManager._instances.pop(str(Path(db_file).resolve()), None)

    def test_returns_dict(self, db):
        assert isinstance(build_facts(db), dict)

    def test_alert_counts_with_no_alerts(self, db):
        facts = build_facts(db)
        assert facts.get('alerts_total', 0) == 0
        assert facts.get('alerts_critical', 0) == 0

    def test_alert_counts_with_data(self, db):
        db.create_alert(
            device_ip='10.0.0.1', severity='high', anomaly_score=0.9,
            explanation='test', top_features='{}',
        )
        facts = build_facts(db)
        assert facts['alerts_total'] >= 1
        assert facts['alerts_high'] >= 1

    def test_new_devices_count(self, db):
        facts = build_facts(db)
        assert 'new_devices' in facts

    def test_missing_agent_actions_table_defaults_to_zero(self, db):
        facts = build_facts(db)
        assert facts.get('agent_actions_total', 0) == 0
        assert facts.get('agent_actions_auto', 0) == 0

    def test_missing_incidents_table_defaults_to_zero(self, db):
        facts = build_facts(db)
        assert facts.get('incidents_total', 0) == 0
