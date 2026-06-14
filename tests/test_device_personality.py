#!/usr/bin/env python3
"""
Unit tests for utils/device_personality.py (Device Personality Profiles).

Covers:
- _facts_to_text: baseline lines, peak hours, today stats, alert counts
- _template_fallback: name/type, alert count, peak hours, active hours note
- generate_personality: None ai / no-provider / source=='rules' / success / exception
- build_profile_facts: real DB queries, graceful degradation on missing tables

Run: pytest tests/test_device_personality.py -v
"""
import sys
import pytest
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.device_personality import (
    _facts_to_text,
    _template_fallback,
    generate_personality,
    build_profile_facts,
    PERSONALITY_TTL,
)
from tests.conftest import create_test_schema


# ---------------------------------------------------------------------------
# _facts_to_text
# ---------------------------------------------------------------------------

class TestFactsToText:

    def _base(self):
        return {
            'device_ip': '192.168.1.10',
            'device_name': 'Smart TV',
            'device_type': 'Television',
            'total_alerts': 0,
            'has_baseline': True,
            'avg_connections': 12.5,
            'avg_bytes_sent': 50_000,
            'avg_unique_destinations': 4.2,
            'today_connections': 30,
            'today_bytes_sent': 2_000_000,
            'today_bytes_recv': 5_000_000,
            'today_unique_dests': 5,
            'peak_hour_range': '18:00-22:00',
            'last_alert_date': None,
        }

    def test_device_name_included(self):
        text = _facts_to_text(self._base())
        assert 'Smart TV' in text

    def test_baseline_connections_included(self):
        text = _facts_to_text(self._base())
        assert 'connections' in text.lower()

    def test_peak_hours_included(self):
        text = _facts_to_text(self._base())
        assert '18:00-22:00' in text

    def test_today_connections_included(self):
        text = _facts_to_text(self._base())
        assert '30' in text

    def test_no_alerts_message(self):
        text = _facts_to_text(self._base())
        assert 'none' in text.lower()

    def test_alerts_count_shown(self):
        facts = self._base()
        facts['total_alerts'] = 7
        facts['last_alert_date'] = '2026-06-05T10:30:00'
        text = _facts_to_text(facts)
        assert '7' in text

    def test_no_baseline_note(self):
        facts = self._base()
        facts['has_baseline'] = False
        text = _facts_to_text(facts)
        assert 'Baseline not yet' in text or 'baseline' in text.lower()

    def test_peak_hours_absent_when_none(self):
        facts = self._base()
        facts['peak_hour_range'] = None
        text = _facts_to_text(facts)
        assert 'Peak activity' not in text


# ---------------------------------------------------------------------------
# _template_fallback
# ---------------------------------------------------------------------------

class TestTemplateFallback:

    def _facts(self, **kw):
        base = {
            'device_ip': '192.168.1.1',
            'device_name': 'Security Camera',
            'device_type': 'Camera',
            'total_alerts': 0,
            'has_baseline': False,
            'today_connections': 0,
            'avg_unique_destinations': 0,
            'peak_hour_range': None,
        }
        base.update(kw)
        return base

    def test_includes_device_name(self):
        text = _template_fallback(self._facts())
        assert 'Security Camera' in text

    def test_includes_device_type(self):
        text = _template_fallback(self._facts())
        assert 'camera' in text.lower()

    def test_no_alerts_message(self):
        text = _template_fallback(self._facts(total_alerts=0))
        assert 'No security alerts' in text

    def test_alert_count_shown(self):
        text = _template_fallback(self._facts(total_alerts=3))
        assert '3' in text

    def test_peak_hours_shown_when_present(self):
        text = _template_fallback(self._facts(peak_hour_range='20:00-23:00'))
        assert '20:00-23:00' in text

    def test_typical_destinations_shown_when_nonzero(self):
        text = _template_fallback(self._facts(avg_unique_destinations=5))
        assert '5' in text

    def test_monitoring_sentence_always_present(self):
        text = _template_fallback(self._facts())
        assert 'watching' in text.lower() or 'monitored' in text.lower()


# ---------------------------------------------------------------------------
# generate_personality
# ---------------------------------------------------------------------------

class TestGeneratePersonality:

    def _mock_ai(self, response_text="This device is well-behaved.", source='groq',
                 has_llm=True, raise_exc=False):
        mock = MagicMock()
        mock.has_llm_provider.return_value = has_llm
        if raise_exc:
            mock.get_response.side_effect = RuntimeError("timeout")
        else:
            mock.get_response.return_value = (response_text, source)
        return mock

    def _facts(self):
        return {
            'device_ip': '192.168.1.5',
            'device_name': 'Smart Fridge',
            'device_type': 'Appliance',
            'total_alerts': 0,
            'has_baseline': False,
            'today_connections': 5,
            'avg_unique_destinations': 2,
            'peak_hour_range': None,
            'today_bytes_sent': 0, 'today_bytes_recv': 0, 'today_unique_dests': 2,
            'last_alert_date': None,
        }

    def test_none_ai_returns_template(self):
        text, source = generate_personality(self._facts(), None)
        assert text
        assert source == 'rules'

    def test_no_llm_provider_returns_template(self):
        mock = self._mock_ai(has_llm=False)
        text, source = generate_personality(self._facts(), mock)
        assert source == 'rules'

    def test_rules_source_returns_template(self):
        mock = self._mock_ai(response_text="x", source='rules')
        text, source = generate_personality(self._facts(), mock)
        assert source == 'rules'

    def test_empty_llm_response_returns_template(self):
        mock = self._mock_ai(response_text='')
        text, source = generate_personality(self._facts(), mock)
        assert source == 'rules'

    def test_exception_returns_template(self):
        mock = self._mock_ai(raise_exc=True)
        text, source = generate_personality(self._facts(), mock)
        assert source == 'rules'
        assert text

    def test_success_returns_llm_text_and_source(self):
        mock = self._mock_ai(response_text="A quiet device.", source='groq')
        text, source = generate_personality(self._facts(), mock)
        assert 'A quiet device.' in text
        assert source == 'groq'

    def test_em_dashes_stripped(self):
        mock = self._mock_ai(response_text="Behaves well — very quiet.", source='groq')
        text, _ = generate_personality(self._facts(), mock)
        assert '—' not in text

    def test_bold_markers_stripped(self):
        mock = self._mock_ai(response_text="**Always** online.", source='openai')
        text, _ = generate_personality(self._facts(), mock)
        assert '**' not in text

    def test_always_returns_something(self):
        text, source = generate_personality(self._facts(), None)
        assert len(text) > 10

    def test_personality_ttl_is_positive(self):
        assert PERSONALITY_TTL > 0


# ---------------------------------------------------------------------------
# build_profile_facts — real DB queries
# ---------------------------------------------------------------------------

class TestBuildProfileFacts:

    @pytest.fixture
    def db(self, tmp_path):
        from database.db_manager import DatabaseManager
        db_file = tmp_path / "test.db"
        mgr = DatabaseManager(str(db_file))
        create_test_schema(mgr)
        # Ensure device_behavior_baselines table exists
        try:
            mgr.conn.execute("""
                CREATE TABLE IF NOT EXISTS device_behavior_baselines (
                    device_ip TEXT, metric_name TEXT, baseline_value REAL,
                    std_deviation REAL, min_value REAL, max_value REAL,
                    sample_count INTEGER,
                    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (device_ip, metric_name)
                )
            """)
        except Exception:
            pass
        mgr.conn.execute(
            "INSERT OR IGNORE INTO devices (device_ip, device_name, device_type) "
            "VALUES (?, ?, ?)",
            ('192.168.1.1', 'Test Device', 'Router'),
        )
        mgr.conn.commit()
        yield mgr
        mgr.close()
        DatabaseManager._instances.pop(str(Path(db_file).resolve()), None)

    def test_returns_dict_with_device_ip(self, db):
        facts = build_profile_facts(db, '192.168.1.1')
        assert facts['device_ip'] == '192.168.1.1'

    def test_device_name_populated(self, db):
        facts = build_profile_facts(db, '192.168.1.1')
        assert facts.get('device_name') == 'Test Device'

    def test_unknown_device_falls_back_gracefully(self, db):
        facts = build_profile_facts(db, '10.99.99.99')
        assert facts['device_ip'] == '10.99.99.99'
        assert facts.get('device_name') == '10.99.99.99'

    def test_has_baseline_false_with_no_baseline_rows(self, db):
        facts = build_profile_facts(db, '192.168.1.1')
        assert facts.get('has_baseline') is False

    def test_has_baseline_true_with_rows(self, db):
        db.conn.execute(
            "INSERT OR REPLACE INTO device_behavior_baselines "
            "(device_ip, metric_name, baseline_value) VALUES (?, ?, ?)",
            ('192.168.1.1', 'hourly_connections', 8.5),
        )
        db.conn.commit()
        facts = build_profile_facts(db, '192.168.1.1')
        assert facts.get('has_baseline') is True
        assert facts.get('avg_connections') == pytest.approx(8.5)

    def test_today_stats_defaults_to_zero(self, db):
        facts = build_profile_facts(db, '192.168.1.1')
        assert facts.get('today_connections', 0) == 0

    def test_today_connections_counted(self, db):
        db.conn.execute(
            "INSERT INTO connections (device_ip, dest_ip, bytes_sent, bytes_received, "
            "timestamp) VALUES (?, ?, ?, ?, datetime('now'))",
            ('192.168.1.1', '8.8.8.8', 1000, 2000),
        )
        db.conn.commit()
        facts = build_profile_facts(db, '192.168.1.1')
        assert facts.get('today_connections', 0) >= 1

    def test_peak_hours_none_when_no_connections(self, db):
        facts = build_profile_facts(db, '192.168.1.1')
        assert facts.get('peak_hours') == []
        assert facts.get('peak_hour_range') is None

    def test_peak_hour_range_format(self, db):
        # Insert connections at 20:00
        db.conn.execute(
            "INSERT INTO connections (device_ip, dest_ip, bytes_sent, bytes_received, "
            "timestamp) VALUES (?, ?, ?, ?, datetime('now', '-1 day', '+20 hours'))",
            ('192.168.1.1', '1.1.1.1', 500, 100),
        )
        db.conn.commit()
        facts = build_profile_facts(db, '192.168.1.1')
        if facts.get('peak_hour_range'):
            assert ':00' in facts['peak_hour_range']
