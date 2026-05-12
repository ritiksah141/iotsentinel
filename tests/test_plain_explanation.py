#!/usr/bin/env python3
"""
Unit tests for Phase 4 — Plain-English alert explainability.

Covers:
- _generate_plain_explanation() produces non-empty text for every severity tier
- _generate_plain_explanation() maps to correct MITRE tactic text
- plain_explanation column round-trips through db_manager.create_alert / get_recent_alerts
- DB migration v2 is idempotent (no error if column already exists)
- Alert dataclass accepts plain_explanation field
- alert_service.create_alert passes plain_explanation through to db

Run: pytest tests/test_plain_explanation.py -v
"""
import sys
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from ml.inference_engine import InferenceEngine
from tests.conftest import create_test_schema


def _plain(conn, tactic):
    """Call _generate_plain_explanation without constructing a full InferenceEngine."""
    return InferenceEngine._generate_plain_explanation(None, conn, tactic)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# _generate_plain_explanation — deterministic template logic
# ---------------------------------------------------------------------------

class TestGeneratePlainExplanation:

    def test_exfiltration_tactic_returns_sentence(self):
        conn = {'device_ip': '192.168.1.5', 'bytes_sent': 50_000_000, 'dest_port': 443}
        result = _plain(conn, "Exfiltration (TA0010)")
        assert result
        assert '192.168.1.5' in result
        assert len(result) > 20

    def test_lateral_movement_tactic_returns_sentence(self):
        conn = {'device_ip': '192.168.1.10', 'bytes_sent': 0, 'dest_port': 22}
        result = _plain(conn, "Lateral Movement (TA0008)")
        assert result
        assert '192.168.1.10' in result

    def test_discovery_tactic_returns_sentence(self):
        conn = {'device_ip': '10.0.0.5', 'dest_port': 80}
        result = _plain(conn, "Discovery (TA0007)")
        assert result
        assert '10.0.0.5' in result

    def test_command_and_control_tactic(self):
        conn = {'device_ip': '192.168.1.20', 'dest_port': 4444}
        result = _plain(conn, "Command and Control (TA0011)")
        assert result
        assert any(w in result.lower() for w in ('hacker', 'immediate', 'address', 'associated'))

    def test_unknown_tactic_fallback_uses_bytes(self):
        conn = {'device_ip': '192.168.1.99', 'bytes_sent': 20_000_000, 'dest_port': 9999}
        result = _plain(conn, "Unknown - something odd")
        assert result
        assert '192.168.1.99' in result

    def test_unknown_tactic_fallback_no_bytes(self):
        conn = {'device_ip': '192.168.1.50', 'bytes_sent': 0, 'dest_port': 9999}
        result = _plain(conn, "Unknown - Further investigation")
        assert result
        assert len(result) > 10

    def test_all_tactic_keys_produce_output(self):
        conn = {'device_ip': '10.0.0.1', 'bytes_sent': 0}
        for tactic_key in InferenceEngine._PLAIN_TACTIC_MAP:
            result = _plain(conn, f"{tactic_key} (TA0001)")
            assert result, f"No output for tactic key '{tactic_key}'"
            assert '10.0.0.1' in result


# ---------------------------------------------------------------------------
# Alert dataclass
# ---------------------------------------------------------------------------

class TestAlertDataclass:

    def test_plain_explanation_field_defaults_none(self):
        from alerts.alert_service import Alert
        a = Alert(device_ip='1.2.3.4', severity='low', anomaly_score=0.5, explanation='test')
        assert a.plain_explanation is None

    def test_plain_explanation_accepts_string(self):
        from alerts.alert_service import Alert
        a = Alert(device_ip='1.2.3.4', severity='low', anomaly_score=0.5,
                  explanation='tech', plain_explanation='plain')
        assert a.plain_explanation == 'plain'

    def test_plain_explanation_in_to_dict(self):
        from alerts.alert_service import Alert
        a = Alert(device_ip='1.2.3.4', severity='medium', anomaly_score=0.6,
                  explanation='tech', plain_explanation='plain sentence')
        d = a.to_dict()
        assert 'plain_explanation' in d
        assert d['plain_explanation'] == 'plain sentence'


# ---------------------------------------------------------------------------
# db_manager.create_alert and round-trip
# ---------------------------------------------------------------------------

class TestDbManagerPlainExplanation:

    @pytest.fixture
    def db(self, tmp_path):
        from database.db_manager import DatabaseManager
        from pathlib import Path
        db_file = tmp_path / "test.db"
        mgr = DatabaseManager(str(db_file))
        create_test_schema(mgr)
        mgr.conn.execute(
            "INSERT OR IGNORE INTO devices (device_ip) VALUES (?)", ('192.168.1.1',))
        mgr.conn.commit()
        yield mgr
        mgr.close()
        DatabaseManager._instances.pop(str(Path(db_file).resolve()), None)

    def test_create_alert_stores_plain_explanation(self, db):
        aid = db.create_alert(
            device_ip='192.168.1.1',
            severity='medium',
            anomaly_score=0.75,
            explanation='Technical jargon',
            top_features='{}',
            plain_explanation='Your smart TV is sending lots of data.',
        )
        assert aid is not None
        row = db.conn.execute(
            "SELECT plain_explanation FROM alerts WHERE id = ?", (aid,)
        ).fetchone()
        assert row[0] == 'Your smart TV is sending lots of data.'

    def test_create_alert_plain_explanation_optional(self, db):
        aid = db.create_alert(
            device_ip='192.168.1.1',
            severity='low',
            anomaly_score=0.4,
            explanation='Some technical explanation',
            top_features='{}',
        )
        assert aid is not None
        row = db.conn.execute(
            "SELECT plain_explanation FROM alerts WHERE id = ?", (aid,)
        ).fetchone()
        assert row[0] is None

    def test_migration_v2_idempotent(self, db):
        """Running _migrate_to_v2 twice should not raise."""
        db._migrate_to_v2()
        db._migrate_to_v2()  # Second call — column already exists, must not error


# ---------------------------------------------------------------------------
# alert_service.create_alert passes plain_explanation to db
# ---------------------------------------------------------------------------

class TestAlertServicePassthrough:

    def test_create_alert_passes_plain_explanation_to_db(self):
        from alerts.alert_service import AlertService
        mock_db = MagicMock()
        mock_db.create_alert.return_value = 42
        svc = AlertService.__new__(AlertService)
        svc.db = mock_db
        svc.rate_limiter = MagicMock()
        svc.rate_limiter.should_send.return_value = (True, "ok")
        svc._dispatcher = None

        with patch.object(svc, '_get_device_name', return_value='Test Device'):
            svc.create_alert(
                device_ip='192.168.1.1',
                severity='high',
                anomaly_score=0.9,
                explanation='tech',
                plain_explanation='plain sentence',
            )

        call_kwargs = mock_db.create_alert.call_args[1]
        assert call_kwargs.get('plain_explanation') == 'plain sentence'

    def test_create_alert_without_plain_passes_none(self):
        from alerts.alert_service import AlertService
        mock_db = MagicMock()
        mock_db.create_alert.return_value = 1
        svc = AlertService.__new__(AlertService)
        svc.db = mock_db
        svc.rate_limiter = MagicMock()
        svc.rate_limiter.should_send.return_value = (True, "ok")
        svc._dispatcher = None

        with patch.object(svc, '_get_device_name', return_value='x'):
            svc.create_alert(
                device_ip='192.168.1.2',
                severity='low',
                anomaly_score=0.3,
                explanation='tech',
            )

        call_kwargs = mock_db.create_alert.call_args[1]
        assert call_kwargs.get('plain_explanation') is None
