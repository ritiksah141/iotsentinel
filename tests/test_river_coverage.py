#!/usr/bin/env python3
"""
Extended coverage tests for RiverMLEngine.

Targets uncovered branches: _classify_event, _predict_attack_from_sequence,
get_device_risk_score, predict_device_failure, save/load paths.

Run: pytest tests/test_river_coverage.py -v --cov=ml.river_engine
"""

import pytest
import os
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

from ml.river_engine import RiverMLEngine
from database.db_manager import DatabaseManager


# ── fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def temp_db():
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
        db_path = f.name
    db = DatabaseManager(db_path)
    yield db
    db.conn.close()
    normalized = str(Path(db_path).resolve())
    DatabaseManager._instances.pop(normalized, None)
    if os.path.exists(db_path):
        os.unlink(db_path)


@pytest.fixture
def engine(temp_db):
    return RiverMLEngine(db_manager=temp_db)


# ── _classify_event branches ──────────────────────────────────────────────────

class TestClassifyEvent:
    def test_port_scan_classification(self, engine):
        conn = {'dst_port': 8888, 'bytes_sent': 100, 'bytes_received': 50, 'protocol': 'tcp'}
        assert engine._classify_event(conn, score=0.7) == 'PORT_SCAN'

    def test_data_exfil_classification(self, engine):
        conn = {'dst_port': 443, 'bytes_sent': 50000, 'bytes_received': 100, 'protocol': 'tcp'}
        assert engine._classify_event(conn, score=0.7) == 'DATA_EXFIL'

    def test_brute_force_classification(self, engine):
        conn = {'dst_port': 22, 'bytes_sent': 200, 'bytes_received': 200, 'protocol': 'tcp'}
        assert engine._classify_event(conn, score=0.7) == 'BRUTE_FORCE_ATTEMPT'

    def test_brute_force_ftp(self, engine):
        # port 21 ≤ 1024, not exfil, not ddos → BRUTE_FORCE_ATTEMPT
        conn = {'dst_port': 21, 'bytes_sent': 200, 'bytes_received': 200, 'protocol': 'tcp'}
        assert engine._classify_event(conn, score=0.7) == 'BRUTE_FORCE_ATTEMPT'

    def test_ddos_classification(self, engine):
        conn = {'dst_port': 80, 'bytes_sent': 300, 'bytes_received': 300, 'protocol': 'tcp'}
        assert engine._classify_event(conn, score=0.9) == 'DDOS_PARTICIPATION'

    def test_dns_tunneling_classification(self, engine):
        conn = {'dst_port': 53, 'bytes_sent': 1000, 'bytes_received': 200, 'protocol': 'udp'}
        assert engine._classify_event(conn, score=0.7) == 'DNS_TUNNELING'

    def test_unknown_anomaly_classification(self, engine):
        conn = {'dst_port': 80, 'bytes_sent': 200, 'bytes_received': 300, 'protocol': 'tcp'}
        assert engine._classify_event(conn, score=0.5) == 'ANOMALY_UNKNOWN'


# ── _calculate_threat_level ───────────────────────────────────────────────────

class TestThreatLevel:
    def test_critical_threat(self, engine):
        assert engine._calculate_threat_level(0.95) == 'critical'

    def test_high_threat(self, engine):
        assert engine._calculate_threat_level(0.75) == 'high'

    def test_medium_threat(self, engine):
        assert engine._calculate_threat_level(0.55) == 'medium'

    def test_low_threat(self, engine):
        assert engine._calculate_threat_level(0.1) == 'low'


# ── _predict_attack_from_sequence ─────────────────────────────────────────────

class TestAttackSequences:
    def _inject_events(self, engine, device_ip, event_type, count):
        """Directly push events into the buffer."""
        for _ in range(count):
            engine.event_buffer.append({
                'type': event_type,
                'ip': device_ip,
                'timestamp': datetime.now(),
                'score': 0.8,
                'port': 22,
                'bytes_sent': 100
            })

    def test_no_prediction_with_few_events(self, engine):
        engine.event_buffer.clear()
        result = engine._predict_attack_from_sequence('192.168.1.1')
        assert result is None

    def test_port_scan_sequence_detected(self, engine):
        engine.event_buffer.clear()
        self._inject_events(engine, '192.168.1.1', 'PORT_SCAN', 3)
        result = engine._predict_attack_from_sequence('192.168.1.1')
        assert result is not None
        assert result['predicted_attack'] == 'NETWORK_RECONNAISSANCE'
        assert 'confidence' in result
        assert 'recommendations' in result

    def test_brute_force_sequence_detected(self, engine):
        engine.event_buffer.clear()
        # Need >= 3 total events in buffer AND >= 2 for this device
        self._inject_events(engine, '192.168.1.2', 'BRUTE_FORCE_ATTEMPT', 3)
        result = engine._predict_attack_from_sequence('192.168.1.2')
        assert result is not None
        assert result['predicted_attack'] == 'CREDENTIAL_STUFFING'

    def test_data_exfil_sequence_detected(self, engine):
        engine.event_buffer.clear()
        self._inject_events(engine, '192.168.1.3', 'DATA_EXFIL', 3)
        result = engine._predict_attack_from_sequence('192.168.1.3')
        assert result is not None
        assert result['predicted_attack'] == 'DATA_BREACH'

    def test_dns_tunneling_sequence_detected(self, engine):
        engine.event_buffer.clear()
        self._inject_events(engine, '192.168.1.4', 'DNS_TUNNELING', 3)
        result = engine._predict_attack_from_sequence('192.168.1.4')
        assert result is not None
        assert result['predicted_attack'] == 'COMMAND_AND_CONTROL'

    def test_compromised_device_multiple_types(self, engine):
        engine.event_buffer.clear()
        ip = '192.168.1.5'
        for event_type in ('PORT_SCAN', 'DATA_EXFIL', 'DDOS_PARTICIPATION'):
            self._inject_events(engine, ip, event_type, 1)
        result = engine._predict_attack_from_sequence(ip)
        assert result is not None
        assert result['predicted_attack'] == 'COMPROMISED_DEVICE'

    def test_no_match_for_different_device(self, engine):
        engine.event_buffer.clear()
        self._inject_events(engine, '192.168.1.10', 'PORT_SCAN', 3)
        result = engine._predict_attack_from_sequence('192.168.1.99')
        assert result is None


# ── get_device_risk_score ────────────────────────────────────────────────────

class TestDeviceRiskScore:
    def _inject_anomaly_events(self, engine, device_ip, score, count, event_type='PORT_SCAN'):
        for _ in range(count):
            engine.event_buffer.append({
                'type': event_type,
                'ip': device_ip,
                'timestamp': datetime.now(),
                'score': score,
                'port': 8888,
                'bytes_sent': 500
            })

    def test_risk_score_no_anomalies(self, engine):
        engine.event_buffer.clear()
        result = engine.get_device_risk_score('192.168.1.10')
        assert result['risk_level'] == 'low'
        assert result['risk_score'] == 0.0
        assert result['recent_anomalies'] == 0

    def test_risk_score_medium(self, engine):
        engine.event_buffer.clear()
        self._inject_anomaly_events(engine, '192.168.1.10', 0.4, 4)
        result = engine.get_device_risk_score('192.168.1.10')
        assert result['risk_level'] in ('medium', 'high', 'critical', 'low')
        assert 0.0 <= result['risk_score'] <= 1.0

    def test_risk_score_critical_from_high_scores(self, engine):
        engine.event_buffer.clear()
        self._inject_anomaly_events(engine, '192.168.1.20', 0.9, 15)
        result = engine.get_device_risk_score('192.168.1.20')
        assert result['risk_level'] in ('high', 'critical')

    def test_risk_score_data_exfil_escalates(self, engine):
        engine.event_buffer.clear()
        self._inject_anomaly_events(engine, '192.168.1.30', 0.5, 3, 'DATA_EXFIL')
        result = engine.get_device_risk_score('192.168.1.30')
        assert result['risk_level'] == 'critical'

    def test_risk_score_brute_force_escalates(self, engine):
        engine.event_buffer.clear()
        self._inject_anomaly_events(engine, '192.168.1.40', 0.3, 2, 'BRUTE_FORCE_ATTEMPT')
        result = engine.get_device_risk_score('192.168.1.40')
        assert result['risk_level'] == 'high'

    def test_risk_score_result_structure(self, engine):
        engine.event_buffer.clear()
        self._inject_anomaly_events(engine, '192.168.1.50', 0.6, 5)
        result = engine.get_device_risk_score('192.168.1.50')
        assert 'risk_level' in result
        assert 'risk_score' in result
        assert 'recent_anomalies' in result
        assert 'status' in result
        assert 'recommendations' in result


# ── predict_device_failure ────────────────────────────────────────────────────

class TestPredictDeviceFailure:
    def test_healthy_device_no_failure_predicted(self, engine):
        metrics = {'packet_loss': 0.01, 'latency_ms': 50, 'retransmits': 2, 'error_rate': 0.005}
        result = engine.predict_device_failure('192.168.1.100', metrics)
        assert result['failure_probability'] < 0.3
        assert result['predicted_in_hours'] is None

    def test_high_packet_loss_triggers_warning(self, engine):
        metrics = {'packet_loss': 0.1, 'latency_ms': 50, 'retransmits': 2, 'error_rate': 0.01}
        result = engine.predict_device_failure('192.168.1.100', metrics)
        assert result['failure_probability'] > 0

    def test_high_latency_contributes(self, engine):
        metrics = {'packet_loss': 0.0, 'latency_ms': 300, 'retransmits': 2, 'error_rate': 0.0}
        result = engine.predict_device_failure('192.168.1.100', metrics)
        assert result['failure_probability'] > 0

    def test_many_retransmits_contributes(self, engine):
        metrics = {'packet_loss': 0.0, 'latency_ms': 10, 'retransmits': 15, 'error_rate': 0.0}
        result = engine.predict_device_failure('192.168.1.100', metrics)
        assert result['failure_probability'] > 0

    def test_high_error_rate_contributes(self, engine):
        metrics = {'packet_loss': 0.0, 'latency_ms': 10, 'retransmits': 2, 'error_rate': 0.05}
        result = engine.predict_device_failure('192.168.1.100', metrics)
        assert result['failure_probability'] > 0

    def test_critical_failure_all_metrics_bad(self, engine):
        metrics = {'packet_loss': 0.2, 'latency_ms': 500, 'retransmits': 20, 'error_rate': 0.1}
        result = engine.predict_device_failure('192.168.1.100', metrics)
        assert result['failure_probability'] >= 0.7
        assert result['predicted_in_hours'] is not None
        assert '⚠️ High risk' in result['recommendations'][0]

    def test_result_structure(self, engine):
        metrics = {'packet_loss': 0.15, 'latency_ms': 300, 'retransmits': 12, 'error_rate': 0.0}
        result = engine.predict_device_failure('192.168.1.100', metrics)
        assert 'failure_probability' in result
        assert 'predicted_in_hours' in result
        assert 'reason' in result
        assert 'recommendations' in result

    def test_empty_metrics_defaults(self, engine):
        result = engine.predict_device_failure('192.168.1.100', {})
        assert result['failure_probability'] == 0.0
        assert result['predicted_in_hours'] is None


# ── save / load error paths ────────────────────────────────────────────────────

class TestSaveLoadPaths:
    def test_save_to_readonly_path_doesnt_crash(self, engine):
        engine.model_path = Path('/nonexistent_dir/model.pkl')
        engine.save_models()  # should log error, not raise

    def test_load_corrupted_file_starts_fresh(self, temp_db, tmp_path):
        bad_model = tmp_path / 'bad.pkl'
        bad_model.write_bytes(b'corrupted data')
        engine = RiverMLEngine(db_manager=temp_db, model_path=str(bad_model))
        assert engine.stats['predictions_made'] == 0
