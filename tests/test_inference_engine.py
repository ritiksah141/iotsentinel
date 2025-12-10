#!/usr/bin/env python3
"""
Unit Tests for ML Inference Engine

Test Coverage:
- Model loading and initialization
- Real-time inference pipeline
- Prediction storage
- Alert generation logic
- Error handling

Run: pytest tests/test_inference_engine.py -v --cov=ml.inference_engine
"""

import pytest
import numpy as np
import pandas as pd
import pickle
import json
from unittest.mock import patch, MagicMock, mock_open
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

# We have to import tensorflow before patching it
try:
    import tensorflow
except ImportError:
    # If tensorflow is not installed, we create a mock to allow tests to run.
    tensorflow = MagicMock()
    sys.modules['tensorflow'] = tensorflow

from ml.inference_engine import InferenceEngine

# ============================================================================
# MOCKS & FIXTURES
# ============================================================================

@pytest.fixture
def mock_db():
    """Fixture for a mocked DatabaseManager."""
    db = MagicMock()
    db.get_unprocessed_connections.return_value = []
    db.is_ip_malicious.return_value = False
    return db

@pytest.fixture
def mock_extractor():
    """Fixture for a mocked FeatureExtractor."""
    extractor = MagicMock()
    X = np.random.rand(2, 5)
    feature_names = ['feat1', 'feat2', 'feat3', 'feat4', 'feat5']
    extractor.extract_features.return_value = (X, feature_names)
    extractor.transform.return_value = X
    return extractor

@pytest.fixture
def mock_config(tmp_path):
    """Fixture to mock the config object with valid paths and alerting thresholds."""
    config_data = {
        'database': {'path': str(tmp_path / 'test.db')},
        'ml': {
            'feature_extractor_path': str(tmp_path / 'extractor.pkl'),
            'isolation_forest_path': str(tmp_path / 'if.pkl'),
            'autoencoder_path': str(tmp_path / 'ae_model'),
        },
        'system': {'status_file_path': str(tmp_path / 'status.json')},
        'alerting': {
            'severity_thresholds': {
                'critical': 0.95,
                'high': 0.8,
                'medium': 0.6,
                'low': 0.1
            }
        }
    }
    mock_config_obj = MagicMock()
    mock_config_obj.get.side_effect = lambda section, key, default=None: config_data.get(section, {}).get(key, default)
    mock_config_obj.get_section.side_effect = lambda section: config_data.get(section, {})
    return mock_config_obj

# ============================================================================
# TEST SUITES
# ============================================================================

class TestInferenceEngineLoading:
    """Tests for model loading logic."""

    @patch('ml.inference_engine.DatabaseManager')
    @patch('ml.inference_engine.FeatureExtractor')
    @patch('ml.inference_engine.config')
    @patch('builtins.open', new_callable=mock_open)
    @patch('pickle.load')
    @patch('pathlib.Path.exists', return_value=True)
    @patch('tensorflow.keras.models.load_model')
    def test_load_models_success(self, mock_load_tf, mock_exists, mock_pickle_load, mock_open_file, mock_cfg, mock_ext_cls, mock_db_cls, mock_config):
        mock_cfg.get.side_effect = mock_config.get
        mock_cfg.get_section.return_value = {}
        mock_pickle_load.side_effect = ["if_model", 0.75]
        mock_load_tf.return_value = "tf_model"

        engine = InferenceEngine()

        assert engine.isolation_forest == "if_model"
        assert engine.autoencoder == "tf_model"
        assert engine.autoencoder_threshold == 0.75
        mock_load_tf.assert_called_once()
        assert mock_pickle_load.call_count == 2
        assert mock_open_file.call_count == 2

    @patch('ml.inference_engine.DatabaseManager')
    @patch('ml.inference_engine.FeatureExtractor')
    @patch('ml.inference_engine.config')
    @patch('pathlib.Path.exists', return_value=False)
    def test_load_models_missing_files_graceful(self, mock_exists, mock_cfg, mock_ext_cls, mock_db_cls, mock_config):
        mock_cfg.get.side_effect = mock_config.get
        mock_cfg.get_section.return_value = {}

        engine = InferenceEngine()

        assert engine.isolation_forest is None
        assert engine.autoencoder is None
        assert engine.autoencoder_threshold is None

    @patch('ml.inference_engine.DatabaseManager')
    @patch('ml.inference_engine.FeatureExtractor')
    @patch('ml.inference_engine.config')
    @patch('builtins.open', new_callable=mock_open)
    @patch('pickle.load')
    @patch('pathlib.Path.exists', return_value=True)
    def test_load_models_no_tensorflow(self, mock_exists, mock_pickle, mock_open_file, mock_cfg, mock_ext_cls, mock_db_cls, mock_config):
        mock_cfg.get.side_effect = mock_config.get
        mock_cfg.get_section.return_value = {}

        with patch.dict(sys.modules, {'tensorflow': None}):
             engine = InferenceEngine()

        assert engine.autoencoder is None
        assert engine.isolation_forest is not None

class TestInferenceProcessing:
    """Tests for the main process_connections logic."""

    @pytest.fixture(autouse=True)
    def setup_mocks(self, mock_db, mock_extractor, mock_config):
        self.mock_if_model = MagicMock()
        self.mock_ae_model = MagicMock()
        self.mock_alerting_system = MagicMock()

        with patch('ml.inference_engine.DatabaseManager', return_value=mock_db), \
             patch('ml.inference_engine.FeatureExtractor', return_value=mock_extractor), \
             patch('ml.inference_engine.config', mock_config), \
             patch('builtins.open', mock_open()), \
             patch('pickle.load', side_effect=[self.mock_if_model, 0.5]), \
             patch('tensorflow.keras.models.load_model', return_value=self.mock_ae_model), \
             patch('pathlib.Path.exists', return_value=True):
            yield

    def get_sample_connections(self):
        return pd.DataFrame([
            {'id': 1, 'device_ip': '192.168.1.10', 'dest_ip': '8.8.8.8'},
            {'id': 2, 'device_ip': '192.168.1.11', 'dest_ip': '1.1.1.1'},
        ])

    def test_process_normal_connection(self, mock_db):
        mock_db.get_unprocessed_connections.return_value = self.get_sample_connections().to_dict('records')
        self.mock_if_model.predict.return_value = np.array([1, 1])

        engine = InferenceEngine(alerting_system=self.mock_alerting_system)
        engine.autoencoder = None

        anomaly_count = engine.process_connections()

        assert anomaly_count == 0
        self.mock_alerting_system.create_alert.assert_not_called()
        mock_db.mark_connections_processed.assert_called_once_with([1, 2])

    def test_process_if_anomaly(self, mock_db):
        mock_db.get_unprocessed_connections.return_value = self.get_sample_connections().to_dict('records')
        self.mock_if_model.predict.side_effect = [np.array([1]), np.array([-1])]
        self.mock_if_model.score_samples.side_effect = [np.array([0.5]), np.array([-0.8])]

        engine = InferenceEngine(alerting_system=self.mock_alerting_system)
        engine.autoencoder = None

        anomaly_count = engine.process_connections()

        assert anomaly_count == 1
        self.mock_alerting_system.create_alert.assert_called_once()
        mock_db.store_prediction.assert_any_call(
            connection_id=2, is_anomaly=True,
            anomaly_score=pytest.approx(0.8), model_type='isolation_forest'
        )

    def test_process_ae_anomaly(self, mock_db, mock_extractor):
        mock_db.get_unprocessed_connections.return_value = self.get_sample_connections().to_dict('records')
        self.mock_if_model.predict.return_value = np.array([1, 1])
        self.mock_ae_model.predict.side_effect = [np.random.rand(1, 5), np.random.rand(1, 5) + 10]

        engine = InferenceEngine(alerting_system=self.mock_alerting_system)
        engine.autoencoder_threshold = 0.5

        anomaly_count = engine.process_connections()

        assert anomaly_count > 0
        self.mock_alerting_system.create_alert.assert_called()

    def test_process_malicious_ip(self, mock_db, mock_extractor):
        mock_db.get_unprocessed_connections.return_value = self.get_sample_connections().to_dict('records')
        mock_db.is_ip_malicious.side_effect = [False, True]
        self.mock_ae_model.predict.return_value = np.zeros((1, mock_extractor.transform.return_value.shape[1]))

        engine = InferenceEngine(alerting_system=self.mock_alerting_system)

        anomaly_count = engine.process_connections()

        assert anomaly_count == 1
        self.mock_alerting_system.create_alert.assert_called_once_with(
            device_ip='192.168.1.11', severity='critical', anomaly_score=1.0,
            explanation=engine._generate_malicious_ip_explanation('192.168.1.11', '1.1.1.1'),
            top_features=json.dumps({'malicious_ip': '1.1.1.1'})
        )
        assert self.mock_if_model.predict.call_count == 1

    def test_no_connections_to_process(self, mock_db):
        mock_db.get_unprocessed_connections.return_value = []
        engine = InferenceEngine(alerting_system=self.mock_alerting_system)
        count = engine.process_connections()
        assert count == 0
        mock_db.mark_connections_processed.assert_not_called()

class TestInferenceHelpers:
    """Tests for helper methods."""

    @pytest.fixture
    def engine(self, mock_config):
        with patch('ml.inference_engine.DatabaseManager'), \
             patch('ml.inference_engine.FeatureExtractor'), \
             patch('ml.inference_engine.config', mock_config):
            return InferenceEngine()

    @pytest.mark.parametrize("score, expected_severity", [
        (0.1, 'low'),
        (0.6, 'medium'),
        (0.8, 'high'),
        (0.95, 'critical')
    ])
    def test_calculate_severity(self, engine, score, expected_severity):
        assert engine._calculate_severity(score) == expected_severity

    def test_generate_explanation(self, engine):
        connection = pd.Series({
            'device_ip': '10.0.0.5', 'dest_ip': '1.2.3.4', 'protocol': 'tcp'
        })
        explanation = engine._generate_explanation(connection, 0.7, 'isolation_forest')
        assert '10.0.0.5' in explanation
        assert '1.2.3.4' in explanation
        assert '0.70' in explanation
        assert 'Isolation Forest' in explanation

    def test_get_top_features(self, engine):
        features = np.array([0.1, -0.9, 0.5, -0.2, 0.8])
        feature_names = ['feat_a', 'feat_b', 'feat_c', 'feat_d', 'feat_e']
        top = engine._get_top_features(features, feature_names, top_n=3)
        assert list(top.keys()) == ['feat_b', 'feat_e', 'feat_c']
        assert top['feat_b'] == -0.9
        assert top['feat_e'] == 0.8
        assert top['feat_c'] == 0.5

class TestMonitoringPause:
    """Tests for the monitoring pause/resume functionality."""

    @pytest.fixture
    def engine(self, tmp_path):
        status_file = tmp_path / "monitoring_status.json"
        with patch('ml.inference_engine.DatabaseManager'), \
             patch('ml.inference_engine.FeatureExtractor'), \
             patch('ml.inference_engine.config') as mock_config:
            mock_config.get_section.return_value = {}
            mock_config.get.return_value = str(status_file)
            engine = InferenceEngine()
            engine.status_file_path = Path(status_file)
            return engine

    def test_monitoring_is_not_paused_by_default(self, engine):
        assert engine._is_monitoring_paused() is False

    def test_monitoring_is_paused_when_status_is_paused(self, engine):
        status_content = {"status": "paused"}
        engine.status_file_path.write_text(json.dumps(status_content))
        assert engine._is_monitoring_paused() is True

    def test_monitoring_is_not_paused_when_status_is_running(self, engine):
        status_content = {"status": "running"}
        engine.status_file_path.write_text(json.dumps(status_content))
        assert engine._is_monitoring_paused() is False

    def test_monitoring_handles_corrupt_status_file(self, engine):
        engine.status_file_path.write_text("this is not json")
        assert engine._is_monitoring_paused() is False
