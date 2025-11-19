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
    """Fixture to mock the config object with valid paths."""
    config_data = {
        'database': {'path': str(tmp_path / 'test.db')},
        'ml': {
            'feature_extractor_path': str(tmp_path / 'extractor.pkl'),
            'isolation_forest_path': str(tmp_path / 'if.pkl'),
            'autoencoder_path': str(tmp_path / 'ae_model'),
        },
        'system': {'status_file_path': str(tmp_path / 'status.json')}
    }
    mock_config_obj = MagicMock()
    mock_config_obj.get.side_effect = lambda section, key, default=None: config_data.get(section, {}).get(key, default)
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
        """TC-IE-001: Verify models are loaded successfully when files exist."""
        # Arrange
        mock_cfg.get.side_effect = mock_config.get
        mock_pickle_load.side_effect = ["if_model", 0.75] # For model and threshold
        mock_load_tf.return_value = "tf_model"

        # Act
        engine = InferenceEngine()

        # Assert
        assert engine.isolation_forest == "if_model"
        assert engine.autoencoder == "tf_model"
        assert engine.autoencoder_threshold == 0.75
        mock_load_tf.assert_called_once()
        assert mock_pickle_load.call_count == 2 # For model and threshold
        assert mock_open_file.call_count == 2 # For if.pkl and threshold.pkl

    @patch('ml.inference_engine.DatabaseManager')
    @patch('ml.inference_engine.FeatureExtractor')
    @patch('ml.inference_engine.config')
    @patch('pathlib.Path.exists', return_value=False)
    def test_load_models_missing_files_graceful(self, mock_exists, mock_cfg, mock_ext_cls, mock_db_cls, mock_config):
        """TC-IE-002: Verify it handles missing model files gracefully."""
        # Arrange
        mock_cfg.get.side_effect = mock_config.get

        # Act
        engine = InferenceEngine()

        # Assert
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
        """TC-IE-003: Verify Autoencoder is disabled if TensorFlow is not installed."""
        # Arrange
        mock_cfg.get.side_effect = mock_config.get

        # Act
        with patch.dict(sys.modules, {'tensorflow': None}):
             engine = InferenceEngine()

        # Assert
        assert engine.autoencoder is None
        assert engine.isolation_forest is not None

class TestInferenceProcessing:
    """Tests for the main process_connections logic."""

    @pytest.fixture(autouse=True)
    def setup_mocks(self, mock_db, mock_extractor, mock_config):
        """Auto-applies patches for this test class."""
        self.mock_if_model = MagicMock()
        self.mock_ae_model = MagicMock()

        with patch('ml.inference_engine.DatabaseManager', return_value=mock_db), \
             patch('ml.inference_engine.FeatureExtractor', return_value=mock_extractor), \
             patch('ml.inference_engine.config', mock_config), \
             patch('ml.inference_engine.send_alert_email') as self.mock_send_email, \
             patch('builtins.open', mock_open()), \
             patch('pickle.load', side_effect=[self.mock_if_model, 0.5]), \
             patch('tensorflow.keras.models.load_model', return_value=self.mock_ae_model), \
             patch('pathlib.Path.exists', return_value=True):
            yield

    def get_sample_connections(self):
        """Helper to get sample connection data."""
        return pd.DataFrame([
            {'id': 1, 'device_ip': '192.168.1.10', 'dest_ip': '8.8.8.8'},
            {'id': 2, 'device_ip': '192.168.1.11', 'dest_ip': '1.1.1.1'},
        ])

    def test_process_normal_connection(self, mock_db):
        """TC-IE-004: Verify normal connections are processed without creating alerts."""
        # Arrange
        mock_db.get_unprocessed_connections.return_value = self.get_sample_connections().to_dict('records')
        self.mock_if_model.predict.return_value = np.array([1])

        engine = InferenceEngine()
        engine.autoencoder = None

        # Act
        anomaly_count = engine.process_connections()

        # Assert
        assert anomaly_count == 0
        assert mock_db.create_alert.call_count == 0
        mock_db.mark_connections_processed.assert_called_once_with([1, 2])

    def test_process_if_anomaly(self, mock_db):
        """TC-IE-005: Verify Isolation Forest anomaly creates an alert."""
        # Arrange
        mock_db.get_unprocessed_connections.return_value = self.get_sample_connections().to_dict('records')
        self.mock_if_model.predict.return_value = np.array([-1])
        self.mock_if_model.score_samples.return_value = np.array([-0.8])

        engine = InferenceEngine()
        engine.autoencoder = None

        # Act
        anomaly_count = engine.process_connections()

        # Assert
        assert anomaly_count > 0
        mock_db.create_alert.assert_called()
        mock_db.store_prediction.assert_called_with(
            connection_id=2,
            is_anomaly=True,
            anomaly_score=pytest.approx(0.8),
            model_type='isolation_forest'
        )

    def test_process_ae_anomaly(self, mock_db, mock_extractor):
        """TC-IE-006: Verify Autoencoder anomaly creates an alert."""
        # Arrange
        mock_db.get_unprocessed_connections.return_value = self.get_sample_connections().to_dict('records')
        self.mock_if_model.predict.return_value = np.array([1])
        self.mock_ae_model.predict.return_value = np.random.rand(1, 5) + 10

        engine = InferenceEngine()
        engine.autoencoder_threshold = 0.5

        # Act
        anomaly_count = engine.process_connections()

        # Assert
        assert anomaly_count > 0
        mock_db.create_alert.assert_called()
        mock_db.store_prediction.assert_called_with(
            connection_id=2,
            is_anomaly=True,
            anomaly_score=pytest.approx(np.mean(np.square(mock_extractor.transform.return_value[1] - self.mock_ae_model.predict.return_value[0]))),
            model_type='autoencoder'
        )

    def test_process_malicious_ip(self, mock_db):
        """TC-IE-007: Verify malicious IP creates a critical alert and skips ML."""
        # Arrange
        mock_db.get_unprocessed_connections.return_value = self.get_sample_connections().to_dict('records')
        mock_db.is_ip_malicious.return_value = True

        engine = InferenceEngine()

        # Act
        anomaly_count = engine.process_connections()

        # Assert
        assert anomaly_count > 0
        mock_db.create_alert.assert_called_with(
            device_ip='192.168.1.11',
            severity='critical',
            anomaly_score=1.0,
            explanation='Connection made to a known malicious IP address: 1.1.1.1',
            top_features=json.dumps({'malicious_ip': '1.1.1.1'})
        )
        assert self.mock_if_model.predict.call_count == 0

    def test_critical_alert_sends_email(self, mock_db):
        """TC-IE-008: Verify a critical alert triggers an email notification."""
        # Arrange
        mock_db.get_unprocessed_connections.return_value = self.get_sample_connections().to_dict('records')
        mock_db.is_ip_malicious.return_value = True

        engine = InferenceEngine()

        # Act
        engine.process_connections()

        # Assert
        assert self.mock_send_email.call_count > 0

    def test_no_connections_to_process(self, mock_db):
        """TC-IE-009: Verify it handles no connections gracefully."""
        # Arrange
        mock_db.get_unprocessed_connections.return_value = []
        engine = InferenceEngine()

        # Act
        count = engine.process_connections()

        # Assert
        assert count == 0
        assert mock_db.mark_connections_processed.call_count == 0


class TestInferenceHelpers:
    """Tests for helper methods."""

    @pytest.fixture
    def engine(self):
        """Simple InferenceEngine instance without mocked dependencies."""
        with patch('ml.inference_engine.DatabaseManager'), \
             patch('ml.inference_engine.FeatureExtractor'), \
             patch('ml.inference_engine.config'):
            return InferenceEngine()

    @pytest.mark.parametrize("score, expected_severity", [
        (0.1, 'low'),
        (0.3, 'medium'),
        (0.6, 'high'),
        (1.1, 'critical')
    ])
    def test_calculate_severity(self, engine, score, expected_severity):
        """TC-IE-010: Verify severity calculation."""
        assert engine._calculate_severity(score) == expected_severity

    def test_generate_explanation(self, engine):
        """TC-IE-011: Verify explanation generation."""
        connection = pd.Series({
            'device_ip': '10.0.0.5',
            'dest_ip': '1.2.3.4',
            'protocol': 'tcp'
        })
        explanation = engine._generate_explanation(connection, 0.7, 'isolation_forest')
        assert '10.0.0.5' in explanation
        assert '1.2.3.4' in explanation
        assert '0.70' in explanation
        assert 'isolation_forest' in explanation

    def test_get_top_features(self, engine):
        """TC-IE-012: Verify extraction of top contributing features."""
        features = np.array([0.1, -0.9, 0.5, -0.2, 0.8])
        feature_names = ['feat_a', 'feat_b', 'feat_c', 'feat_d', 'feat_e']

        top = engine._get_top_features(features, feature_names, top_n=3)

        assert list(top.keys()) == ['feat_b', 'feat_e', 'feat_c']
        assert top['feat_b'] == -0.9
        assert top['feat_e'] == 0.8
        assert top['feat_c'] == 0.5
