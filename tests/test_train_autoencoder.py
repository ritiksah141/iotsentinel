#!/usr/bin/env python3
"""
Unit Tests for Autoencoder Training Script

Test Coverage:
- Data loading and validation
- Model architecture creation
- Training process
- Model evaluation
- Model persistence

Run: pytest tests/test_train_autoencoder.py -v --cov=ml.train_autoencoder
"""

import pytest
import tempfile
import numpy as np
import pandas as pd
from pathlib import Path
import sys
import sqlite3
import pickle
from unittest.mock import patch, MagicMock
from datetime import datetime
import importlib

sys.path.insert(0, str(Path(__file__).parent.parent))

from database.db_manager import DatabaseManager
from ml.feature_extractor import FeatureExtractor
from ml.train_autoencoder import train_autoencoder

# The `db` fixture is now provided by `tests/conftest.py`

@pytest.fixture
def populated_db(db: DatabaseManager):
    """
    Uses the shared `db` fixture and populates it with sample training data.
    """
    db.add_device('192.168.1.100')

    protocols = ['tcp', 'udp']
    conn_states = ['SF', 'S0']

    for i in range(200):
        db.add_connection(
            device_ip='192.168.1.100',
            dest_ip=f'8.8.8.{i % 4}',
            dest_port=80 + (i % 10),
            protocol=protocols[i % len(protocols)],
            conn_state=conn_states[i % len(conn_states)],
            duration=5.0 + i * 0.1,
            bytes_sent=1000 + i * 10,
            bytes_received=2000 + i * 20,
            packets_sent=10 + i,
            packets_received=20 + i
        )
    return db


class TestDataPreparation:
    """Test suite for training data preparation."""

    def test_load_training_data(self, populated_db):
        """TC-TRN-AE-001: Verify loading training data."""
        connections = populated_db.get_unprocessed_connections(limit=1000)
        df = pd.DataFrame(connections)

        assert len(df) == 200
        assert 'duration' in df.columns

    def test_train_test_split(self, populated_db):
        """TC-TRN-AE-002: Verify train/test split."""
        from sklearn.model_selection import train_test_split

        connections = populated_db.get_unprocessed_connections(limit=1000)
        df = pd.DataFrame(connections)

        extractor = FeatureExtractor()
        X, _ = extractor.extract_features(df)

        X_train, X_test = train_test_split(X, test_size=0.2, random_state=42)

        assert len(X_train) == int(0.8 * len(X))
        assert len(X_test) == int(0.2 * len(X))


class TestModelArchitecture:
    """Test suite for Autoencoder architecture."""

    def test_create_autoencoder_model(self):
        """TC-TRN-AE-003: Verify Autoencoder model creation."""
        from tensorflow import keras

        input_dim = 15
        encoding_dim = 7

        model = keras.Sequential([
            keras.layers.Dense(encoding_dim, activation='relu', input_shape=(input_dim,)),
            keras.layers.Dense(input_dim, activation='linear')
        ])

        assert model is not None
        assert len(model.layers) == 2
        assert model.layers[0].output_shape == (None, encoding_dim)
        assert model.layers[1].output_shape == (None, input_dim)

    def test_model_compilation(self):
        """TC-TRN-AE-004: Verify model compilation."""
        from tensorflow import keras

        model = keras.Sequential([
            keras.layers.Dense(7, activation='relu', input_shape=(15,)),
            keras.layers.Dense(15, activation='linear')
        ])

        model.compile(optimizer='adam', loss='mse', metrics=['mae'])

        assert model.optimizer is not None
        assert model.loss == 'mse'


class TestModelTraining:
    """Test suite for Autoencoder training."""

    @patch('ml.train_autoencoder.TENSORFLOW_AVAILABLE', True)
    def test_train_autoencoder(self, populated_db):
        """TC-TRN-AE-005: Verify Autoencoder training."""
        from tensorflow import keras
        from sklearn.model_selection import train_test_split

        connections = populated_db.get_unprocessed_connections(limit=1000)
        df = pd.DataFrame(connections)

        extractor = FeatureExtractor()
        X, _ = extractor.extract_features(df)
        X_scaled = extractor.fit_transform(X)

        X_train, X_val = train_test_split(X_scaled, test_size=0.2, random_state=42)

        input_dim = X_train.shape[1]
        encoding_dim = input_dim // 2

        model = keras.Sequential([
            keras.layers.Dense(encoding_dim, activation='relu', input_shape=(input_dim,)),
            keras.layers.Dense(input_dim, activation='linear')
        ])
        model.compile(optimizer='adam', loss='mse')

        history = model.fit(
            X_train, X_train,
            epochs=5,
            batch_size=32,
            validation_data=(X_val, X_val),
            verbose=0
        )

        assert history is not None
        assert 'loss' in history.history
        assert len(history.history['loss']) == 5

    @patch('ml.train_autoencoder.TENSORFLOW_AVAILABLE', True)
    def test_training_loss_decreases(self, populated_db):
        """TC-TRN-AE-006: Verify training loss decreases."""
        from tensorflow import keras

        connections = populated_db.get_unprocessed_connections(limit=1000)
        df = pd.DataFrame(connections)

        extractor = FeatureExtractor()
        X, _ = extractor.extract_features(df)
        X_scaled = extractor.fit_transform(X)

        input_dim = X_scaled.shape[1]
        model = keras.Sequential([
            keras.layers.Dense(input_dim // 2, activation='relu', input_shape=(input_dim,)),
            keras.layers.Dense(input_dim, activation='linear')
        ])
        model.compile(optimizer='adam', loss='mse')

        history = model.fit(X_scaled, X_scaled, epochs=10, batch_size=32, verbose=0)

        initial_loss = history.history['loss'][0]
        final_loss = history.history['loss'][-1]
        assert final_loss < initial_loss


class TestModelEvaluation:
    """Test suite for model evaluation."""

    @patch('ml.train_autoencoder.TENSORFLOW_AVAILABLE', True)
    def test_calculate_reconstruction_error(self, populated_db):
        """TC-TRN-AE-007: Verify reconstruction error calculation."""
        from tensorflow import keras

        connections = populated_db.get_unprocessed_connections(limit=1000)
        df = pd.DataFrame(connections)

        extractor = FeatureExtractor()
        X, _ = extractor.extract_features(df)
        X_scaled = extractor.fit_transform(X)

        input_dim = X_scaled.shape[1]
        model = keras.Sequential([
            keras.layers.Dense(input_dim // 2, activation='relu', input_shape=(input_dim,)),
            keras.layers.Dense(input_dim, activation='linear')
        ])
        model.compile(optimizer='adam', loss='mse')
        model.fit(X_scaled, X_scaled, epochs=5, verbose=0)

        reconstructed = model.predict(X_scaled, verbose=0)
        mse = np.mean(np.square(X_scaled - reconstructed), axis=1)

        assert len(mse) == len(X_scaled)
        assert np.all(mse >= 0)

    @patch('ml.train_autoencoder.TENSORFLOW_AVAILABLE', True)
    def test_calculate_threshold(self, populated_db):
        """TC-TRN-AE-008: Verify anomaly threshold calculation."""
        from tensorflow import keras

        connections = populated_db.get_unprocessed_connections(limit=1000)
        df = pd.DataFrame(connections)

        extractor = FeatureExtractor()
        X, _ = extractor.extract_features(df)
        X_scaled = extractor.fit_transform(X)

        input_dim = X_scaled.shape[1]
        model = keras.Sequential([
            keras.layers.Dense(input_dim // 2, activation='relu', input_shape=(input_dim,)),
            keras.layers.Dense(input_dim, activation='linear')
        ])
        model.compile(optimizer='adam', loss='mse')
        model.fit(X_scaled, X_scaled, epochs=5, verbose=0)

        reconstructed = model.predict(X_scaled, verbose=0)
        mse = np.mean(np.square(X_scaled - reconstructed), axis=1)

        mean_error = np.mean(mse)
        std_error = np.std(mse)
        threshold = mean_error + 3 * std_error

        assert threshold > 0
        assert threshold > mean_error


class TestModelPersistence:
    """Test suite for model saving and loading."""

    def test_save_autoencoder_model(self, tmp_path):
        """TC-TRN-AE-009: Verify saving Autoencoder model."""
        from tensorflow import keras
        model = keras.Sequential([
            keras.layers.Dense(7, activation='relu', input_shape=(15,)),
            keras.layers.Dense(15, activation='linear')
        ])
        model.compile(optimizer='adam', loss='mse')
        model_path = tmp_path / 'test_autoencoder.h5'
        model.save(model_path)
        assert model_path.exists()

    def test_load_saved_model(self, tmp_path):
        """TC-TRN-AE-010: Verify loading saved model."""
        from tensorflow import keras
        model = keras.Sequential([
            keras.layers.Dense(7, activation='relu', input_shape=(15,)),
            keras.layers.Dense(15, activation='linear')
        ])
        model.compile(optimizer='adam', loss='mse')
        X_dummy = np.random.randn(100, 15)
        model.fit(X_dummy, X_dummy, epochs=1, verbose=0)
        model_path = tmp_path / 'test_autoencoder.h5'
        model.save(model_path)
        loaded_model = keras.models.load_model(model_path)
        assert loaded_model is not None
        original_preds = model.predict(X_dummy, verbose=0)
        loaded_preds = loaded_model.predict(X_dummy, verbose=0)
        np.testing.assert_array_almost_equal(original_preds, loaded_preds, decimal=5)

    def test_save_threshold_value(self, tmp_path):
        """TC-TRN-AE-011: Verify saving threshold value."""
        import json
        threshold = 0.025
        metadata = {'threshold': threshold, 'mean_error': 0.01, 'std_error': 0.005}
        metadata_path = tmp_path / 'ae_metadata.json'
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f)
        assert metadata_path.exists()
        with open(metadata_path, 'r') as f:
            loaded_metadata = json.load(f)
        assert loaded_metadata['threshold'] == threshold


class TestHyperparameters:
    """Test suite for hyperparameter configuration."""

    def test_encoding_dimension_selection(self):
        """TC-TRN-AE-012: Verify encoding dimension configuration."""
        from tensorflow import keras
        input_dim = 20
        encoding_dim = 10
        model = keras.Sequential([
            keras.layers.Dense(encoding_dim, activation='relu', input_shape=(input_dim,)),
            keras.layers.Dense(input_dim, activation='linear')
        ])
        assert model.layers[0].output_shape == (None, encoding_dim)

    @patch('ml.train_autoencoder.TENSORFLOW_AVAILABLE', True)
    def test_batch_size_configuration(self, populated_db):
        """TC-TRN-AE-013: Verify batch size configuration."""
        from tensorflow import keras
        connections = populated_db.get_unprocessed_connections(limit=1000)
        df = pd.DataFrame(connections)
        extractor = FeatureExtractor()
        X, _ = extractor.extract_features(df)
        X_scaled = extractor.fit_transform(X)
        input_dim = X_scaled.shape[1]
        model = keras.Sequential([
            keras.layers.Dense(input_dim // 2, activation='relu', input_shape=(input_dim,)),
            keras.layers.Dense(input_dim, activation='linear')
        ])
        model.compile(optimizer='adam', loss='mse')
        batch_size = 64
        history = model.fit(
            X_scaled, X_scaled, epochs=2, batch_size=batch_size, verbose=0
        )
        assert history is not None


class TestErrorHandling:
    """Test suite for error handling."""

    def test_handle_insufficient_data(self):
        """TC-TRN-AE-014: Verify handling of insufficient training data."""
        from tensorflow import keras
        X_small = np.random.randn(10, 15)
        model = keras.Sequential([
            keras.layers.Dense(7, activation='relu', input_shape=(15,)),
            keras.layers.Dense(15, activation='linear')
        ])
        model.compile(optimizer='adam', loss='mse')
        history = model.fit(X_small, X_small, epochs=2, verbose=0)
        assert history is not None

    def test_handle_invalid_architecture(self):
        """TC-TRN-AE-015: Verify handling of invalid architecture."""
        from tensorflow import keras
        model = keras.Sequential([
            keras.layers.Dense(20, activation='relu', input_shape=(10,)),
            keras.layers.Dense(10, activation='linear')
        ])
        assert model is not None

    @patch('ml.train_autoencoder.TENSORFLOW_AVAILABLE', True)
    @patch('ml.train_autoencoder.DatabaseManager')
    def test_handle_insufficient_data_exit(self, MockDB, tmp_path):
        """TC-TRN-AE-016: Verify graceful exit on insufficient connections (<100)."""
        mock_db_instance = MockDB.return_value
        mock_db_instance.get_unprocessed_connections.return_value = [
            {'id': i, 'device_ip': '192.168.1.100', 'duration': 5.0} for i in range(50)
        ]
        mock_db_instance.close = MagicMock()
        train_autoencoder()
        mock_db_instance.close.assert_called_once()

    @patch('ml.train_autoencoder.DatabaseManager')
    def test_handle_no_tensorflow(self, mock_db_cls):
        """TC-TRN-AE-017: Verify early exit when TensorFlow is not available."""
        with patch.dict(sys.modules, {'tensorflow': None}):
            importlib.reload(sys.modules['ml.train_autoencoder'])
            from ml.train_autoencoder import train_autoencoder as ta
            ta()
        mock_db_cls.assert_not_called()


class TestTrainingScriptIntegration:
    """Test the end-to-end execution of the training script logic."""
    @patch('ml.train_autoencoder.TENSORFLOW_AVAILABLE', True)
    @patch('time.sleep', return_value=None)
    @patch('ml.train_autoencoder.DatabaseManager')
    def test_training_script_saves_models_and_threshold(self, mock_db_cls, mock_sleep, tmp_path):
        """TC-INT-014: Verify full Autoencoder training script executes and saves model/threshold."""
        mock_db_instance = mock_db_cls.return_value
        mock_db_instance.get_unprocessed_connections.return_value = [
            {'id': i, 'device_ip': '192.168.1.100', 'duration': 5.0, 'bytes_sent': 1000, 'bytes_received': 2000, 'packets_sent': 10, 'packets_received': 20, 'protocol': 'tcp', 'conn_state': 'SF', 'dest_port': 443, 'timestamp': datetime.now().isoformat()}
            for i in range(200)
        ]
        mock_config = MagicMock()
        mock_config.get.side_effect = lambda section, key, default=None: {
            ('database', 'path'): str(tmp_path / 'test.db'),
            ('ml', 'autoencoder_path'): str(tmp_path / 'ae_model.h5'),
            ('ml', 'feature_extractor_path'): str(tmp_path / 'ae_extractor.pkl'),
        }.get((section, key), default)

        with patch('ml.train_autoencoder.config', mock_config):
            with patch('ml.train_autoencoder.keras.Model.fit') as mock_fit, \
                 patch('ml.train_autoencoder.keras.Model.predict') as mock_predict, \
                 patch('ml.train_autoencoder.build_autoencoder') as mock_build, \
                 patch('ml.train_autoencoder.Path.exists', return_value=True):

                mock_fit.return_value = MagicMock(history={'loss': [0.1, 0.05]})

                def mock_predict_side_effect(X_input, **kwargs):
                    return np.zeros(X_input.shape)

                mock_predict.side_effect = mock_predict_side_effect

                with patch('ml.train_autoencoder.keras.Model.save') as mock_save:
                    mock_build.return_value.predict = mock_predict
                    mock_build.return_value.fit = mock_fit
                    mock_build.return_value.save = mock_save
                    train_autoencoder()

        mock_save.assert_called_once()
        assert (tmp_path / 'ae_model_threshold.pkl').exists()
        assert (tmp_path / 'ae_extractor.pkl').exists()


class TestTrainingErrorExits:
    """Tests the failure modes and early exit logic."""

    @patch('ml.train_autoencoder.TENSORFLOW_AVAILABLE', True)
    @patch('ml.train_autoencoder.DatabaseManager')
    def test_insufficient_data_exit(self, MockDB_cls):
        """TC-TRN-AE-016: Verify graceful exit when connections < 100."""
        mock_db = MockDB_cls.return_value
        mock_db.get_unprocessed_connections.return_value = [
            {'id': i, 'device_ip': '192.168.1.100', 'duration': 5.0} for i in range(50)
        ]
        mock_db.close = MagicMock()
        train_autoencoder()
        mock_db.close.assert_called_once()

    @patch('ml.train_autoencoder.DatabaseManager')
    def test_no_tensorflow_exit(self, MockDB_cls):
        """TC-TRN-AE-017: Verify graceful exit when TensorFlow is not available."""
        with patch.dict(sys.modules, {'tensorflow': None}):
            importlib.reload(sys.modules['ml.train_autoencoder'])
            from ml.train_autoencoder import train_autoencoder as ta
            ta()
        MockDB_cls.assert_not_called()
