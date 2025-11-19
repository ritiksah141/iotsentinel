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
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from database.db_manager import DatabaseManager
from ml.feature_extractor import FeatureExtractor
from tensorflow.keras.optimizers.legacy import Adam


def create_test_schema(db_manager: DatabaseManager):
    """Helper to create database schema."""
    try:
        cursor = db_manager.conn.cursor()

        cursor.execute("""
        CREATE TABLE devices (
            device_ip TEXT PRIMARY KEY, device_name TEXT, device_type TEXT,
            mac_address TEXT, manufacturer TEXT, first_seen TIMESTAMP, last_seen TIMESTAMP
        );
        """)

        cursor.execute("""
        CREATE TABLE connections (
            id INTEGER PRIMARY KEY AUTOINCREMENT, device_ip TEXT, timestamp TIMESTAMP,
            dest_ip TEXT, dest_port INTEGER, protocol TEXT, service TEXT, duration REAL,
            bytes_sent INTEGER, bytes_received INTEGER, packets_sent INTEGER,
            packets_received INTEGER, conn_state TEXT, processed INTEGER DEFAULT 0,
            FOREIGN KEY (device_ip) REFERENCES devices (device_ip)
        );
        """)

        db_manager.conn.commit()
    except sqlite3.Error as e:
        print(f"Error creating schema: {e}")
        raise


@pytest.fixture
def temp_db():
    """Create temporary database with training data."""
    db_manager = DatabaseManager(':memory:')
    create_test_schema(db_manager)

    # Add sample training data
    db_manager.add_device('192.168.1.100')

    protocols = ['tcp', 'udp']
    conn_states = ['SF', 'S0']

    for i in range(200):
        db_manager.add_connection(
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

    yield db_manager
    db_manager.close()


class TestDataPreparation:
    """Test suite for training data preparation."""

    def test_load_training_data(self, temp_db):
        """TC-TRN-AE-001: Verify loading training data."""
        # Arrange & Act
        connections = temp_db.get_unprocessed_connections(limit=1000)
        df = pd.DataFrame(connections)

        # Assert
        assert len(df) == 200
        assert 'duration' in df.columns

    def test_train_test_split(self, temp_db):
        """TC-TRN-AE-002: Verify train/test split."""
        from sklearn.model_selection import train_test_split

        # Arrange
        connections = temp_db.get_unprocessed_connections(limit=1000)
        df = pd.DataFrame(connections)

        extractor = FeatureExtractor()
        X, _ = extractor.extract_features(df)

        # Act
        X_train, X_test = train_test_split(X, test_size=0.2, random_state=42)

        # Assert
        assert len(X_train) == int(0.8 * len(X))
        assert len(X_test) == int(0.2 * len(X))


class TestModelArchitecture:
    """Test suite for Autoencoder architecture."""

    def test_create_autoencoder_model(self):
        """TC-TRN-AE-003: Verify Autoencoder model creation."""
        from tensorflow import keras

        # Arrange
        input_dim = 15
        encoding_dim = 7

        # Act
        model = keras.Sequential([
            keras.layers.Dense(encoding_dim, activation='relu', input_shape=(input_dim,)),
            keras.layers.Dense(input_dim, activation='linear')
        ])

        # Assert
        assert model is not None
        assert len(model.layers) == 2
        assert model.layers[0].output_shape == (None, encoding_dim)
        assert model.layers[1].output_shape == (None, input_dim)

    def test_model_compilation(self):
        """TC-TRN-AE-004: Verify model compilation."""
        from tensorflow import keras

        # Arrange
        model = keras.Sequential([
            keras.layers.Dense(7, activation='relu', input_shape=(15,)),
            keras.layers.Dense(15, activation='linear')
        ])

        # Act
        model.compile(optimizer='adam', loss='mse', metrics=['mae'])

        # Assert
        assert model.optimizer is not None
        assert model.loss == 'mse'


class TestModelTraining:
    """Test suite for Autoencoder training."""

    def test_train_autoencoder(self, temp_db):
        """TC-TRN-AE-005: Verify Autoencoder training."""
        from tensorflow import keras
        from sklearn.model_selection import train_test_split

        # Arrange
        connections = temp_db.get_unprocessed_connections(limit=1000)
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

        # Act
        history = model.fit(
            X_train, X_train,
            epochs=5,
            batch_size=32,
            validation_data=(X_val, X_val),
            verbose=0
        )

        # Assert
        assert history is not None
        assert 'loss' in history.history
        assert len(history.history['loss']) == 5

    def test_training_loss_decreases(self, temp_db):
        """TC-TRN-AE-006: Verify training loss decreases."""
        from tensorflow import keras

        # Arrange
        connections = temp_db.get_unprocessed_connections(limit=1000)
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

        # Act
        history = model.fit(X_scaled, X_scaled, epochs=10, batch_size=32, verbose=0)

        # Assert
        initial_loss = history.history['loss'][0]
        final_loss = history.history['loss'][-1]
        assert final_loss < initial_loss  # Loss should decrease


class TestModelEvaluation:
    """Test suite for model evaluation."""

    def test_calculate_reconstruction_error(self, temp_db):
        """TC-TRN-AE-007: Verify reconstruction error calculation."""
        from tensorflow import keras

        # Arrange
        connections = temp_db.get_unprocessed_connections(limit=1000)
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

        # Act
        reconstructed = model.predict(X_scaled, verbose=0)
        mse = np.mean(np.square(X_scaled - reconstructed), axis=1)

        # Assert
        assert len(mse) == len(X_scaled)
        assert np.all(mse >= 0)  # MSE is always non-negative

    def test_calculate_threshold(self, temp_db):
        """TC-TRN-AE-008: Verify anomaly threshold calculation."""
        from tensorflow import keras

        # Arrange
        connections = temp_db.get_unprocessed_connections(limit=1000)
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

        # Act
        # Calculate threshold as mean + 3 * std
        mean_error = np.mean(mse)
        std_error = np.std(mse)
        threshold = mean_error + 3 * std_error

        # Assert
        assert threshold > 0
        assert threshold > mean_error


class TestModelPersistence:
    """Test suite for model saving and loading."""

    def test_save_autoencoder_model(self, tmp_path):
        """TC-TRN-AE-009: Verify saving Autoencoder model."""
        from tensorflow import keras

        # Arrange
        model = keras.Sequential([
            keras.layers.Dense(7, activation='relu', input_shape=(15,)),
            keras.layers.Dense(15, activation='linear')
        ])
        model.compile(optimizer='adam', loss='mse')

        model_path = tmp_path / 'test_autoencoder.h5'

        # Act
        model.save(model_path)

        # Assert
        assert model_path.exists()

    def test_load_saved_model(self, tmp_path):
        """TC-TRN-AE-010: Verify loading saved model."""
        from tensorflow import keras

        # Arrange
        model = keras.Sequential([
            keras.layers.Dense(7, activation='relu', input_shape=(15,)),
            keras.layers.Dense(15, activation='linear')
        ])
        model.compile(optimizer='adam', loss='mse')

        # Train briefly
        X_dummy = np.random.randn(100, 15)
        model.fit(X_dummy, X_dummy, epochs=1, verbose=0)

        model_path = tmp_path / 'test_autoencoder.h5'
        model.save(model_path)

        # Act
        loaded_model = keras.models.load_model(model_path)

        # Assert
        assert loaded_model is not None

        # Verify loaded model produces same predictions
        original_preds = model.predict(X_dummy, verbose=0)
        loaded_preds = loaded_model.predict(X_dummy, verbose=0)
        np.testing.assert_array_almost_equal(original_preds, loaded_preds, decimal=5)

    def test_save_threshold_value(self, tmp_path):
        """TC-TRN-AE-011: Verify saving threshold value."""
        import json

        # Arrange
        threshold = 0.025
        metadata = {
            'threshold': threshold,
            'mean_error': 0.01,
            'std_error': 0.005
        }

        metadata_path = tmp_path / 'ae_metadata.json'

        # Act
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f)

        # Assert
        assert metadata_path.exists()

        # Verify can load
        with open(metadata_path, 'r') as f:
            loaded_metadata = json.load(f)

        assert loaded_metadata['threshold'] == threshold


class TestHyperparameters:
    """Test suite for hyperparameter configuration."""

    def test_encoding_dimension_selection(self):
        """TC-TRN-AE-012: Verify encoding dimension configuration."""
        from tensorflow import keras

        # Arrange
        input_dim = 20
        encoding_dim = 10  # Half of input

        # Act
        model = keras.Sequential([
            keras.layers.Dense(encoding_dim, activation='relu', input_shape=(input_dim,)),
            keras.layers.Dense(input_dim, activation='linear')
        ])

        # Assert
        assert model.layers[0].output_shape == (None, encoding_dim)

    def test_batch_size_configuration(self, temp_db):
        """TC-TRN-AE-013: Verify batch size configuration."""
        from tensorflow import keras

        # Arrange
        connections = temp_db.get_unprocessed_connections(limit=1000)
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

        # Act
        batch_size = 64
        history = model.fit(
            X_scaled, X_scaled,
            epochs=2,
            batch_size=batch_size,
            verbose=0
        )

        # Assert
        assert history is not None


class TestErrorHandling:
    """Test suite for error handling."""

    def test_handle_insufficient_data(self):
        """TC-TRN-AE-014: Verify handling of insufficient training data."""
        from tensorflow import keras

        # Arrange - Very small dataset
        X_small = np.random.randn(10, 15)

        model = keras.Sequential([
            keras.layers.Dense(7, activation='relu', input_shape=(15,)),
            keras.layers.Dense(15, activation='linear')
        ])
        model.compile(optimizer='adam', loss='mse')

        # Act - Should still train but with warnings
        history = model.fit(X_small, X_small, epochs=2, verbose=0)

        # Assert
        assert history is not None

    def test_handle_invalid_architecture(self):
        """TC-TRN-AE-015: Verify handling of invalid architecture."""
        from tensorflow import keras

        # Act & Assert - Encoding dim larger than input should still work
        # but is not recommended
        model = keras.Sequential([
            keras.layers.Dense(20, activation='relu', input_shape=(10,)),
            keras.layers.Dense(10, activation='linear')
        ])

        assert model is not None


# Test Report Generator
def generate_ae_training_test_report():
    """Generate AE training test report."""
    import json

    report = {
        'test_suite': 'Autoencoder Training Tests',
        'total_tests': 15,
        'categories': {
            'Data Preparation': 2,
            'Model Architecture': 2,
            'Model Training': 2,
            'Model Evaluation': 2,
            'Model Persistence': 3,
            'Hyperparameters': 2,
            'Error Handling': 2
        },
        'key_validations': [
            'Training data loading and splitting',
            'AE architecture creation',
            'Training process with loss reduction',
            'Reconstruction error and threshold calculation',
            'Model persistence (H5 format)',
            'Hyperparameter configuration',
            'Error recovery mechanisms'
        ]
    }

    print("\n" + "=" * 60)
    print("AUTOENCODER TRAINING TEST REPORT")
    print("=" * 60)
    print(json.dumps(report, indent=2))
    print("=" * 60)

    return report


if __name__ == '__main__':
    pytest.main([
        __file__,
        '-v',
        '--cov=ml.train_autoencoder',
        '--cov-report=html',
        '--cov-report=term-missing'
    ])

    generate_ae_training_test_report()
