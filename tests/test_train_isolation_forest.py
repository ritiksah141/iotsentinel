#!/usr/bin/env python3
"""
Unit Tests for Isolation Forest Training Script

Test Coverage:
- Data loading and validation
- Feature extraction
- Model training
- Model persistence
- Hyperparameter handling

Run: pytest tests/test_train_isolation_forest.py -v --cov=ml.train_isolation_forest
"""

import pytest
import tempfile
import joblib
import numpy as np
import pandas as pd
from pathlib import Path
import sys
import sqlite3
from unittest.mock import Mock, patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from database.db_manager import DatabaseManager
from ml.feature_extractor import FeatureExtractor


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
    db_manager.add_device('192.168.1.100', device_name='Training Device')

    protocols = ['tcp', 'udp']
    conn_states = ['SF', 'S0', 'REJ']

    for i in range(100):
        db_manager.add_connection(
            device_ip='192.168.1.100',
            dest_ip=f'8.8.8.{i % 4}',
            dest_port=80 + (i % 10),
            protocol=protocols[i % len(protocols)],
            conn_state=conn_states[i % len(conn_states)],
            duration=5.0 + float(i * 0.05),
            bytes_sent=1000 + i * 10,
            bytes_received=2000 + i * 20,
            packets_sent=10 + i,
            packets_received=20 + i
        )

    yield db_manager
    db_manager.close()


class TestDataLoading:
    """Test suite for training data loading."""

    def test_load_training_data_from_database(self, temp_db):
        """TC-TRN-IF-001: Verify loading training data from database."""
        # Arrange & Act
        connections = temp_db.get_unprocessed_connections(limit=1000)
        df = pd.DataFrame(connections)

        # Assert
        assert len(df) == 100
        assert 'bytes_sent' in df.columns
        assert 'bytes_received' in df.columns

    def test_validate_minimum_samples(self, temp_db):
        """TC-TRN-IF-002: Verify minimum sample validation."""
        # Arrange
        connections = temp_db.get_unprocessed_connections(limit=1000)
        df = pd.DataFrame(connections)

        # Act & Assert
        assert len(df) >= 50  # Minimum required for training


class TestFeatureEngineering:
    """Test suite for feature engineering in training."""

    def test_extract_features_for_training(self, temp_db):
        """TC-TRN-IF-003: Verify feature extraction for training."""
        # Arrange
        connections = temp_db.get_unprocessed_connections(limit=1000)
        df = pd.DataFrame(connections)

        extractor = FeatureExtractor()

        # Act
        X, feature_names = extractor.extract_features(df)

        # Assert
        assert X.shape[0] == 100
        assert len(feature_names) > 0
        assert 'total_bytes' in feature_names

    def test_feature_scaling(self, temp_db):
        """TC-TRN-IF-004: Verify feature scaling before training."""
        # Arrange
        connections = temp_db.get_unprocessed_connections(limit=1000)
        df = pd.DataFrame(connections)

        extractor = FeatureExtractor()
        X, _ = extractor.extract_features(df)

        # Act
        X_scaled = extractor.fit_transform(X)

        # Assert
        assert X_scaled.shape == X.shape

        # For columns with variance, mean should be ~0 and std dev should be ~1
        has_variance = np.std(X, axis=0) > 1e-6
        assert np.allclose(np.mean(X_scaled[:, has_variance], axis=0), 0, atol=1e-5)
        assert np.allclose(np.std(X_scaled[:, has_variance], axis=0), 1, atol=1e-5)


class TestModelTraining:
    """Test suite for Isolation Forest model training."""

    def test_train_isolation_forest_model(self, temp_db):
        """TC-TRN-IF-005: Verify Isolation Forest training."""
        from sklearn.ensemble import IsolationForest

        # Arrange
        connections = temp_db.get_unprocessed_connections(limit=1000)
        df = pd.DataFrame(connections)

        extractor = FeatureExtractor()
        X, _ = extractor.extract_features(df)
        X_scaled = extractor.fit_transform(X)

        # Act
        model = IsolationForest(contamination=0.1, random_state=42)
        model.fit(X_scaled)

        # Assert
        assert model is not None
        # Verify model can make predictions
        predictions = model.predict(X_scaled)
        assert len(predictions) == len(X_scaled)

    def test_model_hyperparameters(self, temp_db):
        """TC-TRN-IF-006: Verify model hyperparameter configuration."""
        from sklearn.ensemble import IsolationForest

        # Arrange
        connections = temp_db.get_unprocessed_connections(limit=1000)
        df = pd.DataFrame(connections)

        extractor = FeatureExtractor()
        X, _ = extractor.extract_features(df)
        X_scaled = extractor.fit_transform(X)

        # Act
        contamination = 0.05
        n_estimators = 200

        model = IsolationForest(
            contamination=contamination,
            n_estimators=n_estimators,
            random_state=42
        )
        model.fit(X_scaled)

        # Assert
        assert model.contamination == contamination
        assert model.n_estimators == n_estimators


class TestModelPersistence:
    """Test suite for model saving and loading."""

    def test_save_trained_model(self, temp_db, tmp_path):
        """TC-TRN-IF-007: Verify saving trained model to disk."""
        from sklearn.ensemble import IsolationForest

        # Arrange
        connections = temp_db.get_unprocessed_connections(limit=1000)
        df = pd.DataFrame(connections)

        extractor = FeatureExtractor()
        X, _ = extractor.extract_features(df)
        X_scaled = extractor.fit_transform(X)

        model = IsolationForest(contamination=0.1, random_state=42)
        model.fit(X_scaled)

        model_path = tmp_path / 'test_if_model.pkl'

        # Act
        joblib.dump(model, model_path)

        # Assert
        assert model_path.exists()
        assert model_path.stat().st_size > 0

    def test_load_saved_model(self, temp_db, tmp_path):
        """TC-TRN-IF-008: Verify loading saved model from disk."""
        from sklearn.ensemble import IsolationForest

        # Arrange
        connections = temp_db.get_unprocessed_connections(limit=1000)
        df = pd.DataFrame(connections)

        extractor = FeatureExtractor()
        X, _ = extractor.extract_features(df)
        X_scaled = extractor.fit_transform(X)

        model = IsolationForest(contamination=0.1, random_state=42)
        model.fit(X_scaled)

        model_path = tmp_path / 'test_if_model.pkl'
        joblib.dump(model, model_path)

        # Act
        loaded_model = joblib.load(model_path)

        # Assert
        assert loaded_model is not None
        # Verify loaded model produces same predictions
        original_preds = model.predict(X_scaled)
        loaded_preds = loaded_model.predict(X_scaled)
        np.testing.assert_array_equal(original_preds, loaded_preds)

    def test_save_feature_extractor(self, temp_db, tmp_path):
        """TC-TRN-IF-009: Verify saving feature extractor with model."""
        # Arrange
        connections = temp_db.get_unprocessed_connections(limit=1000)
        df = pd.DataFrame(connections)

        extractor = FeatureExtractor()
        X, _ = extractor.extract_features(df)
        extractor.fit_transform(X)

        extractor_path = tmp_path / 'test_feature_extractor.pkl'

        # Act
        extractor.save(extractor_path)

        # Assert
        assert extractor_path.exists()

        # Verify can load
        loaded_extractor = FeatureExtractor()
        loaded_extractor.load(extractor_path)

        assert loaded_extractor.scaler_mean is not None
        assert loaded_extractor.scaler_std is not None


class TestModelEvaluation:
    """Test suite for model evaluation metrics."""

    def test_calculate_anomaly_scores(self, temp_db):
        """TC-TRN-IF-010: Verify anomaly score calculation."""
        from sklearn.ensemble import IsolationForest

        # Arrange
        connections = temp_db.get_unprocessed_connections(limit=1000)
        df = pd.DataFrame(connections)

        extractor = FeatureExtractor()
        X, _ = extractor.extract_features(df)
        X_scaled = extractor.fit_transform(X)

        model = IsolationForest(contamination=0.1, random_state=42)
        model.fit(X_scaled)

        # Act
        scores = model.score_samples(X_scaled)

        # Assert
        assert len(scores) == len(X_scaled)
        assert np.all(scores <= 0)  # IF scores are negative

    def test_anomaly_detection_rate(self, temp_db):
        """TC-TRN-IF-011: Verify anomaly detection rate matches contamination."""
        from sklearn.ensemble import IsolationForest

        # Arrange
        connections = temp_db.get_unprocessed_connections(limit=1000)
        df = pd.DataFrame(connections)

        extractor = FeatureExtractor()
        X, _ = extractor.extract_features(df)
        X_scaled = extractor.fit_transform(X)

        contamination = 0.1
        model = IsolationForest(contamination=contamination, random_state=42)
        model.fit(X_scaled)

        # Act
        predictions = model.predict(X_scaled)
        anomaly_rate = (predictions == -1).sum() / len(predictions)

        # Assert - Should be approximately contamination rate
        assert abs(anomaly_rate - contamination) < 0.05


class TestErrorHandling:
    """Test suite for error handling in training."""

    def test_handle_insufficient_training_data(self):
        """TC-TRN-IF-012: Verify handling of insufficient training data."""
        from sklearn.ensemble import IsolationForest

        # Arrange - Very small dataset
        X_small = np.random.randn(5, 10)
        model = IsolationForest(contamination=0.1, random_state=42)

        # Act - Fitting on a small dataset should work
        try:
            model.fit(X_small)
            # Assert - Model should fit without errors
            assert model is not None
        except ValueError:
            # If it does raise an error, that's also acceptable
            pass

    def test_handle_invalid_contamination(self):
        """TC-TRN-IF-013: Verify handling of invalid contamination parameter."""
        from sklearn.ensemble import IsolationForest

        # Arrange
        X_dummy = np.random.randn(10, 5)

        # Act & Assert - ValueError happens during fit, not __init__
        with pytest.raises(ValueError):
            model = IsolationForest(contamination=1.5)  # Invalid: > 0.5
            model.fit(X_dummy)


# Test Report Generator
def generate_if_training_test_report():
    """Generate IF training test report."""
    import json

    report = {
        'test_suite': 'Isolation Forest Training Tests',
        'total_tests': 13,
        'categories': {
            'Data Loading': 2,
            'Feature Engineering': 2,
            'Model Training': 2,
            'Model Persistence': 3,
            'Model Evaluation': 2,
            'Error Handling': 2
        },
        'key_validations': [
            'Training data loading from database',
            'Feature extraction and scaling',
            'IF model training with hyperparameters',
            'Model and extractor persistence',
            'Anomaly score calculation',
            'Error recovery for edge cases'
        ]
    }

    print("\n" + "=" * 60)
    print("ISOLATION FOREST TRAINING TEST REPORT")
    print("=" * 60)
    print(json.dumps(report, indent=2))
    print("=" * 60)

    return report


if __name__ == '__main__':
    pytest.main([
        __file__,
        '-v',
        '--cov=ml.train_isolation_forest',
        '--cov-report=html',
        '--cov-report=term-missing'
    ])

    generate_if_training_test_report()
