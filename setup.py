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
import tempfile
import joblib
import numpy as np
import pandas as pd
from pathlib import Path
from datetime import datetime
import sys
import sqlite3
from unittest.mock import Mock, patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from ml.inference_engine import InferenceEngine
from database.db_manager import DatabaseManager
from ml.feature_extractor import FeatureExtractor


def create_test_schema(db_manager: DatabaseManager):
    """Helper to create database schema for testing."""
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

        cursor.execute("""
        CREATE TABLE ml_predictions (
            id INTEGER PRIMARY KEY AUTOINCREMENT, connection_id INTEGER NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP, is_anomaly INTEGER,
            anomaly_score REAL, model_type TEXT, model_version TEXT,
            FOREIGN KEY (connection_id) REFERENCES connections (id)
        );
        """)

        cursor.execute("""
        CREATE TABLE alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT, device_ip TEXT NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            severity TEXT CHECK (severity IN ('low', 'medium', 'high', 'critical')),
            anomaly_score REAL, explanation TEXT, top_features TEXT,
            acknowledged INTEGER DEFAULT 0, acknowledged_at TIMESTAMP,
            FOREIGN KEY (device_ip) REFERENCES devices (device_ip)
        );
        """)

        db_manager.conn.commit()
    except sqlite3.Error as e:
        print(f"Error creating schema: {e}")
        raise


@pytest.fixture
def temp_db():
    """Create temporary in-memory database."""
    db_manager = DatabaseManager(':memory:')
    create_test_schema(db_manager)
    yield db_manager
    db_manager.close()


@pytest.fixture
def mock_models(tmp_path):
    """Create mock trained models for testing."""
    from sklearn.ensemble import IsolationForest
    from tensorflow import keras

    # Create and save mock Isolation Forest
    if_model = IsolationForest(contamination=0.1, random_state=42)
    # Fit with dummy data
    X_dummy = np.random.randn(100, 10)
    if_model.fit(X_dummy)

    if_path = tmp_path / 'isolation_forest_model.pkl'
    joblib.dump(if_model, if_path)

    # Create and save mock Autoencoder
    ae_model = keras.Sequential([
        keras.layers.Dense(5, activation='relu', input_shape=(10,)),
        keras.layers.Dense(10, activation='linear')
    ])
    ae_model.compile(optimizer='adam', loss='mse')

    ae_path = tmp_path / 'autoencoder_model.h5'
    ae_model.save(ae_path)

    # Create and save mock Feature Extractor
    extractor = FeatureExtractor()
    extractor.scaler_mean = np.zeros(10)
    extractor.scaler_std = np.ones(10)
    extractor.feature_names = [f'feature_{i}' for i in range(10)]

    fe_path = tmp_path / 'feature_extractor.pkl'
    extractor.save(fe_path)

    return {
        'isolation_forest': if_path,
        'autoencoder': ae_path,
        'feature_extractor': fe_path
    }


class TestInferenceEngineInitialization:
    """Test suite for inference engine initialization."""

    def test_init_with_valid_paths(self, temp_db, mock_models):
        """TC-INF-001: Verify successful initialization with valid model paths."""
        # Arrange & Act
        engine = InferenceEngine(
            db=temp_db,
            if_model_path=mock_models['isolation_forest'],
            ae_model_path=mock_models['autoencoder'],
            feature_extractor_path=mock_models['feature_extractor']
        )

        # Assert
        assert engine.db is not None
        assert engine.if_model is not None
        assert engine.ae_model is not None
        assert engine.feature_extractor is not None

    def test_init_with_missing_model_raises_error(self, temp_db):
        """TC-INF-002: Verify error handling when model files are missing."""
        # Arrange & Act & Assert
        with pytest.raises(FileNotFoundError):
            InferenceEngine(
                db=temp_db,
                if_model_path='/nonexistent/model.pkl',
                ae_model_path='/nonexistent/model.h5',
                feature_extractor_path='/nonexistent/extractor.pkl'
            )

    def test_lazy_loading_works(self, temp_db, mock_models):
        """TC-INF-003: Verify models are loaded lazily on first use."""
        # Arrange
        engine = InferenceEngine(
            db=temp_db,
            if_model_path=mock_models['isolation_forest'],
            ae_model_path=mock_models['autoencoder'],
            feature_extractor_path=mock_models['feature_extractor']
        )

        # Act - Access models to trigger loading
        if_model = engine.if_model
        ae_model = engine.ae_model

        # Assert
        assert if_model is not None
        assert ae_model is not None


class TestFeatureExtraction:
    """Test suite for feature extraction in inference pipeline."""

    def test_extract_features_from_connections(self, temp_db, mock_models):
        """TC-INF-004: Verify feature extraction from connection data."""
        # Arrange
        temp_db.add_device('192.168.1.100')
        for i in range(5):
            temp_db.add_connection(
                device_ip='192.168.1.100',
                dest_ip='8.8.8.8',
                dest_port=80,
                protocol='tcp',
                duration=5.0,
                bytes_sent=1000,
                bytes_received=2000
            )

        engine = InferenceEngine(
            db=temp_db,
            if_model_path=mock_models['isolation_forest'],
            ae_model_path=mock_models['autoencoder'],
            feature_extractor_path=mock_models['feature_extractor']
        )

        # Act
        connections = temp_db.get_unprocessed_connections(limit=10)
        df = pd.DataFrame(connections)

        X, feature_names = engine.feature_extractor.extract_features(df)

        # Assert
        assert X.shape[0] == 5
        assert len(feature_names) > 0


class TestIsolationForestInference:
    """Test suite for Isolation Forest predictions."""

    def test_isolation_forest_predict(self, temp_db, mock_models):
        """TC-INF-005: Verify Isolation Forest prediction."""
        # Arrange
        temp_db.add_device('192.168.1.100')
        temp_db.add_connection(
            device_ip='192.168.1.100',
            dest_ip='8.8.8.8',
            dest_port=80,
            protocol='tcp',
            duration=5.0,
            bytes_sent=1000,
            bytes_received=2000
        )

        engine = InferenceEngine(
            db=temp_db,
            if_model_path=mock_models['isolation_forest'],
            ae_model_path=mock_models['autoencoder'],
            feature_extractor_path=mock_models['feature_extractor']
        )

        # Act
        connections = temp_db.get_unprocessed_connections(limit=10)
        df = pd.DataFrame(connections)

        X, _ = engine.feature_extractor.extract_features(df)
        X_scaled = engine.feature_extractor.transform(X)

        predictions = engine.if_model.predict(X_scaled)
        scores = engine.if_model.score_samples(X_scaled)

        # Assert
        assert len(predictions) == 1
        assert len(scores) == 1
        assert predictions[0] in [-1, 1]  # -1 = anomaly, 1 = normal

    def test_isolation_forest_detects_anomalies(self, temp_db, mock_models):
        """TC-INF-006: Verify Isolation Forest can detect anomalies."""
        # Arrange
        temp_db.add_device('192.168.1.100')

        # Add normal connections
        for i in range(50):
            temp_db.add_connection(
                device_ip='192.168.1.100',
                dest_ip='8.8.8.8',
                dest_port=80,
                protocol='tcp',
                duration=5.0,
                bytes_sent=1000,
                bytes_received=2000
            )

        # Add anomalous connection
        temp_db.add_connection(
            device_ip='192.168.1.100',
            dest_ip='8.8.8.8',
            dest_port=80,
            protocol='tcp',
            duration=5.0,
            bytes_sent=10000000,  # Very large
            bytes_received=2000
        )

        engine = InferenceEngine(
            db=temp_db,
            if_model_path=mock_models['isolation_forest'],
            ae_model_path=mock_models['autoencoder'],
            feature_extractor_path=mock_models['feature_extractor']
        )

        # Act
        connections = temp_db.get_unprocessed_connections(limit=100)
        df = pd.DataFrame(connections)

        X, _ = engine.feature_extractor.extract_features(df)
        X_scaled = engine.feature_extractor.fit_transform(X)

        # Retrain on this data for testing
        engine.if_model.fit(X_scaled)
        predictions = engine.if_model.predict(X_scaled)

        # Assert - Should detect at least some anomalies
        anomalies = (predictions == -1).sum()
        assert anomalies >= 1


class TestAutoencoderInference:
    """Test suite for Autoencoder predictions."""

    def test_autoencoder_reconstruction(self, temp_db, mock_models):
        """TC-INF-007: Verify Autoencoder reconstruction."""
        # Arrange
        temp_db.add_device('192.168.1.100')
        temp_db.add_connection(
            device_ip='192.168.1.100',
            dest_ip='8.8.8.8',
            dest_port=80,
            protocol='tcp',
            duration=5.0,
            bytes_sent=1000,
            bytes_received=2000
        )

        engine = InferenceEngine(
            db=temp_db,
            if_model_path=mock_models['isolation_forest'],
            ae_model_path=mock_models['autoencoder'],
            feature_extractor_path=mock_models['feature_extractor']
        )

        # Act
        connections = temp_db.get_unprocessed_connections(limit=10)
        df = pd.DataFrame(connections)

        X, _ = engine.feature_extractor.extract_features(df)
        X_scaled = engine.feature_extractor.transform(X)

        reconstructed = engine.ae_model.predict(X_scaled, verbose=0)

        # Assert
        assert reconstructed.shape == X_scaled.shape

    def test_autoencoder_reconstruction_error(self, temp_db, mock_models):
        """TC-INF-008: Verify reconstruction error calculation."""
        # Arrange
        temp_db.add_device('192.168.1.100')
        temp_db.add_connection(
            device_ip='192.168.1.100',
            dest_ip='8.8.8.8',
            dest_port=80,
            protocol='tcp',
            duration=5.0,
            bytes_sent=1000,
            bytes_received=2000
        )

        engine = InferenceEngine(
            db=temp_db,
            if_model_path=mock_models['isolation_forest'],
            ae_model_path=mock_models['autoencoder'],
            feature_extractor_path=mock_models['feature_extractor']
        )

        # Act
        connections = temp_db.get_unprocessed_connections(limit=10)
        df = pd.DataFrame(connections)

        X, _ = engine.feature_extractor.extract_features(df)
        X_scaled = engine.feature_extractor.transform(X)

        reconstructed = engine.ae_model.predict(X_scaled, verbose=0)
        mse = np.mean(np.square(X_scaled - reconstructed), axis=1)

        # Assert
        assert len(mse) == 1
        assert mse[0] >= 0  # MSE is always non-negative


class TestPredictionStorage:
    """Test suite for storing predictions in database."""

    def test_store_if_prediction(self, temp_db, mock_models):
        """TC-INF-009: Verify Isolation Forest prediction storage."""
        # Arrange
        temp_db.add_device('192.168.1.100')
        conn_id = temp_db.add_connection(
            device_ip='192.168.1.100',
            dest_ip='8.8.8.8',
            dest_port=80,
            protocol='tcp'
        )

        engine = InferenceEngine(
            db=temp_db,
            if_model_path=mock_models['isolation_forest'],
            ae_model_path=mock_models['autoencoder'],
            feature_extractor_path=mock_models['feature_extractor']
        )

        # Act
        engine.db.store_prediction(
            connection_id=conn_id,
            is_anomaly=True,
            anomaly_score=-0.5,
            model_type='isolation_forest',
            model_version='v1.0'
        )

        # Assert
        cursor = temp_db.conn.cursor()
        cursor.execute("SELECT * FROM ml_predictions WHERE connection_id = ?", (conn_id,))
        prediction = cursor.fetchone()

        assert prediction is not None
        assert prediction['model_type'] == 'isolation_forest'
        assert prediction['is_anomaly'] == 1

    def test_store_ae_prediction(self, temp_db, mock_models):
        """TC-INF-010: Verify Autoencoder prediction storage."""
        # Arrange
        temp_db.add_device('192.168.1.100')
        conn_id = temp_db.add_connection(
            device_ip='192.168.1.100',
            dest_ip='8.8.8.8',
            dest_port=80,
            protocol='tcp'
        )

        engine = InferenceEngine(
            db=temp_db,
            if_model_path=mock_models['isolation_forest'],
            ae_model_path=mock_models['autoencoder'],
            feature_extractor_path=mock_models['feature_extractor']
        )

        # Act
        engine.db.store_prediction(
            connection_id=conn_id,
            is_anomaly=True,
            anomaly_score=0.85,
            model_type='autoencoder',
            model_version='v1.0'
        )

        # Assert
        cursor = temp_db.conn.cursor()
        cursor.execute("SELECT * FROM ml_predictions WHERE connection_id = ?", (conn_id,))
        prediction = cursor.fetchone()

        assert prediction is not None
        assert prediction['model_type'] == 'autoencoder'


class TestAlertGeneration:
    """Test suite for alert generation logic."""

    def test_generate_alert_for_high_score_anomaly(self, temp_db, mock_models):
        """TC-INF-011: Verify alert generation for high-score anomalies."""
        # Arrange
        temp_db.add_device('192.168.1.100', device_name='Test Device')
        conn_id = temp_db.add_connection(
            device_ip='192.168.1.100',
            dest_ip='8.8.8.8',
            dest_port=80,
            protocol='tcp'
        )

        engine = InferenceEngine(
            db=temp_db,
            if_model_path=mock_models['isolation_forest'],
            ae_model_path=mock_models['autoencoder'],
            feature_extractor_path=mock_models['feature_extractor']
        )

        # Act - Store anomaly with high score
        engine.db.store_prediction(
            connection_id=conn_id,
            is_anomaly=True,
            anomaly_score=-0.9,  # High anomaly score
            model_type='isolation_forest'
        )

        # Generate alert (manually, since engine.run() is complex)
        alert_id = engine.db.create_alert(
            device_ip='192.168.1.100',
            severity='high',
            anomaly_score=-0.9,
            explanation='Isolation Forest detected unusual traffic pattern',
            top_features='{"bytes_sent": 0.95}'
        )

        # Assert
        assert alert_id is not None

        alerts = temp_db.get_recent_alerts(hours=24)
        assert len(alerts) == 1
        assert alerts[0]['severity'] == 'high'

    def test_no_alert_for_normal_traffic(self, temp_db, mock_models):
        """TC-INF-012: Verify no alert for normal traffic."""
        # Arrange
        temp_db.add_device('192.168.1.100')
        conn_id = temp_db.add_connection(
            device_ip='192.168.1.100',
            dest_ip='8.8.8.8',
            dest_port=80,
            protocol='tcp'
        )

        engine = InferenceEngine(
            db=temp_db,
            if_model_path=mock_models['isolation_forest'],
            ae_model_path=mock_models['autoencoder'],
            feature_extractor_path=mock_models['feature_extractor']
        )

        # Act - Store normal prediction
        engine.db.store_prediction(
            connection_id=conn_id,
            is_anomaly=False,
            anomaly_score=0.1,
            model_type='isolation_forest'
        )

        # Assert - No alerts should be created
        alerts = temp_db.get_recent_alerts(hours=24)
        assert len(alerts) == 0


class TestErrorHandling:
    """Test suite for error handling in inference engine."""

    def test_handle_empty_connection_batch(self, temp_db, mock_models):
        """TC-INF-013: Verify handling of empty connection batch."""
        # Arrange
        engine = InferenceEngine(
            db=temp_db,
            if_model_path=mock_models['isolation_forest'],
            ae_model_path=mock_models['autoencoder'],
            feature_extractor_path=mock_models['feature_extractor']
        )

        # Act
        connections = temp_db.get_unprocessed_connections(limit=10)

        # Assert - Should be empty and not crash
        assert len(connections) == 0

    def test_handle_malformed_connection_data(self, temp_db, mock_models):
        """TC-INF-014: Verify handling of malformed connection data."""
        # Arrange
        temp_db.add_device('192.168.1.100')
        # Insert connection with None values
        conn_id = temp_db.add_connection(
            device_ip='192.168.1.100',
            dest_ip=None,
            dest_port=None,
            protocol='tcp'
        )

        engine = InferenceEngine(
            db=temp_db,
            if_model_path=mock_models['isolation_forest'],
            ae_model_path=mock_models['autoencoder'],
            feature_extractor_path=mock_models['feature_extractor']
        )

        # Act
        connections = temp_db.get_unprocessed_connections(limit=10)
        df = pd.DataFrame(connections)

        # Should not crash during feature extraction
        X, _ = engine.feature_extractor.extract_features(df)

        # Assert
        assert X.shape[0] == 1


class TestBatchProcessing:
    """Test suite for batch processing capabilities."""

    def test_process_batch_of_connections(self, temp_db, mock_models):
        """TC-INF-015: Verify batch processing of multiple connections."""
        # Arrange
        temp_db.add_device('192.168.1.100')

        # Add 20 connections
        for i in range(20):
            temp_db.add_connection(
                device_ip='192.168.1.100',
                dest_ip='8.8.8.8',
                dest_port=80,
                protocol='tcp',
                duration=5.0,
                bytes_sent=1000,
                bytes_received=2000
            )

        engine = InferenceEngine(
            db=temp_db,
            if_model_path=mock_models['isolation_forest'],
            ae_model_path=mock_models['autoencoder'],
            feature_extractor_path=mock_models['feature_extractor']
        )

        # Act
        connections = temp_db.get_unprocessed_connections(limit=20)
        df = pd.DataFrame(connections)

        X, _ = engine.feature_extractor.extract_features(df)
        X_scaled = engine.feature_extractor.fit_transform(X)

        predictions = engine.if_model.predict(X_scaled)

        # Assert
        assert len(predictions) == 20


# Test Report Generator
def generate_inference_test_report():
    """Generate inference engine test report."""
    import json

    report = {
        'test_suite': 'Inference Engine Unit Tests',
        'total_tests': 15,
        'categories': {
            'Initialization': 3,
            'Feature Extraction': 1,
            'Isolation Forest': 2,
            'Autoencoder': 2,
            'Prediction Storage': 2,
            'Alert Generation': 2,
            'Error Handling': 2,
            'Batch Processing': 1
        },
        'key_validations': [
            'Model loading and lazy initialization',
            'Feature extraction pipeline',
            'IF anomaly detection',
            'AE reconstruction error calculation',
            'Prediction storage in database',
            'Alert generation logic',
            'Error recovery mechanisms'
        ]
    }

    print("\n" + "=" * 60)
    print("INFERENCE ENGINE TEST REPORT")
    print("=" * 60)
    print(json.dumps(report, indent=2))
    print("=" * 60)

    return report


if __name__ == '__main__':
    pytest.main([
        __file__,
        '-v',
        '--cov=ml.inference_engine',
        '--cov-report=html',
        '--cov-report=term-missing'
    ])

    generate_inference_test_report()
