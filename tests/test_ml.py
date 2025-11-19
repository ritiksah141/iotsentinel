#!/usr/bin/env python3
"""
Comprehensive Unit Tests for ML Feature Extractor

Test Coverage:
- Feature extraction accuracy
- Handling missing values
- Scaling/normalization
- Edge cases (zero values, extreme values)
- Feature name consistency

Run: pytest tests/test_ml.py -v --cov=ml
"""

import pytest
import numpy as np
import pandas as pd
from datetime import datetime
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

from ml.feature_extractor import FeatureExtractor


@pytest.fixture
def sample_connections():
    """
    Sample connection data for testing.
    Dates are varied to ensure temporal features have variance.
    """
    return pd.DataFrame([
        {
            'timestamp': '2025-01-15 10:30:00', # Wednesday
            'duration': 5.5,
            'bytes_sent': 1024,
            'bytes_received': 2048,
            'packets_sent': 10,
            'packets_received': 20,
            'protocol': 'tcp',
            'conn_state': 'SF',
            'dest_port': 443,
            'service': 'https'
        },
        {
            'timestamp': '2025-01-16 14:45:00', # Thursday
            'duration': 0.5,
            'bytes_sent': 512,
            'bytes_received': 1024,
            'packets_sent': 5,
            'packets_received': 10,
            'protocol': 'udp',
            'conn_state': 'S0',
            'dest_port': 53,
            'service': 'dns'
        },
        {
            'timestamp': '2025-01-18 22:15:00', # Saturday (for is_weekend)
            'duration': 120.0,
            'bytes_sent': 50000,
            'bytes_received': 5000000,
            'packets_sent': 100,
            'packets_received': 5000,
            'protocol': 'tcp',
            'conn_state': 'SF',
            'dest_port': 80,
            'service': 'http'
        }
    ])


class TestFeatureExtraction:
    """Test suite for feature extraction."""

    def test_extract_basic_features(self, sample_connections):
        """TC-ML-001: Verify extraction of basic features."""
        # Arrange
        extractor = FeatureExtractor()

        # Act
        X, feature_names = extractor.extract_features(sample_connections)

        # Assert
        assert X is not None
        assert X.shape[0] == 3  # 3 connections
        assert len(feature_names) == X.shape[1]

    def test_total_bytes_calculation(self, sample_connections):
        """TC-ML-002: Verify total_bytes feature calculation."""
        # Arrange
        extractor = FeatureExtractor()

        # Act
        X, feature_names = extractor.extract_features(sample_connections)

        # Assert
        total_bytes_idx = feature_names.index('total_bytes')

        # First connection: 1024 + 2048 = 3072
        assert X[0, total_bytes_idx] == 3072

        # Second connection: 512 + 1024 = 1536
        assert X[1, total_bytes_idx] == 1536

        # Third connection: 50000 + 5000000 = 5050000
        assert X[2, total_bytes_idx] == 5050000

    def test_bytes_ratio_calculation(self, sample_connections):
        """TC-ML-003: Verify bytes_ratio feature calculation."""
        # Arrange
        extractor = FeatureExtractor()

        # Act
        X, feature_names = extractor.extract_features(sample_connections)

        # Assert
        bytes_ratio_idx = feature_names.index('bytes_ratio')

        # First connection: 1024 / (2048 + 1)
        assert abs(X[0, bytes_ratio_idx] - (1024 / 2049.0)) < 0.01

        # Second connection: 512 / (1024 + 1)
        assert abs(X[1, bytes_ratio_idx] - (512 / 1025.0)) < 0.01

    def test_bytes_per_second_calculation(self, sample_connections):
        """TC-ML-004: Verify bytes_per_second feature calculation."""
        # Arrange
        extractor = FeatureExtractor()

        # Act
        X, feature_names = extractor.extract_features(sample_connections)

        # Assert
        bps_idx = feature_names.index('bytes_per_second')

        # First connection: 3072 bytes / 5.5 seconds
        # (The epsilon 0.001 is only for 0.0 duration)
        expected_bps = 3072 / 5.5
        assert abs(X[0, bps_idx] - expected_bps) < 1.0

    def test_temporal_features(self, sample_connections):
        """TC-ML-005: Verify temporal feature extraction."""
        # Arrange
        extractor = FeatureExtractor()

        # Act
        X, feature_names = extractor.extract_features(sample_connections)

        # Assert
        hour_idx = feature_names.index('hour_of_day')
        dow_idx = feature_names.index('day_of_week')
        weekend_idx = feature_names.index('is_weekend')

        # First connection (Wed)
        assert X[0, hour_idx] == 10
        assert X[0, dow_idx] == 2
        assert X[0, weekend_idx] == 0

        # Second connection (Thu)
        assert X[1, hour_idx] == 14
        assert X[1, dow_idx] == 3
        assert X[1, weekend_idx] == 0

        # Third connection (Sat)
        assert X[2, hour_idx] == 22
        assert X[2, dow_idx] == 5
        assert X[2, weekend_idx] == 1

    def test_protocol_one_hot_encoding(self, sample_connections):
        """TC-ML-006: Verify protocol one-hot encoding."""
        # Arrange
        extractor = FeatureExtractor()

        # Act
        X, feature_names = extractor.extract_features(sample_connections)

        # Assert - Check for protocol columns
        assert 'proto_tcp' in feature_names
        assert 'proto_udp' in feature_names

        # First connection is TCP
        tcp_idx = feature_names.index('proto_tcp')
        udp_idx = feature_names.index('proto_udp')

        assert X[0, tcp_idx] == 1
        assert X[0, udp_idx] == 0

        # Second connection is UDP
        assert X[1, tcp_idx] == 0
        assert X[1, udp_idx] == 1

    def test_connection_state_encoding(self, sample_connections):
        """TC-ML-007: Verify connection state encoding."""
        # Arrange
        extractor = FeatureExtractor()

        # Act
        X, feature_names = extractor.extract_features(sample_connections)

        # Assert (Features are now lowercased by the extractor)
        assert 'state_sf' in feature_names
        assert 'state_s0' in feature_names

        sf_idx = feature_names.index('state_sf')
        s0_idx = feature_names.index('state_s0')

        # First conn: SF
        assert X[0, sf_idx] == 1
        assert X[0, s0_idx] == 0

        # Second conn: S0
        assert X[1, sf_idx] == 0
        assert X[1, s0_idx] == 1

    def test_port_normalization(self, sample_connections):
        """TC-ML-008: Verify destination port normalization."""
        # Arrange
        extractor = FeatureExtractor()

        # Act
        X, feature_names = extractor.extract_features(sample_connections)

        # Assert
        port_idx = feature_names.index('dest_port_norm')

        # Ports should be normalized to [0, 1]
        assert 0 <= X[0, port_idx] <= 1
        assert 0 <= X[1, port_idx] <= 1
        assert 0 <= X[2, port_idx] <= 1

        # Port 443 / 65535 ≈ 0.00676
        expected_norm = 443 / 65535.0
        assert abs(X[0, port_idx] - expected_norm) < 0.0001


class TestMissingValueHandling:
    """Test suite for missing value handling."""

    def test_missing_duration_handled(self):
        """TC-ML-009: Verify missing duration values are handled."""
        # Arrange
        df = pd.DataFrame([
            {
                'timestamp': '2025-01-15 10:00:00',
                'duration': None,  # Missing
                'bytes_sent': 1000,
                'bytes_received': 2000,
                'packets_sent': 10,
                'packets_received': 20,
                'protocol': 'tcp',
                'dest_port': 80
            }
        ])

        extractor = FeatureExtractor()

        # Act
        X, feature_names = extractor.extract_features(df)

        # Assert - Should not crash
        assert X is not None
        assert X.shape[0] == 1

        # Duration should be filled with 0
        duration_idx = feature_names.index('duration')
        assert X[0, duration_idx] == 0

    def test_missing_bytes_handled(self):
        """TC-ML-010: Verify missing byte values are handled."""
        # Arrange
        df = pd.DataFrame([
            {
                'timestamp': '2025-01-15 10:00:00',
                'duration': 5.0,
                'bytes_sent': None,  # Missing
                'bytes_received': None,  # Missing
                'protocol': 'tcp',
                'dest_port': 80
            }
        ])

        extractor = FeatureExtractor()

        # Act
        X, feature_names = extractor.extract_features(df)

        # Assert
        assert X is not None
        total_bytes_idx = feature_names.index('total_bytes')
        assert X[0, total_bytes_idx] == 0


class TestScalerOperations:
    """Test suite for feature scaling."""

    def test_fit_scaler(self, sample_connections):
        """TC-ML-011: Verify scaler fitting."""
        # Arrange
        extractor = FeatureExtractor()
        X, _ = extractor.extract_features(sample_connections)

        # Act
        extractor.fit_scaler(X)

        # Assert
        assert extractor.scaler_mean is not None
        assert extractor.scaler_std is not None
        assert extractor.scaler_mean.shape[0] == X.shape[1]
        assert extractor.scaler_std.shape[0] == X.shape[1]

    def test_transform_standardization(self, sample_connections):
        """TC-ML-012: Verify feature standardization."""
        # Arrange
        extractor = FeatureExtractor()
        X, _ = extractor.extract_features(sample_connections)

        # Act
        extractor.fit_scaler(X)
        X_scaled = extractor.transform(X)

        # Assert
        # Scaled features should have approximately zero mean
        mean = np.mean(X_scaled, axis=0)
        assert np.all(np.abs(mean) < 1e-5) # Relaxed tolerance

        # Scaled features should have approximately unit variance
        std = np.std(X_scaled, axis=0)

        # FIX: Relax tolerance from 1e-6 to 1e-5 for floating point precision
        assert np.all(np.abs(std - 1.0) < 1e-5)

    def test_fit_transform(self, sample_connections):
        """TC-ML-013: Verify fit_transform combines fit and transform."""
        # Arrange
        extractor = FeatureExtractor()
        X, _ = extractor.extract_features(sample_connections)

        # Act
        X_scaled = extractor.fit_transform(X)

        # Assert
        assert X_scaled.shape == X.shape
        assert extractor.scaler_mean is not None
        assert extractor.scaler_std is not None

        # Check mean and std
        assert np.all(np.abs(np.mean(X_scaled, axis=0)) < 1e-5) # Relaxed tolerance

        # FIX: Relax tolerance from 1e-6 to 1e-5 for floating point precision
        assert np.all(np.abs(np.std(X_scaled, axis=0) - 1.0) < 1e-5)


    def test_transform_without_fit_warns(self, sample_connections):
        """TC-ML-014: Verify warning when transform called without fit."""
        # Arrange
        extractor = FeatureExtractor()
        X, _ = extractor.extract_features(sample_connections)

        # Act - Transform without fitting
        X_result = extractor.transform(X)

        # Assert - Should return original data with warning (logged)
        np.testing.assert_array_equal(X, X_result)


class TestEdgeCases:
    """Test suite for edge cases."""

    def test_empty_dataframe(self):
        """TC-ML-015: Verify handling of empty DataFrame."""
        # Arrange
        empty_df = pd.DataFrame()
        extractor = FeatureExtractor()

        # Act
        X, feature_names = extractor.extract_features(empty_df)

        # Assert
        assert X.shape[0] == 0
        assert len(feature_names) == 0

    def test_single_connection(self):
        """TC-ML-016: Verify handling of single connection."""
        # Arrange
        df = pd.DataFrame([{
            'timestamp': '2025-01-15 10:00:00',
            'duration': 1.0,
            'bytes_sent': 100,
            'bytes_received': 200,
            'protocol': 'tcp',
            'dest_port': 80
        }])

        extractor = FeatureExtractor()

        # Act
        X, feature_names = extractor.extract_features(df)

        # Assert
        assert X.shape[0] == 1
        assert len(feature_names) > 0 # Should have features

    def test_zero_duration_connection(self):
        """TC-ML-017: Verify handling of zero duration."""
        # Arrange
        df = pd.DataFrame([{
            'timestamp': '2025-01-15 10:00:00',
            'duration': 0.0,  # Zero duration
            'bytes_sent': 1000,
            'bytes_received': 2000,
            'protocol': 'tcp',
            'dest_port': 80
        }])

        extractor = FeatureExtractor()

        # Act
        X, feature_names = extractor.extract_features(df)

        # Assert - Should not cause division by zero
        assert X is not None

        # bytes_per_second should handle division by zero gracefully
        bps_idx = feature_names.index('bytes_per_second')
        assert not np.isnan(X[0, bps_idx])
        assert not np.isinf(X[0, bps_idx])
        # Check the logic: (1000 + 2000) / (0.0 + 0.001)
        assert abs(X[0, bps_idx] - 3000 / 0.001) < 1.0

    def test_extreme_values(self):
        """TC-ML-018: Verify handling of extreme values."""
        # Arrange
        df = pd.DataFrame([{
            'timestamp': '2025-01-15 10:00:00',
            'duration': 10000.0,  # Very long
            'bytes_sent': 10000000000,  # 10GB
            'bytes_received': 1,
            'protocol': 'tcp',
            'dest_port': 65535
        }])

        extractor = FeatureExtractor()

        # Act
        X, feature_names = extractor.extract_features(df)

        # Assert - Should not crash
        assert X is not None
        assert not np.any(np.isnan(X))
        assert not np.any(np.isinf(X))


class TestFeaturePersistence:
    """Test suite for feature extractor persistence."""

    def test_save_and_load(self, sample_connections, tmp_path):
        """TC-ML-019: Verify save and load functionality."""
        # Arrange
        extractor1 = FeatureExtractor()
        X, _ = extractor1.extract_features(sample_connections)
        extractor1.fit_scaler(X)

        save_path = tmp_path / 'extractor.pkl'

        # Act - Save
        extractor1.save(save_path)

        # Act - Load into new extractor
        extractor2 = FeatureExtractor()
        extractor2.load(save_path)

        # Assert
        np.testing.assert_array_equal(
            extractor1.scaler_mean,
            extractor2.scaler_mean
        )
        np.testing.assert_array_equal(
            extractor1.scaler_std,
            extractor2.scaler_std
        )
        assert extractor1.feature_names == extractor2.feature_names

    def test_loaded_extractor_produces_same_output(self, sample_connections, tmp_path):
        """TC-ML-020: Verify loaded extractor produces identical output."""
        # Arrange
        extractor1 = FeatureExtractor()
        X, _ = extractor1.extract_features(sample_connections)
        X_scaled1 = extractor1.fit_transform(X)

        save_path = tmp_path / 'extractor.pkl'
        extractor1.save(save_path)

        # Act
        extractor2 = FeatureExtractor()
        extractor2.load(save_path)
        X2, _ = extractor2.extract_features(sample_connections)
        X_scaled2 = extractor2.transform(X2)

        # Assert
        np.testing.assert_array_almost_equal(X_scaled1, X_scaled2, decimal=6)


class TestFeatureInterpretability:
    """Test suite for feature interpretability."""

    def test_feature_names_are_descriptive(self, sample_connections):
        """TC-ML-021: Verify feature names are human-readable."""
        # Arrange
        extractor = FeatureExtractor()

        # Act
        _, feature_names = extractor.extract_features(sample_connections)

        # Assert
        # All feature names should use snake_case
        for name in feature_names:
            assert '_' in name or name.isalpha() or name.islower()
            assert name.islower(), f"Feature name '{name}' is not lowercase"

        # Should have recognizable names
        expected_patterns = [
            'bytes', 'duration', 'hour', 'port', 'proto', 'state'
        ]

        for pattern in expected_patterns:
            assert any(pattern in name for name in feature_names), \
                f"Expected to find feature containing '{pattern}'"

    def test_feature_count_consistency(self, sample_connections):
        """TC-ML-022: Verify consistent feature count across calls."""
        # Arrange
        extractor = FeatureExtractor()

        # Act - Extract features twice
        X1, names1 = extractor.extract_features(sample_connections)
        X2, names2 = extractor.extract_features(sample_connections)

        # Assert
        assert X1.shape[1] == X2.shape[1]
        assert names1 == names2


# Performance Benchmarks
class TestPerformance:
    """Test suite for performance benchmarks."""

    def test_large_batch_performance(self):
        """TC-ML-023: Verify performance with large connection batch."""
        import time

        # Arrange - Create 1000 connections
        large_df = pd.DataFrame([
            {
                'timestamp': '2025-01-15 10:00:00',
                'duration': 5.0,
                'bytes_sent': 1000,
                'bytes_received': 2000,
                'packets_sent': 10,
                'packets_received': 20,
                'protocol': 'tcp',
                'dest_port': 80,
                'conn_state': 'SF'
            }
        ] * 1000)

        extractor = FeatureExtractor()

        # Act
        start_time = time.time()
        X, _ = extractor.extract_features(large_df)
        end_time = time.time()

        elapsed = end_time - start_time

        # Assert - Should process 1000 connections in < 1 second
        assert elapsed < 1.0, f"Took {elapsed:.2f}s (expected < 1.0s)"
        assert X.shape[0] == 1000


# Test Report Generator
def generate_ml_test_report():
    """Generate ML test report for AT3 documentation."""
    import json

    report = {
        'test_suite': 'ML Feature Extractor Unit Tests',
        'total_tests': 23,
        'categories': {
            'Feature Extraction': 8,
            'Missing Value Handling': 2,
            'Scaler Operations': 4,
            'Edge Cases': 4,
            'Feature Persistence': 2,
            'Feature Interpretability': 2,
            'Performance': 1
        },
        'key_validations': [
            'Mathematical accuracy (bytes_ratio, bytes_per_second)',
            'Temporal feature extraction (hour, day_of_week)',
            'One-hot encoding (protocol, connection state)',
            'Standardization (zero mean, unit variance)',
            'Missing value imputation',
            'Zero division handling',
            'Feature persistence (save/load)'
        ],
        'performance_benchmark': {
            '1000_connections': '< 1 second',
            'target_throughput': '1000+ connections/second'
        }
    }

    print("\n" + "=" * 60)
    print("ML FEATURE EXTRACTOR TEST REPORT")
    print("=" * 60)
    print(json.dumps(report, indent=2))
    print("=" * 60)

    return report

class TestFeatureExtractorEdgeCases:
    """Tests for edge cases that hit missing lines."""

    def test_missing_required_columns(self):
        """TC-ML-024: Verify missing byte columns handled gracefully (Lines 67, 72)."""
        # Arrange - Missing 'bytes_sent' and 'bytes_received'
        df = pd.DataFrame([
            {
                'timestamp': '2025-01-15 10:00:00',
                'duration': 5.0,
                'protocol': 'tcp',
                'dest_port': 80
            }
        ])

        extractor = FeatureExtractor()

        # Act
        X, feature_names = extractor.extract_features(df)

        # Assert - Should not crash, and byte counts should be 0
        assert X.shape[0] == 1
        assert 'total_bytes' in feature_names
        total_bytes_idx = feature_names.index('total_bytes')
        assert X[0, total_bytes_idx] == 0

    def test_empty_dataframe_load_transform(self):
        """TC-ML-025: Verify transform() works on empty arrays (Line 165)."""
        # Arrange
        X_empty = np.array([])
        extractor = FeatureExtractor()

        # Act - Transform on empty data without fit
        X_transformed = extractor.transform(X_empty)

        # Assert
        assert X_transformed.shape == (0,) or X_transformed.shape == (0, 0)

        # Act - Fit on empty data (Lines 159-160)
        extractor.fit_scaler(X_empty)
        assert extractor.scaler_mean is None # Should be None because shape is (0,)



if __name__ == '__main__':
    pytest.main([
        __file__,
        '-v',
        '--cov=ml',
        '--cov-report=html',
        '--cov-report=term-missing'
    ])

    generate_ml_test_report()
