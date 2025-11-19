#!/usr/bin/env python3
"""
Feature Extraction for IoTSentinel ML Models

Extracts numerical features from network connection data
for anomaly detection using Autoencoder and Isolation Forest.
"""

import pandas as pd
import numpy as np
import pickle
from pathlib import Path
import logging
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))
from config.config_manager import config

logger = logging.getLogger(__name__)


class FeatureExtractor:
    """Extract features from network connection data."""

    def __init__(self):
        self.feature_names = []
        self.scaler_mean = None
        self.scaler_std = None

    def extract_features(self, connections_df: pd.DataFrame) -> tuple:
        """
        Extract features from connections DataFrame.

        Args:
            connections_df: DataFrame with connection records

        Returns:
            Tuple of (feature_matrix, feature_names)
        """
        if len(connections_df) == 0:
            # Return empty arrays with specific shape to avoid downstream errors
            return np.empty((0, len(self.feature_names) if self.feature_names else 0)), self.feature_names[:]

        df = connections_df.copy()

        # Convert timestamp
        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'])

        # Initialize feature list
        features = []
        feature_names = []

        # 1. Duration features
        if 'duration' in df.columns:
            df['duration'] = df['duration'].fillna(0)
            features.append(df['duration'].values.reshape(-1, 1))
            feature_names.append('duration')

        # 2. Byte features
        bytes_sent_present = 'bytes_sent' in df.columns
        bytes_received_present = 'bytes_received' in df.columns

        if bytes_sent_present:
            df['bytes_sent'] = df['bytes_sent'].fillna(0)
        else:
            df['bytes_sent'] = 0

        if bytes_received_present:
            df['bytes_received'] = df['bytes_received'].fillna(0)
        else:
            df['bytes_received'] = 0

        # Total bytes
        df['total_bytes'] = df['bytes_sent'] + df['bytes_received']
        features.append(df['total_bytes'].values.reshape(-1, 1))
        feature_names.append('total_bytes')

        # Byte ratio (sent/received)
        df['bytes_ratio'] = np.where(
            df['bytes_received'] > 0,
            df['bytes_sent'] / (df['bytes_received'] + 1), # +1 to avoid div by zero if received=1
            df['bytes_sent']
        )
        features.append(df['bytes_ratio'].values.reshape(-1, 1))
        feature_names.append('bytes_ratio')

        # Individual byte counts
        features.append(df['bytes_sent'].values.reshape(-1, 1))
        feature_names.append('bytes_sent')
        features.append(df['bytes_received'].values.reshape(-1, 1))
        feature_names.append('bytes_received')

        # 3. Packet features
        if 'packets_sent' in df.columns and 'packets_received' in df.columns:
            df['packets_sent'] = df['packets_sent'].fillna(0)
            df['packets_received'] = df['packets_received'].fillna(0)

            df['total_packets'] = df['packets_sent'] + df['packets_received']
            features.append(df['total_packets'].values.reshape(-1, 1))
            feature_names.append('total_packets')

        # 4. Rate features
        if 'duration' in df.columns:
            df['bytes_per_second'] = np.where(
                df['duration'] > 0,
                df['total_bytes'] / df['duration'],
                df['total_bytes'] / 0.001 # Avoid division by zero, use a small epsilon
            )
            features.append(df['bytes_per_second'].values.reshape(-1, 1))
            feature_names.append('bytes_per_second')

        # 5. Temporal features
        if 'timestamp' in df.columns:
            df['hour_of_day'] = df['timestamp'].dt.hour
            df['day_of_week'] = df['timestamp'].dt.dayofweek
            df['is_weekend'] = (df['day_of_week'] >= 5).astype(int)

            features.append(df['hour_of_day'].values.reshape(-1, 1))
            feature_names.append('hour_of_day')
            features.append(df['day_of_week'].values.reshape(-1, 1))
            feature_names.append('day_of_week')
            features.append(df['is_weekend'].values.reshape(-1, 1))
            feature_names.append('is_weekend')

        # 6. Protocol features (one-hot encoding)
        if 'protocol' in df.columns:
            # FIX: Convert to string and lowercase before creating dummies
            protocol_dummies = pd.get_dummies(df['protocol'].astype(str).str.lower(), prefix='proto')
            for col in protocol_dummies.columns:
                features.append(protocol_dummies[col].values.reshape(-1, 1))
                feature_names.append(col)

        # 7. Connection state features
        if 'conn_state' in df.columns:
            # FIX: Fill NA, convert to string, and lowercase before creating dummies
            state_dummies = pd.get_dummies(df['conn_state'].fillna('unknown').astype(str).str.lower(), prefix='state')
            for col in state_dummies.columns:
                features.append(state_dummies[col].values.reshape(-1, 1))
                feature_names.append(col)

        # 8. Port feature (normalized)
        if 'dest_port' in df.columns:
            df['dest_port_norm'] = df['dest_port'].fillna(.0) / 65535.0
            features.append(df['dest_port_norm'].values.reshape(-1, 1))
            feature_names.append('dest_port_norm')

        # Concatenate all features
        if features:
            feature_matrix = np.hstack(features)
            self.feature_names = feature_names

            # Final check to ensure no NaN/inf values are returned
            feature_matrix = np.nan_to_num(feature_matrix, nan=0.0, posinf=0.0, neginf=0.0)

            logger.debug(f"Extracted {len(feature_names)} features from {len(df)} connections")
            return feature_matrix, feature_names
        else:
            logger.warning("No features could be extracted")
            return np.array([]), []

    def fit_scaler(self, X: np.ndarray):
        """Fit standardization scaler on training data."""
        if X.shape[0] == 0:
            logger.warning("Cannot fit scaler on empty data.")
            return

        self.scaler_mean = np.mean(X, axis=0)
        self.scaler_std = np.std(X, axis=0)
        self.scaler_std[self.scaler_std == 0] = 1.0  # Avoid division by zero for constant features
        logger.info("Scaler fitted")

    def transform(self, X: np.ndarray) -> np.ndarray:
        """Standardize features using fitted scaler."""
        if self.scaler_mean is None or self.scaler_std is None:
            logger.warning("Scaler not fitted. Returning original data.")
            return X

        if X.shape[0] == 0:
            logger.debug("Transforming empty array.")
            return X

        return (X - self.scaler_mean) / self.scaler_std

    def fit_transform(self, X: np.ndarray) -> np.ndarray:
        """Fit scaler and transform data."""
        self.fit_scaler(X)
        return self.transform(X)

    def save(self, output_path: Path):
        """Save feature extractor state."""
        state = {
            'feature_names': self.feature_names,
            'scaler_mean': self.scaler_mean,
            'scaler_std': self.scaler_std
        }
        with open(output_path, 'wb') as f:
            pickle.dump(state, f)
        logger.info(f"Feature extractor saved to {output_path}")

    def load(self, input_path: Path):
        """Load feature extractor state."""
        with open(input_path, 'rb') as f:
            state = pickle.load(f)
        self.feature_names = state['feature_names']
        self.scaler_mean = state['scaler_mean']
        self.scaler_std = state['scaler_std']
        logger.info(f"Feature extractor loaded from {input_path}")


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)

    # Test with synthetic data
    from database.db_manager import DatabaseManager

    # Use a test DB path
    db_path = config.get('database', 'path', fallback='data/iot_sentinel.db')

    db = DatabaseManager(db_path)

    # We need to ensure schema exists for this main block test
    # This is a bit of a hack, but necessary if not running via pytest
    try:
        db.get_all_devices()
    except sqlite3.OperationalError:
        print("Running __main__, database tables not found. This is OK if running tests.")
        print("If you are testing the script directly, run init_database.py first.")
        db.close()
        sys.exit()

    connections = db.get_unprocessed_connections(limit=100)

    if connections:
        df = pd.DataFrame(connections)
        extractor = FeatureExtractor()
        X, feature_names = extractor.extract_features(df)

        print(f"\nExtracted features shape: {X.shape}")
        print(f"Feature names: {feature_names}")
        print(f"\nSample features:\n{X[:5]}")
    else:
        print("No connections found in database.")

    db.close()
