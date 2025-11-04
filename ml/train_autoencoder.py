#!/usr/bin/env python3
"""
Train Autoencoder for Anomaly Detection

Trains an autoencoder neural network on baseline "normal" traffic.
The autoencoder learns to reconstruct normal patterns.
Anomalies produce high reconstruction error.
"""

import sys
import numpy as np
import pandas as pd
from pathlib import Path
import logging
import pickle

# Add project root
sys.path.insert(0, str(Path(__file__).parent.parent))

from config.config_manager import config
from database.db_manager import DatabaseManager
from ml.feature_extractor import FeatureExtractor

# TensorFlow imports
try:
    import tensorflow as tf
    from tensorflow import keras
    from tensorflow.keras import layers
    TENSORFLOW_AVAILABLE = True
except ImportError:
    TENSORFLOW_AVAILABLE = False
    print("WARNING: TensorFlow not available. Install with: pip install tensorflow")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def build_autoencoder(input_dim: int, encoding_dim: int = 10):
    """
    Build autoencoder model.
    
    Architecture:
    - Encoder: input_dim -> encoding_dim (compressed representation)
    - Decoder: encoding_dim -> input_dim (reconstruction)
    
    Args:
        input_dim: Number of input features
        encoding_dim: Size of compressed representation
    """
    # Encoder
    encoder_input = layers.Input(shape=(input_dim,))
    encoded = layers.Dense(32, activation='relu')(encoder_input)
    encoded = layers.Dense(16, activation='relu')(encoded)
    encoded = layers.Dense(encoding_dim, activation='relu')(encoded)
    
    # Decoder
    decoded = layers.Dense(16, activation='relu')(encoded)
    decoded = layers.Dense(32, activation='relu')(decoded)
    decoder_output = layers.Dense(input_dim, activation='linear')(decoded)
    
    # Autoencoder model
    autoencoder = keras.Model(encoder_input, decoder_output)
    
    # Compile
    autoencoder.compile(
        optimizer='adam',
        loss='mse',  # Mean Squared Error
        metrics=['mae']
    )
    
    return autoencoder


def train_autoencoder():
    """Train autoencoder on baseline data."""
    
    if not TENSORFLOW_AVAILABLE:
        logger.error("TensorFlow not available. Cannot train autoencoder.")
        return
    
    logger.info("=" * 60)
    logger.info("AUTOENCODER TRAINING")
    logger.info("=" * 60)
    
    # 1. Load baseline data
    db = DatabaseManager(config.get('database', 'path'))
    
    logger.info("Loading baseline connections from database...")
    connections = db.get_unprocessed_connections(limit=10000)
    
    if len(connections) < 100:
        logger.error(f"Insufficient data: {len(connections)} connections")
        logger.error("Need at least 100 connections. Run baseline collection first.")
        db.close()
        return
    
    logger.info(f"Loaded {len(connections)} connections")
    
    # 2. Extract features
    logger.info("Extracting features...")
    df = pd.DataFrame(connections)
    extractor = FeatureExtractor()
    X, feature_names = extractor.extract_features(df)
    
    if X.shape[0] == 0:
        logger.error("No features extracted!")
        db.close()
        return
    
    logger.info(f"Feature matrix shape: {X.shape}")
    logger.info(f"Features: {feature_names}")
    
    # 3. Standardize features
    logger.info("Standardizing features...")
    X_scaled = extractor.fit_transform(X)
    
    # 4. Split train/validation
    split_idx = int(0.8 * len(X_scaled))
    X_train = X_scaled[:split_idx]
    X_val = X_scaled[split_idx:]
    
    logger.info(f"Training set: {X_train.shape[0]} samples")
    logger.info(f"Validation set: {X_val.shape[0]} samples")
    
    # 5. Build model
    logger.info("Building autoencoder model...")
    input_dim = X_train.shape[1]
    encoding_dim = max(5, input_dim // 3)  # Compression ratio ~3:1
    
    model = build_autoencoder(input_dim, encoding_dim)
    model.summary()
    
    # 6. Train model
    logger.info("Training autoencoder...")
    
    early_stop = keras.callbacks.EarlyStopping(
        monitor='val_loss',
        patience=10,
        restore_best_weights=True
    )
    
    history = model.fit(
        X_train, X_train,  # Autoencoder reconstructs input
        epochs=100,
        batch_size=32,
        validation_data=(X_val, X_val),
        callbacks=[early_stop],
        verbose=1
    )
    
    # 7. Calculate reconstruction errors on validation set
    logger.info("Calculating reconstruction errors...")
    X_val_pred = model.predict(X_val)
    reconstruction_errors = np.mean(np.square(X_val - X_val_pred), axis=1)
    
    # Calculate threshold (95th percentile)
    threshold = np.percentile(reconstruction_errors, 95)
    
    logger.info(f"Reconstruction error threshold (95th percentile): {threshold:.4f}")
    logger.info(f"Mean error: {np.mean(reconstruction_errors):.4f}")
    logger.info(f"Std error: {np.std(reconstruction_errors):.4f}")
    
    # 8. Save model
    model_dir = Path(config.get('ml', 'autoencoder_path')).parent
    model_dir.mkdir(parents=True, exist_ok=True)
    
    model_path = Path(config.get('ml', 'autoencoder_path'))
    model.save(model_path)
    logger.info(f"✓ Model saved: {model_path}")
    
    # Save threshold
    threshold_path = model_path.parent / 'autoencoder_threshold.pkl'
    with open(threshold_path, 'wb') as f:
        pickle.dump(threshold, f)
    logger.info(f"✓ Threshold saved: {threshold_path}")
    
    # 9. Save feature extractor
    extractor_path = Path(config.get('ml', 'feature_extractor_path'))
    extractor.save(extractor_path)
    logger.info(f"✓ Feature extractor saved: {extractor_path}")
    
    logger.info("=" * 60)
    logger.info("TRAINING COMPLETE")
    logger.info("=" * 60)
    logger.info(f"Model: {model_path}")
    logger.info(f"Threshold: {threshold:.4f}")
    logger.info(f"Input features: {input_dim}")
    logger.info(f"Encoding dimension: {encoding_dim}")
    
    db.close()


if __name__ == '__main__':
    train_autoencoder()