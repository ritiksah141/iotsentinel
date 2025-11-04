#!/usr/bin/env python3
"""
Train Isolation Forest for Anomaly Detection

Isolation Forest is an unsupervised ML algorithm that isolates anomalies.
Works on principle that anomalies are "few and different" - easier to isolate.
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

from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def train_isolation_forest():
    """Train Isolation Forest on baseline data."""
    
    logger.info("=" * 60)
    logger.info("ISOLATION FOREST TRAINING")
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
    
    # Try to load existing feature extractor, or create new one
    extractor_path = Path(config.get('ml', 'feature_extractor_path'))
    extractor = FeatureExtractor()
    
    if extractor_path.exists():
        logger.info("Loading existing feature extractor...")
        extractor.load(extractor_path)
    
    X, feature_names = extractor.extract_features(df)
    
    if X.shape[0] == 0:
        logger.error("No features extracted!")
        db.close()
        return
    
    logger.info(f"Feature matrix shape: {X.shape}")
    
    # 3. Standardize features
    logger.info("Standardizing features...")
    if extractor.scaler_mean is None:
        X_scaled = extractor.fit_transform(X)
        extractor.save(extractor_path)
    else:
        X_scaled = extractor.transform(X)
    
    # 4. Train Isolation Forest
    logger.info("Training Isolation Forest...")
    
    contamination = config.get('ml', 'contamination', default=0.05)
    
    model = IsolationForest(
        contamination=contamination,  # Expected proportion of anomalies
        random_state=42,
        n_estimators=100,
        max_samples='auto',
        n_jobs=-1  # Use all CPU cores
    )
    
    model.fit(X_scaled)
    
    logger.info(f"✓ Model trained with contamination={contamination}")
    
    # 5. Evaluate on training data
    logger.info("Evaluating on training data...")
    predictions = model.predict(X_scaled)
    scores = model.score_samples(X_scaled)
    
    # -1 for anomalies, 1 for normal
    n_anomalies = np.sum(predictions == -1)
    n_normal = np.sum(predictions == 1)
    
    logger.info(f"Predictions: {n_normal} normal, {n_anomalies} anomalies")
    logger.info(f"Score range: [{scores.min():.4f}, {scores.max():.4f}]")
    logger.info(f"Mean score: {scores.mean():.4f}")
    
    # 6. Save model
    model_dir = Path(config.get('ml', 'isolation_forest_path')).parent
    model_dir.mkdir(parents=True, exist_ok=True)
    
    model_path = Path(config.get('ml', 'isolation_forest_path'))
    with open(model_path, 'wb') as f:
        pickle.dump(model, f)
    
    logger.info(f"✓ Model saved: {model_path}")
    
    logger.info("=" * 60)
    logger.info("TRAINING COMPLETE")
    logger.info("=" * 60)
    logger.info(f"Model: {model_path}")
    logger.info(f"Contamination: {contamination}")
    logger.info(f"Input features: {X_scaled.shape[1]}")
    
    db.close()


if __name__ == '__main__':
    train_isolation_forest()