#!/usr/bin/env python3
"""
Automated Model Retraining for IoTSentinel

Periodically retrains ML models using the latest data to adapt to network changes.
Includes a safety validation step before deploying new models.
"""

import logging
import sys
from pathlib import Path
import pandas as pd
import pickle
from datetime import datetime, timedelta
import numpy as np

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from config.config_manager import config
from database.db_manager import DatabaseManager
from ml.feature_extractor import FeatureExtractor
from ml.train_autoencoder import train_autoencoder
from ml.train_isolation_forest import train_isolation_forest

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def get_retraining_data(db: DatabaseManager, days: int = 30) -> pd.DataFrame:
    """Fetch connection data for retraining."""
    logger.info(f"Fetching data from the last {days} days for retraining...")
    # This is a simplified query. A more robust implementation might need
    # to fetch data in chunks if the dataset is very large.
    query = f"SELECT * FROM connections WHERE timestamp > datetime('now', '-{days} days')"
    conn = db.conn
    df = pd.read_sql_query(query, conn)
    logger.info(f"Fetched {len(df)} records.")
    return df

def validate_new_model(new_model, validation_data: pd.DataFrame, model_type: str, threshold: float = None) -> bool:
    """
    A simple validation to prevent deploying a broken model.
    Checks if the new model flags an unreasonable number of anomalies.
    """
    if validation_data.empty:
        logger.warning("Validation data is empty, cannot validate model.")
        return True # Skip validation if no data

    logger.info(f"Validating new {model_type} model...")
    
    if model_type == 'isolation_forest':
        predictions = new_model.predict(validation_data)
        anomaly_ratio = np.mean(predictions == -1)
    elif model_type == 'autoencoder':
        errors = np.mean(np.square(validation_data - new_model.predict(validation_data)), axis=1)
        anomaly_ratio = np.mean(errors > threshold)
    else:
        return False

    logger.info(f"New model anomaly ratio on recent data: {anomaly_ratio:.2%}")

    # Safety check: If the model flags more than 25% of recent traffic as anomalous,
    # it's likely something is wrong.
    if anomaly_ratio > 0.25:
        logger.error(f"VALIDATION FAILED: New model flagged {anomaly_ratio:.2%} of traffic as anomalous. Aborting deployment.")
        return False
    
    logger.info("✓ Model validation passed.")
    return True

def safe_deploy(model_path: Path, new_model: any, is_tf_model: bool = False):
    """Back up the old model and save the new one."""
    if model_path.exists():
        backup_path = model_path.with_suffix(f".bak_{datetime.now().strftime('%Y%m%d')}")
        model_path.rename(backup_path)
        logger.info(f"Backed up old model to {backup_path}")
        
    if is_tf_model:
        new_model.save(model_path)
    else:
        with open(model_path, 'wb') as f:
            pickle.dump(new_model, f)
            
    logger.info(f"✓ Deployed new model to {model_path}")

def retrain_models():
    """The main function to retrain and deploy all models."""
    logger.info("="*60)
    logger.info("Starting automated model retraining...")
    
    db = DatabaseManager(config.get('database', 'path'))
    
    # 1. Get data
    df = get_retraining_data(db, days=30)
    if df.empty or len(df) < 1000:
        logger.warning("Not enough data to retrain models. Aborting.")
        db.close()
        return

    # 2. Prepare features
    extractor = FeatureExtractor()
    X, _ = extractor.extract_features(df)
    X_scaled = extractor.fit_transform(X)
    
    # Use the last 10% of data for validation
    validation_size = int(len(X_scaled) * 0.1)
    train_data = X_scaled[:-validation_size]
    validation_data = X_scaled[-validation_size:]

    # 3. Retrain Isolation Forest
    logger.info("-" * 20)
    logger.info("Retraining Isolation Forest...")
    new_if_model = train_isolation_forest(pd.DataFrame(train_data))
    if new_if_model and validate_new_model(new_if_model, pd.DataFrame(validation_data), 'isolation_forest'):
        if_path = Path(config.get('ml', 'isolation_forest_path'))
        safe_deploy(if_path, new_if_model)

    # 4. Retrain Autoencoder
    logger.info("-" * 20)
    logger.info("Retraining Autoencoder...")
    try:
        new_ae_model, new_threshold = train_autoencoder(train_data)
        if new_ae_model and validate_new_model(new_ae_model, validation_data, 'autoencoder', new_threshold):
            ae_path = Path(config.get('ml', 'autoencoder_path'))
            threshold_path = ae_path.parent / 'autoencoder_threshold.pkl'
            
            safe_deploy(ae_path, new_ae_model, is_tf_model=True)
            safe_deploy(threshold_path, new_threshold)
            
            # Also save the updated feature extractor/scaler
            extractor_path = Path(config.get('ml', 'feature_extractor_path'))
            extractor.save(extractor_path)
            logger.info(f"✓ Saved updated feature extractor to {extractor_path}")

    except ImportError:
        logger.warning("TensorFlow not found, skipping Autoencoder retraining.")
    except Exception as e:
        logger.error(f"An error occurred during Autoencoder retraining: {e}")

    db.close()
    logger.info("Automated retraining process finished.")
    logger.info("="*60)

if __name__ == '__main__':
    retrain_models()
