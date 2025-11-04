#!/usr/bin/env python3
"""
ML Inference Engine for Real-time Anomaly Detection

Runs trained ML models on new network connections.
Generates alerts for anomalies with explanations.
"""

import sys
import time
import numpy as np
import pandas as pd
from pathlib import Path
import logging
import pickle
import json

sys.path.insert(0, str(Path(__file__).parent.parent))

from config.config_manager import config
from database.db_manager import DatabaseManager
from ml.feature_extractor import FeatureExtractor

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class InferenceEngine:
    """Real-time ML inference engine."""
    
    def __init__(self):
        self.db = DatabaseManager(config.get('database', 'path'))
        self.extractor = FeatureExtractor()
        
        # Load models
        self.autoencoder = None
        self.isolation_forest = None
        self.autoencoder_threshold = None
        
        self._load_models()
    
    def _load_models(self):
        """Load trained ML models."""
        # Load feature extractor
        extractor_path = Path(config.get('ml', 'feature_extractor_path'))
        if extractor_path.exists():
            self.extractor.load(extractor_path)
            logger.info(f"✓ Feature extractor loaded")
        else:
            logger.warning("Feature extractor not found. Train models first.")
        
        # Load Isolation Forest
        if_path = Path(config.get('ml', 'isolation_forest_path'))
        if if_path.exists():
            with open(if_path, 'rb') as f:
                self.isolation_forest = pickle.load(f)
            logger.info(f"✓ Isolation Forest loaded")
        else:
            logger.warning("Isolation Forest not found")
        
        # Load Autoencoder (if TensorFlow available)
        try:
            import tensorflow as tf
            ae_path = Path(config.get('ml', 'autoencoder_path'))
            if ae_path.exists():
                self.autoencoder = tf.keras.models.load_model(ae_path)
                logger.info(f"✓ Autoencoder loaded")
                
                # Load threshold
                threshold_path = ae_path.parent / 'autoencoder_threshold.pkl'
                if threshold_path.exists():
                    with open(threshold_path, 'rb') as f:
                        self.autoencoder_threshold = pickle.load(f)
                    logger.info(f"✓ Threshold: {self.autoencoder_threshold:.4f}")
            else:
                logger.warning("Autoencoder not found")
        except ImportError:
            logger.warning("TensorFlow not available. Autoencoder disabled.")
    
    def process_connections(self, batch_size: int = 100):
        """Process unprocessed connections."""
        # Get unprocessed connections
        connections = self.db.get_unprocessed_connections(limit=batch_size)
        
        if not connections:
            logger.debug("No unprocessed connections")
            return 0
        
        logger.info(f"Processing {len(connections)} connections...")
        
        # Extract features
        df = pd.DataFrame(connections)
        X, feature_names = self.extractor.extract_features(df)
        
        if X.shape[0] == 0:
            logger.warning("No features extracted")
            return 0
        
        # Standardize
        X_scaled = self.extractor.transform(X)
        
        # Run inference
        anomaly_count = 0
        
        for i, (conn_id, features) in enumerate(zip(df['id'], X_scaled)):
            is_anomaly = False
            anomaly_score = 0.0
            model_type = 'none'
            
            # Isolation Forest
            if self.isolation_forest:
                if_pred = self.isolation_forest.predict([features])[0]
                if_score = self.isolation_forest.score_samples([features])[0]
                
                if if_pred == -1:  # Anomaly
                    is_anomaly = True
                    anomaly_score = abs(if_score)
                    model_type = 'isolation_forest'
            
            # Autoencoder
            if self.autoencoder and self.autoencoder_threshold:
                ae_pred = self.autoencoder.predict(features.reshape(1, -1), verbose=0)
                reconstruction_error = np.mean(np.square(features - ae_pred[0]))
                
                if reconstruction_error > self.autoencoder_threshold:
                    is_anomaly = True
                    anomaly_score = max(anomaly_score, reconstruction_error)
                    model_type = 'autoencoder'
            
            # Store prediction
            self.db.store_prediction(
                connection_id=conn_id,
                is_anomaly=is_anomaly,
                anomaly_score=float(anomaly_score),
                model_type=model_type
            )
            
            # Create alert if anomaly
            if is_anomaly:
                device_ip = df.iloc[i]['device_ip']
                severity = self._calculate_severity(anomaly_score)
                explanation = self._generate_explanation(df.iloc[i], anomaly_score, model_type)
                
                # Get top contributing features
                top_features = self._get_top_features(features, feature_names)
                
                self.db.create_alert(
                    device_ip=device_ip,
                    severity=severity,
                    anomaly_score=float(anomaly_score),
                    explanation=explanation,
                    top_features=json.dumps(top_features)
                )
                
                anomaly_count += 1
                logger.warning(f"ANOMALY DETECTED: {device_ip} (score: {anomaly_score:.4f})")
        
        # Mark as processed
        connection_ids = df['id'].tolist()
        self.db.mark_connections_processed(connection_ids)
        
        logger.info(f"✓ Processed {len(connections)} connections, {anomaly_count} anomalies")
        return anomaly_count
    
    def _calculate_severity(self, score: float) -> str:
        """Calculate alert severity based on anomaly score."""
        if score > 1.0:
            return 'critical'
        elif score > 0.5:
            return 'high'
        elif score > 0.2:
            return 'medium'
        else:
            return 'low'
    
    def _generate_explanation(self, connection, score: float, model_type: str) -> str:
        """Generate human-readable explanation."""
        device_ip = connection['device_ip']
        dest_ip = connection.get('dest_ip', 'unknown')
        protocol = connection.get('protocol', 'unknown')
        
        explanation = (
            f"Unusual network activity detected from {device_ip}. "
            f"Connection to {dest_ip} ({protocol}) "
            f"deviated from normal baseline pattern "
            f"(anomaly score: {score:.2f}, model: {model_type})."
        )
        
        return explanation
    
    def _get_top_features(self, features, feature_names, top_n=5):
        """Get top contributing features."""
        # Simple approach: highest absolute values
        abs_features = np.abs(features)
        top_indices = np.argsort(abs_features)[-top_n:][::-1]
        
        top_features = {}
        for idx in top_indices:
            if idx < len(feature_names):
                top_features[feature_names[idx]] = float(features[idx])
        
        return top_features
    
    def run_continuous(self, interval: int = 300):
        """Run inference continuously."""
        logger.info("=" * 60)
        logger.info("INFERENCE ENGINE STARTED")
        logger.info(f"Interval: {interval} seconds")
        logger.info("=" * 60)
        
        try:
            while True:
                self.process_connections()
                time.sleep(interval)
        except KeyboardInterrupt:
            logger.info("Stopping inference engine...")
        finally:
            self.db.close()


def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description='IoTSentinel ML Inference Engine')
    parser.add_argument('--once', action='store_true', help='Process once and exit')
    parser.add_argument('--continuous', action='store_true', help='Run continuously')
    parser.add_argument('--interval', type=int, default=300, help='Interval (seconds)')
    
    args = parser.parse_args()
    
    engine = InferenceEngine()
    
    if args.once:
        engine.process_connections()
    elif args.continuous:
        engine.run_continuous(interval=args.interval)
    else:
        print("Use --once to process once, or --continuous to run as service")


if __name__ == '__main__':
    main()