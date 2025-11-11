#!/usr/bin/env python3
"""
Model Comparison Script for IoTSentinel

Compares the performance of the Isolation Forest and Autoencoder models.

1. Loads a sample of baseline data.
2. Injects synthetic anomalies to create a labeled test set.
3. Generates predictions from both models.
4. Calculates Precision, Recall, and F1-score.
5. Saves the comparison results to CSV, PNG, and JSON files.
"""

import sys
import pickle
import json
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from config.config_manager import config
from database.db_manager import DatabaseManager
from ml.feature_extractor import FeatureExtractor

from sklearn.metrics import precision_recall_fscore_support

# TensorFlow import
try:
    import tensorflow as tf
    TENSORFLOW_AVAILABLE = True
except ImportError:
    TENSORFLOW_AVAILABLE = False


def compare_models():
    """
    Loads models, creates a labeled test set, and compares model performance.
    """
    print("="*60)
    print("Starting Model Comparison")
    print("="*60)

    # 1. Load Models and Feature Extractor
    print("[1/5] Loading models and feature extractor...")
    db = DatabaseManager(config.get('database', 'path'))
    extractor = FeatureExtractor()
    extractor.load(Path(config.get('ml', 'feature_extractor_path')))

    with open(Path(config.get('ml', 'isolation_forest_path')), 'rb') as f:
        isolation_forest = pickle.load(f)

    autoencoder = None
    autoencoder_threshold = None
    if TENSORFLOW_AVAILABLE:
        ae_path = Path(config.get('ml', 'autoencoder_path'))
        if ae_path.exists():
            autoencoder = tf.keras.models.load_model(ae_path)
            threshold_path = ae_path.parent / 'autoencoder_threshold.pkl'
            with open(threshold_path, 'rb') as f:
                autoencoder_threshold = pickle.load(f)
    print("✓ Models loaded.")

    # 2. Create Labeled Test Data
    print("[2/5] Creating labeled test data with synthetic anomalies...")
    # Get a sample of normal data
    normal_connections = db.get_unprocessed_connections(limit=1000)
    if len(normal_connections) < 100:
        print("Error: Not enough data in the database to create a test set.")
        return

    normal_df = pd.DataFrame(normal_connections)
    X_normal, _ = extractor.extract_features(normal_df)
    y_normal = np.zeros(len(X_normal)) # Label as 0 for normal

    # Create synthetic anomalies by perturbing normal data
    anomalous_df = normal_df.sample(n=50, random_state=42).copy()
    # Perturb 'bytes_sent' and 'duration' to create anomalies
    anomalous_df['bytes_sent'] = anomalous_df['bytes_sent'] * np.random.uniform(10, 50, size=len(anomalous_df))
    anomalous_df['duration'] = anomalous_df['duration'] * np.random.uniform(5, 20, size=len(anomalous_df))
    
    X_anomalous, _ = extractor.extract_features(anomalous_df)
    y_anomalous = np.ones(len(X_anomalous)) # Label as 1 for anomaly

    # Combine into a single test set
    X_test = np.vstack([X_normal, X_anomalous])
    y_true = np.concatenate([y_normal, y_anomalous])

    # Standardize the test data
    X_test_scaled = extractor.transform(X_test)
    print(f"✓ Test set created: {len(y_true)} samples ({len(y_anomalous)} anomalies).")

    # 3. Generate Predictions
    print("[3/5] Generating predictions from models...")
    # Isolation Forest predictions
    if_preds_raw = isolation_forest.predict(X_test_scaled)
    y_pred_if = np.where(if_preds_raw == -1, 1, 0) # Convert to 0/1 format

    # Autoencoder predictions
    y_pred_ae = np.zeros_like(y_true)
    if autoencoder and autoencoder_threshold:
        reconstruction_errors = np.mean(np.square(X_test_scaled - autoencoder.predict(X_test_scaled, verbose=0)), axis=1)
        y_pred_ae = np.where(reconstruction_errors > autoencoder_threshold, 1, 0)
    print("✓ Predictions generated.")

    # 4. Calculate Metrics
    print("[4/5] Calculating performance metrics...")
    metrics = {}
    p_if, r_if, f1_if, _ = precision_recall_fscore_support(y_true, y_pred_if, average='binary')
    metrics['Isolation Forest'] = {'Precision': p_if, 'Recall': r_if, 'F1-Score': f1_if}

    if autoencoder:
        p_ae, r_ae, f1_ae, _ = precision_recall_fscore_support(y_true, y_pred_ae, average='binary')
        metrics['Autoencoder'] = {'Precision': p_ae, 'Recall': r_ae, 'F1-Score': f1_ae}
    
    metrics_df = pd.DataFrame(metrics).T
    print("✓ Metrics calculated:")
    print(metrics_df)

    # 5. Save Outputs
    print("[5/5] Saving comparison results...")
    # Save CSV
    csv_path = 'model_comparison.csv'
    metrics_df.to_csv(csv_path)
    print(f"✓ Saved CSV report to {csv_path}")

    # Save JSON
    json_path = 'comparison_report.json'
    with open(json_path, 'w') as f:
        json.dump(metrics, f, indent=4)
    print(f"✓ Saved JSON report to {json_path}")

    # Save Visualization
    plt.style.use('seaborn-v0_8-whitegrid')
    fig, ax = plt.subplots(figsize=(10, 6))
    metrics_df.plot(kind='bar', y='F1-Score', ax=ax, legend=False, color=['skyblue', 'salmon'])
    ax.set_title('Model F1-Score Comparison', fontsize=16)
    ax.set_ylabel('F1-Score', fontsize=12)
    ax.set_xlabel('Model', fontsize=12)
    ax.set_xticklabels(metrics_df.index, rotation=0)
    ax.set_ylim(0, 1)
    for i, v in enumerate(metrics_df['F1-Score']):
        ax.text(i, v + 0.02, f"{v:.3f}", ha='center', va='bottom', fontsize=11)

    viz_path = 'model_comparison_visualization.png'
    plt.tight_layout()
    plt.savefig(viz_path)
    print(f"✓ Saved visualization to {viz_path}")
    
    print("\n" + "="*60)
    print("Comparison Complete!")
    print("="*60)

if __name__ == '__main__':
    compare_models()
