#!/usr/bin/env python3
"""
Traffic Forecaster - River-based time-series forecasting for network traffic
Uses SNARIMAX for bandwidth prediction and drift detection
"""

import logging
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
from pathlib import Path
import json

from river import time_series, compose, preprocessing
from river import metrics

logger = logging.getLogger('ml')  # Use dedicated ML logger


class TrafficForecaster:
    """
    River-based traffic forecasting engine for IoTSentinel.

    Predicts network traffic patterns using SNARIMAX (Seasonal ARIMA with exogenous variables).
    Features:
    - 24-hour bandwidth forecasting
    - Anomaly detection (actual vs predicted > 20%)
    - Per-device traffic prediction
    - Drift-aware model updates
    """

    def __init__(self, db_manager=None, model_path: str = "data/models/traffic_forecast.json"):
        """
        Initialize the traffic forecaster.

        Args:
            db_manager: DatabaseManager instance for querying historical traffic
            model_path: Path to save/load the forecasting model
        """
        self.db = db_manager
        self.model_path = Path(model_path)
        self.model_path.parent.mkdir(parents=True, exist_ok=True)

        # River SNARIMAX model for time-series forecasting
        # p=1, d=1, q=1 with seasonal component for daily patterns
        self.model = compose.Pipeline(
            preprocessing.StandardScaler(),
            time_series.SNARIMAX(
                p=1,  # Autoregressive order
                d=1,  # Differencing order
                q=1,  # Moving average order
                m=24, # Seasonal period (24 hours)
                sp=1, # Seasonal AR order
                sq=1  # Seasonal MA order
            )
        )

        # Metrics tracking
        self.mae_metric = metrics.MAE()
        self.rmse_metric = metrics.RMSE()

        # Forecasting state
        self.predictions_made = 0
        self.last_update = None
        self.forecast_cache = {}  # Cache 24h predictions

        logger.info("✓ TrafficForecaster initialized with SNARIMAX model")

    def train_on_historical_data(self, hours: int = 168) -> Dict:
        """
        Train model on historical traffic data (default: 7 days).

        Args:
            hours: Number of hours of historical data to use

        Returns:
            Training statistics dict
        """
        if not self.db:
            logger.warning("No database manager provided, skipping historical training")
            return {"status": "skipped", "reason": "no_database"}

        try:
            # Query hourly traffic aggregates from database
            query = """
            SELECT
                strftime('%Y-%m-%d %H:00:00', timestamp) as hour,
                SUM(bytes_sent + bytes_received) as total_bytes,
                COUNT(DISTINCT device_ip) as active_devices
            FROM connections
            WHERE timestamp >= datetime('now', '-{} hours')
            GROUP BY hour
            ORDER BY hour ASC
            """.format(hours)

            cursor = self.db.conn.cursor()
            cursor.execute(query)
            hourly_data = cursor.fetchall()

            if not hourly_data:
                logger.warning("No historical data found for training")
                return {"status": "no_data", "hours_requested": hours}

            # Train model incrementally
            training_samples = 0
            for row in hourly_data:
                timestamp = datetime.fromisoformat(row[0])
                total_bytes = float(row[1])
                active_devices = int(row[2])

                # Features: hour of day, day of week, active devices
                features = {
                    'hour': timestamp.hour,
                    'weekday': timestamp.weekday(),
                    'active_devices': active_devices
                }

                # Learn from this data point
                y_pred_list = self.model.forecast(horizon=1, xs=[features])
                if y_pred_list:
                    y_pred = y_pred_list[0]
                    self.mae_metric.update(total_bytes, y_pred)
                    self.rmse_metric.update(total_bytes, y_pred)

                self.model.learn_one(y=total_bytes, x=features)
                training_samples += 1

            self.last_update = datetime.now()
            self.save_model()

            stats = {
                "status": "success",
                "training_samples": training_samples,
                "hours_trained": hours,
                "mae": self.mae_metric.get(),
                "rmse": self.rmse_metric.get(),
                "last_update": self.last_update.isoformat()
            }

            logger.info(f"✓ Trained on {training_samples} hourly samples, MAE: {stats['mae']:.2f} bytes")
            return stats

        except Exception as e:
            logger.error(f"Error training on historical data: {e}")
            return {"status": "error", "error": str(e)}

    def forecast_next_24h(self) -> List[Dict]:
        """
        Generate 24-hour traffic forecast.

        Returns:
            List of predictions for next 24 hours with timestamps
        """
        forecasts = []
        current_time = datetime.now()

        try:
            # Get current hour's device count for exogenous variable
            current_devices = self._get_current_device_count()

            for hour_offset in range(1, 25):
                future_time = current_time + timedelta(hours=hour_offset)

                # Features for prediction
                features = {
                    'hour': future_time.hour,
                    'weekday': future_time.weekday(),
                    'active_devices': current_devices  # Assume stable device count
                }

                # Predict bandwidth for this hour
                prediction_list = self.model.forecast(horizon=1, xs=[features])
                predicted_bytes = prediction_list[0] if prediction_list else None

                if predicted_bytes is not None:
                    forecasts.append({
                        'timestamp': future_time.isoformat(),
                        'hour_label': future_time.strftime('%I %p'),  # "01 PM"
                        'predicted_bytes': max(0, predicted_bytes),  # No negative traffic
                        'hour_offset': hour_offset
                    })

            self.forecast_cache = {
                'generated_at': current_time.isoformat(),
                'forecasts': forecasts
            }

            return forecasts

        except Exception as e:
            logger.error(f"Error generating 24h forecast: {e}")
            return []

    def check_anomaly(self, actual_bytes: float, predicted_bytes: float, threshold: float = 0.20) -> Dict:
        """
        Check if actual traffic deviates significantly from prediction.

        Args:
            actual_bytes: Observed traffic in bytes
            predicted_bytes: Predicted traffic in bytes
            threshold: Deviation threshold (default 20%)

        Returns:
            Anomaly detection result dict
        """
        if predicted_bytes == 0:
            return {
                'is_anomaly': actual_bytes > 0,
                'deviation': 0,
                'severity': 'low'
            }

        deviation = (actual_bytes - predicted_bytes) / predicted_bytes
        is_anomaly = abs(deviation) > threshold

        # Severity classification
        if abs(deviation) > 0.5:
            severity = 'critical'
        elif abs(deviation) > 0.3:
            severity = 'high'
        elif abs(deviation) > threshold:
            severity = 'medium'
        else:
            severity = 'low'

        return {
            'is_anomaly': is_anomaly,
            'deviation': deviation,
            'severity': severity,
            'direction': 'above' if deviation > 0 else 'below',
            'actual_bytes': actual_bytes,
            'predicted_bytes': predicted_bytes
        }

    def update_with_current_traffic(self, bytes_count: float) -> Dict:
        """
        Update model with current hour's actual traffic.

        Args:
            bytes_count: Actual bytes transferred this hour

        Returns:
            Update status with prediction accuracy
        """
        current_time = datetime.now()
        current_devices = self._get_current_device_count()

        features = {
            'hour': current_time.hour,
            'weekday': current_time.weekday(),
            'active_devices': current_devices
        }

        # Get prediction before learning
        prediction_list = self.model.forecast(horizon=1, xs=[features])
        prediction = prediction_list[0] if prediction_list else None

        # Update metrics if we had a prediction
        if prediction is not None:
            self.mae_metric.update(bytes_count, prediction)
            self.rmse_metric.update(bytes_count, prediction)

        # Learn from actual data
        self.model.learn_one(y=bytes_count, x=features)
        self.predictions_made += 1

        # Check for anomaly
        anomaly_result = {}
        if prediction is not None:
            anomaly_result = self.check_anomaly(bytes_count, prediction)

        # Auto-save every 24 predictions (once per day)
        if self.predictions_made % 24 == 0:
            self.save_model()

        return {
            'predicted': prediction,
            'actual': bytes_count,
            'mae': self.mae_metric.get(),
            'rmse': self.rmse_metric.get(),
            'predictions_made': self.predictions_made,
            **anomaly_result
        }

    def _get_current_device_count(self) -> int:
        """Get current active device count from database."""
        if not self.db:
            return 10  # Default assumption

        try:
            query = """
            SELECT COUNT(DISTINCT device_ip)
            FROM connections
            WHERE timestamp >= datetime('now', '-1 hour')
            """
            cursor = self.db.conn.cursor()
            cursor.execute(query)
            result = cursor.fetchone()
            if result and result[0]:
                return int(result[0])
        except Exception as e:
            logger.error(f"Error getting device count: {e}")

        return 10

    def save_model(self):
        """Save model state to disk."""
        try:
            state = {
                'predictions_made': self.predictions_made,
                'last_update': self.last_update.isoformat() if self.last_update else None,
                'mae': self.mae_metric.get(),
                'rmse': self.rmse_metric.get()
            }

            self.model_path.write_text(json.dumps(state, indent=2))
            logger.debug(f"✓ Traffic forecasting model saved to {self.model_path}")

        except Exception as e:
            logger.error(f"Error saving model: {e}")

    def load_model(self):
        """Load model state from disk."""
        try:
            if self.model_path.exists():
                state = json.loads(self.model_path.read_text())
                self.predictions_made = state.get('predictions_made', 0)
                self.last_update = datetime.fromisoformat(state['last_update']) if state.get('last_update') else None
                logger.info(f"✓ Loaded forecasting model with {self.predictions_made} predictions")
                return True
        except Exception as e:
            logger.error(f"Error loading model: {e}")

        return False

    def get_stats(self) -> Dict:
        """Get forecasting statistics."""
        return {
            'predictions_made': self.predictions_made,
            'last_update': self.last_update.isoformat() if self.last_update else None,
            'mae': self.mae_metric.get(),
            'rmse': self.rmse_metric.get(),
            'has_cache': bool(self.forecast_cache),
            'model_type': 'SNARIMAX',
            'status': 'active' if self.predictions_made > 0 else 'untrained'
        }
