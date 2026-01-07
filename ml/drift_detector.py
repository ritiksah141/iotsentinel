#!/usr/bin/env python3
"""
Model Drift Detector for IoTSentinel

Monitors ML model performance degradation over time.
Detects distribution shifts and triggers retraining when needed.
"""

import logging
import sqlite3
import numpy as np
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime, timedelta
from scipy import stats

logger = logging.getLogger(__name__)


class DriftDetector:
    """
    Detects model drift using statistical methods.

    Monitors:
    - Reconstruction error distribution (for autoencoders)
    - Prediction distribution shifts (KL divergence)
    - Performance metrics over time
    """

    def __init__(
        self,
        db_path: str = 'data/iot_monitor.db',
        drift_threshold: float = 0.15,
        baseline_window_days: int = 7
    ):
        """
        Initialize drift detector.

        Args:
            db_path: Path to database
            drift_threshold: Drift score threshold for alerts
            baseline_window_days: Days for baseline calculation
        """
        self.db_path = db_path
        self.drift_threshold = drift_threshold
        self.baseline_window_days = baseline_window_days

        # Baseline statistics
        self.baseline_stats = {}

        logger.info(f"Drift detector initialized (threshold: {drift_threshold})")

    def calculate_baseline_stats(
        self,
        model_type: str,
        metric_type: str = 'reconstruction_error'
    ) -> Optional[Dict[str, float]]:
        """
        Calculate baseline statistics from recent model performance.

        Args:
            model_type: Type of model (autoencoder, isolation_forest)
            metric_type: Type of metric to analyze

        Returns:
            Dictionary with baseline statistics or None
        """
        try:
            # Get recent performance data
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Get data from last N days
            cutoff_date = datetime.now() - timedelta(days=self.baseline_window_days)

            cursor.execute('''
                SELECT anomaly_score, timestamp
                FROM ml_predictions
                WHERE model_type = ? AND timestamp > ?
                ORDER BY timestamp DESC
                LIMIT 10000
            ''', (model_type, cutoff_date.isoformat()))

            rows = cursor.fetchall()
            conn.close()

            if len(rows) < 100:
                logger.warning(f"Insufficient data for baseline calculation: {len(rows)} samples")
                return None

            # Extract scores
            scores = np.array([row[0] for row in rows])

            # Calculate statistics
            baseline_stats = {
                'mean': float(np.mean(scores)),
                'std': float(np.std(scores)),
                'median': float(np.median(scores)),
                'q25': float(np.percentile(scores, 25)),
                'q75': float(np.percentile(scores, 75)),
                'min': float(np.min(scores)),
                'max': float(np.max(scores)),
                'count': len(scores),
                'calculated_at': datetime.now().isoformat()
            }

            # Store baseline
            cache_key = f"{model_type}_{metric_type}"
            self.baseline_stats[cache_key] = baseline_stats

            logger.info(f"Calculated baseline for {model_type}: mean={baseline_stats['mean']:.4f}, std={baseline_stats['std']:.4f}")

            return baseline_stats

        except Exception as e:
            logger.error(f"Error calculating baseline stats: {e}")
            return None

    def check_drift(
        self,
        model_type: str,
        current_scores: List[float],
        metric_type: str = 'reconstruction_error'
    ) -> Tuple[bool, float, Dict[str, Any]]:
        """
        Check if model has drifted from baseline.

        Args:
            model_type: Type of model
            current_scores: Recent prediction scores
            metric_type: Type of metric

        Returns:
            Tuple of (has_drifted, drift_score, details)
        """
        try:
            # Get or calculate baseline
            cache_key = f"{model_type}_{metric_type}"
            baseline = self.baseline_stats.get(cache_key)

            if baseline is None:
                baseline = self.calculate_baseline_stats(model_type, metric_type)

            if baseline is None or len(current_scores) < 30:
                logger.warning("Cannot check drift: insufficient data")
                return False, 0.0, {}

            current_scores = np.array(current_scores)

            # Calculate current statistics
            current_mean = np.mean(current_scores)
            current_std = np.std(current_scores)

            # Method 1: Mean shift detection (3-sigma rule)
            baseline_mean = baseline['mean']
            baseline_std = baseline['std']

            mean_shift = abs(current_mean - baseline_mean)
            normalized_shift = mean_shift / baseline_std if baseline_std > 0 else 0

            # Method 2: KL Divergence for distribution shift
            kl_divergence = self._calculate_kl_divergence(
                baseline_mean,
                baseline_std,
                current_mean,
                current_std
            )

            # Method 3: Kolmogorov-Smirnov test
            # Generate samples from baseline distribution
            baseline_samples = np.random.normal(baseline_mean, baseline_std, len(current_scores))
            ks_statistic, ks_pvalue = stats.ks_2samp(baseline_samples, current_scores)

            # Calculate overall drift score (weighted combination)
            drift_score = (
                normalized_shift * 0.4 +  # Mean shift
                kl_divergence * 0.4 +      # Distribution shift
                ks_statistic * 0.2         # Statistical test
            )

            # Determine if drift occurred
            has_drifted = drift_score > self.drift_threshold

            details = {
                'drift_score': float(drift_score),
                'mean_shift': float(mean_shift),
                'normalized_shift': float(normalized_shift),
                'kl_divergence': float(kl_divergence),
                'ks_statistic': float(ks_statistic),
                'ks_pvalue': float(ks_pvalue),
                'baseline_mean': baseline_mean,
                'baseline_std': baseline_std,
                'current_mean': float(current_mean),
                'current_std': float(current_std),
                'threshold': self.drift_threshold,
                'checked_at': datetime.now().isoformat()
            }

            if has_drifted:
                logger.warning(
                    f"Drift detected in {model_type}: score={drift_score:.4f} "
                    f"(threshold={self.drift_threshold})"
                )
            else:
                logger.info(f"No drift detected in {model_type}: score={drift_score:.4f}")

            return has_drifted, drift_score, details

        except Exception as e:
            logger.error(f"Error checking drift: {e}")
            return False, 0.0, {}

    def _calculate_kl_divergence(
        self,
        mean1: float,
        std1: float,
        mean2: float,
        std2: float
    ) -> float:
        """
        Calculate KL divergence between two Gaussian distributions.

        KL(P||Q) = log(σ2/σ1) + (σ1^2 + (μ1-μ2)^2) / (2σ2^2) - 1/2

        Args:
            mean1, std1: Baseline distribution parameters
            mean2, std2: Current distribution parameters

        Returns:
            KL divergence score
        """
        try:
            if std1 <= 0 or std2 <= 0:
                return 0.0

            kl_div = (
                np.log(std2 / std1) +
                (std1**2 + (mean1 - mean2)**2) / (2 * std2**2) -
                0.5
            )

            return max(0.0, float(kl_div))

        except Exception as e:
            logger.error(f"Error calculating KL divergence: {e}")
            return 0.0

    def log_drift_event(
        self,
        model_type: str,
        drift_score: float,
        metric_type: str,
        baseline_value: float,
        current_value: float,
        alert_triggered: bool
    ):
        """
        Log drift detection event to database.

        Args:
            model_type: Type of model
            drift_score: Calculated drift score
            metric_type: Type of metric analyzed
            baseline_value: Baseline metric value
            current_value: Current metric value
            alert_triggered: Whether alert was triggered
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('''
                INSERT INTO model_drift_history
                (model_type, drift_score, metric_type, baseline_value,
                 current_value, alert_triggered, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                model_type,
                drift_score,
                metric_type,
                baseline_value,
                current_value,
                1 if alert_triggered else 0,
                datetime.now().isoformat()
            ))

            conn.commit()
            conn.close()

            logger.debug(f"Logged drift event for {model_type}")

        except Exception as e:
            logger.error(f"Error logging drift event: {e}")

    def get_drift_history(
        self,
        model_type: Optional[str] = None,
        days: int = 30,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Get drift detection history.

        Args:
            model_type: Filter by model type (None = all)
            days: Number of days to look back
            limit: Maximum results

        Returns:
            List of drift event dictionaries
        """
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cutoff_date = datetime.now() - timedelta(days=days)

            if model_type:
                cursor.execute('''
                    SELECT * FROM model_drift_history
                    WHERE model_type = ? AND timestamp > ?
                    ORDER BY timestamp DESC
                    LIMIT ?
                ''', (model_type, cutoff_date.isoformat(), limit))
            else:
                cursor.execute('''
                    SELECT * FROM model_drift_history
                    WHERE timestamp > ?
                    ORDER BY timestamp DESC
                    LIMIT ?
                ''', (cutoff_date.isoformat(), limit))

            events = [dict(row) for row in cursor.fetchall()]
            conn.close()

            return events

        except Exception as e:
            logger.error(f"Error getting drift history: {e}")
            return []

    def monitor_model_performance(
        self,
        model_type: str,
        window_hours: int = 6
    ) -> Dict[str, Any]:
        """
        Monitor recent model performance and check for drift.

        Args:
            model_type: Type of model to monitor
            window_hours: Time window to analyze (hours)

        Returns:
            Dictionary with monitoring results
        """
        try:
            # Get recent predictions
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cutoff_time = datetime.now() - timedelta(hours=window_hours)

            cursor.execute('''
                SELECT anomaly_score FROM ml_predictions
                WHERE model_type = ? AND timestamp > ?
                ORDER BY timestamp DESC
            ''', (model_type, cutoff_time.isoformat()))

            rows = cursor.fetchall()
            conn.close()

            if len(rows) < 30:
                logger.warning(f"Insufficient recent data for {model_type}: {len(rows)} samples")
                return {
                    'status': 'insufficient_data',
                    'samples_count': len(rows),
                    'window_hours': window_hours
                }

            scores = [row[0] for row in rows]

            # Check for drift
            has_drifted, drift_score, details = self.check_drift(
                model_type=model_type,
                current_scores=scores,
                metric_type='reconstruction_error'
            )

            # Log drift event
            self.log_drift_event(
                model_type=model_type,
                drift_score=drift_score,
                metric_type='reconstruction_error',
                baseline_value=details.get('baseline_mean', 0.0),
                current_value=details.get('current_mean', 0.0),
                alert_triggered=has_drifted
            )

            result = {
                'status': 'drift_detected' if has_drifted else 'normal',
                'model_type': model_type,
                'drift_score': drift_score,
                'threshold': self.drift_threshold,
                'samples_count': len(scores),
                'window_hours': window_hours,
                'details': details,
                'recommendation': self._get_recommendation(drift_score, has_drifted)
            }

            return result

        except Exception as e:
            logger.error(f"Error monitoring model performance: {e}")
            return {
                'status': 'error',
                'error': str(e)
            }

    def _get_recommendation(self, drift_score: float, has_drifted: bool) -> str:
        """Get recommendation based on drift score."""
        if not has_drifted:
            return "Model performance is stable. Continue monitoring."
        elif drift_score < self.drift_threshold * 1.5:
            return "Moderate drift detected. Schedule incremental update."
        elif drift_score < self.drift_threshold * 2.0:
            return "Significant drift detected. Perform incremental update soon."
        else:
            return "Severe drift detected. Trigger full model retraining immediately."

    def get_drift_stats(self) -> Dict[str, Any]:
        """
        Get overall drift detection statistics.

        Returns:
            Dictionary with stats
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Total drift events
            cursor.execute("SELECT COUNT(*) FROM model_drift_history")
            total_events = cursor.fetchone()[0]

            # Events with alerts
            cursor.execute("SELECT COUNT(*) FROM model_drift_history WHERE alert_triggered = 1")
            alert_count = cursor.fetchone()[0]

            # Recent drift events (last 7 days)
            cutoff = (datetime.now() - timedelta(days=7)).isoformat()
            cursor.execute(
                "SELECT COUNT(*) FROM model_drift_history WHERE timestamp > ?",
                (cutoff,)
            )
            recent_count = cursor.fetchone()[0]

            # Average drift score by model type
            cursor.execute('''
                SELECT model_type, AVG(drift_score), COUNT(*)
                FROM model_drift_history
                GROUP BY model_type
            ''')
            by_model = {
                row[0]: {'avg_drift_score': row[1], 'event_count': row[2]}
                for row in cursor.fetchall()
            }

            conn.close()

            return {
                'total_drift_events': total_events,
                'alerts_triggered': alert_count,
                'recent_events_7d': recent_count,
                'by_model_type': by_model
            }

        except Exception as e:
            logger.error(f"Error getting drift stats: {e}")
            return {}


# Global drift detector instance
_drift_detector = None


def get_drift_detector(db_path: str = 'data/iot_monitor.db') -> DriftDetector:
    """
    Get global drift detector instance.

    Args:
        db_path: Path to database

    Returns:
        DriftDetector instance
    """
    global _drift_detector
    if _drift_detector is None:
        _drift_detector = DriftDetector(db_path=db_path)
    return _drift_detector
