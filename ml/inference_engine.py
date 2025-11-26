#!/usr/bin/env python3
"""
ML Inference Engine for Real-time Anomaly Detection

Runs trained ML models on new network connections.
Generates alerts for anomalies with explanations.

Updated to use the production-ready AlertingSystem for notifications.
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
    """Real-time ML inference engine with integrated alerting."""

    def __init__(self, alerting_system=None):
        """
        Initialize the inference engine.

        Args:
            alerting_system: Optional AlertingSystem instance for notifications.
                            If not provided, alerts are stored in DB only.
        """
        self.db = DatabaseManager(config.get('database', 'path'))
        self.extractor = FeatureExtractor()
        self.alerting = alerting_system

        # Load models
        self.autoencoder = None
        self.isolation_forest = None
        self.autoencoder_threshold = None

        self._load_models()
        self.last_metric_update = time.time()
        self.status_file_path = Path(config.get('system', 'status_file_path', default='config/monitoring_status.json'))

        # Severity thresholds from config
        self.severity_thresholds = config.get_section('alerting').get('severity_thresholds', {
            'critical': 0.98,
            'high': 0.95,
            'medium': 0.85,
            'low': 0.70
        })

    def set_alerting_system(self, alerting_system):
        """
        Set the alerting system after initialization.

        This allows the orchestrator to inject the alerting system
        after both components are created.

        Args:
            alerting_system: AlertingSystem instance
        """
        self.alerting = alerting_system
        logger.info("Alerting system connected to inference engine")

    def _load_models(self):
        """Load trained ML models."""
        # Load feature extractor
        extractor_path = Path(config.get('ml', 'feature_extractor_path'))
        if extractor_path.exists():
            try:
                self.extractor.load(extractor_path)
                logger.info(f"✓ Feature extractor loaded")
            except Exception as e:
                logger.warning(f"Failed to load feature extractor: {e}")
        else:
            logger.warning("Feature extractor not found. Train models first.")

        # Load Isolation Forest
        if_path = Path(config.get('ml', 'isolation_forest_path'))
        if if_path.exists():
            try:
                with open(if_path, 'rb') as f:
                    self.isolation_forest = pickle.load(f)
                logger.info(f"✓ Isolation Forest loaded")
            except Exception as e:
                logger.warning(f"Failed to load Isolation Forest: {e}")
                self.isolation_forest = None
        else:
            logger.warning("Isolation Forest not found")

        # Load Autoencoder (if TensorFlow available)
        try:
            import tensorflow as tf
            ae_path = Path(config.get('ml', 'autoencoder_path'))
            if ae_path.exists():
                try:
                    self.autoencoder = tf.keras.models.load_model(ae_path)
                    logger.info(f"✓ Autoencoder loaded")

                    # Load threshold
                    threshold_path = ae_path.parent / f"{ae_path.stem}_threshold.pkl"
                    if threshold_path.exists():
                        try:
                            with open(threshold_path, 'rb') as f:
                                self.autoencoder_threshold = pickle.load(f)
                            logger.info(f"✓ Threshold: {self.autoencoder_threshold:.4f}")
                        except Exception as e:
                            logger.warning(f"Failed to load autoencoder threshold: {e}")
                except Exception as e:
                    logger.warning(f"Failed to load Autoencoder: {e}")
                    self.autoencoder = None
            else:
                logger.warning("Autoencoder not found")
        except ImportError:
            logger.warning("TensorFlow not available. Autoencoder disabled.")

    def _create_alert(self, device_ip: str, severity: str, anomaly_score: float,
                      explanation: str, top_features: str = None) -> int:
        """
        Create an alert using the alerting system if available, otherwise direct to DB.

        Args:
            device_ip: Device IP address
            severity: Alert severity level
            anomaly_score: ML anomaly score
            explanation: Human-readable explanation
            top_features: JSON string of top contributing features

        Returns:
            Alert ID if created successfully
        """
        if self.alerting:
            # Use the full alerting system (with notifications)
            return self.alerting.create_alert(
                device_ip=device_ip,
                severity=severity,
                anomaly_score=anomaly_score,
                explanation=explanation,
                top_features=top_features
            )
        else:
            # Fallback to direct database insert (no notifications)
            return self.db.create_alert(
                device_ip=device_ip,
                severity=severity,
                anomaly_score=anomaly_score,
                explanation=explanation,
                top_features=top_features
            )

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

            # Check against threat intelligence feed
            dest_ip = df.iloc[i].get('dest_ip')
            try:
                is_malicious = self.db.is_ip_malicious(dest_ip)
            except Exception:
                is_malicious = False

            if dest_ip and (is_malicious is True):
                device_ip = df.iloc[i]['device_ip']
                explanation = self._generate_malicious_ip_explanation(device_ip, dest_ip)
                logger.warning(f"MALICIOUS IP DETECTED: {device_ip} to {dest_ip}")

                self._create_alert(
                    device_ip=device_ip,
                    severity='critical',
                    anomaly_score=1.0,
                    explanation=explanation,
                    top_features=json.dumps({'malicious_ip': dest_ip})
                )

                anomaly_count += 1
                continue  # Skip ML inference for this connection

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

                self._create_alert(
                    device_ip=device_ip,
                    severity=severity,
                    anomaly_score=float(anomaly_score),
                    explanation=explanation,
                    top_features=json.dumps(top_features)
                )

                anomaly_count += 1
                logger.warning(f"ANOMALY DETECTED: {device_ip} (score: {anomaly_score:.4f}, severity: {severity})")

        # Mark as processed
        connection_ids = df['id'].tolist()
        self.db.mark_connections_processed(connection_ids)

        logger.info(f"✓ Processed {len(connections)} connections, {anomaly_count} anomalies")
        return anomaly_count

    def _calculate_severity(self, score: float) -> str:
        """
        Calculate alert severity based on anomaly score.

        Uses configurable thresholds from alerting config.
        """
        thresholds = self.severity_thresholds

        if score >= thresholds.get('critical', 0.98):
            return 'critical'
        elif score >= thresholds.get('high', 0.95):
            return 'high'
        elif score >= thresholds.get('medium', 0.85):
            return 'medium'
        else:
            return 'low'

    def _generate_malicious_ip_explanation(self, device_ip: str, dest_ip: str) -> str:
        """Generate explanation for malicious IP detection."""
        return (
            f"🚨 CRITICAL: Your device at {device_ip} attempted to connect to a known "
            f"malicious IP address ({dest_ip}). This IP is on our threat intelligence "
            f"blocklist and may be associated with malware, botnets, or other cyber threats. "
            f"Immediate investigation is recommended. Check the device for signs of compromise "
            f"such as unusual processes, unexpected network activity, or recently installed software. "
            f"Potential MITRE Tactic: Command and Control (TA0011)."
        )

    def _generate_explanation(self, connection, score: float, model_type: str) -> str:
        """Generate human-readable educational explanation."""
        device_ip = connection['device_ip']
        dest_ip = connection.get('dest_ip', 'unknown')
        dest_port = connection.get('dest_port', 'unknown')
        protocol = connection.get('protocol', 'unknown')
        bytes_sent = connection.get('bytes_sent', 0)
        bytes_received = connection.get('bytes_received', 0)
        duration = connection.get('duration', 0)

        # Build educational explanation
        explanation_parts = []

        # What happened
        explanation_parts.append(
            f"Unusual network activity detected from your device at {device_ip}."
        )

        # Connection details
        port_info = self._get_port_info(dest_port)
        explanation_parts.append(
            f"The device made a {protocol.upper()} connection to {dest_ip} on port {dest_port} ({port_info})."
        )

        # Why it's unusual
        if model_type == 'isolation_forest':
            explanation_parts.append(
                f"Our Isolation Forest model flagged this connection because it stands out "
                f"from your network's normal patterns (anomaly score: {score:.2f})."
            )
        elif model_type == 'autoencoder':
            explanation_parts.append(
                f"Our Autoencoder model detected this activity because it couldn't accurately "
                f"reconstruct the connection pattern, indicating it's different from learned normal behavior "
                f"(reconstruction error: {score:.2f})."
            )

        # Specific concerns
        concerns = []
        if bytes_sent and bytes_sent > 10_000_000:  # 10MB
            concerns.append(f"large data upload ({self._format_bytes(bytes_sent)})")
        if bytes_received and bytes_received > 50_000_000:  # 50MB
            concerns.append(f"large data download ({self._format_bytes(bytes_received)})")
        if duration and duration > 3600:  # 1 hour
            concerns.append(f"unusually long connection ({duration/3600:.1f} hours)")
        if dest_port in [22, 23, 3389, 5900]:
            concerns.append("remote access port")

        if concerns:
            explanation_parts.append(
                f"Specific concerns: {', '.join(concerns)}."
            )

        # MITRE mapping
        tactic = self._map_to_mitre(connection)
        explanation_parts.append(f"Potential MITRE ATT&CK Tactic: {tactic}.")

        return " ".join(explanation_parts)

    def _get_port_info(self, port) -> str:
        """Get human-readable port description."""
        common_ports = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP/Email',
            53: 'DNS',
            80: 'HTTP/Web',
            110: 'POP3/Email',
            143: 'IMAP/Email',
            443: 'HTTPS/Secure Web',
            445: 'SMB/File Sharing',
            993: 'Secure IMAP',
            995: 'Secure POP3',
            1433: 'MS SQL',
            3306: 'MySQL',
            3389: 'Remote Desktop',
            5432: 'PostgreSQL',
            5900: 'VNC',
            8080: 'HTTP Proxy',
            8443: 'HTTPS Alt'
        }
        try:
            port_num = int(port)
            return common_ports.get(port_num, 'unknown service')
        except (TypeError, ValueError):
            return 'unknown service'

    def _map_to_mitre(self, connection) -> str:
        """Map connection characteristics to MITRE ATT&CK tactics."""
        bytes_sent = connection.get('bytes_sent', 0) or 0
        dest_port = connection.get('dest_port')
        conn_state = connection.get('conn_state', '')

        # Check for data exfiltration
        if bytes_sent > 10_000_000:
            return "Exfiltration (TA0010) - Large outbound data transfer"

        # Check for lateral movement
        if dest_port in [22, 3389, 445, 5900, 23]:
            return "Lateral Movement (TA0008) - Remote access protocol"

        # Check for scanning
        if conn_state and conn_state != 'SF':
            return "Discovery (TA0007) - Possible network scanning"

        # Check for C2
        if dest_port in [4444, 5555, 6666, 1337, 31337]:
            return "Command and Control (TA0011) - Suspicious port"

        # Default
        return "Unknown - Further investigation recommended"

    def _format_bytes(self, bytes_val: int) -> str:
        """Format bytes to human-readable string."""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes_val < 1024:
                return f"{bytes_val:.1f} {unit}"
            bytes_val /= 1024
        return f"{bytes_val:.1f} TB"

    def _get_top_features(self, features, feature_names, top_n=5):
        """Get top contributing features."""
        abs_features = np.abs(features)
        top_indices = np.argsort(abs_features)[-top_n:][::-1]

        top_features = {}
        for idx in top_indices:
            if idx < len(feature_names):
                top_features[feature_names[idx]] = float(features[idx])

        return top_features

    def _is_monitoring_paused(self) -> bool:
        """Check if monitoring is paused via status file."""
        try:
            if self.status_file_path.exists():
                with open(self.status_file_path, 'r') as f:
                    status = json.load(f)
                    return status.get('status') == 'paused'
        except Exception:
            pass
        return False

    def run_continuous(self, interval: int = 300):
        """Run inference continuously."""
        logger.info("=" * 60)
        logger.info("INFERENCE ENGINE STARTED")
        logger.info(f"Interval: {interval} seconds")
        logger.info(f"Alerting system: {'Connected' if self.alerting else 'Not connected (DB only)'}")
        logger.info("=" * 60)

        try:
            while True:
                if self._is_monitoring_paused():
                    logger.info("Monitoring is paused. Checking again in 60 seconds...")
                    time.sleep(60)
                    continue

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
    parser.add_argument('--with-alerts', action='store_true', help='Enable email alerting')

    args = parser.parse_args()

    # Optionally initialize alerting system
    alerting = None
    if args.with_alerts:
        try:
            from alerts.integration import AlertingSystem
            db = DatabaseManager(config.get('database', 'path'))
            alerting = AlertingSystem(db, config)
            alerting.start()
            logger.info("Alerting system enabled")
        except ImportError:
            logger.warning("Alerting module not found. Running without notifications.")
        except Exception as e:
            logger.warning(f"Failed to initialize alerting: {e}")

    engine = InferenceEngine(alerting_system=alerting)

    try:
        if args.once:
            engine.process_connections()
        elif args.continuous:
            engine.run_continuous(interval=args.interval)
        else:
            print("Use --once to process once, or --continuous to run as service")
            print("Add --with-alerts to enable email notifications")
    finally:
        if alerting:
            alerting.stop()


if __name__ == '__main__':
    main()
