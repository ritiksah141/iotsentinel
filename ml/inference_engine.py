#!/usr/bin/env python3
"""
ML Inference Engine for Real-time Anomaly Detection

Uses River-based incremental learning for efficient anomaly detection on Pi.
Generates alerts for anomalies with explanations.

Updated to use RiverMLEngine (incremental learning) and production-ready AlertingSystem.
"""

import sys
import time
import numpy as np
import pandas as pd
from pathlib import Path
import logging
import json

sys.path.insert(0, str(Path(__file__).parent.parent))

from config.config_manager import config
from database.db_manager import DatabaseManager
from ml.feature_extractor import FeatureExtractor
from ml.river_engine import RiverMLEngine
from ml.smart_recommender import SmartRecommender

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

        # Initialize River ML engine (incremental learning)
        self.river_engine = RiverMLEngine(self.db)

        # Initialize smart recommender for context-aware suggestions
        self.recommender = SmartRecommender(self.db)

        self.last_metric_update = time.time()
        self.status_file_path = Path(config.get('system', 'status_file_path', default='config/monitoring_status.json'))

        # Severity thresholds from config
        ml_config = config.get_section('ml')
        self.anomaly_threshold = ml_config.get('anomaly_threshold', 0.7)

        self.severity_thresholds = config.get_section('alerting').get('severity_thresholds', {
            'critical': 0.95,
            'high': 0.85,
            'medium': 0.70,
            'low': 0.50
        })

        logger.info("✓ InferenceEngine initialized with RiverMLEngine (incremental learning)")
        logger.info(f"✓ Anomaly threshold: {self.anomaly_threshold}")

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

    def get_river_stats(self):
        """Get River ML engine statistics for monitoring."""
        return self.river_engine.get_stats()

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
        """Process unprocessed connections using River incremental learning."""
        # Get unprocessed connections
        connections = self.db.get_unprocessed_connections(limit=batch_size)

        if not connections:
            logger.debug("No unprocessed connections")
            return 0

        logger.info(f"Processing {len(connections)} connections with River ML...")

        anomaly_count = 0
        attack_predictions = 0

        for conn in connections:
            conn_id = conn['id']
            device_ip = conn.get('device_ip')
            dest_ip = conn.get('dest_ip')

            # Check against threat intelligence feed first
            try:
                is_malicious = self.db.is_ip_malicious(dest_ip) if dest_ip else False
            except Exception:
                is_malicious = False

            if dest_ip and (is_malicious is True):
                explanation = self._generate_malicious_ip_explanation(device_ip, dest_ip)
                logger.warning(f"MALICIOUS IP DETECTED: {device_ip} to {dest_ip}")

                self._create_alert(
                    device_ip=device_ip,
                    severity='critical',
                    anomaly_score=1.0,
                    explanation=explanation,
                    top_features=json.dumps({'malicious_ip': dest_ip, 'threat_intel': 'blocklist'})
                )

                # Store prediction
                self.db.store_prediction(
                    connection_id=conn_id,
                    is_anomaly=True,
                    anomaly_score=1.0,
                    model_type='threat_intelligence'
                )

                anomaly_count += 1
                continue  # Skip ML inference for known malicious IPs

            # Prepare connection data for River
            connection_data = {
                'device_ip': conn.get('device_ip'),
                'dest_ip': dest_ip,
                'dest_port': conn.get('dest_port'),
                'protocol': conn.get('protocol'),
                'bytes_sent': conn.get('bytes_sent', 0),
                'bytes_received': conn.get('bytes_received', 0),
                'duration': conn.get('duration', 0),
                'packets_sent': conn.get('packets_sent', 0),
                'packets_received': conn.get('packets_received', 0)
            }

            # Analyze with River ML engine (incremental learning happens automatically)
            result = self.river_engine.analyze_connection(connection_data)

            is_anomaly = result['is_anomaly']
            anomaly_score = result['anomaly_score']
            threat_level = result['threat_level']
            attack_type = result.get('predicted_attack')

            # Store prediction
            self.db.store_prediction(
                connection_id=conn_id,
                is_anomaly=is_anomaly,
                anomaly_score=float(anomaly_score),
                model_type='river_incremental'
            )

            # Create alert if anomaly detected
            if is_anomaly and anomaly_score >= self.anomaly_threshold:
                severity = self._calculate_severity(anomaly_score)

                # Generate explanation with River insights
                explanation = self._generate_river_explanation(
                    conn,
                    anomaly_score,
                    threat_level,
                    attack_type
                )

                # Get top contributing features from River result
                top_features = {
                    'anomaly_score': anomaly_score,
                    'threat_level': threat_level,
                    'model': 'river_halfspace_trees'
                }

                if attack_type:
                    top_features['predicted_attack'] = attack_type
                    top_features['attack_confidence'] = result.get('attack_confidence', 0)

                self._create_alert(
                    device_ip=device_ip,
                    severity=severity,
                    anomaly_score=float(anomaly_score),
                    explanation=explanation,
                    top_features=json.dumps(top_features)
                )

                anomaly_count += 1

                if attack_type:
                    attack_predictions += 1
                    logger.warning(
                        f"ATTACK PREDICTED: {device_ip} - {attack_type} "
                        f"(score: {anomaly_score:.2f}, confidence: {result.get('attack_confidence', 0):.0%})"
                    )
                else:
                    logger.warning(
                        f"ANOMALY DETECTED: {device_ip} "
                        f"(score: {anomaly_score:.2f}, severity: {severity})"
                    )

        # Mark as processed
        connection_ids = [conn['id'] for conn in connections]
        self.db.mark_connections_processed(connection_ids)

        logger.info(
            f"✓ Processed {len(connections)} connections | "
            f"Anomalies: {anomaly_count} | Attacks predicted: {attack_predictions}"
        )

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

    def _generate_river_explanation(self, connection, score: float, threat_level: str, attack_type: str = None) -> str:
        """Generate explanation using River ML analysis."""
        device_ip = connection.get('device_ip')
        dest_ip = connection.get('dest_ip', 'unknown')
        dest_port = connection.get('dest_port', 'unknown')
        protocol = connection.get('protocol', 'unknown')
        bytes_sent = connection.get('bytes_sent', 0)
        bytes_received = connection.get('bytes_received', 0)

        explanation_parts = []

        # Opening statement
        explanation_parts.append(
            f"⚠️ Anomalous network activity detected from {device_ip} using River incremental learning."
        )

        # Connection details
        port_info = self._get_port_info(dest_port)
        explanation_parts.append(
            f"Connection: {protocol.upper()} to {dest_ip}:{dest_port} ({port_info})."
        )

        # River analysis
        explanation_parts.append(
            f"River's HalfSpaceTrees model detected unusual patterns "
            f"(anomaly score: {score:.2f}, threat level: {threat_level.upper()})."
        )

        # Attack prediction if available
        if attack_type:
            explanation_parts.append(
                f"🎯 Attack Pattern Detected: {attack_type}. "
                f"This pattern was predicted by River's Hoeffding Adaptive Tree based on "
                f"recent connection sequences from this device."
            )

        # Data transfer concerns
        concerns = []
        if bytes_sent and bytes_sent > 10_000_000:
            concerns.append(f"large upload: {self._format_bytes(bytes_sent)}")
        if bytes_received and bytes_received > 50_000_000:
            concerns.append(f"large download: {self._format_bytes(bytes_received)}")

        if concerns:
            explanation_parts.append(f"Notable: {', '.join(concerns)}.")

        # MITRE mapping
        tactic = self._map_to_mitre(connection)
        explanation_parts.append(f"MITRE ATT&CK: {tactic}.")

        # River learning note
        explanation_parts.append(
            "Note: River continuously learns from your network traffic to improve detection accuracy."
        )

        return " ".join(explanation_parts)

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

    def get_device_risk_scores(self):
        """Get risk scores for all devices from River engine."""
        try:
            devices = self.db.get_all_devices()
            risk_scores = []

            for device in devices:
                device_ip = device.get('ip_address')
                if device_ip:
                    risk_data = self.river_engine.get_device_risk_score(device_ip)
                    risk_scores.append({
                        'device_ip': device_ip,
                        'device_name': device.get('device_name', 'Unknown'),
                        'risk_score': risk_data['risk_score'],
                        'risk_level': risk_data['risk_level'],
                        'failure_probability': risk_data.get('failure_probability', 0),
                        'recommendations': risk_data.get('recommendations', [])
                    })

            # Sort by risk score descending
            risk_scores.sort(key=lambda x: x['risk_score'], reverse=True)
            return risk_scores

        except Exception as e:
            logger.error(f"Error getting device risk scores: {e}")
            return []

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
