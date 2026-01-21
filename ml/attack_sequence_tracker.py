#!/usr/bin/env python3
"""
Attack Sequence Tracker - Pattern-based attack prediction
Tracks event sequences (Port Scan → SSH Fail → Brute Force) and predicts attacks
"""

import logging
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
from pathlib import Path
import json
from collections import deque, defaultdict

from river import tree, metrics

logger = logging.getLogger('ml')  # Use dedicated ML logger


class AttackSequenceTracker:
    """
    Tracks attack event sequences and predicts likely attacks using HoeffdingTree.

    Features:
    - Pattern detection (Port Scan → Failed Login → Brute Force)
    - Sequence-based attack prediction
    - Per-device attack history
    - Confidence scoring for predictions
    """

    # Known attack patterns (sequence → likely next step)
    ATTACK_PATTERNS = {
        ('port_scan',): {
            'next_likely': ['ssh_bruteforce', 'service_exploitation', 'ddos'],
            'confidence': 0.65,
            'severity': 'medium',
            'description': 'Port scanning often precedes targeted attacks'
        },
        ('port_scan', 'failed_login'): {
            'next_likely': ['ssh_bruteforce', 'credential_stuffing'],
            'confidence': 0.85,
            'severity': 'high',
            'description': 'Port scan + failed logins indicate active attack attempt'
        },
        ('failed_login', 'failed_login', 'failed_login'): {
            'next_likely': ['ssh_bruteforce', 'account_lockout'],
            'confidence': 0.90,
            'severity': 'critical',
            'description': 'Repeated failures indicate brute force attack'
        },
        ('data_exfiltration',): {
            'next_likely': ['malware_callback', 'lateral_movement'],
            'confidence': 0.75,
            'severity': 'critical',
            'description': 'Data exfiltration suggests compromised device'
        },
        ('unusual_traffic',): {
            'next_likely': ['data_exfiltration', 'ddos', 'botnet_communication'],
            'confidence': 0.60,
            'severity': 'medium',
            'description': 'Unusual traffic may indicate reconnaissance'
        },
        ('malicious_ip',): {
            'next_likely': ['malware_download', 'c2_communication', 'data_exfiltration'],
            'confidence': 0.80,
            'severity': 'high',
            'description': 'Communication with known malicious IP'
        }
    }

    # Map alert types to sequence events
    ALERT_TO_EVENT = {
        'Scanning Behavior Detected': 'port_scan',
        'Unusual Port Activity': 'port_scan',
        'Connection to Known Malicious IP': 'malicious_ip',
        'High Outbound Traffic': 'data_exfiltration',
        'High Ratio of Outbound to Inbound Bytes': 'data_exfiltration',
        'Excessive Connection Attempts': 'failed_login',
        'Anomalous Connection Time': 'unusual_traffic',
        'Unusual Protocol Usage': 'unusual_traffic'
    }

    def __init__(self, db_manager=None, model_path: str = "data/models/attack_sequences.json"):
        """
        Initialize attack sequence tracker.

        Args:
            db_manager: DatabaseManager for querying alert history
            model_path: Path to save/load sequence data
        """
        self.db = db_manager
        self.model_path = Path(model_path)
        self.model_path.parent.mkdir(parents=True, exist_ok=True)

        # HoeffdingTree for attack type classification
        self.classifier = tree.HoeffdingAdaptiveTreeClassifier(
            grace_period=50,
            max_depth=10,
            leaf_prediction='nba'  # Naive Bayes Adaptive
        )

        # Track sequences per device (last 10 events)
        self.device_sequences: Dict[str, deque] = defaultdict(lambda: deque(maxlen=10))

        # Track predictions made
        self.predictions_made = 0
        self.correct_predictions = 0

        # Metrics
        self.accuracy = metrics.Accuracy()

        # Sequence database (persistent storage)
        self.sequences_db: List[Dict] = []

        logger.info("✓ AttackSequenceTracker initialized with HoeffdingTree")

    def add_event(self, device_ip: str, alert_type: str, severity: str) -> Dict:
        """
        Add an alert event to the sequence tracker.

        Args:
            device_ip: Device that triggered alert
            alert_type: Type of alert (maps to event)
            severity: Alert severity

        Returns:
            Prediction dict with likely next attacks
        """
        # Map alert type to event
        event = self.ALERT_TO_EVENT.get(alert_type, 'unknown')

        if event == 'unknown':
            logger.debug(f"Unknown alert type: {alert_type}")
            return {'status': 'unknown_event', 'predictions': []}

        # Add to device sequence
        timestamp = datetime.now()
        self.device_sequences[device_ip].append({
            'event': event,
            'timestamp': timestamp,
            'severity': severity
        })

        # Get recent sequence (last 3 events)
        recent_events = list(self.device_sequences[device_ip])[-3:]
        sequence_tuple = tuple(e['event'] for e in recent_events)

        # Check for known patterns
        predictions = []

        # Try matching sequences of length 3, 2, 1
        for seq_len in [3, 2, 1]:
            if len(sequence_tuple) >= seq_len:
                check_seq = sequence_tuple[-seq_len:]
                if check_seq in self.ATTACK_PATTERNS:
                    pattern = self.ATTACK_PATTERNS[check_seq]
                    predictions.append({
                        'pattern_matched': list(check_seq),
                        'next_likely': pattern['next_likely'],
                        'confidence': pattern['confidence'],
                        'severity': pattern['severity'],
                        'description': pattern['description'],
                        'device_ip': device_ip,
                        'timestamp': timestamp.isoformat()
                    })
                    break  # Use most specific match

        # Train classifier with this sequence
        if len(sequence_tuple) >= 2:
            features = self._extract_sequence_features(recent_events)
            # Predict next event (if we don't know yet, use current as label for training)
            self.classifier.learn_one(features, event)
            self.predictions_made += 1

        # Save to sequences database
        self.sequences_db.append({
            'device_ip': device_ip,
            'event': event,
            'alert_type': alert_type,
            'severity': severity,
            'timestamp': timestamp.isoformat(),
            'sequence_length': len(self.device_sequences[device_ip]),
            'predictions': predictions
        })

        # Auto-save every 50 events
        if len(self.sequences_db) % 50 == 0:
            self.save_sequences()

        result = {
            'status': 'tracked',
            'event': event,
            'device_ip': device_ip,
            'sequence_length': len(self.device_sequences[device_ip]),
            'predictions': predictions
        }

        if predictions:
            logger.info(f"🎯 Attack pattern detected for {device_ip}: {predictions[0]['description']}")

        return result

    def predict_next_attack(self, device_ip: str) -> Optional[Dict]:
        """
        Predict the next likely attack for a device based on its sequence.

        Args:
            device_ip: Device to predict for

        Returns:
            Prediction dict or None
        """
        if device_ip not in self.device_sequences or len(self.device_sequences[device_ip]) < 2:
            return None

        recent_events = list(self.device_sequences[device_ip])[-3:]
        features = self._extract_sequence_features(recent_events)

        # Get classifier prediction
        try:
            prediction_proba = self.classifier.predict_proba_one(features)
            if prediction_proba:
                # Get top prediction
                top_event = max(prediction_proba.items(), key=lambda x: x[1])

                return {
                    'predicted_event': top_event[0],
                    'confidence': top_event[1],
                    'method': 'ml_classifier',
                    'device_ip': device_ip,
                    'based_on_events': len(recent_events)
                }
        except Exception as e:
            logger.error(f"Error predicting next attack: {e}")

        return None

    def get_device_risk_score(self, device_ip: str) -> Dict:
        """
        Calculate risk score based on attack sequence history.

        Args:
            device_ip: Device to score

        Returns:
            Risk score dict
        """
        if device_ip not in self.device_sequences:
            return {'risk_score': 0, 'risk_level': 'low', 'reason': 'No sequence history'}

        events = list(self.device_sequences[device_ip])

        if len(events) == 0:
            return {'risk_score': 0, 'risk_level': 'low', 'reason': 'No recent events'}

        # Calculate risk factors
        event_count = len(events)
        recent_count = sum(1 for e in events if (datetime.now() - e['timestamp']).seconds < 3600)  # Last hour
        critical_count = sum(1 for e in events if e['severity'] in ['critical', 'high'])

        # Check for escalating patterns
        has_escalation = self._check_escalation(events)

        # Risk score (0-100)
        risk_score = min(100, (
            (event_count * 5) +
            (recent_count * 15) +
            (critical_count * 20) +
            (30 if has_escalation else 0)
        ))

        # Risk level
        if risk_score >= 70:
            risk_level = 'critical'
        elif risk_score >= 50:
            risk_level = 'high'
        elif risk_score >= 30:
            risk_level = 'medium'
        else:
            risk_level = 'low'

        return {
            'risk_score': risk_score,
            'risk_level': risk_level,
            'event_count': event_count,
            'recent_events': recent_count,
            'critical_events': critical_count,
            'has_escalation': has_escalation,
            'device_ip': device_ip
        }

    def get_active_threats(self, min_confidence: float = 0.7) -> List[Dict]:
        """
        Get all active threat predictions across all devices.

        Args:
            min_confidence: Minimum confidence threshold

        Returns:
            List of high-confidence threat predictions
        """
        threats = []

        for device_ip, events in self.device_sequences.items():
            if len(events) < 2:
                continue

            # Get recent sequence
            recent = list(events)[-3:]
            sequence_tuple = tuple(e['event'] for e in recent)

            # Check against known patterns
            for seq_len in [3, 2, 1]:
                if len(sequence_tuple) >= seq_len:
                    check_seq = sequence_tuple[-seq_len:]
                    if check_seq in self.ATTACK_PATTERNS:
                        pattern = self.ATTACK_PATTERNS[check_seq]
                        if pattern['confidence'] >= min_confidence:
                            threats.append({
                                'device_ip': device_ip,
                                'pattern': list(check_seq),
                                'next_likely': pattern['next_likely'],
                                'confidence': pattern['confidence'],
                                'severity': pattern['severity'],
                                'description': pattern['description'],
                                'last_event': recent[-1]['timestamp'].isoformat()
                            })
                        break

        # Sort by confidence
        threats.sort(key=lambda x: x['confidence'], reverse=True)
        return threats

    def _extract_sequence_features(self, events: List[Dict]) -> Dict:
        """Extract features from event sequence for ML classification."""
        features = {}

        # Event types in sequence
        for i, event in enumerate(events[-3:]):  # Last 3 events
            features[f'event_{i}'] = event['event']
            features[f'severity_{i}'] = event['severity']

        # Time gaps between events
        if len(events) >= 2:
            time_gap = (events[-1]['timestamp'] - events[-2]['timestamp']).seconds
            features['time_gap_seconds'] = time_gap
            features['rapid_succession'] = 1 if time_gap < 300 else 0  # < 5 min

        # Sequence length
        features['sequence_length'] = len(events)

        # Severity escalation
        features['has_critical'] = 1 if any(e['severity'] == 'critical' for e in events) else 0

        return features

    def _check_escalation(self, events: List[Dict]) -> bool:
        """Check if events show escalating severity."""
        severity_order = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}

        if len(events) < 2:
            return False

        # Check if recent events are more severe than earlier ones
        recent_avg = sum(severity_order.get(e['severity'], 1) for e in events[-3:]) / min(3, len(events))
        early_avg = sum(severity_order.get(e['severity'], 1) for e in events[:3]) / min(3, len(events))

        return recent_avg > early_avg

    def save_sequences(self):
        """Save sequence database to disk."""
        try:
            # Keep only last 1000 sequences
            recent_sequences = self.sequences_db[-1000:]

            state = {
                'sequences': recent_sequences,
                'predictions_made': self.predictions_made,
                'correct_predictions': self.correct_predictions,
                'device_count': len(self.device_sequences),
                'last_save': datetime.now().isoformat()
            }

            self.model_path.write_text(json.dumps(state, indent=2))
            logger.debug(f"✓ Saved {len(recent_sequences)} attack sequences to {self.model_path}")

        except Exception as e:
            logger.error(f"Error saving sequences: {e}")

    def load_sequences(self):
        """Load sequence database from disk."""
        try:
            if self.model_path.exists():
                state = json.loads(self.model_path.read_text())
                self.sequences_db = state.get('sequences', [])
                self.predictions_made = state.get('predictions_made', 0)
                self.correct_predictions = state.get('correct_predictions', 0)

                logger.info(f"✓ Loaded {len(self.sequences_db)} attack sequences")
                return True
        except Exception as e:
            logger.error(f"Error loading sequences: {e}")

        return False

    def get_stats(self) -> Dict:
        """Get tracker statistics."""
        return {
            'tracked_devices': len(self.device_sequences),
            'total_sequences': len(self.sequences_db),
            'predictions_made': self.predictions_made,
            'accuracy': self.accuracy.get() if self.predictions_made > 0 else 0,
            'active_threats': len(self.get_active_threats()),
            'model_type': 'HoeffdingAdaptiveTree',
            'status': 'active'
        }
