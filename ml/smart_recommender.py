#!/usr/bin/env python3
"""
Smart Recommender for IoTSentinel

Context-aware recommendations using RAG (Retrieval-Augmented Generation) pattern.
Provides actionable security recommendations based on device history and alert context.

NO LLM overhead - uses database retrieval + rule engine.
Perfect for Raspberry Pi - only 5-10MB RAM.
"""

import sys
import logging
import json
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from collections import Counter

sys.path.insert(0, str(Path(__file__).parent.parent))
from database.db_manager import DatabaseManager

logger = logging.getLogger(__name__)


class SmartRecommender:
    """
    Context-aware recommendation engine for security alerts.

    Uses RAG pattern:
    1. Retrieval: Get device history, past behavior, network context from DB
    2. Augmentation: Combine with alert data
    3. Generation: Apply rules to generate prioritized recommendations
    """

    def __init__(self, db_manager: DatabaseManager):
        """
        Initialize recommender.

        Args:
            db_manager: Database manager instance
        """
        self.db = db_manager

        # Load recommendation rules
        self.rules = self._load_recommendation_rules()

        # Statistics
        self.stats = {
            "recommendations_generated": 0,
            "avg_confidence": 0.0,
            "most_common_actions": Counter()
        }

    def get_recommendation_stats(self) -> dict:
        """Get recommendation statistics."""
        return {
            'total_recommendations': self.stats['recommendations_generated'],
            'avg_confidence': self.stats['avg_confidence'],
            'status': 'active'
        }

    def recommend_for_alert(self, alert_id: int) -> List[dict]:
        """
        Generate top 3 recommended actions for an alert.

        Args:
            alert_id: Alert ID from database

        Returns:
            List of up to 3 recommendations, each with:
                - priority: Int (1-3, 1 is highest)
                - action: String (what to do)
                - reason: String (why do it)
                - command: String (terminal command, copy-paste ready)
                - confidence: Float (0-1)
        """
        # 1. Get alert details (from database)
        alert = self._get_alert(alert_id)
        if not alert:
            return []

        device_ip = alert.get('device_ip', '')

        # 2. Get device context (RAG: Retrieval)
        device_context = self._get_device_context(device_ip)

        # 3. Get historical behavior (note: alerts don't have dst_port)
        historical = self._get_historical_behavior(device_ip, None)

        # 4. Get recent similar alerts
        similar_alerts = self._get_similar_alerts(alert)

        # 5. Generate recommendations (RAG: Augmented Generation)
        recommendations = []

        # Apply rules based on alert type and context
        alert_type = alert.get('type', '').upper()
        severity = alert.get('severity', 'medium').upper()
        anomaly_score = alert.get('anomaly_score', 0.5)

        # Rule: Malicious IP detected
        if 'MALICIOUS' in alert_type or 'THREAT' in alert_type:
            recommendations.append({
                'priority': 1,
                'action': 'Block destination IP immediately',
                'reason': f"Destination {alert.get('dst_ip', 'unknown')} is known malicious (threat intelligence)",
                'command': f"sudo iptables -A OUTPUT -d {alert.get('dst_ip', '0.0.0.0')} -j DROP",
                'confidence': 0.95
            })

            recommendations.append({
                'priority': 2,
                'action': 'Scan device for malware',
                'reason': 'Device communicated with known threat - may be compromised',
                'command': f"# Run antivirus scan on {device_context.get('name', device_ip)}",
                'confidence': 0.85
            })

        # Rule: Unknown/unusual destination for known device type
        elif (device_context.get('type') and
              not historical.get('has_contacted_before', True)):

            device_type = device_context.get('type', 'Device')
            dst_country = alert.get('dst_country', 'unknown location')

            recommendations.append({
                'priority': 1,
                'action': 'Verify destination legitimacy',
                'reason': f"{device_type} contacting {dst_country} for first time - unusual behavior",
                'command': f"whois {alert.get('dst_ip', '')} && nslookup {alert.get('dst_ip', '')}",
                'confidence': 0.80
            })

            # If printer/IoT device going to foreign country
            if device_type in ['Printer', 'Camera', 'Smart TV', 'IoT Device']:
                if dst_country not in ['United States', 'unknown location', 'Local']:
                    recommendations.insert(0, {
                        'priority': 1,
                        'action': 'ISOLATE DEVICE IMMEDIATELY',
                        'reason': f"{device_type} contacting {dst_country} - likely firmware compromise",
                        'command': f"sudo iptables -A OUTPUT -s {device_ip} -j DROP",
                        'confidence': 0.92
                    })

        # Rule: Brute force attack
        elif 'BRUTE' in alert_type or 'FORCE' in alert_type:
            failed_attempts = self._count_recent_auth_failures(device_ip)

            recommendations.append({
                'priority': 1,
                'action': 'Block source IP at firewall',
                'reason': f"Brute force attack detected ({failed_attempts} failed attempts)",
                'command': f"sudo iptables -A INPUT -s {device_ip} -j DROP",
                'confidence': 0.90
            })

            recommendations.append({
                'priority': 2,
                'action': 'Enable account lockout policy',
                'reason': 'Prevent future brute force attempts',
                'command': "# Edit /etc/pam.d/common-auth: add 'deny=3 unlock_time=600'",
                'confidence': 0.85
            })

            recommendations.append({
                'priority': 3,
                'action': 'Enable 2FA for affected accounts',
                'reason': 'Strengthen authentication security',
                'command': "# Install and configure Google Authenticator or similar",
                'confidence': 0.80
            })

        # Rule: Port scanning detected
        elif 'SCAN' in alert_type or 'RECONNAISSANCE' in alert_type:
            recommendations.append({
                'priority': 1,
                'action': 'Enable firewall port scan protection',
                'reason': 'Device is probing network for vulnerabilities',
                'command': "sudo iptables -A INPUT -m state --state NEW -m recent --set && "
                          "sudo iptables -A INPUT -m state --state NEW -m recent --update --seconds 60 --hitcount 10 -j DROP",
                'confidence': 0.88
            })

            recommendations.append({
                'priority': 2,
                'action': 'Add device to watchlist',
                'reason': 'Monitor for escalation to active attack',
                'command': f"# Monitor traffic from {device_ip}: tcpdump -i eth0 host {device_ip}",
                'confidence': 0.75
            })

        # Rule: Data exfiltration
        elif 'EXFIL' in alert_type or anomaly_score > 0.9:
            bytes_sent = alert.get('bytes_sent', 0)

            if bytes_sent > 100000:  # >100KB
                recommendations.append({
                    'priority': 1,
                    'action': '⚠️ CRITICAL: Isolate device NOW',
                    'reason': f"Large data upload detected ({bytes_sent/1024:.1f} KB) - potential data breach",
                    'command': f"sudo iptables -A OUTPUT -s {device_ip} -j DROP",
                    'confidence': 0.93
                })

                recommendations.append({
                    'priority': 2,
                    'action': 'Investigate uploaded data',
                    'reason': 'Determine what information was exfiltrated',
                    'command': f"tcpdump -r /opt/zeek/logs -n host {alert.get('dst_ip', '')} -w investigation.pcap",
                    'confidence': 0.85
                })

        # Rule: Anomaly with high score but no specific type
        elif anomaly_score > 0.85:
            recommendations.append({
                'priority': 1,
                'action': 'Investigate device behavior',
                'reason': f"High anomaly score ({anomaly_score:.2f}) - unusual network activity",
                'command': f"sudo tcpdump -i eth0 -n host {device_ip} -c 100",
                'confidence': 0.70
            })

        # Rule: Repeated similar alerts
        if len(similar_alerts) >= 3:
            recommendations.append({
                'priority': 2,
                'action': 'Review device security settings',
                'reason': f"{len(similar_alerts)} similar alerts in 24h - persistent issue",
                'command': f"# Check {device_context.get('name', 'device')} configuration and firmware",
                'confidence': 0.75
            })

        # Generic recommendations if none matched
        if not recommendations:
            recommendations = self._get_generic_recommendations(alert, device_context)

        # Sort by priority and confidence
        recommendations.sort(key=lambda x: (x['priority'], -x['confidence']))

        # Take top 3
        top_3 = recommendations[:3]

        # Update statistics
        self.stats["recommendations_generated"] += len(top_3)
        for rec in top_3:
            self.stats["most_common_actions"][rec['action']] += 1

        if top_3:
            avg_conf = sum(r['confidence'] for r in top_3) / len(top_3)
            # Running average
            total = self.stats["recommendations_generated"]
            self.stats["avg_confidence"] = (
                (self.stats["avg_confidence"] * (total - len(top_3)) + avg_conf * len(top_3)) / total
            )

        return top_3

    def _get_alert(self, alert_id: int) -> Optional[dict]:
        """Fetch alert details from database."""
        try:
            conn = self.db.get_connection()
            cursor = conn.cursor()

            cursor.execute("""
                SELECT
                    id, severity, device_ip, anomaly_score,
                    explanation, timestamp
                FROM alerts
                WHERE id = ?
            """, (alert_id,))

            row = cursor.fetchone()
            conn.close()

            if not row:
                return None

            columns = [desc[0] for desc in cursor.description]
            return dict(zip(columns, row))

        except Exception as e:
            logger.error(f"Failed to fetch alert {alert_id}: {e}")
            return None

    def _get_device_context(self, device_ip: str) -> dict:
        """
        Retrieve device information from database (RAG retrieval).

        Returns device type, manufacturer, typical behavior, etc.
        """
        if not device_ip:
            return {'type': 'Unknown', 'name': 'unknown', 'manufacturer': 'Unknown'}

        try:
            conn = self.db.get_connection()
            cursor = conn.cursor()

            cursor.execute("""
                SELECT
                    mac_address, manufacturer, device_type, first_seen, last_seen,
                    is_trusted, device_name
                FROM devices
                WHERE device_ip = ?
            """, (device_ip,))

            row = cursor.fetchone()
            conn.close()

            if row:
                return {
                    'mac': row[0],
                    'manufacturer': row[1] or 'Unknown',
                    'type': row[2] or 'Device',
                    'first_seen': row[3],
                    'last_seen': row[4],
                    'trust_level': 'trusted' if row[5] else 'unknown',
                    'name': row[6] or f"{row[1]} {row[2]}" if row[1] or row[2] else device_ip
                }

            return {'type': 'Unknown', 'name': device_ip, 'manufacturer': 'Unknown'}

        except Exception as e:
            logger.error(f"Failed to get device context: {e}")
            return {'type': 'Unknown', 'name': device_ip}

    def _get_historical_behavior(self, src_ip: str, dst_port: Optional[int]) -> dict:
        """Check if this connection pattern was seen before."""
        try:
            conn = self.db.get_connection()
            cursor = conn.cursor()

            # Check if device contacted this port before
            cursor.execute("""
                SELECT COUNT(*) FROM connections
                WHERE device_ip = ? AND dest_port = ?
                AND timestamp > datetime('now', '-30 days')
            """, (src_ip, dst_port or 0))

            count = cursor.fetchone()[0]
            conn.close()

            return {
                'has_contacted_before': count > 0,
                'contact_count_30d': count
            }

        except Exception as e:
            logger.error(f"Failed to get historical behavior: {e}")
            return {'has_contacted_before': True, 'contact_count_30d': 0}

    def _get_similar_alerts(self, alert: dict) -> List[dict]:
        """Find similar alerts in last 24h."""
        try:
            conn = self.db.get_connection()
            cursor = conn.cursor()

            cursor.execute("""
                SELECT id, timestamp, severity
                FROM alerts
                WHERE device_ip = ?
                AND severity = ?
                AND timestamp > datetime('now', '-24 hours')
                AND id != ?
                ORDER BY timestamp DESC
                LIMIT 10
            """, (alert.get('device_ip'),
                  alert.get('severity'),
                  alert.get('id')))

            rows = cursor.fetchall()
            conn.close()

            return [
                {'id': row[0], 'timestamp': row[1], 'severity': row[2]}
                for row in rows
            ]

        except Exception as e:
            logger.error(f"Failed to get similar alerts: {e}")
            return []

    def _count_recent_auth_failures(self, src_ip: str) -> int:
        """Count failed authentication attempts in last 5 minutes."""
        try:
            conn = self.db.get_connection()
            cursor = conn.cursor()

            cursor.execute("""
                SELECT COUNT(*) FROM alerts
                WHERE device_ip = ?
                AND severity IN ('high', 'critical')
                AND timestamp > datetime('now', '-5 minutes')
            """, (src_ip,))

            count = cursor.fetchone()[0]
            conn.close()
            return count

        except Exception as e:
            return 0

    def _get_generic_recommendations(self, alert: dict, device_context: dict) -> List[dict]:
        """Fallback generic recommendations."""
        severity = alert.get('severity', 'medium').upper()
        device_ip = alert.get('device_ip', '')
        device_name = device_context.get('name', device_ip or 'device')

        recommendations = []

        # Always recommend investigation
        recommendations.append({
            'priority': 1,
            'action': 'Investigate network activity',
            'reason': f"{severity} severity alert on {device_name}",
            'command': f"tcpdump -i eth0 -n host {device_ip} -c 50",
            'confidence': 0.65
        })

        # Check device settings
        recommendations.append({
            'priority': 2,
            'action': 'Review device security settings',
            'reason': 'Ensure device is properly configured',
            'command': f"# Check {device_name} admin panel and firmware version",
            'confidence': 0.60
        })

        # Monitor for escalation
        recommendations.append({
            'priority': 3,
            'action': 'Monitor device for 24 hours',
            'reason': 'Watch for pattern escalation or repeated anomalies',
            'command': f"# Add {device_ip} to watchlist in IoTSentinel",
            'confidence': 0.55
        })

        return recommendations

    def _load_recommendation_rules(self) -> dict:
        """
        Load recommendation rules from file (future enhancement).

        Currently uses hardcoded rules above.
        Could load from JSON file for easier customization.
        """
        # Placeholder for future JSON-based rules
        return {}

    def get_stats(self) -> dict:
        """Get recommender statistics."""
        top_actions = self.stats["most_common_actions"].most_common(5)

        return {
            "total_recommendations": self.stats["recommendations_generated"],
            "average_confidence": round(self.stats["avg_confidence"], 3),
            "top_actions": [
                {"action": action, "count": count}
                for action, count in top_actions
            ]
        }
