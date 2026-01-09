#!/usr/bin/env python3
"""
Comprehensive IoT Features Module

Combines multiple IoT-specific capabilities:
- Smart Home Context (ecosystem detection, room management, automations)
- Privacy Monitoring (cloud connections, data exfiltration, trackers)
- Network Segmentation (VLAN recommendations, isolation)
- Lifecycle Management (firmware tracking, EOL detection, provisioning)
"""

import json
import logging
import ipaddress
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import socket

logger = logging.getLogger(__name__)


class SmartHomeManager:
    """Manages smart home context, ecosystems, and automations."""

    def __init__(self, db_manager):
        self.db = db_manager

        # Known smart home ecosystems
        self.ecosystems = {
            'Google Home': ['google.com', 'googleapis.com', 'googleusercontent.com'],
            'Amazon Alexa': ['amazon.com', 'amazonaws.com', 'alexa.amazon.com'],
            'Apple HomeKit': ['apple.com', 'icloud.com', 'apple-cloudkit.com'],
            'Samsung SmartThings': ['smartthings.com', 'samsung.com'],
            'Home Assistant': ['home-assistant.io', 'nabucasa.com']
        }

    def detect_smart_hub(self, device_ip: str, open_ports: List[int], services: List[str]) -> Optional[str]:
        """Detect if device is a smart home hub."""
        hub_signatures = {
            'SmartThings': [39500, 39501],
            'Home Assistant': [8123],
            'Hubitat': [8080],
            'Philips Hue Bridge': [80, 443],
        }

        for hub_type, ports in hub_signatures.items():
            if any(port in open_ports for port in ports):
                self._save_smart_hub(device_ip, hub_type)
                return hub_type

        return None

    def _save_smart_hub(self, device_ip: str, hub_type: str):
        """Save detected smart home hub."""
        try:
            cursor = self.db.conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO smart_home_hubs (
                    device_ip, hub_type, hub_name, last_discovered
                ) VALUES (?, ?, ?, CURRENT_TIMESTAMP)
            """, (device_ip, hub_type, f"{hub_type} Hub"))
            self.db.conn.commit()
        except Exception as e:
            logger.error(f"Failed to save smart hub: {e}")

    def detect_ecosystem(self, device_ip: str, dest_domain: str):
        """Detect which smart home ecosystem a device belongs to."""
        for ecosystem, domains in self.ecosystems.items():
            if any(domain in dest_domain for domain in domains):
                self._save_ecosystem_membership(device_ip, ecosystem)
                return ecosystem
        return None

    def _save_ecosystem_membership(self, device_ip: str, ecosystem: str):
        """Save device ecosystem membership."""
        try:
            cursor = self.db.conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO device_ecosystems (
                    device_ip, ecosystem, last_interaction
                ) VALUES (?, ?, CURRENT_TIMESTAMP)
            """, (device_ip, ecosystem))
            self.db.conn.commit()
        except Exception as e:
            logger.error(f"Failed to save ecosystem: {e}")

    def create_room(self, room_name: str, room_type: str = 'other') -> int:
        """Create a smart home room."""
        try:
            cursor = self.db.conn.cursor()
            cursor.execute("""
                INSERT INTO smart_home_rooms (room_name, room_type)
                VALUES (?, ?)
            """, (room_name, room_type))
            self.db.conn.commit()
            return cursor.lastrowid
        except Exception as e:
            logger.error(f"Failed to create room: {e}")
            return -1

    def assign_device_to_room(self, device_ip: str, room_id: int):
        """Assign device to a room."""
        try:
            cursor = self.db.conn.cursor()
            cursor.execute("""
                INSERT OR IGNORE INTO device_room_assignments (device_ip, room_id)
                VALUES (?, ?)
            """, (device_ip, room_id))
            self.db.conn.commit()
        except Exception as e:
            logger.error(f"Failed to assign device to room: {e}")


class PrivacyMonitor:
    """Monitors IoT device privacy concerns and data exfiltration."""

    def __init__(self, db_manager):
        self.db = db_manager

        # Known cloud providers
        self.cloud_providers = {
            'AWS': ['.amazonaws.com', '.aws.amazon.com'],
            'Google Cloud': ['.googleapis.com', '.gstatic.com'],
            'Microsoft Azure': ['.azure.com', '.microsoft.com'],
            'Alibaba Cloud': ['.aliyun.com', '.alibabacloud.com']
        }

        # Known tracking domains
        self.tracking_domains = {
            'Google Analytics': 'google-analytics.com',
            'Facebook': 'facebook.com',
            'Amazon Ads': 'amazon-adsystem.com'
        }

    def track_cloud_connection(self, device_ip: str, dest_ip: str, dest_domain: str,
                               bytes_uploaded: int, bytes_downloaded: int, encrypted: bool = True):
        """Track device connections to cloud services."""
        cloud_provider = self._identify_cloud_provider(dest_domain)

        try:
            cursor = self.db.conn.cursor()
            cursor.execute("""
                INSERT INTO cloud_connections (
                    device_ip, cloud_domain, cloud_ip, cloud_provider,
                    total_bytes_uploaded, total_bytes_downloaded,
                    uses_encryption, connection_count
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 1)
                ON CONFLICT(id) DO UPDATE SET
                    last_seen = CURRENT_TIMESTAMP,
                    connection_count = connection_count + 1,
                    total_bytes_uploaded = total_bytes_uploaded + excluded.total_bytes_uploaded,
                    total_bytes_downloaded = total_bytes_downloaded + excluded.total_bytes_downloaded
            """, (device_ip, dest_domain, dest_ip, cloud_provider,
                  bytes_uploaded, bytes_downloaded, encrypted))
            self.db.conn.commit()

            # Assess privacy concern level
            self._assess_privacy_concern(device_ip, dest_domain, bytes_uploaded)

        except Exception as e:
            logger.error(f"Failed to track cloud connection: {e}")

    def _identify_cloud_provider(self, domain: str) -> Optional[str]:
        """Identify cloud provider from domain."""
        for provider, patterns in self.cloud_providers.items():
            if any(pattern in domain for pattern in patterns):
                return provider
        return None

    def _assess_privacy_concern(self, device_ip: str, domain: str, bytes_uploaded: int):
        """Assess privacy concern level based on cloud activity."""
        concern_level = 'low'

        # High concern if uploading large amounts of data
        if bytes_uploaded > 100 * 1024 * 1024:  # > 100MB
            concern_level = 'high'
        elif bytes_uploaded > 10 * 1024 * 1024:  # > 10MB
            concern_level = 'medium'

        # Update concern level in database
        try:
            cursor = self.db.conn.cursor()
            cursor.execute("""
                UPDATE cloud_connections
                SET privacy_concern_level = ?
                WHERE device_ip = ? AND cloud_domain = ?
            """, (concern_level, device_ip, domain))
            self.db.conn.commit()
        except Exception as e:
            logger.error(f"Failed to update privacy concern: {e}")

    def detect_tracker(self, device_ip: str, dest_domain: str):
        """Detect third-party tracking connections."""
        for tracker_name, tracker_domain in self.tracking_domains.items():
            if tracker_domain in dest_domain:
                self._save_tracker_detection(device_ip, dest_domain, tracker_name)

    def _save_tracker_detection(self, device_ip: str, domain: str, tracker_name: str):
        """Save third-party tracker detection."""
        try:
            cursor = self.db.conn.cursor()
            cursor.execute("""
                INSERT INTO third_party_trackers (
                    device_ip, tracker_domain, tracker_company, tracker_category
                ) VALUES (?, ?, ?, 'analytics')
                ON CONFLICT(id) DO UPDATE SET
                    last_detected = CURRENT_TIMESTAMP,
                    connection_count = connection_count + 1
            """, (device_ip, domain, tracker_name))
            self.db.conn.commit()
        except Exception as e:
            logger.error(f"Failed to save tracker: {e}")

    def check_kids_device_activity(self, device_ip: str) -> Dict:
        """
        Enhanced privacy monitoring for kids' devices.
        Detects high-risk activities and generates alerts.

        Args:
            device_ip: Device IP address

        Returns:
            Dict with risk assessment and recommendations
        """
        try:
            cursor = self.db.conn.cursor()

            # Check if device is marked as kids' device
            cursor.execute("""
                SELECT is_kids_device, device_type, device_name
                FROM devices
                WHERE device_ip = ?
            """, (device_ip,))

            device = cursor.fetchone()
            if not device or not device['is_kids_device']:
                return {'is_kids_device': False}

            risk_factors = []
            risk_score = 0

            # Check 1: Social media connections
            social_media_domains = [
                'facebook.com', 'instagram.com', 'tiktok.com', 'snapchat.com',
                'twitter.com', 'x.com', 'discord.com', 'whatsapp.com'
            ]

            cursor.execute("""
                SELECT DISTINCT dest_ip
                FROM connections
                WHERE device_ip = ?
                AND timestamp >= datetime('now', '-24 hours')
            """, (device_ip,))

            # Check for social media connections (simplified - in production use DNS resolution)
            recent_connections = cursor.fetchall()

            # Check 2: Unknown/suspicious IP connections
            cursor.execute("""
                SELECT COUNT(DISTINCT dest_ip) as unknown_ips
                FROM connections
                WHERE device_ip = ?
                AND timestamp >= datetime('now', '-24 hours')
                AND dest_ip NOT IN (
                    SELECT ip FROM malicious_ips
                )
            """, (device_ip,))

            unknown_count = cursor.fetchone()['unknown_ips']
            if unknown_count > 50:
                risk_score += 30
                risk_factors.append(f'High number of unique connections ({unknown_count})')

            # Check 3: Malicious IP connections
            cursor.execute("""
                SELECT COUNT(*) as malicious_count
                FROM connections c
                INNER JOIN malicious_ips m ON c.dest_ip = m.ip
                WHERE c.device_ip = ?
                AND c.timestamp >= datetime('now', '-24 hours')
            """, (device_ip,))

            malicious_count = cursor.fetchone()['malicious_count']
            if malicious_count > 0:
                risk_score += 50
                risk_factors.append(f'{malicious_count} connections to malicious IPs')
                self._generate_kids_device_alert(
                    device_ip,
                    'critical',
                    f"Kids' device '{device['device_name']}' connected to {malicious_count} malicious IP(s)",
                    {'malicious_connections': malicious_count}
                )

            # Check 4: Excessive data upload (potential oversharing)
            cursor.execute("""
                SELECT SUM(bytes_sent) as total_upload
                FROM connections
                WHERE device_ip = ?
                AND timestamp >= datetime('now', '-24 hours')
            """, (device_ip,))

            total_upload = cursor.fetchone()['total_upload'] or 0
            upload_mb = total_upload / (1024 * 1024)

            if upload_mb > 500:  # More than 500MB upload in 24h
                risk_score += 25
                risk_factors.append(f'High data upload: {upload_mb:.1f}MB')
                self._generate_kids_device_alert(
                    device_ip,
                    'medium',
                    f"Kids' device '{device['device_name']}' uploaded {upload_mb:.1f}MB in 24h (possible file sharing)",
                    {'upload_mb': upload_mb}
                )

            # Check 5: After-hours activity (11 PM - 6 AM)
            cursor.execute("""
                SELECT COUNT(*) as night_connections
                FROM connections
                WHERE device_ip = ?
                AND timestamp >= datetime('now', '-24 hours')
                AND (
                    CAST(strftime('%H', timestamp) AS INTEGER) >= 23
                    OR CAST(strftime('%H', timestamp) AS INTEGER) < 6
                )
            """, (device_ip,))

            night_connections = cursor.fetchone()['night_connections']
            if night_connections > 100:
                risk_score += 15
                risk_factors.append(f'{night_connections} connections during late hours')

            # Determine overall risk level
            if risk_score >= 60:
                risk_level = 'critical'
            elif risk_score >= 35:
                risk_level = 'high'
            elif risk_score >= 15:
                risk_level = 'medium'
            else:
                risk_level = 'low'

            return {
                'is_kids_device': True,
                'device_name': device['device_name'],
                'device_type': device['device_type'],
                'risk_score': risk_score,
                'risk_level': risk_level,
                'risk_factors': risk_factors,
                'recommendations': self._get_kids_device_recommendations(risk_factors)
            }

        except Exception as e:
            logger.error(f"Error checking kids device activity: {e}")
            return {'error': str(e)}

    def _generate_kids_device_alert(self, device_ip: str, severity: str,
                                    explanation: str, indicators: Dict):
        """Generate privacy alert for kids' devices."""
        try:
            from alerts.alert_manager import alert_manager

            alert_manager.create_alert(
                device_ip=device_ip,
                severity=severity,
                anomaly_score=0.0,
                explanation=f"[Kids' Device Privacy] {explanation}",
                top_features=json.dumps(indicators),
                category='privacy'
            )
            logger.warning(f"Kids device alert generated for {device_ip}: {explanation}")

        except Exception as e:
            logger.error(f"Failed to generate kids device alert: {e}")

    def _get_kids_device_recommendations(self, risk_factors: List[str]) -> List[str]:
        """Get parental control recommendations based on risk factors."""
        recommendations = []

        if any('malicious' in factor.lower() for factor in risk_factors):
            recommendations.append("⚠️ Block malicious IPs immediately")
            recommendations.append("Review device activity with child")
            recommendations.append("Consider activating parental control software")

        if any('upload' in factor.lower() for factor in risk_factors):
            recommendations.append("Monitor file sharing applications")
            recommendations.append("Review cloud storage permissions")
            recommendations.append("Educate about oversharing risks")

        if any('late hours' in factor.lower() for factor in risk_factors):
            recommendations.append("Set device usage time limits")
            recommendations.append("Enable bedtime mode/screen time restrictions")

        if any('unique connections' in factor.lower() for factor in risk_factors):
            recommendations.append("Review installed apps and permissions")
            recommendations.append("Enable DNS filtering for age-appropriate content")

        # Always include general recommendations
        recommendations.append("Regular check-ins about online activity")
        recommendations.append("Keep device in common areas during use")

        return recommendations


class NetworkSegmentation:
    """Manages network segmentation and VLAN recommendations."""

    def __init__(self, db_manager):
        self.db = db_manager

    def recommend_segment(self, device_ip: str, device_type: str) -> Dict:
        """
        AI-based network segment recommendation.

        Uses multiple factors:
        - Device type and sensitivity
        - Vulnerability count
        - Recent anomaly detections
        - Privacy concerns
        - Security compliance score

        Args:
            device_ip: Device IP address
            device_type: Type of device

        Returns:
            Dict with segment recommendation and AI confidence score
        """
        try:
            cursor = self.db.conn.cursor()

            # Calculate risk score (0-100, higher = more risky)
            risk_score = 0
            risk_factors = []

            # Factor 1: Device type inherent risk
            high_risk_types = {'IP Camera', 'Smart Lock', 'Router', 'DVR/NVR', 'Security System'}
            medium_risk_types = {'Smart Speaker', 'Smart TV', 'Smart Hub'}

            if device_type in high_risk_types:
                risk_score += 40
                risk_factors.append('High-risk device type')
            elif device_type in medium_risk_types:
                risk_score += 20
                risk_factors.append('Medium-risk device type')
            else:
                risk_score += 10

            # Factor 2: Active vulnerabilities
            cursor.execute("""
                SELECT COUNT(*) as vuln_count
                FROM device_vulnerabilities_detected
                WHERE device_ip = ? AND status = 'active'
            """, (device_ip,))

            vuln_count = cursor.fetchone()['vuln_count']
            if vuln_count > 0:
                risk_score += min(vuln_count * 15, 30)
                risk_factors.append(f'{vuln_count} active vulnerabilities')

            # Factor 3: Recent anomalies/threats
            cursor.execute("""
                SELECT COUNT(*) as alert_count
                FROM alerts
                WHERE device_ip = ?
                AND timestamp >= datetime('now', '-7 days')
                AND severity IN ('high', 'critical')
                AND acknowledged = 0
            """, (device_ip,))

            alert_count = cursor.fetchone()['alert_count']
            if alert_count > 0:
                risk_score += min(alert_count * 10, 20)
                risk_factors.append(f'{alert_count} recent critical alerts')

            # Factor 4: Privacy concerns
            cursor.execute("""
                SELECT COUNT(*) as privacy_count
                FROM cloud_connections
                WHERE device_ip = ?
                AND privacy_concern_level IN ('high', 'critical')
            """, (device_ip,))

            privacy_count = cursor.fetchone()['privacy_count']
            if privacy_count > 0:
                risk_score += 10
                risk_factors.append('High privacy concerns')

            # Determine segment based on risk score
            if risk_score >= 60:
                # Critical isolation needed
                segment_name = 'Critical IoT'
                vlan_id = 40
                reason = f"High risk ({risk_score}/100): {'; '.join(risk_factors)}"
                confidence = 0.95
            elif risk_score >= 35:
                # Moderate isolation
                segment_name = 'IoT Isolated'
                vlan_id = 20
                reason = f"Moderate risk ({risk_score}/100): {'; '.join(risk_factors)}"
                confidence = 0.85
            elif risk_score >= 15:
                # Standard IoT segment
                segment_name = 'Smart Home'
                vlan_id = 30
                reason = f"Standard IoT ({risk_score}/100)"
                confidence = 0.75
            else:
                # Trusted segment
                segment_name = 'IoT Isolated'  # Still isolate by default
                vlan_id = 20
                reason = f"Low risk ({risk_score}/100), isolated for best practice"
                confidence = 0.70

            recommendation = {
                'segment': segment_name,
                'vlan_id': vlan_id,
                'reason': reason,
                'risk_score': risk_score,
                'risk_factors': risk_factors,
                'confidence': confidence,
                'ai_recommended': True
            }

            # Save recommendation
            self._save_segment_recommendation(device_ip, recommendation)

            logger.info(
                f"AI recommendation for {device_ip} ({device_type}): "
                f"{segment_name} (risk: {risk_score}, confidence: {confidence:.2f})"
            )

            return recommendation

        except Exception as e:
            logger.error(f"Error generating AI recommendation: {e}")
            # Fallback to safe default
            return {
                'segment': 'IoT Isolated',
                'vlan_id': 20,
                'reason': 'Default isolation (AI recommendation failed)',
                'risk_score': 50,
                'confidence': 0.5,
                'ai_recommended': False
            }

    def get_ai_segmentation_plan(self) -> Dict:
        """
        Generate comprehensive AI-based segmentation plan for entire network.

        Returns:
            Dict with segmentation plan and statistics
        """
        try:
            cursor = self.db.conn.cursor()
            cursor.execute("SELECT device_ip, device_type, device_name FROM devices")
            devices = cursor.fetchall()

            plan = {
                'total_devices': len(devices),
                'segments': {},
                'high_priority_moves': [],
                'estimated_security_improvement': 0
            }

            for device in devices:
                recommendation = self.recommend_segment(
                    device['device_ip'],
                    device['device_type']
                )

                segment = recommendation['segment']
                if segment not in plan['segments']:
                    plan['segments'][segment] = {
                        'vlan_id': recommendation['vlan_id'],
                        'devices': [],
                        'avg_risk': 0
                    }

                plan['segments'][segment]['devices'].append({
                    'ip': device['device_ip'],
                    'name': device['device_name'],
                    'type': device['device_type'],
                    'risk_score': recommendation['risk_score']
                })

                # Track high-priority moves
                if recommendation['risk_score'] >= 60:
                    plan['high_priority_moves'].append({
                        'device': device['device_name'],
                        'ip': device['device_ip'],
                        'to_segment': segment,
                        'reason': recommendation['reason']
                    })

            # Calculate average risk per segment
            for segment_name, segment_data in plan['segments'].items():
                if segment_data['devices']:
                    avg_risk = sum(d['risk_score'] for d in segment_data['devices']) / len(segment_data['devices'])
                    segment_data['avg_risk'] = round(avg_risk, 1)

            # Estimate security improvement
            plan['estimated_security_improvement'] = min(
                len(plan['high_priority_moves']) * 15,
                100
            )

            return plan

        except Exception as e:
            logger.error(f"Error generating segmentation plan: {e}")
            return {}

    def _save_segment_recommendation(self, device_ip: str, recommendation: Dict):
        """Save segment recommendation to database."""
        try:
            cursor = self.db.conn.cursor()

            # Get or create segment
            cursor.execute("""
                SELECT id FROM network_segments WHERE segment_name = ?
            """, (recommendation['segment'].title() + ' Devices',))

            segment = cursor.fetchone()
            if not segment:
                return

            segment_id = segment['id']

            # Save recommendation
            cursor.execute("""
                INSERT OR REPLACE INTO device_segments (
                    device_ip, segment_id, current_segment, recommended_by, reason
                ) VALUES (?, ?, 0, 'system', ?)
            """, (device_ip, segment_id, recommendation['reason']))

            self.db.conn.commit()
        except Exception as e:
            logger.error(f"Failed to save segment recommendation: {e}")

    def get_segmentation_violations(self, hours: int = 24) -> List[Dict]:
        """Get devices violating segmentation policies."""
        try:
            cursor = self.db.conn.cursor()
            cursor.execute("""
                SELECT * FROM segmentation_violations
                WHERE timestamp >= datetime('now', '-{} hours')
                ORDER BY timestamp DESC
            """.format(hours))

            return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get violations: {e}")
            return []


class FirmwareLifecycleManager:
    """Manages IoT device firmware tracking and lifecycle."""

    def __init__(self, db_manager):
        self.db = db_manager

    def check_firmware_status(self, device_ip: str, current_firmware: str,
                              vendor: str, model: str, generate_alerts: bool = True) -> Dict:
        """
        Check firmware status against database and optionally generate alerts.

        Args:
            device_ip: Device IP address
            current_firmware: Current firmware version
            vendor: Device vendor/manufacturer
            model: Device model
            generate_alerts: Whether to generate alerts for outdated/EOL firmware

        Returns:
            Dict with firmware status information
        """
        try:
            cursor = self.db.conn.cursor()

            # Check if latest firmware exists
            cursor.execute("""
                SELECT firmware_version, is_latest, is_eol, eol_date, security_fixes
                FROM firmware_database
                WHERE vendor = ? AND model = ?
                ORDER BY release_date DESC
                LIMIT 1
            """, (vendor, model))

            latest = cursor.fetchone()

            if latest:
                update_available = (current_firmware != latest['firmware_version'])
                is_eol = latest['is_eol']

                # Calculate firmware age (days)
                cursor.execute("""
                    SELECT julianday('now') - julianday(release_date) as age_days
                    FROM firmware_database
                    WHERE vendor = ? AND model = ? AND firmware_version = ?
                """, (vendor, model, current_firmware))

                age_result = cursor.fetchone()
                firmware_age_days = int(age_result['age_days']) if age_result else 0

                # Update device firmware status
                cursor.execute("""
                    INSERT OR REPLACE INTO device_firmware_status (
                        device_ip, current_firmware, latest_firmware,
                        firmware_age_days, update_available, is_eol,
                        last_update_check
                    ) VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                """, (device_ip, current_firmware, latest['firmware_version'],
                      firmware_age_days, update_available, is_eol))

                self.db.conn.commit()

                # Generate alerts if enabled
                if generate_alerts:
                    # Critical alert for EOL firmware
                    if is_eol:
                        explanation = (
                            f"Device running end-of-life firmware {current_firmware}. "
                            f"No security updates available. "
                            f"Latest version: {latest['firmware_version']}"
                        )
                        self._generate_firmware_alert(
                            device_ip, 'critical', explanation,
                            {'firmware_status': 'eol', 'current': current_firmware}
                        )

                    # High alert for outdated firmware with security fixes
                    elif update_available and latest.get('security_fixes'):
                        security_fixes = latest['security_fixes']
                        explanation = (
                            f"Security update available: {latest['firmware_version']} "
                            f"(currently running {current_firmware}). "
                            f"Fixes: {security_fixes}"
                        )
                        self._generate_firmware_alert(
                            device_ip, 'high', explanation,
                            {'firmware_status': 'outdated_with_security_fixes',
                             'current': current_firmware,
                             'latest': latest['firmware_version']}
                        )

                    # Medium alert for outdated firmware (no critical fixes)
                    elif update_available and firmware_age_days > 180:
                        explanation = (
                            f"Firmware outdated ({firmware_age_days} days old). "
                            f"Update available: {latest['firmware_version']}"
                        )
                        self._generate_firmware_alert(
                            device_ip, 'medium', explanation,
                            {'firmware_status': 'outdated', 'age_days': firmware_age_days}
                        )

                return {
                    'current': current_firmware,
                    'latest': latest['firmware_version'],
                    'update_available': update_available,
                    'is_eol': is_eol,
                    'firmware_age_days': firmware_age_days
                }

            return {'current': current_firmware, 'latest': None, 'update_available': False}

        except Exception as e:
            logger.error(f"Failed to check firmware: {e}")
            return {}

    def _generate_firmware_alert(self, device_ip: str, severity: str,
                                  explanation: str, indicators: Dict):
        """Generate firmware-related alert."""
        try:
            import json
            cursor = self.db.conn.cursor()

            # Check if similar alert already exists (avoid duplicates)
            cursor.execute("""
                SELECT id FROM alerts
                WHERE device_ip = ?
                AND explanation LIKE 'Device running end-of-life firmware%'
                OR explanation LIKE 'Security update available%'
                OR explanation LIKE 'Firmware outdated%'
                AND timestamp >= datetime('now', '-7 days')
                AND acknowledged = 0
            """, (device_ip,))

            if cursor.fetchone():
                # Alert already exists, don't create duplicate
                return

            # Calculate anomaly score based on severity
            anomaly_scores = {'critical': 0.95, 'high': 0.75, 'medium': 0.50, 'low': 0.25}
            anomaly_score = anomaly_scores.get(severity, 0.5)

            cursor.execute("""
                INSERT INTO alerts (
                    device_ip, severity, anomaly_score, explanation, top_features
                ) VALUES (?, ?, ?, ?, ?)
            """, (device_ip, severity, anomaly_score, explanation, json.dumps(indicators)))

            self.db.conn.commit()
            logger.warning(f"Firmware alert generated for {device_ip}: {explanation}")

        except Exception as e:
            logger.error(f"Failed to generate firmware alert: {e}")

    def track_provisioning(self, device_ip: str, mac_address: str) -> int:
        """Track new device provisioning workflow."""
        try:
            cursor = self.db.conn.cursor()
            cursor.execute("""
                INSERT INTO device_provisioning (
                    device_ip, mac_address, provisioning_status
                ) VALUES (?, ?, 'discovered')
            """, (device_ip, mac_address))
            self.db.conn.commit()
            return cursor.lastrowid
        except Exception as e:
            logger.error(f"Failed to track provisioning: {e}")
            return -1

    def update_provisioning_status(self, device_ip: str, status: str):
        """Update device provisioning status."""
        valid_statuses = ['discovered', 'identified', 'configured', 'tested', 'approved', 'rejected']
        if status not in valid_statuses:
            return

        try:
            cursor = self.db.conn.cursor()
            cursor.execute("""
                UPDATE device_provisioning
                SET provisioning_status = ?
                WHERE device_ip = ?
            """, (status, device_ip))
            self.db.conn.commit()
        except Exception as e:
            logger.error(f"Failed to update provisioning: {e}")


# Singleton instances
_smart_home_instance = None
_privacy_monitor_instance = None
_network_segmentation_instance = None
_firmware_manager_instance = None


def get_smart_home_manager(db_manager) -> SmartHomeManager:
    """Get or create Smart Home Manager singleton."""
    global _smart_home_instance
    if _smart_home_instance is None:
        _smart_home_instance = SmartHomeManager(db_manager)
    return _smart_home_instance


def get_privacy_monitor(db_manager) -> PrivacyMonitor:
    """Get or create Privacy Monitor singleton."""
    global _privacy_monitor_instance
    if _privacy_monitor_instance is None:
        _privacy_monitor_instance = PrivacyMonitor(db_manager)
    return _privacy_monitor_instance


def get_network_segmentation(db_manager) -> NetworkSegmentation:
    """Get or create Network Segmentation singleton."""
    global _network_segmentation_instance
    if _network_segmentation_instance is None:
        _network_segmentation_instance = NetworkSegmentation(db_manager)
    return _network_segmentation_instance


def get_firmware_manager(db_manager) -> FirmwareLifecycleManager:
    """Get or create Firmware Lifecycle Manager singleton."""
    global _firmware_manager_instance
    if _firmware_manager_instance is None:
        _firmware_manager_instance = FirmwareLifecycleManager(db_manager)
    return _firmware_manager_instance
