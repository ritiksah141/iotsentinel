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


class NetworkSegmentation:
    """Manages network segmentation and VLAN recommendations."""

    def __init__(self, db_manager):
        self.db = db_manager

    def recommend_segment(self, device_ip: str, device_type: str) -> Dict:
        """Recommend network segment for device based on type and risk."""
        recommendations = {
            'Camera': {'segment': 'isolated', 'vlan_id': 40, 'reason': 'Cameras pose privacy risks'},
            'Speaker': {'segment': 'isolated', 'vlan_id': 40, 'reason': 'Voice assistants record audio'},
            'Bulb': {'segment': 'iot', 'vlan_id': 10, 'reason': 'Low risk IoT device'},
            'Plug': {'segment': 'iot', 'vlan_id': 10, 'reason': 'Low risk IoT device'},
            'Thermostat': {'segment': 'iot', 'vlan_id': 10, 'reason': 'Standard IoT device'},
            'Lock': {'segment': 'isolated', 'vlan_id': 40, 'reason': 'Critical security device'},
            'Router': {'segment': 'trusted', 'vlan_id': 20, 'reason': 'Network infrastructure'},
            'Computer': {'segment': 'trusted', 'vlan_id': 20, 'reason': 'Trusted computing device'},
            'Mobile': {'segment': 'trusted', 'vlan_id': 20, 'reason': 'Personal device'}
        }

        recommendation = recommendations.get(device_type, {
            'segment': 'iot',
            'vlan_id': 10,
            'reason': 'Default IoT segmentation'
        })

        # Save recommendation
        self._save_segment_recommendation(device_ip, recommendation)

        return recommendation

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
                              vendor: str, model: str) -> Dict:
        """Check firmware status against database."""
        try:
            cursor = self.db.conn.cursor()

            # Check if latest firmware exists
            cursor.execute("""
                SELECT firmware_version, is_latest, is_eol
                FROM firmware_database
                WHERE vendor = ? AND model = ?
                ORDER BY release_date DESC
                LIMIT 1
            """, (vendor, model))

            latest = cursor.fetchone()

            if latest:
                update_available = (current_firmware != latest['firmware_version'])
                is_eol = latest['is_eol']

                # Update device firmware status
                cursor.execute("""
                    INSERT OR REPLACE INTO device_firmware_status (
                        device_ip, current_firmware, latest_firmware,
                        update_available, is_eol, last_update_check
                    ) VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                """, (device_ip, current_firmware, latest['firmware_version'],
                      update_available, is_eol))

                self.db.conn.commit()

                return {
                    'current': current_firmware,
                    'latest': latest['firmware_version'],
                    'update_available': update_available,
                    'is_eol': is_eol
                }

            return {'current': current_firmware, 'latest': None, 'update_available': False}

        except Exception as e:
            logger.error(f"Failed to check firmware: {e}")
            return {}

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
