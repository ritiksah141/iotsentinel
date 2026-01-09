#!/usr/bin/env python3
"""
Auto-Provisioning Manager for IoTSentinel

Automatically provisions newly discovered devices through the complete workflow:
1. Add device to database
2. Classify device type
3. Fingerprint device
4. Check for vulnerabilities
5. Schedule baseline learning
"""

import logging
import sqlite3
import json
from typing import Dict, Any, Optional
from datetime import datetime, timedelta
from pathlib import Path

logger = logging.getLogger(__name__)


class AutoProvisioner:
    """
    Manages automatic device provisioning workflow.

    Handles the complete lifecycle from device discovery to security analysis.
    """

    def __init__(
        self,
        db_path: str = 'data/iot_monitor.db',
        baseline_learning_days: int = 7
    ):
        """
        Initialize auto-provisioner.

        Args:
            db_path: Path to database
            baseline_learning_days: Days before scheduling baseline learning
        """
        self.db_path = db_path
        self.baseline_learning_days = baseline_learning_days

        # Track provisioned devices to avoid duplicates
        self.provisioned_devices = set()

        logger.info("Auto-provisioner initialized")

    def is_device_known(self, device_ip: str) -> bool:
        """
        Check if device is already in database.

        Args:
            device_ip: Device IP address

        Returns:
            True if device exists in database
        """
        try:
            conn = self.db_manager.conn
            cursor = conn.cursor()

            cursor.execute(
                "SELECT COUNT(*) FROM devices WHERE ip_address = ?",
                (device_ip,)
            )

            count = cursor.fetchone()[0]

            return count > 0

        except Exception as e:
            logger.error(f"Error checking device existence: {e}")
            return False

    def provision_device(
        self,
        device_info: Dict[str, Any],
        discovery_method: str
    ) -> Optional[str]:
        """
        Automatically provision a newly discovered device.

        Args:
            device_info: Dictionary with device information
                Required: ip_address
                Optional: mac_address, hostname, vendor, open_ports,
                         device_type, manufacturer, model, firmware_version
            discovery_method: How device was discovered (mdns, upnp, nmap, arp)

        Returns:
            Device IP if provisioning successful, None otherwise
        """
        device_ip = device_info.get('ip_address')

        if not device_ip:
            logger.error("Cannot provision device without IP address")
            return None

        # Check if already provisioned in this session
        if device_ip in self.provisioned_devices:
            logger.debug(f"Device {device_ip} already provisioned in this session")
            return None

        # Check if device already exists in database
        if self.is_device_known(device_ip):
            logger.debug(f"Device {device_ip} already exists in database")
            return None

        logger.info(f"Auto-provisioning device: {device_ip} (via {discovery_method})")

        try:
            # Log discovery event
            self._log_discovery_event(device_info, discovery_method)

            # Add device to database
            self._add_device_to_database(device_info, discovery_method)

            # Schedule baseline learning (after N days)
            self._schedule_baseline_learning(device_ip)

            # Mark as provisioned
            self.provisioned_devices.add(device_ip)

            logger.info(f"Successfully provisioned device: {device_ip}")
            return device_ip

        except Exception as e:
            logger.error(f"Error provisioning device {device_ip}: {e}")
            return None

    def _log_discovery_event(
        self,
        device_info: Dict[str, Any],
        discovery_method: str
    ):
        """Log device discovery event to database."""
        try:
            conn = self.db_manager.conn
            cursor = conn.cursor()

            cursor.execute('''
                INSERT INTO discovery_events
                (device_ip, discovery_method, device_info_json, timestamp)
                VALUES (?, ?, ?, ?)
            ''', (
                device_info.get('ip_address'),
                discovery_method,
                json.dumps(device_info),
                datetime.now().isoformat()
            ))

            conn.commit()

        except Exception as e:
            logger.warning(f"Could not log discovery event: {e}")

    def _add_device_to_database(
        self,
        device_info: Dict[str, Any],
        discovery_method: str
    ):
        """
        Add device to database with classification.

        Uses device_classifier if not already classified.
        """
        try:
            from utils.device_classifier import classifier
        except ImportError:
            logger.warning("Device classifier not available")
            classifier = None

        # Extract device information
        ip_address = device_info.get('ip_address')
        mac_address = device_info.get('mac_address', '')
        hostname = device_info.get('hostname', ip_address)
        vendor = device_info.get('vendor', '')

        # Get device classification
        device_type = device_info.get('device_type', 'unknown')
        manufacturer = device_info.get('manufacturer', '')
        icon = device_info.get('icon', '❓')
        category = device_info.get('category', 'other')

        # If not classified, use device classifier
        if device_type == 'unknown' and classifier:
            try:
                classification = classifier.classify_device(
                    mac_address=mac_address,
                    hostname=hostname,
                    open_ports=device_info.get('open_ports', []),
                    ip_address=ip_address
                )

                device_type = classification.get('device_type', 'unknown')
                manufacturer = classification.get('manufacturer') or manufacturer
                icon = classification.get('icon', '❓')
                category = classification.get('category', 'other')

                logger.info(f"Classified {ip_address} as {device_type} ({manufacturer})")

            except Exception as e:
                logger.warning(f"Error classifying device: {e}")

        # Add device to database
        conn = self.db_manager.conn
        cursor = conn.cursor()

        try:
            cursor.execute('''
                INSERT INTO devices
                (ip_address, mac_address, hostname, device_name, vendor,
                 device_type, manufacturer, icon, category, first_seen, last_seen,
                 model, firmware_version, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                ip_address,
                mac_address,
                hostname,
                hostname,  # Use hostname as device_name initially
                vendor or manufacturer,
                device_type,
                manufacturer,
                icon,
                category,
                datetime.now().isoformat(),
                datetime.now().isoformat(),
                device_info.get('model', ''),
                device_info.get('firmware_version', ''),
                f"Auto-discovered via {discovery_method}"
            ))

            conn.commit()
            logger.info(f"Added device {ip_address} to database")

        except sqlite3.IntegrityError:
            logger.info(f"Device {ip_address} already exists, updating last_seen")
            cursor.execute(
                "UPDATE devices SET last_seen = ? WHERE ip_address = ?",
                (datetime.now().isoformat(), ip_address)
            )
            conn.commit()

        finally:

    def _schedule_baseline_learning(self, device_ip: str):
        """
        Schedule baseline learning task for device.

        Args:
            device_ip: Device IP address
        """
        try:
            conn = self.db_manager.conn
            cursor = conn.cursor()

            scheduled_time = datetime.now() + timedelta(days=self.baseline_learning_days)

            cursor.execute('''
                INSERT INTO scheduled_tasks
                (task_type, device_ip, scheduled_at, completed, created_at)
                VALUES (?, ?, ?, 0, ?)
            ''', (
                'baseline_learning',
                device_ip,
                scheduled_time.isoformat(),
                datetime.now().isoformat()
            ))

            conn.commit()

            logger.info(f"Scheduled baseline learning for {device_ip} at {scheduled_time}")

        except Exception as e:
            logger.warning(f"Could not schedule baseline learning: {e}")

    def get_pending_tasks(self, task_type: Optional[str] = None) -> list:
        """
        Get pending scheduled tasks.

        Args:
            task_type: Filter by task type (None = all)

        Returns:
            List of task dictionaries
        """
        try:
            conn = self.db_manager.conn
            cursor = conn.cursor()

            if task_type:
                cursor.execute('''
                    SELECT id, task_type, device_ip, scheduled_at, created_at
                    FROM scheduled_tasks
                    WHERE completed = 0 AND task_type = ?
                    AND scheduled_at <= ?
                    ORDER BY scheduled_at
                ''', (task_type, datetime.now().isoformat()))
            else:
                cursor.execute('''
                    SELECT id, task_type, device_ip, scheduled_at, created_at
                    FROM scheduled_tasks
                    WHERE completed = 0
                    AND scheduled_at <= ?
                    ORDER BY scheduled_at
                ''', (datetime.now().isoformat(),))

            tasks = []
            for row in cursor.fetchall():
                tasks.append({
                    'id': row[0],
                    'task_type': row[1],
                    'device_ip': row[2],
                    'scheduled_at': row[3],
                    'created_at': row[4]
                })

            return tasks

        except Exception as e:
            logger.error(f"Error getting pending tasks: {e}")
            return []

    def mark_task_completed(self, task_id: int):
        """
        Mark a scheduled task as completed.

        Args:
            task_id: Task ID
        """
        try:
            conn = self.db_manager.conn
            cursor = conn.cursor()

            cursor.execute(
                "UPDATE scheduled_tasks SET completed = 1 WHERE id = ?",
                (task_id,)
            )

            conn.commit()

            logger.info(f"Marked task {task_id} as completed")

        except Exception as e:
            logger.error(f"Error marking task completed: {e}")

    def get_discovery_stats(self) -> Dict[str, Any]:
        """
        Get discovery statistics.

        Returns:
            Dictionary with discovery stats
        """
        try:
            conn = self.db_manager.conn
            cursor = conn.cursor()

            # Total discovered devices
            cursor.execute("SELECT COUNT(*) FROM discovery_events")
            total_events = cursor.fetchone()[0]

            # By discovery method
            cursor.execute('''
                SELECT discovery_method, COUNT(*)
                FROM discovery_events
                GROUP BY discovery_method
            ''')
            by_method = dict(cursor.fetchall())

            # Recent discoveries (last 24 hours)
            yesterday = (datetime.now() - timedelta(days=1)).isoformat()
            cursor.execute(
                "SELECT COUNT(*) FROM discovery_events WHERE timestamp > ?",
                (yesterday,)
            )
            recent_count = cursor.fetchone()[0]

            # Pending tasks
            cursor.execute("SELECT COUNT(*) FROM scheduled_tasks WHERE completed = 0")
            pending_tasks = cursor.fetchone()[0]


            return {
                'total_discovery_events': total_events,
                'by_method': by_method,
                'recent_discoveries_24h': recent_count,
                'pending_tasks': pending_tasks,
                'session_provisioned': len(self.provisioned_devices)
            }

        except Exception as e:
            logger.error(f"Error getting discovery stats: {e}")
            return {}


# Global auto-provisioner instance
_auto_provisioner = None


def get_auto_provisioner(db_path: str = 'data/iot_monitor.db') -> AutoProvisioner:
    """
    Get global auto-provisioner instance.

    Args:
        db_path: Path to database

    Returns:
        AutoProvisioner instance
    """
    global _auto_provisioner
    if _auto_provisioner is None:
        _auto_provisioner = AutoProvisioner(db_path=db_path)
    return _auto_provisioner
