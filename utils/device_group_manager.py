#!/usr/bin/env python3
"""
Device Group Manager for IoTSentinel

Manages device groups, memberships, and group-based operations.
"""

import sqlite3
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class DeviceGroupManager:
    """Manages device groups and group memberships"""

    def __init__(self, db_path: str):
        """
        Initialize device group manager.

        Args:
            db_path: Path to SQLite database
        """
        self.db_path = db_path

    def get_all_groups(self) -> List[Dict[str, Any]]:
        """
        Get all device groups.

        Returns:
            List of group dictionaries
        """
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute("""
                SELECT
                    g.*,
                    COUNT(m.device_ip) as device_count
                FROM device_groups g
                LEFT JOIN device_group_members m ON g.id = m.group_id
                GROUP BY g.id
                ORDER BY g.name ASC
            """)

            groups = [dict(row) for row in cursor.fetchall()]
            conn.close()

            return groups

        except sqlite3.Error as e:
            logger.error(f"Error fetching device groups: {e}")
            return []

    def get_group_by_id(self, group_id: int) -> Optional[Dict[str, Any]]:
        """
        Get group by ID.

        Args:
            group_id: Group ID

        Returns:
            Group dictionary or None
        """
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute("""
                SELECT
                    g.*,
                    COUNT(m.device_ip) as device_count
                FROM device_groups g
                LEFT JOIN device_group_members m ON g.id = m.group_id
                WHERE g.id = ?
                GROUP BY g.id
            """, (group_id,))

            row = cursor.fetchone()
            conn.close()

            return dict(row) if row else None

        except sqlite3.Error as e:
            logger.error(f"Error fetching group {group_id}: {e}")
            return None

    def get_group_by_name(self, name: str) -> Optional[Dict[str, Any]]:
        """
        Get group by name.

        Args:
            name: Group name

        Returns:
            Group dictionary or None
        """
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute("""
                SELECT
                    g.*,
                    COUNT(m.device_ip) as device_count
                FROM device_groups g
                LEFT JOIN device_group_members m ON g.id = m.group_id
                WHERE g.name = ?
                GROUP BY g.id
            """, (name,))

            row = cursor.fetchone()
            conn.close()

            return dict(row) if row else None

        except sqlite3.Error as e:
            logger.error(f"Error fetching group '{name}': {e}")
            return None

    def create_group(
        self,
        name: str,
        description: str = "",
        color: str = "#0dcaf0",
        icon: str = "fa-folder",
        created_by: Optional[int] = None
    ) -> Optional[int]:
        """
        Create a new device group.

        Args:
            name: Group name (must be unique)
            description: Group description
            color: Group color (hex code)
            icon: FontAwesome icon class
            created_by: User ID who created the group

        Returns:
            Group ID if created successfully, None otherwise
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute("""
                INSERT INTO device_groups (name, description, color, icon, created_by)
                VALUES (?, ?, ?, ?, ?)
            """, (name, description, color, icon, created_by))

            group_id = cursor.lastrowid
            conn.commit()
            conn.close()

            logger.info(f"Created device group '{name}' (ID: {group_id})")
            return group_id

        except sqlite3.IntegrityError:
            logger.warning(f"Group with name '{name}' already exists")
            return None
        except sqlite3.Error as e:
            logger.error(f"Error creating group: {e}")
            return None

    def update_group(
        self,
        group_id: int,
        name: Optional[str] = None,
        description: Optional[str] = None,
        color: Optional[str] = None,
        icon: Optional[str] = None
    ) -> bool:
        """
        Update group properties.

        Args:
            group_id: Group ID
            name: New name (optional)
            description: New description (optional)
            color: New color (optional)
            icon: New icon (optional)

        Returns:
            True if updated successfully, False otherwise
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Build update query dynamically
            updates = []
            values = []

            if name is not None:
                updates.append("name = ?")
                values.append(name)
            if description is not None:
                updates.append("description = ?")
                values.append(description)
            if color is not None:
                updates.append("color = ?")
                values.append(color)
            if icon is not None:
                updates.append("icon = ?")
                values.append(icon)

            if not updates:
                return False

            values.append(group_id)
            query = f"UPDATE device_groups SET {', '.join(updates)} WHERE id = ?"

            cursor.execute(query, values)
            conn.commit()
            conn.close()

            logger.info(f"Updated device group ID {group_id}")
            return True

        except sqlite3.IntegrityError:
            logger.warning(f"Group name already exists")
            return False
        except sqlite3.Error as e:
            logger.error(f"Error updating group {group_id}: {e}")
            return False

    def delete_group(self, group_id: int) -> bool:
        """
        Delete a device group.

        Args:
            group_id: Group ID

        Returns:
            True if deleted successfully, False otherwise
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Delete group (cascade will remove memberships)
            cursor.execute("DELETE FROM device_groups WHERE id = ?", (group_id,))

            conn.commit()
            conn.close()

            logger.info(f"Deleted device group ID {group_id}")
            return True

        except sqlite3.Error as e:
            logger.error(f"Error deleting group {group_id}: {e}")
            return False

    def add_device_to_group(
        self,
        device_ip: str,
        group_id: int,
        added_by: Optional[int] = None
    ) -> bool:
        """
        Add device to group.

        Args:
            device_ip: Device IP address
            group_id: Group ID
            added_by: User ID who added the device

        Returns:
            True if added successfully, False otherwise
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute("""
                INSERT INTO device_group_members (device_ip, group_id, added_by)
                VALUES (?, ?, ?)
            """, (device_ip, group_id, added_by))

            conn.commit()
            conn.close()

            logger.info(f"Added device {device_ip} to group ID {group_id}")
            return True

        except sqlite3.IntegrityError:
            logger.warning(f"Device {device_ip} already in group {group_id}")
            return False
        except sqlite3.Error as e:
            logger.error(f"Error adding device to group: {e}")
            return False

    def remove_device_from_group(self, device_ip: str, group_id: int) -> bool:
        """
        Remove device from group.

        Args:
            device_ip: Device IP address
            group_id: Group ID

        Returns:
            True if removed successfully, False otherwise
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute("""
                DELETE FROM device_group_members
                WHERE device_ip = ? AND group_id = ?
            """, (device_ip, group_id))

            conn.commit()
            conn.close()

            logger.info(f"Removed device {device_ip} from group ID {group_id}")
            return True

        except sqlite3.Error as e:
            logger.error(f"Error removing device from group: {e}")
            return False

    def get_device_groups(self, device_ip: str) -> List[Dict[str, Any]]:
        """
        Get all groups a device belongs to.

        Args:
            device_ip: Device IP address

        Returns:
            List of group dictionaries
        """
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute("""
                SELECT g.*, m.added_at
                FROM device_groups g
                INNER JOIN device_group_members m ON g.id = m.group_id
                WHERE m.device_ip = ?
                ORDER BY g.name ASC
            """, (device_ip,))

            groups = [dict(row) for row in cursor.fetchall()]
            conn.close()

            return groups

        except sqlite3.Error as e:
            logger.error(f"Error fetching groups for device {device_ip}: {e}")
            return []

    def get_group_devices(self, group_id: int) -> List[Dict[str, Any]]:
        """
        Get all devices in a group.

        Args:
            group_id: Group ID

        Returns:
            List of device dictionaries
        """
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute("""
                SELECT
                    d.*,
                    m.added_at as group_added_at
                FROM devices d
                INNER JOIN device_group_members m ON d.device_ip = m.device_ip
                WHERE m.group_id = ?
                ORDER BY d.device_name ASC, d.device_ip ASC
            """, (group_id,))

            devices = [dict(row) for row in cursor.fetchall()]
            conn.close()

            return devices

        except sqlite3.Error as e:
            logger.error(f"Error fetching devices for group {group_id}: {e}")
            return []

    def move_device_to_group(
        self,
        device_ip: str,
        from_group_id: int,
        to_group_id: int,
        moved_by: Optional[int] = None
    ) -> bool:
        """
        Move device from one group to another.

        Args:
            device_ip: Device IP address
            from_group_id: Source group ID
            to_group_id: Destination group ID
            moved_by: User ID who moved the device

        Returns:
            True if moved successfully, False otherwise
        """
        try:
            # Remove from old group
            self.remove_device_from_group(device_ip, from_group_id)

            # Add to new group
            return self.add_device_to_group(device_ip, to_group_id, moved_by)

        except Exception as e:
            logger.error(f"Error moving device {device_ip}: {e}")
            return False

    def get_ungrouped_devices(self) -> List[Dict[str, Any]]:
        """
        Get all devices not in any group.

        Returns:
            List of device dictionaries
        """
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute("""
                SELECT d.*
                FROM devices d
                LEFT JOIN device_group_members m ON d.device_ip = m.device_ip
                WHERE m.device_ip IS NULL
                ORDER BY d.last_seen DESC
            """)

            devices = [dict(row) for row in cursor.fetchall()]
            conn.close()

            return devices

        except sqlite3.Error as e:
            logger.error(f"Error fetching ungrouped devices: {e}")
            return []

    def get_group_statistics(self, group_id: int, days: int = 7) -> Dict[str, Any]:
        """
        Get statistics for a group.

        Args:
            group_id: Group ID
            days: Number of days for statistics

        Returns:
            Statistics dictionary
        """
        try:
            from datetime import datetime, timedelta

            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            stats = {}
            cutoff_date = datetime.now() - timedelta(days=days)

            # Get device count
            cursor.execute("""
                SELECT COUNT(*) as count
                FROM device_group_members
                WHERE group_id = ?
            """, (group_id,))
            stats['device_count'] = cursor.fetchone()[0]

            # Get total connections for group devices
            cursor.execute("""
                SELECT COUNT(*) as count
                FROM connections c
                INNER JOIN device_group_members m ON c.device_ip = m.device_ip
                WHERE m.group_id = ? AND c.timestamp > ?
            """, (group_id, cutoff_date.isoformat()))
            stats['total_connections'] = cursor.fetchone()[0]

            # Get total data transferred
            cursor.execute("""
                SELECT SUM(c.bytes_sent + c.bytes_received) as total_bytes
                FROM connections c
                INNER JOIN device_group_members m ON c.device_ip = m.device_ip
                WHERE m.group_id = ? AND c.timestamp > ?
            """, (group_id, cutoff_date.isoformat()))
            result = cursor.fetchone()
            stats['total_data_mb'] = (result[0] / (1024 * 1024)) if result[0] else 0

            # Get alert count
            cursor.execute("""
                SELECT COUNT(*) as count
                FROM alerts a
                INNER JOIN device_group_members m ON a.device_ip = m.device_ip
                WHERE m.group_id = ? AND a.timestamp > ?
            """, (group_id, cutoff_date.isoformat()))
            stats['alert_count'] = cursor.fetchone()[0]

            # Get active devices (seen in last 24 hours)
            active_cutoff = datetime.now() - timedelta(hours=24)
            cursor.execute("""
                SELECT COUNT(*) as count
                FROM devices d
                INNER JOIN device_group_members m ON d.device_ip = m.device_ip
                WHERE m.group_id = ? AND d.last_seen > ?
            """, (group_id, active_cutoff.isoformat()))
            stats['active_devices'] = cursor.fetchone()[0]

            conn.close()

            return stats

        except sqlite3.Error as e:
            logger.error(f"Error fetching group statistics: {e}")
            return {}

    def bulk_add_devices(self, device_ips: List[str], group_id: int, added_by: Optional[int] = None) -> int:
        """
        Add multiple devices to a group.

        Args:
            device_ips: List of device IP addresses
            group_id: Group ID
            added_by: User ID who added the devices

        Returns:
            Number of devices successfully added
        """
        count = 0
        for device_ip in device_ips:
            if self.add_device_to_group(device_ip, group_id, added_by):
                count += 1
        return count

    def auto_group_by_type(self) -> Dict[str, int]:
        """
        Automatically assign devices to groups based on their type.

        Returns:
            Dictionary mapping device types to group IDs
        """
        try:
            type_to_group = {
                'iot': 'IoT Devices',
                'computer': 'Computers',
                'mobile': 'Mobile Devices',
                'network': 'Network Infrastructure',
                'security': 'Security Devices',
                'media': 'Media Devices',
                'printer': 'Printers & Peripherals',
            }

            result = {}

            for device_type, group_name in type_to_group.items():
                # Get group ID
                group = self.get_group_by_name(group_name)
                if not group:
                    continue

                # Get devices of this type that aren't in this group
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()

                cursor.execute("""
                    SELECT d.device_ip
                    FROM devices d
                    LEFT JOIN device_group_members m ON d.device_ip = m.device_ip AND m.group_id = ?
                    WHERE d.device_type = ? AND m.device_ip IS NULL
                """, (group['id'], device_type))

                devices = [row[0] for row in cursor.fetchall()]
                conn.close()

                # Add to group
                count = self.bulk_add_devices(devices, group['id'])
                result[device_type] = count

                logger.info(f"Auto-grouped {count} {device_type} devices")

            return result

        except Exception as e:
            logger.error(f"Error in auto-grouping: {e}")
            return {}
