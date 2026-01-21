#!/usr/bin/env python3
"""
Audit Logging Utility for IoTSentinel

Logs all privileged actions for security auditing and compliance.
Tracks who did what, when, and from where.
"""

import logging
from datetime import datetime
from flask_login import current_user
from flask import request

logger = logging.getLogger(__name__)
audit_logger = logging.getLogger('audit')  # Dedicated audit logger


class AuditLogger:
    """Centralized audit logging for security-sensitive actions."""

    def __init__(self, db_manager):
        """Initialize audit logger with database connection."""
        self.db_manager = db_manager

    def log_action(self, action_type, action_description, target_resource=None,
                   success=True, error_message=None):
        """
        Log a privileged action to the audit trail.

        Args:
            action_type: Type of action (e.g., 'device_block', 'user_create', 'emergency_mode')
            action_description: Human-readable description of the action
            target_resource: Resource affected (e.g., device IP, username, setting name)
            success: Whether the action succeeded
            error_message: Error message if action failed
        """
        try:
            # Get user information
            user_id = current_user.id if current_user.is_authenticated else None
            username = current_user.username if current_user.is_authenticated else 'anonymous'

            # Get request information
            ip_address = request.remote_addr if request else None
            user_agent = request.headers.get('User-Agent') if request else None

            # Insert audit log
            conn = self.db_manager.conn
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO audit_log
                (user_id, username, action_type, action_description, target_resource,
                 ip_address, user_agent, success, error_message)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (user_id, username, action_type, action_description, target_resource,
                  ip_address, user_agent, 1 if success else 0, error_message))
            conn.commit()

            # Also log to audit file for redundancy
            log_level = logging.INFO if success else logging.WARNING
            audit_logger.log(log_level, f"{action_type} by {username} - {action_description} [target={target_resource}, success={success}]")

        except Exception as e:
            logger.error(f"Failed to write audit log: {e}")

    def get_recent_audit_logs(self, limit=100, user_id=None, action_type=None):
        """
        Retrieve recent audit logs with optional filtering.

        Args:
            limit: Maximum number of logs to return
            user_id: Filter by specific user
            action_type: Filter by specific action type

        Returns:
            List of audit log dictionaries
        """
        try:
            conn = self.db_manager.conn
            cursor = conn.cursor()

            query = "SELECT * FROM audit_log WHERE 1=1"
            params = []

            if user_id:
                query += " AND user_id = ?"
                params.append(user_id)

            if action_type:
                query += " AND action_type = ?"
                params.append(action_type)

            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)

            cursor.execute(query, params)

            logs = []
            for row in cursor.fetchall():
                logs.append({
                    'id': row['id'],
                    'timestamp': row['timestamp'],
                    'user_id': row['user_id'],
                    'username': row['username'],
                    'action_type': row['action_type'],
                    'action_description': row['action_description'],
                    'target_resource': row['target_resource'],
                    'ip_address': row['ip_address'],
                    'success': bool(row['success']),
                    'error_message': row['error_message']
                })

            return logs

        except Exception as e:
            logger.error(f"Failed to retrieve audit logs: {e}")
            return []

    def cleanup_old_logs(self, days_to_keep=90):
        """
        Remove audit logs older than specified days.

        Args:
            days_to_keep: Number of days to retain logs (default 90)
        """
        try:
            conn = self.db_manager.conn
            cursor = conn.cursor()
            cursor.execute('''
                DELETE FROM audit_log
                WHERE timestamp < datetime('now', '-' || ? || ' days')
            ''', (days_to_keep,))
            deleted_count = cursor.rowcount
            conn.commit()

            if deleted_count > 0:
                logger.info(f"Cleaned up {deleted_count} old audit logs")

            return deleted_count

        except Exception as e:
            logger.error(f"Failed to cleanup audit logs: {e}")
            return 0


# Convenience functions for common audit actions
def log_device_action(audit_logger, action, device_ip, success=True, error_message=None):
    """Log device-related actions (block, unblock, delete, trust)."""
    audit_logger.log_action(
        action_type=f'device_{action}',
        action_description=f'Device {action}: {device_ip}',
        target_resource=device_ip,
        success=success,
        error_message=error_message
    )


def log_bulk_action(audit_logger, action, count, success=True, error_message=None):
    """Log bulk operations (bulk delete, bulk trust, bulk block)."""
    audit_logger.log_action(
        action_type=f'bulk_{action}',
        action_description=f'Bulk {action}: {count} devices',
        target_resource=f'{count}_devices',
        success=success,
        error_message=error_message
    )


def log_emergency_mode(audit_logger, activated, reason=None, success=True, error_message=None):
    """Log emergency mode activation/deactivation."""
    action = 'activate' if activated else 'deactivate'
    description = f'Emergency mode {action}d'
    if reason:
        description += f': {reason}'

    audit_logger.log_action(
        action_type=f'emergency_{action}',
        action_description=description,
        target_resource='emergency_mode',
        success=success,
        error_message=error_message
    )


def log_user_action(audit_logger, action, target_username, success=True, error_message=None):
    """Log user management actions (create, delete, role change)."""
    audit_logger.log_action(
        action_type=f'user_{action}',
        action_description=f'User {action}: {target_username}',
        target_resource=target_username,
        success=success,
        error_message=error_message
    )


def log_settings_change(audit_logger, setting_name, new_value, success=True, error_message=None):
    """Log critical settings changes (firewall, lockdown, etc)."""
    audit_logger.log_action(
        action_type='settings_change',
        action_description=f'Changed {setting_name} to {new_value}',
        target_resource=setting_name,
        success=success,
        error_message=error_message
    )
