"""
Security Audit Logger for IoTSentinel
Logs all security-relevant events for compliance and forensics
"""

import sqlite3
import json
import logging
from datetime import datetime
from typing import Dict, Any, Optional, List
from pathlib import Path
import os

# Setup dedicated security audit logger
logger = logging.getLogger(__name__)

# Setup dedicated file logger for security audit events
security_audit_file_logger = logging.getLogger('security_audit')
security_audit_file_logger.setLevel(logging.INFO)

# Create logs directory if it doesn't exist
log_dir = Path('data/logs')
log_dir.mkdir(parents=True, exist_ok=True)

# Add file handler for security audit logs
security_audit_log_file = log_dir / 'security_audit.log'
file_handler = logging.FileHandler(security_audit_log_file)
file_handler.setLevel(logging.INFO)

# Create formatter for security audit logs
formatter = logging.Formatter(
    '%(asctime)s | %(levelname)-8s | %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
file_handler.setFormatter(formatter)

# Add handler to security audit logger
if not security_audit_file_logger.handlers:  # Prevent duplicate handlers
    security_audit_file_logger.addHandler(file_handler)
    security_audit_file_logger.propagate = False  # Don't propagate to root logger


class SecurityAuditLogger:
    """
    Centralized security audit logging system.
    Logs all critical security events for compliance and forensics.
    Logs to both database (security_audit_log table) and file (data/logs/security_audit.log)

    Security Features:
    - Automatic filtering of sensitive fields (passwords, tokens, keys)
    - Sanitized logging to prevent credential leakage
    - Dual storage (database + file) for compliance
    """

    # Sensitive field names that should be filtered from logs
    SENSITIVE_FIELDS = {
        'password', 'passwd', 'pwd', 'secret', 'token', 'api_key', 'apikey',
        'private_key', 'access_token', 'refresh_token', 'session_key',
        'credential', 'auth_token', 'bearer_token', 'smtp_password',
        'db_password', 'database_password', 'client_secret', 'encryption_key'
    }

    # Event Types
    EVENT_TYPES = {
        'login_success': 'Successful login',
        'login_failure': 'Failed login attempt',
        'logout': 'User logout',
        'permission_denied': 'Access denied',
        'data_export': 'Data exported',
        'data_import': 'Data imported',
        'device_blocked': 'Device blocked',
        'device_unblocked': 'Device unblocked',
        'device_deleted': 'Device deleted',
        'user_created': 'User account created',
        'user_deleted': 'User account deleted',
        'user_modified': 'User account modified',
        'settings_changed': 'System settings changed',
        'firewall_rule_added': 'Firewall rule added',
        'firewall_rule_removed': 'Firewall rule removed',
        'alert_acknowledged': 'Alert acknowledged',
        'bulk_operation': 'Bulk operation performed',
        'scan_started': 'Security scan started',
        'scan_completed': 'Security scan completed',
        'api_key_generated': 'API key generated', # pragma: allowlist secret
        'api_key_revoked': 'API key revoked', # pragma: allowlist secret
        'backup_created': 'Backup created',
        'backup_restored': 'Backup restored',
        'lockdown_activated': 'Emergency lockdown activated',
        'lockdown_deactivated': 'Emergency lockdown deactivated'
    }

    def __init__(self, db_manager=None):
        """Initialize with database manager"""
        self.db_manager = db_manager
        self.file_logger = security_audit_file_logger
        # Note: security_audit_log table is created by config/init_database.py
        # No runtime table creation needed

    @staticmethod
    def _sanitize_details(details: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """
        Remove sensitive information from details dict before logging

        Args:
            details: Dictionary that may contain sensitive data

        Returns:
            Sanitized dictionary with sensitive fields masked
        """
        if not details:
            return details

        sanitized = {}
        for key, value in details.items():
            key_lower = key.lower()

            # Check if key contains any sensitive field name
            is_sensitive = any(sensitive in key_lower for sensitive in SecurityAuditLogger.SENSITIVE_FIELDS)

            if is_sensitive:
                sanitized[key] = '[REDACTED]'
            else:
                sanitized[key] = value

        return sanitized

    def log(self,
            event_type: str,
            user_id: Optional[int] = None,
            username: Optional[str] = None,
            details: Optional[Dict[str, Any]] = None,
            severity: str = 'info',
            ip_address: Optional[str] = None,
            resource_type: Optional[str] = None,
            resource_id: Optional[str] = None,
            result: str = 'success',
            failure_reason: Optional[str] = None,
            session_id: Optional[str] = None) -> bool:
        """
        Log a security audit event to both database and file

        Args:
            event_type: Type of security event
            user_id: User ID who performed the action
            username: Username who performed the action
            details: Additional event details (dict)
            severity: Event severity (critical, high, medium, low, info)
            ip_address: IP address of the request
            resource_type: Type of resource affected
            resource_id: ID of the resource affected
            result: Result of the action (success, failure)
            failure_reason: Reason for failure if result is 'failure'
            session_id: Session identifier

        Returns:
            bool: True if logged successfully, False otherwise
        """
        try:
            timestamp = datetime.now().isoformat()

            # Sanitize sensitive data from details
            sanitized_details = self._sanitize_details(details)

            # Build log message for file
            log_parts = [
                f"Event: {event_type}",
                f"User: {username or 'system'}",
                f"Result: {result.upper()}"
            ]

            if severity:
                log_parts.append(f"Severity: {severity.upper()}")
            if resource_type:
                log_parts.append(f"Resource: {resource_type}")
            if resource_id:
                log_parts.append(f"ResourceID: {resource_id}")
            if ip_address:
                log_parts.append(f"IP: {ip_address}")
            if failure_reason:
                log_parts.append(f"Reason: {failure_reason}")
            if sanitized_details:
                # Format sanitized details for readable logging
                details_str = ', '.join([f"{k}={v}" for k, v in sanitized_details.items()])
                log_parts.append(f"Details: {details_str}")

            log_message = " | ".join(log_parts)

            # Log to file based on severity
            if severity == 'critical':
                self.file_logger.critical(log_message)
            elif severity == 'high':
                self.file_logger.error(log_message)
            elif severity == 'medium':
                self.file_logger.warning(log_message)
            else:
                self.file_logger.info(log_message)

            # Log to database (also sanitized)
            if self.db_manager and hasattr(self.db_manager, 'conn'):
                conn = self.db_manager.conn
                cursor = conn.cursor()

                # Store sanitized details in database too
                details_json = json.dumps(sanitized_details) if sanitized_details else None

                cursor.execute("""
                    INSERT INTO security_audit_log
                    (timestamp, user_id, username, event_type, severity, ip_address,
                     resource_type, resource_id, details, result, failure_reason, session_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    timestamp, user_id, username, event_type, severity, ip_address,
                    resource_type, resource_id, details_json, result, failure_reason, session_id
                ))

                conn.commit()

            # Also log to regular logger for real-time monitoring
            if severity in ['critical', 'high']:
                logger.warning(f"AUDIT: {event_type} - {log_message}")
            else:
                logger.info(f"AUDIT: {event_type} - {log_message}")

            return True

        except Exception as e:
            logger.error(f"Failed to log audit event: {e}")
            # Fallback logging
            self._fallback_log(event_type, username, details, severity)
            return False

    def _fallback_log(self, event_type: str, username: str, details: Dict, severity: str):
        """Fallback logging to regular logger if database fails"""
        log_entry = {
            'type': 'SECURITY_AUDIT',
            'event': event_type,
            'user': username,
            'severity': severity,
            'details': details,
            'timestamp': datetime.now().isoformat()
        }

        if severity in ['critical', 'high']:
            logger.warning(f"AUDIT_FALLBACK: {json.dumps(log_entry)}")
        else:
            logger.info(f"AUDIT_FALLBACK: {json.dumps(log_entry)}")

    def get_recent_events(self,
                         limit: int = 100,
                         event_type: Optional[str] = None,
                         user_id: Optional[int] = None,
                         severity: Optional[str] = None,
                         start_time: Optional[str] = None,
                         end_time: Optional[str] = None) -> List[Dict]:
        """
        Get recent audit events with optional filtering

        Args:
            limit: Maximum number of events to return
            event_type: Filter by event type
            user_id: Filter by user ID
            severity: Filter by severity
            start_time: Filter events after this time (ISO format)
            end_time: Filter events before this time (ISO format)

        Returns:
            List of audit event dictionaries
        """
        try:
            if not self.db_manager or not hasattr(self.db_manager, 'conn'):
                return []

            conn = self.db_manager.conn
            cursor = conn.cursor()

            query = "SELECT * FROM security_audit_log WHERE 1=1"
            params = []

            if event_type:
                query += " AND event_type = ?"
                params.append(event_type)

            if user_id:
                query += " AND user_id = ?"
                params.append(user_id)

            if severity:
                query += " AND severity = ?"
                params.append(severity)

            if start_time:
                query += " AND timestamp >= ?"
                params.append(start_time)

            if end_time:
                query += " AND timestamp <= ?"
                params.append(end_time)

            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)

            cursor.execute(query, params)
            rows = cursor.fetchall()

            events = []
            for row in rows:
                event = dict(row)
                if event.get('details'):
                    try:
                        event['details'] = json.loads(event['details'])
                    except:
                        pass
                events.append(event)

            return events

        except Exception as e:
            logger.error(f"Failed to get audit events: {e}")
            return []

    def get_statistics(self, days: int = 30) -> Dict:
        """Get audit log statistics"""
        try:
            if not self.db_manager or not hasattr(self.db_manager, 'conn'):
                return {}

            conn = self.db_manager.conn
            cursor = conn.cursor()

            from datetime import timedelta
            start_date = (datetime.now() - timedelta(days=days)).isoformat()

            # Total events
            cursor.execute(
                "SELECT COUNT(*) FROM security_audit_log WHERE timestamp >= ?",
                (start_date,)
            )
            total_events = cursor.fetchone()[0]

            # Events by type
            cursor.execute("""
                SELECT event_type, COUNT(*) as count
                FROM security_audit_log
                WHERE timestamp >= ?
                GROUP BY event_type
                ORDER BY count DESC
            """, (start_date,))
            events_by_type = {row[0]: row[1] for row in cursor.fetchall()}

            # Events by severity
            cursor.execute("""
                SELECT severity, COUNT(*) as count
                FROM security_audit_log
                WHERE timestamp >= ?
                GROUP BY severity
                ORDER BY count DESC
            """, (start_date,))
            events_by_severity = {row[0]: row[1] for row in cursor.fetchall()}

            # Failed events
            cursor.execute("""
                SELECT COUNT(*) FROM security_audit_log
                WHERE timestamp >= ? AND result = 'failure'
            """, (start_date,))
            failed_events = cursor.fetchone()[0]

            return {
                'total_events': total_events,
                'failed_events': failed_events,
                'events_by_type': events_by_type,
                'events_by_severity': events_by_severity,
                'period_days': days
            }

        except Exception as e:
            logger.error(f"Failed to get audit statistics: {e}")
            return {}

    def export_to_file(self, filepath: str, format: str = 'json',
                      start_time: Optional[str] = None,
                      end_time: Optional[str] = None) -> bool:
        """Export audit log to file"""
        try:
            events = self.get_recent_events(
                limit=10000,
                start_time=start_time,
                end_time=end_time
            )

            if format == 'json':
                with open(filepath, 'w') as f:
                    json.dump(events, f, indent=2)
            elif format == 'csv':
                import csv
                if events:
                    with open(filepath, 'w', newline='') as f:
                        writer = csv.DictWriter(f, fieldnames=events[0].keys())
                        writer.writeheader()
                        writer.writerows(events)

            logger.info(f"Audit log exported to {filepath}")
            return True

        except Exception as e:
            logger.error(f"Failed to export audit log: {e}")
            return False


# Global instance
_audit_logger = None

def get_audit_logger(db_manager=None):
    """Get or create global audit logger instance"""
    global _audit_logger
    if _audit_logger is None and db_manager is not None:
        _audit_logger = SecurityAuditLogger(db_manager)
    return _audit_logger
