"""
Enhanced Role-Based Access Control (RBAC) System for IoTSentinel
Provides comprehensive permission management and security controls
"""

from functools import wraps
from typing import List, Dict, Optional, Callable, Any
import logging
from flask_login import current_user

logger = logging.getLogger(__name__)


# Role Definitions with Hierarchical Permissions
ROLES = {
    'admin': {
        'name': 'Administrator',
        'level': 100,
        'description': 'Full system access - can manage users, settings, and all features',
        'permissions': [
            'view_dashboard', 'view_devices', 'view_alerts', 'view_security', 'view_analytics',
            'manage_devices', 'manage_alerts', 'manage_security', 'manage_users', 'manage_system',
            'export_data', 'import_data', 'bulk_operations', 'delete_data', 'modify_settings',
            'run_scans', 'block_devices', 'manage_firewall', 'view_audit_logs', 'manage_api'
        ]
    },
    'security_analyst': {
        'name': 'Security Analyst',
        'level': 80,
        'description': 'Security-focused role - can view and manage security features',
        'permissions': [
            'view_dashboard', 'view_devices', 'view_alerts', 'view_security', 'view_analytics',
            'manage_devices', 'manage_alerts', 'manage_security',
            'export_data', 'run_scans', 'block_devices', 'manage_firewall'
        ]
    },
    'operator': {
        'name': 'Operator',
        'level': 60,
        'description': 'Operational role - can view data and perform basic operations',
        'permissions': [
            'view_dashboard', 'view_devices', 'view_alerts', 'view_security', 'view_analytics',
            'manage_devices', 'acknowledge_alerts',
            'export_data_limited'
        ]
    },
    'viewer': {
        'name': 'Viewer',
        'level': 40,
        'description': 'Read-only access - can view dashboard and reports only',
        'permissions': [
            'view_dashboard', 'view_devices', 'view_alerts', 'view_security', 'view_analytics'
        ]
    },
    'kid': {
        'name': 'Child User',
        'level': 20,
        'description': 'Restricted access - limited view with safety features',
        'permissions': [
            'view_dashboard_limited', 'view_devices_basic'
        ]
    }
}


# Permission Categories for Organization
PERMISSION_CATEGORIES = {
    'view': [
        'view_dashboard', 'view_dashboard_limited', 'view_devices', 'view_devices_basic',
        'view_alerts', 'view_security', 'view_analytics', 'view_audit_logs'
    ],
    'manage': [
        'manage_devices', 'manage_alerts', 'manage_security', 'manage_users', 'manage_system'
    ],
    'data': [
        'export_data', 'export_data_limited', 'import_data', 'delete_data', 'bulk_operations'
    ],
    'security_operations': [
        'run_scans', 'block_devices', 'manage_firewall', 'modify_settings'
    ],
    'admin': [
        'manage_users', 'view_audit_logs', 'manage_api'
    ]
}


class PermissionManager:
    """Centralized permission management system"""

    @staticmethod
    def get_user_role(user) -> Optional[str]:
        """Get role from user object"""
        if not user or not user.is_authenticated:
            return None
        return getattr(user, 'role', 'viewer')

    @staticmethod
    def get_role_permissions(role: str) -> List[str]:
        """Get all permissions for a role"""
        role_data = ROLES.get(role, ROLES['viewer'])
        return role_data.get('permissions', [])

    @staticmethod
    def has_permission(user, permission: str) -> bool:
        """Check if user has specific permission"""
        if not user or not user.is_authenticated:
            return False

        role = PermissionManager.get_user_role(user)
        if role == 'admin':
            return True  # Admin has all permissions

        permissions = PermissionManager.get_role_permissions(role)
        return permission in permissions

    @staticmethod
    def has_any_permission(user, permissions: List[str]) -> bool:
        """Check if user has any of the listed permissions"""
        return any(PermissionManager.has_permission(user, p) for p in permissions)

    @staticmethod
    def has_all_permissions(user, permissions: List[str]) -> bool:
        """Check if user has all listed permissions"""
        return all(PermissionManager.has_permission(user, p) for p in permissions)

    @classmethod
    def require_permission(cls, permission: str):
        """Decorator to require specific permission for a callback"""
        def decorator(func: Callable) -> Callable:
            @wraps(func)
            def wrapper(*args, **kwargs):
                if not cls.has_permission(current_user, permission):
                    logger.warning(
                        f"Permission denied: {permission} required for {func.__name__}. "
                        f"User: {current_user.username if current_user.is_authenticated else 'anonymous'}"
                    )
                    return cls._deny_access_response(func, permission)
                return func(*args, **kwargs)
            return wrapper
        return decorator

    @classmethod
    def require_any_permission(cls, permissions: List[str]):
        """Decorator to require any of the listed permissions"""
        def decorator(func: Callable) -> Callable:
            @wraps(func)
            def wrapper(*args, **kwargs):
                if not cls.has_any_permission(current_user, permissions):
                    logger.warning(
                        f"Permission denied: One of {permissions} required for {func.__name__}"
                    )
                    return cls._deny_access_response(func, f"one of {permissions}")
                return func(*args, **kwargs)
            return wrapper
        return decorator

    @classmethod
    def require_admin(cls, func: Callable) -> Callable:
        """Decorator to require admin role"""
        @wraps(func)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated or not current_user.is_admin():
                logger.warning(
                    f"Admin access denied for {func.__name__}. "
                    f"User: {current_user.username if current_user.is_authenticated else 'anonymous'}"
                )
                return cls._deny_access_response(func, "admin")
            return func(*args, **kwargs)
        return wrapper

    @staticmethod
    def _deny_access_response(func: Callable, required: str):
        """Generate denial response based on function signature"""
        # Import here to avoid circular dependency
        from dash import no_update
        from dash.exceptions import PreventUpdate

        # Try to determine return signature
        import inspect
        sig = inspect.signature(func)
        return_count = len([p for p in sig.parameters.values()
                           if p.kind == inspect.Parameter.KEYWORD_ONLY and 'Output' in str(p.default)])

        if return_count == 0:
            raise PreventUpdate
        elif return_count == 1:
            return no_update
        else:
            return tuple([no_update] * return_count)


# Permission Helper Functions
def can_export_data(user=None) -> bool:
    """Check if user can export full data (admin only)"""
    if user is None:
        user = current_user
    return PermissionManager.has_permission(user, 'export_data')


def can_export_limited(user=None) -> bool:
    """Check if user can export limited data"""
    if user is None:
        user = current_user
    return PermissionManager.has_any_permission(user, ['export_data', 'export_data_limited'])


def can_manage_devices(user=None) -> bool:
    """Check if user can manage devices"""
    if user is None:
        user = current_user
    return PermissionManager.has_permission(user, 'manage_devices')


def can_block_devices(user=None) -> bool:
    """Check if user can block/unblock devices"""
    if user is None:
        user = current_user
    return PermissionManager.has_permission(user, 'block_devices')


def can_run_scans(user=None) -> bool:
    """Check if user can run security scans"""
    if user is None:
        user = current_user
    return PermissionManager.has_permission(user, 'run_scans')


def can_delete_data(user=None) -> bool:
    """Check if user can delete data"""
    if user is None:
        user = current_user
    return PermissionManager.has_permission(user, 'delete_data')


def can_manage_system(user=None) -> bool:
    """Check if user can manage system settings"""
    if user is None:
        user = current_user
    return PermissionManager.has_permission(user, 'manage_system')


def get_accessible_pages(user=None) -> List[str]:
    """Get list of pages accessible to user"""
    if user is None:
        user = current_user

    if not user.is_authenticated:
        return []

    pages = ['dashboard']

    if PermissionManager.has_permission(user, 'view_devices'):
        pages.append('devices')
    if PermissionManager.has_permission(user, 'view_alerts'):
        pages.append('alerts')
    if PermissionManager.has_permission(user, 'view_security'):
        pages.append('security')
    if PermissionManager.has_permission(user, 'view_analytics'):
        pages.append('analytics')
    if PermissionManager.has_permission(user, 'manage_system'):
        pages.append('settings')

    return pages


# Feature Access Control
FEATURE_ACCESS = {
    'export_csv': {'permission': 'export_data', 'min_role': 'admin'},
    'export_json': {'permission': 'export_data', 'min_role': 'admin'},
    'export_pdf': {'permission': 'export_data', 'min_role': 'admin'},
    'export_excel': {'permission': 'export_data', 'min_role': 'admin'},
    'export_limited': {'permission': 'export_data_limited', 'min_role': 'operator'},
    'bulk_delete': {'permission': 'delete_data', 'min_role': 'admin'},
    'bulk_block': {'permission': 'block_devices', 'min_role': 'security_analyst'},
    'bulk_trust': {'permission': 'manage_devices', 'min_role': 'security_analyst'},
    'firewall_manage': {'permission': 'manage_firewall', 'min_role': 'security_analyst'},
    'user_management': {'permission': 'manage_users', 'min_role': 'admin'},
    'system_settings': {'permission': 'manage_system', 'min_role': 'admin'},
    'api_management': {'permission': 'manage_api', 'min_role': 'admin'},
}


def check_feature_access(feature: str, user=None) -> bool:
    """Check if user can access a specific feature"""
    if user is None:
        user = current_user

    if not user.is_authenticated:
        return False

    feature_config = FEATURE_ACCESS.get(feature)
    if not feature_config:
        logger.warning(f"Unknown feature access check: {feature}")
        return False

    return PermissionManager.has_permission(user, feature_config['permission'])


# Audit Log Helper
def log_security_event(event_type: str, details: Dict[str, Any], user=None):
    """Log security-related events for audit purposes"""
    if user is None:
        user = current_user

    username = user.username if user and user.is_authenticated else 'anonymous'

    log_entry = {
        'timestamp': datetime.now().isoformat(),
        'user': username,
        'event_type': event_type,
        'details': details
    }

    logger.info(f"SECURITY_EVENT: {log_entry}")

    # Could also write to database audit log here
    try:
        from utils.audit_logger import AuditLogger
        AuditLogger.log_security_event(username, event_type, details)
    except Exception as e:
        logger.error(f"Failed to write audit log: {e}")


# Import datetime for audit logging
from datetime import datetime
