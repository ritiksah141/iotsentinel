"""
Enhanced Toast Notification Management System v2.1.1
Provides consistent, visible, and interactive toast notifications with:
- Persistent toasts
- Toast queue system
- Category filtering
- Toast history
- Action buttons
"""
import dash_bootstrap_components as dbc
from dash import html
import uuid
import json
import sqlite3
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any
from collections import deque
import threading

logger = logging.getLogger(__name__)

# Toast Configuration Constants
TOAST_POSITION_STYLE = {
    "position": "fixed",
    "top": 20,
    "left": "50%",
    "transform": "translateX(-50%)",
    "width": 380,  # Slightly wider for better visibility
    "zIndex": 999999  # Highest z-index - appears above everything including modals
}

TOAST_DURATIONS = {
    "short": 3000,    # 3 seconds minimum
    "medium": 4000,   # 4 seconds default
    "long": 5000,     # 5 seconds for important messages
    "persistent": 0   # No auto-dismiss
}

TOAST_ICONS = {
    "success": "✅",
    "error": "❌",
    "danger": "❌",
    "warning": "⚠️",
    "info": "ℹ️"
}

# Category definitions (synced with database)
TOAST_CATEGORIES = {
    "general": {"name": "General", "icon": "fa-info-circle", "color": "#0dcaf0", "priority": 0},
    "security": {"name": "Security", "icon": "fa-shield-alt", "color": "#dc3545", "priority": 10},
    "network": {"name": "Network", "icon": "fa-network-wired", "color": "#17a2b8", "priority": 8},
    "device": {"name": "Device", "icon": "fa-microchip", "color": "#6c757d", "priority": 7},
    "user": {"name": "User", "icon": "fa-user", "color": "#6f42c1", "priority": 6},
    "system": {"name": "System", "icon": "fa-cog", "color": "#fd7e14", "priority": 5},
    "export": {"name": "Export", "icon": "fa-file-export", "color": "#20c997", "priority": 3},
    "scan": {"name": "Scan", "icon": "fa-radar", "color": "#ffc107", "priority": 4},
}

# Store for toast details (for detail modal)
toast_details_store = {}

# Toast queue for sequential display
toast_queue = deque()
queue_lock = threading.Lock()

# Active toasts counter
active_toasts_count = 0
max_simultaneous_toasts = 3


class ToastHistoryManager:
    """Manages toast history persistence to database"""
    _db_manager = None  # Cached DatabaseManager instance

    @classmethod
    def get_db_manager(cls):
        """Get or create cached DatabaseManager instance"""
        if cls._db_manager is None:
            db_path = cls.get_db_path()
            if db_path:
                from database.db_manager import DatabaseManager
                cls._db_manager = DatabaseManager(db_path=db_path)
        return cls._db_manager

    @staticmethod
    def get_db_path():
        """Get database path from config"""
        try:
            from config.config_manager import config
            return config.get('database', 'path')
        except Exception as e:
            logger.warning(f"Could not get database path from config: {e}")
            return None

    @staticmethod
    def save_to_history(
        toast_id: str,
        toast_type: str,
        category: str,
        header: str,
        message: str,
        detail_message: Optional[str] = None,
        user_id: Optional[int] = None,
        session_id: Optional[str] = None,
        duration: int = 0,
        metadata: Optional[Dict] = None
    ):
        """Save toast to history database"""
        try:
            db_manager = ToastHistoryManager.get_db_manager()
            if db_manager is None:
                return False

            conn = db_manager.conn
            cursor = conn.cursor()

            cursor.execute("""
                INSERT INTO toast_history
                (toast_id, toast_type, category, header, message, detail_message,
                 user_id, session_id, duration, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                toast_id,
                toast_type,
                category,
                header,
                message,
                detail_message,
                user_id,
                session_id,
                duration,
                json.dumps(metadata) if metadata else None
            ))

            conn.commit()
            return True

        except Exception as e:
            logger.error(f"Failed to save toast to history: {e}")
            return False

    @staticmethod
    def get_history(
        user_id: Optional[int] = None,
        category: Optional[str] = None,
        toast_type: Optional[str] = None,
        limit: int = 50,
        offset: int = 0
    ) -> List[Dict]:
        """Retrieve toast history from database"""
        try:
            db_manager = ToastHistoryManager.get_db_manager()
            if db_manager is None:
                return []

            conn = db_manager.conn
            cursor = conn.cursor()

            query = "SELECT * FROM toast_history WHERE 1=1"
            params = []

            if user_id is not None:
                query += " AND user_id = ?"
                params.append(user_id)

            if category:
                query += " AND category = ?"
                params.append(category)

            if toast_type:
                query += " AND toast_type = ?"
                params.append(toast_type)

            query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])

            cursor.execute(query, params)
            results = [dict(row) for row in cursor.fetchall()]

            return results

        except Exception as e:
            logger.error(f"Failed to retrieve toast history: {e}")
            return []

    @staticmethod
    def mark_dismissed(toast_id: str):
        """Mark toast as dismissed in history"""
        try:
            db_manager = ToastHistoryManager.get_db_manager()
            if db_manager is None:
                return False

            conn = db_manager.conn
            cursor = conn.cursor()

            cursor.execute("""
                UPDATE toast_history
                SET dismissed = 1, dismissed_at = CURRENT_TIMESTAMP
                WHERE toast_id = ?
            """, (toast_id,))

            conn.commit()
            return True

        except Exception as e:
            logger.error(f"Failed to mark toast as dismissed: {e}")
            return False

    @staticmethod
    def cleanup_old_history(days: int = 30):
        """Clean up old toast history"""
        try:
            db_manager = ToastHistoryManager.get_db_manager()
            if db_manager is None:
                return False

            conn = db_manager.conn
            cursor = conn.cursor()

            cursor.execute("""
                DELETE FROM toast_history
                WHERE timestamp < datetime('now', '-' || ? || ' days')
            """, (days,))

            deleted_count = cursor.rowcount
            conn.commit()

            logger.info(f"Cleaned up {deleted_count} old toast history records")
            return True

        except Exception as e:
            logger.error(f"Failed to cleanup toast history: {e}")
            return False


class ToastManager:
    """Factory for creating enhanced toast notifications with advanced features"""

    @staticmethod
    def create_toast(
        message: str,
        toast_type: str = "info",
        header: Optional[str] = None,
        duration: Any = "medium",
        custom_header: Optional[Any] = None,
        dismissable: bool = True,
        detail_message: Optional[str] = None,
        show_detail_button: bool = False,
        persistent: bool = False,
        category: str = "general",
        user_id: Optional[int] = None,
        session_id: Optional[str] = None,
        actions: Optional[List[Dict]] = None,
        save_to_history: bool = True,
        metadata: Optional[Dict] = None
    ):
        """
        Create a standardized toast notification with optional detail view

        Args:
            message: Toast body text (short summary)
            toast_type: 'success', 'error', 'danger', 'warning', 'info'
            header: Header text (auto-adds emoji if custom_header not provided)
            duration: 'short' (3s), 'medium' (4s), 'long' (5s), 'persistent' (no auto-dismiss), or int (ms)
            custom_header: Custom header component (overrides header)
            dismissable: Allow manual dismissal
            detail_message: Detailed message shown in modal when "View Details" clicked
            show_detail_button: Show "View Details" button (auto-enabled if detail_message provided)
            persistent: If True, toast will not auto-dismiss (overrides duration)
            category: Toast category (general/security/network/device/user/system/export/scan)
            user_id: User ID for history tracking
            session_id: Session ID for history tracking
            actions: List of action button dicts: [{"label": "Retry", "id": "retry-btn", "color": "primary"}]
            save_to_history: Whether to save this toast to history database
            metadata: Additional metadata to store with toast
        """
        # Normalize toast_type
        if toast_type == "error":
            toast_type = "danger"

        # Determine color (no icon - using category badges instead)
        color = toast_type

        # Auto-generate header with emoji if not custom
        if custom_header is None and header:
            emoji = TOAST_ICONS.get(toast_type, "")
            header = f"{emoji} {header}"
        elif custom_header:
            header = custom_header

        # Get duration value (persistent toasts have duration=0)
        if persistent:
            duration_ms = 0
        elif isinstance(duration, str):
            duration_ms = TOAST_DURATIONS.get(duration, 4000)
        else:
            duration_ms = duration

        # Auto-enable detail button if detail_message provided
        if detail_message and not show_detail_button:
            show_detail_button = True

        # Generate unique ID for this toast (for detail tracking)
        toast_id = str(uuid.uuid4())

        # Build toast body components
        body_components = []

        # Message text
        body_components.append(html.Div(message, className="mb-2"))

        # Add action buttons if provided
        if actions:
            action_buttons = []
            for action in actions:
                btn = dbc.Button(
                    action.get("label", "Action"),
                    id={"type": "toast-action-btn", "toast_id": toast_id, "action": action.get("id", "action")},
                    color=action.get("color", "primary"),
                    size="sm",
                    outline=action.get("outline", True),
                    className="me-2"
                )
                action_buttons.append(btn)

            body_components.append(
                html.Div(action_buttons, className="d-flex gap-2 mb-2 toast-action-buttons")
            )

        # Add detail button if needed
        if show_detail_button and detail_message:
            # Store detail message for modal retrieval
            toast_details_store[toast_id] = {
                "header": header,
                "message": message,
                "detail": detail_message,
                "type": toast_type,
                "category": category
            }

            body_components.append(
                html.Div([
                    dbc.Button(
                        [html.I(className="fas fa-info-circle me-1"), "View Details"],
                        id={"type": "toast-detail-btn", "toast_id": toast_id},
                        color="link",
                        size="sm",
                        className="p-0 text-decoration-none fw-bold toast-detail-button"
                    )
                ], className="d-flex justify-content-end")
            )

        # Build final toast body
        if len(body_components) == 1:
            toast_body = body_components[0]
        else:
            toast_body = html.Div(body_components)

        # Add category badge to header for ALL toasts (category labels replace colored icons)
        if category in TOAST_CATEGORIES:
            cat_info = TOAST_CATEGORIES[category]
            category_badge = html.Span(
                [
                    html.I(className=f"fas {cat_info['icon']} me-1"),
                    cat_info['name']
                ],
                className="badge me-2",
                style={"backgroundColor": cat_info['color'], "fontSize": "0.7em"}
            )

            if isinstance(header, str):
                header = html.Div([category_badge, header])

        # Save to history if enabled
        if save_to_history:
            ToastHistoryManager.save_to_history(
                toast_id=toast_id,
                toast_type=toast_type,
                category=category,
                header=str(header) if isinstance(header, str) else "Notification",
                message=message,
                detail_message=detail_message,
                user_id=user_id,
                session_id=session_id,
                duration=duration_ms,
                metadata=metadata
            )

        # Create toast with enhanced attributes (no icon - using category badges instead)
        toast = dbc.Toast(
            toast_body,
            id={"type": "enhanced-toast", "toast_id": toast_id, "category": category},
            header=header,
            color=color,
            duration=duration_ms,
            is_open=True,
            dismissable=dismissable,
            style=TOAST_POSITION_STYLE,
            className=f"enhanced-toast-notification toast-category-{category}" +
                      (" toast-persistent" if persistent else "")
        )

        return toast

    @staticmethod
    def success(message, header="Success", duration="medium", detail_message=None,
                persistent=False, category="general", **kwargs):
        """Quick success toast with optional details"""
        return ToastManager.create_toast(
            message,
            "success",
            header,
            duration,
            detail_message=detail_message,
            persistent=persistent,
            category=category,
            **kwargs
        )

    @staticmethod
    def error(message, header="Error", duration="long", detail_message=None,
              persistent=False, category="general", **kwargs):
        """Quick error toast with optional details (longer duration for errors)"""
        return ToastManager.create_toast(
            message,
            "error",
            header,
            duration,
            detail_message=detail_message,
            persistent=persistent,
            category=category,
            **kwargs
        )

    @staticmethod
    def warning(message, header="Warning", duration="medium", detail_message=None,
                persistent=False, category="general", **kwargs):
        """Quick warning toast with optional details"""
        return ToastManager.create_toast(
            message,
            "warning",
            header,
            duration,
            detail_message=detail_message,
            persistent=persistent,
            category=category,
            **kwargs
        )

    @staticmethod
    def info(message, header="Info", duration="long", detail_message=None,
             persistent=False, category="general", **kwargs):
        """Quick info toast with optional details"""
        return ToastManager.create_toast(
            message,
            "info",
            header,
            duration,
            detail_message=detail_message,
            persistent=persistent,
            category=category,
            **kwargs
        )

    @staticmethod
    def custom_header_toast(
        message,
        header_text,
        color_class,
        toast_type="info",
        duration="medium",
        detail_message=None,
        **kwargs
    ):
        """
        Create toast with custom colored square header

        Args:
            message: Toast body
            header_text: Header text
            color_class: Bootstrap color class (bg-success, bg-danger, etc.)
            toast_type: Toast type for body styling
            duration: Duration preset or ms value
            detail_message: Optional detailed message
        """
        custom_header = html.Div([
            html.Span(className=f"toast-color-square {color_class} me-2"),
            html.Strong(header_text)
        ], className="d-flex align-items-center")

        return ToastManager.create_toast(
            message,
            toast_type=toast_type,
            custom_header=custom_header,
            duration=duration,
            detail_message=detail_message,
            **kwargs
        )

    @staticmethod
    def get_detail(toast_id):
        """Retrieve stored detail message for a toast"""
        return toast_details_store.get(toast_id)

    @staticmethod
    def clear_detail(toast_id):
        """Remove a specific toast's details from the store."""
        if toast_id in toast_details_store:
            del toast_details_store[toast_id]

    @staticmethod
    def clear_details():
        """Clear old toast details from memory (call periodically to prevent memory leak)"""
        toast_details_store.clear()


# Helper function to create the toast detail modal (add this to app.py layout)
def create_toast_detail_modal():
    """
    Creates a modal for displaying detailed toast messages.
    Add this component to your app.py layout.
    """
    return dbc.Modal([
        dbc.ModalHeader(
            dbc.ModalTitle(id="toast-detail-modal-title"),
            close_button=True
        ),
        dbc.ModalBody([
            html.Div(id="toast-detail-modal-summary", className="mb-3"),
            html.Hr(),
            html.Div(id="toast-detail-modal-content", className="toast-detail-content")
        ]),
        dbc.ModalFooter([
            dbc.Button(
                "Close",
                id="toast-detail-modal-close",
                color="secondary",
                size="sm"
            )
        ])
    ], id="toast-detail-modal", size="lg", is_open=False, backdrop=True, keyboard=True)


def create_toast_history_panel():
    """
    Creates a sliding panel for toast history.
    Add this component to your app.py layout.
    """
    return html.Div([
        # Floating button to open history
        dbc.Button(
            [html.I(className="fas fa-history me-2"), "Toast History"],
            id="toast-history-toggle-btn",
            color="info",
            size="sm",
            className="toast-history-toggle-btn",
            style={
                "position": "fixed",
                "bottom": "20px",
                "right": "20px",
                "zIndex": 999998,
                "borderRadius": "25px",
                "boxShadow": "0 4px 6px rgba(0,0,0,0.3)"
            }
        ),

        # History panel (initially hidden)
        html.Div([
            # Header
            html.Div([
                html.H5("Toast History", className="mb-0"),
                dbc.Button(
                    html.I(className="fas fa-times"),
                    id="toast-history-close-btn",
                    color="link",
                    size="sm",
                    className="text-white"
                )
            ], className="d-flex justify-content-between align-items-center p-3 bg-primary text-white"),

            # Filters
            html.Div([
                dbc.Row([
                    dbc.Col([
                        dbc.Label("Category", size="sm"),
                        dbc.Select(
                            id="toast-history-category-filter",
                            options=[
                                {"label": "All Categories", "value": "all"},
                                *[{"label": v['name'], "value": k} for k, v in TOAST_CATEGORIES.items()]
                            ],
                            value="all",
                            size="sm"
                        )
                    ], width=6),
                    dbc.Col([
                        dbc.Label("Type", size="sm"),
                        dbc.Select(
                            id="toast-history-type-filter",
                            options=[
                                {"label": "All Types", "value": "all"},
                                {"label": "Success", "value": "success"},
                                {"label": "Error", "value": "danger"},
                                {"label": "Warning", "value": "warning"},
                                {"label": "Info", "value": "info"}
                            ],
                            value="all",
                            size="sm"
                        )
                    ], width=6)
                ], className="mb-2"),
                dbc.Button(
                    [html.I(className="fas fa-trash me-2"), "Clear All"],
                    id="toast-history-clear-btn",
                    color="danger",
                    size="sm",
                    outline=True,
                    className="w-100"
                )
            ], className="p-3 border-bottom"),

            # History list
            html.Div(
                id="toast-history-list",
                className="toast-history-list p-3",
                style={"maxHeight": "calc(100vh - 250px)", "overflowY": "auto"}
            )
        ],
        id="toast-history-panel",
        className="toast-history-panel",
        style={
            "position": "fixed",
            "top": 0,
            "right": "-400px",  # Hidden by default
            "width": "400px",
            "height": "100vh",
            "backgroundColor": "white",
            "boxShadow": "-2px 0 10px rgba(0,0,0,0.3)",
            "zIndex": 999999,
            "transition": "right 0.3s ease-in-out"
        })
    ], id="toast-history-container")


# Export constants for use in static toast declarations
__all__ = [
    'ToastManager',
    'ToastHistoryManager',
    'TOAST_POSITION_STYLE',
    'TOAST_DURATIONS',
    'TOAST_ICONS',
    'TOAST_CATEGORIES',
    'create_toast_detail_modal',
    'create_toast_history_panel'
]
