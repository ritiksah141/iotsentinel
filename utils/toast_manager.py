"""
Enhanced Toast Notification Management System
Provides consistent, visible, and interactive toast notifications
"""
import dash_bootstrap_components as dbc
from dash import html
import uuid

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
    "long": 5000      # 5 seconds for important messages
}

TOAST_ICONS = {
    "success": "✅",
    "error": "❌",
    "warning": "⚠️",
    "info": "ℹ️"
}

# Store for toast details (for detail modal)
toast_details_store = {}

class ToastManager:
    """Factory for creating enhanced toast notifications with detail view support"""

    @staticmethod
    def create_toast(
        message,
        toast_type="info",
        header=None,
        duration="medium",
        custom_header=None,
        dismissable=True,
        detail_message=None,
        show_detail_button=False
    ):
        """
        Create a standardized toast notification with optional detail view

        Args:
            message: Toast body text (short summary)
            toast_type: 'success', 'error', 'danger', 'warning', 'info'
            header: Header text (auto-adds emoji if custom_header not provided)
            duration: 'short' (3s), 'medium' (4s), 'long' (5s) or int (ms)
            custom_header: Custom header component (overrides header)
            dismissable: Allow manual dismissal
            detail_message: Detailed message shown in modal when "View Details" clicked
            show_detail_button: Show "View Details" button (auto-enabled if detail_message provided)
        """
        # Normalize toast_type
        if toast_type == "error":
            toast_type = "danger"

        # Determine icon and color
        icon_map = {
            "success": "success",
            "danger": "danger",
            "warning": "warning",
            "info": "info"
        }
        icon = icon_map.get(toast_type, "info")
        color = toast_type

        # Auto-generate header with emoji if not custom
        if custom_header is None and header:
            emoji = TOAST_ICONS.get(toast_type, "")
            header = f"{emoji} {header}"
        elif custom_header:
            header = custom_header

        # Get duration value
        if isinstance(duration, str):
            duration_ms = TOAST_DURATIONS.get(duration, 4000)
        else:
            duration_ms = duration

        # Auto-enable detail button if detail_message provided
        if detail_message and not show_detail_button:
            show_detail_button = True

        # Generate unique ID for this toast (for detail tracking)
        toast_id = str(uuid.uuid4())

        # Build toast body with optional detail button
        if show_detail_button and detail_message:
            # Store detail message for modal retrieval
            toast_details_store[toast_id] = {
                "header": header,
                "message": message,
                "detail": detail_message,
                "type": toast_type
            }

            toast_body = html.Div([
                html.Div(message, className="mb-2"),
                html.Div([
                    dbc.Button(
                        [html.I(className="fas fa-info-circle me-1"), "View Details"],
                        id={"type": "toast-detail-btn", "toast_id": toast_id},
                        color="link",
                        size="sm",
                        className="p-0 text-decoration-none fw-bold toast-detail-button"
                    )
                ], className="d-flex justify-content-end")
            ])
        else:
            toast_body = message

        return dbc.Toast(
            toast_body,
            id={"type": "enhanced-toast", "toast_id": toast_id},
            header=header,
            icon=icon,
            color=color,
            duration=duration_ms,
            is_open=True,
            dismissable=dismissable,
            style=TOAST_POSITION_STYLE,
            className="enhanced-toast-notification"  # Custom class for brighter styling
        )

    @staticmethod
    def success(message, header="Success", duration="medium", detail_message=None):
        """Quick success toast with optional details"""
        return ToastManager.create_toast(
            message,
            "success",
            header,
            duration,
            detail_message=detail_message
        )

    @staticmethod
    def error(message, header="Error", duration="long", detail_message=None):
        """Quick error toast with optional details (longer duration for errors)"""
        return ToastManager.create_toast(
            message,
            "error",
            header,
            duration,
            detail_message=detail_message
        )

    @staticmethod
    def warning(message, header="Warning", duration="medium", detail_message=None):
        """Quick warning toast with optional details"""
        return ToastManager.create_toast(
            message,
            "warning",
            header,
            duration,
            detail_message=detail_message
        )

    @staticmethod
    def info(message, header="Info", duration="long", detail_message=None):
        """Quick info toast with optional details"""
        return ToastManager.create_toast(
            message,
            "info",
            header,
            duration,
            detail_message=detail_message
        )

    @staticmethod
    def custom_header_toast(
        message,
        header_text,
        color_class,
        toast_type="info",
        duration="medium",
        detail_message=None
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
            detail_message=detail_message
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


# Export constants for use in static toast declarations
__all__ = [
    'ToastManager',
    'TOAST_POSITION_STYLE',
    'TOAST_DURATIONS',
    'TOAST_ICONS',
    'create_toast_detail_modal'
]
