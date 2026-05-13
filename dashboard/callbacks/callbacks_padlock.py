"""
Phase 3 — Padlock overlays for API-gated feature cards.

Two cards in the Integrations tab are gated:
  - 'email'   → requires email_smtp SMTP credentials
  - 'api-hub' → requires at least one threat-intel API key

When credentials are absent the overlay is shown (display:flex).
Clicking the overlay either opens the existing full-config modal (email)
or a lightweight unlock modal (api-hub / AbuseIPDB).
"""

import logging

from dash import ALL, Input, Output, State, ctx, no_update

from dashboard.shared import db_manager
from alerts.integration_system import IntegrationManager

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Style helpers
# ---------------------------------------------------------------------------

_LOCKED_STYLE = {
    "display": "flex",
    "position": "absolute",
    "top": 0, "left": 0, "right": 0, "bottom": 0,
    "background": "rgba(15, 23, 42, 0.75)",
    "backdropFilter": "blur(2px)",
    "color": "rgba(255, 255, 255, 0.9)",
    "flexDirection": "column",
    "alignItems": "center",
    "justifyContent": "center",
    "cursor": "pointer",
    "borderRadius": "0.5rem",
    "zIndex": 10,
}
_UNLOCKED_STYLE = {"display": "none"}

# ---------------------------------------------------------------------------
# Module-level credential helpers (testable via patch)
# ---------------------------------------------------------------------------

def _is_email_configured() -> bool:
    try:
        mgr = IntegrationManager(db_manager)
        creds = mgr.get_integration_credentials('email_smtp')
        return bool(creds and creds.get('smtp_server'))
    except Exception:
        return False


def _is_threat_intel_configured() -> bool:
    """Returns True if at least one threat-intel integration has an API key."""
    try:
        mgr = IntegrationManager(db_manager)
        for key in ('abuseipdb', 'virustotal', 'alienvault_otx'):
            creds = mgr.get_integration_credentials(key)
            if creds and creds.get('api_key'):
                return True
        return False
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Module-level callback implementations (testable directly)
# ---------------------------------------------------------------------------

def _save_api_key_impl(n_clicks, api_key, current_trigger):
    """
    Persist the AbuseIPDB API key and close the unlock modal.

    Returns (modal_is_open, refresh_trigger, feedback_text).
    """
    if not n_clicks:
        return no_update, no_update, no_update
    if not api_key or not api_key.strip():
        return no_update, no_update, "Please enter an API key."
    try:
        mgr = IntegrationManager(db_manager)
        success = mgr.configure_integration(
            "abuseipdb", api_key=api_key.strip(), enabled=True
        )
        if success:
            return False, (current_trigger or 0) + 1, ""
        return no_update, no_update, "Could not save the key — please try again."
    except Exception as e:
        logger.error(f"Padlock save error: {e}")
        return no_update, no_update, f"Error: {e}"


# ---------------------------------------------------------------------------
# Callback registration
# ---------------------------------------------------------------------------

def register(app):

    # -- 1. Update overlay visibility whenever the page loads or a key is saved --
    @app.callback(
        Output({"type": "padlock-overlay", "feature": "email"}, "style"),
        Output({"type": "padlock-overlay", "feature": "api-hub"}, "style"),
        Input("url", "pathname"),
        Input("padlock-refresh-trigger", "data"),
    )
    def update_lock_states(_pathname, _trigger):
        email_style = _UNLOCKED_STYLE if _is_email_configured() else _LOCKED_STYLE
        apihub_style = _UNLOCKED_STYLE if _is_threat_intel_configured() else _LOCKED_STYLE
        return email_style, apihub_style

    # -- 2. Route overlay clicks to the right modal --
    @app.callback(
        Output("email-modal", "is_open"),
        Output("unlock-padlock-modal", "is_open"),
        Input({"type": "padlock-overlay", "feature": ALL}, "n_clicks"),
        State("email-modal", "is_open"),
        prevent_initial_call=True,
    )
    def handle_padlock_click(n_clicks_list, email_modal_open):
        if not ctx.triggered_id or not any(n_clicks_list):
            return no_update, no_update

        feature = (
            ctx.triggered_id.get("feature")
            if isinstance(ctx.triggered_id, dict)
            else None
        )

        if feature == "email":
            return True, False
        if feature == "api-hub":
            return no_update, True

        return no_update, no_update

    # -- 3. Save the AbuseIPDB API key from the unlock modal --
    @app.callback(
        Output("unlock-padlock-modal", "is_open", allow_duplicate=True),
        Output("padlock-refresh-trigger", "data"),
        Output("unlock-api-key-feedback", "children"),
        Input("unlock-save-btn", "n_clicks"),
        State("unlock-api-key-input", "value"),
        State("padlock-refresh-trigger", "data"),
        prevent_initial_call=True,
    )
    def save_api_key(n_clicks, api_key, current_trigger):
        return _save_api_key_impl(n_clicks, api_key, current_trigger)

    # -- 4. Cancel button closes the unlock modal --
    @app.callback(
        Output("unlock-padlock-modal", "is_open", allow_duplicate=True),
        Input("unlock-cancel-btn", "n_clicks"),
        prevent_initial_call=True,
    )
    def close_unlock_modal(n_clicks):
        if not n_clicks:
            return no_update
        return False
