"""
Setup Wizard Callbacks
======================
Handles step navigation, optional API-key validation, and final .env write
for the first-run setup wizard (/setup route).
"""
import logging
import os
from pathlib import Path

import dash
import requests
from dash import ALL, Input, Output, State, callback_context, html
import dash_bootstrap_components as dbc

from dashboard.shared import config

logger = logging.getLogger(__name__)

_ENV_PATH = Path(__file__).parent.parent.parent / '.env'


def _validate_groq(api_key: str) -> tuple[bool, str]:
    """Ping Groq models endpoint to confirm key is valid."""
    if not api_key or len(api_key) < 20:
        return False, "Key looks too short — check you copied all characters."
    try:
        r = requests.get(
            "https://api.groq.com/openai/v1/models",
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=5,
        )
        if r.status_code == 200:
            return True, "✓ Key verified!"
        return False, f"That key didn't work (status {r.status_code}). Check it and try again."
    except Exception:
        return False, "Could not reach Groq — check your internet connection."


def _validate_abuseipdb(api_key: str) -> tuple[bool, str]:
    """Ping AbuseIPDB check endpoint with a known safe IP."""
    if not api_key or len(api_key) < 20:
        return False, "Key looks too short — check you copied all characters."
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": "1.1.1.1", "maxAgeInDays": 90},
            headers={"Key": api_key, "Accept": "application/json"},
            timeout=5,
        )
        if r.status_code == 200:
            return True, "✓ Key verified!"
        return False, f"That key didn't work (status {r.status_code}). Check it and try again."
    except Exception:
        return False, "Could not reach AbuseIPDB — check your internet connection."


def register(app):
    """Register all setup wizard callbacks."""

    # ------------------------------------------------------------------
    # Step navigation + progress bar
    # ------------------------------------------------------------------
    @app.callback(
        [
            Output("setup-step-store", "data"),
            Output("setup-step-1-container", "style"),
            Output("setup-step-2-container", "style"),
            Output("setup-step-3-container", "style"),
            Output("setup-back-btn", "style"),
            Output("setup-next-btn", "children"),
            Output("setup-next-btn", "color"),
            Output("setup-progress", "value"),
            Output("setup-review-content", "children"),
            Output("setup-status", "children"),
        ],
        [
            Input("setup-next-btn", "n_clicks"),
            Input("setup-back-btn", "n_clicks"),
            Input("setup-skip-btn", "n_clicks"),
        ],
        [
            State("setup-step-store", "data"),
            State("setup-network-cidr", "value"),
            State("setup-interface", "value"),
            State("setup-admin-password", "value"),
            State("setup-admin-password-confirm", "value"),
            State("setup-smtp-user", "value"),
            State("setup-smtp-password", "value"),
            State("setup-groq-key", "value"),
            State("setup-abuseipdb-key", "value"),
        ],
        prevent_initial_call=True,
    )
    def navigate_steps(
        next_clicks, back_clicks, skip_clicks,
        step_data,
        cidr, interface, password, password_confirm,
        smtp_user, smtp_password, groq_key, abuseipdb_key,
    ):
        show = {"display": "block"}
        hide = {"display": "none"}
        back_hide = {"display": "none"}
        back_show = {"display": "block"}

        triggered = callback_context.triggered_id
        current_step = (step_data or {}).get("step", 1)
        status_msg = dash.no_update

        if triggered == "setup-skip-btn":
            # Write minimal .env with just the network settings and redirect
            _save_config(cidr, interface, None, None, None, None, None, None)
            return (
                {"step": 3}, hide, hide, show, back_show,
                "Launch IoTSentinel →", "success", 100,
                _build_review(cidr, interface, None, None, None),
                dash.no_update,
            )

        if triggered == "setup-next-btn":
            if current_step == 1:
                if password and password != password_confirm:
                    return (
                        step_data, show, hide, hide, back_hide,
                        "Next →", "primary", 33,
                        dash.no_update,
                        dbc.Alert("Passwords do not match.", color="danger", dismissable=True),
                    )
                return (
                    {"step": 2}, hide, show, hide, back_show,
                    "Next →", "primary", 66,
                    dash.no_update, dash.no_update,
                )
            elif current_step == 2:
                return (
                    {"step": 3}, hide, hide, show, back_show,
                    "Launch IoTSentinel →", "success", 100,
                    _build_review(cidr, interface, smtp_user, groq_key, abuseipdb_key),
                    dash.no_update,
                )
            elif current_step == 3:
                # Final save
                admin_pw = password or "admin"
                success = _save_config(
                    cidr, interface, admin_pw,
                    smtp_user, smtp_password, groq_key, abuseipdb_key, password,
                )
                if success:
                    return (
                        {"step": 3}, hide, hide, show, back_show,
                        "Launch IoTSentinel →", "success", 100,
                        dash.no_update,
                        dbc.Alert(
                            [
                                html.Strong("Setup complete! "),
                                "Redirecting to login…",
                            ],
                            color="success", className="mt-2"
                        ),
                    )
                return (
                    step_data, hide, hide, show, back_show,
                    "Launch IoTSentinel →", "success", 100,
                    dash.no_update,
                    dbc.Alert("Setup failed — check the logs.", color="danger"),
                )

        if triggered == "setup-back-btn":
            if current_step == 2:
                return (
                    {"step": 1}, show, hide, hide, back_hide,
                    "Next →", "primary", 33,
                    dash.no_update, dash.no_update,
                )
            elif current_step == 3:
                return (
                    {"step": 2}, hide, show, hide, back_show,
                    "Next →", "primary", 66,
                    dash.no_update, dash.no_update,
                )

        raise dash.exceptions.PreventUpdate

    # ------------------------------------------------------------------
    # Live Groq key validation
    # ------------------------------------------------------------------
    @app.callback(
        Output("setup-groq-feedback", "children"),
        Input("setup-groq-key", "value"),
        prevent_initial_call=True,
    )
    def validate_groq_key(api_key):
        if not api_key:
            return ""
        ok, msg = _validate_groq(api_key)
        return html.Span(msg, className="text-success" if ok else "text-danger")

    # ------------------------------------------------------------------
    # Live AbuseIPDB key validation
    # ------------------------------------------------------------------
    @app.callback(
        Output("setup-abuseipdb-feedback", "children"),
        Input("setup-abuseipdb-key", "value"),
        prevent_initial_call=True,
    )
    def validate_abuseipdb_key(api_key):
        if not api_key:
            return ""
        ok, msg = _validate_abuseipdb(api_key)
        return html.Span(msg, className="text-success" if ok else "text-danger")

    # ------------------------------------------------------------------
    # Gmail GIF toggle
    # ------------------------------------------------------------------
    @app.callback(
        Output("setup-gmail-gif-collapse", "is_open"),
        Input("setup-gmail-gif-btn", "n_clicks"),
        State("setup-gmail-gif-collapse", "is_open"),
        prevent_initial_call=True,
    )
    def toggle_gmail_gif(n_clicks, is_open):
        return not is_open

    # ------------------------------------------------------------------
    # Redirect to /login after successful save (via URL)
    # ------------------------------------------------------------------
    @app.callback(
        Output("setup-url", "href"),
        Input("setup-status", "children"),
        prevent_initial_call=True,
    )
    def redirect_after_setup(status_children):
        if not status_children:
            raise dash.exceptions.PreventUpdate
        # Check if the alert says "Setup complete"
        try:
            if isinstance(status_children, dict):
                props = status_children.get("props", {})
                children = props.get("children", [])
                for child in children:
                    if isinstance(child, dict) and "Setup complete" in str(child):
                        return "/login"
            text = str(status_children)
            if "Setup complete" in text:
                return "/login"
        except Exception:
            pass
        raise dash.exceptions.PreventUpdate


def _build_review(cidr, interface, smtp_user, groq_key, abuseipdb_key):
    """Build the review summary shown on step 3."""
    rows = [
        ("Network CIDR", cidr or "192.168.1.0/24"),
        ("Interface", interface or "wlan0"),
        ("Email alerts", smtp_user if smtp_user else "Not configured (can add later)"),
        ("AI explanations", "Enabled ✓" if groq_key else "Not configured (can add later)"),
        ("Threat intel", "Enabled ✓" if abuseipdb_key else "Not configured (can add later)"),
    ]
    return dbc.Table(
        [html.Tbody([
            html.Tr([html.Td(k, className="fw-semibold text-muted small", style={"width": "45%"}),
                     html.Td(v, className="small")])
            for k, v in rows
        ])],
        bordered=False, size="sm", className="mb-0"
    )


def _save_config(
    cidr, interface, admin_password,
    smtp_user, smtp_password, groq_key, abuseipdb_key, raw_password,
) -> bool:
    """Write .env and update default_config.json, mark is_configured=true."""
    try:
        env_vars = {}

        # Network config (stored in JSON, not .env)
        config.update("network", "local_networks", [cidr or "192.168.1.0/24"])
        config.update("network", "interface", interface or "wlan0")

        # Admin password goes to env
        if admin_password:
            env_vars["IOTSENTINEL_ADMIN_PASSWORD"] = admin_password

        # Email
        if smtp_user and smtp_password:
            env_vars["EMAIL_SMTP_HOST"] = "smtp.gmail.com"
            env_vars["EMAIL_SMTP_PORT"] = "587"
            env_vars["EMAIL_SMTP_USER"] = smtp_user
            env_vars["EMAIL_SMTP_PASSWORD"] = smtp_password
            env_vars["EMAIL_SENDER_EMAIL"] = smtp_user
            env_vars["EMAIL_RECIPIENT_EMAIL"] = smtp_user

        # AI assistant
        if groq_key:
            env_vars["GROQ_API_KEY"] = groq_key

        # Threat intel
        if abuseipdb_key:
            env_vars["THREAT_INTELLIGENCE_ABUSEIPDB_API_KEY"] = abuseipdb_key

        if env_vars:
            config.write_env(env_vars)

        config.update("system", "is_configured", True)
        return True

    except Exception as e:
        logger.error(f"Setup save failed: {e}")
        return False
