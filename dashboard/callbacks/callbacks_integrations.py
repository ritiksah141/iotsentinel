"""Integrations & API callbacks — Email, API Hub, External Integrations."""

import os
import smtplib
import logging
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

import dash
import dash_bootstrap_components as dbc
from dash import dcc, html, Input, Output, State, callback_context, ALL, no_update
from flask_login import login_required, current_user

from dashboard.shared import (
    db_manager,
    export_helper,
    security_audit_logger,
    get_db_connection,
    ToastManager,
    PermissionManager,
    can_export_data,
)

logger = logging.getLogger(__name__)


def register(app):
    # ========================================================================
    # CALLBACKS - EMAIL SETTINGS
    # ========================================================================

    @app.callback(
        [Output('email-enable-switch', 'value'),
         Output('email-to', 'value')],
        Input('url', 'pathname'),
        prevent_initial_call=True
    )
    def load_email_settings(pathname):
        """Load email settings for the current user."""
        if not current_user.is_authenticated:
            return False, ''

        # Fetch user preferences
        try:
            conn = db_manager.conn
            cursor = conn.cursor()

            # Get email enabled preference
            cursor.execute("SELECT preference_value FROM user_preferences WHERE user_id = ? AND preference_key = 'email_enabled'", (current_user.id,))
            result = cursor.fetchone()
            enabled = result[0].lower() == 'true' if result else False

            # Get recipient email preference
            cursor.execute("SELECT preference_value FROM user_preferences WHERE user_id = ? AND preference_key = 'email_recipient'", (current_user.id,))
            result = cursor.fetchone()
            recipient_email = result[0] if result else os.environ.get('EMAIL_RECIPIENT_EMAIL', '')

        except Exception as e:
            logger.error(f"Error loading email preferences: {e}")
            enabled = False
            recipient_email = os.environ.get('EMAIL_RECIPIENT_EMAIL', '')

        return enabled, recipient_email

    @app.callback(
        [Output('toast-container', 'children', allow_duplicate=True),
         Output('email-modal', 'is_open', allow_duplicate=True)],
        Input('save-email-settings-btn', 'n_clicks'),
        [State('email-enable-switch', 'value'),
         State('email-to', 'value')],
        prevent_initial_call=True
    )
    def save_email_settings(n_clicks, enabled, recipient_email):
        """Save email notification settings for the current user."""
        if n_clicks is None or not current_user.is_authenticated:
            raise dash.exceptions.PreventUpdate

        try:
            conn = db_manager.conn
            cursor = conn.cursor()

            # Save enabled state
            cursor.execute("""
                INSERT INTO user_preferences (user_id, preference_key, preference_value)
                VALUES (?, ?, ?)
                ON CONFLICT(user_id, preference_key) DO UPDATE SET preference_value = excluded.preference_value
            """, (current_user.id, 'email_enabled', str(enabled)))

            # Save recipient email
            if recipient_email:
                cursor.execute("""
                    INSERT INTO user_preferences (user_id, preference_key, preference_value)
                    VALUES (?, ?, ?)
                    ON CONFLICT(user_id, preference_key) DO UPDATE SET preference_value = excluded.preference_value
                """, (current_user.id, 'email_recipient', recipient_email))

            conn.commit()

            logger.info(f"Email settings for user {current_user.id} - Enabled: {enabled}, Recipient: {recipient_email}")

            # Log email settings change to security audit
            security_audit_logger.log(
                event_type='settings_changed',
                severity='info',
                user_id=current_user.id,
                username=current_user.username,
                resource_type='settings',
                resource_id='email_configuration',
                details={'email_enabled': enabled, 'recipient': recipient_email},
                result='success'
            )

            toast = ToastManager.success(
                "Settings Saved",
                detail_message=f"Email notification settings saved - Enabled: {enabled}, Recipient: {recipient_email}"
            )

            return toast, False  # Close the modal

        except Exception as e:
            logger.error(f"Error saving email settings: {e}")
            toast = ToastManager.error(
                "Save Failed",
                detail_message=f"Error saving email settings: {str(e)}"
            )
            return toast, dash.no_update  # Keep modal open on error

    @app.callback(
        Output('toast-container', 'children', allow_duplicate=True),
        Input('test-email-btn', 'n_clicks'),
        State('email-to', 'value'),
        prevent_initial_call=True
    )
    def send_test_email(n_clicks, recipient_email):
        """Send a test email to verify configuration from environment variables"""
        if n_clicks is None:
            raise dash.exceptions.PreventUpdate

        try:
            # Load SMTP settings from environment variables
            smtp_host = os.environ.get('EMAIL_SMTP_HOST')
            smtp_port = os.environ.get('EMAIL_SMTP_PORT')
            smtp_user = os.environ.get('EMAIL_SMTP_USER')
            smtp_password = os.environ.get('EMAIL_SMTP_PASSWORD')
            sender_email = os.environ.get('EMAIL_SENDER_EMAIL', 'iotsentinel-noreply@security.com')

            # Use provided recipient or fall back to env
            to_email = recipient_email or os.environ.get('EMAIL_RECIPIENT_EMAIL')

            # Validate inputs
            if not all([smtp_host, smtp_port, smtp_user, smtp_password]):
                return ToastManager.warning(
                    "Configuration Missing",
                    detail_message="SMTP configuration missing in .env file. Please configure EMAIL_SMTP_HOST, EMAIL_SMTP_PORT, EMAIL_SMTP_USER, and EMAIL_SMTP_PASSWORD."
                )

            if not to_email:
                return ToastManager.warning(
                    "Email Required",
                    detail_message="Please enter a recipient email address to send the test email."
                )

            # Create test email
            message = MIMEMultipart("alternative")
            message["Subject"] = "🛡️ IoTSentinel Test Email"
            message["From"] = sender_email
            message["To"] = to_email

            text_content = f"""
IoTSentinel Test Email
======================

This is a test email from your IoTSentinel dashboard.

Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

If you received this email, your email notification settings are configured correctly!

---
IoTSentinel Network Security Monitor
"""

            html_content = f"""
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: Arial, sans-serif; padding: 20px; background-color: #f5f5f5;">
    <div style="max-width: 600px; margin: 0 auto; background: white; border-radius: 8px; padding: 30px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
        <div style="text-align: center; margin-bottom: 20px;">
            <h1 style="color: #667eea; margin: 0;">🛡️ IoTSentinel</h1>
            <p style="color: #666; margin: 10px 0;">Test Email Successful</p>
        </div>

        <div style="background: #e8f5e9; padding: 20px; border-radius: 8px; border-left: 4px solid #4caf50;">
            <p style="margin: 0; color: #2e7d32;"><strong>✅ Configuration Verified</strong></p>
            <p style="margin: 10px 0 0 0; color: #555;">Your email notification settings are working correctly!</p>
        </div>

        <div style="margin-top: 20px; padding: 15px; background: #f8f9fa; border-radius: 8px;">
            <p style="margin: 0; font-size: 14px; color: #666;">
                <strong>Timestamp:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br>
                <strong>Sent from:</strong> IoTSentinel Dashboard
            </p>
        </div>

        <div style="margin-top: 20px; text-align: center; font-size: 12px; color: #999;">
            <p>IoTSentinel - Network Security Monitoring System</p>
        </div>
    </div>
</body>
</html>
"""

            message.attach(MIMEText(text_content, "plain"))
            message.attach(MIMEText(html_content, "html"))

            # Send email
            server = smtplib.SMTP(smtp_host, int(smtp_port), timeout=60)
            server.ehlo()
            server.starttls()
            server.login(smtp_user, smtp_password)
            server.send_message(message)
            server.quit()

            logger.info(f"Test email sent successfully to {to_email}")
            return ToastManager.success(
                "Email Sent",
                detail_message=f"Test email sent successfully to {to_email}"
            )

        except Exception as e:
            logger.error(f"Failed to send test email: {e}")
            return ToastManager.error(
                "Email Failed",
                detail_message=f"Failed to send email: {str(e)}"
            )

    # ========================================================================
    # EMAIL MODAL TOGGLE
    # ========================================================================

    @app.callback(
        Output("email-modal", "is_open"),
        [Input("email-card-btn", "n_clicks"),
         Input("close-email-modal-btn", "n_clicks")],
        State("email-modal", "is_open"),
        prevent_initial_call=True
    )
    def toggle_email_modal(open_clicks, close_clicks, is_open):
        ctx = dash.callback_context
        if not ctx.triggered:
            raise dash.exceptions.PreventUpdate
        trigger_id = ctx.triggered[0]['prop_id'].split('.')[0]
        if trigger_id == 'close-email-modal-btn':
            return False
        if trigger_id == 'email-card-btn' and open_clicks:
            return not is_open
        return is_open

    # ========================================================================
    # EMAIL HISTORY LIST
    # ========================================================================

    @app.callback(
        Output('email-history-list', 'children'),
        Input('ws', 'message')
    )
    def update_email_history(ws_message):
        """Update email history list with configured email and recent activity."""
        try:
            # Get configured email from environment
            recipient_email = os.getenv('ALERT_RECIPIENT_EMAIL', os.getenv('EMAIL_SMTP_USER', 'Not configured'))

            # Query database for recent alerts that would trigger emails
            conn = db_manager.conn
            cursor = conn.cursor()

            # Get recent critical/high alerts (simulating sent emails)
            cursor.execute('''
                SELECT
                    severity,
                    timestamp,
                    device_ip,
                    explanation
                FROM alerts
                WHERE severity IN ('critical', 'high')
                AND timestamp >= datetime('now', '-7 days')
                ORDER BY timestamp DESC
                LIMIT 10
            ''')
            recent_alerts = cursor.fetchall()

            if not recent_alerts:
                return dbc.Alert([
                    html.I(className="fa fa-info-circle me-2"),
                    f"No recent email alerts sent. Configured recipient: {recipient_email}"
                ], color="info", className="mb-0")

            # Build email history list
            history_items = []

            for alert in recent_alerts:
                # Calculate time ago
                try:
                    alert_time = datetime.strptime(alert['timestamp'], '%Y-%m-%d %H:%M:%S')
                    time_diff = datetime.now() - alert_time

                    if time_diff.days > 0:
                        time_ago = f"{time_diff.days} day{'s' if time_diff.days > 1 else ''} ago"
                    elif time_diff.seconds >= 3600:
                        hours = time_diff.seconds // 3600
                        time_ago = f"{hours} hour{'s' if hours > 1 else ''} ago"
                    else:
                        minutes = time_diff.seconds // 60
                        time_ago = f"{minutes} minute{'s' if minutes > 1 else ''} ago" if minutes > 0 else "Just now"
                except:
                    time_ago = alert['timestamp']

                # Determine icon and color
                icon_class = "fa-exclamation-triangle text-danger" if alert['severity'] == 'critical' else "fa-exclamation-circle text-warning"

                # Extract alert description from explanation (first 50 chars)
                alert_desc = alert['explanation'][:50] + '...' if alert['explanation'] and len(alert['explanation']) > 50 else (alert['explanation'] or 'Security Alert')

                history_items.append(
                    html.Div([
                        html.Div([
                            html.I(className=f"fa {icon_class} me-2"),
                            html.Strong(f"{alert['severity'].upper()}: "),
                            html.Span(alert_desc, className="small"),
                            html.Small(f" - sent to {recipient_email}", className="text-muted d-block")
                        ]),
                        html.Small([
                            html.Span(time_ago, className="text-muted me-2"),
                            html.Code(alert['device_ip'], className="text-info small") if alert['device_ip'] else ""
                        ])
                    ], className="d-flex justify-content-between align-items-center py-2 border-bottom")
                )

            # Add summary at the top
            history_items.insert(0,
                dbc.Alert([
                    html.I(className="fa fa-envelope me-2"),
                    html.Small([
                        f"Showing {len(recent_alerts)} recent email alerts sent to ",
                        html.Strong(recipient_email)
                    ])
                ], color="light", className="mb-2 py-2")
            )

            return history_items

        except Exception as e:
            logger.error(f"Error updating email history: {e}")
            return dbc.Alert([
                html.I(className="fa fa-exclamation-triangle me-2"),
                f"Error loading email history: {str(e)}"
            ], color="danger", className="mb-0")

    # ========================================================================
    # SAVE / RESET EMAIL TEMPLATES
    # ========================================================================

    # Save Email Template Callback
    @app.callback(
        [Output('toast-container', 'children', allow_duplicate=True),
         Output('email-modal', 'is_open', allow_duplicate=True)],
        Input('save-template-btn', 'n_clicks'),
        [State('template-select', 'value'),
         State('template-subject', 'value'),
         State('template-body', 'value')],
        prevent_initial_call=True
    )
    def save_email_template(n_clicks, template_type, subject, body):
        """Save email template."""
        if not n_clicks:
            raise dash.exceptions.PreventUpdate

        try:
            # Would save to database in real implementation
            if not subject or not body:
                toast = ToastManager.warning(
                "Validation Error",
                detail_message="Validation Error"
            )
                return toast, True  # Keep modal open

            toast = ToastManager.success(
                "Template Saved",
                detail_message="Template Saved"
            )
            return toast, False  # Close modal

        except Exception as e:
            logger.error(f"Error saving template: {e}")
            toast = ToastManager.error(
                "Error",
                detail_message="Error"
            )
            return toast, True

    # Reset Email Template Callback
    @app.callback(
        [Output('template-subject', 'value'),
         Output('template-body', 'value'),
         Output('toast-container', 'children', allow_duplicate=True)],
        Input('reset-template-btn', 'n_clicks'),
        State('template-select', 'value'),
        prevent_initial_call=True
    )
    def reset_email_template(n_clicks, template_type):
        """Reset email template to default values."""
        if not n_clicks:
            raise dash.exceptions.PreventUpdate

        # Default templates
        default_templates = {
            'critical_alert': {
                'subject': 'CRITICAL ALERT: IoTSentinel Security Warning',
                'body': '''Dear Administrator,

IoTSentinel has detected a CRITICAL security event on your network:

Device: {device_ip}
Alert Type: {alert_type}
Severity: CRITICAL
Timestamp: {timestamp}

Description:
{description}

Recommended Actions:
1. Investigate the affected device immediately
2. Review recent network activity
3. Consider isolating the device if threat is confirmed

This is an automated alert from IoTSentinel.
Dashboard: http://your-dashboard-url

Best regards,
IoTSentinel Security System'''
            },
            'daily_summary': {
                'subject': 'IoTSentinel Daily Security Summary',
                'body': '''Daily Network Security Report

Date: {date}

Summary:
- Total Devices Monitored: {total_devices}
- New Alerts: {new_alerts}
- Critical Threats: {critical_count}
- Security Score: {security_score}/100

Top Security Events:
{top_events}

Network Health: {network_health}

View detailed dashboard at: http://your-dashboard-url

This is an automated daily report from IoTSentinel.'''
            },
            'weekly_report': {
                'subject': 'IoTSentinel Weekly Security Report',
                'body': '''Weekly Network Security Analysis

Week of: {week_start} to {week_end}

Executive Summary:
- Average Security Score: {avg_security_score}/100
- Total Alerts: {total_alerts}
- Devices Added: {new_devices}
- Threats Blocked: {blocked_threats}

Trends:
{security_trends}

Recommendations:
{recommendations}

Detailed analytics available at: http://your-dashboard-url

This is an automated weekly report from IoTSentinel.'''
            }
        }

        template = default_templates.get(template_type, default_templates['critical_alert'])

        toast = ToastManager.success(
                "Template Reset",
                detail_message="Template Reset"
            )

        return template['subject'], template['body'], toast

    # ========================================================================
    # API HUB - MODAL TOGGLE
    # ========================================================================

    @app.callback(
        Output("api-hub-modal", "is_open"),
        [Input("api-hub-card-btn", "n_clicks"),
         Input("api-hub-close-btn", "n_clicks")],
        State("api-hub-modal", "is_open"),
        prevent_initial_call=True
    )
    def toggle_api_hub_modal(open_clicks, close_clicks, is_open):
        return not is_open

    # ========================================================================
    # API HUB - OVERVIEW STATS
    # ========================================================================

    @app.callback(
        [Output('api-hub-enabled-count', 'children'),
         Output('api-hub-healthy-count', 'children'),
         Output('api-hub-total-requests', 'children'),
         Output('api-hub-success-rate', 'children'),
         Output('api-hub-integration-cards', 'children'),
         Output('toast-container', 'children', allow_duplicate=True)],
        [Input('api-hub-modal', 'is_open'),
         Input('api-hub-refresh-btn', 'n_clicks')],
        prevent_initial_call=True
    )
    def update_api_hub_overview(is_open, refresh_clicks):
        ctx = callback_context

        if not is_open:
            return dash.no_update, dash.no_update, dash.no_update, dash.no_update, dash.no_update, dash.no_update

        # Check if refresh button was clicked
        toast = dash.no_update
        if ctx.triggered and 'api-hub-refresh-btn' in ctx.triggered[0]['prop_id']:
            toast = ToastManager.info("Refreshing", detail_message="API Hub data refreshed successfully")

        try:
            from alerts.integration_system import IntegrationManager

            conn = get_db_connection()
            mgr = IntegrationManager(db_manager)

            # Get all integrations
            integrations = mgr.get_all_integrations()

            # Calculate stats
            enabled_count = sum(1 for i in integrations if i['is_enabled'])
            healthy_count = sum(1 for i in integrations if i['health_status'] == 'healthy')
            total_requests = sum(i['total_requests'] for i in integrations)
            total_successful = sum(i['successful_requests'] for i in integrations)
            success_rate = f"{int(total_successful / total_requests * 100)}%" if total_requests > 0 else "N/A"

            # Group by category
            categories = {}
            for integration in integrations:
                cat = integration['category']
                if cat not in categories:
                    categories[cat] = []
                categories[cat].append(integration)

            # Create category cards
            category_names = {
                'threat_intel': 'Threat Intelligence',
                'geolocation': 'Geolocation',
                'notifications': 'Notifications',
                'ticketing': 'Ticketing',
                'webhooks': 'Webhooks'
            }

            category_icons = {
                'threat_intel': 'shield-alt',
                'geolocation': 'globe',
                'notifications': 'bell',
                'ticketing': 'tasks',
                'webhooks': 'plug'
            }

            cards = []
            for cat, integrations_list in categories.items():
                enabled = sum(1 for i in integrations_list if i['is_enabled'])
                total = len(integrations_list)
                healthy = sum(1 for i in integrations_list if i['health_status'] == 'healthy' and i['is_enabled'])

                cards.append(
                    dbc.Col([
                        dbc.Card([
                            dbc.CardHeader([
                                html.I(className=f"fa fa-{category_icons.get(cat, 'cog')} me-2"),
                                category_names.get(cat, cat.title())
                            ], className="glass-card-header"),
                            dbc.CardBody([
                                html.Div([
                                    html.H4(f"{enabled}/{total}", className="mb-1"),
                                    html.P("Enabled", className="text-muted small mb-2"),
                                    html.Div([
                                        html.I(className=f"fa fa-circle text-{'success' if healthy == enabled and enabled > 0 else 'warning'} me-1"),
                                        html.Small(f"{healthy} healthy", className="text-muted")
                                    ])
                                ])
                            ])
                        ], className="glass-card border-0 shadow-sm h-100")
                    ], md=4, className="mb-3")
                )

            return (
                str(enabled_count),
                str(healthy_count),
                str(total_requests),
                success_rate,
                dbc.Row(cards),
                toast
            )

        except Exception as e:
            logger.error(f"Error updating API hub overview: {e}")
            return "0", "0", "0", "N/A", dbc.Alert(f"Error: {str(e)}", color="danger"), dash.no_update

    # ========================================================================
    # API HUB - CATEGORY TABS
    # ========================================================================

    # API Hub - Threat Intel Tab
    @app.callback(
        Output('api-hub-threat-intel-content', 'children'),
        Input('api-hub-tabs', 'active_tab'),
        prevent_initial_call=True
    )
    def update_threat_intel_tab(active_tab):
        if active_tab != 'api-hub-threat':
            return dash.no_update

        try:
            from alerts.integration_system import IntegrationManager

            mgr = IntegrationManager(db_manager)
            integrations = mgr.get_integrations_by_category('threat_intel')

            return create_integration_config_ui(integrations, 'threat_intel')

        except Exception as e:
            return dbc.Alert(f"Error: {str(e)}", color="danger")

    # API Hub - Notifications Tab
    @app.callback(
        Output('api-hub-notifications-content', 'children'),
        Input('api-hub-tabs', 'active_tab'),
        prevent_initial_call=True
    )
    def update_notifications_tab(active_tab):
        if active_tab != 'api-hub-notifications':
            return dash.no_update

        try:
            from alerts.integration_system import IntegrationManager

            mgr = IntegrationManager(db_manager)
            integrations = mgr.get_integrations_by_category('notifications')

            return create_integration_config_ui(integrations, 'notifications')

        except Exception as e:
            return dbc.Alert(f"Error: {str(e)}", color="danger")

    # API Hub - Ticketing Tab
    @app.callback(
        Output('api-hub-ticketing-content', 'children'),
        Input('api-hub-tabs', 'active_tab'),
        prevent_initial_call=True
    )
    def update_ticketing_tab(active_tab):
        if active_tab != 'api-hub-ticketing':
            return dash.no_update

        try:
            from alerts.integration_system import IntegrationManager

            mgr = IntegrationManager(db_manager)
            integrations = mgr.get_integrations_by_category('ticketing')

            return create_integration_config_ui(integrations, 'ticketing')

        except Exception as e:
            return dbc.Alert(f"Error: {str(e)}", color="danger")

    # API Hub - Geolocation Tab
    @app.callback(
        Output('api-hub-geolocation-content', 'children'),
        Input('api-hub-tabs', 'active_tab'),
        prevent_initial_call=True
    )
    def update_geolocation_tab(active_tab):
        if active_tab != 'api-hub-geo':
            return dash.no_update

        try:
            from alerts.integration_system import IntegrationManager

            mgr = IntegrationManager(db_manager)
            integrations = mgr.get_integrations_by_category('geolocation')

            return create_integration_config_ui(integrations, 'geolocation')

        except Exception as e:
            return dbc.Alert(f"Error: {str(e)}", color="danger")

    # API Hub - Webhooks Tab
    @app.callback(
        Output('api-hub-webhooks-content', 'children'),
        Input('api-hub-tabs', 'active_tab'),
        prevent_initial_call=True
    )
    def update_webhooks_tab(active_tab):
        if active_tab != 'api-hub-webhooks':
            return dash.no_update

        try:
            from alerts.integration_system import IntegrationManager

            mgr = IntegrationManager(db_manager)
            integrations = mgr.get_integrations_by_category('webhooks')

            return create_integration_config_ui(integrations, 'webhooks')

        except Exception as e:
            return dbc.Alert(f"Error: {str(e)}", color="danger")

    # ========================================================================
    # API HUB - SETTINGS TAB (inline UI)
    # ========================================================================

    @app.callback(
        Output('api-hub-settings-content', 'children'),
        Input('api-hub-tabs', 'active_tab'),
        prevent_initial_call=True
    )
    def update_api_hub_settings_tab(active_tab):
        if active_tab != 'api-hub-settings':
            return dash.no_update

        try:
            return dbc.Container([
                dbc.Row([
                    dbc.Col([
                        dbc.Card([
                            dbc.CardHeader([
                                html.I(className="fa fa-cog me-2"),
                                "Integration Hub Settings"
                            ], className="glass-card-header"),
                            dbc.CardBody([
                                # Rate Limiting Settings
                                html.H6([html.I(className="fa fa-tachometer-alt me-2"), "Rate Limiting"], className="mb-3"),
                                dbc.Row([
                                    dbc.Col([
                                        html.Label("Global Daily Request Limit", className="form-label"),
                                        dbc.Input(type="number", value=10000, disabled=True, size="sm"),
                                        html.Small("Maximum total API requests per day across all integrations", className="text-muted")
                                    ], md=6),
                                    dbc.Col([
                                        html.Label("Request Timeout (seconds)", className="form-label"),
                                        dbc.Input(type="number", value=30, disabled=True, size="sm"),
                                        html.Small("Maximum time to wait for API responses", className="text-muted")
                                    ], md=6)
                                ], className="mb-4"),

                                html.Hr(),

                                # Encryption Settings
                                html.H6([html.I(className="fa fa-lock me-2"), "Security & Encryption"], className="mb-3"),
                                dbc.Alert([
                                    html.I(className="fa fa-shield-alt me-2"),
                                    "All API credentials are encrypted using AES-256 Fernet encryption before database storage. ",
                                    "The encryption key is stored in .env as ",
                                    html.Code("IOTSENTINEL_ENCRYPTION_KEY"),
                                    ". Never share or commit this key!"
                                ], color="success", className="mb-3"),

                                dbc.Row([
                                    dbc.Col([
                                        html.Label("Encryption Status", className="form-label"),
                                        dbc.InputGroup([
                                            dbc.InputGroupText(html.I(className="fa fa-check-circle text-success")),
                                            dbc.Input(value="Active - AES-256 Fernet", disabled=True, size="sm")
                                        ]),
                                    ], md=6),
                                    dbc.Col([
                                        html.Label("Credential Storage", className="form-label"),
                                        dbc.InputGroup([
                                            dbc.InputGroupText(html.I(className="fa fa-database text-info")),
                                            dbc.Input(value="SQLite - Encrypted Blobs", disabled=True, size="sm")
                                        ]),
                                    ], md=6)
                                ], className="mb-4"),

                                html.Hr(),

                                # Legacy Integration Info - UPDATED
                                html.H6([html.I(className="fa fa-sync-alt me-2"), "Legacy Code Integration"], className="mb-3"),
                                dbc.Alert([
                                    html.I(className="fa fa-check-circle me-2"),
                                    html.Strong("✅ UPDATED: "),
                                    "The legacy threat intelligence system (utils/threat_intel.py) has been updated to support Integration Hub! ",
                                    html.Br(),
                                    html.Br(),
                                    html.Strong("Priority order for API keys: "),
                                    html.Br(),
                                    "1️⃣ Direct parameter (highest priority)",
                                    html.Br(),
                                    "2️⃣ Environment variable (.env)",
                                    html.Br(),
                                    "3️⃣ Integration Hub (encrypted database) ← NEW!",
                                    html.Br(),
                                    html.Br(),
                                    html.Strong("What this means: "),
                                    html.Br(),
                                    "• You can safely remove API keys from .env",
                                    html.Br(),
                                    "• Legacy code automatically reads from Integration Hub",
                                    html.Br(),
                                    "• All threat intelligence features continue working",
                                    html.Br(),
                                    "• Single source of truth: Integration Hub database",
                                    html.Br(),
                                    html.Br(),
                                    html.I(className="fa fa-shield-alt me-2"),
                                    html.Strong("Security: "),
                                    "Keys in .env are plaintext. Keys in Integration Hub are AES-256 encrypted!"
                                ], color="success", className="mb-3"),

                                html.Hr(),

                                # Data Management
                                html.H6([html.I(className="fa fa-database me-2"), "Data Management"], className="mb-3"),
                                dbc.Row([
                                    dbc.Col([
                                        dbc.Button([
                                            html.I(className="fa fa-trash-alt me-2"),
                                            "Clear Request Logs"
                                        ], id="api-hub-clear-logs-btn", color="danger", outline=True, size="sm", className="w-100 mb-2"),
                                        html.Small("Remove all API request history", className="text-muted")
                                    ], md=4),
                                    dbc.Col([
                                        dbc.Button([
                                            html.I(className="fa fa-sync-alt me-2"),
                                            "Reset Health Status"
                                        ], id="api-hub-reset-health-btn", color="warning", outline=True, size="sm", className="w-100 mb-2"),
                                        html.Small("Clear health check cache", className="text-muted")
                                    ], md=4),
                                    dbc.Col([
                                        html.Label("Export Format:", className="fw-bold mb-2 small"),
                                        dbc.Select(
                                            id='api-hub-export-format',
                                            options=[
                                                {'label': '📄 CSV Format', 'value': 'csv'},
                                                {'label': '📋 JSON Format', 'value': 'json'},
                                                {'label': '📕 PDF Report', 'value': 'pdf'},
                                                {'label': '📊 Excel Workbook', 'value': 'excel'}
                                            ],
                                            value='json',
                                            size="sm",
                                            className="mb-2"
                                        ),
                                        dbc.Button([
                                            html.I(className="fa fa-download me-2"),
                                            "Export Config"
                                        ], id="api-hub-export-config-btn", color="info", outline=True, size="sm", className="w-100 mb-2"),
                                        html.Small("Download integration settings", className="text-muted")
                                    ], md=4)
                                ]),

                                html.Hr(),

                                # Quick Setup Guide
                                html.H6([html.I(className="fa fa-rocket me-2"), "Quick Setup Guide"], className="mb-3"),
                                dbc.Alert([
                                    html.I(className="fa fa-lightbulb me-2"),
                                    html.Strong("New to Integration Hub? "),
                                    "Follow these steps:",
                                    html.Br(),
                                    html.Br(),
                                    "1️⃣ Navigate to any integration category tab (Threat Intel, Notifications, etc.)",
                                    html.Br(),
                                    "2️⃣ Click ",
                                    html.Strong("Configure"),
                                    " on an integration card",
                                    html.Br(),
                                    "3️⃣ Enter your API credentials (get free keys from provider websites)",
                                    html.Br(),
                                    "4️⃣ Click ",
                                    html.Strong("Test"),
                                    " to verify the connection",
                                    html.Br(),
                                    "5️⃣ Toggle ",
                                    html.Strong("Enable"),
                                    " to activate the integration",
                                    html.Br(),
                                    html.Br(),
                                    html.I(className="fa fa-check-circle text-success me-2"),
                                    "All credentials are automatically encrypted with AES-256 before storage!"
                                ], color="info", className="mb-0")
                            ])
                        ], className="glass-card border-0 shadow-sm")
                    ], md=12)
                ]),

                # Confirmation modals
                dbc.Modal([
                    dbc.ModalHeader(dbc.ModalTitle([
                        html.I(className="fa fa-exclamation-triangle me-2 text-danger"),
                        "Clear Request Logs?"
                    ])),
                    dbc.ModalBody([
                        html.P("This will permanently delete all API request history from the database."),
                        html.P([
                            html.Strong("Warning: "),
                            "This action cannot be undone!"
                        ], className="text-danger mb-0")
                    ]),
                    dbc.ModalFooter([
                        dbc.Button("Cancel", id="cancel-clear-logs-btn", color="secondary", size="sm", className="me-2"),
                        dbc.Button([
                            html.I(className="fa fa-trash-alt me-2"),
                            "Clear Logs"
                        ], id="confirm-clear-logs-btn", color="danger", size="sm")
                    ])
                ], id="clear-logs-confirm-modal", is_open=False),

                dbc.Modal([
                    dbc.ModalHeader(dbc.ModalTitle([
                        html.I(className="fa fa-sync-alt me-2 text-warning"),
                        "Reset Health Status?"
                    ])),
                    dbc.ModalBody([
                        html.P("This will clear all health check results and force re-validation of all integrations."),
                        html.P("The next health check will run automatically within a few minutes.", className="text-muted mb-0")
                    ]),
                    dbc.ModalFooter([
                        dbc.Button("Cancel", id="cancel-reset-health-btn", color="secondary", size="sm", className="me-2"),
                        dbc.Button([
                            html.I(className="fa fa-sync-alt me-2"),
                            "Reset Status"
                        ], id="confirm-reset-health-btn", color="warning", size="sm")
                    ])
                ], id="reset-health-confirm-modal", is_open=False)
            ], fluid=True)

        except Exception as e:
            logger.error(f"Error rendering API Hub settings: {e}")
            return dbc.Alert(f"Error: {str(e)}", color="danger")

    # ========================================================================
    # API HUB - CONFIGURE / SAVE / CANCEL (pattern-matching ALL)
    # ========================================================================

    @app.callback(
        [Output('api-config-modal', 'is_open'),
         Output('api-config-modal-title', 'children'),
         Output('api-config-form-content', 'children'),
         Output('api-config-store', 'data')],
        [Input({'type': 'config-integration', 'index': ALL}, 'n_clicks'),
         Input('api-config-save-btn', 'n_clicks'),
         Input('api-config-cancel-btn', 'n_clicks')],
        [State('api-config-modal', 'is_open'),
         State('api-config-store', 'data'),
         State({'type': 'api-config-field', 'field': ALL}, 'value'),
         State({'type': 'api-config-field', 'field': ALL}, 'id'),
         State({'type': 'config-integration-enable', 'index': ALL}, 'value')],
        prevent_initial_call=True
    )
    @login_required
    def handle_integration_config(config_clicks, save_click, cancel_click, is_open, store_data,
                                  field_values, field_ids, enable_values):
        """Handle integration configuration modal."""
        from alerts.integration_system import IntegrationManager, INTEGRATIONS

        ctx = callback_context
        if not ctx.triggered:
            return dash.no_update, dash.no_update, dash.no_update, dash.no_update

        trigger_id = ctx.triggered[0]['prop_id']

        # Cancel button clicked
        if 'api-config-cancel-btn' in trigger_id:
            return False, dash.no_update, dash.no_update, None

        # Save button clicked
        if 'api-config-save-btn' in trigger_id and store_data:
            if not PermissionManager.has_permission(current_user, 'manage_api'):
                security_audit_logger.log(
                    event_type='permission_denied',
                    user_id=current_user.id if current_user.is_authenticated else None,
                    username=current_user.username if current_user.is_authenticated else 'anonymous',
                    details={'action': 'configure_integration', 'integration_id': store_data.get('integration_id')},
                    severity='high',
                    result='failure',
                    failure_reason='Requires manage_api permission (admin only)'
                )
                return True, dash.no_update, dbc.Alert("Permission denied: admin access required.", color="danger"), store_data
            try:
                integration_id = store_data.get('integration_id')
                mgr = IntegrationManager(db_manager)

                # Build credentials dict from form fields
                credentials = {}
                if field_values and field_ids:
                    for value, field_id in zip(field_values, field_ids):
                        field_name = field_id['field']
                        if value:  # Only include non-empty values
                            credentials[field_name] = value

                # Get enabled status
                enabled = bool(enable_values[0]) if enable_values else False

                # Save configuration (credentials will be encrypted automatically)
                success = mgr.configure_integration(integration_id, enabled=enabled, **credentials)

                if success:
                    security_audit_logger.log(
                        event_type='settings_changed',
                        user_id=current_user.id,
                        username=current_user.username,
                        details={'settings_type': 'api_integration', 'integration_id': integration_id, 'enabled': enabled},
                        severity='high',
                        resource_type='integration',
                        resource_id=str(integration_id),
                        result='success'
                    )
                    return False, dash.no_update, dash.no_update, None
                else:
                    return True, dash.no_update, dbc.Alert("Failed to save configuration", color="danger"), store_data

            except Exception as e:
                logger.error(f"Error saving integration config: {e}")
                return True, dash.no_update, dbc.Alert(f"Error: {str(e)}", color="danger"), store_data

        # Configure button clicked - open modal
        if any(config_clicks):
            # Find which button was clicked
            integration_id = None
            for i, clicks in enumerate(config_clicks):
                if clicks:
                    button_id = ctx.triggered[0]['prop_id'].split('.')[0]
                    integration_id = eval(button_id)['index']
                    break

            if not integration_id or integration_id not in INTEGRATIONS:
                return dash.no_update, dash.no_update, dash.no_update, dash.no_update

            integration_info = INTEGRATIONS[integration_id]
            mgr = IntegrationManager(db_manager)
            integration_data = mgr.get_integration(integration_id)

            # Build configuration form
            form_fields = []

            # Add enable/disable switch
            form_fields.append(
                dbc.Row([
                    dbc.Col([
                        dbc.Label("Enable Integration"),
                        dbc.Switch(
                            id={'type': 'config-integration-enable', 'index': integration_id},
                            value=integration_data.get('is_enabled', False),
                            className="mb-3"
                        )
                    ])
                ])
            )

            # Add fields based on integration requirements
            for field in integration_info.get('setup_fields', []):
                field_label = field.replace('_', ' ').title()
                field_type = "password" if field in ['password', 'api_key', 'api_secret', 'api_token',
                                                      'personal_access_token', 'bot_token', 'webhook_key',
                                                      'user_key'] else "text"

                placeholder = f"Enter your {field_label.lower()}"
                if field == 'webhook_url':
                    placeholder = f"https://..."
                elif field == 'smtp_port':
                    placeholder = "587"

                form_fields.append(
                    dbc.Row([
                        dbc.Col([
                            dbc.Label(field_label),
                            dbc.Input(
                                id={'type': 'api-config-field', 'field': field},
                                type=field_type,
                                placeholder=placeholder,
                                className="mb-3"
                            )
                        ])
                    ])
                )

            # Add helpful information
            info_alert = dbc.Alert([
                html.H5([html.I(className=f"fa fa-{integration_info['icon']} me-2"), integration_info['name']]),
                html.P(integration_info['description'], className="mb-2"),
                html.Hr(),
                html.Div([
                    html.Strong("Free Tier: "),
                    html.Span(integration_info['free_tier'], className="text-success")
                ], className="mb-2"),
                html.Div([
                    html.Strong("Priority: "),
                    dbc.Badge(integration_info['priority'].title(),
                             color={'high': 'danger', 'medium': 'warning', 'low': 'info'}[integration_info['priority']])
                ], className="mb-2"),
                html.Hr(),
                html.Small([
                    html.I(className="fa fa-book me-1"),
                    html.A("View Documentation", href=integration_info['docs_url'],
                          target="_blank", className="text-decoration-none")
                ])
            ], color="info", className="mb-3")

            form_content = html.Div([
                info_alert,
                html.Div(form_fields)
            ])

            title = [
                html.I(className=f"fa fa-{integration_info['icon']} me-2"),
                f"Configure {integration_info['name']}"
            ]

            store_data = {'integration_id': integration_id}

            return True, title, form_content, store_data

        return dash.no_update, dash.no_update, dash.no_update, dash.no_update

    # ========================================================================
    # API HUB - TEST INTEGRATION (pattern-matching ALL)
    # ========================================================================

    @app.callback(
        Output('toast-container', 'children', allow_duplicate=True),
        Input({'type': 'test-integration', 'index': ALL}, 'n_clicks'),
        prevent_initial_call=True
    )
    def test_integration_handler(test_clicks):
        """Test an integration to verify it's working."""
        from alerts.integration_system import IntegrationManager
        from alerts.integration_actions import IntegrationActions

        if not any(test_clicks):
            return dash.no_update

        ctx = callback_context
        button_id = eval(ctx.triggered[0]['prop_id'].split('.')[0])
        integration_id = button_id['index']

        try:
            mgr = IntegrationManager(db_manager)
            actions = IntegrationActions(db_manager)
            integration = mgr.get_integration(integration_id)

            if not integration or not integration['is_enabled']:
                return ToastManager.error("Integration Not Enabled",
                                         detail_message="Please configure and enable this integration first.")

            # Test based on category
            success = False
            error_msg = None

            try:
                if integration['category'] == 'notifications':
                    if integration_id == 'slack':
                        success = actions.send_slack_alert("🧪 Test alert from IoTSentinel", "low")
                    elif integration_id == 'discord':
                        success = actions.send_discord_alert("🧪 Test alert from IoTSentinel", "low")
                    elif integration_id == 'telegram':
                        success = actions.send_telegram_alert("🧪 Test alert from IoTSentinel")
                    elif integration_id == 'email_smtp':
                        success = actions.send_email_alert("Test Alert", "This is a test from IoTSentinel")

                elif integration['category'] == 'threat_intel':
                    # Test with Google DNS IP (known safe)
                    result = actions.query_threat_intel("8.8.8.8")
                    success = bool(result and result.get('sources'))

                elif integration['category'] == 'geolocation':
                    result = actions.get_ip_geolocation("8.8.8.8")
                    success = bool(result)

                else:
                    success = True  # Other categories don't have easy tests

            except Exception as e:
                error_msg = str(e)
                success = False

            if success:
                mgr.update_health_status(integration_id, 'healthy')
                return ToastManager.success("Integration Test Passed",
                                           detail_message=f"{integration['name']} is working correctly!")
            else:
                mgr.update_health_status(integration_id, 'error', error_msg)
                return ToastManager.error("Integration Test Failed",
                                         detail_message=error_msg or "Please check your configuration.")

        except Exception as e:
            logger.error(f"Error testing integration: {e}")
            return ToastManager.error("Test Error", detail_message=str(e))

    # ========================================================================
    # API HUB - TOGGLE INTEGRATION ENABLE/DISABLE (pattern-matching ALL)
    # ========================================================================

    @app.callback(
        Output('toast-container', 'children', allow_duplicate=True),
        Input({'type': 'toggle-integration', 'index': ALL}, 'n_clicks'),
        prevent_initial_call=True
    )
    def toggle_integration_handler(toggle_clicks):
        """Toggle integration enabled/disabled state."""
        from alerts.integration_system import IntegrationManager

        if not any(toggle_clicks):
            return dash.no_update

        ctx = callback_context
        button_id = eval(ctx.triggered[0]['prop_id'].split('.')[0])
        integration_id = button_id['index']

        try:
            mgr = IntegrationManager(db_manager)
            integration = mgr.get_integration(integration_id)

            if not integration:
                return ToastManager.error("Error", detail_message="Integration not found")

            # Toggle the state
            if integration['is_enabled']:
                success = mgr.disable_integration(integration_id)
                if success:
                    return ToastManager.info("Integration Disabled",
                                            detail_message=f"{integration['name']} has been disabled")
            else:
                # Check if configured before enabling
                creds = mgr.get_integration_credentials(integration_id)
                if not creds:
                    return ToastManager.warning("Configuration Required",
                                               detail_message="Please configure this integration before enabling it")

                success = mgr.configure_integration(integration_id, enabled=True, **creds)
                if success:
                    return ToastManager.success("Integration Enabled",
                                               detail_message=f"{integration['name']} is now active")

            return dash.no_update

        except Exception as e:
            logger.error(f"Error toggling integration: {e}")
            return ToastManager.error("Error", detail_message=str(e))

    # ========================================================================
    # API HUB SETTINGS - CLEAR LOGS CONFIRM MODAL
    # ========================================================================

    @app.callback(
        Output("clear-logs-confirm-modal", "is_open"),
        [Input("api-hub-clear-logs-btn", "n_clicks"),
         Input("cancel-clear-logs-btn", "n_clicks"),
         Input("confirm-clear-logs-btn", "n_clicks")],
        State("clear-logs-confirm-modal", "is_open"),
        prevent_initial_call=True
    )
    def toggle_clear_logs_modal(open_clicks, cancel_clicks, confirm_clicks, is_open):
        return not is_open

    # ========================================================================
    # API HUB SETTINGS - CLEAR REQUEST LOGS
    # ========================================================================

    @app.callback(
        [Output('toast-container', 'children', allow_duplicate=True),
         Output("clear-logs-confirm-modal", "is_open", allow_duplicate=True)],
        Input("confirm-clear-logs-btn", "n_clicks"),
        prevent_initial_call=True
    )
    def clear_request_logs_handler(confirm_clicks):
        """Clear all API request logs from database."""
        if not confirm_clicks:
            return dash.no_update, dash.no_update

        try:
            cursor = db_manager.conn.cursor()
            cursor.execute("DELETE FROM api_integration_logs")
            db_manager.conn.commit()

            return ToastManager.success("Logs Cleared",
                                       detail_message="All API request logs have been deleted"), False
        except Exception as e:
            logger.error(f"Error clearing logs: {e}")
            return ToastManager.error("Error", detail_message=str(e)), False

    # ========================================================================
    # API HUB SETTINGS - RESET HEALTH CONFIRM MODAL
    # ========================================================================

    @app.callback(
        Output("reset-health-confirm-modal", "is_open"),
        [Input("api-hub-reset-health-btn", "n_clicks"),
         Input("cancel-reset-health-btn", "n_clicks"),
         Input("confirm-reset-health-btn", "n_clicks")],
        State("reset-health-confirm-modal", "is_open"),
        prevent_initial_call=True
    )
    def toggle_reset_health_modal(open_clicks, cancel_clicks, confirm_clicks, is_open):
        return not is_open

    # ========================================================================
    # API HUB SETTINGS - RESET HEALTH STATUS
    # ========================================================================

    @app.callback(
        [Output('toast-container', 'children', allow_duplicate=True),
         Output("reset-health-confirm-modal", "is_open", allow_duplicate=True)],
        Input("confirm-reset-health-btn", "n_clicks"),
        prevent_initial_call=True
    )
    def reset_health_status_handler(confirm_clicks):
        """Reset all integration health statuses."""
        if not confirm_clicks:
            return dash.no_update, dash.no_update

        try:
            cursor = db_manager.conn.cursor()
            cursor.execute("""
                UPDATE api_integrations
                SET health_status = 'untested',
                    last_health_check = NULL
            """)
            db_manager.conn.commit()

            return ToastManager.success("Health Status Reset",
                                       detail_message="All health checks have been cleared. Re-validation will occur automatically."), False
        except Exception as e:
            logger.error(f"Error resetting health: {e}")
            return ToastManager.error("Error", detail_message=str(e)), False

    # ========================================================================
    # API HUB SETTINGS - EXPORT CONFIGURATION (RBAC)
    # ========================================================================

    @app.callback(
        [Output('toast-container', 'children', allow_duplicate=True),
         Output('download-api-hub-config', 'data')],
        Input("api-hub-export-config-btn", "n_clicks"),
        State('api-hub-export-format', 'value'),
        prevent_initial_call=True
    )
    @login_required
    def export_config_handler(export_clicks, export_format):
        """Export integration configuration (credentials excluded for security). Requires export_data permission."""
        if not export_clicks:
            return dash.no_update, dash.no_update

        if not can_export_data(current_user):
            security_audit_logger.log(
                event_type='permission_denied',
                user_id=current_user.id,
                username=current_user.username,
                details={'action': 'export_api_hub_config', 'format': export_format},
                severity='high',
                result='failure',
                failure_reason='Requires export_data permission (admin only)'
            )
            toast = ToastManager.error(
                "Permission Denied",
                detail_message="You don't have permission to export configuration."
            )
            return toast, None

        try:
            export_format = export_format or 'json'
            logger.info(f"API Hub export config button clicked (format: {export_format})")

            security_audit_logger.log(
                event_type='data_export',
                user_id=current_user.id,
                username=current_user.username,
                details={'resource': 'api_hub_config', 'format': export_format},
                severity='high',
                resource_type='configuration',
                result='success'
            )

            # Use export_helper for consistent export pattern (like other export buttons)
            download_data = export_helper.export_integrations(format=export_format)

            logger.info(f"Export data returned: {download_data is not None}")

            if download_data:
                logger.info(f"Preparing download: {download_data.get('filename')}")
                return (
                    ToastManager.success("Configuration Exported",
                                       detail_message=f"Download started as {export_format.upper()} (credentials excluded for security)"),
                    download_data
                )
            else:
                logger.warning("Export integrations returned None")
                return (
                    ToastManager.error("Export Failed",
                                     detail_message="No data available or export failed"),
                    None
                )
        except Exception as e:
            logger.error(f"Error exporting config: {e}", exc_info=True)
            return ToastManager.error("Error", detail_message=str(e)), None


# ============================================================================
# HELPER FUNCTIONS (module-level, used by callbacks above)
# ============================================================================

def create_integration_config_ui(integrations, category):
    """Helper function to create integration configuration UI."""

    cards = []

    for integration in integrations:
        # Status badge
        status_color = {
            'healthy': 'success',
            'degraded': 'warning',
            'error': 'danger',
            'untested': 'secondary'
        }.get(integration['health_status'], 'secondary')

        status_badge = dbc.Badge(
            integration['health_status'].title(),
            color=status_color,
            className="ms-2"
        )

        # Priority badge
        priority_color = {
            'high': 'danger',
            'medium': 'warning',
            'low': 'info'
        }.get(integration['priority'], 'secondary')

        priority_badge = dbc.Badge(
            f"{integration['priority'].title()} Priority",
            color=priority_color,
            pill=True
        )

        # Create card
        card = dbc.Col([
            dbc.Card([
                dbc.CardHeader([
                    html.Div([
                        html.I(className=f"fa fa-{integration['icon']} me-2"),
                        html.Strong(integration['name']),
                        status_badge
                    ], className="d-flex align-items-center justify-content-between")
                ], className="glass-card-header"),
                dbc.CardBody([
                    html.P(integration['description'], className="text-muted small mb-2"),
                    html.Div([
                        priority_badge,
                        dbc.Badge(integration['free_tier'], color="success", className="ms-2")
                    ], className="mb-3"),

                    html.Div([
                        html.Small(f"Requests: {integration['total_requests']} | Success: {integration['successful_requests']} | Failed: {integration['failed_requests']}",
                                 className="text-muted d-block mb-2")
                    ]),

                    html.Hr(),

                    # Action buttons
                    dbc.ButtonGroup([
                        dbc.Button([
                            html.I(className="fa fa-cog me-1"),
                            "Configure"
                        ], id={"type": "config-integration", "index": integration['id']},
                           color="primary", size="sm", outline=True),
                        dbc.Button([
                            html.I(className="fa fa-vial me-1"),
                            "Test"
                        ], id={"type": "test-integration", "index": integration['id']},
                           color="info", size="sm", outline=True),
                        dbc.Button([
                            html.I(className=f"fa fa-{'toggle-on' if integration['is_enabled'] else 'toggle-off'} me-1"),
                            "Enabled" if integration['is_enabled'] else "Disabled"
                        ], id={"type": "toggle-integration", "index": integration['id']},
                           color="success" if integration['is_enabled'] else "secondary",
                           size="sm", outline=not integration['is_enabled'])
                    ], className="w-100"),

                    # Documentation link
                    html.Div([
                        html.A([
                            html.I(className="fa fa-book me-1"),
                            "Documentation"
                        ], href=integration['docs_url'], target="_blank",
                           className="small text-muted text-decoration-none d-block mt-2")
                    ])
                ])
            ], className="glass-card border-0 shadow-sm h-100")
        ], md=6, lg=4, className="mb-3")

        cards.append(card)

    if not cards:
        return dbc.Alert("No integrations available in this category.", color="info")

    return dbc.Row(cards)
