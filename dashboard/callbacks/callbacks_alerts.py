"""
Alerts & Threats tab callbacks — alert management, threat intelligence,
auto-response, threat maps, risk heatmaps, forensics-related interval callbacks.

Extracted from app.py.  All callbacks are registered via ``register(app)``.
"""

import json
import logging
import os
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Optional, Any

import dash
import dash_bootstrap_components as dbc
import pandas as pd
import plotly.express as px
import plotly.graph_objs as go
from dash import dcc, html, Input, Output, State, callback_context, ALL, no_update

from flask_login import login_required, current_user

from dashboard.shared import (
    db_manager,
    chart_factory,
    threat_intel,
    logger as _shared_logger,
    config,
    export_helper,
    inference_engine,
    smart_recommender,
    attack_tracker,
    ai_assistant,
    security_audit_logger,
    audit_logger,
    get_db_connection,
    get_alert_with_context,
    get_device_today_stats,
    get_device_baseline,
    create_educational_explanation,
    create_timestamp_display,
    create_threat_intel_badge,
    create_baseline_comparison_chart,
    format_bytes,
    SEVERITY_COLORS,
    RISK_COLORS,
    SEVERITY_CONFIG,
    MITRE_ATTACK_MAPPING,
    ToastManager,
    ChartFactory,
    PermissionManager,
    log_device_action,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# register(app) — all alert/threat callbacks are defined inside
# ---------------------------------------------------------------------------

def register(app):
    """Register all alert and threat related callbacks with the Dash app."""

    # ========================================================================
    # CALLBACKS - ALERTS
    # ========================================================================

    # Store alerts data from websocket OR interval (fallback for Mac/websocket issues)
    @app.callback(
        Output('alerts-data-store', 'data'),
        [Input('ws', 'message'), Input('refresh-interval', 'n_intervals')]
    )
    def store_alerts_data(ws_message, n_intervals):
        # Try websocket first
        if ws_message is not None:
            recent_alerts = ws_message.get('recent_alerts', [])
            return recent_alerts

        # Fallback: Fetch from database directly (for Mac or websocket failures)
        try:
            cursor = db_manager.conn.cursor()
            cursor.execute("""
                SELECT
                    a.id,
                    a.timestamp,
                    a.device_ip,
                    d.device_name,
                    a.severity,
                    a.anomaly_score,
                    a.explanation,
                    a.top_features,
                    a.acknowledged,
                    a.acknowledged_at
                FROM alerts a
                LEFT JOIN devices d ON a.device_ip = d.device_ip
                WHERE a.timestamp >= datetime('now', '-24 hours')
                ORDER BY a.timestamp DESC
                LIMIT 100
            """)

            rows = cursor.fetchall()
            recent_alerts = []
            for row in rows:
                recent_alerts.append({
                    'id': row[0],
                    'timestamp': row[1],
                    'device_ip': row[2],
                    'device_name': row[3] or 'Unknown Device',
                    'severity': row[4],
                    'anomaly_score': row[5],
                    'explanation': row[6],
                    'top_features': row[7],
                    'acknowledged': row[8] or 0,
                    'acknowledged_at': row[9]
                })

            return recent_alerts

        except Exception as e:
            return []

    # Display alerts with filtering
    @app.callback(
        Output('alerts-container-compact', 'children'),
        [Input('alerts-data-store', 'data'), Input('alert-filter', 'data'), Input('show-reviewed-alerts', 'value')],
        prevent_initial_call=False
    )
    def update_alerts_compact(recent_alerts_raw, filter_severity, show_reviewed):
        # Handle empty or missing alerts
        if not recent_alerts_raw:
            return dbc.Alert([
                html.Div([
                    html.I(className="fa fa-check-circle me-2", style={'fontSize': '1.5rem'}),
                    html.Div([
                        html.H5("All Clear!", className="mb-1"),
                        html.P("No security alerts detected in the last 24 hours.", className="mb-0 small text-muted")
                    ])
                ], className="d-flex align-items-center")
            ], color="success", className="compact-alert")

        df = pd.DataFrame(recent_alerts_raw)

        # Filter out acknowledged alerts unless user wants to see them
        if not df.empty:
            # show_reviewed is a list: [] when unchecked, [1] when checked
            show_acknowledged = show_reviewed and len(show_reviewed) > 0

            if not show_acknowledged:
                df = df[df['acknowledged'] == 0]

        if filter_severity and filter_severity != 'all' and not df.empty:
            df = df[df['severity'] == filter_severity]

        if len(df) == 0:
            return dbc.Alert([
                html.Div([
                    html.I(className="fa fa-check-circle me-2", style={'fontSize': '1.5rem'}),
                    html.Div([
                        html.H5("All Clear!", className="mb-1"),
                        html.P("No security alerts detected in the last 24 hours.", className="mb-0 small text-muted")
                    ])
                ], className="d-flex align-items-center")
            ], color="success", className="compact-alert")

        alert_items = []
        for _, alert in df.iterrows():
            # Safely extract device name
            device_name = alert.get('device_name') or alert.get('device_ip', 'Unknown Device')
            severity = alert.get('severity', 'medium')
            config_data = SEVERITY_CONFIG.get(severity, SEVERITY_CONFIG['medium'])

            # Safely parse timestamp
            try:
                timestamp = alert.get('timestamp')
                if timestamp:
                    dt = datetime.fromisoformat(timestamp)
                    time_str = dt.strftime('%H:%M')
                else:
                    time_str = "N/A"
            except Exception as e:
                time_str = "N/A"

            # Safely get MITRE tactic
            explanation = alert.get('explanation', 'Unknown')
            mitre_info = MITRE_ATTACK_MAPPING.get(explanation, {})
            tactic = mitre_info.get('tactic', 'Unknown').split('(')[0].strip()

            # Check if alert is acknowledged/reviewed
            is_reviewed = alert.get('acknowledged', 0) == 1

            alert_items.append(
                dbc.Card([
                    dbc.CardBody([
                        html.Div([
                            html.Div([
                                dbc.Badge([html.I(className=f"fa {config_data['icon']} me-1"), severity.upper()],
                                         color=config_data['color'], className="me-2"),
                                dbc.Badge(tactic, color="dark", className="badge-sm"),
                                dbc.Badge("✓ Reviewed", color="success", className="ms-1") if is_reviewed else None
                            ]),
                            html.Small(time_str, className="text-cyber")
                        ], className="d-flex justify-content-between mb-2"),
                        html.Strong(device_name, className="d-block mb-1"),
                        html.P(explanation[:80] + "..." if explanation and len(explanation) > 80 else (explanation or "No description available"),
                               className="alert-text-compact mb-2"),
                        dbc.Button([html.I(className="fa fa-info-circle me-1"), "Details"],
                                  id={'type': 'alert-detail-btn', 'index': int(alert.get('id', 0))},
                                  size="sm", color=config_data['color'], outline=True, className="w-100 cyber-button")
                    ], className="p-2")
                ], className=f"alert-card-compact mb-2 border-{config_data['color']}")
            )
        return html.Div(alert_items, className="fade-in")

    # Alert details modal
    @app.callback(
        [Output('alert-details-modal', 'is_open'),
         Output('alert-details-title', 'children'),
         Output('alert-details-body', 'children'),
         Output('current-alert-id', 'data')],
        [Input({'type': 'alert-detail-btn', 'index': dash.dependencies.ALL}, 'n_clicks'),
         Input('alert-close-btn', 'n_clicks')],
        [State('alert-details-modal', 'is_open')],
        prevent_initial_call=True
    )
    def toggle_alert_details(btn_clicks, close_click, is_open):
        ctx = callback_context
        if not ctx.triggered:
            return False, "", "", None

        trigger_id = ctx.triggered[0]['prop_id']

        # Close button clicked
        if 'alert-close-btn' in trigger_id:
            return False, "", "", None

        # Detail button clicked - check if it was actually clicked (not None)
        if 'alert-detail-btn' in trigger_id:
            # Check if any button was actually clicked (has a non-None value)
            if not any(btn_clicks):
                return dash.no_update

            try:
                trigger_data = json.loads(trigger_id.split('.')[0])
                alert_id = trigger_data['index']
            except (json.JSONDecodeError, KeyError):
                return False, "", "", None

            alert = get_alert_with_context(alert_id)
            if not alert:
                return True, "Alert Not Found", html.P("Could not load alert details."), None

            device_name = alert.get('device_name') or alert.get('device_ip', 'Unknown')
            title = f"🔍 Alert Details: {device_name}"
            body = create_educational_explanation(alert)
            return True, title, body, alert_id

        return dash.no_update

    # Mark alert reviewed
    @app.callback(
        [Output('toast-container', 'children', allow_duplicate=True),
         Output('alert-details-modal', 'is_open', allow_duplicate=True)],
        [Input('alert-acknowledge-btn', 'n_clicks')],
        [State('current-alert-id', 'data')],
        prevent_initial_call=True
    )
    @login_required
    def acknowledge_alert_callback(n_clicks, alert_id):
        """Mark alert as reviewed/acknowledged. Requires acknowledge_alerts permission (operator+)."""
        if not n_clicks or not alert_id:
            return dash.no_update, dash.no_update

        # Check permission
        if not PermissionManager.has_permission(current_user, 'acknowledge_alerts'):
            security_audit_logger.log(
                event_type='permission_denied',
                user_id=current_user.id if current_user.is_authenticated else None,
                username=current_user.username if current_user.is_authenticated else 'anonymous',
                details={'action': 'acknowledge_alert', 'alert_id': alert_id},
                severity='medium',
                result='failure',
                failure_reason='Requires acknowledge_alerts permission (operator+)'
            )
            toast = ToastManager.error(
                "Permission Denied",
                detail_message="You don't have permission to acknowledge alerts. Operator privileges required."
            )
            return toast, dash.no_update

        try:
            success = db_manager.acknowledge_alert(alert_id)

            if success:
                # Log successful acknowledgment
                security_audit_logger.log(
                    event_type='alert_acknowledged',
                    user_id=current_user.id,
                    username=current_user.username,
                    details={'alert_id': alert_id},
                    severity='low',
                    resource_type='alert',
                    resource_id=str(alert_id),
                    result='success'
                )
                toast = ToastManager.success(
                    "Alert Reviewed",
                    detail_message=f"Alert #{alert_id} has been marked as reviewed."
                )
                return toast, False  # Close the modal
            else:
                toast = ToastManager.error(
                    "Failed to Mark as Reviewed",
                    detail_message="Failed to mark alert as reviewed. Please try again."
                )
                return toast, dash.no_update

        except Exception as e:
            logger.error(f"Error acknowledging alert {alert_id}: {e}")
            toast = ToastManager.error(
                "Error Acknowledging Alert",
                detail_message=f"An error occurred: {str(e)}"
            )
            return toast, dash.no_update

    # Severity filter buttons
    @app.callback(
        Output('alert-filter', 'data'),
        [Input('filter-all', 'n_clicks'), Input('filter-critical', 'n_clicks'),
         Input('filter-high', 'n_clicks'), Input('filter-medium', 'n_clicks'), Input('filter-low', 'n_clicks')]
    )
    def update_alert_filter(*_):
        ctx = callback_context
        if not ctx.triggered:
            return 'all'
        button_id = ctx.triggered[0]['prop_id'].split('.')[0]
        return button_id.split('-')[1]

    # ========================================================================
    # CALLBACKS - AI-POWERED ALERT ANALYSIS
    # ========================================================================

    @app.callback(
        [Output('ai-alert-analysis-collapse', 'is_open'),
         Output('ai-alert-analysis-body', 'children')],
        [Input('ask-ai-alert-btn', 'n_clicks')],
        [State('alert-details-title', 'children')],
        prevent_initial_call=True
    )
    def ask_ai_about_alert(n_clicks, alert_title):
        """
        Generate AI-powered deep analysis of an alert using HybridAI + Smart Recommender.
        """
        if not n_clicks:
            return False, [dbc.Spinner(html.Div("Analyzing alert with AI..."), color="info")]

        try:
            # Extract device from title (format: "🔍 Alert Details: DEVICE_NAME")
            device_identifier = alert_title.split(": ")[-1] if ": " in str(alert_title) else "Unknown"

            # Get the alert from database - device_identifier could be IP or name
            # First try to get device_ip from devices table if it's a name
            cursor = db_manager.conn.cursor()
            cursor.execute(
                "SELECT device_ip FROM devices WHERE device_name = ? OR device_ip = ? OR custom_name = ? LIMIT 1",
                (device_identifier, device_identifier, device_identifier)
            )
            device_row = cursor.fetchone()

            if device_row:
                device_ip_to_search = device_row[0]
            else:
                # Assume it's already an IP
                device_ip_to_search = device_identifier

            # Now get the alert
            cursor.execute(
                "SELECT id, device_ip, severity, explanation, anomaly_score FROM alerts WHERE device_ip = ? ORDER BY timestamp DESC LIMIT 1",
                (device_ip_to_search,)
            )
            alert_result = cursor.fetchone()

            if not alert_result:
                return True, [
                    dbc.Alert("Could not find alert details in database.", color="warning")
                ]

            alert_id = alert_result[0]
            device_ip = alert_result[1]
            severity = alert_result[2]
            explanation = alert_result[3]
            anomaly_score = alert_result[4]

            # Get device name for display
            cursor.execute(
                "SELECT device_name, custom_name FROM devices WHERE device_ip = ?",
                (device_ip,)
            )
            device_row = cursor.fetchone()
            if device_row and (device_row[1] or device_row[0]):
                device_name = device_row[1] or device_row[0]
            else:
                device_name = device_ip

            # Get Smart Recommender analysis
            recommendations = smart_recommender.recommend_for_alert(alert_id)

            # Get attack sequence prediction
            attack_prediction = attack_tracker.predict_next_attack(device_ip)
            device_risk = attack_tracker.get_device_risk_score(device_ip)

            # Build AI context
            context = f"""
            Device: {device_name} ({device_ip})
            Alert Severity: {severity}
            Explanation: {explanation}
            Anomaly Score: {anomaly_score}

            Smart Recommendations: {len(recommendations)} actions suggested
            Attack Risk Score: {device_risk.get('risk_score', 0)}/100 ({device_risk.get('risk_level', 'unknown')})
            """

            if attack_prediction:
                context += f"\nPredicted Next Attack: {attack_prediction.get('predicted_event', 'unknown')} (confidence: {attack_prediction.get('confidence', 0):.2f})"

            # Ask HybridAI for analysis
            prompt = f"Provide a comprehensive security analysis of this alert. What should the user do? Is this a serious threat? Context: {context}"
            ai_response, source = ai_assistant.get_response(prompt=prompt, context=context)

            # Format the response
            analysis_content = [
                # AI Analysis
                dbc.Alert([
                    html.Div([
                        html.I(className="fa fa-brain me-2"),
                        html.Strong("AI Security Analysis"),
                        dbc.Badge(f"SOURCE: {source.upper()}", color="success", className="ms-2 float-end")
                    ], className="mb-3"),
                    dcc.Markdown(ai_response)
                ], color="light", className="mb-3"),

                # Smart Recommendations
                html.H6([html.I(className="fa fa-lightbulb me-2"), "Recommended Actions"], className="mt-3 mb-2"),
                html.Div([
                    dbc.Card([
                        dbc.CardBody([
                            html.Div([
                                dbc.Badge(f"Priority {rec['priority']}",
                                         color="danger" if rec['priority'] == 1 else "warning" if rec['priority'] == 2 else "info",
                                         className="me-2"),
                                html.Strong(rec['action']),
                                dbc.Badge(f"{rec['confidence']*100:.0f}%", color="light", text_color="dark", className="float-end")
                            ], className="mb-2"),
                            html.P(rec['reason'], className="small mb-2"),
                            html.Code(rec.get('command', ''), className="d-block p-2 bg-light") if rec.get('command') else None
                        ])
                    ], className="mb-2")
                    for rec in recommendations[:3]
                ]) if recommendations else html.P("No specific recommendations available.", className="text-muted small"),

                # Attack Prediction
                html.H6([html.I(className="fa fa-bullseye me-2"), "Threat Intelligence"], className="mt-3 mb-2"),
                dbc.Card([
                    dbc.CardBody([
                        html.Div([
                            html.Strong("Device Risk Score: "),
                            dbc.Badge(f"{device_risk['risk_score']}/100",
                                     color="danger" if device_risk['risk_score'] >= 70 else "warning" if device_risk['risk_score'] >= 50 else "success",
                                     className="ms-2"),
                            dbc.Badge(device_risk['risk_level'].upper(), color="secondary", className="ms-2")
                        ], className="mb-2"),
                        html.P(f"Event sequence length: {device_risk.get('event_count', 0)} events", className="small mb-1"),
                        html.P(f"Recent activity: {device_risk.get('recent_events', 0)} events in last hour", className="small mb-1"),
                        html.Div([
                            html.Strong("Predicted Next Attack: "),
                            html.Span(attack_prediction.get('predicted_event', 'Unknown').replace('_', ' ').title(), className="text-danger"),
                            dbc.Badge(f"{attack_prediction.get('confidence', 0):.0%} confident", color="warning", className="ms-2")
                        ], className="mt-2") if attack_prediction else html.P("No attack pattern detected yet.", className="text-muted small")
                    ])
                ], className="border-info")
            ]

            return True, analysis_content

        except Exception as e:
            logger.error(f"Error in AI alert analysis: {e}")
            return True, [
                dbc.Alert(f"Error generating AI analysis: {str(e)}", color="danger")
            ]

    # ========================================================================
    # CALLBACKS - THREAT INTELLIGENCE MODAL
    # ========================================================================

    @app.callback(
        Output("threat-modal", "is_open"),
        [Input("threat-card-btn", "n_clicks"),
         Input("close-threat-intel-modal-btn", "n_clicks")],
        State("threat-modal", "is_open"),
        prevent_initial_call=True
    )
    def toggle_threat_modal(open_clicks, close_clicks, is_open):
        return not is_open

    # Threat Intelligence Overview Tab Callback
    @app.callback(
        [Output('threat-intel-active-threats', 'children'),
         Output('threat-intel-vulnerabilities', 'children'),
         Output('threat-intel-blocked-devices', 'children'),
         Output('threat-intel-threat-level', 'children'),
         Output('threat-intel-distribution-chart', 'figure'),
         Output('threat-intel-recent-threats', 'children'),
         Output('toast-container', 'children', allow_duplicate=True)],
        [Input('threat-modal', 'is_open'),
         Input('refresh-threat-intel-btn', 'n_clicks')],
        prevent_initial_call=True
    )
    def update_threat_intel_overview(is_open, refresh_clicks):
        from dash import callback_context

        # Check if refresh button was clicked
        show_toast = callback_context.triggered[0]['prop_id'] == 'refresh-threat-intel-btn.n_clicks' if callback_context.triggered else False

        if not is_open and not show_toast:
            return dash.no_update, dash.no_update, dash.no_update, dash.no_update, dash.no_update, dash.no_update, dash.no_update

        db = get_db_connection()

        # Count active threats (high severity unacknowledged alerts)
        active_threats = db.execute('''
            SELECT COUNT(*)
            FROM alerts
            WHERE severity IN ('critical', 'high')
              AND acknowledged = 0
        ''').fetchone()[0]

        # Count active vulnerabilities
        vulnerabilities = db.execute('''
            SELECT COUNT(*)
            FROM device_vulnerabilities_detected
            WHERE status = 'active'
        ''').fetchone()[0]

        # Count blocked devices
        blocked_devices = db.execute('''
            SELECT COUNT(*)
            FROM devices
            WHERE is_blocked = 1
        ''').fetchone()[0]

        # Calculate threat level (LOW, MEDIUM, HIGH, CRITICAL)
        total_devices = db.execute('SELECT COUNT(*) FROM devices').fetchone()[0]
        if total_devices > 0:
            threat_ratio = (active_threats + vulnerabilities + blocked_devices) / total_devices
            if threat_ratio > 0.5:
                threat_level = "CRITICAL"
                threat_color = "danger"
            elif threat_ratio > 0.3:
                threat_level = "HIGH"
                threat_color = "warning"
            elif threat_ratio > 0.1:
                threat_level = "MEDIUM"
                threat_color = "info"
            else:
                threat_level = "LOW"
                threat_color = "success"
        else:
            threat_level = "N/A"
            threat_color = "secondary"

        # Threat distribution by severity
        threat_dist = db.execute('''
            SELECT
                severity,
                COUNT(*) as count
            FROM alerts
            WHERE acknowledged = 0
            GROUP BY severity
            ORDER BY
                CASE severity
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    ELSE 5
                END
        ''').fetchall()

        # Prepare data for chart
        if threat_dist:
            severities = [row[0].upper() for row in threat_dist]
            counts = [row[1] for row in threat_dist]
            # Map severities to colors using SEVERITY_COLORS
            colors = [SEVERITY_COLORS.get(sev.lower(), '#6c757d') for sev in severities]
        else:
            severities = []
            counts = []
            colors = []

        # Create pie chart using ChartFactory
        dist_fig = ChartFactory.create_pie_chart(
            labels=severities,
            values=counts,
            colors=colors,
            title='Threat Distribution',
            hole=0.4,
            show_legend=True,
            legend_orientation='v'
        )

        # Recent threats (last 10)
        recent_threats = db.execute('''
            SELECT
                a.explanation,
                a.severity,
                a.device_ip,
                d.device_name,
                a.timestamp
            FROM alerts a
            LEFT JOIN devices d ON a.device_ip = d.device_ip
            WHERE a.acknowledged = 0
            ORDER BY a.timestamp DESC
            LIMIT 10
        ''').fetchall()

        # Build recent threats list
        threat_items = []
        for alert_type, severity, device_ip, device_name, timestamp in recent_threats:
            severity_colors_map = {
                'critical': 'danger',
                'high': 'warning',
                'medium': 'info',
                'low': 'success'
            }

            severity_icons_map = {
                'critical': 'fa-skull-crossbones',
                'high': 'fa-exclamation-triangle',
                'medium': 'fa-info-circle',
                'low': 'fa-check-circle'
            }

            sev_color = severity_colors_map.get(severity, 'secondary')
            sev_icon = severity_icons_map.get(severity, 'fa-info')

            threat_items.append(
                html.Div([
                    html.Div([
                        html.Div([
                            html.I(className=f"fa {sev_icon} me-2 text-{sev_color}"),
                            html.Span(alert_type or "Unknown Threat", className="fw-bold"),
                        ], className="mb-1"),
                        html.Div([
                            dbc.Badge(severity.upper() if severity else "UNKNOWN", color=sev_color, className="me-2"),
                            html.Span(device_name or device_ip, className="text-muted", style={"fontSize": "0.85rem"}),
                            html.Span(f" • {timestamp[:19] if timestamp else 'Unknown'}", className="text-muted", style={"fontSize": "0.8rem"})
                        ])
                    ], className="p-2 mb-2", style={"backgroundColor": "rgba(255,255,255,0.05)", "borderRadius": "5px"})
                ])
            )

        # Create toast if refresh was clicked
        toast = ToastManager.success(
            "Threat intelligence refreshed",
            detail_message=f"{active_threats} active threat(s), {vulnerabilities} vulnerabilities, {blocked_devices} blocked device(s)"
        ) if show_toast else dash.no_update

        return (
            str(active_threats),
            str(vulnerabilities),
            str(blocked_devices),
            html.Span(threat_level, className=f"text-{threat_color}"),
            dist_fig,
            html.Div(threat_items) if threat_items else html.P("No recent threats detected.", className="text-muted text-center"),
            toast
        )

    # Threat Intelligence Feed Tab Callback
    @app.callback(
        [Output('threat-intel-feed-list', 'children'),
         Output('toast-container', 'children', allow_duplicate=True)],
        [Input('threat-modal', 'is_open'),
         Input('threat-intel-tabs', 'active_tab'),
         Input('refresh-threat-intel-btn', 'n_clicks'),
         Input('refresh-threat-feed-btn', 'n_clicks'),
         Input('threat-feed-search-input', 'value'),
         Input('threat-feed-severity-filter', 'value'),
         Input('threat-feed-status-filter', 'value')],
        prevent_initial_call=True
    )
    def update_threat_intel_feed(is_open, active_tab, refresh_clicks, feed_refresh_clicks, search_text, severity_filter, status_filter):
        from dash import callback_context
        ctx = callback_context

        # Check if refresh button was clicked
        show_toast = ctx.triggered and ctx.triggered[0]['prop_id'] in ['refresh-threat-feed-btn.n_clicks', 'refresh-threat-intel-btn.n_clicks'] if ctx.triggered else False

        if not is_open or active_tab != 'threat-intel-feed-tab':
            if show_toast:
                # Return toast even if modal is closed
                return dash.no_update, dash.no_update
            return dash.no_update, dash.no_update

        db = get_db_connection()

        # Get all threats with details including acknowledgement status
        threats = db.execute('''
            SELECT
                a.explanation,
                a.severity,
                a.device_ip,
                d.device_name,
                d.device_type,
                a.timestamp,
                a.explanation,
                a.acknowledged
            FROM alerts a
            LEFT JOIN devices d ON a.device_ip = d.device_ip
            ORDER BY a.timestamp DESC
        ''').fetchall()


        # Apply status filter (active = not acknowledged, resolved = acknowledged)
        if status_filter and status_filter != 'all':
            if status_filter == 'active':
                threats = [t for t in threats if not t[7]]  # acknowledged = 0
            elif status_filter == 'resolved':
                threats = [t for t in threats if t[7]]  # acknowledged = 1

        # Apply severity filter
        if severity_filter and severity_filter != 'all':
            threats = [t for t in threats if t[1] == severity_filter]

        # Apply search filter with None handling - search in IP, botnet name (alert type), malicious domain (details)
        if search_text and search_text.strip():
            search_text = search_text.strip().lower()
            filtered_threats = []
            for threat in threats:
                alert_type = (threat[0] or '').lower()  # botnet name / malicious domain
                device_ip = (threat[2] or '').lower()   # IP address
                device_name = (threat[3] or '').lower()
                details = (threat[6] or '').lower()     # additional details that may contain domains

                if (search_text in alert_type or
                    search_text in device_ip or
                    search_text in device_name or
                    search_text in details):
                    filtered_threats.append(threat)
            threats = filtered_threats

        # Generate toast if refresh was clicked
        toast = ToastManager.success(
            "Threat intelligence refreshed",
            detail_message=f"Displaying {len(threats)} threat(s)"
        ) if show_toast else dash.no_update

        if not threats:
            return html.P("No threat intelligence data available.", className="text-muted text-center"), toast

        # Build threat feed cards
        feed_cards = []
        for alert_type, severity, device_ip, device_name, device_type, timestamp, details, acknowledged in threats:
            severity_colors_map = {
                'critical': 'danger',
                'high': 'warning',
                'medium': 'info',
                'low': 'success'
            }

            severity_icons_map = {
                'critical': 'fa-skull-crossbones',
                'high': 'fa-exclamation-triangle',
                'medium': 'fa-info-circle',
                'low': 'fa-check-circle'
            }

            sev_color = severity_colors_map.get(severity, 'secondary')
            sev_icon = severity_icons_map.get(severity, 'fa-info')

            feed_cards.append(
                dbc.Card([
                    dbc.CardHeader([
                        html.Div([
                            html.Div([
                                html.I(className=f"fa {sev_icon} me-2"),
                                html.Span(alert_type or "Unknown Threat", className="fw-bold")
                            ]),
                            dbc.Badge([
                                html.I(className=f"fa {sev_icon} me-1"),
                                severity.upper() if severity else "UNKNOWN"
                            ], color=sev_color)
                        ], className="d-flex justify-content-between align-items-center")
                    ], className="glass-card-header"),
                    dbc.CardBody([
                        html.Div([
                            html.P([
                                html.I(className="fa fa-laptop me-2"),
                                html.Strong("Device: "),
                                device_name or device_ip
                            ], className="mb-1"),
                            html.P([
                                html.I(className="fa fa-tag me-2"),
                                html.Strong("Type: "),
                                device_type or "Unknown"
                            ], className="mb-1"),
                            html.P([
                                html.I(className="fa fa-clock me-2"),
                                html.Strong("Time: "),
                                timestamp[:19] if timestamp else "Unknown"
                            ], className="mb-2"),
                            html.Hr(className="my-2"),
                            html.P([
                                html.Strong("Details: "),
                                details or "No additional details available."
                            ], className="text-muted mb-0", style={"fontSize": "0.9rem"})
                        ])
                    ], className="p-3")
                ], className="glass-card border-0 shadow-sm mb-2")
            )

        return html.Div(feed_cards), toast

    # Threat Intelligence Attack Patterns Tab Callback
    @app.callback(
        Output('threat-intel-attack-patterns', 'children'),
        [Input('threat-modal', 'is_open'),
         Input('refresh-threat-intel-btn', 'n_clicks')],
        prevent_initial_call=True
    )
    def update_threat_intel_patterns(is_open, refresh_clicks):
        if not is_open:
            return dash.no_update

        db = get_db_connection()

        # Analyze attack patterns
        # 1. Most targeted devices
        targeted_devices = db.execute('''
            SELECT
                d.device_ip,
                d.device_name,
                d.device_type,
                COUNT(*) as alert_count
            FROM alerts a
            JOIN devices d ON a.device_ip = d.device_ip
            GROUP BY d.device_ip
            ORDER BY alert_count DESC
            LIMIT 10
        ''').fetchall()

        # 2. Attack type distribution
        attack_types = db.execute('''
            SELECT
                explanation,
                COUNT(*) as count
            FROM alerts
            GROUP BY explanation
            ORDER BY count DESC
            LIMIT 10
        ''').fetchall()

        # 3. Temporal patterns (attacks by hour)
        temporal_pattern = db.execute('''
            SELECT
                strftime('%H', timestamp) as hour,
                COUNT(*) as count
            FROM alerts
            WHERE timestamp > datetime('now', '-7 days')
            GROUP BY hour
            ORDER BY hour
        ''').fetchall()


        # Build pattern analysis UI
        return html.Div([
            # Most Targeted Devices
            dbc.Card([
                dbc.CardHeader([
                    html.I(className="fa fa-bullseye me-2"),
                    "Most Targeted Devices"
                ], className="glass-card-header"),
                dbc.CardBody([
                    html.Div([
                        html.Div([
                            html.Div([
                                html.I(className="fa fa-laptop me-2"),
                                html.Span(device_name or device_ip, className="fw-bold"),
                                dbc.Badge(f"{alert_count} alerts", color="danger", className="ms-2")
                            ], className="d-flex align-items-center justify-content-between mb-2 p-2",
                               style={"backgroundColor": "rgba(255,255,255,0.05)", "borderRadius": "5px"})
                        ])
                        for device_ip, device_name, device_type, alert_count in targeted_devices
                    ]) if targeted_devices else html.P("No targeted devices detected.", className="text-muted")
                ])
            ], className="glass-card border-0 shadow-sm mb-3"),

            # Attack Type Distribution
            dbc.Card([
                dbc.CardHeader([
                    html.I(className="fa fa-chart-bar me-2"),
                    "Attack Type Distribution"
                ], className="glass-card-header"),
                dbc.CardBody([
                    html.Div([
                        html.Div([
                            html.Div([
                                html.Span(attack_type or "Unknown", className="fw-bold"),
                                dbc.Badge(f"{count} occurrences", color="warning", className="ms-2")
                            ], className="d-flex align-items-center justify-content-between mb-2 p-2",
                               style={"backgroundColor": "rgba(255,255,255,0.05)", "borderRadius": "5px"})
                        ])
                        for attack_type, count in attack_types
                    ]) if attack_types else html.P("No attack types detected.", className="text-muted")
                ])
            ], className="glass-card border-0 shadow-sm mb-3"),

            # Temporal Pattern
            dbc.Card([
                dbc.CardHeader([
                    html.I(className="fa fa-clock me-2"),
                    "Attack Temporal Pattern (Last 7 Days)"
                ], className="glass-card-header"),
                dbc.CardBody([
                    dcc.Graph(
                        figure=ChartFactory.create_bar_chart(
                            x_values=[f"{row[0]}:00" for row in temporal_pattern] if temporal_pattern else [],
                            y_values=[row[1] for row in temporal_pattern] if temporal_pattern else [],
                            colors='#dc3545',
                            x_title='Hour of Day',
                            y_title='Attack Count'
                        ) if temporal_pattern else ChartFactory.create_empty_chart('No attack data available'),
                        config={'displayModeBar': False},
                        style={'height': '300px'}
                    )
                ])
            ], className="glass-card border-0 shadow-sm")
        ])

    # Threat Intelligence Response Tab Callback
    @app.callback(
        Output('threat-intel-response-list', 'children'),
        [Input('threat-modal', 'is_open'),
         Input('refresh-threat-intel-btn', 'n_clicks')],
        prevent_initial_call=True
    )
    def update_threat_intel_response(is_open, refresh_clicks):
        if not is_open:
            return dash.no_update

        db = get_db_connection()

        recommendations = []

        # 1. Check for unacknowledged critical alerts
        critical_alerts = db.execute('''
            SELECT COUNT(*)
            FROM alerts
            WHERE severity = 'critical' AND acknowledged = 0
        ''').fetchone()[0]

        if critical_alerts > 0:
            recommendations.append({
                'priority': 1,
                'title': f'Respond to {critical_alerts} Critical Alerts',
                'severity': 'critical',
                'description': 'Critical security alerts require immediate attention and response.',
                'actions': [
                    'Review each critical alert in detail',
                    'Isolate affected devices from the network',
                    'Investigate root cause and attack vector',
                    'Apply security patches or workarounds',
                    'Document incident for future reference'
                ]
            })

        # 2. Check for active vulnerabilities
        active_vulns = db.execute('''
            SELECT COUNT(DISTINCT v.device_ip)
            FROM device_vulnerabilities_detected v
            WHERE v.status = 'active'
        ''').fetchone()[0]

        if active_vulns > 0:
            recommendations.append({
                'priority': 1,
                'title': f'Patch Vulnerabilities on {active_vulns} Devices',
                'severity': 'high',
                'description': 'Active vulnerabilities provide attack vectors for threat actors.',
                'actions': [
                    'Prioritize CVE vulnerabilities by severity',
                    'Apply available firmware updates',
                    'Implement temporary mitigations for unpatched vulnerabilities',
                    'Schedule regular vulnerability scans',
                    'Monitor vendor security advisories'
                ]
            })

        # 3. Check for blocked devices that are still attempting connections
        blocked_active = db.execute('''
            SELECT COUNT(DISTINCT c.device_ip)
            FROM connections c
            JOIN devices d ON c.device_ip = d.device_ip
            WHERE d.is_blocked = 1
              AND c.timestamp > datetime('now', '-1 hour')
        ''').fetchone()[0]

        if blocked_active > 0:
            recommendations.append({
                'priority': 2,
                'title': f'Investigate {blocked_active} Blocked Devices Still Active',
                'severity': 'high',
                'description': 'Blocked devices are still attempting network connections.',
                'actions': [
                    'Verify firewall rules are properly enforced',
                    'Check for MAC address spoofing attempts',
                    'Review device blocking mechanisms',
                    'Consider physical device removal if necessary',
                    'Update intrusion prevention rules'
                ]
            })

        # 4. Security monitoring recommendations
        total_devices = db.execute('SELECT COUNT(*) FROM devices').fetchone()[0]
        monitored_devices = db.execute('''
            SELECT COUNT(DISTINCT device_ip)
            FROM connections
            WHERE timestamp > datetime('now', '-24 hours')
        ''').fetchone()[0]

        monitoring_coverage = (monitored_devices / total_devices * 100) if total_devices > 0 else 0

        if monitoring_coverage < 80:
            recommendations.append({
                'priority': 3,
                'title': 'Improve Security Monitoring Coverage',
                'severity': 'medium',
                'description': f'Only {monitoring_coverage:.0f}% of devices are actively monitored.',
                'actions': [
                    'Deploy monitoring agents to uncovered devices',
                    'Verify network tap/span configurations',
                    'Enable logging on all IoT devices',
                    'Set up continuous network traffic analysis',
                    'Implement anomaly detection systems'
                ]
            })

        # 5. General threat response best practices
        recommendations.append({
            'priority': 3,
            'title': 'Threat Response Best Practices',
            'severity': 'info',
            'description': 'General recommendations for maintaining strong security posture.',
            'actions': [
                'Establish incident response playbooks',
                'Conduct regular security drills and simulations',
                'Maintain up-to-date threat intelligence feeds',
                'Implement automated threat response where possible',
                'Review and update security policies quarterly',
                'Train staff on security awareness and incident reporting'
            ]
        })


        # Sort by priority
        recommendations.sort(key=lambda x: x['priority'])

        # Build recommendation cards
        recommendation_cards = []
        for rec in recommendations:
            severity_colors = {
                'critical': 'danger',
                'high': 'warning',
                'medium': 'info',
                'low': 'success',
                'info': 'primary'
            }

            severity_icons = {
                'critical': 'fa-skull-crossbones',
                'high': 'fa-exclamation-triangle',
                'medium': 'fa-info-circle',
                'low': 'fa-check-circle',
                'info': 'fa-lightbulb'
            }

            color = severity_colors.get(rec['severity'], 'secondary')
            icon = severity_icons.get(rec['severity'], 'fa-info')

            action_items = [
                html.Li(action, className="mb-1", style={"fontSize": "0.9rem"})
                for action in rec['actions']
            ]

            recommendation_cards.append(
                dbc.Card([
                    dbc.CardHeader([
                        html.Div([
                            html.Div([
                                dbc.Badge(f"Priority {rec['priority']}", color="dark", className="me-2"),
                                dbc.Badge([
                                    html.I(className=f"fa {icon} me-1"),
                                    rec['severity'].upper()
                                ], color=color)
                            ]),
                            html.H6(rec['title'], className="mb-0 mt-2")
                        ])
                    ], className="glass-card-header"),
                    dbc.CardBody([
                        html.P(rec['description'], className="text-muted mb-3"),
                        html.H6([
                            html.I(className="fa fa-tasks me-2"),
                            "Recommended Actions:"
                        ], style={"fontSize": "0.95rem"}, className="mb-2"),
                        html.Ul(action_items, className="mb-0")
                    ])
                ], className="glass-card border-0 shadow-sm mb-3")
            )

        return html.Div(recommendation_cards)

    # ========================================================================
    # CALLBACKS - THREAT MAP & RISK HEATMAP TIMESTAMPS
    # ========================================================================

    # Threat Map Modal - Timestamp Update
    @app.callback(
        [Output('threat-map-timestamp-display', 'children'),
         Output('threat-map-timestamp-store', 'data'),
         Output('toast-container', 'children', allow_duplicate=True)],
        [Input('threat-map-modal', 'is_open'),
         Input('refresh-threat-map-btn', 'n_clicks')],
        prevent_initial_call=True
    )
    def update_threat_map_timestamp(is_open, refresh_clicks):
        """Update timestamp display for Threat Map Modal"""
        from dash import callback_context
        ctx = callback_context

        # Check if refresh button was clicked
        show_toast = ctx.triggered and ctx.triggered[0]['prop_id'] == 'refresh-threat-map-btn.n_clicks' if ctx.triggered else False

        if not is_open:
            raise dash.exceptions.PreventUpdate

        # Get current timestamp
        current_time = datetime.now()
        timestamp_str = current_time.isoformat()

        # Create display element
        display = create_timestamp_display(current_time)

        # Create toast only if refresh was clicked
        toast = ToastManager.success(
            "Threat map refreshed",
            detail_message="Global threat intelligence data updated successfully"
        ) if show_toast else dash.no_update

        return display, timestamp_str, toast

    # Risk Heatmap Modal - Timestamp Update
    @app.callback(
        [Output('risk-heatmap-timestamp-display', 'children'),
         Output('risk-heatmap-timestamp-store', 'data'),
         Output('toast-container', 'children', allow_duplicate=True)],
        [Input('risk-heatmap-modal', 'is_open'),
         Input('refresh-risk-heatmap-btn', 'n_clicks')],
        prevent_initial_call=True
    )
    def update_risk_heatmap_timestamp(is_open, refresh_clicks):
        """Update timestamp display for Risk Heatmap Modal"""
        from dash import callback_context
        ctx = callback_context

        # Check if refresh button was clicked
        show_toast = ctx.triggered and ctx.triggered[0]['prop_id'] == 'refresh-risk-heatmap-btn.n_clicks' if ctx.triggered else False

        if not is_open:
            raise dash.exceptions.PreventUpdate

        # Get current timestamp
        current_time = datetime.now()
        timestamp_str = current_time.isoformat()

        # Create display element
        display = create_timestamp_display(current_time)

        # Create toast only if refresh was clicked
        toast = ToastManager.success(
            "Risk heatmap refreshed",
            detail_message="Risk visualization data updated successfully"
        ) if show_toast else dash.no_update

        return display, timestamp_str, toast

    # ========================================================================
    # CALLBACKS - THREAT MAP & RISK HEATMAP MODALS
    # ========================================================================

    # Toggle callbacks for threat map and risk heatmap modals
    @app.callback(
        Output("threat-map-modal", "is_open"),
        [Input("threat-map-card-btn", "n_clicks"),
         Input("close-threat-map-modal-btn", "n_clicks")],
        State("threat-map-modal", "is_open"),
        prevent_initial_call=True
    )
    def toggle_threat_map_modal(open_clicks, close_clicks, is_open):
        ctx = dash.callback_context
        if not ctx.triggered:
            raise dash.exceptions.PreventUpdate

        trigger_id = ctx.triggered[0]['prop_id'].split('.')[0]

        if trigger_id == 'close-threat-map-modal-btn':
            return False
        if trigger_id == 'threat-map-card-btn' and open_clicks:
            return not is_open
        return is_open

    @app.callback(
        Output("risk-heatmap-modal", "is_open"),
        [Input("risk-heatmap-card-btn", "n_clicks"),
         Input("close-risk-heatmap-modal-btn", "n_clicks")],
        State("risk-heatmap-modal", "is_open"),
        prevent_initial_call=True
    )
    def toggle_risk_heatmap_modal(open_clicks, close_clicks, is_open):
        return not is_open

    # ========================================================================
    # CALLBACKS - AUTO-RESPONSE MODAL
    # ========================================================================

    @app.callback(
        Output("auto-response-modal", "is_open"),
        [Input("auto-response-card-btn", "n_clicks"),
         Input("close-auto-response-modal-btn", "n_clicks")],
        State("auto-response-modal", "is_open"),
        prevent_initial_call=True
    )
    def toggle_auto_response_modal(open_clicks, close_clicks, is_open):
        return not is_open

    # Auto Response Overview Stats
    @app.callback(
        [Output('auto-blocked-count', 'children', allow_duplicate=True),
         Output('auto-alerts-count', 'children', allow_duplicate=True),
         Output('auto-active-rules', 'children'),
         Output('auto-last-action', 'children', allow_duplicate=True),
         Output('auto-response-timeline-chart', 'figure'),
         Output('auto-response-timestamp-display', 'children'),
         Output('auto-response-timestamp-store', 'data'),
         Output('toast-container', 'children', allow_duplicate=True)],
        [Input('auto-response-modal', 'is_open'),
         Input('refresh-auto-response-btn', 'n_clicks')],
        prevent_initial_call=True
    )
    def update_auto_response_overview(is_open, refresh_clicks):
        """Update auto response overview stats."""
        from dash import callback_context
        from datetime import datetime

        # Check if refresh button was clicked
        show_toast = callback_context.triggered[0]['prop_id'] == 'refresh-auto-response-btn.n_clicks'

        toast = ToastManager.success(
            "Auto response data refreshed successfully",
            header="Dashboard Refreshed",
            detail_message="Refreshed Data:\n• Blocked devices count\n• Recent alerts (last 24h)\n• Active response rules\n• Last automated action\n• Response timeline\n\nAll auto-response metrics have been updated."
        ) if show_toast else None

        if not is_open and not show_toast:
            raise dash.exceptions.PreventUpdate

        # Get current timestamp
        current_time = datetime.now()
        timestamp_str = current_time.isoformat()
        timestamp_display = create_timestamp_display(current_time)

        try:
            conn = get_db_connection()

            cursor = conn.cursor()

            # Get blocked devices count
            cursor.execute('SELECT COUNT(*) as count FROM devices WHERE is_blocked = 1')
            blocked_count = cursor.fetchone()['count']

            # Get alerts in last 24 hours
            cursor.execute(f'''
                SELECT COUNT(*) as count
                FROM alerts
                WHERE timestamp > datetime('now', '-24 hours')
            ''')
            alerts_24h = cursor.fetchone()['count']

            # Get active rules count
            cursor.execute('SELECT COUNT(*) as count FROM alert_rules WHERE is_enabled = 1')
            active_rules = cursor.fetchone()['count']

            # Get last triggered rule
            cursor.execute('''
                SELECT last_triggered
                FROM alert_rules
                WHERE last_triggered IS NOT NULL
                ORDER BY last_triggered DESC
                LIMIT 1
            ''')
            last_trigger_row = cursor.fetchone()
            if last_trigger_row and last_trigger_row['last_triggered']:
                last_time = last_trigger_row['last_triggered']
                # Format as relative time
                try:
                    last_dt = datetime.fromisoformat(last_time.replace('Z', '+00:00'))
                    now = datetime.now()
                    diff = now - last_dt
                    if diff.days > 0:
                        last_action = f"{diff.days}d ago"
                    elif diff.seconds > 3600:
                        last_action = f"{diff.seconds // 3600}h ago"
                    else:
                        last_action = f"{diff.seconds // 60}m ago"
                except:
                    last_action = "Recently"
            else:
                last_action = "Never"

            # Get alert timeline for last 7 days
            query_timeline = '''
                SELECT
                    strftime('%Y-%m-%d', timestamp) as date,
                    severity,
                    COUNT(*) as count
                FROM alerts
                WHERE timestamp > datetime('now', '-7 days')
                GROUP BY date, severity
                ORDER BY date
            '''
            cursor.execute(query_timeline)
            timeline_data = cursor.fetchall()

            # Create timeline chart
            if timeline_data:
                # Organize data by severity
                dates = sorted(set(row['date'] for row in timeline_data))
                severities = {'critical': [], 'high': [], 'medium': [], 'low': []}

                for date in dates:
                    for sev in severities.keys():
                        count = sum(row['count'] for row in timeline_data if row['date'] == date and row['severity'] == sev)
                        severities[sev].append(count)

                timeline_fig = ChartFactory.create_stacked_bar_chart(
                    x_values=dates,
                    y_data_list=[severities['critical'], severities['high'], severities['medium'], severities['low']],
                    labels=['Critical', 'High', 'Medium', 'Low'],
                    colors=[SEVERITY_COLORS['critical'], SEVERITY_COLORS['high'], SEVERITY_COLORS['medium'], SEVERITY_COLORS['low']],
                    title='Auto-Response Timeline',
                    x_title='Date',
                    y_title='Alerts'
                )
            else:
                timeline_fig = {}

            return (
                str(blocked_count),
                str(alerts_24h),
                str(active_rules),
                last_action,
                timeline_fig,
                timestamp_display,
                timestamp_str,
                toast
            )

        except Exception as e:
            logger.error(f"Error updating auto response overview: {e}")
            return "—", "—", "—", "—", {}, timestamp_display, timestamp_str, toast

    # Alert Rules Table
    @app.callback(
        Output('alert-rules-table', 'children'),
        [Input('auto-response-modal', 'is_open'),
         Input('refresh-auto-response-btn', 'n_clicks')],
        prevent_initial_call=True
    )
    def update_alert_rules_table(is_open, refresh_clicks):
        """Display configured alert rules."""
        if not is_open:
            raise dash.exceptions.PreventUpdate

        try:
            conn = get_db_connection()

            cursor = conn.cursor()
            cursor.execute('''
                SELECT id, name, description, rule_type, severity, threshold_value,
                       is_enabled, trigger_count, last_triggered
                FROM alert_rules
                ORDER BY is_enabled DESC, severity DESC, name
            ''')
            rules = cursor.fetchall()

            if not rules:
                return dbc.Alert([
                    html.I(className="fa fa-info-circle me-2"),
                    "No alert rules configured yet."
                ], color="info")

            # Create table
            table_rows = []
            for rule in rules:
                severity_color = {
                    'critical': 'danger',
                    'high': 'warning',
                    'medium': 'info',
                    'low': 'success'
                }.get(rule['severity'], 'secondary')

                status_badge = dbc.Badge(
                    "Active" if rule['is_enabled'] else "Disabled",
                    color="success" if rule['is_enabled'] else "secondary"
                )

                table_rows.append(html.Tr([
                    html.Td(html.Strong(rule['name'])),
                    html.Td(rule['description'] or '—'),
                    html.Td(rule['rule_type'].replace('_', ' ').title()),
                    html.Td(dbc.Badge(rule['severity'].upper(), color=severity_color)),
                    html.Td(str(rule['threshold_value']) if rule['threshold_value'] else '—'),
                    html.Td(status_badge),
                    html.Td(str(rule['trigger_count']) if rule['trigger_count'] else '0'),
                    html.Td(html.Small(rule['last_triggered'][:16] if rule['last_triggered'] else 'Never', className="text-muted"))
                ]))

            table = dbc.Table([
                html.Thead(html.Tr([
                    html.Th("Rule Name"),
                    html.Th("Description"),
                    html.Th("Type"),
                    html.Th("Severity"),
                    html.Th("Threshold"),
                    html.Th("Status"),
                    html.Th("Triggers"),
                    html.Th("Last Triggered")
                ])),
                html.Tbody(table_rows)
            ], bordered=True, hover=True, responsive=True, dark=False, className="mb-0 table-adaptive")

            return table

        except Exception as e:
            logger.error(f"Error loading alert rules: {e}")
            return dbc.Alert(f"Error loading rules: {str(e)}", color="danger")

    # Auto Response Action History
    @app.callback(
        Output('auto-response-log', 'children', allow_duplicate=True),
        [Input('auto-response-modal', 'is_open'),
         Input('auto-history-timerange', 'value'),
         Input('refresh-auto-response-btn', 'n_clicks')],
        prevent_initial_call=True
    )
    def update_auto_response_log(is_open, hours, refresh_clicks):
        """Display automated action history."""
        if not is_open:
            raise dash.exceptions.PreventUpdate

        hours = hours or 24  # Default to 24 hours

        try:
            conn = get_db_connection()

            cursor = conn.cursor()

            # Get recent alerts
            query = f'''
                SELECT timestamp, device_ip, severity, anomaly_score, explanation
                FROM alerts
                WHERE timestamp > datetime('now', '-{hours} hours')
                ORDER BY timestamp DESC
                LIMIT 50
            '''
            cursor.execute(query)
            alerts = cursor.fetchall()

            if not alerts:
                return dbc.Alert([
                    html.I(className="fa fa-check-circle me-2"),
                    "No automated actions in the selected time range."
                ], color="success")

            # Create timeline cards
            action_cards = []
            for alert in alerts:
                severity_color = {
                    'critical': 'danger',
                    'high': 'warning',
                    'medium': 'info',
                    'low': 'success'
                }.get(alert['severity'], 'secondary')

                icon_class = {
                    'critical': 'fa-exclamation-circle',
                    'high': 'fa-exclamation-triangle',
                    'medium': 'fa-info-circle',
                    'low': 'fa-check-circle'
                }.get(alert['severity'], 'fa-bell')

                action_cards.append(
                    dbc.Card([
                        dbc.CardBody([
                            dbc.Row([
                                dbc.Col([
                                    html.I(className=f"fa {icon_class} fa-2x text-{severity_color}")
                                ], width="auto"),
                                dbc.Col([
                                    html.Div([
                                        dbc.Badge(alert['severity'].upper(), color=severity_color, className="me-2"),
                                        html.Span(alert['device_ip'], className="fw-bold"),
                                        html.Small(f" • {alert['timestamp'][:16]}", className="text-muted ms-2")
                                    ]),
                                    html.P(alert['explanation'] or 'Automated security action triggered', className="mb-1 mt-2"),
                                    html.Small(f"Anomaly Score: {alert['anomaly_score']:.2f}" if alert['anomaly_score'] else "", className="text-muted")
                                ])
                            ])
                        ], className="py-2")
                    ], className="mb-2 border-0 shadow-sm")
                )

            return html.Div(action_cards)

        except Exception as e:
            logger.error(f"Error loading action history: {e}")
            return dbc.Alert(f"Error loading history: {str(e)}", color="danger")

    # Rule Analytics
    @app.callback(
        Output('rule-analytics-content', 'children'),
        [Input('auto-response-modal', 'is_open'),
         Input('refresh-auto-response-btn', 'n_clicks')],
        prevent_initial_call=True
    )
    def update_rule_analytics(is_open, refresh_clicks):
        """Display rule performance analytics."""
        if not is_open:
            raise dash.exceptions.PreventUpdate

        try:
            conn = get_db_connection()

            cursor = conn.cursor()
            cursor.execute('''
                SELECT name, severity, trigger_count, is_enabled, last_triggered
                FROM alert_rules
                ORDER BY trigger_count DESC
                LIMIT 10
            ''')
            rules = cursor.fetchall()

            if not rules:
                return dbc.Alert("No rule analytics available", color="info")

            # Create analytics cards
            cards = []
            for idx, rule in enumerate(rules):
                severity_color = {
                    'critical': 'danger',
                    'high': 'warning',
                    'medium': 'info',
                    'low': 'success'
                }.get(rule['severity'], 'secondary')

                cards.append(
                    dbc.Card([
                        dbc.CardBody([
                            dbc.Row([
                                dbc.Col([
                                    html.H2(f"#{idx + 1}", className="text-muted mb-0")
                                ], width="auto"),
                                dbc.Col([
                                    html.H6(rule['name'], className="mb-2"),
                                    html.Div([
                                        dbc.Badge(rule['severity'].upper(), color=severity_color, className="me-2"),
                                        dbc.Badge(
                                            "Active" if rule['is_enabled'] else "Disabled",
                                            color="success" if rule['is_enabled'] else "secondary"
                                        )
                                    ]),
                                    html.Div([
                                        html.Strong(f"Triggered {rule['trigger_count'] or 0} times"),
                                        html.Small(f" • Last: {rule['last_triggered'][:16] if rule['last_triggered'] else 'Never'}", className="text-muted ms-2")
                                    ], className="mt-2")
                                ])
                            ])
                        ])
                    ], className="mb-3 glass-card border-0 shadow-sm")
                )

            return html.Div(cards)

        except Exception as e:
            logger.error(f"Error loading rule analytics: {e}")
            return dbc.Alert(f"Error loading analytics: {str(e)}", color="danger")

    # ========================================================================
    # CALLBACKS - GEOGRAPHIC THREAT MAP (GEOLOCATION)
    # ========================================================================

    @app.callback(
        [Output('geographic-threat-map', 'figure'),
         Output('threat-map-total', 'children'),
         Output('threat-map-countries', 'children'),
         Output('toast-container', 'children', allow_duplicate=True)],
        [Input('refresh-interval', 'n_intervals'),
         Input('refresh-threat-map-btn', 'n_clicks')],
        prevent_initial_call=True
    )
    def update_geographic_threat_map(n, refresh_clicks):
        """Update geographic threat map with attack origins."""
        from dash import callback_context
        import requests
        from time import sleep

        # Check if refresh button was clicked (and it's a real click, not page load)
        show_toast = (
            callback_context.triggered and
            callback_context.triggered[0]['prop_id'] == 'refresh-threat-map-btn.n_clicks' and
            refresh_clicks is not None and
            refresh_clicks > 0
        )

        try:
            conn = get_db_connection()
            if not conn:
                toast = ToastManager.error(
                    "Failed to connect to database",
                    detail_message="Unable to establish connection to the database.\n\nPlease check:\n- Database service is running\n- Database file permissions\n- Network connectivity"
                ) if show_toast else dash.no_update
                return go.Figure(), "0 Threats", "0 Countries", toast

            cursor = conn.cursor()

            # Get unique external IPs from connections (potential attack sources)
            cursor.execute('''
                SELECT DISTINCT dest_ip, COUNT(*) as count
                FROM connections
                WHERE timestamp >= datetime("now", "-1 hour")
                AND dest_ip NOT LIKE '192.168.%'
                AND dest_ip NOT LIKE '10.%'
                AND dest_ip NOT LIKE '172.16.%'
                GROUP BY dest_ip
                ORDER BY count DESC
                LIMIT 20
            ''')

            threats = cursor.fetchall()

            if not threats:
                fig = go.Figure()
                fig.update_layout(
                    title="No External Threats Detected",
                    geo=dict(showcountries=True),
                    height=500
                )
                toast = ToastManager.info(
                    "Threat map refreshed - No threats detected",
                    detail_message="No external threats detected in the last hour.\n\nYour network appears to be secure with no suspicious external connections.\n\nThis is good news - continue monitoring for any changes."
                ) if show_toast else dash.no_update
                return fig, "0 Threats", "0 Countries", toast

            # IP-to-location mapping using real geolocation
            locations = []
            for threat in threats:
                # Try to get real geolocation for IP
                try:
                    # Use ip-api.com (free, no API key needed, 45 req/min limit)
                    response = requests.get(
                        f"http://ip-api.com/json/{threat['dest_ip']}?fields=status,country,countryCode,lat,lon,isp",
                        timeout=2
                    )
                    if response.status_code == 200:
                        data = response.json()
                        if data.get('status') == 'success':
                            locations.append({
                                'ip': threat['dest_ip'],
                                'count': threat['count'],
                                'lat': data.get('lat', 0),
                                'lon': data.get('lon', 0),
                                'country': data.get('country', 'Unknown'),
                                'country_code': data.get('countryCode', '??'),
                                'isp': data.get('isp', 'Unknown')
                            })
                            sleep(0.05)  # Rate limiting (max 20 req/sec)
                            continue
                except Exception as e:
                    logger.warning(f"Geolocation failed for {threat['dest_ip']}: {e}")

                # Fallback: Use approximate location for private/invalid IPs
                locations.append({
                    'ip': threat['dest_ip'],
                    'count': threat['count'],
                    'lat': 0,
                    'lon': 0,
                    'country': 'Unknown',
                    'country_code': '??',
                    'isp': 'Unknown'
                })

            # Create map
            fig = go.Figure()

            # Add threat markers with real geolocation data
            fig.add_trace(go.Scattergeo(
                lon=[loc['lon'] for loc in locations],
                lat=[loc['lat'] for loc in locations],
                text=[f"<b>{loc['ip']}</b><br>Country: {loc['country']} ({loc['country_code']})<br>ISP: {loc['isp']}<br>Connections: {loc['count']}"
                      for loc in locations],
                mode='markers',
                marker=dict(
                    size=[min(loc['count'] * 2, 30) for loc in locations],
                    color=[loc['count'] for loc in locations],
                    colorscale='Reds',
                    showscale=True,
                    colorbar=dict(title="Connections"),
                    line=dict(width=0.5, color='rgba(255,255,255,0.8)')
                ),
                name='Threats'
            ))

            fig.update_layout(
                title=dict(
                    text='Global Threat Origins - Last Hour',
                    x=0.5,
                    xanchor='center'
                ),
                geo=dict(
                    projection_type='natural earth',
                    showland=True,
                    landcolor='rgb(243, 243, 243)',
                    coastlinecolor='rgb(204, 204, 204)',
                    showocean=True,
                    oceancolor='rgb(230, 245, 255)',
                    showcountries=True,
                    countrycolor='rgb(204, 204, 204)'
                ),
                height=500,
                margin=dict(l=0, r=0, t=40, b=0)
            )

            unique_countries = len(set([loc['country_code'] for loc in locations if loc['country_code'] != '??']))
            total_threats = sum(loc['count'] for loc in locations)

            toast = ToastManager.success(
                "Threat map refreshed",
                detail_message=f"Threat Map Update Summary:\n\nTotal Threats: {total_threats}\nUnique Countries: {unique_countries}\nTime Period: Last 1 hour\n\nThe global threat map has been updated with the latest attack data."
            ) if show_toast else dash.no_update

            return fig, f"{total_threats} Threats", f"{unique_countries} Countries", toast

        except Exception as e:
            logger.error(f"Error updating geographic threat map: {e}")
            toast = ToastManager.error("Failed to update threat map", detail_message=str(e)) if show_toast else dash.no_update
            return go.Figure(), "Error", "Error", toast

    # Top Countries Tab
    @app.callback(
        Output('threat-map-top-countries', 'children'),
        [Input('threat-map-modal', 'is_open'),
         Input('refresh-threat-map-btn', 'n_clicks'),
         Input('refresh-interval', 'n_intervals')],
        prevent_initial_call=True
    )
    def update_threat_map_top_countries(is_open, refresh_clicks, n):
        """Update Top Countries tab in Threat Map modal."""
        if not is_open:
            raise dash.exceptions.PreventUpdate

        try:
            conn = get_db_connection()

            cursor = conn.cursor()

            # Get external IPs with geolocation
            cursor.execute('''
                SELECT DISTINCT dest_ip, COUNT(*) as count
                FROM connections
                WHERE timestamp >= datetime("now", "-1 hour")
                AND dest_ip NOT LIKE '192.168.%'
                AND dest_ip NOT LIKE '10.%'
                AND dest_ip NOT LIKE '172.16.%'
                GROUP BY dest_ip
                ORDER BY count DESC
                LIMIT 20
            ''')

            threats = cursor.fetchall()

            if not threats:
                return html.P("No external threats detected in the last hour", className="text-muted text-center py-4")

            # Get geolocation for IPs and group by country
            import requests
            from time import sleep

            country_stats = defaultdict(lambda: {'count': 0, 'ips': []})

            for threat in threats:
                try:
                    response = requests.get(
                        f"http://ip-api.com/json/{threat['dest_ip']}?fields=status,country,countryCode",
                        timeout=2
                    )
                    if response.status_code == 200:
                        data = response.json()
                        if data.get('status') == 'success':
                            country = data.get('country', 'Unknown')
                            country_code = data.get('countryCode', '??')
                            country_key = f"{country} ({country_code})"
                            country_stats[country_key]['count'] += threat['count']
                            country_stats[country_key]['ips'].append(threat['dest_ip'])
                            sleep(0.05)
                except Exception as e:
                    logger.warning(f"Geolocation failed for {threat['dest_ip']}: {e}")

            if not country_stats:
                return html.P("Unable to determine country origins", className="text-muted text-center py-4")

            # Sort countries by threat count
            sorted_countries = sorted(country_stats.items(), key=lambda x: x[1]['count'], reverse=True)

            # Build country list
            country_cards = []
            for i, (country, stats) in enumerate(sorted_countries[:10], 1):
                country_cards.append(
                    dbc.Card([
                        dbc.CardBody([
                            html.Div([
                                html.Div([
                                    html.H5(f"#{i}", className="text-muted mb-0"),
                                ], className="me-3"),
                                html.Div([
                                    html.H5(country, className="mb-1"),
                                    html.P([
                                        html.I(className="fa fa-wifi me-2 text-danger"),
                                        f"{stats['count']} connections"
                                    ], className="mb-1 small"),
                                    html.P([
                                        html.I(className="fa fa-server me-2 text-warning"),
                                        f"{len(stats['ips'])} unique IPs"
                                    ], className="mb-0 small text-muted")
                                ], className="flex-grow-1")
                            ], className="d-flex align-items-center")
                        ])
                    ], className="mb-3 border-0 shadow-sm")
                )

            return html.Div(country_cards)

        except Exception as e:
            logger.error(f"Error updating top countries: {e}")
            return html.P(f"Error: {str(e)}", className="text-danger text-center py-4")

    # Attack Timeline Tab
    @app.callback(
        Output('threat-map-details', 'children'),
        [Input('threat-map-modal', 'is_open'),
         Input('refresh-threat-map-btn', 'n_clicks'),
         Input('refresh-interval', 'n_intervals')],
        prevent_initial_call=True
    )
    def update_threat_map_timeline(is_open, refresh_clicks, n):
        """Update Attack Timeline tab in Threat Map modal."""
        if not is_open:
            raise dash.exceptions.PreventUpdate

        try:
            conn = get_db_connection()

            cursor = conn.cursor()

            # Get hourly attack statistics for the last 24 hours
            cursor.execute('''
                SELECT
                    strftime('%H:00', timestamp) as hour,
                    COUNT(DISTINCT dest_ip) as unique_ips,
                    COUNT(*) as total_connections
                FROM connections
                WHERE timestamp >= datetime("now", "-24 hours")
                AND dest_ip NOT LIKE '192.168.%'
                AND dest_ip NOT LIKE '10.%'
                AND dest_ip NOT LIKE '172.16.%'
                GROUP BY strftime('%H', timestamp)
                ORDER BY timestamp DESC
            ''')

            hourly_data = cursor.fetchall()

            if not hourly_data:
                return html.P("No attack data available for the last 24 hours", className="text-muted text-center py-4")

            # Build timeline cards
            timeline_items = []
            for item in hourly_data:
                timeline_items.append(
                    dbc.Card([
                        dbc.CardBody([
                            html.Div([
                                html.Div([
                                    html.I(className="fa fa-clock fa-2x text-warning me-3")
                                ]),
                                html.Div([
                                    html.H5(f"{item['hour']}", className="mb-1"),
                                    html.P([
                                        html.Span([
                                            html.I(className="fa fa-globe me-2 text-danger"),
                                            f"{item['unique_ips']} unique IPs"
                                        ], className="me-3"),
                                        html.Span([
                                            html.I(className="fa fa-wifi me-2 text-info"),
                                            f"{item['total_connections']} connections"
                                        ])
                                    ], className="mb-0 small")
                                ], className="flex-grow-1")
                            ], className="d-flex align-items-center")
                        ])
                    ], className="mb-3 border-0 shadow-sm")
                )

            return html.Div([
                dbc.Alert([
                    html.I(className="fa fa-chart-line me-2"),
                    f"Attack activity over the last 24 hours ({len(hourly_data)} time periods recorded)"
                ], color="info", className="mb-3"),
                html.Div(timeline_items)
            ])

        except Exception as e:
            logger.error(f"Error updating attack timeline: {e}")
            return html.P(f"Error: {str(e)}", className="text-danger text-center py-4")

    # ========================================================================
    # CALLBACKS - DEVICE RISK HEATMAP
    # ========================================================================

    @app.callback(
        [Output('device-risk-heatmap', 'figure'),
         Output('high-risk-count', 'children'),
         Output('medium-risk-count', 'children'),
         Output('low-risk-count', 'children'),
         Output('avg-risk-score', 'children'),
         Output('toast-container', 'children', allow_duplicate=True)],
        [Input('risk-heatmap-modal', 'is_open'),
         Input('refresh-risk-heatmap-btn', 'n_clicks'),
         Input('refresh-interval', 'n_intervals')],
        prevent_initial_call=True
    )
    def update_device_risk_heatmap(is_open, refresh_clicks, n):
        """Update device risk heat map with vulnerability scores."""
        from dash import callback_context

        # Check if refresh button was clicked
        show_toast = callback_context.triggered and callback_context.triggered[0]['prop_id'] == 'refresh-risk-heatmap-btn.n_clicks'

        try:
            conn = get_db_connection()

            cursor = conn.cursor()

            # Calculate risk score for each device
            cursor.execute('''
                SELECT
                    d.device_ip,
                    d.device_name,
                    d.is_trusted,
                    d.is_blocked,
                    (SELECT COUNT(*) FROM alerts WHERE device_ip = d.device_ip
                     AND timestamp >= datetime("now", "-24 hours")) as alert_count,
                    (SELECT COUNT(*) FROM connections WHERE device_ip = d.device_ip
                     AND timestamp >= datetime("now", "-1 hour")) as connection_count
                FROM devices d
                ORDER BY d.last_seen DESC
                LIMIT 50
            ''')

            devices = cursor.fetchall()

            if not devices:
                return go.Figure(), "0", "0", "0", "0"

            # Calculate risk scores
            device_risks = []
            for device in devices:
                # Risk calculation:
                # Base: 0
                # Critical alerts: +30 each
                # Not trusted: +40
                # Is blocked: already identified, score 100
                # High connection count: +10
                risk = 0

                if device['is_blocked']:
                    risk = 100
                else:
                    risk += device['alert_count'] * 15  # Alerts contribute heavily
                    if not device['is_trusted']:
                        risk += 30  # Untrusted devices
                    if device['connection_count'] > 100:
                        risk += 15  # Very active devices

                risk = min(risk, 100)  # Cap at 100

                device_risks.append({
                    'ip': device['device_ip'],
                    'name': device['device_name'] or device['device_ip'].split('.')[-1],
                    'risk': risk,
                    'alerts': device['alert_count'],
                    'connections': device['connection_count']
                })

            # Sort by risk descending
            device_risks.sort(key=lambda x: x['risk'], reverse=True)

            # Create heat map using plotly
            # Organize into grid (e.g., 10 columns)
            grid_cols = 10
            grid_rows = (len(device_risks) + grid_cols - 1) // grid_cols

            z_values = []
            text_values = []
            hover_text = []

            for row in range(grid_rows):
                z_row = []
                text_row = []
                hover_row = []
                for col in range(grid_cols):
                    idx = row * grid_cols + col
                    if idx < len(device_risks):
                        dev = device_risks[idx]
                        z_row.append(dev['risk'])
                        text_row.append(dev['name'])
                        hover_row.append(
                            f"<b>{dev['ip']}</b><br>" +
                            f"Name: {dev['name']}<br>" +
                            f"Risk Score: {dev['risk']}/100<br>" +
                            f"Alerts (24h): {dev['alerts']}<br>" +
                            f"Connections (1h): {dev['connections']}"
                        )
                    else:
                        z_row.append(None)
                        text_row.append("")
                        hover_row.append("")
                z_values.append(z_row)
                text_values.append(text_row)
                hover_text.append(hover_row)

            # Create heatmap
            fig = go.Figure(data=go.Heatmap(
                z=z_values,
                text=text_values,
                hovertext=hover_text,
                hoverinfo='text',
                colorscale=[
                    [0, '#10b981'],      # Green (low risk)
                    [0.5, '#f59e0b'],    # Orange (medium risk)
                    [1, '#ef4444']       # Red (high risk)
                ],
                showscale=True,
                colorbar=dict(
                    title="Risk Score",
                    tickvals=[0, 25, 50, 75, 100],
                    ticktext=['0', '25', '50', '75', '100']
                ),
                texttemplate='%{text}',
                textfont={"size": 10}
            ))

            fig.update_layout(
                title=dict(
                    text=f'Device Risk Assessment - {len(device_risks)} Devices',
                    x=0.5,
                    xanchor='center'
                ),
                xaxis=dict(showticklabels=False, showgrid=False),
                yaxis=dict(showticklabels=False, showgrid=False),
                height=500,
                margin=dict(l=20, r=20, t=60, b=20)
            )

            # Count risk levels
            high_risk = sum(1 for d in device_risks if d['risk'] >= 70)
            medium_risk = sum(1 for d in device_risks if 40 <= d['risk'] < 70)
            low_risk = sum(1 for d in device_risks if d['risk'] < 40)

            # Calculate average risk score
            avg_risk = sum(d['risk'] for d in device_risks) / len(device_risks) if device_risks else 0

            toast = ToastManager.success(
                "Data Updated",
                detail_message="Data Updated"
            ) if show_toast else dash.no_update

            return fig, str(high_risk), str(medium_risk), str(low_risk), f"{avg_risk:.1f}", toast

        except Exception as e:
            logger.error(f"Error updating device risk heatmap: {e}")
            return go.Figure(), "Error", "Error", "Error", "Error", dash.no_update

    # Risk Heat Map - Device Details Tab
    @app.callback(
        Output('risk-device-details', 'children'),
        [Input('risk-heatmap-modal', 'is_open'),
         Input('risk-level-filter', 'value'),
         Input('refresh-risk-heatmap-btn', 'n_clicks')],
        prevent_initial_call=True
    )
    def update_risk_device_details(is_open, risk_filter, refresh_clicks):
        if not is_open:
            return dash.no_update

        try:
            conn = get_db_connection()
            cursor = conn.cursor()

            # Get device risk information
            cursor.execute('''
                SELECT d.device_ip, d.device_name, d.device_type, d.is_trusted, d.is_blocked,
                       (SELECT COUNT(*) FROM alerts WHERE device_ip = d.device_ip
                        AND timestamp >= datetime("now", "-24 hours")) as alert_count,
                       (SELECT COUNT(*) FROM device_vulnerabilities_detected dvd
                        WHERE dvd.device_ip = d.device_ip AND dvd.status = 'active') as vuln_count,
                       (SELECT COUNT(*) FROM connections WHERE device_ip = d.device_ip
                        AND timestamp >= datetime("now", "-1 hour")) as connection_count
                FROM devices d
                ORDER BY d.last_seen DESC
                LIMIT 100
            ''')
            devices = cursor.fetchall()

            if not devices:
                return dbc.Alert([
                    html.I(className="fa fa-info-circle me-2"),
                    "No devices found in the database."
                ], color="info")

            # Calculate risk scores
            device_cards = []
            for device in devices:
                device_ip, device_name, device_type, is_trusted, is_blocked, alert_count, vuln_count, connection_count = device

                # Calculate risk
                risk = 0
                if is_blocked:
                    risk = 100
                else:
                    risk += alert_count * 15
                    risk += vuln_count * 10
                    if not is_trusted:
                        risk += 30
                    if connection_count > 100:
                        risk += 15
                risk = min(risk, 100)

                # Determine risk level
                if risk >= 70:
                    risk_level = 'high'
                    risk_badge = dbc.Badge("HIGH RISK", color="danger", className="me-2")
                    card_class = "border-danger"
                elif risk >= 40:
                    risk_level = 'medium'
                    risk_badge = dbc.Badge("MEDIUM RISK", color="warning", className="me-2")
                    card_class = "border-warning"
                else:
                    risk_level = 'low'
                    risk_badge = dbc.Badge("LOW RISK", color="success", className="me-2")
                    card_class = "border-success"

                # Apply filter
                if risk_filter != 'all' and risk_filter != risk_level:
                    continue

                # Build device card
                device_cards.append(
                    dbc.Card([
                        dbc.CardBody([
                            html.Div([
                                html.H6([
                                    risk_badge,
                                    html.I(className="fa fa-laptop me-2 text-primary"),
                                    html.Span(device_name or device_ip, className="fw-bold")
                                ], className="mb-2"),
                                dbc.Row([
                                    dbc.Col([
                                        dbc.Progress(value=risk, max=100, color="danger" if risk >= 70 else "warning" if risk >= 40 else "success",
                                                    className="mb-2", style={"height": "20px"}),
                                        html.Small([
                                            html.Strong("Risk Score: "), f"{risk}/100", html.Br(),
                                            html.Strong("IP: "), device_ip, html.Br(),
                                            html.Strong("Type: "), device_type or "Unknown", html.Br(),
                                            html.Strong("Alerts (24h): "), str(alert_count), html.Br(),
                                            html.Strong("Vulnerabilities: "), str(vuln_count), html.Br(),
                                            html.Strong("Connections (1h): "), str(connection_count), html.Br(),
                                            html.Strong("Trusted: "), "Yes" if is_trusted else "No", html.Br(),
                                            html.Strong("Blocked: "), "Yes" if is_blocked else "No"
                                        ], className="text-muted")
                                    ], md=12)
                                ])
                            ])
                        ], className="p-3")
                    ], className=f"glass-card {card_class} shadow-sm mb-2")
                )

            if not device_cards:
                return dbc.Alert([
                    html.I(className="fa fa-info-circle me-2"),
                    f"No devices found with {risk_filter} risk level."
                ], color="info")

            return html.Div(device_cards, style={'maxHeight': '500px', 'overflowY': 'auto'})

        except Exception as e:
            logger.error(f"Error loading risk device details: {e}")
            return dbc.Alert(f"Error loading device details: {str(e)}", color="danger")

    # Risk Heat Map - Risk Factors Tab
    @app.callback(
        [Output('risk-factors-chart', 'figure'),
         Output('risk-distribution-chart', 'figure'),
         Output('risk-factors-summary', 'children')],
        [Input('risk-heatmap-modal', 'is_open'),
         Input('refresh-risk-heatmap-btn', 'n_clicks')],
        prevent_initial_call=True
    )
    def update_risk_factors(is_open, refresh_clicks):
        if not is_open:
            return dash.no_update, dash.no_update, dash.no_update

        try:
            conn = get_db_connection()
            cursor = conn.cursor()

            # Get risk factor counts
            cursor.execute('SELECT COUNT(*) FROM devices WHERE is_trusted = 0')
            untrusted_count = cursor.fetchone()[0] or 0

            cursor.execute('SELECT COUNT(*) FROM devices WHERE is_blocked = 1')
            blocked_count = cursor.fetchone()[0] or 0

            cursor.execute('SELECT COUNT(DISTINCT device_ip) FROM alerts WHERE timestamp >= datetime("now", "-24 hours")')
            devices_with_alerts = cursor.fetchone()[0] or 0

            cursor.execute('SELECT COUNT(DISTINCT device_ip) FROM device_vulnerabilities_detected WHERE status = "active"')
            devices_with_vulns = cursor.fetchone()[0] or 0


            # Risk factors bar chart using ChartFactory
            factors_fig = ChartFactory.create_bar_chart(
                x_values=['Untrusted Devices', 'Blocked Devices', 'Recent Alerts', 'Vulnerabilities'],
                y_values=[untrusted_count, blocked_count, devices_with_alerts, devices_with_vulns],
                colors=RISK_COLORS,
                title='Risk Factor Breakdown',
                x_title='Risk Factor',
                y_title='Device Count',
                tick_angle=-30
            )

            # Risk distribution pie chart using ChartFactory
            dist_fig = ChartFactory.create_pie_chart(
                labels=['Untrusted', 'Blocked', 'Alerts', 'Vulnerabilities'],
                values=[untrusted_count, blocked_count, devices_with_alerts, devices_with_vulns],
                colors=RISK_COLORS,
                title='Risk Distribution',
                show_legend=True
            )

            # Summary cards
            summary = html.Div([
                dbc.Row([
                    dbc.Col([
                        dbc.Alert([
                            html.H5([html.I(className="fa fa-exclamation-triangle me-2"), "Risk Factor Analysis"], className="alert-heading"),
                            html.Hr(),
                            html.P([html.Strong(f"{untrusted_count} untrusted devices"), " on the network may pose security risks."]),
                            html.P([html.Strong(f"{blocked_count} devices are currently blocked"), " due to suspected malicious activity."]),
                            html.P([html.Strong(f"{devices_with_alerts} devices triggered alerts"), " in the last 24 hours."]),
                            html.P([html.Strong(f"{devices_with_vulns} devices have active vulnerabilities"), " that need attention."], className="mb-0")
                        ], color="warning")
                    ])
                ])
            ])

            return factors_fig, dist_fig, summary

        except Exception as e:
            logger.error(f"Error loading risk factors: {e}")
            empty_fig = ChartFactory.create_empty_chart('Error loading data')
            return empty_fig, empty_fig, dbc.Alert(f"Error: {str(e)}", color="danger")

    # Risk Heat Map - Remediation Tab
    @app.callback(
        Output('risk-remediation-recommendations', 'children'),
        [Input('risk-heatmap-modal', 'is_open'),
         Input('refresh-risk-heatmap-btn', 'n_clicks')],
        prevent_initial_call=True
    )
    def update_risk_remediation(is_open, refresh_clicks):
        if not is_open:
            return dash.no_update

        try:
            conn = get_db_connection()
            cursor = conn.cursor()

            # Get high risk devices
            cursor.execute('''
                SELECT d.device_ip, d.device_name, d.is_trusted, d.is_blocked,
                       (SELECT COUNT(*) FROM alerts WHERE device_ip = d.device_ip
                        AND timestamp >= datetime("now", "-24 hours")) as alert_count,
                       (SELECT COUNT(*) FROM device_vulnerabilities_detected dvd
                        WHERE dvd.device_ip = d.device_ip AND dvd.status = 'active') as vuln_count
                FROM devices d
                ORDER BY d.last_seen DESC
                LIMIT 50
            ''')
            devices = cursor.fetchall()

            # Calculate risk and identify high-risk devices
            high_risk_devices = []
            for device in devices:
                device_ip, device_name, is_trusted, is_blocked, alert_count, vuln_count = device
                risk = 0
                if is_blocked:
                    risk = 100
                else:
                    risk += alert_count * 15
                    risk += vuln_count * 10
                    if not is_trusted:
                        risk += 30
                risk = min(risk, 100)

                if risk >= 70:
                    high_risk_devices.append({
                        'ip': device_ip,
                        'name': device_name or device_ip,
                        'risk': risk,
                        'alerts': alert_count,
                        'vulns': vuln_count,
                        'trusted': is_trusted,
                        'blocked': is_blocked
                    })

            if not high_risk_devices:
                return dbc.Alert([
                    html.I(className="fa fa-check-circle me-2"),
                    "No high-risk devices detected. Your network security posture is good!"
                ], color="success")

            # Build remediation recommendations
            recommendations = []
            for idx, device in enumerate(sorted(high_risk_devices, key=lambda x: x['risk'], reverse=True)[:10], 1):
                priority_badge = dbc.Badge(f"Priority #{idx}", color="dark", className="me-2")
                risk_badge = dbc.Badge(f"Risk: {device['risk']}/100", color="danger", className="me-2")

                # Build recommendation steps
                steps = []
                if device['blocked']:
                    steps.append(html.Li([html.I(className="fa fa-ban text-danger me-2"), html.Strong("Already Blocked: "), "Device is currently blocked. Investigate and remediate before unblocking."]))
                else:
                    if device['alerts'] > 0:
                        steps.append(html.Li([html.I(className="fa fa-exclamation-triangle text-warning me-2"), html.Strong(f"Review {device['alerts']} Alert(s): "), "Investigate recent alerts to identify attack patterns or anomalies."]))
                    if device['vulns'] > 0:
                        steps.append(html.Li([html.I(className="fa fa-bug text-danger me-2"), html.Strong(f"Patch {device['vulns']} Vulnerabilit(ies): "), "Update firmware/software to address known CVE vulnerabilities."]))
                    if not device['trusted']:
                        steps.append(html.Li([html.I(className="fa fa-shield-alt text-info me-2"), html.Strong("Mark as Trusted: "), "Verify device legitimacy and mark as trusted if authorized."]))

                    steps.extend([
                        html.Li([html.I(className="fa fa-network-wired text-primary me-2"), html.Strong("Network Segmentation: "), "Move to isolated VLAN with restricted access."]),
                        html.Li([html.I(className="fa fa-eye text-info me-2"), html.Strong("Enhanced Monitoring: "), "Enable detailed logging and traffic analysis."]),
                        html.Li([html.I(className="fa fa-ban text-danger me-2"), html.Strong("Consider Blocking: "), "If threat persists, block device pending investigation."])
                    ])

                recommendations.append(
                    dbc.Card([
                        dbc.CardHeader([
                            priority_badge,
                            risk_badge,
                            html.I(className="fa fa-laptop me-2"),
                            html.Span(device['name'], className="fw-bold")
                        ], className="glass-card-header"),
                        dbc.CardBody([
                            html.P([html.Strong("IP Address: "), device['ip']], className="mb-2"),
                            html.H6("Recommended Actions:", className="mb-2"),
                            html.Ul(steps, className="mb-0")
                        ], className="p-3")
                    ], className="glass-card border-0 shadow-sm mb-3")
                )

            return html.Div(recommendations, style={'maxHeight': '500px', 'overflowY': 'auto'})

        except Exception as e:
            logger.error(f"Error loading risk remediation: {e}")
            return dbc.Alert(f"Error loading recommendations: {str(e)}", color="danger")

    # ========================================================================
    # INTERVAL-BASED AUTO-RESPONSE DASHBOARD
    # ========================================================================

    @app.callback(
        [Output('auto-blocked-count', 'children', allow_duplicate=True),
         Output('auto-alerts-count', 'children', allow_duplicate=True),
         Output('auto-last-action', 'children', allow_duplicate=True),
         Output('auto-response-log', 'children', allow_duplicate=True)],
        [Input('refresh-interval', 'n_intervals')],
        prevent_initial_call=True
    )
    def update_automated_response_dashboard(n):
        """Display automated security actions taken by the system."""
        try:
            conn = get_db_connection()

            cursor = conn.cursor()

            # Count blocked devices
            cursor.execute('SELECT COUNT(*) as count FROM devices WHERE is_blocked = 1')
            blocked_count = cursor.fetchone()['count']

            # Count alerts generated (last 24 hours)
            cursor.execute('SELECT COUNT(*) as count FROM alerts WHERE timestamp >= datetime("now", "-24 hours")')
            alerts_count = cursor.fetchone()['count']

            # Total automated actions (blocks + alerts)
            total_actions = blocked_count + alerts_count

            # Get last action timestamp
            cursor.execute('''
                SELECT MAX(timestamp) as last_time FROM (
                    SELECT timestamp FROM alerts WHERE timestamp >= datetime("now", "-24 hours")
                    UNION ALL
                    SELECT first_seen as timestamp FROM devices WHERE is_blocked = 1
                )
            ''')
            result = cursor.fetchone()
            if result and result['last_time']:
                from datetime import datetime
                last_time = datetime.fromisoformat(result['last_time'])
                now = datetime.now()
                diff = now - last_time
                if diff.total_seconds() < 60:
                    last_action = "Just now"
                elif diff.total_seconds() < 3600:
                    last_action = f"{int(diff.total_seconds() / 60)}m ago"
                else:
                    last_action = f"{int(diff.total_seconds() / 3600)}h ago"
            else:
                last_action = "N/A"

            # Get recent automated actions
            actions_log = []

            # Get recent blocks
            cursor.execute('''
                SELECT device_ip, device_name, first_seen FROM devices
                WHERE is_blocked = 1
                ORDER BY first_seen DESC
                LIMIT 10
            ''')
            blocked_devices = cursor.fetchall()

            for device in blocked_devices:
                actions_log.append({
                    'type': 'block',
                    'timestamp': device['first_seen'],
                    'description': f"Blocked device {device['device_ip']}" + (f" ({device['device_name']})" if device['device_name'] else ""),
                    'severity': 'danger'
                })

            # Get recent critical alerts
            cursor.execute('''
                SELECT device_ip, severity, timestamp, explanation
                FROM alerts
                WHERE timestamp >= datetime("now", "-24 hours")
                ORDER BY timestamp DESC
                LIMIT 15
            ''')
            recent_alerts = cursor.fetchall()

            for alert in recent_alerts:
                actions_log.append({
                    'type': 'alert',
                    'timestamp': alert['timestamp'],
                    'description': f"Alert on {alert['device_ip']}: {alert['explanation']}",
                    'severity': alert['severity']
                })

            # Sort all actions by timestamp
            actions_log.sort(key=lambda x: x['timestamp'], reverse=True)
            actions_log = actions_log[:20]  # Limit to 20 most recent

            # Build action log display
            if actions_log:
                log_items = []
                for action in actions_log:
                    severity_colors = {
                        'critical': 'danger',
                        'high': 'warning',
                        'medium': 'info',
                        'low': 'secondary',
                        'danger': 'danger'
                    }
                    color = severity_colors.get(action['severity'], 'secondary')

                    icon_class = "fa-shield-alt" if action['type'] == 'block' else "fa-exclamation-triangle"

                    log_items.append(
                        dbc.ListGroupItem([
                            html.Div([
                                html.Div([
                                    html.I(className=f"fa {icon_class} me-2", style={"color": f"var(--bs-{color})"}),
                                    html.Span(action['description'], className="flex-grow-1")
                                ], className="d-flex align-items-start mb-1"),
                                html.Small(action['timestamp'], className="text-muted")
                            ])
                        ], className="border-start border-3", style={"borderColor": f"var(--bs-{color}) !important"})
                    )

                log_display = dbc.ListGroup(log_items, flush=True)
            else:
                log_display = dbc.Alert("No automated actions recorded yet.", color="info")


            return str(blocked_count), str(alerts_count), last_action, log_display

        except Exception as e:
            logger.error(f"Error loading automated response dashboard: {e}")
            error_display = html.P(f"Error: {str(e)}", className="text-danger")
            return "0", "0", "Error", error_display

    # ========================================================================
    # INTERVAL-BASED VULNERABILITY SCANNER
    # ========================================================================

    @app.callback(
        [Output('vuln-critical-count', 'children', allow_duplicate=True),
         Output('vuln-high-count', 'children', allow_duplicate=True)],
        [Input('refresh-interval', 'n_intervals')],
        prevent_initial_call=True
    )
    def update_vulnerability_scanner(n):
        """Scan devices for known vulnerabilities and security issues."""
        try:
            conn = get_db_connection()

            cursor = conn.cursor()

            # Get all devices
            cursor.execute('SELECT device_ip, device_name, device_type FROM devices')
            devices = cursor.fetchall()

            vulnerabilities = []

            for device in devices:
                device_vulns = []

                # Check for insecure ports from connections
                cursor.execute('''
                    SELECT DISTINCT dest_port FROM connections
                    WHERE device_ip = ?
                    AND timestamp >= datetime("now", "-24 hours")
                ''', (device['device_ip'],))
                ports = [row['dest_port'] for row in cursor.fetchall()]

                # Telnet (port 23) - Critical vulnerability
                if 23 in ports:
                    device_vulns.append({
                        'severity': 'critical',
                        'cve': 'INSECURE-TELNET',
                        'title': 'Unencrypted Telnet Protocol',
                        'description': 'Device uses insecure Telnet protocol (port 23). Credentials can be intercepted.',
                        'recommendation': 'Disable Telnet and use SSH (port 22) instead'
                    })

                # FTP (port 21) - High vulnerability
                if 21 in ports:
                    device_vulns.append({
                        'severity': 'high',
                        'cve': 'INSECURE-FTP',
                        'title': 'Unencrypted FTP Protocol',
                        'description': 'Device uses insecure FTP protocol. Use SFTP or FTPS.',
                        'recommendation': 'Switch to SFTP (port 22) or FTPS (port 990)'
                    })

                # HTTP (port 80) - Medium vulnerability
                if 80 in ports:
                    device_vulns.append({
                        'severity': 'medium',
                        'cve': 'INSECURE-HTTP',
                        'title': 'Unencrypted HTTP Protocol',
                        'description': 'Device uses HTTP without encryption. Use HTTPS.',
                        'recommendation': 'Enable HTTPS (port 443) for secure communication'
                    })

                # Check for common IoT device vulnerabilities by type
                if device['device_type']:
                    device_type_lower = device['device_type'].lower()

                    # IP Camera vulnerabilities
                    if 'camera' in device_type_lower or 'cam' in device_type_lower:
                        device_vulns.append({
                            'severity': 'high',
                            'cve': 'CVE-2021-36260',
                            'title': 'IP Camera Default Credentials',
                            'description': 'Many IP cameras ship with default credentials that are publicly known.',
                            'recommendation': 'Change default admin password immediately'
                        })

                    # Smart TV vulnerabilities
                    if 'tv' in device_type_lower or 'television' in device_type_lower:
                        device_vulns.append({
                            'severity': 'medium',
                            'cve': 'CVE-2020-27403',
                            'title': 'Smart TV Privacy Concerns',
                            'description': 'Smart TVs may collect viewing data and transmit to external servers.',
                            'recommendation': 'Review privacy settings and disable tracking'
                        })

                    # Router vulnerabilities
                    if 'router' in device_type_lower or 'gateway' in device_type_lower:
                        device_vulns.append({
                            'severity': 'critical',
                            'cve': 'CVE-2022-26318',
                            'title': 'Router Firmware Vulnerabilities',
                            'description': 'Routers with outdated firmware are vulnerable to remote code execution.',
                            'recommendation': 'Update router firmware to latest version'
                        })

                    # IoT Hub vulnerabilities
                    if 'hub' in device_type_lower or 'bridge' in device_type_lower:
                        device_vulns.append({
                            'severity': 'high',
                            'cve': 'CVE-2021-33041',
                            'title': 'IoT Hub Authentication Bypass',
                            'description': 'Some IoT hubs have weak authentication mechanisms.',
                            'recommendation': 'Enable strong authentication and 2FA if available'
                        })

                # Add device vulnerabilities to main list
                for vuln in device_vulns:
                    vuln['device_ip'] = device['device_ip']
                    vuln['device_name'] = device['device_name'] or device['device_ip']
                    vulnerabilities.append(vuln)


            # Count vulnerabilities by severity
            critical_count = len([v for v in vulnerabilities if v['severity'] == 'critical'])
            high_count = len([v for v in vulnerabilities if v['severity'] == 'high'])

            return str(critical_count), str(high_count)

        except Exception as e:
            logger.error(f"Error running vulnerability scan: {e}")
            return "0", "0"

    # ========================================================================
    # INTERVAL-BASED API INTEGRATION STATUS
    # ========================================================================

    @app.callback(
        Output('api-integration-status', 'children'),
        [Input('refresh-interval', 'n_intervals')]
    )
    def update_api_integration_hub(n):
        """Display status of external API integrations with real connectivity checks."""
        try:
            import requests as req_lib

            def check_api_health(api_name, test_url, headers=None, timeout=2):
                """Check if API is reachable and responding."""
                try:
                    response = req_lib.get(test_url, headers=headers, timeout=timeout)
                    if response.status_code in [200, 401, 403]:  # 401/403 means API exists but needs auth
                        return 'connected', 'success'
                    return 'error', 'danger'
                except:
                    return 'not_configured', 'warning'

            # Check actual API connectivity
            api_integrations = []

            # AbuseIPDB - Check from environment or config (FREE tier: 1000 queries/day)
            abuseipdb_key = os.getenv('THREAT_INTELLIGENCE_ABUSEIPDB_API_KEY') or os.getenv('ABUSEIPDB_API_KEY')
            if not abuseipdb_key:
                try:
                    abuseipdb_key = config.get('threat_intel', 'abuseipdb_key')
                except:
                    pass

            if abuseipdb_key and abuseipdb_key != 'your_abuseipdb_key_here': # pragma: allowlist secret
                status, color = check_api_health(
                    'AbuseIPDB',
                    'https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8',
                    headers={'Key': abuseipdb_key, 'Accept': 'application/json'}
                )
            else:
                status, color = 'not_configured', 'warning'

            api_integrations.append({
                'name': 'AbuseIPDB',
                'status': status,
                'description': 'IP reputation (FREE: 1000/day)',
                'icon': 'fa-database',
                'color': color,
                'signup_url': 'https://www.abuseipdb.com/register',
                'env_var': 'THREAT_INTELLIGENCE_ABUSEIPDB_API_KEY'
            })

            # VirusTotal - Check for API key in environment (FREE tier: 4 requests/minute)
            vt_key = os.getenv('VIRUSTOTAL_API_KEY')
            if vt_key:
                status, color = check_api_health(
                    'VirusTotal',
                    'https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8',
                    headers={'x-apikey': vt_key}
                )
            else:
                status, color = 'not_configured', 'warning'
            api_integrations.append({
                'name': 'VirusTotal',
                'status': status,
                'description': 'Malware scanning (FREE: 4 req/min)',
                'icon': 'fa-virus',
                'color': color,
                'signup_url': 'https://www.virustotal.com/gui/join-us',
                'env_var': 'VIRUSTOTAL_API_KEY'
            })

            # Shodan - Check for API key (FREE tier: 100 queries/month)
            shodan_key = os.getenv('SHODAN_API_KEY')
            if shodan_key:
                status, color = check_api_health(
                    'Shodan',
                    f'https://api.shodan.io/api-info?key={shodan_key}'
                )
            else:
                status, color = 'not_configured', 'warning'
            api_integrations.append({
                'name': 'Shodan',
                'status': status,
                'description': 'IoT search (FREE: 100/month)',
                'icon': 'fa-search',
                'color': color,
                'signup_url': 'https://account.shodan.io/register',
                'env_var': 'SHODAN_API_KEY'
            })

            # AlienVault OTX - Check for API key (100% FREE)
            otx_key = os.getenv('OTX_API_KEY')
            if otx_key:
                # Use a better endpoint that works with new accounts
                status, color = check_api_health(
                    'OTX',
                    'https://otx.alienvault.com/api/v1/indicators/IPv4/8.8.8.8/general',
                    headers={'X-OTX-API-KEY': otx_key}
                )
            else:
                status, color = 'not_configured', 'warning'
            api_integrations.append({
                'name': 'AlienVault OTX',
                'status': status,
                'description': 'Open threat exchange (100% FREE)',
                'icon': 'fa-exchange-alt',
                'color': color,
                'signup_url': 'https://otx.alienvault.com/accounts/signup',
                'env_var': 'OTX_API_KEY'
            })

            # GreyNoise - Check for API key (FREE tier: 50 queries/day)
            greynoise_key = os.getenv('GREYNOISE_API_KEY')
            if greynoise_key:
                status, color = check_api_health(
                    'GreyNoise',
                    'https://api.greynoise.io/v3/community/8.8.8.8',
                    headers={'key': greynoise_key}
                )
            else:
                status, color = 'not_configured', 'warning'
            api_integrations.append({
                'name': 'GreyNoise',
                'status': status,
                'description': 'Internet scanner intel (FREE: 50/day)',
                'icon': 'fa-radar',
                'color': color,
                'signup_url': 'https://www.greynoise.io/signup',
                'env_var': 'GREYNOISE_API_KEY'
            })

            # IPinfo - Check for API key (FREE tier: 50k queries/month)
            ipinfo_key = os.getenv('IPINFO_API_KEY')
            if ipinfo_key:
                status, color = check_api_health(
                    'IPinfo',
                    f'https://ipinfo.io/8.8.8.8?token={ipinfo_key}'
                )
            else:
                status, color = 'not_configured', 'warning'
            api_integrations.append({
                'name': 'IPinfo',
                'status': status,
                'description': 'IP geolocation (FREE: 50k/month)',
                'icon': 'fa-map-marked-alt',
                'color': color,
                'signup_url': 'https://ipinfo.io/signup',
                'env_var': 'IPINFO_API_KEY'
            })

            # MITRE ATT&CK - Public resource (100% FREE, no API key needed)
            status, color = check_api_health('MITRE', 'https://attack.mitre.org/')
            api_integrations.append({
                'name': 'MITRE ATT&CK',
                'status': status,
                'description': 'Threat framework (100% FREE, no key)',
                'icon': 'fa-shield-alt',
                'color': color,
                'signup_url': None,
                'env_var': None
            })

            api_cards = []
            for api in api_integrations:
                status_text = {
                    'connected': '✓ Connected',
                    'not_configured': 'Configure',
                    'error': '✗ Connection Failed'
                }.get(api['status'], api['status'].title())

                status_badge = dbc.Badge(
                    status_text,
                    color=api['color'],
                    className="ms-2",
                    pill=True
                )

                # Build card content
                card_content = [
                    html.Div([
                        html.I(className=f"fa {api['icon']} fa-2x text-{api['color']} me-3"),
                        html.Div([
                            html.H5([api['name'], status_badge], className="mb-1"),
                            html.P(api['description'], className="mb-0 text-muted small")
                        ], style={'flex': '1'})
                    ], className="d-flex align-items-center")
                ]

                # Add configuration instructions if not configured
                if api['status'] == 'not_configured' and api.get('env_var'):
                    card_content.append(
                        html.Div([
                            html.Hr(className="my-2"),
                            html.Div([
                                html.Strong("To configure:", className="text-primary small"),
                                html.Ol([
                                    html.Li([
                                        "Sign up: ",
                                        html.A("Get API Key", href=api['signup_url'], target="_blank", className="text-decoration-none")
                                    ], className="small mb-1"),
                                    html.Li([
                                        "Add to .env file: ",
                                        html.Code(f"{api['env_var']}=your_key_here", className="bg-light px-2 py-1 rounded")
                                    ], className="small mb-1"),
                                    html.Li("Restart dashboard", className="small")
                                ], className="mb-0 ps-3", style={'fontSize': '0.85rem'})
                            ], className="bg-light p-2 rounded")
                        ])
                    )
                elif api['status'] == 'connected':
                    card_content.append(
                        html.Div([
                            html.Hr(className="my-2"),
                            html.Div([
                                html.I(className="fa fa-check-circle text-success me-2"),
                                html.Span("API is active and responding", className="small text-success")
                            ])
                        ])
                    )
                elif api['status'] == 'error' and api.get('env_var'):
                    card_content.append(
                        html.Div([
                            html.Hr(className="my-2"),
                            html.Div([
                                html.I(className="fa fa-exclamation-triangle text-danger me-2"),
                                html.Span("Check API key or network connection", className="small text-danger")
                            ])
                        ])
                    )

                api_cards.append(
                    dbc.Card([
                        dbc.CardBody(card_content)
                    ], className="mb-3 border-0 shadow-sm hover-card")
                )

            return html.Div(api_cards)

        except Exception as e:
            logger.error(f"Error loading API integration status: {e}")
            return html.P(f"Error: {str(e)}", className="text-danger")

    # ========================================================================
    # INTERVAL-BASED BENCHMARK COMPARISON
    # ========================================================================

    @app.callback(
        Output('benchmark-comparison', 'children'),
        [Input('refresh-interval', 'n_intervals')]
    )
    def update_benchmark_comparison(n):
        """Compare network security metrics against industry standards."""
        try:
            conn = get_db_connection()

            cursor = conn.cursor()

            # Calculate current metrics
            cursor.execute('SELECT COUNT(*) as count FROM devices')
            device_count = cursor.fetchone()['count']

            cursor.execute('SELECT COUNT(*) as count FROM alerts WHERE timestamp >= datetime("now", "-24 hours")')
            alerts_24h = cursor.fetchone()['count']

            cursor.execute('SELECT COUNT(*) as count FROM devices WHERE is_blocked = 1')
            blocked_devices = cursor.fetchone()['count']


            # Industry benchmarks (simulated)
            benchmarks = [
                {
                    'metric': 'Device Inventory',
                    'your_value': device_count,
                    'industry_avg': 15,
                    'best_practice': 'Maintain complete device inventory',
                    'status': 'good' if device_count > 0 else 'poor'
                },
                {
                    'metric': 'Alert Rate (per day)',
                    'your_value': alerts_24h,
                    'industry_avg': 5,
                    'best_practice': 'Lower is better - indicates fewer threats',
                    'status': 'good' if alerts_24h <= 10 else 'poor' if alerts_24h > 20 else 'average'
                },
                {
                    'metric': 'Blocked Devices',
                    'your_value': blocked_devices,
                    'industry_avg': 2,
                    'best_practice': 'Actively block malicious devices',
                    'status': 'good' if blocked_devices > 0 else 'poor'
                },
                {
                    'metric': 'Update Frequency',
                    'your_value': 'Real-time',
                    'industry_avg': 'Hourly',
                    'best_practice': 'Monitor continuously',
                    'status': 'excellent'
                }
            ]

            benchmark_cards = []
            for benchmark in benchmarks:
                status_colors = {
                    'excellent': 'success',
                    'good': 'success',
                    'average': 'warning',
                    'poor': 'danger'
                }
                color = status_colors.get(benchmark['status'], 'secondary')

                benchmark_cards.append(
                    dbc.Card([
                        dbc.CardBody([
                            html.H6(benchmark['metric'], className="mb-3"),
                            dbc.Row([
                                dbc.Col([
                                    html.Div([
                                        html.Small("Your Network", className="text-muted d-block"),
                                        html.H4(str(benchmark['your_value']), className=f"text-{color} mb-0")
                                    ])
                                ], width=6),
                                dbc.Col([
                                    html.Div([
                                        html.Small("Industry Average", className="text-muted d-block"),
                                        html.H4(str(benchmark['industry_avg']), className="text-muted mb-0")
                                    ])
                                ], width=6)
                            ]),
                            html.Hr(),
                            html.P([
                                html.I(className="fa fa-lightbulb me-2 text-warning"),
                                html.Small(benchmark['best_practice'], className="text-muted")
                            ], className="mb-0")
                        ])
                    ], className="mb-3 border-0 shadow-sm")
                )

            return html.Div(benchmark_cards)

        except Exception as e:
            logger.error(f"Error loading benchmark comparison: {e}")
            return html.P(f"Error: {str(e)}", className="text-danger")

    # ========================================================================
    # INTERVAL-BASED PERFORMANCE ANALYTICS
    # ========================================================================

    @app.callback(
        [Output('perf-avg-latency', 'children', allow_duplicate=True),
         Output('perf-throughput', 'children', allow_duplicate=True),
         Output('perf-packet-loss', 'children', allow_duplicate=True),
         Output('performance-graph', 'figure', allow_duplicate=True)],
        [Input('refresh-interval', 'n_intervals')],
        prevent_initial_call=True
    )
    def update_performance_analytics(n):
        """Display network performance metrics."""
        try:
            conn = get_db_connection()
            if not conn:
                empty_fig = go.Figure()
                return "N/A", "N/A", "N/A", empty_fig

            cursor = conn.cursor()

            # Calculate performance metrics from connection data
            cursor.execute('''
                SELECT
                    AVG(bytes_sent + bytes_received) as avg_bytes,
                    AVG(duration) as avg_duration,
                    COUNT(*) as conn_count,
                    MIN(timestamp) as first_conn,
                    MAX(timestamp) as last_conn,
                    SUM(CASE WHEN conn_state IN ('S0', 'REJ', 'RSTO', 'RSTOS0', 'RSTR') THEN 1 ELSE 0 END) as failed_conns
                FROM connections
                WHERE timestamp >= datetime("now", "-1 hour")
            ''')
            result = cursor.fetchone()

            # Calculate real latency from connection duration (if available)
            if result['avg_duration'] and result['avg_duration'] > 0:
                avg_latency_ms = result['avg_duration'] * 1000  # Convert seconds to ms
                avg_latency = f"{avg_latency_ms:.1f}ms"
            else:
                avg_latency = "N/A"  # Not available from current data

            # Calculate throughput
            if result['avg_bytes'] and result['conn_count']:
                throughput_mbps = (result['avg_bytes'] * result['conn_count'] * 8) / (1024 * 1024 * 3600)  # Convert to Mbps
                throughput = f"{throughput_mbps:.2f} Mbps"
            else:
                throughput = "0 Mbps"

            # Calculate packet loss approximation from failed connections
            if result['conn_count'] and result['conn_count'] > 0:
                loss_rate = (result['failed_conns'] / result['conn_count']) * 100
                packet_loss = f"{loss_rate:.2f}%"
            else:
                packet_loss = "N/A"

            # Generate performance graph
            cursor.execute('''
                SELECT
                    strftime('%H:%M', timestamp) as time_bucket,
                    COUNT(*) as conn_count,
                    AVG(bytes_sent + bytes_received) as avg_size
                FROM connections
                WHERE timestamp >= datetime("now", "-1 hour")
                GROUP BY strftime('%H:%M', timestamp)
                ORDER BY timestamp
            ''')
            perf_data = cursor.fetchall()


            if perf_data:
                fig = go.Figure()

                fig.add_trace(go.Scatter(
                    x=[row['time_bucket'] for row in perf_data],
                    y=[row['conn_count'] for row in perf_data],
                    mode='lines+markers',
                    name='Connections/min',
                    line=dict(color='#3b82f6', width=2),
                    marker=dict(size=6)
                ))

                fig.update_layout(
                    title="Network Activity (Last Hour)",
                    xaxis_title="Time",
                    yaxis_title="Connections",
                    template='plotly_white',
                    height=300,
                    showlegend=False
                )
            else:
                fig = go.Figure()
                fig.update_layout(
                    title="No performance data available",
                    xaxis=dict(visible=False),
                    yaxis=dict(visible=False),
                    template='plotly_white',
                    height=300
                )

            return avg_latency, throughput, packet_loss, fig

        except Exception as e:
            logger.error(f"Error loading performance analytics: {e}")
            empty_fig = go.Figure()
            empty_fig.update_layout(title=f"Error: {str(e)}")
            return "Error", "Error", "Error", empty_fig

    # ========================================================================
    # CROSS-CHART FILTERING CALLBACKS
    # ========================================================================

    @app.callback(
        Output('global-severity-filter', 'data'),
        Input('alert-timeline', 'clickData'),
        prevent_initial_call=True
    )
    def filter_by_severity_from_timeline(click_data):
        """When user clicks on alert timeline, filter all charts by that severity."""
        if not click_data:
            return None

        try:
            # Extract severity from the clicked bar
            severity = click_data['points'][0]['fullData']['name']
            logger.info(f"Cross-chart filter activated: severity={severity}")
            return severity
        except (KeyError, IndexError) as e:
            logger.error(f"Error extracting severity from click data: {e}")
            return None

    @app.callback(
        Output('global-device-filter', 'data'),
        Input('device-heatmap', 'clickData'),
        prevent_initial_call=True
    )
    def filter_by_device_from_heatmap(click_data):
        """When user clicks on device heatmap, filter all charts by that device."""
        if not click_data:
            return None

        try:
            # Extract device IP from the clicked cell
            device_ip = click_data['points'][0]['y']
            logger.info(f"Cross-chart filter activated: device_ip={device_ip}")
            return device_ip
        except (KeyError, IndexError) as e:
            logger.error(f"Error extracting device IP from click data: {e}")
            return None

    @app.callback(
        Output('toast-container', 'children', allow_duplicate=True),
        [Input('global-severity-filter', 'data'),
         Input('global-device-filter', 'data')],
        prevent_initial_call=True
    )
    def show_filter_notification(severity_filter, device_filter):
        """Show toast notification when cross-chart filters are applied."""
        if severity_filter:
            return ToastManager.info(
                "Cross-Chart Filter Active",
                detail_message=f"Filtering all charts by severity: {severity_filter.upper()}",
                duration=3000
            )
        elif device_filter:
            return ToastManager.info(
                "Cross-Chart Filter Active",
                detail_message=f"Filtering all charts by device: {device_filter}",
                duration=3000
            )

        return dash.no_update

    # ========================================================================
    # MITRE ATT&CK SANKEY VISUALIZATION
    # ========================================================================

    @app.callback(
        Output('attack-path-sankey', 'figure'),
        [Input('threat-modal', 'is_open'),
         Input('global-severity-filter', 'data')],
        prevent_initial_call=True
    )
    def create_attack_path_visualization(is_open, severity_filter):
        """
        Create Sankey diagram showing attack progression through MITRE ATT&CK kill chain.
        Maps alerts to MITRE tactics and shows attack flow.
        """
        if not is_open:
            raise dash.exceptions.PreventUpdate

        try:
            conn = get_db_connection()
            cursor = conn.cursor()

            # Query alerts and extract MITRE tactics
            query = """
                SELECT
                    a.explanation,
                    a.severity,
                    a.device_ip,
                    a.timestamp,
                    COUNT(*) as count
                FROM alerts a
                WHERE a.timestamp >= datetime('now', '-7 days')
            """

            if severity_filter:
                query += f" AND a.severity = '{severity_filter}'"

            query += " GROUP BY a.explanation, a.severity ORDER BY a.timestamp"

            cursor.execute(query)
            alerts = cursor.fetchall()

            # MITRE ATT&CK Kill Chain stages
            kill_chain_stages = [
                "Reconnaissance",
                "Resource Development",
                "Initial Access",
                "Execution",
                "Persistence",
                "Privilege Escalation",
                "Defense Evasion",
                "Credential Access",
                "Discovery",
                "Lateral Movement",
                "Collection",
                "Command and Control",
                "Exfiltration",
                "Impact"
            ]

            # Map alerts to kill chain stages based on MITRE mapping
            stage_mapping = {}
            for alert in alerts:
                explanation = alert['explanation']
                mitre_info = MITRE_ATTACK_MAPPING.get(explanation, {})
                tactic = mitre_info.get('tactic', 'Unknown')

                # Extract stage from tactic (e.g., "Exfiltration (TA0010)" -> "Exfiltration")
                stage = tactic.split('(')[0].strip() if tactic != 'Unknown' else 'Unknown'

                if stage not in stage_mapping:
                    stage_mapping[stage] = 0
                stage_mapping[stage] += alert['count']

            # Create Sankey diagram data
            source_nodes = []
            target_nodes = []
            values = []
            node_labels = ["Alerts Detected"] + list(stage_mapping.keys()) + ["Security Response"]

            # Connect "Alerts Detected" to each attack stage
            for idx, (stage, count) in enumerate(stage_mapping.items(), start=1):
                source_nodes.append(0)  # From "Alerts Detected"
                target_nodes.append(idx)  # To attack stage
                values.append(count)

            # Connect attack stages to "Security Response"
            response_idx = len(node_labels) - 1
            for idx, (stage, count) in enumerate(stage_mapping.items(), start=1):
                source_nodes.append(idx)  # From attack stage
                target_nodes.append(response_idx)  # To "Security Response"
                values.append(count)

            # Create figure
            fig = go.Figure(data=[go.Sankey(
                node=dict(
                    pad=15,
                    thickness=20,
                    line=dict(color="black", width=0.5),
                    label=node_labels,
                    color=["#17a2b8"] + ["#dc3545" if "Exfiltration" in label or "Impact" in label
                           else "#fd7e14" if "Command" in label or "Lateral" in label
                           else "#ffc107" for label in node_labels[1:-1]] + ["#28a745"]
                ),
                link=dict(
                    source=source_nodes,
                    target=target_nodes,
                    value=values,
                    color="rgba(0,0,0,0.2)"
                )
            )])

            fig.update_layout(
                title="Attack Path Visualization - MITRE ATT&CK Kill Chain",
                font=dict(size=12),
                height=500,
                hovermode='closest'
            )

            return fig

        except Exception as e:
            logger.error(f"Error creating attack path visualization: {e}")
            # Return empty figure on error
            fig = go.Figure()
            fig.update_layout(title=f"Error loading attack path: {str(e)}")
            return fig
