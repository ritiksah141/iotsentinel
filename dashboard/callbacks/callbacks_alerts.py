"""
Alerts & Threats tab callbacks — alert management, threat intelligence,
auto-response, threat maps, risk heatmaps, forensics-related interval callbacks.

Extracted from app.py.  All callbacks are registered via ``register(app)``.
"""

import json
import logging
from collections import defaultdict
from datetime import datetime

import dash
import dash_bootstrap_components as dbc
import pandas as pd
import plotly.express as px
import plotly.graph_objs as go
from dash import dcc, html, Input, Output, State, callback_context, ALL, no_update

from flask_login import login_required, current_user

from utils.alert_explainer import (
    build_prompt, parse_ai_text, persist as persist_plain, clean_ai_text as _clean,
    source_label as _source_label, source_badge_class as _source_badge_class,
    source_icon as _source_icon, build_followup_prompt,
)
from utils.ip_geolocator import geolocate_ips

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
    mitre_stage_from_tactic,
    mitre_tactic_from_explanation,
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
        [Input('ws', 'message'), Input('refresh-interval', 'n_intervals')],
        prevent_initial_call=True  # W15: WS populates on connect; don't burst DB on page load
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
                    a.acknowledged_at,
                    a.plain_explanation,
                    a.plain_explanation_ai,
                    a.ai_source
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
                    'acknowledged_at': row[9],
                    'plain_explanation': row[10],
                    'plain_explanation_ai': row[11] or 0,
                    'ai_source': row[12] or '',
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
        show_acknowledged = bool(show_reviewed and len(show_reviewed) > 0)

        df = pd.DataFrame(recent_alerts_raw) if recent_alerts_raw else pd.DataFrame()

        # When showing reviewed, supplement with acknowledged alerts fetched directly
        # from DB (the store may only hold recent unacknowledged data).
        if show_acknowledged:
            try:
                cursor = db_manager.conn.cursor()
                cursor.execute("""
                    SELECT a.id, a.timestamp, a.device_ip, d.device_name, a.severity,
                           a.anomaly_score, a.explanation, a.top_features,
                           a.acknowledged, a.acknowledged_at, a.plain_explanation,
                           a.plain_explanation_ai, a.ai_source
                    FROM alerts a
                    LEFT JOIN devices d ON a.device_ip = d.device_ip
                    WHERE a.acknowledged = 1
                    ORDER BY a.timestamp DESC
                    LIMIT 50
                """)
                ack_rows = cursor.fetchall()
                ack_alerts = [{
                    'id': r[0], 'timestamp': r[1], 'device_ip': r[2],
                    'device_name': r[3] or 'Unknown Device', 'severity': r[4],
                    'anomaly_score': r[5], 'explanation': r[6], 'top_features': r[7],
                    'acknowledged': r[8] or 0, 'acknowledged_at': r[9],
                    'plain_explanation': r[10],
                    'plain_explanation_ai': r[11] or 0,
                    'ai_source': r[12] or '',
                } for r in ack_rows]
                if ack_alerts:
                    ack_df = pd.DataFrame(ack_alerts)
                    df = pd.concat([df, ack_df]).drop_duplicates(subset=['id']).reset_index(drop=True)
            except Exception as e:
                logger.error(f"Failed to fetch acknowledged alerts: {e}")

        if df.empty:
            return dbc.Alert([
                html.Div([
                    html.I(className="fa fa-check-circle me-2 u-text-xl"),
                    html.Div([
                        html.H5("All Clear!", className="mb-1"),
                        html.P("No security alerts detected in the last 24 hours.", className="mb-0 small text-muted")
                    ])
                ], className="d-flex align-items-center")
            ], color="success", className="compact-alert")

        # Filter out acknowledged unless showing them
        if not show_acknowledged:
            df = df[df['acknowledged'] == 0]

        if filter_severity and filter_severity != 'all' and not df.empty:
            df = df[df['severity'] == filter_severity]

        if len(df) == 0:
            return dbc.Alert([
                html.Div([
                    html.I(className="fa fa-check-circle me-2 u-text-xl"),
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
            plain_explanation = alert.get('plain_explanation')
            mitre_info = MITRE_ATTACK_MAPPING.get(explanation, {})
            tactic = mitre_info.get('tactic', 'Unknown').split('(')[0].strip()

            # Check if alert is acknowledged/reviewed
            is_reviewed = alert.get('acknowledged', 0) == 1
            ai_explained = int(alert.get('plain_explanation_ai', 0)) == 1
            ai_src = alert.get('ai_source', '')

            # Always show plain English on the card — technical detail stays in the modal.
            # Priority: LLM-generated plain_explanation > MITRE user_explanation > truncated technical string
            if plain_explanation:
                display_text = plain_explanation
            elif mitre_info.get('user_explanation'):
                display_text = mitre_info['user_explanation']
            else:
                display_text = (explanation[:80] + "…" if explanation and len(explanation) > 80
                                else explanation or "No description available")

            # AI source badge — only shown when the text was written by an AI provider.
            # Reuses shared source_label/icon helpers so the label is consistent across
            # the modal, chat, and briefing card.
            if ai_explained and ai_src:
                ai_badge = dbc.Badge(
                    [html.I(className=f"fa {_source_icon(ai_src)} me-1"), _source_label(ai_src)],
                    className=f"ms-1 {_source_badge_class(ai_src)}",
                    title=f"Explanation written by {_source_label(ai_src)}",
                )
            else:
                ai_badge = None

            alert_id = int(alert.get('id', 0))
            alert_items.append(
                dbc.Card([
                    dbc.CardBody([
                        html.Div([
                            html.Div([
                                dbc.Badge([html.I(className=f"fa {config_data['icon']} me-1"), severity.upper()],
                                         color=config_data['color'], className="me-2"),
                                dbc.Badge(tactic, color="dark", className="badge-sm"),
                                dbc.Badge("✓ Reviewed", color="success", className="ms-1") if is_reviewed else None,
                                ai_badge,
                            ]),
                            html.Small(time_str, className="text-cyber")
                        ], className="d-flex justify-content-between mb-2"),
                        html.Strong(device_name, className="d-block mb-1"),
                        html.P(display_text, className="alert-text-compact mb-2",
                               id={'type': 'alert-plain-text', 'index': alert_id}),
                        html.Div([
                            dbc.Button([html.I(className="fa fa-info-circle me-1"), "Details"],
                                       id={'type': 'alert-detail-btn', 'index': alert_id},
                                       size="sm", color=config_data['color'], outline=True,
                                       className="w-100 cyber-button"),
                            dbc.Button([html.I(className="fa fa-wand-magic-sparkles me-1"), "Ask AI"],
                                       id={'type': 'explain-btn', 'index': alert_id},
                                       size="sm", color="secondary", outline=True,
                                       className="w-100 cyber-button",
                                       title="Get a plain-English AI explanation of this alert"),
                        ], className="d-grid gap-1")
                    ], className="p-2")
                ], className=f"alert-card-compact mb-2 border-{config_data['color']}")
            )
        return html.Div(alert_items, className="fade-in")

    # Incident correlation panel — groups of related alerts
    @app.callback(
        Output('incidents-panel', 'children'),
        Input('alerts-data-store', 'data'),
        prevent_initial_call=False,
    )
    def update_incidents_panel(alerts_data):
        from datetime import datetime, timezone
        try:
            incidents = db_manager.get_open_incidents(limit=10)
        except Exception:
            return None

        if not incidents:
            return None

        SEV_COLOR = {'critical': 'danger', 'high': 'warning', 'medium': 'info', 'low': 'secondary'}
        SEV_ICON = {'critical': 'fa-skull-crossbones', 'high': 'fa-triangle-exclamation',
                    'medium': 'fa-circle-exclamation', 'low': 'fa-circle-info'}

        cards = []
        for inc in incidents:
            sev = inc.get('max_severity', 'low')
            color = SEV_COLOR.get(sev, 'secondary')
            icon = SEV_ICON.get(sev, 'fa-circle-info')
            count = inc.get('alert_count', 1)
            device = inc.get('device_name') or inc.get('device_ip', 'Unknown')
            title = inc.get('title', 'Security incident')

            try:
                updated = datetime.fromisoformat(str(inc.get('updated_at', '')).replace('Z', '+00:00'))
                now = datetime.now(timezone.utc) if updated.tzinfo else datetime.utcnow()
                mins_ago = int((now - updated).total_seconds() / 60)
                age = f"{mins_ago}m ago" if mins_ago < 60 else f"{mins_ago // 60}h ago"
            except Exception:
                age = "recently"

            cards.append(
                dbc.Alert([
                    html.Div([
                        html.Div([
                            html.I(className=f"fa {icon} me-2"),
                            html.Strong(title, className="me-2"),
                            dbc.Badge(f"{count} alert{'s' if count != 1 else ''}", color=color,
                                      className="me-2"),
                            dbc.Badge(sev.upper(), color=color, className="me-2"),
                        ], className="d-flex align-items-center flex-wrap gap-1"),
                        html.Small([
                            html.I(className="fa fa-microchip me-1 text-muted"),
                            device,
                            html.Span(" - ", className="text-muted mx-1"),
                            html.I(className="fa fa-clock me-1 text-muted"),
                            age,
                        ], className="text-muted mt-1 d-block"),
                    ], className="flex-grow-1"),
                ], color=color, className="py-2 px-3 mb-1 d-flex align-items-center",
                   style={"borderRadius": "8px", "fontSize": "0.82rem"})
            )

        if not cards:
            return None

        return html.Div([
            html.Div([
                html.I(className="fa fa-layer-group me-2 text-warning"),
                html.Strong(f"Active Incidents ({len(incidents)})", className="u-text-sm"),
            ], className="d-flex align-items-center mb-1 px-1"),
            html.Div(cards),
        ])

    # AI activity pulse badge — shows when the background worker rewrote an alert recently
    @app.callback(
        Output('ai-activity-badge', 'className'),
        Input('refresh-interval', 'n_intervals'),
        prevent_initial_call=False,
    )
    def update_ai_activity_badge(_n):
        """Pulse the 'AI active' badge when the worker has rewritten an alert in the last 3 min."""
        import time as _t
        try:
            ts_str = db_manager.get_setting('last_ai_activity', '0')
            ts = int(ts_str or 0)
            active = ts > 0 and (_t.time() - ts) < 180  # 3-minute window
        except Exception:
            active = False
        base = "ms-2 badge-sm pulse-badge"
        return f"{base} d-inline-flex" if active else f"{base} d-none"

    # "Ask AI" — opens AI analysis modal with explanation + specific actions
    @app.callback(
        [Output('toast-container', 'children', allow_duplicate=True),
         Output('alerts-data-store', 'data', allow_duplicate=True),
         Output('alert-ai-analysis-modal', 'is_open'),
         Output('alert-analysis-modal-title', 'children'),
         Output('alert-analysis-modal-body', 'children'),
         Output('alert-chat-history', 'data')],
        Input({'type': 'explain-btn', 'index': ALL}, 'n_clicks'),
        State('alerts-data-store', 'data'),
        prevent_initial_call=True,
    )
    def explain_alert_in_plain_english(n_clicks_list, current_alerts):
        if not any(n for n in (n_clicks_list or []) if n):
            raise dash.exceptions.PreventUpdate

        triggered = callback_context.triggered_id
        if not triggered or not isinstance(triggered, dict):
            raise dash.exceptions.PreventUpdate

        alert_id = triggered.get('index')
        if alert_id is None:
            raise dash.exceptions.PreventUpdate

        alert_row = next(
            (a for a in (current_alerts or []) if int(a.get('id', -1)) == int(alert_id)),
            None
        )
        if not alert_row:
            try:
                cursor = db_manager.conn.cursor()
                cursor.execute(
                    """SELECT a.id, a.device_ip, d.device_name, a.severity, a.explanation, a.plain_explanation
                       FROM alerts a LEFT JOIN devices d ON a.device_ip = d.device_ip
                       WHERE a.id = ? LIMIT 1""",
                    (int(alert_id),)
                )
                row = cursor.fetchone()
                if row:
                    alert_row = {
                        'id': row[0], 'device_ip': row[1],
                        'device_name': row[2] or row[1],
                        'severity': row[3], 'explanation': row[4], 'plain_explanation': row[5],
                    }
            except Exception:
                pass
        if not alert_row:
            raise dash.exceptions.PreventUpdate

        try:
            tech_explanation = alert_row.get('explanation', '')
            device_ip = alert_row.get('device_ip', 'A device')
            device_name = alert_row.get('device_name') or device_ip
            severity = alert_row.get('severity', 'medium')

            # Count today's alerts for this device (urgency context)
            try:
                cur = db_manager.conn.cursor()
                cur.execute(
                    "SELECT COUNT(*) FROM alerts WHERE device_ip=? AND timestamp >= date('now')",
                    (device_ip,)
                )
                today_count = cur.fetchone()[0]
            except Exception:
                today_count = 1

            # Get smart recommendations for concrete actions
            try:
                recs = smart_recommender.recommend_for_alert(int(alert_id))
            except Exception:
                recs = []

            # Build prompt + call LLM via shared helper (identical to background worker path).
            prompt = build_prompt(device_name, severity, today_count, tech_explanation, recs)
            ai_text, source = ai_assistant.get_response(
                prompt=prompt, max_tokens=250, temperature=0.35
            )

            # Parse the structured sections via shared helper.
            sections = parse_ai_text(ai_text, tech_explanation)
            what_happened = sections['what_happened']
            worry_level = sections['worry_level']
            worry_reason = sections['worry_reason']
            top_action = sections['top_action']

            # Persist to DB, set the AI flag, and record which provider answered.
            plain_text = what_happened or ai_text or tech_explanation
            persist_plain(db_manager, alert_id, plain_text, source=source)

            updated_alerts = [
                {**a, 'plain_explanation': plain_text} if int(a.get('id', -1)) == int(alert_id) else a
                for a in (current_alerts or [])
            ]

            # ── Build modal body ──────────────────────────────────────────────
            worry_color = {
                'nothing to worry about': 'success',
                'worth a quick check': 'warning',
                'take action now': 'danger',
            }.get((worry_level or '').lower().strip(), 'info')

            rec_items = []
            for r in recs[:3]:
                rec_items.append(
                    dbc.ListGroupItem([
                        html.Div([
                            dbc.Badge(f"#{r['priority']}", color="dark", className="me-2 flex-shrink-0"),
                            html.Span(r['action'], className="fw-semibold"),
                            dbc.Badge(f"{int(r['confidence']*100)}%", color="secondary",
                                      className="ms-auto badge-sm flex-shrink-0"),
                        ], className="d-flex align-items-center mb-1"),
                        html.Small(_clean(r.get('reason', '')), className="text-muted"),
                    ], className="px-3 py-2")
                )

            # Fallback when recommender has no category-specific recs (e.g. EOL / privacy alerts)
            if not rec_items and top_action:
                rec_items.append(
                    dbc.ListGroupItem([
                        html.Div([
                            dbc.Badge("#1", color="primary", className="me-2 flex-shrink-0"),
                            html.Span(top_action, className="fw-semibold"),
                        ], className="d-flex align-items-center"),
                    ], className="px-3 py-2")
                )

            modal_body = html.Div([
                # What happened
                html.Div([
                    html.I(className="fa fa-info-circle me-2 text-info"),
                    html.Strong("What happened"),
                ], className="mb-1"),
                dcc.Markdown(what_happened, className="mb-3"),

                # Worry level verdict
                dbc.Alert([
                    html.I(className=f"fa fa-{'check-circle' if worry_color == 'success' else 'exclamation-triangle' if worry_color == 'danger' else 'question-circle'} me-2"),
                    html.Strong(worry_level or "Assessment"),
                    html.Span(f". {worry_reason}" if worry_reason else ""),
                ], color=worry_color, className="py-2 mb-3") if worry_level else None,

                # Top action
                html.Div([
                    html.I(className="fa fa-bolt me-2 text-warning"),
                    html.Strong("What to do: "),
                    html.Span(top_action or "Check your device's recent activity in the Devices tab."),
                ], className="mb-3") if top_action else None,

                # Suggested actions list
                html.Div([
                    html.Hr(className="my-2"),
                    html.Div([
                        html.I(className="fa fa-list-check me-2 text-primary"),
                        html.Strong("Suggested actions"),
                        html.Small(f" ({len(recs)} step{'s' if len(recs) != 1 else ''})", className="text-muted ms-1"),
                    ], className="mb-2"),
                    dbc.ListGroup(rec_items, flush=True, className="rounded-2"),
                ]) if rec_items else None,

                # Source footer — which AI provider generated this explanation
                html.Div([
                    html.Small([
                        "Analysis by ",
                        dbc.Badge(
                            [html.I(className=f"fa {_source_icon(source)} me-1"), _source_label(source)],
                            className=_source_badge_class(source),
                        )
                    ], className="text-muted")
                ], className="mt-3 text-end"),
            ])

            modal_title = [
                html.I(className=f"fa fa-{'shield-alt' if severity in ('critical','high') else 'info-circle'} me-2 text-{'danger' if severity == 'critical' else 'warning' if severity == 'high' else 'info'}"),
                f"{severity.upper()} Alert - {device_name}",
            ]

            toast = ToastManager.create_toast(
                message="AI analysis ready",
                toast_type="success",
                header="Ask AI",
                detail_message=f"Powered by {_source_label(source)}.",
                duration=2500,
            )
            # Reset the ask-why chat for this alert
            chat_reset = {'history': [], 'alert_id': int(alert_id)}
            return toast, updated_alerts, True, modal_title, modal_body, chat_reset

        except Exception as e:
            logger.error(f"AI explain failed for alert {alert_id}: {e}")
            toast = ToastManager.create_toast(
                message="Could not generate analysis",
                toast_type="warning",
                header="AI Unavailable",
                detail_message="Try again, or check AI settings.",
                duration=4000,
            )
            return toast, no_update, False, no_update, no_update, no_update


    # Alert details modal
    @app.callback(
        [Output('alert-details-modal', 'is_open'),
         Output('alert-details-title', 'children'),
         Output('alert-details-body', 'children'),
         Output('current-alert-id', 'data')],
        [Input({'type': 'alert-detail-btn', 'index': dash.dependencies.ALL}, 'n_clicks')],
        [State('alert-details-modal', 'is_open')],
        prevent_initial_call=True
    )
    def toggle_alert_details(btn_clicks, is_open):
        ctx = callback_context
        if not ctx.triggered:
            return False, "", "", None

        trigger_id = ctx.triggered[0]['prop_id']


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

    # Suppress alert — mute future alerts for this device for a chosen duration
    @app.callback(
        [Output('toast-container', 'children', allow_duplicate=True),
         Output('alert-details-modal', 'is_open', allow_duplicate=True)],
        [Input('alert-suppress-btn', 'n_clicks')],
        [State('current-alert-id', 'data'),
         State('alert-suppress-duration', 'value')],
        prevent_initial_call=True,
    )
    @login_required
    def suppress_alert_callback(n_clicks, alert_id, duration_str):
        """Suppress future alerts for the device associated with this alert."""
        if not n_clicks or not alert_id:
            return dash.no_update, dash.no_update

        if not PermissionManager.has_permission(current_user, 'acknowledge_alerts'):
            toast = ToastManager.error(
                "Permission Denied",
                detail_message="You need operator privileges to suppress alerts.",
            )
            return toast, dash.no_update

        try:
            # Resolve device_ip from the alert
            cursor = db_manager.conn.cursor()
            cursor.execute("SELECT device_ip FROM alerts WHERE id = ?", (int(alert_id),))
            row = cursor.fetchone()
            if not row:
                return ToastManager.warning("Alert not found"), dash.no_update

            device_ip = row[0] if isinstance(row, (list, tuple)) else row['device_ip']
            hours = int(duration_str) if duration_str and duration_str != "0" else None
            username = current_user.username if current_user.is_authenticated else "unknown"

            success = db_manager.suppress_device_alerts(device_ip, hours, username)
            if not success:
                return ToastManager.error("Failed to set suppression - check logs."), dash.no_update

            label = f"{hours}h" if hours else "indefinitely"
            toast = ToastManager.success(
                f"Alerts suppressed for {device_ip} ({label})",
                detail_message="Future alerts for this device will be silenced. Remove via Device Settings.",
                duration=5000,
            )
            return toast, False  # close modal
        except Exception as e:
            logger.error(f"Suppress alert failed for alert {alert_id}: {e}")
            return ToastManager.error("Suppression error", detail_message=str(e)), dash.no_update

    # Severity filter buttons — also updates active class on each button
    @app.callback(
        [Output('alert-filter', 'data'),
         Output('filter-all', 'className'),
         Output('filter-critical', 'className'),
         Output('filter-high', 'className'),
         Output('filter-medium', 'className'),
         Output('filter-low', 'className')],
        [Input('filter-all', 'n_clicks'), Input('filter-critical', 'n_clicks'),
         Input('filter-high', 'n_clicks'), Input('filter-medium', 'n_clicks'), Input('filter-low', 'n_clicks')]
    )
    def update_alert_filter(*_):
        ctx = callback_context
        if not ctx.triggered:
            active = 'all'
        else:
            button_id = ctx.triggered[0]['prop_id'].split('.')[0]
            active = button_id.split('-')[1]
        base = 'filter-btn-sev'
        severities = ['all', 'critical', 'high', 'medium', 'low']
        classes = [
            f'{base} filter-btn-{s}' + (' filter-btn-active' if s == active else '')
            for s in severities
        ]
        return active, *classes

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
        Input("threat-card-btn", "n_clicks"),
        State("threat-modal", "is_open"),
        prevent_initial_call=True
    )
    def toggle_threat_modal(open_clicks, is_open):
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
        [State('resolved-theme-store', 'data')],
        prevent_initial_call=True
    )
    def update_threat_intel_overview(is_open, refresh_clicks, theme_data):
        from dash import callback_context
        is_dark = (theme_data or {}).get('theme') == 'dark'

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
            legend_orientation='v',
            dark_mode=is_dark
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
                            html.Span(device_name or device_ip, className="text-muted u-text-sm"),
                            html.Span(f" • {timestamp[:19] if timestamp else 'Unknown'}", className="text-muted u-text-xs")
                        ])
                    ], className="p-2 mb-2 glass-subtle")
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
                            ], className="text-muted mb-0 u-text-sm")
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
                            ], className="d-flex align-items-center justify-content-between mb-2 p-2 glass-subtle")
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
                            ], className="d-flex align-items-center justify-content-between mb-2 p-2 glass-subtle")
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
                        className="chart-h-300"
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
                html.Li(action, className="mb-1 u-text-sm")
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
                        ], className="mb-2 u-text-sm"),
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
        Input("threat-map-card-btn", "n_clicks"),
        State("threat-map-modal", "is_open"),
        prevent_initial_call=True
    )
    def toggle_threat_map_modal(open_clicks, is_open):
        return not is_open

    # When the threat-map modal opens, the geographic Scattergeo was drawn while its
    # container was hidden (display:none), so the geo basemap collapsed to 0 width and
    # only the markers + "Connections" colorbar showed. Modal open does not fire a
    # window resize, so nudge a few resizes once it is visible to make Plotly redraw
    # the map at the correct size.
    app.clientside_callback(
        """
        function(is_open) {
            if (is_open) {
                [250, 700, 1500].forEach(function(t) {
                    setTimeout(function() {
                        window.dispatchEvent(new Event('resize'));
                    }, t);
                });
            }
            return window.dash_clientside.no_update;
        }
        """,
        Output("geographic-threat-map", "style"),
        Input("threat-map-modal", "is_open"),
        prevent_initial_call=True,
    )

    @app.callback(
        Output("risk-heatmap-modal", "is_open"),
        Input("risk-heatmap-card-btn", "n_clicks"),
        State("risk-heatmap-modal", "is_open"),
        prevent_initial_call=True
    )
    def toggle_risk_heatmap_modal(open_clicks, is_open):
        return not is_open

    # ========================================================================
    # CALLBACKS - AUTO-RESPONSE MODAL
    # ========================================================================

    @app.callback(
        Output("auto-response-modal", "is_open"),
        Input("auto-response-card-btn", "n_clicks"),
        State("auto-response-modal", "is_open"),
        prevent_initial_call=True
    )
    def toggle_auto_response_modal(open_clicks, is_open):
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
            return "-", "-", "-", "-", {}, timestamp_display, timestamp_str, toast

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
                    html.Td(rule['description'] or '-'),
                    html.Td(rule['rule_type'].replace('_', ' ').title()),
                    html.Td(dbc.Badge(rule['severity'].upper(), color=severity_color)),
                    html.Td(str(rule['threshold_value']) if rule['threshold_value'] else '-'),
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
        [State('resolved-theme-store', 'data')],
        prevent_initial_call=True
    )
    def update_geographic_threat_map(n, refresh_clicks, theme_data):
        """Update geographic threat map with attack origins."""
        from dash import callback_context
        import requests
        from time import sleep
        is_dark = (theme_data or {}).get('theme') == 'dark'
        text_color = '#e4e4e7' if is_dark else '#333333'
        geo_style = dict(
            landcolor='rgb(40, 45, 60)' if is_dark else 'rgb(243, 243, 243)',
            coastlinecolor='rgba(255,255,255,0.2)' if is_dark else 'rgb(204, 204, 204)',
            oceancolor='rgb(20, 25, 40)' if is_dark else 'rgb(230, 245, 255)',
            countrycolor='rgba(255,255,255,0.15)' if is_dark else 'rgb(204, 204, 204)',
        )

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

            # Get unique external IPs from connections (where devices reach out to).
            # 24h window matches the header stat cards and the panel caption — the old
            # 1h window left the map almost always empty during testing.
            cursor.execute('''
                SELECT DISTINCT dest_ip, COUNT(*) as count
                FROM connections
                WHERE timestamp >= datetime("now", "-24 hours")
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
                fig.add_annotation(
                    text="No external connections in the last 24 hours.",
                    showarrow=False, font=dict(size=15, color=text_color),
                    xref="paper", yref="paper", x=0.5, y=0.5,
                )
                fig.update_layout(
                    title="Global Threat Distribution",
                    geo=dict(showcountries=True, **geo_style),
                    height=500, paper_bgcolor='rgba(0,0,0,0)', font={'color': text_color},
                )
                toast = ToastManager.info(
                    "Threat map refreshed - No external connections",
                    detail_message="No external connections detected in the last 24 hours.\n\nThis map shows where your devices reach out on the internet. An empty map simply means none of your devices have talked to an external address recently."
                ) if show_toast else dash.no_update
                return fig, "0 Threats", "0 Countries", toast

            # IP-to-location mapping — one cached batch lookup instead of
            # 20 sequential per-IP requests (see utils/ip_geolocator.py)
            geo_by_ip = geolocate_ips([t['dest_ip'] for t in threats])
            locations = []
            for threat in threats:
                geo = geo_by_ip.get(threat['dest_ip'])
                locations.append({
                    'ip': threat['dest_ip'],
                    'count': threat['count'],
                    'lat': geo['lat'] if geo else 0,
                    'lon': geo['lon'] if geo else 0,
                    'country': geo['country'] if geo else 'Unknown',
                    'country_code': geo['country_code'] if geo else '??',
                    'isp': geo['isp'] if geo else 'Unknown'
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
                title=dict(text='Global Threat Origins - Last 24 Hours', x=0.5, xanchor='center',
                           font=dict(color=text_color)),
                paper_bgcolor='rgba(0,0,0,0)',
                font={'color': text_color},
                geo=dict(
                    projection_type='natural earth',
                    showland=True,
                    showocean=True,
                    showcountries=True,
                    bgcolor='rgba(0,0,0,0)',
                    **geo_style
                ),
                # autosize + responsive config let the geo basemap draw at the right
                # size when the modal/tab becomes visible. Without it, a chart rendered
                # while its container is hidden collapses to 0 width and only the
                # markers and the "Connections" colorbar show, with no map.
                autosize=True,
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

            # Get external IPs with geolocation (24h — matches the Global Map tab)
            cursor.execute('''
                SELECT DISTINCT dest_ip, COUNT(*) as count
                FROM connections
                WHERE timestamp >= datetime("now", "-24 hours")
                AND dest_ip NOT LIKE '192.168.%'
                AND dest_ip NOT LIKE '10.%'
                AND dest_ip NOT LIKE '172.16.%'
                GROUP BY dest_ip
                ORDER BY count DESC
                LIMIT 20
            ''')

            threats = cursor.fetchall()

            if not threats:
                return html.P("No external connections in the last 24 hours", className="text-muted text-center py-4")

            # Group by country — shares the geolocation cache with the threat
            # map, so the same IPs are never queried twice per refresh
            geo_by_ip = geolocate_ips([t['dest_ip'] for t in threats])
            country_stats = defaultdict(lambda: {'count': 0, 'ips': []})

            for threat in threats:
                geo = geo_by_ip.get(threat['dest_ip'])
                if geo:
                    country_key = f"{geo['country']} ({geo['country_code']})"
                    country_stats[country_key]['count'] += threat['count']
                    country_stats[country_key]['ips'].append(threat['dest_ip'])

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
        [State('resolved-theme-store', 'data')],
        prevent_initial_call=True
    )
    def update_device_risk_heatmap(is_open, refresh_clicks, n, theme_data):
        """Update device risk heat map with vulnerability scores."""
        from dash import callback_context
        is_dark = (theme_data or {}).get('theme') == 'dark'
        text_color = '#e4e4e7' if is_dark else '#333333'

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
                title=dict(text=f'Device Risk Assessment - {len(device_risks)} Devices',
                           x=0.5, xanchor='center', font=dict(color=text_color)),
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                font={'color': text_color},
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
                                                    className="mb-2 progress-sm"),
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

            return html.Div(device_cards, className="scroll-panel-md")

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

            return html.Div(recommendations, className="scroll-panel-md")

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
        """
        Count active CVEs from the real NVD pipeline and exposed-service findings.

        CVE data comes from device_vulnerabilities_detected (populated by the daily
        NVD sync + on-join CVE scan run by SecurityAgent).  Port-based unsafe-protocol
        findings are kept as a separate signal but no longer assigned fake CVE IDs.
        """
        try:
            cursor = db_manager.conn.cursor()

            # Real CVE counts from NVD pipeline (severity lives in iot_vulnerabilities, not in dvd)
            cursor.execute("""
                SELECT iv.severity, COUNT(*) AS cnt
                FROM device_vulnerabilities_detected dvd
                JOIN iot_vulnerabilities iv ON dvd.cve_id = iv.cve_id
                WHERE dvd.status NOT IN ('patched', 'false_positive')
                GROUP BY iv.severity
            """)
            sev_rows = cursor.fetchall()
            sev_counts = {r['severity']: r['cnt'] for r in sev_rows} if sev_rows else {}

            critical_count = sev_counts.get('critical', 0)
            high_count = sev_counts.get('high', 0)

            # Exposed services (insecure protocols) — add to severity counts as a signal,
            # but do NOT fabricate CVE IDs for them
            cursor.execute("""
                SELECT DISTINCT device_ip, dest_port FROM connections
                WHERE dest_port IN (21, 23, 80)
                  AND timestamp >= datetime('now', '-24 hours')
            """)
            port_rows = cursor.fetchall()
            for row in port_rows:
                port = row['dest_port']
                if port == 23:   # Telnet — treat as critical exposure
                    critical_count += 1
                elif port == 21:  # FTP — treat as high exposure
                    high_count += 1
                # port 80 (HTTP) is medium; not counted in critical/high badges

            return str(critical_count), str(high_count)

        except Exception as e:
            logger.error(f"Error running vulnerability scanner: {e}")
            return "0", "0"

    # ========================================================================
    # INTERVAL-BASED BENCHMARK COMPARISON  (api-integration-status removed — id no longer exists)
    # ========================================================================

    # ========================================================================
    # INTERVAL-BASED BENCHMARK COMPARISON
    # ========================================================================

    @app.callback(
        Output('benchmark-comparison', 'children'),
        [Input('refresh-interval', 'n_intervals')],
        prevent_initial_call=True  # W15: not on active tab at startup
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


            # Recommended targets (fixed security baselines, not live industry data)
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
                                ], xs=12, sm=6),
                                dbc.Col([
                                    html.Div([
                                        html.Small("Recommended Target", className="text-muted d-block"),
                                        html.H4(str(benchmark['industry_avg']), className="text-muted mb-0")
                                    ])
                                ], xs=12, sm=6)
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
        [State('resolved-theme-store', 'data')],
        prevent_initial_call=True
    )
    def update_performance_analytics(n, theme_data):
        """Display network performance metrics."""
        is_dark = (theme_data or {}).get('theme') == 'dark'
        text_color = '#e4e4e7' if is_dark else '#333333'
        base_layout = dict(plot_bgcolor='rgba(0,0,0,0)', paper_bgcolor='rgba(0,0,0,0)',
                           font={'color': text_color})
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
                    height=300,
                    showlegend=False,
                    **base_layout
                )
            else:
                fig = go.Figure()
                fig.update_layout(
                    title="No performance data available",
                    xaxis=dict(visible=False),
                    yaxis=dict(visible=False),
                    height=300,
                    **base_layout
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
        State('resolved-theme-store', 'data'),
        prevent_initial_call=True
    )
    def create_attack_path_visualization(is_open, severity_filter, theme_data):
        """
        Create Sankey diagram showing attack progression through MITRE ATT&CK kill chain.
        Maps alerts to MITRE tactics and shows attack flow.
        """
        if not is_open:
            raise dash.exceptions.PreventUpdate
        is_dark = (theme_data or {}).get('theme') == 'dark'
        text_color = '#e4e4e7' if is_dark else '#333333'

        try:
            conn = get_db_connection()
            cursor = conn.cursor()

            # Query alerts and extract MITRE tactics
            query = """
                SELECT
                    a.mitre_tactic,
                    a.explanation,
                    a.severity,
                    COUNT(*) as count
                FROM alerts a
                WHERE a.timestamp >= datetime('now', '-7 days')
            """

            params = []
            if severity_filter:
                query += " AND a.severity = ?"
                params.append(severity_filter)

            query += " GROUP BY a.mitre_tactic, a.explanation, a.severity ORDER BY a.timestamp"

            cursor.execute(query, params)
            alerts = cursor.fetchall()

            # Severity → kill-chain stage, used only as a last resort for legacy
            # alerts created before the mitre_tactic column existed and with no
            # MITRE marker in their explanation text.
            severity_default_stage = {
                'critical': 'Command and Control',
                'high': 'Exfiltration',
                'medium': 'Discovery',
                'low': 'Reconnaissance',
            }

            # Map each alert group to a kill-chain stage. Preference order:
            #   1. the persisted mitre_tactic column (set at insert time)
            #   2. the "MITRE ATT&CK: ..." marker embedded in the explanation (legacy)
            #   3. a severity-based default so nothing silently vanishes
            stage_mapping = {}
            for alert in alerts:
                tactic = alert['mitre_tactic'] or mitre_tactic_from_explanation(alert['explanation'])
                stage = mitre_stage_from_tactic(tactic)
                if stage == 'Unknown':
                    stage = severity_default_stage.get(alert['severity'], 'Discovery')
                stage_mapping[stage] = stage_mapping.get(stage, 0) + alert['count']

            # Friendly empty-state instead of a blank chart when there are no alerts.
            if not stage_mapping:
                fig = go.Figure()
                fig.add_annotation(
                    text="No alerts in the last 7 days — no attack path to map.",
                    showarrow=False, font=dict(size=15, color=text_color),
                    xref="paper", yref="paper", x=0.5, y=0.5,
                )
                fig.update_layout(
                    title="Attack Path Visualization - MITRE ATT&CK Kill Chain",
                    paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
                    height=500, font=dict(color=text_color),
                    xaxis=dict(visible=False), yaxis=dict(visible=False),
                )
                return fig

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
                font=dict(size=12, color=text_color),
                paper_bgcolor='rgba(0,0,0,0)',
                height=500,
                hovermode='closest'
            )

            return fig

        except Exception as e:
            logger.error(f"Error creating attack path visualization: {e}")
            fig = go.Figure()
            fig.update_layout(title=f"Error loading attack path: {str(e)}",
                              paper_bgcolor='rgba(0,0,0,0)', font={'color': text_color})
            return fig

    # ── Ask Why: per-alert conversational AI analyst ─────────────────────────
    # Handles chip clicks ("Why is this bad?" etc.) and free-text input.
    # Grounds every answer in the actual alert + device data from this network.

    def _render_alert_chat(history: list) -> list:
        """Render alert conversation as chat bubbles (reuses .chat-bubble CSS)."""
        bubbles = []
        for msg in history:
            role = msg.get('role', 'assistant')
            content = msg.get('content', '')
            src = msg.get('source', '')
            ts = msg.get('timestamp', '')[:16].replace('T', ' ')

            if role == 'user':
                bubbles.append(
                    dbc.Card(
                        dbc.CardBody([
                            html.Div([
                                html.I(className="fa fa-user-circle me-2"),
                                html.Strong("You", className="u-text-chat"),
                                html.Small(ts, className="ms-2 text-muted u-text-chat-sm"),
                            ], className="d-flex align-items-center mb-1"),
                            html.P(content, className="mb-0 small"),
                        ], className="chat-bubble"),
                        color="primary", outline=True, className="mb-2 chat-bubble--user",
                    )
                )
            else:
                src_badge = (
                    dbc.Badge(
                        [html.I(className=f"fa {_source_icon(src)} me-1"), _source_label(src)],
                        className=f"ms-2 {_source_badge_class(src)}",
                    ) if src else html.Span()
                )
                bubbles.append(
                    dbc.Card(
                        dbc.CardBody([
                            html.Div([
                                html.I(className="fa fa-robot me-2"),
                                html.Strong("IoTSentinel AI", className="u-text-chat"),
                                src_badge,
                                html.Small(ts, className="ms-2 text-muted u-text-chat-sm"),
                            ], className="d-flex align-items-center mb-1"),
                            dcc.Markdown(content, className="mb-0 small"),
                        ], className="chat-bubble"),
                        className="mb-2 chat-bubble--ai",
                    )
                )
        return bubbles

    @app.callback(
        [Output('alert-chat-messages', 'children'),
         Output('alert-chat-history', 'data', allow_duplicate=True),
         Output('alert-chat-input', 'value')],
        [Input('alert-chat-send', 'n_clicks'),
         Input('alert-q-why', 'n_clicks'),
         Input('alert-q-action', 'n_clicks'),
         Input('alert-q-data', 'n_clicks')],
        [State('alert-chat-input', 'value'),
         State('alert-chat-history', 'data'),
         State('alerts-data-store', 'data')],
        prevent_initial_call=True,
    )
    def alert_followup_chat(send_n, why_n, action_n, data_n,
                            user_input, chat_store, alerts_data):
        """Handle Ask-why follow-up conversation grounded in the real alert data."""
        triggered_id = callback_context.triggered_id

        # Determine the user message from chip or free-text
        chip_questions = {
            'alert-q-why':    "Why is this bad?",
            'alert-q-action': "What should I do?",
            'alert-q-data':   "Is my data safe?",
        }
        question = chip_questions.get(triggered_id, (user_input or '').strip())
        if not question:
            raise dash.exceptions.PreventUpdate

        chat_store = chat_store or {'history': [], 'alert_id': None}
        history = list(chat_store.get('history', []))
        alert_id = chat_store.get('alert_id')

        history.append({
            'role': 'user',
            'content': question,
            'timestamp': datetime.now().isoformat(),
        })

        # --- Build grounded context from the actual alert + device + baseline ---
        try:
            alert_row = None
            for a in (alerts_data or []):
                if alert_id and int(a.get('id', -1)) == int(alert_id):
                    alert_row = a
                    break

            if alert_row is None and alert_id:
                # Try DB fallback
                try:
                    cur = db_manager.conn.cursor()
                    cur.execute(
                        "SELECT a.*, d.device_name FROM alerts a "
                        "LEFT JOIN devices d ON a.device_ip=d.device_ip "
                        "WHERE a.id=?", (alert_id,)
                    )
                    r = cur.fetchone()
                    if r:
                        alert_row = dict(r)
                except Exception:
                    pass

            device_name = 'Unknown device'
            device_ip = ''
            severity = 'medium'
            explanation = ''
            plain_exp = ''
            today_count = 1
            recent_dests = []

            if alert_row:
                device_name = alert_row.get('device_name') or alert_row.get('device_ip', 'Unknown')
                device_ip = alert_row.get('device_ip', '')
                severity = alert_row.get('severity', 'medium')
                explanation = alert_row.get('explanation', '')
                plain_exp = alert_row.get('plain_explanation', '')
                try:
                    cur = db_manager.conn.cursor()
                    cur.execute(
                        "SELECT COUNT(*) FROM alerts WHERE device_ip=? AND timestamp>=date('now')",
                        (device_ip,)
                    )
                    today_count = cur.fetchone()[0] or 1
                    # Recent destinations for context
                    cur.execute(
                        "SELECT DISTINCT dest_ip FROM connections "
                        "WHERE device_ip=? AND timestamp>=datetime('now','-24 hours') LIMIT 5",
                        (device_ip,)
                    )
                    recent_dests = [r[0] for r in cur.fetchall()]
                except Exception:
                    pass

            # Smart recommendations
            recs = []
            try:
                recs = smart_recommender.recommend_for_alert(int(alert_id)) if alert_id else []
            except Exception:
                pass

            prompt, network_context = build_followup_prompt(
                alert_row=alert_row or {
                    'device_name': device_name, 'device_ip': device_ip,
                    'severity': severity,
                    'explanation': explanation, 'plain_explanation': plain_exp,
                },
                today_count=today_count,
                destinations=recent_dests,
                recs=recs,
                history=history,
                question=question,
            )

        except Exception as exc:
            logger.error(f"alert_followup_chat context build failed: {exc}")
            network_context = "You are a helpful network security assistant."
            prompt = question

        # --- Rate cap (same soft cap as AI chat) ---
        try:
            from dashboard.shared import config as _cfg, rate_limiter as _rl
            _tier = _cfg.get('system', 'deployment_tier', 'household')
            _uid = str(getattr(current_user, 'id', 'anonymous')) if current_user.is_authenticated else 'anonymous'
            _cap_ok, _, _ = _rl.check_rate_limit(_uid, f'ai_chat_{_tier}')
        except Exception:
            _cap_ok = True

        # --- Call AI ---
        try:
            if not _cap_ok:
                ai_text = "Daily AI limit reached. Try again after midnight."
                source = 'rules'
            else:
                ai_text, source = ai_assistant.get_response(
                    prompt=prompt,
                    context=network_context,
                    max_tokens=200,
                    temperature=0.4,
                )
                ai_text = _clean(ai_text or "I could not find an answer. Try again.")
        except Exception as exc:
            logger.warning(f"alert_followup_chat AI call failed: {exc}")
            ai_text = "AI is unavailable right now. Check AI Settings for configuration."
            source = 'rules'

        history.append({
            'role': 'assistant',
            'content': ai_text,
            'timestamp': datetime.now().isoformat(),
            'source': source,
        })

        new_store = {**chat_store, 'history': history[-20:]}  # keep last 10 turns
        bubbles = _render_alert_chat(history)
        return bubbles, new_store, ''  # clear input box
