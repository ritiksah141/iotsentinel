"""
AI Agent callbacks — pending action approval/rejection UI.

The autonomous SecurityAgent queues high-risk actions (firewall blocks, isolation)
in the agent_actions table. This module renders those actions and handles
Approve / Reject button clicks.
"""

import json

from utils.alert_explainer import source_label as _source_label, source_badge_class as _source_badge_class

import dash
import dash_bootstrap_components as dbc
from dash import (html, Input, Output, State, callback_context, ALL)

from flask_login import current_user

from dashboard.shared import (
    db_manager,
    logger,
    config,
    audit_logger,
    firewall_enforcer,
)

_RISK_COLORS = {'high': 'danger', 'low': 'success', 'medium': 'warning'}
_STATUS_COLORS = {
    'pending': 'warning',
    'approved': 'info',
    'executed': 'success',
    'rejected': 'danger',
    'auto': 'secondary',
}
_ACTION_ICONS = {
    'firewall_block': 'fa-ban',
    'mark_suspicious': 'fa-triangle-exclamation',
    'notify': 'fa-bell',
    'acknowledge': 'fa-check',
    'device_triage': 'fa-network-wired',
}

_STEP_ICONS = {'ok': 'fa-check-circle text-success',
               'warn': 'fa-exclamation-circle text-warning',
               'bad': 'fa-times-circle text-danger'}


def _investigation_timeline(steps: list) -> html.Div:
    """Render investigation steps as a compact vertical timeline."""
    if not steps:
        return html.Div()
    items = []
    for i, step in enumerate(steps):
        verdict = step.get('verdict', 'ok')
        icon_cls = _STEP_ICONS.get(verdict, 'fa-circle text-muted')
        items.append(
            dbc.ListGroupItem([
                html.Div([
                    html.I(className=f"fa {icon_cls} me-2 flex-shrink-0"),
                    html.Span(step.get('label', ''), className="fw-semibold me-2"),
                    html.Small(step.get('detail', ''), className="text-muted"),
                ], className="d-flex align-items-start"),
            ], className="px-2 py-1 border-0")
        )
    return html.Div([
        html.Hr(className="my-2"),
        html.Div([
            html.I(className="fa fa-magnifying-glass me-2 text-info"),
            html.Small("Investigation timeline", className="fw-semibold text-muted"),
        ], className="mb-1"),
        dbc.ListGroup(items, flush=True, className="small rounded-2"),
    ])


def _action_card(action: dict) -> dbc.Card:
    """Render a single agent action card. Handles alert actions and device triage."""
    aid = action['id']
    device = action.get('device_name') or action.get('device_ip', 'Unknown')
    action_type = action.get('action_type', '')
    risk = action.get('risk_level', 'low')
    status = action.get('status', 'pending')
    plain_report = action.get('plain_report', '') or action.get('rationale', '')
    severity = action.get('severity', '')
    ts = action.get('created_at', '')

    icon = _ACTION_ICONS.get(action_type, 'fa-robot')
    risk_color = _RISK_COLORS.get(risk, 'secondary')
    status_color = _STATUS_COLORS.get(status, 'secondary')

    # --- Device triage: Trust / Block buttons ---
    if action_type == 'device_triage' and status == 'pending':
        buttons = [
            dbc.Button(
                [html.I(className="fa fa-shield-check me-1"), "Trust"],
                id={'type': 'agent-trust-btn', 'index': aid},
                color="success", size="sm", className="me-2", n_clicks=0,
            ),
            dbc.Button(
                [html.I(className="fa fa-ban me-1"), "Block"],
                id={'type': 'agent-block-btn', 'index': aid},
                color="outline-danger", size="sm", n_clicks=0,
            ),
        ]
    elif status == 'pending':
        buttons = [
            dbc.Button(
                [html.I(className="fa fa-check me-1"), "Approve"],
                id={'type': 'agent-approve-btn', 'index': aid},
                color="success", size="sm", className="me-2", n_clicks=0,
            ),
            dbc.Button(
                [html.I(className="fa fa-times me-1"), "Reject"],
                id={'type': 'agent-reject-btn', 'index': aid},
                color="outline-danger", size="sm", n_clicks=0,
            ),
        ]
    else:
        buttons = []

    # --- Investigation timeline ---
    timeline = html.Div()
    raw_investigation = action.get('investigation')
    if raw_investigation:
        try:
            steps = json.loads(raw_investigation)
            if isinstance(steps, list):
                timeline = _investigation_timeline(steps)
        except Exception:
            pass

    return dbc.Card([
        dbc.CardBody([
            dbc.Row([
                dbc.Col([
                    html.I(className=f"fa {icon} fa-2x text-{risk_color}")
                ], width="auto", className="d-flex align-items-center pe-0"),
                dbc.Col([
                    html.Div([
                        html.Strong(device, className="me-2"),
                        dbc.Badge(action_type.replace('_', ' ').title(),
                                  color=risk_color, className="me-1"),
                        dbc.Badge(status, color=status_color, className="me-1"),
                        dbc.Badge(f"Risk: {risk}", color=risk_color, pill=True),
                        dbc.Badge(
                            _source_label(action.get('ai_source', '')) or "AI",
                            className=f"ms-1 {_source_badge_class(action.get('ai_source', ''))}",
                            title="AI-generated analysis",
                        ),
                    ], className="mb-1"),
                    html.P(plain_report, className="mb-1 small"),
                    html.Small(
                        f"{'Severity: ' + severity.upper() + ' • ' if severity else ''}{ts[:16] if ts else ''}",
                        className="text-muted"
                    ),
                    timeline,
                ]),
                dbc.Col(html.Div(buttons, className="d-flex flex-wrap gap-1"), width="auto",
                        className="d-flex align-items-center"),
            ], className="g-2 align-items-start"),
        ], className="p-3")
    ], className="mb-2 border-0 shadow-sm",
       style={'borderLeft': f'4px solid var(--bs-{risk_color})'})


def register(app):
    """Register AI Agent callbacks."""

    # ------------------------------------------------------------------
    # Refresh the agent panel (open modal or interval tick)
    # ------------------------------------------------------------------

    @app.callback(
        [Output('agent-panel-content', 'children'),
         Output('agent-pending-badge', 'children'),
         Output('agent-pending-badge', 'style')],
        [Input('agent-modal', 'is_open'),
         Input('agent-refresh-interval', 'n_intervals')],
        prevent_initial_call=False,
    )
    def refresh_agent_panel(is_open, _n):
        try:
            pending = db_manager.get_pending_agent_actions()
            recent = db_manager.get_agent_actions(limit=20)
        except Exception as e:
            logger.error(f"Agent panel DB error: {e}")
            return [html.P("Error loading agent actions.", className="text-danger")], "", {'display': 'none'}

        badge_text = str(len(pending)) if pending else ""
        badge_style = {} if pending else {'display': 'none'}

        # --- pending section ---
        pending_cards = [
            html.H6([html.I(className="fa fa-clock me-2 text-warning"),
                     f"Awaiting Approval ({len(pending)})"],
                    className="mb-2") if pending else None
        ]
        for a in pending:
            pending_cards.append(_action_card(a))

        # --- recent (non-pending) ---
        recent_non_pending = [a for a in recent if a.get('status') != 'pending']
        history_section = []
        if recent_non_pending:
            history_section.append(html.Hr())
            history_section.append(
                html.H6([html.I(className="fa fa-history me-2"),
                         "Recent Actions"], className="mb-2 text-muted")
            )
            for a in recent_non_pending[:10]:
                history_section.append(_action_card(a))

        if not pending and not recent_non_pending:
            pending_cards = [
                html.Div([
                    html.I(className="fa fa-robot fa-3x text-info mb-3 d-block"),
                    html.P("All clear. No pending actions.",
                           className="fw-semibold mb-1"),
                    html.P([
                        "The agent scans for new high/critical alerts every 60 seconds. ",
                        "When it detects a threat it will either auto-remediate low-risk actions ",
                        "(mark device suspicious, acknowledge alerts) or queue high-risk actions ",
                        "(firewall blocks) here for your approval."
                    ], className="text-muted small mb-0 mx-auto", style={"maxWidth": "380px"}),
                ], className="py-4 text-center")
            ]

        content = [c for c in pending_cards if c is not None] + history_section
        return content, badge_text, badge_style

    # ------------------------------------------------------------------
    # Open / close modal
    # ------------------------------------------------------------------

    @app.callback(
        Output('agent-modal', 'is_open'),
        [Input('open-agent-button', 'n_clicks'),
         Input('close-agent-modal-btn', 'n_clicks')],
        State('agent-modal', 'is_open'),
        prevent_initial_call=True,
    )
    def toggle_agent_modal(open_clicks, close_clicks, is_open):
        ctx = callback_context
        if not ctx.triggered:
            return is_open
        trigger = ctx.triggered[0]['prop_id']
        if 'open-agent-button' in trigger and open_clicks:
            return True
        if 'close-agent-modal-btn' in trigger and close_clicks:
            return False
        return is_open

    # ------------------------------------------------------------------
    # Agent start/stop toggle — reads+writes system_settings.agent_enabled
    # ------------------------------------------------------------------

    def _agent_is_enabled() -> bool:
        val = db_manager.get_setting('agent_enabled', 'true')
        return str(val).lower() not in ('false', '0', 'no')

    @app.callback(
        [Output('agent-status-pill', 'children'),
         Output('agent-toggle-btn', 'children'),
         Output('agent-toggle-btn', 'color')],
        [Input('agent-modal', 'is_open'),
         Input('agent-toggle-btn', 'n_clicks')],
        prevent_initial_call=False,
    )
    def update_agent_toggle(is_open, n_clicks):
        ctx = callback_context
        triggered = ctx.triggered[0]['prop_id'] if ctx.triggered else ''

        # If the button was clicked, flip the flag
        if 'agent-toggle-btn' in triggered and n_clicks:
            if not current_user.is_authenticated or not current_user.is_admin():
                # Not authorised — just reflect current state without changing
                pass
            else:
                currently_enabled = _agent_is_enabled()
                db_manager.set_setting('agent_enabled', 'false' if currently_enabled else 'true')

        enabled = _agent_is_enabled()

        if enabled:
            pill = dbc.Badge(
                [html.I(className="fa fa-circle me-1"), "Agent Running"],
                color="success", pill=True,
            )
            btn_label = [html.I(className="fa fa-pause me-1"), "Pause Agent"]
            btn_color = "warning"
        else:
            pill = dbc.Badge(
                [html.I(className="fa fa-circle me-1"), "Agent Stopped"],
                color="danger", pill=True,
            )
            btn_label = [html.I(className="fa fa-play me-1"), "Start Agent"]
            btn_color = "success"

        return pill, btn_label, btn_color

    # ------------------------------------------------------------------
    # Approve action
    # ------------------------------------------------------------------

    @app.callback(
        Output('agent-action-result', 'children', allow_duplicate=True),
        Input({'type': 'agent-approve-btn', 'index': ALL}, 'n_clicks'),
        prevent_initial_call=True,
    )
    def approve_action(n_clicks_list):
        ctx = callback_context
        if not ctx.triggered or not any(n_clicks_list):
            raise dash.exceptions.PreventUpdate

        trigger = ctx.triggered[0]
        if not trigger['value']:
            raise dash.exceptions.PreventUpdate

        prop_id = trigger['prop_id']
        try:
            action_id = json.loads(prop_id.split('.')[0])['index']
        except Exception:
            raise dash.exceptions.PreventUpdate

        # Fetch the action record
        try:
            actions = db_manager.get_pending_agent_actions()
            action = next((a for a in actions if a['id'] == action_id), None)
        except Exception as e:
            return dbc.Alert(f"DB error: {e}", color="danger", duration=5000)

        if not action:
            return dbc.Alert("Action not found or already resolved.", color="warning", duration=4000)

        if not current_user.is_authenticated or not current_user.is_admin():
            return dbc.Alert("Admin access required to approve agent actions.", color="danger", duration=4000)

        # Mark as approved
        db_manager.update_agent_action_status(action_id, 'approved', current_user.username)

        # Execute
        action_type = action.get('action_type', '')
        device_ip = action.get('device_ip', '')
        mac = action.get('mac_address') or ''
        success = False

        try:
            if action_type == 'firewall_block':
                if firewall_enforcer:
                    success = firewall_enforcer.block_device(device_ip, mac or None)
                    db_manager.set_device_blocked(device_ip, True)
                else:
                    # Enforcer unavailable — fall back to DB flag only
                    db_manager.set_device_blocked(device_ip, True)
                    success = True
            else:
                success = True  # nothing destructive to execute

            db_manager.update_agent_action_status(action_id, 'executed', current_user.username)

            try:
                audit_logger.log_action(
                    f"agent_action_approved:{action_type}",
                    f"Approved agent action on {device_ip}",
                    target_resource=device_ip,
                    success=success,
                )
            except Exception:
                pass

        except Exception as e:
            logger.error(f"Failed to execute approved action {action_id}: {e}")
            return dbc.Alert(f"Execution error: {e}", color="danger", duration=6000)

        backend = getattr(firewall_enforcer, 'backend_name', 'db-flag') if firewall_enforcer else 'db-flag'
        msg = (f"Action '{action_type}' executed on {device_ip}. "
               f"Backend: {backend}. Success: {success}")
        return dbc.Alert(msg, color="success" if success else "warning", duration=6000)

    # ------------------------------------------------------------------
    # Reject action
    # ------------------------------------------------------------------

    @app.callback(
        Output('agent-action-result', 'children', allow_duplicate=True),
        Input({'type': 'agent-reject-btn', 'index': ALL}, 'n_clicks'),
        prevent_initial_call=True,
    )
    def reject_action(n_clicks_list):
        ctx = callback_context
        if not ctx.triggered or not any(n_clicks_list):
            raise dash.exceptions.PreventUpdate

        trigger = ctx.triggered[0]
        if not trigger['value']:
            raise dash.exceptions.PreventUpdate

        prop_id = trigger['prop_id']
        try:
            action_id = json.loads(prop_id.split('.')[0])['index']
        except Exception:
            raise dash.exceptions.PreventUpdate

        if not current_user.is_authenticated or not current_user.is_admin():
            return dbc.Alert("Admin access required.", color="danger", duration=4000)

        db_manager.update_agent_action_status(action_id, 'rejected', current_user.username)

        try:
            audit_logger.log_action(
                "agent_action_rejected",
                f"Rejected agent action #{action_id}",
                target_resource=str(action_id),
                success=True,
            )
        except Exception:
            pass

        return dbc.Alert("Action rejected. No changes were made.", color="info", duration=4000)

    # ------------------------------------------------------------------
    # Trust device (new-device triage)
    # ------------------------------------------------------------------

    @app.callback(
        Output('agent-action-result', 'children', allow_duplicate=True),
        Input({'type': 'agent-trust-btn', 'index': ALL}, 'n_clicks'),
        prevent_initial_call=True,
    )
    def trust_device(n_clicks_list):
        ctx = callback_context
        if not ctx.triggered or not any(n for n in (n_clicks_list or []) if n):
            raise dash.exceptions.PreventUpdate
        trigger = ctx.triggered[0]
        if not trigger['value']:
            raise dash.exceptions.PreventUpdate
        try:
            action_id = json.loads(trigger['prop_id'].split('.')[0])['index']
        except Exception:
            raise dash.exceptions.PreventUpdate

        if not current_user.is_authenticated:
            return dbc.Alert("Login required.", color="danger", duration=4000)

        actions = db_manager.get_pending_agent_actions()
        action = next((a for a in actions if a['id'] == action_id), None)
        if not action:
            return dbc.Alert("Action not found or already resolved.", color="warning", duration=4000)

        device_ip = action.get('device_ip', '')
        try:
            params = json.loads(action.get('params') or '{}')
        except Exception:
            params = {}

        db_manager.update_device_metadata(device_ip, is_trusted=1)
        db_manager.update_agent_action_status(action_id, 'executed',
                                               getattr(current_user, 'username', 'user'))
        name = action.get('device_name') or device_ip
        return dbc.Alert(
            [html.I(className="fa fa-shield-check me-2"), f"{name} has been trusted."],
            color="success", duration=5000,
        )

    # ------------------------------------------------------------------
    # Block device (new-device triage)
    # ------------------------------------------------------------------

    @app.callback(
        Output('agent-action-result', 'children', allow_duplicate=True),
        Input({'type': 'agent-block-btn', 'index': ALL}, 'n_clicks'),
        prevent_initial_call=True,
    )
    def block_triaged_device(n_clicks_list):
        ctx = callback_context
        if not ctx.triggered or not any(n for n in (n_clicks_list or []) if n):
            raise dash.exceptions.PreventUpdate
        trigger = ctx.triggered[0]
        if not trigger['value']:
            raise dash.exceptions.PreventUpdate
        try:
            action_id = json.loads(trigger['prop_id'].split('.')[0])['index']
        except Exception:
            raise dash.exceptions.PreventUpdate

        if not current_user.is_authenticated or not current_user.is_admin():
            return dbc.Alert("Admin access required.", color="danger", duration=4000)

        actions = db_manager.get_pending_agent_actions()
        action = next((a for a in actions if a['id'] == action_id), None)
        if not action:
            return dbc.Alert("Action not found or already resolved.", color="warning", duration=4000)

        device_ip = action.get('device_ip', '')
        mac = action.get('mac_address', '')
        db_manager.set_device_blocked(device_ip, True)
        if firewall_enforcer:
            try:
                firewall_enforcer.block_device(device_ip, mac or None)
            except Exception as e:
                logger.warning(f"[agent] Firewall block on triage failed: {e}")
        db_manager.update_agent_action_status(action_id, 'executed',
                                               getattr(current_user, 'username', 'admin'))
        name = action.get('device_name') or device_ip
        return dbc.Alert(
            [html.I(className="fa fa-ban me-2"), f"{name} has been blocked."],
            color="warning", duration=5000,
        )
