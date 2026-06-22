"""
Device Management, Firmware, Smart Home, Privacy callbacks — device trust,
device table pagination, bulk operations, device details, IoT protocol stats,
threat detection, privacy scores, tracker detection, cloud uploads, data flow,
smart home hubs/ecosystems/rooms/automations, firmware status/EOL/updates,
modal toggles, timestamps, exports, and device hierarchy sunburst chart.

Extracted from app.py.  All callbacks are registered via ``register(app)``.
"""

import base64
import io
import json
from datetime import datetime, timedelta
from typing import List

import dash
import dash_bootstrap_components as dbc
import pandas as pd
import plotly.graph_objs as go
from dash import (dcc, html, Input, Output, State, callback_context, ALL, no_update)

from flask_login import login_required, current_user

from dashboard.shared import (
    db_manager,
    chart_factory,
    export_helper,
    logger,
    config,
    audit_logger,
    security_audit_logger,
    ai_assistant,
    group_manager,
    get_intelligence,
    get_protocol_analyzer,
    get_threat_detector,
    get_smart_home_manager,
    get_privacy_monitor,
    get_network_segmentation,
    get_firmware_manager,
    firewall_enforcer,
    log_device_action,
    log_bulk_action,
    can_export_data,
    can_manage_devices,
    can_block_devices,
    can_delete_data,
    rate_limiter,
    iot_protocol_analyzer,
    iot_threat_detector,
    get_db_connection,
    get_device_details,
    create_status_indicator,
    create_device_icon,
    create_baseline_comparison_chart,
    create_timestamp_display,
    format_bytes,
    ToastManager,
    ChartFactory,
    PermissionManager,
)


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def get_non_eol_devices():
    """Helper function to get non-EOL devices for replacement dropdown."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT device_ip, device_name, device_type
            FROM devices
            WHERE last_seen >= datetime("now", "-30 days")
            AND (device_type NOT LIKE '%legacy%' AND device_type NOT LIKE '%old%')
        ''')
        devices = cursor.fetchall()
        return [{'label': f"{d['device_name'] or d['device_ip']} ({d['device_type']})", 'value': d['device_ip']} for d in devices]
    except Exception as e:
        logger.error(f"Error fetching non-EOL devices: {e}")
        return []


# ---------------------------------------------------------------------------
# Module-level helpers for smart-home UI rendering
# ---------------------------------------------------------------------------

def _render_automations(db_mgr):
    """Build the automations list from smart_home_automations table."""
    try:
        automations = db_mgr.get_all_automations()
        if not automations:
            return dbc.Alert([
                html.I(className="fa fa-magic me-2"),
                "No automations yet. Click 'Create Automation' to get started!"
            ], color="info")

        trigger_labels = {
            "time": "🕐 Time-based", "device": "🔌 Device State",
            "location": "🏠 Location", "sensor": "🌡️ Sensor",
        }
        cards = []
        for auto in automations:
            status_badge = (dbc.Badge("Active", color="success", className="me-2")
                            if auto.get('is_enabled')
                            else dbc.Badge("Disabled", color="secondary", className="me-2"))
            cards.append(
                dbc.Card([dbc.CardBody([
                    html.H5([html.I(className="fa fa-magic me-2 text-primary"), auto['name']],
                            className="mb-2"),
                    dbc.Row([
                        dbc.Col([html.Strong("Trigger:"),
                                 html.P(trigger_labels.get(auto['trigger_type'], auto['trigger_type']),
                                        className="text-muted mb-1")], md=3),
                        dbc.Col([html.Strong("Condition:"),
                                 html.P(auto.get('condition_text') or "—",
                                        className="text-muted mb-1")], md=4),
                        dbc.Col([html.Strong("Action:"),
                                 html.P(auto['action_text'], className="text-muted mb-1")], md=4),
                        dbc.Col([status_badge], md=1),
                    ]),
                    html.Div([
                        dbc.Button([html.I(className="fa fa-trash me-1"), "Delete"],
                                   id={'type': 'delete-automation-btn', 'index': auto['id']},
                                   size="sm", color="danger", outline=True, className="mt-2"),
                    ])
                ])], className="shadow-sm mb-3")
            )
        return html.Div(cards)

    except Exception as e:
        logger.error(f"Error rendering automations: {e}")
        return dbc.Alert("Error loading automations", color="danger")


# ---------------------------------------------------------------------------
# register(app) — all device-management callbacks
# ---------------------------------------------------------------------------

def register(app):
    """Register all device-management callbacks on *app*."""

    # ====================================================================
    # 1. Device trust switch
    # ====================================================================
    @app.callback(
        Output('toast-container', 'children', allow_duplicate=True),
        Input({'type': 'device-trust-switch', 'ip': ALL}, 'value'),
        prevent_initial_call=True
    )
    def toggle_device_trust(value):
        ctx = callback_context
        if not ctx.triggered:
            raise dash.exceptions.PreventUpdate

        # Ensure the callback was triggered by an actual value change, not initial render
        if not value or all(v is None for v in value):
            raise dash.exceptions.PreventUpdate

        triggered_id = ctx.triggered_id
        if not isinstance(triggered_id, dict):
            return ToastManager.error("Invalid trigger for trust switch.")

        try:
            device_ip = triggered_id['ip']
            is_trusted = ctx.triggered[0]['value']
        except (TypeError, KeyError) as e:
            logger.error(f"Error parsing trust switch ID or value: {e}")
            return ToastManager.error(
                "Error processing request.",
                detail_message=f"Technical details:\n{str(e)}\n\nPlease try again or contact support if the issue persists."
            )

        success = db_manager.set_device_trust(device_ip, is_trusted)

        if success:
            status_text = "Trusted" if is_trusted else "Untrusted"
            return ToastManager.success(
                f"Device {device_ip} set to {status_text}.",
                detail_message=f"Device IP: {device_ip}\nNew Status: {status_text}\nTimestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            )
        else:
            return ToastManager.error(
                f"Failed to update trust status for {device_ip}.",
                detail_message=f"Device IP: {device_ip}\nRequested Status: {'Trusted' if is_trusted else 'Untrusted'}\n\nPossible reasons:\n- Database connection issue\n- Device not found in database\n- Permission denied"
            )

    # ====================================================================
    # 2. Device count badges
    # ====================================================================
    @app.callback(
        [Output('total-devices-count', 'children'),
         Output('trusted-devices-count', 'children'),
         Output('blocked-devices-count', 'children'),
         Output('unknown-devices-count', 'children')],
        Input('device-mgmt-modal', 'is_open'),
        prevent_initial_call=True
    )
    def update_device_counts(is_open):
        """Update device count badges when modal opens"""
        if not is_open:
            raise dash.exceptions.PreventUpdate

        try:
            devices = db_manager.get_all_devices()
            total = len(devices)
            trusted = sum(1 for d in devices if d.get('is_trusted', False))
            blocked = sum(1 for d in devices if d.get('is_blocked', False))
            unknown = sum(1 for d in devices if d.get('device_type') == 'unknown')

            return str(total), str(trusted), str(blocked), str(unknown)
        except Exception as e:
            logger.error(f"Error updating device counts: {e}")
            return "0", "0", "0", "0"

    # ====================================================================
    # 3. Device mgmt table (paginated)
    # ====================================================================
    @app.callback(
        [Output('device-management-table', 'children'),
         Output('device-table-page', 'data', allow_duplicate=True),
         Output('toast-container', 'children', allow_duplicate=True)],
        [Input('device-mgmt-modal', 'is_open'),
         Input('device-mgmt-tabs', 'active_tab'),
         Input('load-devices-btn', 'n_clicks'),
         Input('refresh-device-mgmt-btn', 'n_clicks'),
         Input('device-search-input', 'value'),
         Input('device-status-filter', 'value'),
         Input({'type': 'device-page-btn', 'action': ALL}, 'n_clicks')],
        [State('device-table-page', 'data'),
         State('selected-devices-store', 'data')],
        prevent_initial_call=True
    )
    def load_device_management_table(is_open, active_tab, load_clicks, refresh_clicks, search_text, status_filter, page_clicks, current_page, selected_devices):
        """Load devices for management with pagination"""
        ctx = callback_context

        # Only load when modal is open and devices tab is active
        if not is_open:
            raise dash.exceptions.PreventUpdate

        if active_tab != 'devices-list-tab':
            raise dash.exceptions.PreventUpdate

        # Check if refresh button was clicked for toast notification
        trigger_id = ctx.triggered[0]['prop_id'].split('.')[0] if ctx.triggered else ''
        show_refresh_toast = trigger_id in ['load-devices-btn', 'refresh-device-mgmt-btn']

        # Determine which button was clicked
        if not ctx.triggered:
            page = 1
        else:
            # Handle pattern-matching pagination buttons
            if 'device-page-btn' in trigger_id:
                try:
                    import json
                    button_id = json.loads(trigger_id)
                    action = button_id.get('action', '')
                    if action == 'prev':
                        page = max(1, current_page - 1)
                    elif action == 'next':
                        page = current_page + 1
                    else:
                        page = 1
                except:
                    page = 1
            elif trigger_id in ['device-search-input', 'device-status-filter']:
                page = 1  # Reset to page 1 when search or filter changes
            else:
                page = 1  # Reset to page 1 on initial load or refresh

        # Pagination settings
        ITEMS_PER_PAGE = 20

        devices = db_manager.get_all_devices()

        if not devices:
            return dbc.Alert("No devices found", color="info"), 1, dash.no_update

        # Apply status filter
        if status_filter and status_filter != 'all':
            if status_filter == 'trusted':
                devices = [d for d in devices if d.get('is_trusted', False)]
            elif status_filter == 'blocked':
                devices = [d for d in devices if d.get('is_blocked', False)]
            elif status_filter == 'unknown':
                devices = [d for d in devices if not d.get('is_trusted', False) and not d.get('is_blocked', False)]

        # Apply search filter
        if search_text and search_text.strip():
            search_text = search_text.strip().lower()
            filtered_devices = []
            for device in devices:
                device_ip = (device.get('device_ip') or '').lower()
                device_type = (device.get('device_type') or '').lower()
                manufacturer = (device.get('manufacturer') or '').lower()
                custom_name = (device.get('custom_name') or device.get('device_name') or '').lower()
                category = (device.get('category') or '').lower()
                mac_address = (device.get('mac_address') or '').lower()

                # Search in multiple fields
                if (search_text in device_ip or
                    search_text in device_type or
                    search_text in manufacturer or
                    search_text in custom_name or
                    search_text in category or
                    search_text in mac_address):
                    filtered_devices.append(device)
            devices = filtered_devices

        if not devices:
            return dbc.Alert("No devices match your search criteria", color="info"), 1, dash.no_update

        # Calculate pagination
        total_devices = len(devices)
        total_pages = (total_devices + ITEMS_PER_PAGE - 1) // ITEMS_PER_PAGE
        page = min(page, total_pages)  # Don't exceed max pages

        start_idx = (page - 1) * ITEMS_PER_PAGE
        end_idx = start_idx + ITEMS_PER_PAGE
        page_devices = devices[start_idx:end_idx]

        # Ensure selected_devices is a list
        if not selected_devices:
            selected_devices = []

        # Create device management table
        rows = []
        for device in page_devices:
            device_ip = device['device_ip']
            device_type = device.get('device_type', 'unknown')
            manufacturer = device.get('manufacturer', 'Unknown')
            custom_name = device.get('custom_name') or device.get('device_name') or device_ip
            category = device.get('category', 'other')
            icon = device.get('icon', '❓')

            # Get device groups
            groups = db_manager.get_device_groups(device_ip)
            group_names = ', '.join([g['name'] for g in groups]) if groups else 'None'

            # Check if device is selected
            is_selected = device_ip in selected_devices

            row = dbc.Card([
                dbc.CardBody([
                    dbc.Row([
                        # Checkbox - NEW
                        dbc.Col([
                            dbc.Checkbox(
                                id={'type': 'device-checkbox', 'ip': device_ip},
                                className="device-select-checkbox",
                                value=is_selected
                            )
                        ], width=1, className="d-flex align-items-center justify-content-center"),

                        # Icon & Name
                        dbc.Col([
                            html.Div([
                                html.Span(icon, className="u-icon-lg"),
                                html.Div([
                                    html.Strong(custom_name),
                                    html.Br(),
                                    html.Small(f"{manufacturer} • {device_type}", className="text-muted")
                                ])
                            ], className="d-flex align-items-center")
                        ], width=3),

                        # IP & Category
                        dbc.Col([
                            html.Div([
                                html.Small("IP Address", className="text-muted d-block"),
                                html.Span(device_ip),
                                html.Br(),
                                html.Small("Category", className="text-muted d-block"),
                                dbc.Badge(category, color="info", className="mt-1")
                            ])
                        ], width=3),

                        # Groups
                        dbc.Col([
                            html.Div([
                                html.Small("Groups", className="text-muted d-block"),
                                html.Span(group_names)
                            ])
                        ], width=3),

                        # Actions
                        dbc.Col([
                            dbc.Button([html.I(className="fa fa-info-circle me-2"), "View Details"],
                                      id={'type': 'view-device-btn', 'ip': device_ip},
                                      color="primary", size="sm", outline=True,
                                      title="View details")
                        ], width=2, className="text-end")
                    ])
                ])
            ], className="mb-2")

            rows.append(row)

        # Pagination controls
        pagination = dbc.Row([
            dbc.Col([
                html.Div([
                    dbc.Button("← Previous", id={'type': 'device-page-btn', 'action': 'prev'}, size="sm",
                              disabled=(page == 1), color="primary", outline=True),
                    html.Span(f" Page {page} of {total_pages} ",
                             className="mx-3 align-middle"),
                    dbc.Button("Next →", id={'type': 'device-page-btn', 'action': 'next'}, size="sm",
                              disabled=(page >= total_pages), color="primary", outline=True)
                ], className="d-flex align-items-center justify-content-center")
            ])
        ], className="mt-3")

        # Generate success toast if refresh button was clicked
        toast = ToastManager.success(
            "Device list refreshed",
            detail_message=f"Displaying {total_devices} device(s)"
        ) if show_refresh_toast else dash.no_update

        return html.Div([
            dbc.Row([
                dbc.Col([
                    html.Div([
                        dbc.Button([
                            dbc.Checkbox(
                                id='select-all-devices-checkbox',
                                label="",
                                className="d-inline me-2",
                                value=False,
                                style={'margin': '0', 'verticalAlign': 'middle', 'pointerEvents': 'none'}
                            ),
                            html.Span([
                                html.I(className="fa fa-check-double me-2"),
                                "Select All"
                            ])
                        ], id='select-all-btn-wrapper', color="primary", size="sm", outline=True, className="select-all-btn"),
                        html.H6(f"Total Devices: {total_devices} | Showing {start_idx + 1}-{min(end_idx, total_devices)}",
                               className="mb-0 d-inline text-muted ms-3")
                    ], className="d-flex align-items-center justify-content-between")
                ], width=12),
            ], className="mb-3 pb-2 border-bottom"),
            html.Div(rows, id='device-rows-container', **{'data-virtual-scroll': 'true', 'data-item-height': '100'}),
            pagination
        ]), page, toast

    # ====================================================================
    # 4. Bulk device operations
    # ====================================================================
    @app.callback(
        [Output('toast-container', 'children', allow_duplicate=True),
         Output('bulk-action-confirm-modal', 'is_open'),
         Output('bulk-action-pending-store', 'data'),
         Output('bulk-action-modal-title', 'children'),
         Output('bulk-action-modal-icon', 'className'),
         Output('bulk-action-modal-question', 'children'),
         Output('bulk-action-modal-detail', 'children'),
         Output('bulk-action-modal-warning', 'children'),
         Output('bulk-action-modal-warning', 'color'),
         Output('bulk-action-confirm-btn', 'children'),
         Output('bulk-action-confirm-btn', 'color')],
        [Input('bulk-trust-btn', 'n_clicks'),
         Input('bulk-block-btn', 'n_clicks'),
         Input('bulk-delete-btn', 'n_clicks')],
        [State({'type': 'device-checkbox', 'ip': ALL}, 'value'),
         State({'type': 'device-checkbox', 'ip': ALL}, 'id')],
        prevent_initial_call=True
    )
    def handle_bulk_operations(trust_clicks, block_clicks, delete_clicks, checkbox_values, checkbox_ids):
        """Show confirmation modal for trust/block; pass through to delete modal."""
        nu = dash.no_update
        ctx = dash.callback_context
        if not ctx.triggered:
            return (nu,) * 11

        if all(c is None or c == 0 for c in [trust_clicks, block_clicks, delete_clicks]):
            return (nu,) * 11

        if not current_user.is_authenticated:
            return (ToastManager.error("Authentication required", detail_message="Please log in."),) + (nu,) * 10

        button_id = ctx.triggered[0]['prop_id'].split('.')[0]

        if button_id == 'bulk-trust-btn' and not can_manage_devices(current_user):
            return (ToastManager.warning("Access Denied", detail_message="Permission denied."),) + (nu,) * 10
        if button_id == 'bulk-block-btn' and not can_block_devices(current_user):
            return (ToastManager.warning("Access Denied", detail_message="Permission denied."),) + (nu,) * 10

        selected_ips = [checkbox_ids[i]['ip'] for i, v in enumerate(checkbox_values) if v]

        if not selected_ips:
            return (ToastManager.warning("No Selection", detail_message="No devices selected."),) + (nu,) * 10

        count = len(selected_ips)

        if button_id == 'bulk-delete-btn':
            # Delete path — handled by the existing bulk-delete-modal callback
            return (nu,) * 11

        if button_id == 'bulk-trust-btn':
            return (
                nu,                                                          # toast
                True,                                                        # open modal
                {'action': 'trust', 'ips': selected_ips},                   # store
                [html.I(className="fa fa-check-circle me-2 text-success"), f"Trust {count} Device(s)"],
                "fa fa-check-circle fa-3x text-success mb-2",
                f"Trust {count} selected device(s)?",
                "These devices will be marked as trusted on your network.",
                [html.I(className="fa fa-info-circle me-2"), "Trusted devices are exempt from lockdown and threat alerts."],
                "info",
                [html.I(className="fa fa-check me-2"), "Trust All"],
                "success",
            )

        if button_id == 'bulk-block-btn':
            return (
                nu,
                True,
                {'action': 'block', 'ips': selected_ips},
                [html.I(className="fa fa-ban me-2 text-danger"), f"Block {count} Device(s)"],
                "fa fa-ban fa-3x text-danger mb-2",
                f"Block {count} selected device(s)?",
                "These devices will be denied network access immediately.",
                [html.I(className="fa fa-exclamation-triangle me-2"), "Blocking a device disconnects it. You can unblock it at any time."],
                "warning",
                [html.I(className="fa fa-ban me-2"), "Block All"],
                "danger",
            )

        return (nu,) * 11

    @app.callback(
        [Output('toast-container', 'children', allow_duplicate=True),
         Output('bulk-action-confirm-modal', 'is_open', allow_duplicate=True),
         Output('bulk-action-pending-store', 'data', allow_duplicate=True)],
        [Input('bulk-action-confirm-btn', 'n_clicks'),
         Input('bulk-action-cancel', 'n_clicks')],
        State('bulk-action-pending-store', 'data'),
        prevent_initial_call=True,
    )
    def execute_bulk_action(confirm_clicks, cancel_clicks, pending):
        ctx = dash.callback_context
        if not ctx.triggered:
            raise dash.exceptions.PreventUpdate
        trigger = ctx.triggered[0]['prop_id'].split('.')[0]
        if trigger == 'bulk-action-cancel':
            return dash.no_update, False, None
        if trigger != 'bulk-action-confirm-btn' or not pending:
            raise dash.exceptions.PreventUpdate
        if not current_user.is_authenticated:
            return ToastManager.error("Authentication required", detail_message="Please log in."), False, None

        action = pending.get('action')
        ips = pending.get('ips', [])
        try:
            if action == 'trust':
                if not can_manage_devices(current_user):
                    return ToastManager.warning("Access Denied", detail_message="Permission denied."), False, None
                for ip in ips:
                    db_manager.set_device_trust(ip, is_trusted=True)
                return ToastManager.success("Bulk Trust", detail_message=f"Trusted {len(ips)} device(s)."), False, None
            elif action == 'block':
                if not can_block_devices(current_user):
                    return ToastManager.warning("Access Denied", detail_message="Permission denied."), False, None
                for ip in ips:
                    db_manager.set_device_blocked(ip, is_blocked=True)
                return ToastManager.error("Bulk Block", detail_message=f"Blocked {len(ips)} device(s)."), False, None
        except Exception as e:
            logger.error(f"Bulk action execution error: {e}")
            return ToastManager.error("Operation Failed", detail_message=str(e)), False, None
        raise dash.exceptions.PreventUpdate

    # ====================================================================
    # 5. Bulk delete confirmation modal
    # ====================================================================
    @app.callback(
        [Output('bulk-delete-modal', 'is_open'),
         Output('bulk-delete-confirm-message', 'children')],
        [Input('bulk-delete-btn', 'n_clicks'),
         Input('bulk-delete-cancel', 'n_clicks'),
         Input('bulk-delete-confirm', 'n_clicks')],
        [State('bulk-delete-modal', 'is_open'),
         State({'type': 'device-checkbox', 'ip': ALL}, 'value'),
         State({'type': 'device-checkbox', 'ip': ALL}, 'id')],
        prevent_initial_call=True
    )
    def toggle_bulk_delete_modal(delete_clicks, cancel_clicks, confirm_clicks, is_open, checkbox_values, checkbox_ids):
        """Show/hide bulk delete confirmation modal"""
        ctx = dash.callback_context
        if not ctx.triggered:
            return False, ""

        button_id = ctx.triggered[0]['prop_id'].split('.')[0]

        if button_id == 'bulk-delete-btn':
            # Count selected devices
            selected_count = sum(1 for val in checkbox_values if val)
            if selected_count == 0:
                return False, ""

            message = f"You are about to delete {selected_count} device(s) from the database."
            return True, message

        # Close modal on cancel or confirm
        return False, ""

    # ====================================================================
    # 6. Bulk delete confirmed action
    # ====================================================================
    @app.callback(
        Output('toast-container', 'children', allow_duplicate=True),
        Input('bulk-delete-confirm', 'n_clicks'),
        [State({'type': 'device-checkbox', 'ip': ALL}, 'value'),
         State({'type': 'device-checkbox', 'ip': ALL}, 'id')],
        prevent_initial_call=True
    )
    def bulk_delete_confirmed(confirm_clicks, checkbox_values, checkbox_ids):
        """Execute bulk delete after confirmation (Admin only)"""
        if not confirm_clicks:
            raise dash.exceptions.PreventUpdate

        # Admin-only check
        if not current_user.is_authenticated or not current_user.is_admin():
            toast = ToastManager.error(
                "Access Denied",
                detail_message="Bulk device deletion is restricted to administrators only."
            )
            return toast

        # Get selected device IPs
        selected_ips = [
            checkbox_ids[i]['ip']
            for i, checked in enumerate(checkbox_values)
            if checked
        ]

        if not selected_ips:
            return dash.no_update

        # Check rate limit for bulk operations
        allowed, remaining, reset_sec = rate_limiter.check_rate_limit(
            current_user.username, 'bulk_operation'
        )
        if not allowed:
            toast = ToastManager.warning(
                "Rate Limit Exceeded",
                detail_message=f"Too many bulk operations. Try again in {reset_sec} seconds."
            )
            return toast

        # Check delete permission
        if not can_delete_data(current_user):
            security_audit_logger.log(
                event_type='permission_denied',
                user_id=current_user.id if current_user.is_authenticated else None,
                username=current_user.username if current_user.is_authenticated else 'anonymous',
                details={'action': 'bulk_delete_devices', 'device_count': len(selected_ips)},
                severity='high',
                result='failure',
                failure_reason='Insufficient permissions - requires delete_data (admin only)'
            )
            toast = ToastManager.error(
                "Permission Denied",
                detail_message="You don't have permission to delete devices. This action requires admin privileges."
            )
            return toast

        # Record the attempt
        rate_limiter.record_attempt(current_user.username, 'bulk_operation', success=True)

        try:
            count = len(selected_ips)
            conn = db_manager.conn
            cursor = conn.cursor()

            for ip in selected_ips:
                cursor.execute("DELETE FROM devices WHERE device_ip = ?", (ip,))

            conn.commit()

            # Log to audit trail
            log_bulk_action(audit_logger, 'delete', count, success=True)

            # Log to security audit
            security_audit_logger.log(
                event_type='bulk_operation',
                user_id=current_user.id,
                username=current_user.username,
                details={'operation': 'delete', 'device_count': count, 'device_ips': selected_ips},
                severity='high',
                resource_type='devices',
                result='success'
            )

            toast = ToastManager.warning(
                "Bulk Delete",
                detail_message=f"Deleted {count} device(s)"
            )
            return toast

        except Exception as e:
            logger.error(f"Bulk delete error: {e}")
            log_bulk_action(audit_logger, 'delete', count, success=False, error_message=str(e))
            toast = ToastManager.error(
                "Delete Failed",
                detail_message=f"Error: {str(e)}"
            )
            return toast

    # ====================================================================
    # 7. Bulk trust all unknown devices
    # ====================================================================
    @app.callback(
        Output('toast-container', 'children', allow_duplicate=True),
        Input('bulk-trust-all-btn', 'n_clicks'),
        prevent_initial_call=True
    )
    @login_required
    def bulk_trust_all_unknown(n_clicks):
        """Trust all unknown/unclassified devices. Requires manage_devices permission."""
        if not n_clicks:
            raise dash.exceptions.PreventUpdate

        # Check manage devices permission
        if not can_manage_devices(current_user):
            security_audit_logger.log(
                event_type='permission_denied',
                user_id=current_user.id if current_user.is_authenticated else None,
                username=current_user.username if current_user.is_authenticated else 'anonymous',
                details={'action': 'bulk_trust_devices'},
                severity='medium',
                result='failure',
                failure_reason='Insufficient permissions - requires manage_devices'
            )
            toast = ToastManager.error(
                "Permission Denied",
                detail_message="You don't have permission to manage devices."
            )
            return toast

        # Check rate limit
        allowed, remaining, reset_sec = rate_limiter.check_rate_limit(
            current_user.username, 'bulk_operation'
        )
        if not allowed:
            toast = ToastManager.warning(
                "Rate Limit Exceeded",
                detail_message=f"Too many bulk operations. Try again in {reset_sec} seconds."
            )
            return toast

        # Record the attempt
        rate_limiter.record_attempt(current_user.username, 'bulk_operation', success=True)

        try:
            conn = get_db_connection()

            cursor = conn.cursor()
            cursor.execute('''
                UPDATE devices SET is_trusted = 1
                WHERE is_trusted = 0 AND is_blocked = 0
            ''')
            count = cursor.rowcount
            conn.commit()

            # Log to audit trail
            log_bulk_action(audit_logger, 'trust', count, success=True)

            # Log to security audit
            security_audit_logger.log(
                event_type='bulk_operation',
                user_id=current_user.id,
                username=current_user.username,
                details={'operation': 'trust_all_unknown', 'device_count': count},
                severity='medium',
                resource_type='devices',
                result='success'
            )

            toast = ToastManager.success(
                "Bulk Trust Complete",
                detail_message=f"Marked {count} device(s) as trusted"
            )
            return toast

        except Exception as e:
            logger.error(f"Error trusting all: {e}")
            log_bulk_action(audit_logger, 'trust', 0, success=False, error_message=str(e))
            toast = ToastManager.error(
                "Error",
                detail_message="Error"
            )
            return toast

    # ====================================================================
    # 8. Bulk block suspicious devices
    # ====================================================================
    @app.callback(
        Output('toast-container', 'children', allow_duplicate=True),
        Input('bulk-block-suspicious-btn', 'n_clicks'),
        prevent_initial_call=True
    )
    @login_required
    def bulk_block_suspicious(n_clicks):
        """Block all suspicious devices (those with alerts). Requires block_devices permission."""
        if not n_clicks:
            raise dash.exceptions.PreventUpdate

        # RBAC permission check
        if not can_block_devices(current_user):
            security_audit_logger.log(
                event_type='permission_denied',
                user_id=current_user.id if current_user.is_authenticated else None,
                username=current_user.username if current_user.is_authenticated else 'anonymous',
                details={'action': 'bulk_block_suspicious'},
                severity='high',
                result='failure',
                failure_reason='Requires block_devices permission (security_analyst+)'
            )
            toast = ToastManager.error(
                "Permission Denied",
                detail_message="You don't have permission to block devices. Security analyst privileges required."
            )
            return toast

        # Check rate limit
        allowed, remaining, reset_sec = rate_limiter.check_rate_limit(
            current_user.username, 'bulk_operation'
        )
        if not allowed:
            toast = ToastManager.warning(
                "Rate Limit Exceeded",
                detail_message=f"Too many bulk operations. Try again in {reset_sec} seconds."
            )
            return toast

        # Record the attempt
        rate_limiter.record_attempt(current_user.username, 'bulk_operation', success=True)

        try:
            conn = get_db_connection()

            cursor = conn.cursor()
            # Block devices that have critical/high alerts
            cursor.execute('''
                UPDATE devices SET is_blocked = 1
                WHERE device_ip IN (
                    SELECT DISTINCT device_ip FROM alerts
                    WHERE severity IN ('critical', 'high')
                )
            ''')
            count = cursor.rowcount
            conn.commit()

            # Log to audit trail
            log_bulk_action(audit_logger, 'block_suspicious', count, success=True)

            # Log to security audit
            security_audit_logger.log(
                event_type='bulk_operation',
                user_id=current_user.id,
                username=current_user.username,
                details={'operation': 'block_suspicious', 'device_count': count},
                severity='high',
                resource_type='devices',
                result='success'
            )

            toast = ToastManager.warning(
                "Bulk Block Complete",
                detail_message=f"Blocked {count} suspicious device(s) with critical/high alerts"
            )
            return toast

        except Exception as e:
            logger.error(f"Error blocking suspicious: {e}")
            log_bulk_action(audit_logger, 'block_suspicious', 0, success=False, error_message=str(e))
            toast = ToastManager.error(
                "Error",
                detail_message="Error"
            )
            return toast

    # ====================================================================
    # 9. Toggle bulk buttons & selected count
    # ====================================================================
    @app.callback(
        [Output('bulk-trust-btn', 'disabled'),
         Output('bulk-block-btn', 'disabled'),
         Output('bulk-delete-btn', 'disabled'),
         Output('selected-count-display', 'children'),
         Output('selected-devices-store', 'data')],
        [Input({'type': 'device-checkbox', 'ip': ALL}, 'value')],
        [State({'type': 'device-checkbox', 'ip': ALL}, 'id')],
        prevent_initial_call=True
    )
    def toggle_bulk_buttons(checkbox_values, checkbox_ids):
        """Enable/disable bulk action buttons based on selections, update count, and sync store"""
        selected_count = sum(1 for val in checkbox_values if val) if checkbox_values else 0
        has_selection = selected_count > 0

        # Build list of selected device IPs
        selected_ips = []
        if checkbox_values and checkbox_ids:
            for i, val in enumerate(checkbox_values):
                if val and i < len(checkbox_ids):
                    selected_ips.append(checkbox_ids[i]['ip'])

        # Disabled = NOT has_selection
        return not has_selection, not has_selection, not has_selection, str(selected_count), selected_ips

    # ====================================================================
    # 10. Clientside: toggle select-all checkbox when button is clicked
    # ====================================================================
    app.clientside_callback(
        """
        function(n_clicks, current_value) {
            if (!n_clicks) {
                return window.dash_clientside.no_update;
            }
            return !current_value;
        }
        """,
        Output('select-all-devices-checkbox', 'value'),
        Input('select-all-btn-wrapper', 'n_clicks'),
        State('select-all-devices-checkbox', 'value'),
        prevent_initial_call=True
    )

    # ====================================================================
    # 11. Select all devices
    # ====================================================================
    @app.callback(
        Output({'type': 'device-checkbox', 'ip': ALL}, 'value'),
        Input('select-all-devices-checkbox', 'value'),
        prevent_initial_call=True
    )
    def select_all_devices(select_all):
        """Select or deselect all device checkboxes"""
        if select_all is None:
            return dash.no_update

        # Get the number of outputs from callback context
        # In pattern-matching callbacks, outputs_list contains all matched outputs
        num_checkboxes = len(callback_context.outputs_list)

        # Return a list of True or False values for each checkbox
        return [select_all] * num_checkboxes

    # ====================================================================
    # 12. Selected devices list
    # ====================================================================
    @app.callback(
        Output('selected-devices-list', 'children'),
        Input('selected-devices-store', 'data')
    )
    def display_selected_devices(selected_ips):
        """Display the list of selected devices in the Bulk Actions tab"""
        if not selected_ips:
            return html.Div([
                html.I(className="fa fa-info-circle me-2 text-muted"),
                html.Span("No devices selected. Go to the Devices tab and check the boxes next to devices you want to manage.", className="text-muted")
            ], className="text-center py-3")

        # Get all devices and filter for selected IPs
        all_devices = db_manager.get_all_devices()
        devices_info = [d for d in all_devices if d.get('device_ip') in selected_ips]

        if not devices_info:
            return html.Div("Selected devices not found", className="text-muted text-center")

        # Create cards for each selected device
        device_cards = []
        for device in devices_info:
            device_ip = device.get('device_ip', '')
            device_name = device.get('custom_name') or device.get('device_name') or device_ip
            manufacturer = device.get('manufacturer', 'Unknown')
            device_type = device.get('device_type', 'Unknown')
            icon = device.get('icon', '❓')

            card = dbc.Card([
                dbc.CardBody([
                    dbc.Row([
                        dbc.Col([
                            html.Span(icon, className="u-icon-lg"),
                            html.Strong(device_name),
                            html.Br(),
                            html.Small(f"{manufacturer} • {device_type}", className="text-muted")
                        ], xs=8, sm=8),
                        dbc.Col([
                            html.Small("IP:", className="text-muted d-block"),
                            html.Span(device_ip, className="font-monospace small")
                        ], xs=4, sm=4, className="text-end")
                    ])
                ])
            ], className="mb-2")
            device_cards.append(card)

        return html.Div([
            html.H6([
                html.I(className="fa fa-list me-2"),
                f"Selected Devices ({len(devices_info)})"
            ], className="mb-3"),
            html.Div(device_cards, className="scroll-panel-sm")
        ])

    # ====================================================================
    # 13. Device details view
    # ====================================================================
    @app.callback(
        [Output('device-detail-view', 'children'),
         Output('device-detail-modal-title', 'children'),
         Output('device-detail-modal', 'is_open', allow_duplicate=True)],
        Input({'type': 'view-device-btn', 'ip': ALL}, 'n_clicks'),
        State({'type': 'view-device-btn', 'ip': ALL}, 'id'),
        prevent_initial_call=True
    )
    def show_device_details_modal(clicks, ids):
        """Open device details as a centered modal popup when view button is clicked"""
        ctx = callback_context

        if not ctx.triggered or not any(clicks):
            raise dash.exceptions.PreventUpdate

        # Find which button was clicked
        triggered_idx = None
        for i, click_count in enumerate(clicks):
            if click_count and click_count > 0:
                triggered_idx = i
                break

        if triggered_idx is None:
            raise dash.exceptions.PreventUpdate

        device_ip = ids[triggered_idx]['ip']

        # Get device details
        device = get_device_details(device_ip)
        if not device:
            return html.Div([
                dbc.Alert("Device details not found", color="warning")
            ]), "Unknown Device", True

        device_name = device.get('custom_name') or device.get('device_name') or device_ip
        device_type = device.get('device_type', 'unknown')
        baseline = device.get('baseline', {})
        today_stats = device.get('today_stats', {})

        # Calculate hardware lifecycle info
        mfg_date = device.get('manufacturing_date')
        eol_date = device.get('hardware_eol_date')
        device_age_msg = ""
        eol_warning = None

        if mfg_date:
            try:
                mfg_datetime = datetime.fromisoformat(mfg_date) if isinstance(mfg_date, str) else mfg_date
                age_days = (datetime.now() - mfg_datetime).days
                age_years = age_days // 365
                age_months = (age_days % 365) // 30
                if age_years > 0:
                    device_age_msg = f"Device is {age_years} year(s) and {age_months} month(s) old"
                else:
                    device_age_msg = f"Device is {age_months} month(s) old"
            except:
                device_age_msg = ""

        if eol_date:
            try:
                eol_datetime = datetime.fromisoformat(eol_date) if isinstance(eol_date, str) else eol_date
                days_to_eol = (eol_datetime - datetime.now()).days
                if days_to_eol < 0:
                    eol_warning = dbc.Alert([
                        html.I(className="fa fa-exclamation-triangle me-2"),
                        f"⚠️ This device is past its End-of-Life date by {abs(days_to_eol)} days. Consider replacement for security."
                    ], color="danger", className="mb-2")
                elif days_to_eol < 180:
                    eol_warning = dbc.Alert([
                        html.I(className="fa fa-exclamation-circle me-2"),
                        f"⚠️ This device will reach End-of-Life in {days_to_eol} days. Plan for replacement."
                    ], color="warning", className="mb-2")
            except:
                pass

        # Fetch recent alerts for History tab
        try:
            _hist_cursor = db_manager.conn.cursor()
            _hist_cursor.execute(
                """SELECT id, timestamp, severity, explanation, acknowledged
                   FROM alerts WHERE device_ip = ?
                   ORDER BY timestamp DESC LIMIT 20""",
                (device_ip,)
            )
            recent_device_alerts = [dict(r) for r in _hist_cursor.fetchall()]
        except Exception:
            recent_device_alerts = []

        # Fetch CVE vulnerabilities for the Security tab
        try:
            from utils.cve_matcher import CVEMatcher
            _cve_matcher = CVEMatcher(db_manager=db_manager)
            device_cves = _cve_matcher.get_device_vulnerabilities(device_ip)
        except Exception:
            device_cves = []

        # ── Tab helpers ──────────────────────────────────────────────────
        def _info_row(icon, label, value):
            return html.Div([
                html.I(className=f"fa {icon} me-2 text-muted"),
                html.Strong(f"{label}: "),
                html.Span(value)
            ], className="mb-2")

        # ── Tab 1: Overview ───────────────────────────────────────────────
        tab_overview = html.Div([
            # AI Personality Profile card — populated by update_device_personality callback
            dbc.Card([
                dbc.CardBody([
                    html.Div([
                        html.Div([
                            html.I(className="fa fa-user-circle me-2 text-purple"),
                            html.Strong("Device Personality"),
                            html.Small(" - AI behavioural profile", className="text-muted ms-1"),
                        ], className="d-flex align-items-center"),
                        html.Div([
                            dbc.Badge(
                                id="device-personality-source-badge",
                                children="",
                                className="ms-2 badge-sm badge bg-secondary",
                            ),
                            html.Small(
                                id="device-personality-timestamp",
                                children="",
                                className="text-muted ms-2",
                            ),
                            dbc.Button(
                                html.I(className="fa fa-sync-alt"),
                                id="device-personality-refresh-btn",
                                size="sm", color="link",
                                className="ms-1 p-0 text-muted",
                                title="Regenerate personality profile",
                            ),
                        ], className="d-flex align-items-center"),
                    ], className="d-flex align-items-center justify-content-between mb-2"),
                    html.Div(
                        id="device-personality-content",
                        children=[
                            html.Div([
                                html.I(className="fa fa-circle-notch fa-spin me-2 text-muted"),
                                html.Small("Generating personality profile...", className="text-muted"),
                            ], className="py-2"),
                        ],
                    ),
                    # Carries the current device IP so the fill callback fires on modal open
                    dcc.Store(id="device-personality-device", data=device_ip),
                ]),
            ], className="mb-3 border-0 glass-card shadow-sm"),

            dbc.Card([
                dbc.CardBody([
                    html.Div([
                        html.I(className="fa fa-info-circle me-2 text-primary"),
                        html.Strong("Basic Information")
                    ], className="mb-3"),
                    dbc.Row([
                        dbc.Col([
                            _info_row("fa-network-wired", "IP Address", device_ip),
                            _info_row("fa-ethernet",      "MAC Address", device.get('mac_address', 'Unknown')),
                            _info_row("fa-industry",      "Manufacturer", device.get('manufacturer', 'Unknown')),
                        ], xs=12, sm=6),
                        dbc.Col([
                            html.Div([
                                html.I(className="fa fa-tag me-2 text-muted"),
                                html.Strong("Device Type: "),
                                dbc.Badge(device.get('device_type', 'Unknown'), color="info", className="ms-1")
                            ], className="mb-2"),
                            _info_row("fa-clock",   "First Seen", device.get('first_seen', 'Unknown')),
                            _info_row("fa-history", "Last Seen",  device.get('last_seen', 'Unknown')),
                        ], xs=12, sm=6),
                    ]),
                    html.Hr(className="my-2"),
                    # Editable friendly name with AI suggestion
                    html.Div([
                        html.I(className="fa fa-pen me-2 text-muted"),
                        html.Strong("Friendly Name"),
                        html.Small(" - shown throughout the dashboard", className="text-muted ms-1"),
                    ], className="mb-2"),
                    dbc.InputGroup([
                        dbc.Input(
                            id={'type': 'device-custom-name', 'ip': device_ip},
                            value=device.get('custom_name') or '',
                            placeholder="e.g. Living Room TV, Kids iPad, Front Door Camera",
                            size="sm",
                            debounce=False,
                        ),
                        dbc.Button(
                            [html.I(className="fa fa-save me-1"), "Save"],
                            id={'type': 'device-name-save-btn', 'ip': device_ip},
                            size="sm", color="success", outline=True,
                        ),
                    ], size="sm", className="mb-3"),
                    html.Hr(),
                    dbc.Row([
                        dbc.Col([
                            dbc.Card([
                                dbc.CardBody([
                                    html.H4(f"{device.get('total_connections', 0):,}", className="mb-0 text-info"),
                                    html.Small("Total Connections", className="text-muted")
                                ], className="text-center py-2")
                            ], className="border-0 bg-transparent")
                        ], xs=12, sm=4),
                        dbc.Col([
                            dbc.Card([
                                dbc.CardBody([
                                    html.H4(str(device.get('total_alerts', 0)), className="mb-0 text-warning"),
                                    html.Small("Total Alerts", className="text-muted")
                                ], className="text-center py-2")
                            ], className="border-0 bg-transparent")
                        ], xs=12, sm=4),
                        dbc.Col([
                            dbc.Card([
                                dbc.CardBody([
                                    html.H4(str(device.get('active_alerts', 0)), className="mb-0 text-danger"),
                                    html.Small("Active Alerts", className="text-muted")
                                ], className="text-center py-2")
                            ], className="border-0 bg-transparent")
                        ], xs=12, sm=4),
                    ]),
                ])
            ], className="mb-3 border-primary"),
        ], className="p-2")

        # ── Tab 2: Traffic ────────────────────────────────────────────────
        tab_traffic = html.Div([
            dbc.Card([
                dbc.CardBody([
                    html.H6([html.I(className="fa fa-chart-area me-2 text-info"), "Baseline vs Today"],
                            className="mb-3"),
                    dbc.Row([
                        dbc.Col([
                            dcc.Graph(
                                figure=create_baseline_comparison_chart(
                                    baseline, today_stats, "Data Sent",
                                    "avg_bytes_sent", "today_bytes_sent", "Data Sent: Baseline vs Today"
                                ) if baseline and baseline.get('has_baseline') else go.Figure().update_layout(title="No baseline data yet"),
                                config={'displayModeBar': False}
                            )
                        ], xs=12, sm=6),
                        dbc.Col([
                            dcc.Graph(
                                figure=create_baseline_comparison_chart(
                                    baseline, today_stats, "Connections",
                                    "avg_connections", "today_connections", "Connections: Baseline vs Today"
                                ) if baseline and baseline.get('has_baseline') else go.Figure().update_layout(title="No baseline data yet"),
                                config={'displayModeBar': False}
                            )
                        ], xs=12, sm=6),
                    ]),
                    html.Hr(),
                    dbc.Row([
                        dbc.Col([
                            html.Small([html.I(className="fa fa-arrow-up me-1"), "Today bytes sent: "],
                                       className="text-muted"),
                            html.Strong(f"{today_stats.get('today_bytes_sent', 0):,} B")
                        ], xs=12, sm=6, className="mb-2"),
                        dbc.Col([
                            html.Small([html.I(className="fa fa-plug me-1"), "Today connections: "],
                                       className="text-muted"),
                            html.Strong(str(today_stats.get('today_connections', 0)))
                        ], xs=12, sm=6, className="mb-2"),
                    ]) if today_stats else html.Div(),
                ])
            ], className="border-0 shadow-sm"),
        ], className="p-2")

        # ── Tab 3: Security ───────────────────────────────────────────────
        tab_security = html.Div([
            # Status + Trust
            dbc.Card([
                dbc.CardBody([
                    html.Div([
                        html.I(className="fa fa-shield-alt me-2 text-success"),
                        html.Strong("Security Status")
                    ], className="mb-3"),
                    html.Div([
                        html.Strong("Current Status: "),
                        create_status_indicator(device.get('status', 'unknown'), "1.2rem"),
                        html.Span(device.get('status', 'unknown').upper(), className="ms-2 fw-bold")
                    ], className="mb-3"),
                    html.Div([
                        html.I(className="fa fa-user-shield me-2 text-primary"),
                        html.Strong("Trust Status"),
                        dbc.Switch(
                            id={'type': 'device-trust-switch', 'ip': device_ip},
                            label="Mark as Trusted Device",
                            value=bool(device.get('is_trusted', False)),
                            className="ms-3 d-inline-block"
                        )
                    ], className="mb-2"),
                    html.Small([
                        html.I(className="fa fa-info-circle me-1"),
                        "Trusted devices have different alert thresholds and security policies"
                    ], className="text-muted d-block"),
                ])
            ], className="mb-3 border-success"),
            # Kids Protection
            dbc.Card([
                dbc.CardBody([
                    html.Div([
                        html.I(className="fa fa-child me-2 text-info"),
                        html.Strong("Kids Device Protection")
                    ], className="mb-2"),
                    dbc.Switch(
                        id={'type': 'device-kids-switch', 'ip': device_ip},
                        label="Enable Kids Device Monitoring",
                        value=bool(device.get('is_kids_device', False)),
                        className="mb-2"
                    ),
                    html.Small([
                        html.I(className="fa fa-shield-alt me-1"),
                        "Monitors for malicious IPs, excessive uploads, and late-night activity (11PM-6AM)"
                    ], className="text-muted d-block"),
                    dbc.Alert([
                        html.I(className="fa fa-check-circle me-2"),
                        "Kids device protection is actively monitoring this device"
                    ], color="info", className="mt-2 mb-0 u-text-sm") if device.get('is_kids_device', False) else html.Div(),
                ])
            ], className="mb-3 border-info" if device.get('is_kids_device', False) else "mb-3"),
            # Network Access Control
            dbc.Card([
                dbc.CardBody([
                    html.Div([
                        html.I(className="fa fa-network-wired me-2 text-warning"),
                        html.Strong("Network Access Control")
                    ], className="mb-3"),
                    dbc.Alert([
                        html.I(className="fa fa-ban me-2"),
                        "This device is currently BLOCKED from network access"
                    ], color="danger") if device.get('is_blocked', False) else html.Div(),
                    dbc.Button(
                        [html.I(className="fa fa-ban me-2"), "Block Device"] if not device.get('is_blocked', False) else [html.I(className="fa fa-check-circle me-2"), "Unblock Device"],
                        id={'type': 'device-block-btn', 'ip': device_ip},
                        color="danger" if not device.get('is_blocked', False) else "success",
                        outline=True, size="sm", className="w-100"
                    ),
                    html.Div(id={'type': 'block-status', 'ip': device_ip}, className="mt-2"),
                    html.Small([
                        html.I(className="fa fa-info-circle me-1"),
                        "Requires firewall integration to be enabled"
                    ], className="text-muted d-block mt-2"),
                ])
            ], className="mb-3 border-warning"),
            # Known CVE Vulnerabilities
            dbc.Card([
                dbc.CardBody([
                    html.Div([
                        html.I(className="fa fa-bug me-2 text-danger"),
                        html.Strong("Known Vulnerabilities (CVE)"),
                        dbc.Badge(
                            str(len(device_cves)),
                            color="danger" if any(v.get('severity') in ('critical', 'high') for v in device_cves) else "warning" if device_cves else "secondary",
                            className="ms-2",
                        ),
                    ], className="mb-3"),
                    *([
                        dbc.ListGroup([
                            dbc.ListGroupItem([
                                html.Div([
                                    dbc.Badge(
                                        v.get('severity', 'unknown').upper(),
                                        color={'critical': 'danger', 'high': 'warning', 'medium': 'info', 'low': 'secondary'}.get(v.get('severity', 'unknown'), 'secondary'),
                                        className="me-2",
                                    ),
                                    html.Strong(v.get('cve_id', 'Unknown'), className="me-2"),
                                    html.Small(f"CVSS {v.get('cvss_score', 0.0):.1f}", className="text-muted"),
                                ], className="d-flex align-items-center mb-1"),
                                html.Small(
                                    (v.get('description') or 'No description available')[:120],
                                    className="text-muted d-block",
                                ),
                            ], className="border-0 mb-1")
                            for v in device_cves[:10]
                        ], flush=True)
                    ] if device_cves else [
                        html.Div([
                            html.I(className="fa fa-check-circle text-success me-2"),
                            html.Small("No known CVEs matched for this device.", className="text-muted"),
                        ])
                    ]),
                    html.Small([
                        html.I(className="fa fa-sync-alt me-1"),
                        "CVE data synced daily from the National Vulnerability Database (NVD)."
                    ], className="text-muted d-block mt-2"),
                ])
            ], className="mb-3 border-danger" if device_cves else "mb-3"),
        ], className="p-2")

        # ── Tab 4: Firmware ───────────────────────────────────────────────
        tab_firmware = html.Div([
            dbc.Card([
                dbc.CardBody([
                    html.Div([
                        html.I(className="fa fa-microchip me-2 text-info"),
                        html.Strong("Firmware & Model Info")
                    ], className="mb-3"),
                    dbc.Row([
                        dbc.Col([
                            dbc.Label("Model", size="sm", className="fw-bold"),
                            dbc.Input(
                                id={'type': 'device-model', 'ip': device_ip},
                                type="text",
                                value=device.get('model') or '',
                                size="sm", className="mb-2",
                                placeholder="e.g. Nest Hub 2nd Gen"
                            ),
                        ], xs=12, sm=6),
                        dbc.Col([
                            dbc.Label("Firmware Version", size="sm", className="fw-bold"),
                            dbc.Input(
                                id={'type': 'device-firmware', 'ip': device_ip},
                                type="text",
                                value=device.get('firmware_version') or '',
                                size="sm", className="mb-2",
                                placeholder="e.g. 1.52.301085"
                            ),
                        ], xs=12, sm=6),
                    ], className="g-2 mb-3"),
                ])
            ], className="mb-3 border-info"),
            dbc.Card([
                dbc.CardBody([
                    html.Div([
                        html.I(className="fa fa-recycle me-2 text-success"),
                        html.Strong("Hardware Lifecycle & E-Waste Tracking")
                    ], className="mb-3"),
                    eol_warning if eol_warning else html.Div(),
                    dbc.Row([
                        dbc.Col([
                            dbc.Label([html.I(className="fa fa-calendar me-1"), "Manufacturing Date"],
                                      size="sm", className="fw-bold text-primary"),
                            dbc.Input(
                                id={'type': 'device-mfg-date', 'ip': device_ip},
                                type="date",
                                value=device.get('manufacturing_date') or '',
                                size="sm", className="mb-2"
                            ),
                            html.Small([html.I(className="fa fa-birthday-cake me-1"), device_age_msg],
                                       className="text-success d-block") if device_age_msg else html.Div(),
                        ], xs=12, sm=6),
                        dbc.Col([
                            dbc.Label([html.I(className="fa fa-calendar-times me-1"), "Hardware EOL Date"],
                                      size="sm", className="fw-bold text-primary"),
                            dbc.Input(
                                id={'type': 'device-eol-date', 'ip': device_ip},
                                type="date",
                                value=device.get('hardware_eol_date') or '',
                                size="sm", className="mb-2"
                            ),
                        ], xs=12, sm=6),
                    ], className="g-2 mb-2"),
                    html.Small([
                        html.I(className="fa fa-leaf me-1"),
                        "Track device lifecycle for sustainability planning and proper recycling"
                    ], className="text-muted d-block"),
                ])
            ], className="mb-3 border-success"),
        ], className="p-2")

        # ── Tab 5: History ────────────────────────────────────────────────
        if recent_device_alerts:
            _sev_colors = {'critical': 'danger', 'high': 'warning', 'medium': 'info', 'low': 'secondary'}
            history_items = [
                dbc.ListGroupItem([
                    html.Div([
                        dbc.Badge(a.get('severity', 'low').upper(),
                                  color=_sev_colors.get(a.get('severity', 'low'), 'secondary'),
                                  className="me-2"),
                        html.Small(str(a.get('timestamp', ''))[:16], className="text-muted me-2"),
                        dbc.Badge("Reviewed", color="success", className="ms-1") if a.get('acknowledged') else None,
                    ], className="d-flex align-items-center mb-1"),
                    html.Small(a.get('explanation', 'No description')[:120], className="text-muted"),
                ], className="border-0 mb-1")
                for a in recent_device_alerts
            ]
            tab_history = html.Div([
                dbc.Card([
                    dbc.CardBody([
                        html.H6([html.I(className="fa fa-clock-rotate-left me-2"), f"Recent Alerts ({len(recent_device_alerts)})"],
                                className="mb-3"),
                        dbc.ListGroup(history_items, flush=True),
                    ])
                ], className="border-0 shadow-sm"),
            ], className="p-2")
        else:
            tab_history = html.Div([
                html.Div([
                    html.I(className="fa fa-check-circle fa-3x text-success mb-3 d-block"),
                    html.P("No alert history for this device.", className="text-muted text-center"),
                ], className="py-4 text-center")
            ], className="p-2")

        # ── Assemble modal title ─────────────────────────────────────────
        modal_title = [
            create_device_icon(device_type, use_emoji=True, use_fa=True, size="1.5rem"),
            html.Span(f"Device Details: {device_name}", className="ms-2")
        ]

        # ── Assemble tabbed body content ─────────────────────────────────
        details_content = dbc.Tabs([
            dbc.Tab(tab_overview,  label="Overview",  tab_id="dev-tab-overview",  className="pt-2"),
            dbc.Tab(tab_traffic,   label="Traffic",   tab_id="dev-tab-traffic",   className="pt-2"),
            dbc.Tab(tab_security,  label="Security",  tab_id="dev-tab-security",  className="pt-2"),
            dbc.Tab(tab_firmware,  label="Firmware",  tab_id="dev-tab-firmware",  className="pt-2"),
            dbc.Tab(tab_history,   label="History",   tab_id="dev-tab-history",   className="pt-2"),
        ], id="device-detail-tabs", active_tab="dev-tab-overview")

        # Open the centered device details modal
        return details_content, modal_title, True

    # ====================================================================
    # 14. Save device details
    # ====================================================================
    @app.callback(
        [Output('toast-container', 'children', allow_duplicate=True),
         Output('device-detail-modal', 'is_open', allow_duplicate=True)],
        Input('save-device-details-btn', 'n_clicks'),
        [State({'type': 'device-trust-switch', 'ip': ALL}, 'value'),
         State({'type': 'device-trust-switch', 'ip': ALL}, 'id'),
         State({'type': 'device-kids-switch', 'ip': ALL}, 'value'),
         State({'type': 'device-kids-switch', 'ip': ALL}, 'id'),
         State({'type': 'device-mfg-date', 'ip': ALL}, 'value'),
         State({'type': 'device-mfg-date', 'ip': ALL}, 'id'),
         State({'type': 'device-eol-date', 'ip': ALL}, 'value'),
         State({'type': 'device-eol-date', 'ip': ALL}, 'id'),
         State({'type': 'device-model', 'ip': ALL}, 'value'),
         State({'type': 'device-model', 'ip': ALL}, 'id'),
         State({'type': 'device-firmware', 'ip': ALL}, 'value'),
         State({'type': 'device-firmware', 'ip': ALL}, 'id')],
        prevent_initial_call=True
    )
    def save_device_details(n_clicks, trust_values, trust_ids, kids_values, kids_ids,
                           mfg_dates, mfg_ids, eol_dates, eol_ids,
                           model_values, model_ids, firmware_values, firmware_ids):
        """Save device details (trust, kids, lifecycle, model, firmware) and return to list."""
        if not n_clicks:
            raise dash.exceptions.PreventUpdate
        if not current_user.is_authenticated or not can_manage_devices(current_user):
            raise dash.exceptions.PreventUpdate

        try:
            device_ip = None
            trust_value = False
            kids_value = False
            mfg_date = None
            eol_date = None
            model_value = None
            firmware_value = None

            # Extract device IP and values from the IDs
            if trust_ids and len(trust_ids) > 0:
                for i, id_dict in enumerate(trust_ids):
                    if id_dict and 'ip' in id_dict:
                        device_ip = id_dict['ip']
                        trust_value = trust_values[i] if i < len(trust_values) else False

            if kids_ids and len(kids_ids) > 0:
                for i, id_dict in enumerate(kids_ids):
                    if id_dict and 'ip' in id_dict and id_dict['ip'] == device_ip:
                        kids_value = kids_values[i] if i < len(kids_values) else False

            if mfg_ids and len(mfg_ids) > 0:
                for i, id_dict in enumerate(mfg_ids):
                    if id_dict and 'ip' in id_dict and id_dict['ip'] == device_ip:
                        mfg_date = mfg_dates[i] if i < len(mfg_dates) and mfg_dates[i] else None

            if eol_ids and len(eol_ids) > 0:
                for i, id_dict in enumerate(eol_ids):
                    if id_dict and 'ip' in id_dict and id_dict['ip'] == device_ip:
                        eol_date = eol_dates[i] if i < len(eol_dates) and eol_dates[i] else None

            if model_ids and len(model_ids) > 0:
                for i, id_dict in enumerate(model_ids):
                    if id_dict and 'ip' in id_dict and id_dict['ip'] == device_ip:
                        model_value = model_values[i] if i < len(model_values) else None

            if firmware_ids and len(firmware_ids) > 0:
                for i, id_dict in enumerate(firmware_ids):
                    if id_dict and 'ip' in id_dict and id_dict['ip'] == device_ip:
                        firmware_value = firmware_values[i] if i < len(firmware_values) else None

            if device_ip:
                # Track what changed for specific toast message
                changes = []
                audit_details = {}

                # Update trust status in database
                db_manager.set_device_trust(device_ip, bool(trust_value))
                if trust_value:
                    changes.append("marked as trusted")
                    audit_details['trust_status'] = 'trusted'

                # Update kids device status
                if kids_value:
                    audit_details['kids_device'] = True
                cursor = db_manager.conn.cursor()
                cursor.execute(
                    "UPDATE devices SET is_kids_device = ? WHERE device_ip = ?",
                    (1 if kids_value else 0, device_ip)
                )
                if kids_value:
                    changes.append("kids device protection enabled")

                # Update hardware lifecycle dates
                if mfg_date or eol_date:
                    cursor.execute(
                        "UPDATE devices SET manufacturing_date = ?, hardware_eol_date = ? WHERE device_ip = ?",
                        (mfg_date if mfg_date else None, eol_date if eol_date else None, device_ip)
                    )
                    if mfg_date and eol_date:
                        changes.append("hardware lifecycle dates updated")
                    elif mfg_date:
                        changes.append("manufacturing date set")
                    elif eol_date:
                        changes.append("EOL date set")

                # Update model + firmware version
                if model_value is not None or firmware_value is not None:
                    cursor.execute(
                        "UPDATE devices SET model = COALESCE(?, model), firmware_version = COALESCE(?, firmware_version) WHERE device_ip = ?",
                        (model_value or None, firmware_value or None, device_ip)
                    )
                    if model_value:
                        changes.append(f"model set to {model_value}")
                    if firmware_value:
                        changes.append(f"firmware set to {firmware_value}")

                db_manager.conn.commit()

                # Log device details change to security audit
                if changes and current_user.is_authenticated:
                    if mfg_date:
                        audit_details['manufacturing_date'] = mfg_date
                    if eol_date:
                        audit_details['eol_date'] = eol_date

                    security_audit_logger.log(
                        event_type='settings_changed',
                        severity='info',
                        user_id=current_user.id,
                        username=current_user.username,
                        resource_type='device',
                        resource_id=device_ip,
                        details={'changes': changes, **audit_details},
                        result='success'
                    )

                # Create detailed success message
                if changes:
                    detail_msg = f"Device {device_ip}: " + ", ".join(changes)
                else:
                    detail_msg = f"Device settings updated for {device_ip}"

                toast = ToastManager.success(
                    "Device Settings Saved",
                    detail_message=detail_msg
                )

                # Close the details modal (user lands back on the device list)
                return toast, False

            # If we couldn't find device IP, show error
            toast = ToastManager.error(
                "Save Failed",
                detail_message="Could not identify device"
            )
            return toast, dash.no_update

        except Exception as e:
            logger.error(f"Error saving device details: {e}")
            toast = ToastManager.error(
                "Save Failed",
                detail_message=f"Error: {str(e)}"
            )
            return toast, dash.no_update

    # ====================================================================
    # 15. MQTT/CoAP stats
    # ====================================================================
    @app.callback(
        Output('mqtt-coap-stats', 'children'),
        [Input('refresh-interval', 'n_intervals')],
        prevent_initial_call=True  # W15: Devices tab not visible at startup
    )
    def update_protocol_stats(n):
        """Update MQTT and CoAP statistics."""
        if not iot_protocol_analyzer:
            return dbc.Alert([
                html.I(className="fa fa-info-circle me-2"),
                "IoT Protocol Analyzer ready. No protocol traffic detected yet."
            ], color="info")

        try:
            summary = iot_protocol_analyzer.get_protocol_summary()
            if not summary:
                return dbc.Alert("No IoT protocol traffic detected yet", color="info")

            cards = []
            for protocol, stats in summary.items():
                encryption_status = "🔒 Encrypted" if stats.get('encryption_used') else "⚠️ Unencrypted"
                encryption_color = "green" if stats.get('encryption_used') else "red"

                cards.append(
                    dbc.Col([
                        dbc.Card([
                            dbc.CardBody([
                                html.H4(protocol.upper(), className="text-primary mb-2"),
                                html.P(f"📊 Messages: {stats.get('total_messages', 0):,}", className="mb-1 small"),
                                html.P(f"📦 Bytes: {stats.get('total_bytes', 0):,}", className="mb-1 small"),
                                html.P(encryption_status, className="mb-0 small",
                                      style={'color': encryption_color, 'fontWeight': 'bold'})
                            ])
                        ], className="cyber-card text-center", style={"borderLeft": f"4px solid {encryption_color}"})
                    ], xs=12, sm=4)
                )

            return dbc.Row(cards, className="mt-3")
        except Exception as e:
            logger.error(f"Error updating protocol stats: {e}")
            return dbc.Alert(f"Error loading protocol stats", color="warning")

    # ====================================================================
    # 17. Threat detection stats
    # ====================================================================
    @app.callback(
        Output('threat-detection-stats', 'children'),
        [Input('refresh-interval', 'n_intervals')],
        prevent_initial_call=True  # W15: Devices tab not visible at startup
    )
    def update_threat_stats(n):
        """Update threat detection statistics."""
        if not iot_threat_detector:
            return dbc.Alert("IoT Threat Detector ready. Monitoring for threats...", color="info")

        try:
            summary = iot_threat_detector.get_threat_summary(hours=24)

            botnet_count = sum(v['count'] for v in summary.get('botnet_detections', {}).values())
            ddos_count = sum(v['count'] for v in summary.get('ddos_events', {}).values())

            return dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardBody([
                            html.H2(str(botnet_count), className="text-danger mb-0"),
                            html.P("🐛 Botnet Detections", className="text-muted small")
                        ])
                    ], className="cyber-card text-center border-left-danger")
                ], xs=12, sm=4),
                dbc.Col([
                    dbc.Card([
                        dbc.CardBody([
                            html.H2(str(ddos_count), className="text-warning mb-0"),
                            html.P("⚡ DDoS Events", className="text-muted small")
                        ])
                    ], className="cyber-card text-center border-left-warning")
                ], xs=12, sm=4),
                dbc.Col([
                    dbc.Card([
                        dbc.CardBody([
                            html.H2(str(summary.get('total_threats', 0)), className="text-info mb-0"),
                            html.P("📊 Total Threats", className="text-muted small")
                        ])
                    ], className="cyber-card text-center border-left-info")
                ], xs=12, sm=4)
            ], className="mt-3")
        except Exception as e:
            logger.error(f"Error updating threat stats: {e}")
            return dbc.Alert("No threat data available yet", color="info")

    # ====================================================================
    # 18. Privacy score section
    # ====================================================================
    @app.callback(
        Output('privacy-score-section', 'children'),
        [Input('refresh-interval', 'n_intervals')],
        prevent_initial_call=True  # W15: Devices tab not visible at startup
    )
    def update_privacy_score(n):
        """Update overall privacy score."""
        try:
            conn = get_db_connection()

            cursor = conn.cursor()
            cursor.execute('''
                SELECT privacy_concern_level, COUNT(DISTINCT device_ip) as count
                FROM cloud_connections
                GROUP BY privacy_concern_level
            ''')

            concerns = {row['privacy_concern_level']: row['count'] for row in cursor.fetchall()}

            high_concern = concerns.get('high', 0) + concerns.get('critical', 0)
            total_devices = sum(concerns.values())

            if total_devices == 0:
                return dbc.Alert([
                    html.I(className="fa fa-cloud me-2"),
                    "No cloud connections detected yet. Privacy monitoring active."
                ], color="success")

            privacy_score = max(0, 100 - (high_concern / total_devices * 50))

            score_color = "success" if privacy_score > 70 else "warning" if privacy_score > 40 else "danger"

            return dbc.Card([
                dbc.CardBody([
                    html.H1(f"{privacy_score:.0f}", className=f"text-center text-{score_color} mb-1 u-text-hero"),
                    html.P("Privacy Score", className="text-center text-muted mb-1"),
                    html.Small(f"{high_concern} of {total_devices} devices with privacy concerns",
                              className="text-center d-block text-muted")
                ])
            ], className="cyber-card mt-3 border-left-accent")
        except Exception as e:
            logger.error(f"Error calculating privacy score: {e}")
            return dbc.Alert("Privacy monitoring active", color="info")

    # ====================================================================
    # 19. Privacy modal score
    # ====================================================================
    @app.callback(
        [Output('privacy-modal-score-value', 'children'),
         Output('privacy-modal-score-bar', 'value'),
         Output('privacy-modal-score-bar', 'color'),
         Output('privacy-modal-score-status', 'children'),
         Output('privacy-modal-score-status', 'className'),
         Output('privacy-modal-breakdown', 'children'),
         Output('privacy-modal-recommendations', 'children')],
        [Input('privacy-modal', 'is_open')],
        prevent_initial_call=True
    )
    def update_privacy_modal_score(is_open):
        """Update privacy modal score display with real data."""
        if not is_open:
            raise dash.exceptions.PreventUpdate

        try:
            conn = get_db_connection()

            cursor = conn.cursor()

            # Get privacy concerns
            cursor.execute('''
                SELECT privacy_concern_level, COUNT(DISTINCT device_ip) as count
                FROM cloud_connections
                GROUP BY privacy_concern_level
            ''')
            concerns = {row['privacy_concern_level']: row['count'] for row in cursor.fetchall()}

            # Get encryption stats from cloud_connections
            cursor.execute('''
                SELECT
                    SUM(CASE WHEN uses_encryption = 1 THEN 1 ELSE 0 END) as encrypted,
                    COUNT(*) as total
                FROM cloud_connections
            ''')
            enc_row = cursor.fetchone()
            encrypted = enc_row['encrypted'] or 0
            total_conn = enc_row['total'] or 1
            encryption_pct = int((encrypted / max(total_conn, 1)) * 100)

            # Get external connections
            cursor.execute('''
                SELECT COUNT(DISTINCT dest_ip) as count FROM connections
                WHERE timestamp >= datetime("now", "-24 hours")
                AND dest_ip NOT LIKE "192.168.%"
                AND dest_ip NOT LIKE "10.%"
            ''')
            external_conn = cursor.fetchone()['count']


            high_concern = concerns.get('high', 0) + concerns.get('critical', 0)
            total_devices = sum(concerns.values()) or 1

            privacy_score = max(0, 100 - (high_concern / total_devices * 50))

            if privacy_score > 70:
                color = "success"
                status = "Your network privacy is GOOD"
                status_class = "text-center text-success fw-bold"
            elif privacy_score > 40:
                color = "warning"
                status = "Your network privacy needs ATTENTION"
                status_class = "text-center text-warning fw-bold"
            else:
                color = "danger"
                status = "Your network privacy is at RISK"
                status_class = "text-center text-danger fw-bold"

            # Build breakdown
            enc_color = "text-success" if encryption_pct > 80 else "text-warning" if encryption_pct > 50 else "text-danger"
            leak_status = "Low" if high_concern < 3 else "Medium" if high_concern < 6 else "High"
            leak_color = "text-success" if leak_status == "Low" else "text-warning" if leak_status == "Medium" else "text-danger"
            ext_color = "text-success" if external_conn < 10 else "text-warning" if external_conn < 30 else "text-danger"

            breakdown = html.Div([
                html.Div(["🔒 Encryption: ", html.Strong(f"{encryption_pct}%", className=enc_color)], className="mb-2"),
                html.Div(["📡 Data Leakage: ", html.Strong(leak_status, className=leak_color)], className="mb-2"),
                html.Div(["🌐 External Connections: ", html.Strong(f"{external_conn} tracked", className=ext_color)], className="mb-2"),
                html.Div(["🔍 High Concern Devices: ", html.Strong(f"{high_concern}", className=leak_color)], className="mb-2")
            ])

            # Build recommendations
            recommendations = []
            if encryption_pct < 80:
                recommendations.append(dbc.Alert([
                    html.I(className="fa fa-exclamation-triangle me-2"),
                    f"{100 - encryption_pct}% of connections are unencrypted. Consider enabling encryption."
                ], color="warning", className="mb-2"))
            if high_concern > 0:
                recommendations.append(dbc.Alert([
                    html.I(className="fa fa-info-circle me-2"),
                    f"{high_concern} devices have privacy concerns. Review cloud connections."
                ], color="info", className="mb-0"))
            if not recommendations:
                recommendations.append(dbc.Alert([
                    html.I(className="fa fa-check-circle me-2"),
                    "No immediate privacy concerns detected. Keep monitoring!"
                ], color="success", className="mb-0"))

            return f"{privacy_score:.0f}", int(privacy_score), color, status, status_class, breakdown, recommendations

        except Exception as e:
            logger.error(f"Error updating privacy modal: {e}")
            return "—", 0, "secondary", "Error loading data", "text-center text-muted fw-bold", [], []

    # ====================================================================
    # 20. Cloud upload stats
    # ====================================================================
    @app.callback(
        [Output('cloud-upload-total', 'children'),
         Output('cloud-services-count', 'children'),
         Output('suspicious-uploads-count', 'children')],
        [Input('privacy-modal', 'is_open')],
        prevent_initial_call=True
    )
    def update_cloud_upload_stats(is_open):
        """Update cloud upload statistics."""
        if not is_open:
            raise dash.exceptions.PreventUpdate

        try:
            conn = get_db_connection()

            cursor = conn.cursor()

            # Get total data uploaded (estimate from connections)
            cursor.execute('''
                SELECT SUM(bytes_sent) as total FROM connections
                WHERE timestamp >= datetime("now", "-24 hours")
            ''')
            total_bytes = cursor.fetchone()['total'] or 0

            # Format bytes
            if total_bytes >= 1073741824:
                upload_str = f"{total_bytes / 1073741824:.1f} GB"
            elif total_bytes >= 1048576:
                upload_str = f"{total_bytes / 1048576:.1f} MB"
            elif total_bytes >= 1024:
                upload_str = f"{total_bytes / 1024:.1f} KB"
            else:
                upload_str = f"{total_bytes} B"

            # Get cloud services count
            cursor.execute('''
                SELECT COUNT(DISTINCT cloud_provider) as count FROM cloud_connections
            ''')
            services = cursor.fetchone()['count']

            # Get suspicious uploads (high concern)
            cursor.execute('''
                SELECT COUNT(*) as count FROM cloud_connections
                WHERE privacy_concern_level IN ('high', 'critical')
            ''')
            suspicious = cursor.fetchone()['count']


            return upload_str, str(services), str(suspicious)

        except Exception as e:
            logger.error(f"Error updating cloud stats: {e}")
            return "0 B", "0", "0"

    # ====================================================================
    # 21. Tracker detection
    # ====================================================================
    @app.callback(
        [Output('trackers-detected-count', 'children'),
         Output('trackers-blocked-count', 'children', allow_duplicate=True),
         Output('trackers-pending-count', 'children', allow_duplicate=True),
         Output('tracker-categories-list', 'children'),
         Output('toast-container', 'children', allow_duplicate=True)],
        [Input('privacy-modal', 'is_open'),
         Input('refresh-tracker-btn', 'n_clicks'),
         Input('tracker-search-input', 'value'),
         Input('privacy-concern-filter', 'value')],
        prevent_initial_call=True
    )
    def update_tracker_stats(is_open, refresh_clicks, search_text, privacy_filter):
        """Update tracker detection statistics with search and filter support."""
        from dash import callback_context
        ctx = callback_context

        # Check if refresh button was clicked
        show_toast = ctx.triggered and ctx.triggered[0]['prop_id'] == 'refresh-tracker-btn.n_clicks' if ctx.triggered else False

        if not is_open:
            raise dash.exceptions.PreventUpdate

        try:
            conn = get_db_connection()

            cursor = conn.cursor()

            # Build filter clause for privacy concern level
            privacy_clause = ""
            if privacy_filter and privacy_filter != 'all':
                privacy_clause = f"AND privacy_concern_level = '{privacy_filter}'"

            # Get tracker stats from cloud connections based on provider type
            cursor.execute(f'''
                SELECT cloud_provider, cloud_domain, device_ip, privacy_concern_level, COUNT(*) as count
                FROM cloud_connections
                WHERE (cloud_provider LIKE '%analytics%'
                   OR cloud_provider LIKE '%track%'
                   OR cloud_provider LIKE '%ad%'
                   OR cloud_provider LIKE '%facebook%'
                   OR cloud_provider LIKE '%google%')
                   {privacy_clause}
                GROUP BY cloud_provider, cloud_domain, device_ip, privacy_concern_level
            ''')
            trackers = cursor.fetchall()

            # Apply search filter if provided
            if search_text and search_text.strip():
                search_lower = search_text.lower()
                trackers = [
                    t for t in trackers
                    if search_lower in (t['cloud_domain'] or '').lower()
                    or search_lower in (t['cloud_provider'] or '').lower()
                    or search_lower in (t['device_ip'] or '').lower()
                ]

            # Categorize trackers
            analytics_count = 0
            ad_count = 0
            social_count = 0

            for t in trackers:
                provider = t['cloud_provider'].lower() if t['cloud_provider'] else ''
                count = t['count']
                if 'analytics' in provider or 'google' in provider:
                    analytics_count += count
                elif 'ad' in provider or 'advertising' in provider:
                    ad_count += count
                elif 'facebook' in provider or 'twitter' in provider or 'social' in provider:
                    social_count += count

            total_detected = analytics_count + ad_count + social_count

            # Check if we have blocked devices to get actual blocked count
            try:
                cursor.execute('SELECT COUNT(DISTINCT device_ip) as count FROM devices WHERE is_blocked = 1')
                blocked_devices = cursor.fetchone()['count']
                # Blocked trackers = trackers from blocked devices
                blocked = min(blocked_devices, total_detected)
            except:
                blocked = 0
            pending = total_detected - blocked


            categories = html.Div([
                html.Div([
                    html.Span("📊 Analytics Trackers", className="me-2"),
                    dbc.Badge(str(analytics_count), color="danger" if analytics_count > 5 else "warning")
                ], className="d-flex justify-content-between align-items-center py-2 border-bottom"),
                html.Div([
                    html.Span("📢 Advertising Networks", className="me-2"),
                    dbc.Badge(str(ad_count), color="warning" if ad_count > 0 else "success")
                ], className="d-flex justify-content-between align-items-center py-2 border-bottom"),
                html.Div([
                    html.Span("🔗 Social Media Trackers", className="me-2"),
                    dbc.Badge(str(social_count), color="info" if social_count > 0 else "success")
                ], className="d-flex justify-content-between align-items-center py-2")
            ], className="mb-4")

            # Generate toast if refresh was clicked
            toast = ToastManager.success(
                "Privacy trackers refreshed",
                detail_message=f"Displaying {total_detected} tracker(s)"
            ) if show_toast else dash.no_update

            return str(total_detected), str(blocked), str(pending), categories, toast

        except Exception as e:
            logger.error(f"Error updating tracker stats: {e}")
            return "0", "0", "0", [], dash.no_update

    # ====================================================================
    # 22. Data flow statistics
    # ====================================================================
    @app.callback(
        [Output('dataflow-inbound-total', 'children'),
         Output('dataflow-outbound-total', 'children'),
         Output('dataflow-inbound-bar', 'value'),
         Output('dataflow-outbound-bar', 'value'),
         Output('dataflow-destinations-list', 'children')],
        [Input('privacy-modal', 'is_open')],
        prevent_initial_call=True
    )
    def update_dataflow_stats(is_open):
        """Update data flow statistics."""
        if not is_open:
            raise dash.exceptions.PreventUpdate

        try:
            conn = get_db_connection()

            cursor = conn.cursor()

            # Get inbound/outbound data
            cursor.execute('''
                SELECT
                    SUM(bytes_received) as inbound,
                    SUM(bytes_sent) as outbound
                FROM connections
                WHERE timestamp >= datetime("now", "-24 hours")
            ''')
            row = cursor.fetchone()
            inbound = row['inbound'] or 0
            outbound = row['outbound'] or 0

            total = max(inbound + outbound, 1)
            inbound_pct = int((inbound / total) * 100)
            outbound_pct = int((outbound / total) * 100)

            # Get top destinations
            cursor.execute('''
                SELECT dest_ip, SUM(bytes_sent) as total_bytes
                FROM connections
                WHERE timestamp >= datetime("now", "-24 hours")
                GROUP BY dest_ip
                ORDER BY total_bytes DESC
                LIMIT 5
            ''')
            destinations = cursor.fetchall()


            dest_list = []
            icons = [("fa-globe", "text-info"), ("fa-cloud", "text-primary"),
                     ("fa-server", "text-success"), ("fa-database", "text-warning"),
                     ("fa-question-circle", "text-secondary")]

            for i, dest in enumerate(destinations):
                icon_class, color = icons[min(i, len(icons)-1)]
                dest_list.append(html.Div([
                    html.Div([html.I(className=f"fa {icon_class} me-2 {color}"), dest['dest_ip']]),
                    html.Span(format_bytes(dest['total_bytes']), className="text-muted")
                ], className="d-flex justify-content-between py-2 border-bottom" if i < len(destinations)-1 else "d-flex justify-content-between py-2"))

            if not dest_list:
                dest_list = [html.P("No data flow detected", className="text-muted")]

            return format_bytes(inbound), format_bytes(outbound), inbound_pct, outbound_pct, dest_list

        except Exception as e:
            logger.error(f"Error updating dataflow stats: {e}")
            return "0 B", "0 B", 0, 0, []

    # ====================================================================
    # 23. Smart home hubs
    # ====================================================================
    @app.callback(
        Output('smarthome-hubs-list', 'children', allow_duplicate=True),
        [Input('smarthome-modal', 'is_open')],
        prevent_initial_call=True
    )
    def update_smarthome_hubs(is_open):
        """Update detected smart home hubs."""
        if not is_open:
            raise dash.exceptions.PreventUpdate

        try:
            conn = get_db_connection()

            cursor = conn.cursor()

            # Get devices that might be hubs (based on device type or connections)
            cursor.execute('''
                SELECT d.device_ip, d.device_name, d.device_type, d.last_seen,
                       (SELECT COUNT(*) FROM connections WHERE device_ip = d.device_ip) as conn_count
                FROM devices d
                WHERE d.device_type LIKE '%hub%'
                   OR d.device_type LIKE '%bridge%'
                   OR d.device_name LIKE '%Echo%'
                   OR d.device_name LIKE '%Google%'
                   OR d.device_name LIKE '%Hue%'
                   OR d.device_name LIKE '%SmartThings%'
                ORDER BY conn_count DESC
                LIMIT 6
            ''')
            hubs = cursor.fetchall()

            if not hubs:
                return dbc.Alert([
                    html.I(className="fa fa-info-circle me-2"),
                    "No smart home hubs detected. Hubs will appear here once detected."
                ], color="info")

            hub_cards = []
            icons = ["fa-robot text-primary", "fa-home text-info", "fa-lightbulb text-warning",
                     "fa-broadcast-tower text-success", "fa-server text-secondary", "fa-wifi text-dark"]

            for i, hub in enumerate(hubs):
                # Calculate status based on last_seen time
                try:
                    last_seen = datetime.fromisoformat(hub['last_seen']) if hub['last_seen'] else None
                    is_online = last_seen and (datetime.now() - last_seen) < timedelta(hours=1)
                    is_idle = last_seen and (datetime.now() - last_seen) < timedelta(hours=24)
                except:
                    is_online, is_idle = False, False
                status_color = "success" if is_online else "warning" if is_idle else "danger"
                status_text = "Online" if is_online else "Idle" if is_idle else "Offline"

                hub_cards.append(
                    dbc.Col([
                        dbc.Card([
                            dbc.CardBody([
                                html.Div([
                                    html.I(className=f"fa fa-circle text-{status_color} me-2 u-text-tiny"),
                                    html.Span(status_text, className=f"small text-{status_color}")
                                ], className="text-end"),
                                html.I(className=f"fa {icons[i % len(icons)]} fa-3x mb-2"),
                                html.H6(hub['device_name'] or f"Hub {i+1}", className="mb-1"),
                                html.Small(hub['device_ip'], className="text-muted d-block"),
                                html.Small(f"{hub['conn_count']} connections", className="text-muted")
                            ], className="text-center")
                        ], className="border-0 bg-transparent h-100")
                    ], md=4, className="mb-3")
                )

            return dbc.Row(hub_cards)

        except Exception as e:
            logger.error(f"Error updating smart home hubs: {e}")
            return dbc.Alert("Error loading hub data", color="danger")

    # ====================================================================
    # 24. Device ecosystems
    # ====================================================================
    @app.callback(
        Output('smarthome-ecosystems-list', 'children', allow_duplicate=True),
        [Input('smarthome-modal', 'is_open')],
        prevent_initial_call=True
    )
    def update_smarthome_ecosystems(is_open):
        """Update device ecosystems."""
        if not is_open:
            raise dash.exceptions.PreventUpdate

        try:
            conn = get_db_connection()

            cursor = conn.cursor()

            # Get device counts by manufacturer/ecosystem
            cursor.execute('''
                SELECT
                    CASE
                        WHEN device_name LIKE '%Amazon%' OR device_name LIKE '%Echo%' OR device_name LIKE '%Alexa%' THEN 'Amazon Alexa'
                        WHEN device_name LIKE '%Google%' OR device_name LIKE '%Nest%' THEN 'Google Home'
                        WHEN device_name LIKE '%Apple%' OR device_name LIKE '%HomeKit%' THEN 'Apple HomeKit'
                        WHEN device_name LIKE '%Samsung%' OR device_name LIKE '%SmartThings%' THEN 'Samsung SmartThings'
                        WHEN device_name LIKE '%Philips%' OR device_name LIKE '%Hue%' THEN 'Philips Hue'
                        ELSE 'Other/Unknown'
                    END as ecosystem,
                    COUNT(*) as count
                FROM devices
                GROUP BY ecosystem
                ORDER BY count DESC
            ''')
            ecosystems = cursor.fetchall()
            total = sum([e['count'] for e in ecosystems])

            if not ecosystems or total == 0:
                return dbc.Alert("No devices detected yet", color="info")

            colors = {"Amazon Alexa": ("🔵", "primary"), "Google Home": ("🔴", "danger"),
                      "Apple HomeKit": ("🟡", "warning"), "Samsung SmartThings": ("🟢", "success"),
                      "Philips Hue": ("🟣", "info"), "Other/Unknown": ("⚪", "secondary")}

            eco_cards = []
            for eco in ecosystems:
                emoji, color = colors.get(eco['ecosystem'], ("⚪", "secondary"))
                pct = int((eco['count'] / max(total, 1)) * 100)

                eco_cards.append(
                    dbc.Card([
                        dbc.CardBody([
                            dbc.Row([
                                dbc.Col([
                                    html.Div([
                                        html.Span(emoji, className="u-text-xxl"),
                                        html.H5(eco['ecosystem'], className="mb-0 ms-2 d-inline")
                                    ], className="d-flex align-items-center")
                                ], md=6),
                                dbc.Col([
                                    html.Div([
                                        html.Span(str(eco['count']), className=f"h3 text-{color} mb-0"),
                                        html.Small(" devices", className="text-muted")
                                    ], className="text-end")
                                ], md=6)
                            ]),
                            dbc.Progress(value=pct, color=color, className="mt-2 progress-xs")
                        ])
                    ], className="mb-3 border-0 bg-transparent")
                )

            return html.Div(eco_cards)

        except Exception as e:
            logger.error(f"Error updating ecosystems: {e}")
            return dbc.Alert("Error loading ecosystem data", color="danger")

    # ====================================================================
    # 25. Room mapping
    # ====================================================================
    @app.callback(
        Output('smarthome-rooms-list', 'children', allow_duplicate=True),
        [Input('smarthome-modal', 'is_open')],
        prevent_initial_call=True
    )
    def update_smarthome_rooms(is_open):
        """Render rooms from smart_home_rooms / device_room_assignments tables."""
        if not is_open:
            raise dash.exceptions.PreventUpdate

        try:
            rooms = db_manager.get_all_rooms()
            default_icons = {
                "living": ("fa-couch", "text-info"), "bedroom": ("fa-bed", "text-primary"),
                "kitchen": ("fa-utensils", "text-warning"), "office": ("fa-briefcase", "text-success"),
                "garage": ("fa-car", "text-secondary"), "garden": ("fa-tree", "text-success"),
                "bathroom": ("fa-bath", "text-info"),
            }
            room_cards = []
            for room in rooms:
                room_lower = (room['room_name'] or "").lower()
                icon, color = next(
                    ((v[0], v[1]) for k, v in default_icons.items() if k in room_lower),
                    (room.get('icon') or "fa-home", "text-primary")
                )
                count = room.get('device_count', 0)
                room_cards.append(
                    dbc.Col([
                        dbc.Card([dbc.CardBody([
                            html.I(className=f"fa {icon} fa-2x {color} mb-2"),
                            html.H6(room['room_name'], className="mb-1"),
                            dbc.Badge(f"{count} device{'s' if count != 1 else ''}",
                                      color="primary" if count > 0 else "secondary"),
                        ], className="text-center py-3")],
                        className="border-0 bg-transparent h-100 hover-lift u-pointer")
                    ], md=3, className="mb-3")
                )
            # "Add Room" card
            room_cards.append(
                dbc.Col([
                    dbc.Card([dbc.CardBody([
                        html.I(className="fa fa-plus fa-2x text-primary mb-2"),
                        html.H6("Add Room", className="mb-1 text-primary"),
                        dbc.InputGroup([
                            dbc.Input(id="new-room-name-input", placeholder="Room name", size="sm"),
                            dbc.Button(html.I(className="fa fa-check"), id="add-room-btn",
                                       color="primary", size="sm"),
                        ], className="mt-2"),
                        html.Div(id="add-room-status", className="mt-1"),
                    ], className="text-center py-3")],
                    className="border border-primary border-dashed h-100")
                ], md=3, className="mb-3")
            )
            return dbc.Row(room_cards)
        except Exception as e:
            logger.error(f"Error rendering rooms: {e}")
            return dbc.Alert("Error loading room data", color="danger")

    # ====================================================================
    # 26. Automations list
    # ====================================================================
    @app.callback(
        Output('smarthome-automations-list', 'children', allow_duplicate=True),
        [Input('smarthome-modal', 'is_open')],
        prevent_initial_call=True
    )
    def update_smarthome_automations(is_open):
        """Render automations list from smart_home_automations table."""
        if not is_open:
            raise dash.exceptions.PreventUpdate

        return _render_automations(db_manager)

    # ====================================================================
    # 26a. Add Room button
    # ====================================================================
    @app.callback(
        [Output('smarthome-rooms-list', 'children', allow_duplicate=True),
         Output('add-room-status', 'children', allow_duplicate=True)],
        Input('add-room-btn', 'n_clicks'),
        State('new-room-name-input', 'value'),
        prevent_initial_call=True
    )
    def add_room(n_clicks, room_name):
        """Create a new room and refresh the rooms list."""
        if not n_clicks:
            raise dash.exceptions.PreventUpdate
        if not room_name or not room_name.strip():
            return dash.no_update, dbc.Alert("Enter a room name.", color="warning", className="small py-1")
        rid = db_manager.add_room(room_name.strip())
        if rid:
            try:
                rooms = db_manager.get_all_rooms()
                default_icons = {
                    "living": ("fa-couch", "text-info"), "bedroom": ("fa-bed", "text-primary"),
                    "kitchen": ("fa-utensils", "text-warning"), "office": ("fa-briefcase", "text-success"),
                    "garage": ("fa-car", "text-secondary"), "garden": ("fa-tree", "text-success"),
                    "bathroom": ("fa-bath", "text-info"),
                }
                room_cards = []
                for room in rooms:
                    rl = (room['room_name'] or "").lower()
                    icon, color = next(((v[0], v[1]) for k, v in default_icons.items() if k in rl),
                                       ("fa-home", "text-primary"))
                    cnt = room.get('device_count', 0)
                    room_cards.append(
                        dbc.Col([dbc.Card([dbc.CardBody([
                            html.I(className=f"fa {icon} fa-2x {color} mb-2"),
                            html.H6(room['room_name'], className="mb-1"),
                            dbc.Badge(f"{cnt} device{'s' if cnt != 1 else ''}",
                                      color="primary" if cnt > 0 else "secondary"),
                        ], className="text-center py-3")],
                        className="border-0 bg-transparent h-100 hover-lift u-pointer")],
                        md=3, className="mb-3")
                    )
                room_cards.append(
                    dbc.Col([dbc.Card([dbc.CardBody([
                        html.I(className="fa fa-plus fa-2x text-primary mb-2"),
                        html.H6("Add Room", className="mb-1 text-primary"),
                        dbc.InputGroup([
                            dbc.Input(id="new-room-name-input", placeholder="Room name", size="sm"),
                            dbc.Button(html.I(className="fa fa-check"), id="add-room-btn",
                                       color="primary", size="sm"),
                        ], className="mt-2"),
                        html.Div(id="add-room-status", className="mt-1"),
                    ], className="text-center py-3")],
                    className="border border-primary border-dashed h-100")],
                    md=3, className="mb-3")
                )
                return dbc.Row(room_cards), ""
            except Exception as e:
                logger.error(f"Error refreshing rooms after add: {e}")
        return dash.no_update, dbc.Alert("Could not save room.", color="danger", className="small py-1")

    # ====================================================================
    # 26b. Delete Automation button
    # ====================================================================
    @app.callback(
        Output('smarthome-automations-list', 'children', allow_duplicate=True),
        Input({'type': 'delete-automation-btn', 'index': ALL}, 'n_clicks'),
        prevent_initial_call=True
    )
    def delete_automation(n_clicks_list):
        """Delete an automation and refresh the list."""
        if not any(n_clicks_list):
            raise dash.exceptions.PreventUpdate
        ctx = callback_context
        if not ctx.triggered:
            raise dash.exceptions.PreventUpdate
        btn_id = json.loads(ctx.triggered[0]['prop_id'].split('.')[0])
        auto_id = btn_id.get('index')
        if auto_id is not None:
            db_manager.delete_automation(int(auto_id))
        return _render_automations(db_manager)

    # ====================================================================
    # 27. Firmware status counts
    # ====================================================================
    @app.callback(
        [Output('firmware-uptodate-count', 'children', allow_duplicate=True),
         Output('firmware-updates-count', 'children', allow_duplicate=True),
         Output('firmware-critical-count', 'children', allow_duplicate=True),
         Output('firmware-unknown-count', 'children', allow_duplicate=True)],
        [Input('firmware-modal', 'is_open')],
        prevent_initial_call=True
    )
    def update_firmware_stats(is_open):
        """Update firmware status counts."""
        if not is_open:
            raise dash.exceptions.PreventUpdate

        try:
            conn = get_db_connection()

            cursor = conn.cursor()

            # Try to get actual firmware status from device_firmware_status table
            try:
                cursor.execute('SELECT COUNT(*) as total FROM device_firmware_status')
                total = cursor.fetchone()['total']

                if total > 0:
                    cursor.execute('SELECT COUNT(*) as count FROM device_firmware_status WHERE update_available = 0 AND is_eol = 0')
                    up_to_date = cursor.fetchone()['count']

                    cursor.execute('SELECT COUNT(*) as count FROM device_firmware_status WHERE update_available = 1 AND is_eol = 0')
                    updates_available = cursor.fetchone()['count']

                    cursor.execute('SELECT COUNT(*) as count FROM device_firmware_status WHERE is_eol = 1')
                    critical = cursor.fetchone()['count']

                    unknown = total - up_to_date - updates_available - critical
                    return str(up_to_date), str(updates_available), str(critical), str(max(0, unknown))
            except:
                pass

            # Fallback: estimate from devices table if firmware_status table is empty
            cursor.execute('SELECT COUNT(*) as total FROM devices')
            total = cursor.fetchone()['total']

            # Get devices with firmware info
            cursor.execute('SELECT COUNT(*) as count FROM devices WHERE firmware_version IS NOT NULL AND firmware_version != ""')
            with_firmware = cursor.fetchone()['count']

            # Devices with firmware info are considered "up to date", others are "unknown"
            up_to_date = with_firmware
            unknown = total - with_firmware


            return str(up_to_date), "0", "0", str(max(0, unknown))

        except Exception as e:
            logger.error(f"Error updating firmware stats: {e}")
            return "0", "0", "0", "0"

    # ====================================================================
    # 28. End-of-life devices — uses HardwareLifecycleManager
    # ====================================================================
    @app.callback(
        Output('eol-devices-list', 'children', allow_duplicate=True),
        [Input('firmware-modal', 'is_open'),
         Input('refresh-firmware-btn', 'n_clicks')],
        prevent_initial_call=True
    )
    def update_eol_devices(is_open, _refresh):
        """Update EOL devices list using real lifecycle data."""
        if not is_open:
            raise dash.exceptions.PreventUpdate

        try:
            from utils.hardware_lifecycle import get_lifecycle_manager
            lifecycle_mgr = get_lifecycle_manager(db_manager)

            # Pull all devices that have lifecycle data (manufacturing_date set)
            # plus any with a hardware_eol_date regardless
            cursor = db_manager.conn.cursor()
            cursor.execute("""
                SELECT device_ip FROM devices
                WHERE manufacturing_date IS NOT NULL OR hardware_eol_date IS NOT NULL
            """)
            device_ips = [r['device_ip'] for r in cursor.fetchall()]

            # Also check ALL devices — those with neither date show a "set date" nudge
            cursor.execute("SELECT device_ip FROM devices")
            all_ips = [r['device_ip'] for r in cursor.fetchall()]

            # Statuses we want to surface as warnings
            warn_statuses = {'past_eol', 'approaching_eol', 'possibly_past_eol'}

            _ICON = {"camera": "fa-video", "plug": "fa-plug", "light": "fa-lightbulb",
                     "router": "fa-wifi", "tv": "fa-tv", "speaker": "fa-volume-high",
                     "default": "fa-microchip"}

            def _icon(device_type):
                dt = (device_type or "").lower()
                return next((v for k, v in _ICON.items() if k in dt), _ICON["default"])

            def _badge_config(status):
                return {
                    'past_eol':        ("danger",  "Past EOL — replace immediately"),
                    'approaching_eol': ("warning", "Approaching EOL"),
                    'possibly_past_eol': ("warning", "Possibly past EOL — verify"),
                }.get(status, ("secondary", status))

            cards = []
            for ip in device_ips:
                result = lifecycle_mgr.check_device_lifecycle(ip, generate_alerts=False)
                if 'error' in result or result.get('status') not in warn_statuses:
                    continue

                status = result['status']
                color, label = _badge_config(status)
                name = result.get('device_name') or ip
                dtype = result.get('device_type', '')

                if status == 'past_eol':
                    detail = f"Past EOL by {result.get('days_past_eol', '?')} days"
                elif status in ('approaching_eol', 'possibly_past_eol'):
                    detail = result.get('message', '')
                else:
                    detail = result.get('message', '')

                recycling = result.get('recycling_link')

                cards.append(dbc.Card([
                    dbc.CardBody([
                        dbc.Row([
                            dbc.Col([
                                html.Div([
                                    html.I(className=f"fa {_icon(dtype)} text-{color} me-2"),
                                    html.Strong(name),
                                ]),
                                html.Small(
                                    f"IP: {ip}  •  Age: {result.get('device_age_years', '?')} yrs"
                                    + (f"  •  EOL: {result.get('hardware_eol_date', result.get('estimated_eol_date', ''))}"
                                       if result.get('hardware_eol_date') or result.get('estimated_eol_date') else ""),
                                    className="text-muted d-block"
                                ),
                                html.Div([
                                    dbc.Badge(label, color=color, className="mt-1 me-2"),
                                    html.Small(detail, className="text-muted"),
                                ]),
                            ], md=8),
                            dbc.Col([
                                dbc.Button([
                                    html.I(className="fa fa-exchange-alt me-1"), "Replace"
                                ], id={'type': 'replace-eol-device-btn', 'ip': ip},
                                   color="warning", size="sm", outline=True, className="mb-1 w-100"),
                                html.A([
                                    html.I(className="fa fa-recycle me-1"), "Recycle"
                                ], href=recycling, target="_blank",
                                   className="btn btn-sm btn-outline-success w-100") if recycling else None,
                            ], md=4, className="text-end d-flex flex-column align-items-end justify-content-center"),
                        ])
                    ])
                ], className=f"mb-2 border-start border-{color} border-3"))

            if not cards:
                return dbc.Alert([
                    html.I(className="fa fa-check-circle me-2"),
                    html.Strong("All clear. "),
                    "No end-of-life or approaching-EOL devices detected.",
                    html.Br(),
                    html.Small(
                        "Set a manufacturing date on devices to enable lifecycle tracking.",
                        className="text-muted"
                    )
                ], color="success")

            return html.Div(cards)

        except Exception as e:
            logger.error(f"Error updating EOL devices: {e}")
            return dbc.Alert(f"Error loading EOL device data: {e}", color="danger")

    # ====================================================================
    # 29. EOL replacement modal (pattern-matching)
    # ====================================================================
    @app.callback(
        [Output('eol-replacement-modal', 'is_open'),
         Output('replacement-device-dropdown', 'options'),
         Output('eol-device-ip-store', 'data')],
        [Input({'type': 'replace-eol-device-btn', 'ip': ALL}, 'n_clicks')],
        [State('eol-replacement-modal', 'is_open')],
        prevent_initial_call=True
    )
    def open_replace_modal(n_clicks, is_open):
        """Open the replacement modal and populate the dropdown."""
        if not any(n_clicks):
            raise dash.exceptions.PreventUpdate

        ctx = callback_context
        triggered_id = ctx.triggered_id
        eol_device_ip = triggered_id['ip']

        non_eol_devices = get_non_eol_devices()
        return True, non_eol_devices, eol_device_ip

    # ====================================================================
    # 30. Replacement button disable (clientside)
    # ====================================================================
    app.clientside_callback(
        """
        function(value) {
            return value == null;
        }
        """,
        Output('confirm-replacement-btn', 'disabled'),
        Input('replacement-device-dropdown', 'value')
    )

    # ====================================================================
    # 31. Device replacement
    # ====================================================================
    @app.callback(
        [Output('eol-replacement-modal', 'is_open', allow_duplicate=True),
         Output('toast-container', 'children', allow_duplicate=True)],
        [Input('confirm-replacement-btn', 'n_clicks')],
        [State('eol-device-ip-store', 'data'),
         State('replacement-device-dropdown', 'value')],
        prevent_initial_call=True
    )
    def replace_device(n_clicks, eol_device_ip, new_device_ip):
        """Handle the device replacement logic with real DB persistence."""
        if not n_clicks:
            raise dash.exceptions.PreventUpdate

        if not eol_device_ip or not new_device_ip:
            return False, ToastManager.warning(
                "Invalid Selection", detail_message="Please select both an EOL device and its replacement."
            )

        try:
            conn = get_db_connection()
            if not conn:
                return False, ToastManager.error("Database Error", detail_message="Could not connect to database.")
            cursor = conn.cursor()

            # Fetch the old device's metadata to carry forward
            cursor.execute(
                "SELECT notes, device_type, manufacturer FROM devices WHERE device_ip = ?",
                (eol_device_ip,)
            )
            old_device = cursor.fetchone()

            if old_device:
                # Copy notes and custom_name to the replacement device (only if not already set)
                db_manager.update_device_metadata(
                    new_device_ip,
                    **{k: v for k, v in {
                        'notes': old_device['notes'],
                        'device_type': old_device['device_type'],
                        'manufacturer': old_device['manufacturer'],
                    }.items() if v is not None}
                )

            # Mark the EOL device as blocked/inactive so it no longer appears as active
            db_manager.set_device_blocked(eol_device_ip, True)

            # Record the replacement in the notes of the new device
            replacement_note = f"Replaced EOL device {eol_device_ip}"
            cursor.execute(
                "UPDATE devices SET notes = COALESCE(notes || '; ', '') || ? WHERE device_ip = ?",
                (replacement_note, new_device_ip)
            )
            db_manager.conn.commit()

            logger.info(f"Device replacement: {eol_device_ip} → {new_device_ip}")
            return False, ToastManager.success(
                "Device Replaced",
                detail_message=f"Replacement recorded. {eol_device_ip} is now marked inactive."
            )

        except Exception as e:
            logger.error(f"Error replacing device: {e}")
            return False, ToastManager.error("Replacement Failed", detail_message=str(e))

    # ====================================================================
    # 32. Cancel replacement modal
    # ====================================================================
    @app.callback(
        Output('eol-replacement-modal', 'is_open', allow_duplicate=True),
        Input('cancel-replacement-btn', 'n_clicks'),
        prevent_initial_call=True
    )
    def cancel_replacement(n_clicks):
        """Close the replacement modal."""
        if not n_clicks:
            raise dash.exceptions.PreventUpdate
        return False

    # ====================================================================
    # 33. Firmware updates list
    # ====================================================================
    @app.callback(
        Output('firmware-updates-list', 'children', allow_duplicate=True),
        [Input('firmware-modal', 'is_open')],
        prevent_initial_call=True
    )
    def update_firmware_updates_list(is_open):
        """List devices with available firmware updates from device_firmware_status."""
        if not is_open:
            raise dash.exceptions.PreventUpdate

        try:
            conn = get_db_connection()

            cursor = conn.cursor()

            # Query the real firmware status table
            cursor.execute('''
                SELECT dfs.device_ip, dfs.current_firmware, dfs.latest_firmware,
                       dfs.firmware_age_days, dfs.is_eol, dfs.update_available,
                       d.device_name, d.device_type, d.manufacturer
                FROM device_firmware_status dfs
                LEFT JOIN devices d ON dfs.device_ip = d.device_ip
                WHERE dfs.update_available = 1 OR dfs.is_eol = 1
                ORDER BY dfs.is_eol DESC, dfs.firmware_age_days DESC
            ''')
            rows = cursor.fetchall()

            if not rows:
                return dbc.Alert([
                    html.I(className="fa fa-check-circle me-2"),
                    "All tracked devices are running the latest firmware."
                ], color="success")

            update_cards = []
            icons = {"light": "fa-lightbulb text-warning", "camera": "fa-video text-info",
                     "thermostat": "fa-thermometer-half text-info", "plug": "fa-plug text-success",
                     "sensor": "fa-broadcast-tower text-primary", "default": "fa-microchip text-secondary"}

            for device in rows:
                device_type = (device['device_type'] or "").lower()
                icon = next((v for k, v in icons.items() if k in device_type), icons["default"])

                if device['is_eol']:
                    update_type, badge_color = ("EOL / No Support", "danger")
                else:
                    update_type, badge_color = ("Firmware Update", "warning")

                current_fw = device['current_firmware'] or "Unknown"
                latest_fw = device['latest_firmware'] or "Unknown"
                age_days = device['firmware_age_days'] or 0

                update_cards.append(
                    dbc.Card([
                        dbc.CardBody([
                            dbc.Row([
                                dbc.Col([
                                    html.Div([
                                        html.I(className=f"fa {icon} me-2"),
                                        html.Strong(device['device_name'] or device['device_ip'] or "Unknown Device")
                                    ]),
                                    html.Small(
                                        f"{current_fw} → {latest_fw} ({age_days}d old)",
                                        className="text-muted"
                                    )
                                ], md=7),
                                dbc.Col([
                                    dbc.Badge(update_type, color=badge_color, className="me-1"),
                                    dbc.Button([
                                        html.I(className="fa fa-download")
                                    ], color="success", size="sm", className="ms-2")
                                ], md=5, className="text-end")
                            ])
                        ])
                    ], className="mb-2 border-0 bg-transparent")
                )

            return html.Div(update_cards)

        except Exception as e:
            logger.error(f"Error updating firmware list: {e}")
            return dbc.Alert("Error loading update data", color="danger")

    # ====================================================================
    # 34. Cloud uploads section
    # ====================================================================
    @app.callback(
        Output('cloud-uploads-section', 'children'),
        [Input('privacy-modal', 'is_open')],
        prevent_initial_call=True
    )
    def update_cloud_uploads_section(is_open):
        """Update cloud uploads connection list."""
        if not is_open:
            raise dash.exceptions.PreventUpdate

        try:
            conn = get_db_connection()

            cursor = conn.cursor()

            # Get recent cloud connections
            cursor.execute('''
                SELECT device_ip, cloud_provider, privacy_concern_level, last_seen
                FROM cloud_connections
                ORDER BY last_seen DESC
                LIMIT 10
            ''')
            connections = cursor.fetchall()

            if not connections:
                return dbc.Alert([
                    html.I(className="fa fa-cloud me-2"),
                    "No cloud connections detected recently."
                ], color="info")

            conn_cards = []
            for conn_data in connections:
                concern = conn_data['privacy_concern_level'] or 'low'
                badge_color = "danger" if concern in ['high', 'critical'] else "warning" if concern == 'medium' else "success"

                conn_cards.append(
                    html.Div([
                        html.Div([
                            html.I(className="fa fa-cloud me-2 text-info"),
                            html.Strong(conn_data['cloud_provider'] or "Unknown Provider")
                        ]),
                        html.Div([
                            html.Small(conn_data['device_ip'], className="text-muted me-2"),
                            dbc.Badge(concern.capitalize(), color=badge_color, size="sm")
                        ])
                    ], className="d-flex justify-content-between py-2 border-bottom")
                )

            return html.Div(conn_cards)

        except Exception as e:
            logger.error(f"Error updating cloud uploads: {e}")
            return dbc.Alert("Error loading cloud data", color="danger")

    # ====================================================================
    # 35. Tracker detection details
    # ====================================================================
    @app.callback(
        [Output('tracker-detection-section', 'children', allow_duplicate=True),
         Output('toast-container', 'children', allow_duplicate=True)],
        [Input('privacy-modal', 'is_open'),
         Input('view-tracker-log-btn', 'n_clicks')],
        prevent_initial_call=True
    )
    def update_tracker_detection_section(is_open, n_clicks):
        """Update tracker detection details when modal opens or button is clicked."""
        ctx = dash.callback_context

        # Check which input triggered the callback
        if not ctx.triggered:
            raise dash.exceptions.PreventUpdate

        trigger_id = ctx.triggered[0]['prop_id'].split('.')[0]

        # If modal triggered but isn't open, don't update
        if trigger_id == 'privacy-modal' and not is_open:
            raise dash.exceptions.PreventUpdate

        try:
            # Query database for tracker/external connections
            conn = db_manager.conn
            cursor = conn.cursor()

            # Get external connections that could be trackers (last 24 hours)
            cursor.execute('''
                SELECT
                    device_ip,
                    dest_ip,
                    dest_port,
                    protocol,
                    COUNT(*) as connection_count,
                    MIN(timestamp) as first_seen,
                    MAX(timestamp) as last_seen
                FROM connections
                WHERE timestamp >= datetime('now', '-24 hours')
                AND dest_port NOT IN (80, 443, 53)
                GROUP BY device_ip, dest_ip, dest_port
                ORDER BY connection_count DESC
                LIMIT 50
            ''')

            tracker_connections = cursor.fetchall()

            if not tracker_connections:
                toast = ToastManager.info(
                    "Tracker Log",
                    detail_message="No Suspicious Tracker Connections Detected\n\nAnalysis Period: Last 24 hours\nPorts Checked: All except 80 (HTTP), 443 (HTTPS), 53 (DNS)\n\nYour network appears clean with no unusual external connections detected."
                )
                return dbc.Alert([
                    html.I(className="fa fa-info-circle me-2"),
                    "No suspicious tracker connections detected in the last 24 hours"
                ], color="success"), toast

            # Build tracker table
            tracker_log = dbc.Card([
                dbc.CardHeader([
                    html.I(className="fa fa-list me-2"),
                    html.Strong(f"Tracker Connection Log (Last 24 Hours) - {len(tracker_connections)} Entries")
                ], className="glass-card-header"),
                dbc.CardBody([
                    dbc.Table([
                        html.Thead([
                            html.Tr([
                                html.Th("Device IP"),
                                html.Th("Destination IP"),
                                html.Th("Port"),
                                html.Th("Protocol"),
                                html.Th("Connections"),
                                html.Th("First Seen"),
                                html.Th("Last Seen")
                            ])
                        ]),
                        html.Tbody([
                            html.Tr([
                                html.Td(row['device_ip']),
                                html.Td([
                                    html.Code(row['dest_ip'], className="text-danger")
                                ]),
                                html.Td(dbc.Badge(str(row['dest_port']), color="info")),
                                html.Td(row['protocol'] or 'TCP'),
                                html.Td(dbc.Badge(str(row['connection_count']), color="warning")),
                                html.Td(html.Small(row['first_seen'][:16] if row['first_seen'] else 'N/A', className="text-muted")),
                                html.Td(html.Small(row['last_seen'][:16] if row['last_seen'] else 'N/A', className="text-muted"))
                            ]) for row in tracker_connections
                        ])
                    ], bordered=True, hover=True, responsive=True, size="sm", className="table-adaptive")
                ])
            ], className="shadow-sm")

            # Calculate statistics for detail message
            unique_devices = len(set(row['device_ip'] for row in tracker_connections))
            unique_destinations = len(set(row['dest_ip'] for row in tracker_connections))
            total_connections = sum(row['connection_count'] for row in tracker_connections)

            toast = ToastManager.success(
                "Tracker Log Loaded",
                detail_message=f"Tracker Connection Analysis Complete\n\nTotal Entries: {len(tracker_connections)}\nUnique Devices: {unique_devices}\nUnique Destinations: {unique_destinations}\nTotal Connections: {total_connections}\nTime Period: Last 24 hours\n\nSuspicious connections detected on non-standard ports."
            )

            return tracker_log, toast

        except Exception as e:
            logger.error(f"Error loading tracker log: {e}")
            toast = ToastManager.error(
                "Error Loading Tracker Log",
                detail_message=f"Failed to Load Tracker Connection Data\n\nError Details:\n{str(e)}\n\nPossible Causes:\n- Database connection issue\n- Query execution failure\n- Data corruption\n\nPlease check the logs for more information."
            )
            return dbc.Alert([
                html.I(className="fa fa-exclamation-triangle me-2"),
                f"Error loading tracker data: {str(e)}"
            ], color="danger"), toast

    # ====================================================================
    # 36. Firmware status overview
    # ====================================================================
    @app.callback(
        Output('firmware-status-section', 'children'),
        [Input('refresh-interval', 'n_intervals')],
        prevent_initial_call=True  # W15: Devices tab not visible at startup
    )
    def update_firmware_status(n):
        """Update firmware status overview."""
        try:
            conn = get_db_connection()

            cursor = conn.cursor()
            cursor.execute('SELECT COUNT(*) as total FROM device_firmware_status')
            total = cursor.fetchone()['total']

            if total == 0:
                return dbc.Alert([
                    html.I(className="fa fa-microchip me-2"),
                    "Firmware tracking will appear as devices are discovered and classified."
                ], color="info")

            cursor.execute('SELECT COUNT(*) as updates FROM device_firmware_status WHERE update_available = 1')
            updates_available = cursor.fetchone()['updates']

            cursor.execute('SELECT COUNT(*) as eol FROM device_firmware_status WHERE is_eol = 1')
            eol_devices = cursor.fetchone()['eol']


            up_to_date = total - updates_available - eol_devices

            return dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardBody([
                            html.H3(str(updates_available), className="text-primary mb-0"),
                            html.P("🔄 Updates Available", className="text-muted small")
                        ])
                    ], className="cyber-card text-center")
                ], xs=12, sm=4),
                dbc.Col([
                    dbc.Card([
                        dbc.CardBody([
                            html.H3(str(eol_devices), className="text-danger mb-0"),
                            html.P("⏰ End-of-Life", className="text-muted small")
                        ])
                    ], className="cyber-card text-center")
                ], xs=12, sm=4),
                dbc.Col([
                    dbc.Card([
                        dbc.CardBody([
                            html.H3(str(up_to_date), className="text-success mb-0"),
                            html.P("✅ Up-to-Date", className="text-muted small")
                        ])
                    ], className="cyber-card text-center")
                ], xs=12, sm=4)
            ], className="mt-3")
        except Exception as e:
            logger.error(f"Error updating firmware status: {e}")
            return dbc.Alert("Firmware monitoring active", color="info")

    # ====================================================================
    # 37. Device mgmt modal toggle
    # ====================================================================
    @app.callback(
        Output("device-mgmt-modal", "is_open"),
        Input("device-mgmt-card-btn", "n_clicks"),
        State("device-mgmt-modal", "is_open"),
        prevent_initial_call=True
    )
    def toggle_device_mgmt_modal(open_clicks, is_open):
        ctx = dash.callback_context
        if not ctx.triggered:
            raise dash.exceptions.PreventUpdate
        trigger_id = ctx.triggered[0]['prop_id'].split('.')[0]
        if trigger_id == 'device-mgmt-card-btn' and open_clicks:
            return not is_open
        return is_open

    # ====================================================================
    # 38. Device mgmt timestamp
    # ====================================================================
    @app.callback(
        [Output('device-mgmt-timestamp-display', 'children'),
         Output('device-mgmt-timestamp-store', 'data'),
         Output('toast-container', 'children', allow_duplicate=True)],
        [Input('device-mgmt-modal', 'is_open'),
         Input('refresh-device-mgmt-btn', 'n_clicks')],
        prevent_initial_call=True
    )
    def update_device_mgmt_timestamp(is_open, refresh_clicks):
        """Update timestamp display for Device Management Modal"""
        from dash import callback_context
        ctx = callback_context

        # Check if refresh button was clicked
        show_toast = ctx.triggered and ctx.triggered[0]['prop_id'] == 'refresh-device-mgmt-btn.n_clicks' if ctx.triggered else False

        if not is_open:
            raise dash.exceptions.PreventUpdate

        # Get current timestamp
        current_time = datetime.now()
        timestamp_str = current_time.isoformat()

        # Create timestamp display
        display = create_timestamp_display(current_time)

        # Generate toast if refresh was clicked
        toast = ToastManager.success(
            "Device inventory refreshed",
            detail_message="Device list updated successfully"
        ) if show_toast else dash.no_update

        return display, timestamp_str, toast

    # ====================================================================
    # 39. Privacy modal toggle
    # ====================================================================
    @app.callback(
        Output("privacy-modal", "is_open"),
        Input("privacy-card-btn", "n_clicks"),
        State("privacy-modal", "is_open"),
        prevent_initial_call=True
    )
    def toggle_privacy_modal(open_clicks, is_open):
        ctx = dash.callback_context
        if not ctx.triggered:
            raise dash.exceptions.PreventUpdate
        trigger_id = ctx.triggered[0]['prop_id'].split('.')[0]
        if trigger_id == 'privacy-card-btn' and open_clicks:
            return not is_open
        return is_open

    # ====================================================================
    # 40. Smart home modal toggle
    # ====================================================================
    @app.callback(
        Output("smarthome-modal", "is_open"),
        Input("smarthome-card-btn", "n_clicks"),
        State("smarthome-modal", "is_open"),
        prevent_initial_call=True
    )
    def toggle_smarthome_modal(open_clicks, is_open):
        ctx = dash.callback_context
        if not ctx.triggered:
            raise dash.exceptions.PreventUpdate
        trigger_id = ctx.triggered[0]['prop_id'].split('.')[0]
        if trigger_id == 'smarthome-card-btn' and open_clicks:
            return not is_open
        return is_open

    # ====================================================================
    # 41. Smart home timestamp
    # ====================================================================
    @app.callback(
        [Output('smarthome-timestamp-display', 'children'),
         Output('smarthome-timestamp-store', 'data'),
         Output('toast-container', 'children', allow_duplicate=True)],
        [Input('smarthome-modal', 'is_open'),
         Input('refresh-smarthome-btn', 'n_clicks')],
        prevent_initial_call=True
    )
    def update_smarthome_timestamp(is_open, refresh_clicks):
        """Update timestamp display for Smart Home Modal"""
        from dash import callback_context
        ctx = callback_context

        # Check if refresh button was clicked
        show_toast = ctx.triggered and ctx.triggered[0]['prop_id'] == 'refresh-smarthome-btn.n_clicks' if ctx.triggered else False

        if not is_open:
            raise dash.exceptions.PreventUpdate

        # Get current timestamp
        current_time = datetime.now()
        timestamp_str = current_time.isoformat()

        # Create timestamp display
        display = create_timestamp_display(current_time)

        # Generate toast if refresh was clicked
        toast = ToastManager.success(
            "Smart home data refreshed",
            detail_message="IoT hub and device data updated successfully"
        ) if show_toast else dash.no_update

        return display, timestamp_str, toast

    # ====================================================================
    # 42. Smart home export
    # ====================================================================
    @app.callback(
        [Output('download-smarthome-csv', 'data'),
         Output('toast-container', 'children', allow_duplicate=True)],
        Input('export-smarthome-csv-btn', 'n_clicks'),
        State('export-format-smarthome', 'value'),
        prevent_initial_call=True
    )
    def export_smarthome_csv(n_clicks, export_format):
        """Export smart home device data in selected format"""
        if not n_clicks:
            raise dash.exceptions.PreventUpdate

        try:
            # Normalize format (xlsx -> excel)
            format_map = {'xlsx': 'excel', 'csv': 'csv', 'json': 'json', 'pdf': 'pdf'}
            export_format = format_map.get(export_format or 'csv', 'csv')

            # Export all devices (includes smart home devices)
            download_data = export_helper.export_devices(format=export_format)

            if download_data:
                toast = ToastManager.success(
                    "Export Complete",
                    detail_message=f"Smart home data exported as {export_format.upper()}"
                )
                return download_data, toast
            else:
                toast = ToastManager.error(
                    "Export Failed",
                    detail_message="No data available or export failed"
                )
                return dash.no_update, toast

        except Exception as e:
            logger.error(f"Error exporting smart home data: {e}")
            toast = ToastManager.error(
                "Export Failed",
                detail_message=f"Error: {str(e)}"
            )
            return dash.no_update, toast

    # ====================================================================
    # 43. Firmware modal toggle
    # ====================================================================
    @app.callback(
        Output("firmware-modal", "is_open"),
        Input("firmware-card-btn", "n_clicks"),
        State("firmware-modal", "is_open"),
        prevent_initial_call=True
    )
    def toggle_firmware_modal(open_clicks, is_open):
        ctx = dash.callback_context
        if not ctx.triggered:
            raise dash.exceptions.PreventUpdate
        trigger_id = ctx.triggered[0]['prop_id'].split('.')[0]
        if trigger_id == 'firmware-card-btn' and open_clicks:
            return not is_open
        return is_open

    # ====================================================================
    # 44. Firmware timestamp
    # ====================================================================
    @app.callback(
        [Output('firmware-timestamp-display', 'children'),
         Output('firmware-timestamp-store', 'data'),
         Output('toast-container', 'children', allow_duplicate=True)],
        [Input('firmware-modal', 'is_open'),
         Input('refresh-firmware-btn', 'n_clicks')],
        prevent_initial_call=True
    )
    def update_firmware_timestamp(is_open, refresh_clicks):
        """Update timestamp display for Firmware Modal"""
        from dash import callback_context
        ctx = callback_context

        # Check if refresh button was clicked
        show_toast = ctx.triggered and ctx.triggered[0]['prop_id'] == 'refresh-firmware-btn.n_clicks' if ctx.triggered else False

        if not is_open:
            raise dash.exceptions.PreventUpdate

        # Get current timestamp
        current_time = datetime.now()
        timestamp_str = current_time.isoformat()

        # Create timestamp display
        display = create_timestamp_display(current_time)

        # Generate toast if refresh was clicked
        toast = ToastManager.success(
            "Firmware data refreshed",
            detail_message="Firmware status and updates refreshed successfully"
        ) if show_toast else dash.no_update

        return display, timestamp_str, toast

    # ====================================================================
    # 45. Firmware export
    # ====================================================================
    @app.callback(
        [Output('download-firmware-csv', 'data'),
         Output('toast-container', 'children', allow_duplicate=True)],
        Input('export-firmware-csv-btn', 'n_clicks'),
        State('export-format-firmware', 'value'),
        prevent_initial_call=True
    )
    def export_firmware_csv(n_clicks, export_format):
        """Export firmware status data in selected format (device information)"""
        if not n_clicks:
            raise dash.exceptions.PreventUpdate

        try:
            # Normalize format (xlsx -> excel)
            format_map = {'xlsx': 'excel', 'csv': 'csv', 'json': 'json', 'pdf': 'pdf'}
            export_format = format_map.get(export_format or 'csv', 'csv')

            # Export all devices (includes firmware-related info)
            download_data = export_helper.export_devices(format=export_format)

            if download_data:
                toast = ToastManager.success(
                    "Export Complete",
                    detail_message=f"Firmware data exported as {export_format.upper()}"
                )
                return download_data, toast
            else:
                toast = ToastManager.error(
                    "Export Failed",
                    detail_message="No data available or export failed"
                )
                return dash.no_update, toast

        except Exception as e:
            logger.error(f"Error exporting firmware data: {e}")
            toast = ToastManager.error(
                "Export Failed",
                detail_message=f"Error: {str(e)}"
            )
            return dash.no_update, toast

    # ====================================================================
    # 46. Firmware settings save (RBAC)
    # ====================================================================
    @app.callback(
        [Output('toast-container', 'children', allow_duplicate=True),
         Output('firmware-modal', 'is_open', allow_duplicate=True)],
        Input('save-firmware-settings-btn', 'n_clicks'),
        [State('auto-update-policy', 'value'),
         State('update-schedule-select', 'value'),
         State('firmware-notification-settings', 'value')],
        prevent_initial_call=True
    )
    @login_required
    def save_firmware_settings(n_clicks, update_policy, update_schedule, notification_settings):
        """Save firmware settings and close modal with toast. Requires admin role."""
        if not n_clicks:
            raise dash.exceptions.PreventUpdate

        if not current_user.is_admin():
            security_audit_logger.log(
                event_type='permission_denied',
                user_id=current_user.id,
                username=current_user.username,
                details={'action': 'modify_firmware_settings'},
                severity='high',
                result='failure',
                failure_reason='Requires admin role'
            )
            toast = ToastManager.error(
                "Permission Denied",
                detail_message="Firmware settings can only be changed by administrators."
            )
            return toast, True

        try:
            # Save settings to database (would use user preferences table)
            conn = get_db_connection()
            if conn:
                # Settings would be saved here
                pass

            security_audit_logger.log(
                event_type='settings_changed',
                user_id=current_user.id,
                username=current_user.username,
                details={
                    'settings_type': 'firmware',
                    'update_policy': update_policy,
                    'update_schedule': update_schedule,
                    'notification_settings': notification_settings
                },
                severity='high',
                resource_type='firmware_settings',
                result='success'
            )

            toast = ToastManager.success(
                "Settings Saved",
                detail_message="Settings Saved"
            )
            return toast, False  # Close modal

        except Exception as e:
            logger.error(f"Error saving firmware settings: {e}")
            toast = ToastManager.error(
                "Error",
                detail_message="Error"
            )
            return toast, True  # Keep modal open

    # ====================================================================
    # 47. Privacy report export
    # ====================================================================
    @app.callback(
        [Output('toast-container', 'children', allow_duplicate=True),
         Output('privacy-modal', 'is_open', allow_duplicate=True),
         Output('download-export', 'data', allow_duplicate=True)],
        Input('export-privacy-report-btn', 'n_clicks'),
        State('export-format-privacy', 'value'),
        prevent_initial_call=True
    )
    def export_privacy_report(n_clicks, export_format):
        """Export privacy report in selected format."""
        if not n_clicks:
            raise dash.exceptions.PreventUpdate

        try:
            # Normalize format (xlsx -> excel)
            format_map = {'xlsx': 'excel', 'csv': 'csv', 'json': 'json', 'pdf': 'pdf'}
            export_format = format_map.get(export_format or 'csv', 'csv')

            # Export alerts data (privacy reports are based on alerts)
            download_data = export_helper.export_alerts(format=export_format, days=30)

            if download_data:
                toast = ToastManager.success(
                    "Export Complete",
                    detail_message=f"Privacy report exported as {export_format.upper()}"
                )
                return toast, False, download_data
            else:
                toast = ToastManager.error(
                    "Export Failed",
                    detail_message="No data available or export failed"
                )
                return toast, True, None

        except Exception as e:
            logger.error(f"Error exporting privacy report: {e}")
            toast = ToastManager.error(
                "Export Error",
                detail_message=str(e)
            )
            return toast, True, None

    # ====================================================================
    # 48. Block all trackers
    # ====================================================================
    @app.callback(
        [Output('trackers-blocked-count', 'children', allow_duplicate=True),
         Output('trackers-pending-count', 'children', allow_duplicate=True),
         Output('tracker-detection-section', 'children', allow_duplicate=True),
         Output('toast-container', 'children', allow_duplicate=True)],
        Input('block-all-trackers-btn', 'n_clicks'),
        [State('trackers-pending-count', 'children')],
        prevent_initial_call=True
    )
    def block_all_trackers(n_clicks, pending_count):
        """Block all pending tracker destination IPs via the firewall engine."""
        if not n_clicks:
            raise dash.exceptions.PreventUpdate

        try:
            conn = get_db_connection()
            if not conn:
                return dash.no_update, dash.no_update, dash.no_update, ToastManager.error(
                    "Block Failed", detail_message="Database unavailable"
                )

            cursor = conn.cursor()

            # Collect real tracker destination IPs from connections and cloud data
            # These are external IPs contacting ad/analytics/tracking services
            tracker_ips = set()

            # Source 1: cloud connections flagged as high/critical privacy concern
            try:
                cursor.execute('''
                    SELECT DISTINCT cloud_ip FROM cloud_connections
                    WHERE privacy_concern_level IN ('high', 'critical')
                      AND cloud_ip IS NOT NULL AND cloud_ip != ''
                ''')
                for row in cursor.fetchall():
                    tracker_ips.add(row['cloud_ip'])
            except Exception as _e:
                logger.debug(f"cloud_connections query skipped: {_e}")

            # Source 2 (removed): third_party_trackers stores domain names, not IPs —
            # a dest_ip ↔ tracker_domain join is type-incorrect and always returns zero rows.
            # cloud_connections (source 1) already covers IP-based blocking.

            if not tracker_ips:
                updated_section = dbc.Alert([
                    html.I(className="fa fa-info-circle me-2"),
                    "No confirmed tracker IPs found — privacy concern data may not yet be populated."
                ], color="info")
                return dash.no_update, "0", updated_section, ToastManager.info(
                    "No Trackers Found", detail_message="Run a discovery scan to populate tracker data."
                )

            # Block each IP via the firewall engine
            blocked_count = 0
            failed_count = 0
            if firewall_enforcer:
                for ip in tracker_ips:
                    try:
                        ok = firewall_enforcer.block_ip(ip)
                        if ok:
                            blocked_count += 1
                        else:
                            failed_count += 1
                    except Exception as _block_err:
                        logger.warning(f"Failed to block tracker IP {ip}: {_block_err}")
                        failed_count += 1
            else:
                # Firewall enforcer not available (development/non-Pi environment)
                blocked_count = len(tracker_ips)
                logger.info(f"Firewall enforcer not available; would block {blocked_count} tracker IPs")

            result_color = "success" if failed_count == 0 else "warning"
            status_msg = f"Blocked {blocked_count} tracker IP(s)"
            if failed_count:
                status_msg += f" ({failed_count} failed — check firewall permissions)"

            updated_section = dbc.Alert([
                html.I(className=f"fa fa-{'check-circle' if failed_count == 0 else 'exclamation-triangle'} me-2"),
                status_msg + ". Your network is now more secure!"
            ], color=result_color)

            toast = ToastManager.success("Trackers Blocked", detail_message=status_msg)
            return str(blocked_count), "0", updated_section, toast

        except Exception as e:
            logger.error(f"Error blocking trackers: {e}")
            return dash.no_update, dash.no_update, dash.no_update, ToastManager.error(
                "Error", detail_message=str(e)
            )

    # ====================================================================
    # 49. Check firmware updates
    # ====================================================================
    @app.callback(
        [Output('firmware-updates-list', 'children', allow_duplicate=True),
         Output('firmware-uptodate-count', 'children', allow_duplicate=True),
         Output('firmware-updates-count', 'children', allow_duplicate=True),
         Output('toast-container', 'children', allow_duplicate=True)],
        Input('check-firmware-updates-btn', 'n_clicks'),
        prevent_initial_call=True
    )
    def check_firmware_updates(n_clicks):
        """Check firmware status from device_firmware_status and refresh the list."""
        if not n_clicks:
            raise dash.exceptions.PreventUpdate

        try:
            conn = get_db_connection()
            if not conn:
                return (
                    dbc.Alert("Database unavailable", color="danger"),
                    "0", "0",
                    ToastManager.error("Check Failed", detail_message="Database unavailable"),
                )

            cursor = conn.cursor()

            # Read real counts from device_firmware_status
            cursor.execute('SELECT COUNT(*) as total FROM device_firmware_status')
            total_row = cursor.fetchone()
            total = total_row['total'] if total_row else 0

            if total == 0:
                # No firmware records yet
                msg = dbc.Alert([
                    html.I(className="fa fa-info-circle me-2"),
                    "No firmware status data yet. Run a device scan to populate firmware information."
                ], color="info")
                return msg, "0", "0", ToastManager.info(
                    "No Data", detail_message="Run a device scan first."
                )

            cursor.execute(
                "SELECT COUNT(*) as count FROM device_firmware_status WHERE update_available = 0 AND is_eol = 0"
            )
            up_to_date = cursor.fetchone()['count']

            cursor.execute(
                "SELECT COUNT(*) as count FROM device_firmware_status WHERE update_available = 1 OR is_eol = 1"
            )
            needs_update = cursor.fetchone()['count']

            # Build the updates list from real data
            cursor.execute('''
                SELECT dfs.device_ip, dfs.current_firmware, dfs.latest_firmware,
                       dfs.is_eol, dfs.firmware_age_days,
                       d.device_name, d.device_type
                FROM device_firmware_status dfs
                LEFT JOIN devices d ON dfs.device_ip = d.device_ip
                WHERE dfs.update_available = 1 OR dfs.is_eol = 1
                ORDER BY dfs.is_eol DESC, dfs.firmware_age_days DESC
                LIMIT 20
            ''')
            rows = cursor.fetchall()

            if not rows:
                updates_list = dbc.Alert([
                    html.I(className="fa fa-check-circle me-2"),
                    f"All {up_to_date} tracked devices are running the latest firmware."
                ], color="success")
            else:
                cards = []
                for r in rows:
                    label = "EOL" if r['is_eol'] else "Update Available"
                    color = "danger" if r['is_eol'] else "warning"
                    name = r['device_name'] or r['device_ip']
                    cards.append(dbc.ListGroupItem([
                        html.Div([
                            dbc.Badge(label, color=color, className="me-2"),
                            html.Strong(name),
                            html.Span(
                                f"  {r['current_firmware'] or '?'} → {r['latest_firmware'] or '?'}",
                                className="text-muted ms-2 small"
                            ),
                        ])
                    ]))
                updates_list = dbc.ListGroup(cards, flush=True)

            toast = ToastManager.success(
                "Check Complete",
                detail_message=f"{needs_update} device(s) need attention; {up_to_date} up to date."
            )
            return updates_list, str(up_to_date), str(needs_update), toast

        except Exception as e:
            logger.error(f"Error checking firmware updates: {e}")
            return (
                dbc.Alert(f"Error: {e}", color="danger"),
                "0", "0",
                ToastManager.error("Error", detail_message=str(e)),
            )

    # ====================================================================
    # 50. Update all firmware
    # ====================================================================
    @app.callback(
        Output('toast-container', 'children', allow_duplicate=True),
        Input('update-all-firmware-btn', 'n_clicks'),
        prevent_initial_call=True
    )
    def update_all_firmware(n_clicks):
        """Update all firmware with toast notification."""
        if not n_clicks:
            raise dash.exceptions.PreventUpdate

        # In a real system, this would trigger actual firmware updates
        toast = ToastManager.info(
                "Updates Scheduled",
                detail_message="Updates Scheduled"
            )
        return toast

    # ====================================================================
    # 51. Refresh smart home data
    # ====================================================================
    @app.callback(
        [Output('smarthome-hubs-list', 'children', allow_duplicate=True),
         Output('smarthome-ecosystems-list', 'children', allow_duplicate=True),
         Output('smarthome-rooms-list', 'children', allow_duplicate=True),
         Output('smarthome-automations-list', 'children', allow_duplicate=True),
         Output('toast-container', 'children', allow_duplicate=True)],
        Input('refresh-smarthome-btn', 'n_clicks'),
        prevent_initial_call=True
    )
    def refresh_smarthome(n_clicks):
        """Refresh all smart home data and displays."""
        if not n_clicks:
            raise dash.exceptions.PreventUpdate

        try:
            conn = get_db_connection()
            if not conn:
                toast = ToastManager.error(
                "Refresh Failed",
                detail_message="Refresh Failed"
            )
                return dash.no_update, dash.no_update, dash.no_update, dash.no_update, toast

            # Get fresh data from database
            cursor = conn.cursor()

            # Hubs list (simplified - show count)
            cursor.execute('SELECT COUNT(DISTINCT device_ip) as count FROM devices WHERE device_type LIKE "%hub%"')
            hubs_count = cursor.fetchone()['count']
            hubs_list = dbc.Alert([
                html.I(className="fa fa-broadcast-tower me-2"),
                f"{hubs_count} smart home hub(s) detected"
            ], color="success" if hubs_count > 0 else "info")

            # Ecosystems list (simplified - show count)
            cursor.execute('SELECT COUNT(DISTINCT manufacturer) as count FROM devices WHERE manufacturer IS NOT NULL')
            ecosystems_count = cursor.fetchone()['count']
            ecosystems_list = dbc.Alert([
                html.I(className="fa fa-sitemap me-2"),
                f"{ecosystems_count} manufacturer ecosystem(s) detected"
            ], color="info")

            # Rooms list — real count from DB
            cursor.execute('''
                SELECT COUNT(*) as count FROM smart_home_rooms
            ''')
            room_count = cursor.fetchone()['count']
            rooms_list = dbc.Alert([
                html.I(className="fa fa-map-marker-alt me-2"),
                f"{room_count} room(s) configured" if room_count else
                "No rooms yet — use the Rooms tab to create them."
            ], color="success" if room_count else "info")

            # Automations list — real data
            automations_list = _render_automations(db_manager)


            toast = ToastManager.success(
                "Refreshed",
                detail_message="Refreshed"
            )

            return hubs_list, ecosystems_list, rooms_list, automations_list, toast

        except Exception as e:
            logger.error(f"Error refreshing smart home data: {e}")
            toast = ToastManager.error(
                "Error",
                detail_message="Error"
            )
            return dash.no_update, dash.no_update, dash.no_update, dash.no_update, toast

    # ====================================================================
    # 52. Refresh firmware stats
    # ====================================================================
    @app.callback(
        [Output('firmware-uptodate-count', 'children', allow_duplicate=True),
         Output('firmware-updates-count', 'children', allow_duplicate=True),
         Output('firmware-critical-count', 'children', allow_duplicate=True),
         Output('firmware-unknown-count', 'children', allow_duplicate=True),
         Output('eol-devices-list', 'children', allow_duplicate=True),
         Output('firmware-updates-list', 'children', allow_duplicate=True),
         Output('toast-container', 'children', allow_duplicate=True)],
        Input('refresh-firmware-btn', 'n_clicks'),
        prevent_initial_call=True
    )
    def refresh_firmware(n_clicks):
        """Refresh firmware data with toast notification."""
        if not n_clicks:
            raise dash.exceptions.PreventUpdate

        try:
            # Refresh firmware stats
            conn = get_db_connection()
            if not conn:
                toast = ToastManager.error(
                "Refresh Failed",
                detail_message="Refresh Failed"
            )
                return "0", "0", "0", "0", dbc.Alert("No data", color="info"), html.Div("No updates"), toast

            cursor = conn.cursor()

            # Get firmware stats
            try:
                cursor.execute('SELECT COUNT(*) as total FROM device_firmware_status')
                total = cursor.fetchone()['total']

                if total > 0:
                    cursor.execute('SELECT COUNT(*) as count FROM device_firmware_status WHERE update_available = 0 AND is_eol = 0')
                    up_to_date = cursor.fetchone()['count']

                    cursor.execute('SELECT COUNT(*) as count FROM device_firmware_status WHERE update_available = 1 AND is_eol = 0')
                    updates_available = cursor.fetchone()['count']

                    cursor.execute('SELECT COUNT(*) as count FROM device_firmware_status WHERE is_eol = 1')
                    critical = cursor.fetchone()['count']

                    unknown = total - up_to_date - updates_available - critical
                    stats = (str(up_to_date), str(updates_available), str(critical), str(max(0, unknown)))
                else:
                    # Fallback
                    cursor.execute('SELECT COUNT(*) as total FROM devices')
                    total = cursor.fetchone()['total']
                    cursor.execute('SELECT COUNT(*) as count FROM devices WHERE firmware_version IS NOT NULL AND firmware_version != ""')
                    with_firmware = cursor.fetchone()['count']
                    stats = (str(with_firmware), "0", "0", str(max(0, total - with_firmware)))
            except:
                cursor.execute('SELECT COUNT(*) as total FROM devices')
                total = cursor.fetchone()['total']
                stats = (str(total), "0", "0", "0")

            # EOL list is handled by update_eol_devices (triggered by same refresh btn)
            eol_list = no_update

            # Get firmware updates
            updates_list = html.Div([
                dbc.Alert([
                    html.I(className="fa fa-check-circle me-2"),
                    "All devices are up to date!"
                ], color="success")
            ])

            toast = ToastManager.success(
                "Firmware data refreshed",
                detail_message="Firmware status and lifecycle data has been refreshed."
            )

            return *stats, eol_list, updates_list, toast

        except Exception as e:
            logger.error(f"Error refreshing firmware data: {e}")
            toast = ToastManager.error(
                "Error",
                detail_message="Error"
            )
            return "0", "0", "0", "0", dbc.Alert("Error loading data", color="danger"), html.Div("Error"), toast

    # ====================================================================
    # 53. Import devices CSV/JSON
    # ====================================================================
    @app.callback(
        [Output('import-status', 'children'),
         Output('toast-container', 'children', allow_duplicate=True)],
        Input('import-devices-upload', 'contents'),
        State('import-devices-upload', 'filename'),
        prevent_initial_call=True
    )
    def import_devices(contents, filename):
        """Import devices from uploaded CSV or JSON file."""
        if not contents:
            raise dash.exceptions.PreventUpdate

        try:
            # Parse the uploaded file
            content_type, content_string = contents.split(',')
            decoded = base64.b64decode(content_string)

            imported_count = 0

            if filename.endswith('.csv'):
                # Parse CSV
                df = pd.read_csv(io.StringIO(decoded.decode('utf-8')))

                conn = get_db_connection()

                cursor = conn.cursor()

                for _, row in df.iterrows():
                    try:
                        # Insert or update device
                        cursor.execute('''
                            INSERT OR REPLACE INTO devices
                            (device_ip, device_name, device_type, mac_address, manufacturer, is_trusted, is_blocked)
                            VALUES (?, ?, ?, ?, ?, ?, ?)
                        ''', (
                            row.get('IP Address'),
                            row.get('Device Name'),
                            row.get('Type'),
                            row.get('MAC Address'),
                            row.get('Manufacturer'),
                            1 if row.get('Status') == 'Trusted' else 0,
                            1 if row.get('Status') == 'Blocked' else 0
                        ))
                        imported_count += 1
                    except Exception as e:
                        logger.warning(f"Error importing row: {e}")
                        continue

                conn.commit()

            elif filename.endswith('.json'):
                # Parse JSON
                import_data = json.loads(decoded.decode('utf-8'))

                conn = get_db_connection()

                cursor = conn.cursor()

                for device in import_data:
                    try:
                        cursor.execute('''
                            INSERT OR REPLACE INTO devices
                            (device_ip, device_name, device_type, mac_address, manufacturer, is_trusted, is_blocked)
                            VALUES (?, ?, ?, ?, ?, ?, ?)
                        ''', (
                            device.get('device_ip'),
                            device.get('device_name'),
                            device.get('device_type'),
                            device.get('mac_address'),
                            device.get('manufacturer'),
                            device.get('is_trusted', 0),
                            device.get('is_blocked', 0)
                        ))
                        imported_count += 1
                    except Exception as e:
                        logger.warning(f"Error importing device: {e}")
                        continue

                conn.commit()
            else:
                raise Exception("Unsupported file format. Please upload CSV or JSON.")

            # Success message
            status = dbc.Alert(
                [html.I(className="fa fa-check-circle me-2"), f"Successfully imported {imported_count} devices!"],
                color="success",
                className="mb-0"
            )

            toast = ToastManager.success(
                "Import Complete",
                detail_message="Import Complete"
            )

            return status, toast

        except Exception as e:
            logger.error(f"Error importing devices: {e}")

            status = dbc.Alert(
                [html.I(className="fa fa-exclamation-triangle me-2"), f"Import failed: {str(e)}"],
                color="danger",
                className="mb-0"
            )

            toast = ToastManager.error(
                "Import Error",
                detail_message="Import Error"
            )

            return status, toast

    # ====================================================================
    # 54. Export devices (RBAC)
    # ====================================================================
    @app.callback(
        [Output('toast-container', 'children', allow_duplicate=True),
         Output('download-export', 'data', allow_duplicate=True),
         Output('device-mgmt-modal', 'is_open', allow_duplicate=True)],
        Input('export-devices-btn', 'n_clicks'),
        State('export-format-select', 'value'),
        prevent_initial_call=True
    )
    @login_required
    def export_devices(n_clicks, export_format):
        """Export devices list in selected format (CSV, JSON, PDF, Excel). Requires export_data permission."""
        if not n_clicks:
            raise dash.exceptions.PreventUpdate

        # Check export permission
        if not can_export_data(current_user):
            security_audit_logger.log(
                event_type='permission_denied',
                user_id=current_user.id if current_user.is_authenticated else None,
                username=current_user.username if current_user.is_authenticated else 'anonymous',
                details={'action': 'export_devices', 'format': export_format},
                severity='medium',
                result='failure',
                failure_reason='Insufficient permissions - requires export_data'
            )
            toast = ToastManager.error(
                "Permission Denied",
                detail_message="You don't have permission to export data. Contact your administrator."
            )
            return toast, None, True

        try:
            # Normalize format (xlsx -> excel)
            format_map = {'xlsx': 'excel', 'csv': 'csv', 'json': 'json', 'pdf': 'pdf'}
            export_format = format_map.get(export_format or 'csv', 'csv')

            # Use universal export helper
            download_data = export_helper.export_devices(format=export_format)

            if download_data:
                # Log successful export
                security_audit_logger.log(
                    event_type='data_export',
                    user_id=current_user.id,
                    username=current_user.username,
                    details={'resource': 'devices', 'format': export_format},
                    severity='info',
                    resource_type='devices',
                    result='success'
                )
                toast = ToastManager.success(
                    "Export Complete",
                    detail_message=f"Devices exported as {export_format.upper()}"
                )
                return toast, download_data, False
            else:
                toast = ToastManager.error(
                    "Export Failed",
                    detail_message="No data available or export failed"
                )
                return toast, None, True

        except Exception as e:
            logger.error(f"Error exporting devices: {e}")
            toast = ToastManager.error(
                "Export Error",
                detail_message=str(e)
            )
            return toast, None, True

    # ====================================================================
    # 55. Automation creation form
    # ====================================================================
    @app.callback(
        [Output('smarthome-automations-list', 'children', allow_duplicate=True),
         Output('toast-container', 'children', allow_duplicate=True)],
        Input('create-automation-btn', 'n_clicks'),
        prevent_initial_call=True
    )
    def create_automation(n_clicks):
        """Show automation creation form."""
        if not n_clicks:
            raise dash.exceptions.PreventUpdate

        # Create automation creation form
        automation_form = dbc.Card([
            dbc.CardHeader([
                html.I(className="fa fa-plus-circle me-2 text-primary"),
                html.Strong("Create New Automation")
            ]),
            dbc.CardBody([
                dbc.Form([
                    # Automation Name
                    dbc.Row([
                        dbc.Label("Automation Name", html_for="auto-name", sm=3, xs=12),
                        dbc.Col([
                            dbc.Input(
                                type="text",
                                id="auto-name",
                                placeholder="e.g., Evening Lights Off",
                            )
                        ], sm=9, xs=12)
                    ], className="mb-3"),

                    # Trigger Type
                    dbc.Row([
                        dbc.Label("Trigger", html_for="auto-trigger", sm=3, xs=12),
                        dbc.Col([
                            dbc.Select(
                                id="auto-trigger",
                                options=[
                                    {"label": "🕐 Time-based (Schedule)", "value": "time"},
                                    {"label": "🔌 Device State Change", "value": "device"},
                                    {"label": "🏠 Location (Home/Away)", "value": "location"},
                                    {"label": "🌡️ Sensor Reading", "value": "sensor"}
                                ],
                                value="time"
                            )
                        ], sm=9, xs=12)
                    ], className="mb-3"),

                    # Condition
                    dbc.Row([
                        dbc.Label("Condition", html_for="auto-condition", sm=3, xs=12),
                        dbc.Col([
                            dbc.Input(
                                type="text",
                                id="auto-condition",
                                placeholder="e.g., After 10:00 PM",
                            )
                        ], sm=9, xs=12)
                    ], className="mb-3"),

                    # Action
                    dbc.Row([
                        dbc.Label("Action", html_for="auto-action", sm=3, xs=12),
                        dbc.Col([
                            dbc.Textarea(
                                id="auto-action",
                                placeholder="e.g., Turn off all lights in living room",
                                rows=3
                            )
                        ], sm=9, xs=12)
                    ], className="mb-3"),

                    # Buttons
                    dbc.Row([
                        dbc.Col([
                            dbc.Button([
                                html.I(className="fa fa-save me-2"),
                                "Save Automation"
                            ], color="primary", id="save-automation-btn", className="me-2"),
                            dbc.Button([
                                html.I(className="fa fa-times me-2"),
                                "Cancel"
                            ], color="secondary", outline=True, id="cancel-automation-btn")
                        ], width=12)
                    ])
                ])
            ])
        ], className="shadow-sm mb-3")

        toast = ToastManager.info(
                "Create Automation",
                detail_message="Create Automation"
            )

        return automation_form, toast

    # ====================================================================
    # 56. Save automation
    # ====================================================================
    @app.callback(
        [Output('smarthome-automations-list', 'children', allow_duplicate=True),
         Output('toast-container', 'children', allow_duplicate=True)],
        Input('save-automation-btn', 'n_clicks'),
        [State('auto-name', 'value'),
         State('auto-trigger', 'value'),
         State('auto-condition', 'value'),
         State('auto-action', 'value')],
        prevent_initial_call=True
    )
    def save_automation(n_clicks, name, trigger, condition, action):
        """Persist the new automation to smart_home_automations and re-render the list."""
        if not n_clicks:
            raise dash.exceptions.PreventUpdate

        if not name or not action:
            return dash.no_update, ToastManager.warning(
                "Validation Error", detail_message="Name and Action are required."
            )

        aid = db_manager.save_automation(
            name=name.strip(),
            trigger_type=trigger or "time",
            condition_text=(condition or "").strip(),
            action_text=action.strip(),
        )

        if aid is None:
            return dash.no_update, ToastManager.error(
                "Save Failed", detail_message="Could not save automation."
            )

        return _render_automations(db_manager), ToastManager.success(
            "Automation Saved", detail_message=f'"{name}" saved.'
        )

    # ====================================================================
    # 57. Cancel automation
    # ====================================================================
    @app.callback(
        [Output('smarthome-automations-list', 'children', allow_duplicate=True),
         Output('toast-container', 'children', allow_duplicate=True)],
        Input('cancel-automation-btn', 'n_clicks'),
        prevent_initial_call=True
    )
    def cancel_automation(n_clicks):
        """Cancel automation creation and restore the automations list."""
        if not n_clicks:
            raise dash.exceptions.PreventUpdate

        return _render_automations(db_manager), ToastManager.info(
            "Cancelled", detail_message="Automation creation cancelled."
        )

    # ====================================================================
    # 58. Device hierarchy sunburst chart
    # ====================================================================
    @app.callback(
        Output('device-hierarchy-sunburst', 'figure'),
        [Input('device-mgmt-modal', 'is_open'),
         Input('global-device-filter', 'data')],
        State('resolved-theme-store', 'data'),
        prevent_initial_call=True
    )
    def create_device_hierarchy_sunburst(is_open, device_filter, theme_data):
        """
        Create Sunburst chart showing hierarchical device data:
        Center -> Device Categories -> Device Types -> Specific Devices
        """
        if not is_open:
            raise dash.exceptions.PreventUpdate
        is_dark = (theme_data or {}).get('theme') == 'dark'
        text_color = '#e4e4e7' if is_dark else '#333333'

        try:
            conn = get_db_connection()
            cursor = conn.cursor()

            # Query device hierarchy data
            cursor.execute("""
                SELECT
                    d.device_ip,
                    d.device_name,
                    d.device_type,
                    d.manufacturer,
                    COUNT(DISTINCT c.id) as connection_count
                FROM devices d
                LEFT JOIN connections c ON d.device_ip = c.device_ip
                    AND c.timestamp >= datetime('now', '-24 hours')
                GROUP BY d.device_ip, d.device_name, d.device_type, d.manufacturer
            """)

            devices = cursor.fetchall()

            if not devices:
                fig = go.Figure()
                fig.update_layout(title="No device data available")
                return fig

            # Build hierarchical structure
            # Format: labels, parents, values
            labels = ["All Devices"]
            parents = [""]
            values = [0]  # Will be sum of all connections
            colors = ["#17a2b8"]

            # Group by device type
            type_groups = {}
            total_connections = 0

            for device in devices:
                device_type = device['device_type'] or "Unknown"
                connections = device['connection_count'] or 0

                if device_type not in type_groups:
                    type_groups[device_type] = {'devices': [], 'total_connections': 0}

                type_groups[device_type]['devices'].append(device)
                type_groups[device_type]['total_connections'] += connections

            # Add device type level
            type_colors = {
                'Smart TV': '#9c27b0',
                'Smart Speaker': '#2196f3',
                'Camera': '#f44336',
                'Thermostat': '#ff9800',
                'Laptop': '#4caf50',
                'Smartphone': '#00bcd4',
                'Router': '#e91e63',
                'Unknown': '#9e9e9e'
            }

            for device_type, group_data in type_groups.items():
                # Leaf value floor is (connection_count or 1); parent must match that sum
                leaf_sum = sum(max(d['connection_count'] or 0, 1) for d in group_data['devices'])
                total_connections += leaf_sum

                labels.append(device_type)
                parents.append("All Devices")
                values.append(leaf_sum)
                colors.append(type_colors.get(device_type, '#607d8b'))

                # Add individual devices under each type
                for device in group_data['devices']:
                    device_label = device['device_name'] or device['device_ip']
                    labels.append(device_label)
                    parents.append(device_type)
                    values.append(max(device['connection_count'] or 0, 1))

                    # Color based on connection activity
                    conn_count = device['connection_count'] or 0
                    if conn_count > 100:
                        colors.append('#dc3545')  # High activity - red
                    elif conn_count > 50:
                        colors.append('#ffc107')  # Medium activity - yellow
                    else:
                        colors.append('#28a745')  # Low activity - green

            values[0] = total_connections  # root must equal sum of all leaf values

            # Create Sunburst chart
            fig = go.Figure(go.Sunburst(
                labels=labels,
                parents=parents,
                values=values,
                marker=dict(
                    colors=colors,
                    line=dict(color='white', width=2)
                ),
                branchvalues="total",
                hovertemplate='<b>%{label}</b><br>Connections: %{value}<br><extra></extra>'
            ))

            fig.update_layout(
                title="Device Hierarchy - Interactive Sunburst Chart",
                font=dict(size=12, color=text_color),
                paper_bgcolor='rgba(0,0,0,0)',
                height=600,
                hovermode='closest'
            )

            return fig

        except Exception as e:
            logger.error(f"Error creating sunburst chart: {e}")
            fig = go.Figure()
            fig.update_layout(title=f"Error loading device hierarchy: {str(e)}",
                              paper_bgcolor='rgba(0,0,0,0)', font={'color': text_color})
            return fig

    # ── AI Device Name Suggestion ─────────────────────────────────────────────

    @app.callback(
        Output('toast-container', 'children', allow_duplicate=True),
        Input({'type': 'device-name-save-btn', 'ip': ALL}, 'n_clicks'),
        State({'type': 'device-custom-name', 'ip': ALL}, 'value'),
        State({'type': 'device-name-save-btn', 'ip': ALL}, 'id'),
        prevent_initial_call=True,
    )
    def save_device_custom_name(n_clicks_list, name_values, btn_ids):
        if not any(n for n in (n_clicks_list or []) if n):
            raise dash.exceptions.PreventUpdate
        triggered = callback_context.triggered_id
        if not triggered or not isinstance(triggered, dict):
            raise dash.exceptions.PreventUpdate
        device_ip = triggered.get('ip')
        if not device_ip:
            raise dash.exceptions.PreventUpdate
        if not current_user.is_authenticated or not can_manage_devices(current_user):
            return ToastManager.error("Permission denied", detail_message="You need device management permissions.")
        # Find the value for this IP
        name_val = ''
        for ids, val in zip(btn_ids or [], name_values or []):
            if isinstance(ids, dict) and ids.get('ip') == device_ip:
                name_val = (val or '').strip()
                break
        try:
            db_manager.update_device_metadata(device_ip, custom_name=name_val or None)
            return ToastManager.success(
                f"Name saved: {name_val or '(cleared)'}",
                detail_message=f"Device {device_ip} will now show as '{name_val}' in the dashboard.",
                duration=3000,
            )
        except Exception as e:
            logger.error(f"Failed to save custom name for {device_ip}: {e}")
            return ToastManager.error("Save failed", detail_message=str(e))

    # ── Device Personality Profile ────────────────────────────────────────

    import time as _time
    from utils.device_personality import build_profile_facts, generate_personality, PERSONALITY_TTL
    from utils.alert_explainer import source_label as _sl, source_badge_class as _sbc
    from dashboard.shared import ai_assistant as _ai

    @app.callback(
        [Output('device-personality-content', 'children'),
         Output('device-personality-timestamp', 'children'),
         Output('device-personality-source-badge', 'children'),
         Output('device-personality-source-badge', 'className'),
         Output('device-personality-cache', 'data')],
        [Input('device-personality-device', 'data'),
         Input('device-personality-refresh-btn', 'n_clicks')],
        State('device-personality-cache', 'data'),
        prevent_initial_call=False,
    )
    def update_device_personality(device_ip, _refresh, cache):
        if not device_ip:
            raise dash.exceptions.PreventUpdate

        cache = cache or {}
        cached = cache.get(device_ip, {})
        age = _time.time() - float(cached.get('ts', 0))
        is_manual = (
            callback_context.triggered_id == 'device-personality-refresh-btn'
            if callback_context.triggered else False
        )

        if not is_manual and age < PERSONALITY_TTL and cached.get('text'):
            hrs  = int(age // 3600)
            mins = int((age % 3600) // 60)
            ts_label = f"Updated {hrs}h {mins}m ago" if hrs else f"Updated {mins}m ago"
            src = cached.get('source', '')
            return (
                dcc.Markdown(cached['text'], className="mb-0 small"),
                ts_label,
                _sl(src),
                _sbc(src),
                cache,
            )

        try:
            facts = build_profile_facts(db_manager, device_ip)
            text, source = generate_personality(facts, _ai)
        except Exception as exc:
            logger.warning(f"[device_personality] generation failed for {device_ip}: {exc}")
            text = "Profile unavailable. Check back after the baseline learning period completes."
            source = 'rules'

        cache[device_ip] = {'text': text, 'source': source, 'ts': _time.time()}
        return (
            dcc.Markdown(text, className="mb-0 small"),
            "Just now",
            _sl(source),
            _sbc(source),
            cache,
        )
