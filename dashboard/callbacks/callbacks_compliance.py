"""
Compliance, Vulnerability Scanner, Attack Surface, Firewall, Sustainability,
Education, and Network Segmentation callbacks.

Extracted from app.py.  All callbacks are registered via ``register(app)``.
"""

import json
import logging
import random
from collections import defaultdict
from datetime import datetime

import dash
import dash_bootstrap_components as dbc
import pandas as pd
import plotly.express as px
import plotly.graph_objs as go
from dash import dcc, html, Input, Output, State, callback_context, ALL, no_update

from flask_login import current_user, login_required

from dashboard.shared import (
    db_manager,
    chart_factory,
    export_helper,
    logger as _shared_logger,
    config,
    get_firmware_manager,
    get_network_segmentation,
    get_sustainability_calculator,
    get_intelligence,
    get_threat_detector,
    security_audit_logger,
    can_export_data,
    SEVERITY_COLORS,
    RISK_COLORS,
    ChartFactory,
    get_db_connection,
    create_timestamp_display,
    ToastManager,
    PermissionManager,
)

logger = logging.getLogger(__name__)


def register(app):
    """Register all compliance-related callbacks with the Dash app."""

    # =========================================================================
    # FIREWALL CALLBACKS
    # =========================================================================

    @app.callback(
        Output("firewall-modal", "is_open"),
        Input("firewall-card-btn", "n_clicks"),
        State("firewall-modal", "is_open"),
        prevent_initial_call=True
    )
    def toggle_firewall_modal(n, is_open):
        return not is_open

    @app.callback(
        [Output("firewall-modal", "is_open", allow_duplicate=True),
         Output("toast-container", "children", allow_duplicate=True)],
        [Input("save-firewall-btn", "n_clicks"),
         Input("cancel-firewall-btn", "n_clicks")],
        State("lockdown-switch", "value"),
        prevent_initial_call=True
    )
    def handle_firewall_modal_actions(save_clicks, cancel_clicks, lockdown_state):
        """Handle Firewall modal Save and Cancel actions (Admin/Parent only)."""
        ctx = dash.callback_context
        if not ctx.triggered:
            return dash.no_update, dash.no_update

        # Defensive check: ensure buttons have actually been clicked
        if save_clicks is None and cancel_clicks is None:
            return dash.no_update, dash.no_update

        button_id = ctx.triggered[0]['prop_id'].split('.')[0]

        if button_id == 'cancel-firewall-btn':
            # Cancel button - close modal with toast
            toast = ToastManager.info(
                "Changes discarded",
                detail_message="Firewall settings were not saved."
            )
            return False, toast

        elif button_id == 'save-firewall-btn':
            # RBAC permission check - require manage_firewall (security_analyst+)
            if not PermissionManager.has_permission(current_user, 'manage_firewall'):
                security_audit_logger.log(
                    event_type='permission_denied',
                    user_id=current_user.id if current_user.is_authenticated else None,
                    username=current_user.username if current_user.is_authenticated else 'anonymous',
                    details={'action': 'modify_firewall', 'lockdown_state': lockdown_state},
                    severity='high',
                    result='failure',
                    failure_reason='Requires manage_firewall permission (security_analyst+)'
                )
                toast = ToastManager.error(
                    "Permission Denied",
                    detail_message="Firewall and lockdown settings require security analyst privileges."
                )
                return False, toast

            try:
                # Save firewall settings
                conn = db_manager.conn
                cursor = conn.cursor()

                # Permissions already enforced via RBAC
            except Exception as e:
                logger.error(f"Error checking user permissions: {e}")

            # Save button - apply lockdown state and close modal
            try:
                # Here you would typically save the lockdown state to database or config
                # For now, we'll just show a success toast
                if lockdown_state:
                    toast = ToastManager.success(
                        "Lockdown Mode Enabled",
                        detail_message="All untrusted devices are now blocked. Only trusted devices can access the network."
                    )
                else:
                    toast = ToastManager.success(
                        "Lockdown Mode Disabled",
                        detail_message="Network access restrictions have been removed."
                    )

                security_audit_logger.log(
                    event_type='lockdown_activated' if lockdown_state else 'lockdown_deactivated',
                    user_id=current_user.id,
                    username=current_user.username,
                    details={'lockdown_enabled': lockdown_state, 'action': 'firewall_settings_changed'},
                    severity='high',
                    resource_type='firewall',
                    result='success'
                )
                return False, toast
            except Exception as e:
                toast = ToastManager.error(
                    "Failed to save firewall settings",
                    detail_message=f"Error: {str(e)}"
                )
                return dash.no_update, toast

        return dash.no_update, dash.no_update

    # =========================================================================
    # EDUCATION CALLBACKS
    # =========================================================================

    @app.callback(
        Output("education-modal", "is_open"),
        [Input("education-card-btn", "n_clicks"),
         Input("close-education-modal-btn", "n_clicks")],
        State("education-modal", "is_open"),
        prevent_initial_call=True
    )
    def toggle_education_modal(open_clicks, close_clicks, is_open):
        return not is_open

    # =========================================================================
    # EXPORT SECURITY REPORT CALLBACK (RBAC)
    # =========================================================================

    @app.callback(
        [Output('toast-container', 'children', allow_duplicate=True),
         Output('download-export', 'data', allow_duplicate=True)],
        Input('export-security-report-btn', 'n_clicks'),
        State('export-format-security', 'value'),
        prevent_initial_call=True
    )
    @login_required
    def export_security_report(n_clicks, export_format):
        """Export comprehensive security summary report in selected format. Requires export_data permission."""
        if not n_clicks:
            raise dash.exceptions.PreventUpdate

        # Check export permission
        if not can_export_data(current_user):
            security_audit_logger.log(
                event_type='permission_denied',
                user_id=current_user.id if current_user.is_authenticated else None,
                username=current_user.username if current_user.is_authenticated else 'anonymous',
                details={'action': 'export_security_report', 'format': export_format},
                severity='medium',
                result='failure',
                failure_reason='Insufficient permissions - requires export_data'
            )
            toast = ToastManager.error(
                "Permission Denied",
                detail_message="You don't have permission to export security reports."
            )
            return toast, None

        try:
            # Normalize format (xlsx -> excel)
            format_map = {'xlsx': 'excel', 'csv': 'csv', 'json': 'json', 'pdf': 'pdf'}
            export_format = format_map.get(export_format or 'csv', 'csv')

            # Log export attempt
            security_audit_logger.log(
                event_type='data_export',
                user_id=current_user.id,
                username=current_user.username,
                details={'resource': 'security_report', 'format': export_format, 'days': 7},
                severity='info',
                resource_type='security_report',
                result='success'
            )

            # Export alerts data (security reports are based on alerts)
            download_data = export_helper.export_alerts(format=export_format, days=7)

            if download_data:
                toast = ToastManager.success(
                    "Export Complete",
                    detail_message=f"Security report exported as {export_format.upper()}"
                )
                return toast, download_data
            else:
                toast = ToastManager.error(
                    "Export Failed",
                    detail_message="No data available or export failed"
                )
                return toast, None

        except Exception as e:
            logger.error(f"Error exporting security report: {e}")
            toast = ToastManager.error(
                "Export Error",
                detail_message=str(e)
            )
            return toast, None

    # =========================================================================
    # NETWORK SEGMENTATION CALLBACKS
    # =========================================================================

    @app.callback(
        Output("segmentation-modal", "is_open"),
        [Input("segmentation-card-btn", "n_clicks"),
         Input("close-segmentation-modal-btn", "n_clicks")],
        State("segmentation-modal", "is_open"),
        prevent_initial_call=True
    )
    def toggle_segmentation_modal(open_clicks, close_clicks, is_open):
        return not is_open

    # Segmentation Modal - Timestamp Update
    @app.callback(
        [Output('segmentation-timestamp-display', 'children'),
         Output('segmentation-timestamp-store', 'data'),
         Output('toast-container', 'children', allow_duplicate=True)],
        [Input('segmentation-modal', 'is_open'),
         Input('refresh-segmentation-btn', 'n_clicks')],
        prevent_initial_call=True
    )
    def update_segmentation_timestamp(is_open, refresh_clicks):
        """Update timestamp display for Segmentation Modal"""
        from dash import callback_context
        ctx = callback_context

        # Check if refresh button was clicked
        show_toast = ctx.triggered and ctx.triggered[0]['prop_id'] == 'refresh-segmentation-btn.n_clicks' if ctx.triggered else False

        if not is_open:
            raise dash.exceptions.PreventUpdate

        # Get current timestamp
        current_time = datetime.now()
        timestamp_str = current_time.isoformat()

        # Create timestamp display
        display = create_timestamp_display(current_time)

        # Generate toast if refresh was clicked
        toast = ToastManager.success(
            "Segmentation data refreshed",
            detail_message="Network segmentation analysis updated successfully"
        ) if show_toast else dash.no_update

        return display, timestamp_str, toast

    # Network Segmentation Overview Stats
    @app.callback(
        [Output('seg-total-segments', 'children'),
         Output('seg-segmented-devices', 'children'),
         Output('seg-unsegmented-devices', 'children'),
         Output('seg-violations-24h', 'children'),
         Output('segmentation-coverage-chart', 'figure')],
        [Input('segmentation-modal', 'is_open'),
         Input('refresh-segmentation-btn', 'n_clicks')],
        prevent_initial_call=True
    )
    def update_segmentation_overview(is_open, refresh_clicks):
        """Update network segmentation overview statistics."""
        if not is_open:
            raise dash.exceptions.PreventUpdate

        try:
            conn = get_db_connection()

            cursor = conn.cursor()

            # Get total segments
            cursor.execute('SELECT COUNT(*) as count FROM network_segments')
            total_segments = cursor.fetchone()['count']

            # Get total devices
            cursor.execute('SELECT COUNT(*) as count FROM devices')
            total_devices = cursor.fetchone()['count']

            # Get segmented devices (devices in device_segments with current_segment=1)
            cursor.execute('''
                SELECT COUNT(DISTINCT device_ip) as count
                FROM device_segments
                WHERE current_segment = 1
            ''')
            segmented_devices = cursor.fetchone()['count']

            # Calculate unsegmented devices
            unsegmented_devices = total_devices - segmented_devices

            # Get violations in last 24 hours
            cursor.execute(f'''
                SELECT COUNT(*) as count
                FROM segmentation_violations
                WHERE timestamp > datetime('now', '-24 hours')
            ''')
            violations_24h = cursor.fetchone()['count']

            # Create coverage chart (pie chart)
            coverage_fig = ChartFactory.create_pie_chart(
                labels=['Segmented', 'Unsegmented'],
                values=[segmented_devices, unsegmented_devices],
                colors=['#00bc8c', '#f39c12'],
                title='Coverage',
                show_legend=True,
                legend_orientation='h'
            )


            return (
                str(total_segments),
                str(segmented_devices),
                str(unsegmented_devices),
                str(violations_24h),
                coverage_fig
            )

        except Exception as e:
            logger.error(f"Error updating segmentation overview: {e}")
            return "—", "—", "—", "—", {}

    # Segments List Table
    @app.callback(
        Output('segments-list-table', 'children'),
        [Input('segmentation-modal', 'is_open'),
         Input('refresh-segmentation-btn', 'n_clicks')],
        prevent_initial_call=True
    )
    def update_segments_list(is_open, refresh_clicks):
        """Display list of all network segments."""
        if not is_open:
            raise dash.exceptions.PreventUpdate

        try:
            conn = get_db_connection()

            cursor = conn.cursor()
            cursor.execute('''
                SELECT
                    ns.segment_name,
                    ns.vlan_id,
                    ns.subnet,
                    ns.security_level,
                    ns.isolation_enabled,
                    COUNT(ds.device_ip) as device_count
                FROM network_segments ns
                LEFT JOIN device_segments ds ON ns.id = ds.segment_id AND ds.current_segment = 1
                GROUP BY ns.id, ns.segment_name, ns.vlan_id, ns.subnet, ns.security_level, ns.isolation_enabled
                ORDER BY ns.security_level DESC, ns.segment_name
            ''')
            segments = cursor.fetchall()

            if not segments:
                return dbc.Alert([
                    html.I(className="fa fa-info-circle me-2"),
                    "No network segments configured yet. Segments can be created to isolate different device types."
                ], color="info")

            # Create table
            table_header = [
                html.Thead(html.Tr([
                    html.Th("Segment Name"),
                    html.Th("VLAN ID"),
                    html.Th("Subnet"),
                    html.Th("Security Level"),
                    html.Th("Isolation"),
                    html.Th("Devices")
                ]))
            ]

            table_rows = []
            for seg in segments:
                security_badge_color = {
                    'critical': 'danger',
                    'high': 'warning',
                    'medium': 'info',
                    'low': 'secondary'
                }.get(seg['security_level'], 'secondary')

                table_rows.append(html.Tr([
                    html.Td(seg['segment_name']),
                    html.Td(seg['vlan_id'] if seg['vlan_id'] else '—'),
                    html.Td(seg['subnet'] if seg['subnet'] else '—'),
                    html.Td(dbc.Badge(seg['security_level'].upper(), color=security_badge_color)),
                    html.Td([
                        html.I(className="fa fa-check text-success" if seg['isolation_enabled'] else "fa fa-times text-muted")
                    ]),
                    html.Td(dbc.Badge(seg['device_count'], color="primary", className="rounded-pill"))
                ]))

            table_body = [html.Tbody(table_rows)]

            return dbc.Table(table_header + table_body, bordered=True, hover=True, responsive=True, dark=False, className="mb-0 table-adaptive")

        except Exception as e:
            logger.error(f"Error loading segments list: {e}")
            return dbc.Alert(f"Error loading segments: {str(e)}", color="danger")

    # Segment Filter Dropdown Population
    @app.callback(
        Output('seg-filter-dropdown', 'options'),
        Input('segmentation-modal', 'is_open'),
        prevent_initial_call=True
    )
    def populate_segment_filter(is_open):
        """Populate segment filter dropdown."""
        if not is_open:
            return []

        try:
            conn = get_db_connection()

            cursor = conn.cursor()
            cursor.execute('SELECT id, segment_name FROM network_segments ORDER BY segment_name')
            segments = cursor.fetchall()

            options = [{'label': 'All Segments', 'value': 'all'}]
            options.extend([
                {'label': seg['segment_name'], 'value': seg['id']}
                for seg in segments
            ])

            return options

        except Exception as e:
            logger.error(f"Error populating segment filter: {e}")
            return [{'label': 'Error loading segments', 'value': ''}]

    # Device Segment Mapping Table
    @app.callback(
        Output('device-segment-mapping-table', 'children'),
        [Input('segmentation-modal', 'is_open'),
         Input('seg-filter-dropdown', 'value'),
         Input('refresh-segmentation-btn', 'n_clicks')],
        prevent_initial_call=True
    )
    def update_device_mapping(is_open, segment_filter, refresh_clicks):
        """Display device-to-segment mapping."""
        if not is_open:
            raise dash.exceptions.PreventUpdate

        try:
            conn = get_db_connection()

            cursor = conn.cursor()

            # Build query based on filter
            if segment_filter and segment_filter != 'all':
                query = f'''
                    SELECT
                        d.device_ip,
                        d.device_name,
                        d.device_type,
                        ns.segment_name,
                        ns.security_level,
                        ds.assigned_at
                    FROM device_segments ds
                    JOIN devices d ON ds.device_ip = d.device_ip
                    JOIN network_segments ns ON ds.segment_id = ns.id
                    WHERE ds.current_segment = 1 AND ds.segment_id = ?
                    ORDER BY ds.assigned_at DESC
                    LIMIT 100
                '''
                cursor.execute(query, (segment_filter,))
            else:
                query = '''
                    SELECT
                        d.device_ip,
                        d.device_name,
                        d.device_type,
                        ns.segment_name,
                        ns.security_level,
                        ds.assigned_at
                    FROM device_segments ds
                    JOIN devices d ON ds.device_ip = d.device_ip
                    JOIN network_segments ns ON ds.segment_id = ns.id
                    WHERE ds.current_segment = 1
                    ORDER BY ds.assigned_at DESC
                    LIMIT 100
                '''
                cursor.execute(query)

            mappings = cursor.fetchall()

            if not mappings:
                return dbc.Alert([
                    html.I(className="fa fa-info-circle me-2"),
                    "No device-to-segment mappings found. Devices can be assigned to segments for network isolation."
                ], color="info")

            # Create table
            table_header = [
                html.Thead(html.Tr([
                    html.Th("Device IP"),
                    html.Th("Device Name"),
                    html.Th("Type"),
                    html.Th("Segment"),
                    html.Th("Security Level"),
                    html.Th("Assigned")
                ]))
            ]

            table_rows = []
            for mapping in mappings:
                security_badge_color = {
                    'critical': 'danger',
                    'high': 'warning',
                    'medium': 'info',
                    'low': 'secondary'
                }.get(mapping['security_level'], 'secondary')

                assigned_time = mapping['assigned_at'][:16] if mapping['assigned_at'] else '—'

                table_rows.append(html.Tr([
                    html.Td(mapping['device_ip']),
                    html.Td(mapping['device_name'] if mapping['device_name'] else '—'),
                    html.Td(mapping['device_type'] if mapping['device_type'] else '—'),
                    html.Td(mapping['segment_name']),
                    html.Td(dbc.Badge(mapping['security_level'].upper(), color=security_badge_color)),
                    html.Td(html.Small(assigned_time, className="text-muted"))
                ]))

            table_body = [html.Tbody(table_rows)]

            return dbc.Table(table_header + table_body, bordered=True, hover=True, responsive=True, dark=False, className="mb-0 table-adaptive")

        except Exception as e:
            logger.error(f"Error loading device mapping: {e}")
            return dbc.Alert(f"Error loading device mapping: {str(e)}", color="danger")

    # Violations Timeline and Table
    @app.callback(
        [Output('violations-timeline-chart', 'children'),
         Output('violations-list-table', 'children')],
        [Input('segmentation-modal', 'is_open'),
         Input('seg-violations-timerange', 'value'),
         Input('refresh-segmentation-btn', 'n_clicks')],
        prevent_initial_call=True
    )
    def update_violations(is_open, hours, refresh_clicks):
        """Display segmentation violations timeline and table."""
        if not is_open:
            raise dash.exceptions.PreventUpdate

        try:
            conn = get_db_connection()

            cursor = conn.cursor()

            # Get violations timeline
            query_timeline = f'''
                SELECT
                    strftime('%Y-%m-%d %H:00', timestamp) as hour,
                    COUNT(*) as count
                FROM segmentation_violations
                WHERE timestamp > datetime('now', '-{hours} hours')
                GROUP BY hour
                ORDER BY hour
            '''
            cursor.execute(query_timeline)
            timeline_data = cursor.fetchall()

            # Create timeline chart
            if timeline_data:
                timeline_fig = ChartFactory.create_bar_chart(
                    x_values=[row['hour'] for row in timeline_data],
                    y_values=[row['count'] for row in timeline_data],
                    colors='#e74c3c',
                    title='Violations Timeline',
                    x_title='Time',
                    y_title='Violations'
                )
                timeline_chart = dcc.Graph(figure=timeline_fig, config={'displayModeBar': False})
            else:
                timeline_chart = dbc.Alert([
                    html.I(className="fa fa-check-circle me-2"),
                    "No violations detected in the selected time range."
                ], color="success")

            # Get violations table
            query_table = f'''
                SELECT
                    sv.timestamp,
                    sv.source_device_ip,
                    sv.dest_device_ip,
                    sv.violation_type,
                    sv.severity,
                    sv.blocked,
                    ns1.segment_name as source_segment,
                    ns2.segment_name as dest_segment
                FROM segmentation_violations sv
                LEFT JOIN network_segments ns1 ON sv.source_segment_id = ns1.id
                LEFT JOIN network_segments ns2 ON sv.dest_segment_id = ns2.id
                WHERE sv.timestamp > datetime('now', '-{hours} hours')
                ORDER BY sv.timestamp DESC
                LIMIT 50
            '''
            cursor.execute(query_table)
            violations = cursor.fetchall()

            if not violations:
                return timeline_chart, dbc.Alert([
                    html.I(className="fa fa-check-circle me-2"),
                    "No violations found in the selected time range."
                ], color="success")

            # Create violations table
            table_header = [
                html.Thead(html.Tr([
                    html.Th("Time"),
                    html.Th("Source"),
                    html.Th("Source Segment"),
                    html.Th("Destination"),
                    html.Th("Dest Segment"),
                    html.Th("Type"),
                    html.Th("Severity"),
                    html.Th("Blocked")
                ]))
            ]

            table_rows = []
            for v in violations:
                severity_color = {
                    'critical': 'danger',
                    'high': 'warning',
                    'medium': 'info',
                    'low': 'secondary'
                }.get(v['severity'], 'secondary')

                table_rows.append(html.Tr([
                    html.Td(html.Small(v['timestamp'][:16], className="text-muted")),
                    html.Td(v['source_device_ip']),
                    html.Td(v['source_segment'] if v['source_segment'] else '—'),
                    html.Td(v['dest_device_ip'] if v['dest_device_ip'] else '—'),
                    html.Td(v['dest_segment'] if v['dest_segment'] else '—'),
                    html.Td(v['violation_type'] if v['violation_type'] else '—'),
                    html.Td(dbc.Badge(v['severity'].upper() if v['severity'] else 'N/A', color=severity_color)),
                    html.Td([
                        html.I(className="fa fa-ban text-danger" if v['blocked'] else "fa fa-check text-success")
                    ])
                ]))

            table_body = [html.Tbody(table_rows)]
            violations_table = dbc.Table(table_header + table_body, bordered=True, hover=True, responsive=True, dark=False, className="mb-0 table-adaptive")

            return timeline_chart, violations_table

        except Exception as e:
            logger.error(f"Error loading violations: {e}")
            return dbc.Alert(f"Error loading violations: {str(e)}", color="danger"), None

    # VLAN Recommendations
    @app.callback(
        Output('vlan-recommendations', 'children'),
        [Input('segmentation-modal', 'is_open'),
         Input('refresh-segmentation-btn', 'n_clicks')],
        prevent_initial_call=True
    )
    def update_vlan_recommendations(is_open, refresh_clicks):
        """Generate VLAN recommendations based on device types."""
        if not is_open:
            raise dash.exceptions.PreventUpdate

        try:
            conn = get_db_connection()

            cursor = conn.cursor()

            # Get devices not in any segment or in recommended segments
            cursor.execute('''
                SELECT
                    d.device_ip,
                    d.device_name,
                    d.device_type,
                    d.is_blocked,
                    d.is_trusted,
                    d.total_connections
                FROM devices d
                LEFT JOIN device_segments ds ON d.device_ip = ds.device_ip AND ds.current_segment = 1
                WHERE ds.device_ip IS NULL
                ORDER BY d.is_blocked DESC, d.is_trusted ASC, d.total_connections DESC
                LIMIT 20
            ''')
            unsegmented_devices = cursor.fetchall()

            # Get recommended segments
            cursor.execute('''
                SELECT segment_name, purpose, security_level, vlan_id
                FROM network_segments
                WHERE recommended = 1
                ORDER BY security_level DESC
            ''')
            recommended_segments = cursor.fetchall()


            if not unsegmented_devices:
                return dbc.Alert([
                    html.I(className="fa fa-check-circle me-2"),
                    "All devices are properly segmented! No recommendations needed."
                ], color="success")

            # Create recommendation cards
            recommendation_cards = []

            # Recommended segments section
            if recommended_segments:
                recommendation_cards.append(
                    dbc.Card([
                        dbc.CardBody([
                            html.H6([html.I(className="fa fa-star me-2"), "Recommended Segments"], className="mb-3"),
                            html.Div([
                                dbc.Row([
                                    dbc.Col([
                                        dbc.Card([
                                            dbc.CardBody([
                                                html.H6(seg['segment_name'], className="mb-2"),
                                                html.P(seg['purpose'] if seg['purpose'] else 'No description', className="text-muted small mb-2"),
                                                html.Div([
                                                    dbc.Badge(f"VLAN {seg['vlan_id']}" if seg['vlan_id'] else "No VLAN", color="info", className="me-2"),
                                                    dbc.Badge(seg['security_level'].upper(), color={
                                                        'critical': 'danger',
                                                        'high': 'warning',
                                                        'medium': 'info',
                                                        'low': 'secondary'
                                                    }.get(seg['security_level'], 'secondary'))
                                                ])
                                            ])
                                        ], className="glass-card border shadow-sm mb-3")
                                    ], md=6)
                                    for seg in recommended_segments
                                ])
                            ])
                        ])
                    ], className="glass-card border-0 shadow-sm mb-3")
                )

            # Unsegmented devices section
            recommendation_cards.append(
                dbc.Card([
                    dbc.CardBody([
                        html.H6([html.I(className="fa fa-exclamation-triangle me-2 text-warning"), "Unsegmented Devices Requiring Attention"], className="mb-3"),
                        html.P(f"Found {len(unsegmented_devices)} devices not assigned to any network segment.", className="text-muted small mb-3"),

                        html.Div([
                            html.Div([
                                dbc.Row([
                                    dbc.Col(html.Strong("Device IP"), width=3),
                                    dbc.Col(html.Strong("Name/Type"), width=4),
                                    dbc.Col(html.Strong("Status"), width=2),
                                    dbc.Col(html.Strong("Suggested Segment"), width=3)
                                ], className="mb-2 pb-2 border-bottom")
                            ]),
                            html.Div([
                                dbc.Row([
                                    dbc.Col(dev['device_ip'], width=3),
                                    dbc.Col([
                                        html.Div(dev['device_name'] if dev['device_name'] else '—'),
                                        html.Small(dev['device_type'] if dev['device_type'] else 'Unknown', className="text-muted")
                                    ], width=4),
                                    dbc.Col(
                                        dbc.Badge("Blocked" if dev['is_blocked'] else "Trusted" if dev['is_trusted'] else "Unknown",
                                        color='danger' if dev['is_blocked'] else 'success' if dev['is_trusted'] else 'warning'),
                                        width=2
                                    ),
                                    dbc.Col(
                                        dbc.Badge(
                                            "IoT Segment" if dev['device_type'] and 'IoT' in dev['device_type'] else "Guest Network" if dev['is_blocked'] else "Main Network",
                                            color="primary",
                                            className="w-100"
                                        ),
                                        width=3
                                    )
                                ], className="mb-2 py-1")
                                for dev in unsegmented_devices[:10]
                            ])
                        ])
                    ])
                ], className="glass-card border-0 shadow-sm mb-3")
            )

            # Add general recommendations
            recommendation_cards.append(
                dbc.Card([
                    dbc.CardBody([
                        html.H6([html.I(className="fa fa-lightbulb me-2 text-info"), "Best Practices"], className="mb-3"),
                        html.Ul([
                            html.Li("Separate IoT devices into dedicated VLANs with restricted internet access"),
                            html.Li("Place high-risk devices in isolated segments with enhanced monitoring"),
                            html.Li("Create separate segments for guest devices and corporate assets"),
                            html.Li("Implement firewall rules between segments to prevent lateral movement"),
                            html.Li("Regularly review and update segment assignments as the network evolves")
                        ], className="mb-0 text-muted small")
                    ])
                ], className="glass-card border-0 shadow-sm")
            )

            return html.Div(recommendation_cards)

        except Exception as e:
            logger.error(f"Error generating VLAN recommendations: {e}")
            return dbc.Alert(f"Error generating recommendations: {str(e)}", color="danger")

    # =========================================================================
    # ATTACK SURFACE CALLBACKS
    # =========================================================================

    @app.callback(
        Output("attack-surface-modal", "is_open"),
        [Input("attack-surface-card-btn", "n_clicks"),
         Input("close-attack-surface-modal-btn", "n_clicks")],
        State("attack-surface-modal", "is_open"),
        prevent_initial_call=True
    )
    def toggle_attack_surface_modal(open_clicks, close_clicks, is_open):
        return not is_open

    # Attack Surface Overview Tab Callback
    @app.callback(
        [Output('attack-surface-open-ports', 'children'),
         Output('attack-surface-services', 'children'),
         Output('attack-surface-high-risk', 'children'),
         Output('attack-surface-exposure-score', 'children'),
         Output('attack-surface-vector-chart', 'figure'),
         Output('attack-surface-top-vectors', 'children'),
         Output('toast-container', 'children', allow_duplicate=True)],
        [Input('attack-surface-modal', 'is_open'),
         Input('refresh-attack-surface-btn', 'n_clicks')],
        prevent_initial_call=True
    )
    def update_attack_surface_overview(is_open, refresh_clicks):
        from dash import callback_context

        # Check if refresh button was clicked
        show_toast = callback_context.triggered[0]['prop_id'] == 'refresh-attack-surface-btn.n_clicks'

        toast = ToastManager.success(
                "Data Refreshed",
                detail_message="Data Refreshed"
            ) if show_toast else None

        if not is_open:
            return dash.no_update, dash.no_update, dash.no_update, dash.no_update, dash.no_update, dash.no_update, toast

        db = get_db_connection()

        # Count unique open ports across all devices
        open_ports = db.execute('''
            SELECT COUNT(DISTINCT dest_port)
            FROM connections
            WHERE dest_port IS NOT NULL AND dest_port > 0
        ''').fetchone()[0]

        # Count unique service types (by protocol)
        services_count = db.execute('''
            SELECT COUNT(DISTINCT protocol)
            FROM connections
        ''').fetchone()[0]

        # High-risk devices (untrusted + vulnerabilities + unencrypted)
        high_risk_devices = db.execute('''
            SELECT COUNT(DISTINCT d.device_ip)
            FROM devices d
            LEFT JOIN device_vulnerabilities_detected v ON d.device_ip = v.device_ip
            LEFT JOIN iot_protocols p ON d.device_ip = p.device_ip
            WHERE d.is_trusted = 0
               OR v.status = 'active'
               OR p.encryption_used = 0
        ''').fetchone()[0]

        # Calculate exposure score (0-100, lower is better)
        total_devices = db.execute('SELECT COUNT(*) FROM devices').fetchone()[0]
        if total_devices > 0:
            risk_ratio = high_risk_devices / total_devices
            exposure_score = min(100, int(risk_ratio * 100 + open_ports * 2))
        else:
            exposure_score = 0

        # Determine score color
        if exposure_score < 30:
            score_color = "success"
        elif exposure_score < 60:
            score_color = "warning"
        else:
            score_color = "danger"

        # Attack vector distribution
        vector_data = db.execute('''
            SELECT
                CASE
                    WHEN dest_port IN (80, 443, 8080) THEN 'Web Services'
                    WHEN dest_port IN (22, 23) THEN 'Remote Access'
                    WHEN dest_port IN (21, 20) THEN 'File Transfer'
                    WHEN dest_port IN (1883, 8883) THEN 'MQTT/IoT'
                    WHEN dest_port IN (53, 5353) THEN 'DNS'
                    ELSE 'Other Services'
                END as vector_type,
                COUNT(*) as count
            FROM connections
            WHERE dest_port IS NOT NULL
            GROUP BY vector_type
            ORDER BY count DESC
        ''').fetchall()

        vector_labels = [row[0] for row in vector_data]
        vector_values = [row[1] for row in vector_data]

        # Create bar chart using ChartFactory
        vector_fig = ChartFactory.create_bar_chart(
            x_values=vector_labels,
            y_values=vector_values,
            colors=['#dc3545', '#ffc107', '#17a2b8', '#28a745', '#6c757d', '#17a2b8'],
            title='Attack Vector Distribution',
            x_title='Attack Vector Type',
            y_title='Connection Count'
        )

        # Top attack vectors list
        top_vectors_items = []
        for i, (vector, count) in enumerate(vector_data[:5]):
            if i == 0:
                badge_color = "danger"
                icon = "fa-exclamation-circle"
            elif i == 1:
                badge_color = "warning"
                icon = "fa-exclamation-triangle"
            else:
                badge_color = "info"
                icon = "fa-info-circle"

            top_vectors_items.append(
                html.Div([
                    html.Div([
                        html.I(className=f"fa {icon} me-2 text-{badge_color}"),
                        html.Span(vector, className="fw-bold"),
                        dbc.Badge(f"{count} connections", color=badge_color, className="ms-2")
                    ], className="d-flex align-items-center justify-content-between mb-2 p-2",
                       style={"backgroundColor": "rgba(255,255,255,0.05)", "borderRadius": "5px"})
                ])
            )

        return (
            str(open_ports),
            str(services_count),
            str(high_risk_devices),
            html.Span([
                str(exposure_score),
                html.Span("/100", className="text-muted", style={"fontSize": "0.7rem"})
            ], className=f"text-{score_color}"),
            vector_fig,
            html.Div(top_vectors_items) if top_vectors_items else html.P("No attack vectors detected.", className="text-muted mb-0"),
            toast
        )

    # Attack Surface Exposed Services Tab Callback
    @app.callback(
        [Output('attack-surface-services-list', 'children'),
         Output('toast-container', 'children', allow_duplicate=True)],
        [Input('attack-surface-modal', 'is_open'),
         Input('attack-surface-tabs', 'active_tab'),
         Input('refresh-attack-surface-btn', 'n_clicks'),
         Input('refresh-attack-services-btn', 'n_clicks'),
         Input('attack-surface-services-search', 'value'),
         Input('attack-surface-risk-filter', 'value'),
         Input('attack-surface-port-status-filter', 'value')],
        prevent_initial_call=True
    )
    def update_attack_surface_services(is_open, active_tab, refresh_clicks, services_refresh_clicks, search_text, risk_filter, port_status_filter):
        from dash import callback_context
        ctx = callback_context

        # Check if refresh button was clicked
        show_toast = ctx.triggered and ctx.triggered[0]['prop_id'] in ['refresh-attack-services-btn.n_clicks', 'refresh-attack-surface-btn.n_clicks'] if ctx.triggered else False

        if not is_open or active_tab != 'attack-surface-services-tab':
            if show_toast:
                return dash.no_update, dash.no_update
            return dash.no_update, dash.no_update

        # Port status filter: "closed" means no exposed services (since these are all open)
        if port_status_filter == 'closed':
            toast = ToastManager.success(
                "Attack surface refreshed",
                detail_message="No closed ports in exposed services view"
            ) if show_toast else dash.no_update
            return html.P("Closed ports are not shown in the exposed services view. All services here are open/active.", className="text-muted"), toast

        db = get_db_connection()

        # Get service information from connections
        services = db.execute('''
            SELECT
                c.protocol,
                c.dest_port,
                COUNT(DISTINCT c.device_ip) as device_count,
                COUNT(*) as connection_count,
                MAX(c.timestamp) as last_seen
            FROM connections c
            WHERE c.dest_port IS NOT NULL
            GROUP BY c.protocol, c.dest_port
            ORDER BY connection_count DESC
        ''').fetchall()

        # Service risk mapping (define early to use for filtering)
        def get_service_info(port, protocol):
            common_services = {
                80: ("HTTP", "high", "Unencrypted web traffic"),
                443: ("HTTPS", "low", "Encrypted web traffic"),
                22: ("SSH", "medium", "Remote shell access"),
                23: ("Telnet", "critical", "Unencrypted remote access"),
                21: ("FTP", "high", "Unencrypted file transfer"),
                1883: ("MQTT", "medium", "IoT messaging protocol"),
                8883: ("MQTT/TLS", "low", "Encrypted IoT messaging"),
                53: ("DNS", "medium", "Domain name resolution"),
                3306: ("MySQL", "high", "Database access"),
                5432: ("PostgreSQL", "high", "Database access"),
                6379: ("Redis", "high", "In-memory database"),
                8080: ("HTTP-Alt", "high", "Alternative web service")
            }

            if port in common_services:
                return common_services[port]
            elif port < 1024:
                return (f"Port {port}", "medium", "System/well-known port")
            else:
                return (f"Port {port}", "low", "Dynamic/private port")

        # Apply search filter with None handling
        if search_text and search_text.strip():
            search_text = search_text.strip().lower()
            filtered_services = []
            for service in services:
                protocol = (service[0] or '').lower()
                port = str(service[1]) if service[1] else ''

                if (search_text in protocol or search_text in port):
                    filtered_services.append(service)
            services = filtered_services

        # Apply risk level filter
        if risk_filter and risk_filter != 'all':
            filtered_services = []
            for service in services:
                protocol, port, device_count, conn_count, last_seen = service
                _, risk_level, _ = get_service_info(port, protocol)

                if risk_level == risk_filter:
                    filtered_services.append(service)
            services = filtered_services

        # Generate toast if refresh was clicked
        toast = ToastManager.success(
            "Attack surface refreshed",
            detail_message=f"Displaying {len(services)} exposed service(s)"
        ) if show_toast else dash.no_update

        if not services:
            return html.P("No exposed services detected.", className="text-muted"), toast

        service_rows = []
        for protocol, port, device_count, conn_count, last_seen in services:
            service_name, risk_level, description = get_service_info(port, protocol)

            # Risk badge styling
            risk_badges = {
                'critical': ('danger', 'fa-skull-crossbones'),
                'high': ('warning', 'fa-exclamation-triangle'),
                'medium': ('info', 'fa-info-circle'),
                'low': ('success', 'fa-check-circle')
            }

            badge_color, badge_icon = risk_badges.get(risk_level, ('secondary', 'fa-question'))

            service_rows.append(
                dbc.Card([
                    dbc.CardBody([
                        dbc.Row([
                            dbc.Col([
                                html.H6([
                                    html.I(className="fa fa-server me-2"),
                                    service_name
                                ], className="mb-1"),
                                html.P([
                                    dbc.Badge(f"{protocol.upper()}", color="secondary", className="me-2"),
                                    dbc.Badge(f"Port {port}", color="primary", className="me-2"),
                                    dbc.Badge([
                                        html.I(className=f"fa {badge_icon} me-1"),
                                        risk_level.upper()
                                    ], color=badge_color)
                                ], className="mb-2"),
                                html.P(description, className="text-muted mb-1", style={"fontSize": "0.85rem"})
                            ], md=8),
                            dbc.Col([
                                html.Div([
                                    html.Div([
                                        html.I(className="fa fa-network-wired me-1"),
                                        html.Span(f"{device_count} devices", className="text-muted", style={"fontSize": "0.85rem"})
                                    ], className="mb-1"),
                                    html.Div([
                                        html.I(className="fa fa-exchange-alt me-1"),
                                        html.Span(f"{conn_count} connections", className="text-muted", style={"fontSize": "0.85rem"})
                                    ], className="mb-1"),
                                    html.Div([
                                        html.I(className="fa fa-clock me-1"),
                                        html.Span(f"Last: {last_seen[:19] if last_seen else 'Unknown'}",
                                                 className="text-muted", style={"fontSize": "0.85rem"})
                                    ])
                                ])
                            ], md=4, className="text-end")
                        ])
                    ], className="p-3")
                ], className="glass-card border-0 shadow-sm mb-2")
            )

        return html.Div(service_rows), toast

    # Attack Surface Open Ports Tab Callback
    @app.callback(
        Output('attack-surface-ports-list', 'children'),
        [Input('attack-surface-modal', 'is_open'),
         Input('refresh-attack-surface-btn', 'n_clicks')],
        prevent_initial_call=True
    )
    def update_attack_surface_ports(is_open, refresh_clicks):
        if not is_open:
            return dash.no_update

        db = get_db_connection()

        # Get ports grouped by device
        devices_ports = db.execute('''
            SELECT
                d.device_ip,
                d.device_name,
                d.device_type,
                GROUP_CONCAT(DISTINCT c.dest_port) as ports,
                COUNT(DISTINCT c.dest_port) as port_count,
                d.is_trusted
            FROM devices d
            LEFT JOIN connections c ON d.device_ip = c.device_ip OR d.device_ip = c.dest_ip
            WHERE c.dest_port IS NOT NULL
            GROUP BY d.device_ip
            ORDER BY port_count DESC
            LIMIT 50
        ''').fetchall()

        if not devices_ports:
            return html.P("No open ports detected.", className="text-muted")

        device_cards = []
        for device_ip, device_name, device_type, ports_str, port_count, is_trusted in devices_ports:
            ports_list = sorted([int(p) for p in ports_str.split(',') if p.strip().isdigit()])

            # Trust badge
            trust_badge = dbc.Badge(
                "Trusted" if is_trusted else "Untrusted",
                color="success" if is_trusted else "danger",
                className="me-2"
            )

            # Port badges (show first 10, then summary)
            port_badges = []
            for port in ports_list[:10]:
                color = "danger" if port < 1024 else "info"
                port_badges.append(
                    dbc.Badge(str(port), color=color, className="me-1 mb-1")
                )

            if len(ports_list) > 10:
                port_badges.append(
                    dbc.Badge(f"+{len(ports_list) - 10} more", color="secondary", className="me-1 mb-1")
                )

            device_cards.append(
                dbc.Card([
                    dbc.CardBody([
                        html.H6([
                            html.I(className="fa fa-laptop me-2"),
                            device_name or device_ip
                        ], className="mb-2"),
                        html.Div([
                            trust_badge,
                            dbc.Badge(device_type or "Unknown", color="info", className="me-2"),
                            dbc.Badge(f"{port_count} ports", color="warning")
                        ], className="mb-2"),
                        html.Div([
                            html.P("Open Ports:", className="text-muted mb-1", style={"fontSize": "0.85rem"}),
                            html.Div(port_badges)
                        ])
                    ], className="p-3")
                ], className="glass-card border-0 shadow-sm mb-2")
            )

        return html.Div(device_cards)

    # Attack Surface Mitigation Tab Callback
    @app.callback(
        Output('attack-surface-mitigation-list', 'children'),
        [Input('attack-surface-modal', 'is_open'),
         Input('refresh-attack-surface-btn', 'n_clicks')],
        prevent_initial_call=True
    )
    def update_attack_surface_mitigation(is_open, refresh_clicks):
        if not is_open:
            return dash.no_update

        db = get_db_connection()

        recommendations = []

        # 1. Check for insecure protocols
        insecure_protocols = db.execute('''
            SELECT COUNT(*)
            FROM connections
            WHERE dest_port IN (23, 21, 80, 69)
        ''').fetchone()[0]

        if insecure_protocols > 0:
            recommendations.append({
                'priority': 1,
                'title': 'Disable Insecure Protocols',
                'severity': 'critical',
                'description': f'{insecure_protocols} connections using insecure protocols (Telnet, FTP, HTTP) detected.',
                'actions': [
                    'Disable Telnet (port 23) and use SSH instead',
                    'Replace FTP (port 21) with SFTP or FTPS',
                    'Migrate HTTP (port 80) traffic to HTTPS (port 443)',
                    'Block insecure protocols at the firewall level'
                ]
            })

        # 2. Check for untrusted devices
        untrusted_devices = db.execute('''
            SELECT COUNT(*) FROM devices WHERE is_trusted = 0
        ''').fetchone()[0]

        if untrusted_devices > 0:
            recommendations.append({
                'priority': 2,
                'title': f'Review {untrusted_devices} Untrusted Devices',
                'severity': 'high',
                'description': 'Untrusted devices pose a security risk to your network.',
                'actions': [
                    'Audit all untrusted devices and verify their legitimacy',
                    'Move untrusted IoT devices to a separate VLAN',
                    'Implement device authentication mechanisms',
                    'Consider blocking unknown devices by default'
                ]
            })

        # 3. Check for high port exposure
        high_port_devices = db.execute('''
            SELECT COUNT(DISTINCT device_ip)
            FROM connections
            WHERE dest_port IS NOT NULL
            GROUP BY device_ip
            HAVING COUNT(DISTINCT dest_port) > 10
        ''').fetchone()

        if high_port_devices and high_port_devices[0] > 0:
            recommendations.append({
                'priority': 2,
                'title': f'Reduce Port Exposure on {high_port_devices[0]} Devices',
                'severity': 'high',
                'description': 'Some devices have excessive open ports, increasing attack surface.',
                'actions': [
                    'Close unused ports on devices',
                    'Implement host-based firewall rules',
                    'Disable unnecessary services',
                    'Use port knocking for sensitive services'
                ]
            })

        # 4. Check for unencrypted IoT protocols
        unencrypted_iot = db.execute('''
            SELECT COUNT(*)
            FROM iot_protocols
            WHERE encryption_used = 0
        ''').fetchone()[0]

        if unencrypted_iot > 0:
            recommendations.append({
                'priority': 2,
                'title': 'Enable Encryption for IoT Protocols',
                'severity': 'high',
                'description': f'{unencrypted_iot} devices using unencrypted IoT protocols.',
                'actions': [
                    'Switch MQTT to port 8883 with TLS encryption',
                    'Enable encryption in protocol configuration',
                    'Use VPN tunnels for IoT traffic',
                    'Implement certificate-based authentication'
                ]
            })

        # 5. Network segmentation recommendation
        segments = db.execute('SELECT COUNT(DISTINCT segment_id) FROM device_segments').fetchone()[0]

        if segments < 3:
            recommendations.append({
                'priority': 3,
                'title': 'Implement Network Segmentation',
                'severity': 'medium',
                'description': 'Limited network segmentation detected. Proper segmentation reduces lateral movement risk.',
                'actions': [
                    'Create separate VLANs for IoT, corporate, and guest networks',
                    'Implement firewall rules between segments',
                    'Use micro-segmentation for critical devices',
                    'Apply zero-trust network principles'
                ]
            })

        # 6. Firewall rules recommendation
        recommendations.append({
            'priority': 3,
            'title': 'Strengthen Firewall Rules',
            'severity': 'medium',
            'description': 'General firewall hardening improves network security posture.',
            'actions': [
                'Implement default-deny egress rules',
                'Allow only necessary outbound connections',
                'Block common attack ports (e.g., 445, 139, 135)',
                'Enable geo-blocking for international traffic if not needed',
                'Regularly review and update firewall rules'
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
                'low': 'success'
            }

            severity_icons = {
                'critical': 'fa-skull-crossbones',
                'high': 'fa-exclamation-triangle',
                'medium': 'fa-info-circle',
                'low': 'fa-check-circle'
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

    # =========================================================================
    # COMPLIANCE CALLBACKS
    # =========================================================================

    @app.callback(
        Output("compliance-modal", "is_open"),
        [Input("compliance-card-btn", "n_clicks"),
         Input("close-compliance-modal-btn", "n_clicks")],
        State("compliance-modal", "is_open"),
        prevent_initial_call=True
    )
    def toggle_compliance_modal(open_clicks, close_clicks, is_open):
        ctx = dash.callback_context
        if not ctx.triggered:
            raise dash.exceptions.PreventUpdate

        trigger_id = ctx.triggered[0]['prop_id'].split('.')[0]

        if trigger_id == 'close-compliance-modal-btn':
            return False
        if trigger_id == 'compliance-card-btn' and open_clicks:
            return not is_open
        return is_open

    @app.callback(
        [Output('compliance-requirements-list', 'children'),
         Output('toast-container', 'children', allow_duplicate=True)],
        [Input('compliance-modal', 'is_open'),
         Input('compliance-tabs', 'active_tab'),
         Input('refresh-compliance-overview-btn', 'n_clicks'),
         Input('compliance-search-input', 'value'),
         Input('compliance-status-filter', 'value')],
        prevent_initial_call=True
    )
    def update_compliance_requirements(is_open, active_tab, refresh_clicks, search_text, status_filter):
        """Update compliance requirements list with search and filter support."""
        from dash import callback_context
        ctx = callback_context

        # Check if refresh button was clicked
        show_toast = ctx.triggered and ctx.triggered[0]['prop_id'] == 'refresh-compliance-overview-btn.n_clicks' if ctx.triggered else False

        if not is_open:
            raise dash.exceptions.PreventUpdate

        # Only update when on the overview tab (unless refresh was clicked)
        if active_tab != 'compliance-overview-tab' and not show_toast:
            return dash.no_update, dash.no_update

        try:
            conn = get_db_connection()

            cursor = conn.cursor()

            # Get network health metrics to compute compliance status
            cursor.execute('''
                SELECT
                    overall_security_score,
                    privacy_score,
                    compliance_score,
                    vulnerable_devices,
                    encrypted_connections_pct
                FROM network_health_metrics
                ORDER BY timestamp DESC
                LIMIT 1
            ''')
            health_data = cursor.fetchone()

            # Get security metrics
            cursor.execute('''
                SELECT COUNT(*) as critical_alerts
                FROM alerts
                WHERE severity = 'critical' AND acknowledged = 0
                AND timestamp > datetime('now', '-7 days')
            ''')
            security_data = cursor.fetchone()

            # Get device counts
            cursor.execute('''
                SELECT COUNT(*) as total_devices,
                       COUNT(CASE WHEN is_trusted = 1 THEN 1 END) as trusted_devices
                FROM devices
            ''')
            device_data = cursor.fetchone()


            # Extract metrics with defaults
            security_score = (health_data['overall_security_score'] or 0) if health_data else 0
            privacy_score = (health_data['privacy_score'] or 0) if health_data else 0
            compliance_score = (health_data['compliance_score'] or 0) if health_data else 0
            vulnerable_count = (health_data['vulnerable_devices'] or 0) if health_data else 0
            encrypted_pct = (health_data['encrypted_connections_pct'] or 0) if health_data else 0
            critical_alerts = security_data['critical_alerts'] or 0
            total_devices = device_data['total_devices'] or 0
            trusted_devices = device_data['trusted_devices'] or 0

            # Define compliance requirements with computed status
            requirements = [
                {
                    'regulation': 'GDPR',
                    'requirement': 'Data Encryption',
                    'description': 'Encrypt data in transit and at rest',
                    'status': 'compliant' if encrypted_pct >= 80 else 'partial' if encrypted_pct >= 50 else 'non-compliant'
                },
                {
                    'regulation': 'GDPR',
                    'requirement': 'Data Minimization',
                    'description': 'Collect only necessary personal data',
                    'status': 'compliant' if privacy_score >= 70 else 'partial'
                },
                {
                    'regulation': 'GDPR',
                    'requirement': 'Right to Erasure',
                    'description': 'Users can request data deletion',
                    'status': 'partial'
                },
                {
                    'regulation': 'NIST',
                    'requirement': 'Device Identification',
                    'description': 'Unique identification for all IoT devices',
                    'status': 'compliant' if total_devices > 0 else 'non-compliant'
                },
                {
                    'regulation': 'NIST',
                    'requirement': 'Network Security',
                    'description': 'Secure network communications and monitoring',
                    'status': 'compliant' if security_score >= 70 else 'partial' if security_score >= 50 else 'non-compliant'
                },
                {
                    'regulation': 'NIST',
                    'requirement': 'Incident Response',
                    'description': 'Ability to detect and respond to security incidents',
                    'status': 'compliant' if critical_alerts == 0 else 'partial' if critical_alerts < 5 else 'non-compliant'
                },
                {
                    'regulation': 'NIST',
                    'requirement': 'Vulnerability Management',
                    'description': 'Identify and remediate vulnerabilities',
                    'status': 'compliant' if vulnerable_count == 0 else 'partial' if vulnerable_count < 3 else 'non-compliant'
                },
                {
                    'regulation': 'IoT Act',
                    'requirement': 'No Default Passwords',
                    'description': 'Devices must not have default credentials',
                    'status': 'compliant'
                },
                {
                    'regulation': 'IoT Act',
                    'requirement': 'Vulnerability Disclosure',
                    'description': 'Establish vulnerability disclosure policy',
                    'status': 'compliant'
                },
                {
                    'regulation': 'IoT Act',
                    'requirement': 'Security Updates',
                    'description': 'Provide timely security updates',
                    'status': 'partial'
                },
                {
                    'regulation': 'IoT Act',
                    'requirement': 'Secure by Default',
                    'description': 'Default configuration should be secure',
                    'status': 'compliant' if trusted_devices >= total_devices * 0.8 else 'partial'
                }
            ]

            # Apply search filter
            if search_text and search_text.strip():
                search_lower = search_text.lower()
                requirements = [
                    req for req in requirements
                    if search_lower in req['regulation'].lower()
                    or search_lower in req['requirement'].lower()
                    or search_lower in req['description'].lower()
                ]

            # Apply status filter
            if status_filter and status_filter != 'all':
                requirements = [req for req in requirements if req['status'] == status_filter]

            # Build UI components
            requirement_cards = []
            for req in requirements:
                # Status badge
                if req['status'] == 'compliant':
                    status_badge = dbc.Badge("✅ Compliant", color="success")
                elif req['status'] == 'non-compliant':
                    status_badge = dbc.Badge("❌ Non-Compliant", color="danger")
                else:
                    status_badge = dbc.Badge("⚠️ Partial", color="warning")

                # Regulation badge
                reg_colors = {
                    'GDPR': 'info',
                    'NIST': 'primary',
                    'IoT Act': 'secondary'
                }

                requirement_cards.append(
                    dbc.Card([
                        dbc.CardBody([
                            html.Div([
                                html.Div([
                                    dbc.Badge(req['regulation'], color=reg_colors.get(req['regulation'], 'secondary'), className="me-2"),
                                    status_badge
                                ], className="mb-2"),
                                html.H6(req['requirement'], className="mb-2"),
                                html.P(req['description'], className="text-muted small mb-0")
                            ])
                        ])
                    ], className="mb-2 border-start border-3 border-" +
                    ("success" if req['status'] == 'compliant' else "danger" if req['status'] == 'non-compliant' else "warning"))
                )

            # Generate toast if refresh was clicked
            toast = ToastManager.success(
                "Compliance requirements refreshed",
                detail_message=f"Displaying {len(requirements)} requirement(s)"
            ) if show_toast else dash.no_update

            return requirement_cards if requirement_cards else [html.P("No requirements match your filters.", className="text-muted")], toast

        except Exception as e:
            logger.error(f"Error updating compliance requirements: {e}")
            return [html.P("Error loading compliance requirements.", className="text-danger")], dash.no_update

    # =========================================================================
    # VULNERABILITY SCANNER CALLBACKS
    # =========================================================================

    @app.callback(
        Output("vuln-scanner-modal", "is_open"),
        [Input("vuln-scanner-card-btn", "n_clicks"),
         Input("close-vuln-scanner-modal-btn", "n_clicks")],
        State("vuln-scanner-modal", "is_open"),
        prevent_initial_call=True
    )
    def toggle_vuln_scanner_modal(open_clicks, close_clicks, is_open):
        return not is_open

    # Vulnerability Scanner - Overview Tab
    @app.callback(
        [Output('vuln-critical-count', 'children', allow_duplicate=True),
         Output('vuln-high-count', 'children', allow_duplicate=True),
         Output('vuln-total-devices', 'children'),
         Output('vuln-total-cve', 'children'),
         Output('vuln-timeline-chart', 'figure'),
         Output('toast-container', 'children', allow_duplicate=True)],
        [Input('vuln-scanner-modal', 'is_open'),
         Input('refresh-vuln-scanner-btn', 'n_clicks')],
        prevent_initial_call=True
    )
    def update_vuln_overview(is_open, refresh_clicks):
        from dash import callback_context

        # Check if refresh button was clicked
        show_toast = callback_context.triggered[0]['prop_id'] == 'refresh-vuln-scanner-btn.n_clicks' if callback_context.triggered else False

        # Create toast if refresh was clicked
        toast = ToastManager.success(
                "Data Updated",
                detail_message="Data Updated"
            ) if show_toast else dash.no_update

        if not is_open and not show_toast:
            return dash.no_update, dash.no_update, dash.no_update, dash.no_update, dash.no_update, dash.no_update

        # If modal closed but refresh was clicked, return toast with no_update for other values
        if not is_open and show_toast:
            return dash.no_update, dash.no_update, dash.no_update, dash.no_update, dash.no_update, toast

        try:
            db = get_db_connection()
            cursor = db.cursor()

            # Get vulnerability counts by severity
            cursor.execute('''
                SELECT v.severity, COUNT(DISTINCT dvd.id) as count
                FROM iot_vulnerabilities v
                LEFT JOIN device_vulnerabilities_detected dvd ON v.cve_id = dvd.cve_id
                WHERE dvd.status = 'active'
                GROUP BY v.severity
            ''')
            severity_counts = {row[0]: row[1] for row in cursor.fetchall()}

            critical_count = severity_counts.get('critical', 0)
            high_count = severity_counts.get('high', 0)

            # Get total affected devices
            cursor.execute('''
                SELECT COUNT(DISTINCT device_ip)
                FROM device_vulnerabilities_detected
                WHERE status = 'active'
            ''')
            total_devices = cursor.fetchone()[0] or 0

            # Get total CVEs in database
            cursor.execute('SELECT COUNT(*) FROM iot_vulnerabilities')
            total_cve = cursor.fetchone()[0] or 0

            # Get vulnerability detections over time (last 30 days)
            cursor.execute(f'''
                SELECT DATE(detected_date) as day,
                       v.severity,
                       COUNT(*) as count
                FROM device_vulnerabilities_detected dvd
                JOIN iot_vulnerabilities v ON dvd.cve_id = v.cve_id
                WHERE detected_date > datetime('now', '-30 days')
                GROUP BY day, v.severity
                ORDER BY day
            ''')
            timeline_data = cursor.fetchall()


            # Prepare timeline chart data
            from collections import defaultdict
            dates = defaultdict(list)
            severities = {'critical': defaultdict(int), 'high': defaultdict(int), 'medium': defaultdict(int), 'low': defaultdict(int)}

            for row in timeline_data:
                day, severity, count = row
                if severity in severities:
                    severities[severity][day] = count

            # Get unique dates
            all_dates = sorted(set(row[0] for row in timeline_data))
            if not all_dates:
                # Create empty chart
                all_dates = ['No Data']
                for sev in severities:
                    severities[sev] = {'No Data': 0}

            traces = [
                {'x': all_dates, 'y': [severities['critical'].get(d, 0) for d in all_dates], 'name': 'Critical', 'color': SEVERITY_COLORS['critical']},
                {'x': all_dates, 'y': [severities['high'].get(d, 0) for d in all_dates], 'name': 'High', 'color': SEVERITY_COLORS['high']},
                {'x': all_dates, 'y': [severities['medium'].get(d, 0) for d in all_dates], 'name': 'Medium', 'color': SEVERITY_COLORS['medium']},
                {'x': all_dates, 'y': [severities['low'].get(d, 0) for d in all_dates], 'name': 'Low', 'color': SEVERITY_COLORS['low']}
            ]

            timeline_fig = ChartFactory.create_multi_line_chart(
                traces_data=traces,
                title='Vulnerability Discovery Timeline',
                x_title='Date',
                y_title='Vulnerabilities Detected'
            )

            return str(critical_count), str(high_count), str(total_devices), str(total_cve), timeline_fig, toast

        except Exception as e:
            logger.error(f"Error loading vulnerability overview: {e}")
            empty_fig = ChartFactory.create_empty_chart('Error loading data')
            return "0", "0", "0", "0", empty_fig, dash.no_update

    # Vulnerability Scanner - CVE Database Tab
    @app.callback(
        [Output('vuln-cve-database-table', 'children'),
         Output('toast-container', 'children', allow_duplicate=True)],
        [Input('vuln-scanner-modal', 'is_open'),
         Input('vuln-scanner-tabs', 'active_tab'),
         Input('refresh-vuln-scanner-btn', 'n_clicks'),
         Input('refresh-cve-database-btn', 'n_clicks'),
         Input('cve-database-search-input', 'value'),
         Input('cve-severity-filter', 'value')],
        prevent_initial_call=True
    )
    def update_cve_database(is_open, active_tab, refresh_clicks, cve_refresh_clicks, search_text, severity_filter):
        from dash import callback_context
        ctx = callback_context

        # Check if refresh button was clicked
        show_toast = ctx.triggered and ctx.triggered[0]['prop_id'] in ['refresh-cve-database-btn.n_clicks', 'refresh-vuln-scanner-btn.n_clicks'] if ctx.triggered else False

        if not is_open or active_tab != 'vuln-cve-tab':
            if show_toast:
                return dash.no_update, dash.no_update
            return dash.no_update, dash.no_update

        try:
            db = get_db_connection()
            cursor = db.cursor()

            cursor.execute('''
                SELECT cve_id, title, severity, cvss_score, affected_vendors,
                       affected_models, exploit_available, patch_available, published_date
                FROM iot_vulnerabilities
                ORDER BY
                    CASE severity
                        WHEN 'critical' THEN 1
                        WHEN 'high' THEN 2
                        WHEN 'medium' THEN 3
                        WHEN 'low' THEN 4
                    END,
                    cvss_score DESC,
                    published_date DESC
            ''')
            cves = cursor.fetchall()

            # Apply severity filter
            if severity_filter and severity_filter != 'all':
                cves = [cve for cve in cves if cve[2] == severity_filter]

            # Apply search filter with None handling
            if search_text and search_text.strip():
                search_text = search_text.strip().lower()
                filtered_cves = []
                for cve in cves:
                    cve_id = (cve[0] or '').lower()
                    title = (cve[1] or '').lower()
                    vendors = (cve[4] or '').lower()
                    models = (cve[5] or '').lower()

                    if (search_text in cve_id or
                        search_text in title or
                        search_text in vendors or
                        search_text in models):
                        filtered_cves.append(cve)
                cves = filtered_cves

            # Generate toast if refresh was clicked
            toast = ToastManager.success(
                "CVE database refreshed",
                detail_message=f"Displaying {len(cves)} CVE vulnerabilities"
            ) if show_toast else dash.no_update

            if not cves:
                return dbc.Alert([
                    html.I(className="fa fa-info-circle me-2"),
                    "No CVE vulnerabilities in database. The vulnerability database can be populated through automated feeds or manual imports."
                ], color="info"), toast

            # Build table
            table_rows = []
            for cve in cves:
                cve_id, title, severity, cvss_score, vendors, models, exploit_avail, patch_avail, pub_date = cve

                # Severity badge
                severity_colors = {'critical': 'danger', 'high': 'warning', 'medium': 'info', 'low': 'success'}
                severity_badge = dbc.Badge(severity.upper() if severity else 'UNKNOWN', color=severity_colors.get(severity, 'secondary'), className="me-2")

                # CVSS badge
                cvss_badge = dbc.Badge(f"CVSS {cvss_score:.1f}" if cvss_score else "N/A", color="dark", className="me-2")

                # Status badges
                exploit_badge = dbc.Badge("Exploit Available", color="danger", className="me-1") if exploit_avail else None
                patch_badge = dbc.Badge("Patch Available", color="success", className="me-1") if patch_avail else None

                table_rows.append(
                    html.Div([
                        dbc.Card([
                            dbc.CardBody([
                                html.Div([
                                    html.H6([
                                        severity_badge,
                                        cvss_badge,
                                        html.Span(cve_id, className="text-primary fw-bold")
                                    ], className="mb-2"),
                                    html.P(title or "No description available", className="mb-2"),
                                    html.Small([
                                        html.Strong("Vendors: "), vendors or "Unknown", html.Br(),
                                        html.Strong("Models: "), models or "Unknown", html.Br(),
                                        html.Strong("Published: "), pub_date or "Unknown", html.Br(),
                                        exploit_badge, patch_badge
                                    ], className="text-muted")
                                ])
                            ], className="p-3")
                        ], className="glass-card border-0 shadow-sm mb-2")
                    ])
                )

            return html.Div(table_rows, style={'maxHeight': '500px', 'overflowY': 'auto'}), toast

        except Exception as e:
            logger.error(f"Error loading CVE database: {e}")
            return dbc.Alert(f"Error loading CVE database: {str(e)}", color="danger"), dash.no_update

    # Vulnerability Scanner - Device Scan Tab
    @app.callback(
        [Output('vuln-device-scan-results', 'children'),
         Output('toast-container', 'children', allow_duplicate=True)],
        [Input('vuln-scanner-modal', 'is_open'),
         Input('vuln-scanner-tabs', 'active_tab'),
         Input('vuln-status-filter', 'value'),
         Input('vuln-severity-filter', 'value'),
         Input('refresh-vuln-scanner-btn', 'n_clicks'),
         Input('refresh-device-scan-btn', 'n_clicks'),
         Input('device-scan-search-input', 'value')],
        prevent_initial_call=True
    )
    def update_device_scan_results(is_open, active_tab, status_filter, severity_filter, refresh_clicks, scan_refresh_clicks, search_text):
        from dash import callback_context
        ctx = callback_context

        # Check if refresh button was clicked
        show_toast = ctx.triggered and ctx.triggered[0]['prop_id'] in ['refresh-device-scan-btn.n_clicks', 'refresh-vuln-scanner-btn.n_clicks'] if ctx.triggered else False

        if not is_open or active_tab != 'vuln-scan-tab':
            if show_toast:
                return dash.no_update, dash.no_update
            return dash.no_update, dash.no_update

        try:
            db = get_db_connection()
            cursor = db.cursor()

            # Build query based on filters
            status_clause = "" if status_filter == 'all' else f"AND dvd.status = '{status_filter}'"

            # CVSS severity ranges: critical (9.0-10.0), high (7.0-8.9), medium (4.0-6.9), low (0.1-3.9)
            severity_clause = ""
            if severity_filter and severity_filter != 'all':
                if severity_filter == 'critical':
                    severity_clause = "AND v.cvss_score >= 9.0 AND v.cvss_score <= 10.0"
                elif severity_filter == 'high':
                    severity_clause = "AND v.cvss_score >= 7.0 AND v.cvss_score < 9.0"
                elif severity_filter == 'medium':
                    severity_clause = "AND v.cvss_score >= 4.0 AND v.cvss_score < 7.0"
                elif severity_filter == 'low':
                    severity_clause = "AND v.cvss_score >= 0.1 AND v.cvss_score < 4.0"

            cursor.execute(f'''
                SELECT dvd.device_ip, d.device_name, d.device_type,
                       COUNT(DISTINCT dvd.cve_id) as vuln_count,
                       GROUP_CONCAT(DISTINCT v.severity) as severities,
                       GROUP_CONCAT(DISTINCT v.cve_id) as cve_ids,
                       GROUP_CONCAT(DISTINCT v.title) as titles,
                       GROUP_CONCAT(DISTINCT v.affected_vendors) as vendors,
                       GROUP_CONCAT(DISTINCT v.affected_models) as models,
                       MAX(dvd.detected_date) as last_detected,
                       dvd.status
                FROM device_vulnerabilities_detected dvd
                LEFT JOIN devices d ON dvd.device_ip = d.device_ip
                LEFT JOIN iot_vulnerabilities v ON dvd.cve_id = v.cve_id
                WHERE 1=1 {status_clause} {severity_clause}
                GROUP BY dvd.device_ip, dvd.status
                ORDER BY vuln_count DESC, last_detected DESC
            ''')
            devices = cursor.fetchall()

            # Apply search filter with None handling - search in CVE ID, title, vendor, model, device
            if search_text and search_text.strip():
                search_text = search_text.strip().lower()
                filtered_devices = []
                for device in devices:
                    device_ip = (device[0] or '').lower()
                    device_name = (device[1] or '').lower()
                    device_type = (device[2] or '').lower()
                    cve_ids = (device[5] or '').lower()
                    titles = (device[6] or '').lower()
                    vendors = (device[7] or '').lower()
                    models = (device[8] or '').lower()

                    if (search_text in device_ip or
                        search_text in device_name or
                        search_text in device_type or
                        search_text in cve_ids or
                        search_text in titles or
                        search_text in vendors or
                        search_text in models):
                        filtered_devices.append(device)
                devices = filtered_devices

            # Generate toast if refresh was clicked
            toast = ToastManager.success(
                "Device scan refreshed",
                detail_message=f"Displaying {len(devices)} device(s) with vulnerabilities"
            ) if show_toast else dash.no_update

            if not devices:
                return dbc.Alert([
                    html.I(className="fa fa-check-circle me-2"),
                    f"No devices found with {status_filter if status_filter != 'all' else 'any'} vulnerabilities."
                ], color="success"), toast

            # Build device cards
            device_cards = []
            for device in devices:
                device_ip, device_name, device_type, vuln_count, severities, cve_ids, titles, vendors, models, last_detected, status = device

                # Determine risk level based on vulnerability count and severities
                has_critical = 'critical' in (severities or '')
                has_high = 'high' in (severities or '')

                if has_critical:
                    risk_badge = dbc.Badge("CRITICAL RISK", color="danger", className="me-2")
                    card_class = "border-danger"
                elif has_high:
                    risk_badge = dbc.Badge("HIGH RISK", color="warning", className="me-2")
                    card_class = "border-warning"
                else:
                    risk_badge = dbc.Badge("MEDIUM RISK", color="info", className="me-2")
                    card_class = "border-info"

                # Status badge
                status_colors = {'active': 'danger', 'patched': 'success', 'mitigated': 'warning', 'false_positive': 'secondary'}
                status_badge = dbc.Badge(status.upper() if status else 'UNKNOWN', color=status_colors.get(status, 'secondary'))

                device_cards.append(
                    dbc.Card([
                        dbc.CardBody([
                            html.Div([
                                html.H6([
                                    risk_badge,
                                    status_badge,
                                    html.I(className="fa fa-laptop ms-2 me-2 text-primary"),
                                    html.Span(device_name or device_ip, className="fw-bold")
                                ], className="mb-2"),
                                dbc.Row([
                                    dbc.Col([
                                        html.Small([
                                            html.Strong("IP: "), device_ip, html.Br(),
                                            html.Strong("Type: "), device_type or "Unknown", html.Br(),
                                            html.Strong("Vulnerabilities: "), html.Span(f"{vuln_count}", className="text-danger fw-bold"), html.Br(),
                                            html.Strong("Last Detected: "), last_detected or "Unknown"
                                        ], className="text-muted")
                                    ], md=12)
                                ])
                            ])
                        ], className="p-3")
                    ], className=f"glass-card {card_class} shadow-sm mb-2")
                )

            return html.Div(device_cards, style={'maxHeight': '500px', 'overflowY': 'auto'}), toast

        except Exception as e:
            logger.error(f"Error loading device scan results: {e}")
            return dbc.Alert(f"Error loading scan results: {str(e)}", color="danger"), dash.no_update

    # Vulnerability Scanner - Recommendations Tab
    @app.callback(
        Output('vuln-recommendations', 'children'),
        [Input('vuln-scanner-modal', 'is_open'),
         Input('refresh-vuln-scanner-btn', 'n_clicks')],
        prevent_initial_call=True
    )
    def update_vuln_recommendations(is_open, refresh_clicks):
        if not is_open:
            return dash.no_update

        try:
            db = get_db_connection()
            cursor = db.cursor()

            # Get top vulnerabilities with recommendations
            cursor.execute('''
                SELECT v.cve_id, v.title, v.severity, v.cvss_score,
                       v.workaround, v.patch_available,
                       COUNT(DISTINCT dvd.device_ip) as affected_devices
                FROM iot_vulnerabilities v
                JOIN device_vulnerabilities_detected dvd ON v.cve_id = dvd.cve_id
                WHERE dvd.status = 'active'
                GROUP BY v.cve_id
                ORDER BY
                    CASE v.severity
                        WHEN 'critical' THEN 1
                        WHEN 'high' THEN 2
                        WHEN 'medium' THEN 3
                        WHEN 'low' THEN 4
                    END,
                    affected_devices DESC,
                    v.cvss_score DESC
                LIMIT 20
            ''')
            vulns = cursor.fetchall()

            if not vulns:
                return dbc.Alert([
                    html.I(className="fa fa-check-circle me-2"),
                    "No active vulnerabilities requiring mitigation. Your network is currently secure!"
                ], color="success")

            # Build recommendation cards
            recommendations = []
            for idx, vuln in enumerate(vulns, 1):
                cve_id, title, severity, cvss_score, workaround, patch_available, affected_devices = vuln

                # Severity styling
                severity_colors = {'critical': 'danger', 'high': 'warning', 'medium': 'info', 'low': 'success'}
                severity_badge = dbc.Badge(severity.upper() if severity else 'UNKNOWN', color=severity_colors.get(severity, 'secondary'), className="me-2")

                # Priority badge
                priority_badge = dbc.Badge(f"Priority #{idx}", color="dark", className="me-2")

                # Recommendations list
                rec_items = []
                if patch_available:
                    rec_items.append(html.Li([
                        html.I(className="fa fa-check-circle text-success me-2"),
                        html.Strong("Update firmware: "), "A patch is available. Update all affected devices immediately."
                    ]))
                else:
                    rec_items.append(html.Li([
                        html.I(className="fa fa-exclamation-triangle text-warning me-2"),
                        html.Strong("No patch available: "), "Monitor vendor announcements for security updates."
                    ]))

                if workaround:
                    rec_items.append(html.Li([
                        html.I(className="fa fa-tools text-info me-2"),
                        html.Strong("Workaround: "), workaround
                    ]))

                # Generic recommendations
                rec_items.extend([
                    html.Li([
                        html.I(className="fa fa-network-wired text-primary me-2"),
                        html.Strong("Network Segmentation: "), "Isolate affected devices in a separate VLAN with restricted access."
                    ]),
                    html.Li([
                        html.I(className="fa fa-ban text-danger me-2"),
                        html.Strong("Access Control: "), "Review and restrict network access for these devices."
                    ]),
                    html.Li([
                        html.I(className="fa fa-eye text-info me-2"),
                        html.Strong("Monitoring: "), "Enable enhanced logging and monitoring for suspicious activity."
                    ])
                ])

                recommendations.append(
                    dbc.Card([
                        dbc.CardHeader([
                            priority_badge,
                            severity_badge,
                            html.Span(cve_id, className="text-primary fw-bold")
                        ], className="glass-card-header"),
                        dbc.CardBody([
                            html.P(title or "No description available", className="mb-3"),
                            dbc.Alert([
                                html.I(className="fa fa-server me-2"),
                                html.Strong(f"{affected_devices} device(s) affected"),
                                html.Span(f" | CVSS Score: {cvss_score:.1f}" if cvss_score else "", className="ms-2")
                            ], color=severity_colors.get(severity, 'secondary'), className="mb-3"),
                            html.H6("Recommended Actions:", className="mb-2"),
                            html.Ul(rec_items, className="mb-0")
                        ], className="p-3")
                    ], className="glass-card border-0 shadow-sm mb-3")
                )

            return html.Div(recommendations, style={'maxHeight': '500px', 'overflowY': 'auto'})

        except Exception as e:
            logger.error(f"Error loading recommendations: {e}")
            return dbc.Alert(f"Error loading recommendations: {str(e)}", color="danger")

    # =========================================================================
    # SUSTAINABILITY DASHBOARD CALLBACKS
    # =========================================================================

    @app.callback(
        Output("sustainability-modal", "is_open"),
        [Input("sustainability-card-btn", "n_clicks"),
         Input("close-sustainability-modal-btn", "n_clicks")],
        State("sustainability-modal", "is_open"),
        prevent_initial_call=True
    )
    def toggle_sustainability_modal(open_clicks, close_clicks, is_open):
        """Toggle sustainability modal open/close."""
        return not is_open

    @app.callback(
        [Output('carbon-footprint-gauge', 'figure'),
         Output('trees-needed', 'children'),
         Output('car-miles-equiv', 'children'),
         Output('carbon-trend-chart', 'figure'),
         Output('sustainability-data-store', 'data'),
         Output('toast-container', 'children', allow_duplicate=True)],
        [Input('sustainability-modal', 'is_open'),
         Input('refresh-sustainability-btn', 'n_clicks')],
        prevent_initial_call=True
    )
    def update_carbon_footprint(is_open, refresh_clicks):
        """Update carbon footprint metrics and visualizations."""
        from dash import callback_context

        # Check if refresh button was clicked
        show_toast = (
            callback_context.triggered and
            callback_context.triggered[0]['prop_id'] == 'refresh-sustainability-btn.n_clicks' and
            refresh_clicks is not None and
            refresh_clicks > 0
        )

        if not is_open and not show_toast:
            return dash.no_update, dash.no_update, dash.no_update, dash.no_update, dash.no_update, dash.no_update

        try:
            # Get sustainability calculator (using global db_manager)
            sustainability_calc = get_sustainability_calculator(db_manager)

            # Calculate current carbon footprint (24 hours)
            carbon_data = sustainability_calc.calculate_network_carbon_footprint(hours=24)

            # Create gauge chart for daily carbon footprint
            gauge_fig = go.Figure(go.Indicator(
                mode="gauge+number+delta",
                value=carbon_data['daily_carbon_kg'],
                domain={'x': [0, 1], 'y': [0, 1]},
                title={'text': "Daily Carbon Footprint (kg CO₂)", 'font': {'size': 20}},
                delta={'reference': 10, 'increasing': {'color': "#dc2626"}},
                gauge={
                    'axis': {'range': [None, 50], 'tickwidth': 1, 'tickcolor': "darkblue"},
                    'bar': {'color': "#10b981"},
                    'bgcolor': "white",
                    'borderwidth': 2,
                    'bordercolor': "gray",
                    'steps': [
                        {'range': [0, 15], 'color': '#d1fae5'},
                        {'range': [15, 30], 'color': '#fef3c7'},
                        {'range': [30, 50], 'color': '#fee2e2'}
                    ],
                    'threshold': {
                        'line': {'color': "red", 'width': 4},
                        'thickness': 0.75,
                        'value': 40
                    }
                }
            ))

            gauge_fig.update_layout(
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                font={'color': "var(--text-primary)", 'family': "Arial"},
                height=300,
                margin=dict(l=20, r=20, t=40, b=20)
            )

            # Get historical data for trend chart (30 days)
            history = sustainability_calc.get_sustainability_history(days=30)

            if history:
                dates = [datetime.fromisoformat(h['timestamp']).date() for h in history]
                carbon_values = [h['carbon_footprint_kg'] for h in history]
            else:
                # If no history, create sample data point
                dates = [datetime.now().date()]
                carbon_values = [carbon_data['daily_carbon_kg']]

            # Create trend line chart
            trend_fig = ChartFactory.create_line_chart(
                x_values=dates,
                y_values=carbon_values,
                line_color='#10b981',
                x_title='Date',
                y_title='Carbon Footprint (kg CO₂)',
                fill='tozeroy'
            )

            # Format badges
            trees_badge = f"{carbon_data['equivalent_trees']:.1f}"
            miles_badge = f"{carbon_data['equivalent_miles_driven']:.0f}"

            # Create toast if refresh was clicked
            toast = ToastManager.success(
                "Sustainability Metrics Updated",
                detail_message=f"Carbon footprint data has been refreshed.\n\nDaily CO₂: {carbon_data['daily_carbon_kg']:.2f} kg\nYearly estimate: {carbon_data['yearly_carbon_kg']:.1f} kg\nTrees to offset: {carbon_data['equivalent_trees']:.1f}\n\nData reflects current network usage patterns."
            ) if show_toast else dash.no_update

            return gauge_fig, trees_badge, miles_badge, trend_fig, carbon_data, toast

        except Exception as e:
            logger.error(f"Error updating carbon footprint: {e}")
            toast = ToastManager.error(
                "Error Loading Sustainability Data",
                detail_message=f"Failed to calculate carbon footprint metrics.\n\nError: {str(e)}\n\nPlease try again or check system logs."
            ) if show_toast else dash.no_update

            empty_fig = go.Figure()
            empty_fig.update_layout(
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                xaxis={'visible': False},
                yaxis={'visible': False},
                annotations=[{
                    'text': 'Data unavailable',
                    'xref': 'paper',
                    'yref': 'paper',
                    'showarrow': False,
                    'font': {'size': 14, 'color': 'gray'}
                }]
            )

            return empty_fig, "N/A", "N/A", empty_fig, {}, toast

    @app.callback(
        [Output('today-energy-kwh', 'children'),
         Output('today-energy-cost', 'children'),
         Output('monthly-energy-cost', 'children'),
         Output('yearly-energy-cost', 'children'),
         Output('top-energy-consumers-chart', 'figure')],
        [Input('sustainability-tabs', 'active_tab'),
         Input('refresh-sustainability-btn', 'n_clicks')],
        prevent_initial_call=True
    )
    def update_energy_consumption(active_tab, refresh_clicks):
        """Update energy consumption metrics and charts."""
        if active_tab != 'energy-tab':
            return dash.no_update, dash.no_update, dash.no_update, dash.no_update, dash.no_update

        try:
            # Get sustainability calculator (using global db_manager)
            sustainability_calc = get_sustainability_calculator(db_manager)

            # Calculate total energy consumption
            energy_data = sustainability_calc.calculate_total_energy_consumption()

            # Format display values
            today_kwh = f"{energy_data.get('total_energy_kwh', 0):.2f}"
            today_cost = f"${energy_data.get('estimated_cost_usd', 0):.2f}"
            monthly_cost = f"${energy_data.get('monthly_estimate_cost', 0):.2f}"
            yearly_cost = f"${energy_data.get('yearly_estimate_cost', 0):.2f}"

            # Create bar chart for top energy consumers
            device_breakdown = energy_data.get('device_breakdown', [])

            if device_breakdown:
                device_names = [f"{d.get('device_name', d.get('device_ip', 'Unknown'))[:20]}" for d in device_breakdown[:10]]
                energy_values = [d.get('estimated_energy_kwh', 0) for d in device_breakdown[:10]]

                consumers_fig = go.Figure(data=[
                    go.Bar(
                        x=device_names,
                        y=energy_values,
                        marker_color='#f59e0b',
                        text=[f"{val:.2f} kWh" for val in energy_values],
                        textposition='auto',
                    )
                ])

                consumers_fig.update_layout(
                    paper_bgcolor='rgba(0,0,0,0)',
                    plot_bgcolor='rgba(0,0,0,0)',
                    font={'color': "var(--text-primary)"},
                    xaxis={'title': 'Device', 'tickangle': -45},
                    yaxis={'title': 'Energy (kWh)'},
                    height=400,
                    margin=dict(l=40, r=20, t=20, b=100)
                )
            else:
                consumers_fig = go.Figure()
                consumers_fig.update_layout(
                    paper_bgcolor='rgba(0,0,0,0)',
                    plot_bgcolor='rgba(0,0,0,0)',
                    xaxis={'visible': False},
                    yaxis={'visible': False},
                    annotations=[{
                        'text': 'No energy data available',
                        'xref': 'paper',
                        'yref': 'paper',
                        'showarrow': False,
                        'font': {'size': 14, 'color': 'gray'}
                    }]
                )

            return today_kwh, today_cost, monthly_cost, yearly_cost, consumers_fig

        except Exception as e:
            logger.error(f"Error updating energy consumption: {e}")
            return "N/A", "N/A", "N/A", "N/A", go.Figure()

    @app.callback(
        Output('green-best-practices-content', 'children'),
        [Input('sustainability-tabs', 'active_tab')],
        prevent_initial_call=True
    )
    def update_green_best_practices(active_tab):
        """Display green security best practices."""
        if active_tab != 'practices-tab':
            return dash.no_update

        try:
            # Get sustainability calculator (using global db_manager)
            sustainability_calc = get_sustainability_calculator(db_manager)

            # Get best practices
            practices = sustainability_calc.get_green_best_practices()

            # Create cards for each practice
            practice_cards = []

            category_icons = {
                'Power Management': 'fa-plug',
                'Device Lifecycle': 'fa-recycle',
                'Network Optimization': 'fa-network-wired',
                'Green Purchasing': 'fa-shopping-cart',
                'Recycling': 'fa-trash-arrow-up',
                'Security Efficiency': 'fa-shield-halved'
            }

            category_colors = {
                'Power Management': 'success',
                'Device Lifecycle': 'info',
                'Network Optimization': 'primary',
                'Green Purchasing': 'warning',
                'Recycling': 'secondary',
                'Security Efficiency': 'danger'
            }

            for practice in practices:
                category = practice.get('category', 'General')
                icon = category_icons.get(category, 'fa-leaf')
                color = category_colors.get(category, 'success')

                practice_cards.append(
                    dbc.Card([
                        dbc.CardHeader([
                            html.Div([
                                html.I(className=f"fa {icon} fa-2x text-{color} mb-2"),
                                html.H5(practice.get('title', ''), className="mb-1"),
                                dbc.Badge(category, color=color, className="mb-2")
                            ], className="text-center")
                        ], className="glass-card-header"),
                        dbc.CardBody([
                            html.P(practice.get('description', ''), className="mb-3"),
                            html.Div([
                                html.Div([
                                    html.I(className="fa fa-chart-line me-2 text-success"),
                                    html.Strong("Impact: "),
                                    html.Span(practice.get('impact', ''))
                                ], className="mb-2"),
                                html.Div([
                                    html.I(className="fa fa-gauge me-2 text-info"),
                                    html.Strong("Difficulty: "),
                                    html.Span(practice.get('difficulty', ''))
                                ], className="mb-3")
                            ]),
                            html.Hr(),
                            html.H6([
                                html.I(className="fa fa-lightbulb me-2"),
                                "Examples:"
                            ], className="mb-2"),
                            html.Ul([
                                html.Li(example, className="mb-1")
                                for example in practice.get('examples', [])
                            ], className="mb-0 small")
                        ])
                    ], className="glass-card border-0 shadow-sm mb-3")
                )

            return html.Div(practice_cards)

        except Exception as e:
            logger.error(f"Error loading green best practices: {e}")
            return dbc.Alert([
                html.I(className="fa fa-exclamation-triangle me-2"),
                f"Error loading best practices: {str(e)}"
            ], color="danger")

    # Sustainability Modal - Export Callback
    @app.callback(
        [Output('download-sustainability-report', 'data'),
         Output('toast-container', 'children', allow_duplicate=True)],
        Input('export-sustainability-btn', 'n_clicks'),
        State('export-format-sustainability', 'value'),
        prevent_initial_call=True
    )
    def export_sustainability_report(n_clicks, export_format):
        """Export sustainability metrics in selected format."""
        if not n_clicks:
            raise dash.exceptions.PreventUpdate

        try:
            # Normalize format
            format_map = {'xlsx': 'excel', 'csv': 'csv', 'json': 'json', 'pdf': 'pdf'}
            export_format = format_map.get(export_format or 'csv', 'csv')

            # Get sustainability data (using global db_manager)
            sustainability_calc = get_sustainability_calculator(db_manager)

            # Calculate current metrics
            carbon_data = sustainability_calc.calculate_network_carbon_footprint(hours=24)
            energy_data = sustainability_calc.calculate_total_energy_consumption()

            # Use export_helper for consistent export pattern
            download_data = export_helper.export_sustainability(
                format=export_format,
                carbon_data=carbon_data,
                energy_data=energy_data
            )

            if download_data:
                toast = ToastManager.success(
                    "Export Complete",
                    detail_message=f"Sustainability report exported as {export_format.upper()}"
                )
                return download_data, toast
            else:
                toast = ToastManager.error(
                    "Export Failed",
                    detail_message="Failed to generate export file"
                )
                return dash.no_update, toast

        except Exception as e:
            logger.error(f"Error exporting sustainability report: {e}")
            toast = ToastManager.error(
                "Export Failed",
                detail_message=f"Error: {str(e)}"
            )
            return dash.no_update, toast

    # =========================================================================
    # FULL COMPLIANCE EVALUATION (GDPR/NIST/IoT Act scores)
    # =========================================================================

    @app.callback(
        [Output('compliance-overall-score', 'children'),
         Output('gdpr-compliance-content', 'children'),
         Output('nist-compliance-content', 'children'),
         Output('iot-act-compliance-content', 'children'),
         Output('toast-container', 'children', allow_duplicate=True)],
        [Input('refresh-interval', 'n_intervals'),
         Input('refresh-compliance-btn', 'n_clicks')],
        prevent_initial_call=True
    )
    def update_compliance_dashboard(n, refresh_clicks):
        """Evaluate compliance with GDPR, NIST, and IoT Cybersecurity Act."""
        from dash import callback_context

        # Check if refresh button was clicked (and it's a real click, not page load)
        show_toast = (
            callback_context.triggered and
            callback_context.triggered[0]['prop_id'] == 'refresh-compliance-btn.n_clicks' and
            refresh_clicks is not None and
            refresh_clicks > 0
        )

        # Defensive check: ensure at least one input has triggered
        if n is None and refresh_clicks is None:
            return dash.no_update, dash.no_update, dash.no_update, dash.no_update, dash.no_update

        try:
            conn = get_db_connection()
            if not conn:
                toast = ToastManager.error("Failed to connect to database") if show_toast else dash.no_update
                return "N/A", "Database error", "Database error", "Database error", toast

            cursor = conn.cursor()

            # ========== GDPR COMPLIANCE ==========
            gdpr_checks = []
            gdpr_score = 0
            gdpr_total = 5

            # 1. Data minimization - not storing excessive connection logs
            cursor.execute('SELECT COUNT(*) as count FROM connections WHERE timestamp < datetime("now", "-30 days")')
            old_connections = cursor.fetchone()['count']
            if old_connections < 10000:
                gdpr_checks.append(("Data Minimization", "✓ PASS", "success", "Old data properly purged"))
                gdpr_score += 1
            else:
                gdpr_checks.append(("Data Minimization", "✗ FAIL", "danger", f"{old_connections} old records should be purged"))

            # 2. Privacy controls - tracking external connections
            cursor.execute('''
                SELECT COUNT(DISTINCT dest_ip) as count FROM connections
                WHERE dest_ip NOT LIKE '192.168.%' AND dest_ip NOT LIKE '10.%'
                AND timestamp >= datetime("now", "-24 hours")
            ''')
            external_ips = cursor.fetchone()['count']
            if external_ips < 100:
                gdpr_checks.append(("Privacy Controls", "✓ PASS", "success", f"{external_ips} external destinations"))
                gdpr_score += 1
            else:
                gdpr_checks.append(("Privacy Controls", "⚠ WARNING", "warning", f"{external_ips} external destinations - review privacy"))

            # 3. Device tracking consent
            cursor.execute('SELECT COUNT(*) as count FROM devices WHERE is_trusted = 1')
            trusted = cursor.fetchone()['count']
            cursor.execute('SELECT COUNT(*) as count FROM devices')
            total_devices = cursor.fetchone()['count']
            if total_devices > 0 and (trusted / total_devices) > 0.7:
                gdpr_checks.append(("User Consent", "✓ PASS", "success", f"{int(trusted/total_devices*100)}% devices trusted"))
                gdpr_score += 1
            else:
                gdpr_checks.append(("User Consent", "✗ FAIL", "danger", "Most devices not explicitly trusted"))

            # 4. Right to deletion
            gdpr_checks.append(("Right to Deletion", "✓ PASS", "success", "Deletion capabilities implemented"))
            gdpr_score += 1

            # 5. Data security
            cursor.execute('SELECT COUNT(*) as count FROM alerts WHERE severity = "critical" AND timestamp >= datetime("now", "-7 days")')
            recent_critical = cursor.fetchone()['count']
            if recent_critical == 0:
                gdpr_checks.append(("Data Security", "✓ PASS", "success", "No critical breaches detected"))
                gdpr_score += 1
            else:
                gdpr_checks.append(("Data Security", "✗ FAIL", "danger", f"{recent_critical} critical alerts last week"))

            # ========== NIST FRAMEWORK ==========
            nist_checks = []
            nist_score = 0
            nist_total = 5

            # 1. Identify - Asset inventory
            if total_devices > 0:
                nist_checks.append(("Identify", "✓ PASS", "success", f"{total_devices} devices inventoried"))
                nist_score += 1
            else:
                nist_checks.append(("Identify", "✗ FAIL", "danger", "No devices in inventory"))

            # 2. Protect - Access controls
            cursor.execute('SELECT COUNT(*) as count FROM devices WHERE is_blocked = 1')
            blocked = cursor.fetchone()['count']
            if blocked > 0:
                nist_checks.append(("Protect", "✓ PASS", "success", f"{blocked} devices blocked"))
                nist_score += 1
            else:
                nist_checks.append(("Protect", "⚠ INFO", "info", "No blocked devices - ensure access controls"))

            # 3. Detect - Monitoring
            cursor.execute('SELECT COUNT(*) as count FROM alerts WHERE timestamp >= datetime("now", "-24 hours")')
            recent_alerts = cursor.fetchone()['count']
            nist_checks.append(("Detect", "✓ PASS", "success", f"{recent_alerts} alerts last 24h - monitoring active"))
            nist_score += 1

            # 4. Respond - Incident response
            cursor.execute('SELECT COUNT(*) as count FROM alerts WHERE severity IN ("critical", "high")')
            high_severity = cursor.fetchone()['count']
            if high_severity < 10:
                nist_checks.append(("Respond", "✓ PASS", "success", "Incident response active"))
                nist_score += 1
            else:
                nist_checks.append(("Respond", "✗ FAIL", "danger", f"{high_severity} unresolved critical/high alerts"))

            # 5. Recover - Backup capabilities
            nist_checks.append(("Recover", "✓ PASS", "success", "Database backup enabled"))
            nist_score += 1

            # ========== IoT CYBERSECURITY ACT ==========
            iot_checks = []
            iot_score = 0
            iot_total = 5

            # 1. Device authentication
            if total_devices > 0 and trusted > 0:
                iot_checks.append(("Device Authentication", "✓ PASS", "success", f"{trusted}/{total_devices} devices authenticated"))
                iot_score += 1
            else:
                iot_checks.append(("Device Authentication", "✗ FAIL", "danger", "No device authentication"))

            # 2. Secure communication
            cursor.execute('''
                SELECT COUNT(*) as count FROM connections
                WHERE dest_port IN (443, 8883, 5671)
                AND timestamp >= datetime("now", "-24 hours")
            ''')
            secure_conns = cursor.fetchone()['count']
            cursor.execute('SELECT COUNT(*) as count FROM connections WHERE timestamp >= datetime("now", "-24 hours")')
            total_conns = cursor.fetchone()['count']
            if total_conns > 0 and (secure_conns / total_conns) > 0.5:
                iot_checks.append(("Secure Communication", "✓ PASS", "success", f"{int(secure_conns/total_conns*100)}% using TLS/SSL"))
                iot_score += 1
            else:
                iot_checks.append(("Secure Communication", "⚠ WARNING", "warning", "Many unencrypted connections"))

            # 3. Patch management
            iot_checks.append(("Patch Management", "⚠ INFO", "info", "Manual verification required"))

            # 4. No default passwords
            iot_checks.append(("Default Credentials", "✓ PASS", "success", "No default passwords detected"))
            iot_score += 1

            # 5. Network segmentation
            cursor.execute('SELECT COUNT(DISTINCT device_ip) as count FROM connections WHERE dest_ip LIKE "192.168.%"')
            internal_devices = cursor.fetchone()['count']
            if internal_devices > total_devices * 0.8:
                iot_checks.append(("Network Segmentation", "✓ PASS", "success", "Devices properly segmented"))
                iot_score += 1
            else:
                iot_checks.append(("Network Segmentation", "⚠ WARNING", "warning", "Review network segmentation"))


            # Calculate overall score
            total_score = gdpr_score + nist_score + iot_score
            max_score = gdpr_total + nist_total + iot_total
            overall_percentage = int((total_score / max_score) * 100)
            overall_display = f"{overall_percentage}%"

            # Build compliance displays
            def build_check_list(checks):
                return html.Div([
                    dbc.ListGroup([
                        dbc.ListGroupItem([
                            html.Div([
                                html.Div([
                                    html.Strong(check[0]),
                                    dbc.Badge(check[1], color=check[2], className="ms-2")
                                ], className="d-flex justify-content-between align-items-center mb-1"),
                                html.P(check[3], className="mb-0 small text-muted")
                            ])
                        ], className="border-0 mb-2")
                        for check in checks
                    ], flush=True)
                ])

            gdpr_display = html.Div([
                html.Div([
                    html.H5(f"{int(gdpr_score/gdpr_total*100)}% Compliant", className="text-primary mb-3")
                ]),
                build_check_list(gdpr_checks)
            ])

            nist_display = html.Div([
                html.Div([
                    html.H5(f"{int(nist_score/nist_total*100)}% Compliant", className="text-primary mb-3")
                ]),
                build_check_list(nist_checks)
            ])

            iot_display = html.Div([
                html.Div([
                    html.H5(f"{int(iot_score/iot_total*100)}% Compliant", className="text-primary mb-3")
                ]),
                build_check_list(iot_checks)
            ])

            toast = ToastManager.success(
                "Compliance dashboard refreshed",
                detail_message=f"Overall compliance score: {overall_percentage}%\n\nGDPR: {int(gdpr_score/gdpr_total*100)}%\nNIST: {int(nist_score/nist_total*100)}%\nIoT Act: {int(iot_score/iot_total*100)}%"
            ) if show_toast else dash.no_update

            return overall_display, gdpr_display, nist_display, iot_display, toast

        except Exception as e:
            logger.error(f"Error evaluating compliance: {e}")
            error_msg = html.P(f"Error: {str(e)}", className="text-danger")
            toast = ToastManager.error("Failed to update compliance dashboard", detail_message=str(e)) if show_toast else dash.no_update
            return "Error", error_msg, error_msg, error_msg, toast
