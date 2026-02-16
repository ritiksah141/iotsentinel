"""
Analytics, Timeline, Protocol Analysis, Performance, Benchmarking,
Forensic and Trend-Analysis callbacks.

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

from flask_login import current_user

from dashboard.shared import (
    db_manager,
    chart_factory,
    export_helper,
    logger as _shared_logger,
    config,
    get_protocol_analyzer,
    get_threat_detector,
    get_intelligence,
    trend_analyzer,
    ChartFactory,
    SEVERITY_COLORS,
    get_db_connection,
    create_timestamp_display,
    ToastManager,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# register(app) — all analytics callbacks are defined inside
# ---------------------------------------------------------------------------

def register(app):
    """Register every analytics-related callback on *app*."""

    # ================================================================
    # Analytics Modal Toggle
    # ================================================================
    @app.callback(
        Output("analytics-modal", "is_open"),
        [Input("analytics-card-btn", "n_clicks"),
         Input("close-analytics-modal-btn", "n_clicks")],
        State("analytics-modal", "is_open"),
        prevent_initial_call=True
    )
    def toggle_analytics_modal(open_clicks, close_clicks, is_open):
        return not is_open

    # ================================================================
    # Analytics Modal - Timestamp Update
    # ================================================================
    @app.callback(
        [Output('analytics-timestamp-display', 'children'),
         Output('analytics-timestamp-store', 'data'),
         Output('toast-container', 'children', allow_duplicate=True)],
        [Input('analytics-modal', 'is_open'),
         Input('refresh-analytics-btn', 'n_clicks')],
        prevent_initial_call=True
    )
    def update_analytics_timestamp(is_open, refresh_clicks):
        """Update timestamp display for Analytics Modal"""
        from dash import callback_context
        ctx = callback_context

        # Check if refresh button was clicked
        show_toast = ctx.triggered and ctx.triggered[0]['prop_id'] == 'refresh-analytics-btn.n_clicks' if ctx.triggered else False

        if not is_open:
            raise dash.exceptions.PreventUpdate

        # Get current timestamp
        current_time = datetime.now()
        timestamp_str = current_time.isoformat()

        # Create timestamp display
        display = create_timestamp_display(current_time)

        # Generate toast if refresh was clicked
        toast = ToastManager.success(
            "Analytics refreshed",
            detail_message="Network analytics data updated successfully"
        ) if show_toast else dash.no_update

        return display, timestamp_str, toast

    # ================================================================
    # Timeline Visualization Modal Toggle
    # ================================================================
    @app.callback(
        Output("timeline-viz-modal", "is_open"),
        [Input("timeline-card-btn", "n_clicks"),
         Input("close-timeline-modal-btn", "n_clicks")],
        State("timeline-viz-modal", "is_open"),
        prevent_initial_call=True
    )
    def toggle_timeline_viz_modal(open_clicks, close_clicks, is_open):
        """Toggle Timeline Visualization modal."""
        return not is_open

    # ================================================================
    # Timeline Visualization Modal - Timestamp Update
    # ================================================================
    @app.callback(
        [Output('timeline-viz-timestamp-display', 'children'),
         Output('timeline-viz-timestamp-store', 'data'),
         Output('toast-container', 'children', allow_duplicate=True)],
        [Input('timeline-viz-modal', 'is_open'),
         Input('refresh-timeline-viz-btn', 'n_clicks')],
        prevent_initial_call=True
    )
    def update_timeline_viz_timestamp(is_open, refresh_clicks):
        """Update timestamp display for Timeline Visualization Modal"""
        from dash import callback_context
        ctx = callback_context

        # Check if refresh button was clicked
        show_toast = ctx.triggered and ctx.triggered[0]['prop_id'] == 'refresh-timeline-viz-btn.n_clicks' if ctx.triggered else False

        if not is_open:
            raise dash.exceptions.PreventUpdate

        # Get current timestamp
        current_time = datetime.now()
        timestamp_str = current_time.isoformat()

        # Create timestamp display
        display = create_timestamp_display(current_time)

        # Generate toast if refresh was clicked
        toast = ToastManager.success(
            "Timeline refreshed",
            detail_message="Timeline visualization data updated successfully"
        ) if show_toast else dash.no_update

        return display, timestamp_str, toast

    # ================================================================
    # Timeline Visualization Modal - Export (Universal Format Support)
    # ================================================================
    @app.callback(
        [Output('download-timeline-viz-csv', 'data'),
         Output('toast-container', 'children', allow_duplicate=True)],
        Input('export-timeline-viz-csv-btn', 'n_clicks'),
        State('export-format-timeline', 'value'),
        prevent_initial_call=True
    )
    def export_timeline_viz_csv(n_clicks, export_format):
        """Export timeline visualization data in selected format (connections from last 30 days)"""
        if not n_clicks:
            raise dash.exceptions.PreventUpdate

        try:
            # Normalize format (xlsx -> excel)
            format_map = {'xlsx': 'excel', 'csv': 'csv', 'json': 'json', 'pdf': 'pdf'}
            export_format = format_map.get(export_format or 'csv', 'csv')

            # Export connections from last 30 days (720 hours)
            download_data = export_helper.export_connections(format=export_format, hours=720)

            if download_data:
                toast = ToastManager.success(
                    "Export Complete",
                    detail_message=f"Timeline data exported as {export_format.upper()}"
                )
                return download_data, toast
            else:
                toast = ToastManager.error(
                    "Export Failed",
                    detail_message="No data available or export failed"
                )
                return dash.no_update, toast

        except Exception as e:
            logger.error(f"Error exporting timeline visualization: {e}")
            toast = ToastManager.error(
                "Export failed",
                detail_message=f"Error: {str(e)}"
            )
            return dash.no_update, toast

    # ================================================================
    # Network Activity Timeline
    # ================================================================
    @app.callback(
        [Output('activity-timeline-graph', 'figure'),
         Output('toast-container', 'children', allow_duplicate=True)],
        [Input('timeline-viz-modal', 'is_open'),
         Input('timeline-range-select', 'value'),
         Input('refresh-timeline-viz-btn', 'n_clicks')],
        prevent_initial_call=True
    )
    def update_activity_timeline(is_open, hours, refresh_clicks):
        """Update network activity timeline graph."""
        from dash import callback_context

        # Check if refresh button was clicked
        show_toast = callback_context.triggered[0]['prop_id'] == 'refresh-timeline-viz-btn.n_clicks'

        toast = ToastManager.success(
                "Timeline Refreshed",
                detail_message="Timeline Refreshed"
            ) if show_toast else None

        if not is_open:
            return {}, toast

        try:
            conn = get_db_connection()
            cursor = conn.cursor()

            # Query connections in the selected time range with anomaly data
            query = f"""
            SELECT
                strftime('%Y-%m-%d %H:%M', c.timestamp) as time,
                COUNT(*) as connection_count,
                COUNT(CASE WHEN p.is_anomaly = 1 THEN 1 END) as anomaly_count
            FROM connections c
            LEFT JOIN ml_predictions p ON c.id = p.connection_id
            WHERE c.timestamp > datetime('now', '-{hours} hours')
            GROUP BY strftime('%Y-%m-%d %H:%M', c.timestamp)
            ORDER BY time
            """
            cursor.execute(query)
            results = cursor.fetchall()

            if not results:
                return ChartFactory.create_empty_chart('No network activity recorded in this time range'), toast

            times = [row[0] for row in results]
            connections = [row[1] for row in results]
            anomalies = [row[2] for row in results]

            # Create multi-line chart using ChartFactory
            traces = [
                {'x': times, 'y': connections, 'name': 'Connections', 'color': '#00d4ff'},
                {'x': times, 'y': anomalies, 'name': 'Anomalies', 'color': '#ff4444'}
            ]
            fig = ChartFactory.create_multi_line_chart(
                traces_data=traces,
                title=f'Network Activity - Last {hours} Hours',
                x_title='Time',
                y_title='Count'
            )

            return fig, toast

        except Exception as e:
            logger.error(f"Error loading activity timeline: {e}")
            return ChartFactory.create_empty_chart('Error loading data'), toast

    # ================================================================
    # Device Activity Breakdown
    # ================================================================
    @app.callback(
        Output('device-activity-timeline', 'figure'),
        [Input('timeline-viz-modal', 'is_open'),
         Input('refresh-timeline-viz-btn', 'n_clicks')],
        prevent_initial_call=True
    )
    def update_device_activity_timeline(is_open, refresh_clicks):
        """Update device activity breakdown timeline."""
        if not is_open:
            return {}

        try:
            conn = get_db_connection()
            cursor = conn.cursor()

            # Get top 10 most active devices
            query = """
            SELECT
                device_ip,
                COUNT(*) as activity_count
            FROM connections
            WHERE timestamp > datetime('now', '-24 hours')
            GROUP BY device_ip
            ORDER BY activity_count DESC
            LIMIT 10
            """
            cursor.execute(query)
            device_results = cursor.fetchall()

            if not device_results:
                return ChartFactory.create_empty_chart('No device activity data')

            # Get hourly activity for each top device
            traces = []
            colors = ['#00d4ff', '#00ff88', '#ffaa00', '#ff4444', '#aa00ff',
                      '#ff00aa', '#00ffff', '#ffff00', '#ff8800', '#8800ff']

            for idx, (device_ip, _) in enumerate(device_results):
                query = f"""
                SELECT
                    strftime('%Y-%m-%d %H:00', timestamp) as hour,
                    COUNT(*) as count
                FROM connections
                WHERE device_ip = ? AND timestamp > datetime('now', '-24 hours')
                GROUP BY hour
                ORDER BY hour
                """
                cursor.execute(query, (device_ip,))
                hourly_data = cursor.fetchall()

                if hourly_data:
                    hours = [row[0] for row in hourly_data]
                    counts = [row[1] for row in hourly_data]

                    traces.append({
                        'x': hours,
                        'y': counts,
                        'name': device_ip,
                        'color': colors[idx % len(colors)]
                    })


            # Create multi-line chart using ChartFactory
            fig = ChartFactory.create_multi_line_chart(
                traces_data=traces,
                title='Device Activity - Last 24 Hours (Top 10)',
                x_title='Time',
                y_title='Connections'
            )

            return fig

        except Exception as e:
            logger.error(f"Error loading device activity timeline: {e}")
            return ChartFactory.create_empty_chart('Error loading data')

    # ================================================================
    # Protocol Usage Over Time
    # ================================================================
    @app.callback(
        Output('connection-patterns-timeline', 'children'),
        [Input('timeline-viz-modal', 'is_open'),
         Input('refresh-timeline-viz-btn', 'n_clicks')],
        prevent_initial_call=True
    )
    def update_connection_patterns_timeline(is_open, refresh_clicks):
        """Update connection patterns timeline."""
        if not is_open:
            return []

        try:
            conn = get_db_connection()
            cursor = conn.cursor()

            # Get protocol distribution over time
            query = """
            SELECT
                strftime('%Y-%m-%d %H:00', timestamp) as hour,
                protocol,
                COUNT(*) as count
            FROM connections
            WHERE timestamp > datetime('now', '-24 hours')
            GROUP BY hour, protocol
            ORDER BY hour, count DESC
            """
            cursor.execute(query)
            results = cursor.fetchall()

            if not results:
                return dbc.Alert("No connection pattern data available in the last 24 hours", color="info", className="m-3")

            # Organize data by protocol
            from collections import defaultdict
            protocol_data = defaultdict(lambda: {'hours': [], 'counts': []})

            for hour, protocol, count in results:
                protocol_data[protocol]['hours'].append(hour)
                protocol_data[protocol]['counts'].append(count)

            # Create traces for each protocol
            protocol_colors = {
                'TCP': '#00d4ff',
                'UDP': '#00ff88',
                'ICMP': '#ffaa00',
                'HTTP': '#ff4444',
                'HTTPS': '#aa00ff',
                'DNS': '#ff00aa',
                'SSH': '#00ffff',
                'FTP': '#ffff00'
            }

            traces = []
            for protocol, data in protocol_data.items():
                color = protocol_colors.get(protocol, '#888888')
                traces.append({
                    'x': data['hours'],
                    'y': data['counts'],
                    'name': protocol,
                    'color': color
                })

            fig = ChartFactory.create_multi_line_chart(
                traces_data=traces,
                title='Protocol Usage Over Time - Last 24 Hours',
                x_title='Time',
                y_title='Connections'
            )

            return dcc.Graph(figure=fig, config={'displayModeBar': True, 'displaylogo': False})

        except Exception as e:
            logger.error(f"Error loading connection patterns: {e}")
            return dbc.Alert(f"Error loading connection patterns: {str(e)}", color="danger", className="m-3")

    # ================================================================
    # Anomaly Detection Timeline
    # ================================================================
    @app.callback(
        Output('anomaly-timeline-section', 'children'),
        [Input('timeline-viz-modal', 'is_open'),
         Input('refresh-timeline-viz-btn', 'n_clicks')],
        prevent_initial_call=True
    )
    def update_anomaly_timeline(is_open, refresh_clicks):
        """Update anomaly detection timeline."""
        if not is_open:
            return []

        try:
            conn = get_db_connection()
            cursor = conn.cursor()

            # Get anomalies over time with severity (JOIN with ml_predictions)
            query = """
            SELECT
                strftime('%Y-%m-%d %H:00', c.timestamp) as hour,
                COUNT(*) as total_anomalies,
                SUM(CASE WHEN p.anomaly_score > 0.8 THEN 1 ELSE 0 END) as high_severity,
                SUM(CASE WHEN p.anomaly_score > 0.5 AND p.anomaly_score <= 0.8 THEN 1 ELSE 0 END) as medium_severity,
                SUM(CASE WHEN p.anomaly_score <= 0.5 THEN 1 ELSE 0 END) as low_severity
            FROM connections c
            INNER JOIN ml_predictions p ON c.id = p.connection_id
            WHERE p.is_anomaly = 1 AND c.timestamp > datetime('now', '-7 days')
            GROUP BY hour
            ORDER BY hour
            """
            cursor.execute(query)
            results = cursor.fetchall()

            if not results:
                return dbc.Alert([
                    html.I(className="fa fa-check-circle me-2"),
                    "No anomalies detected in the last 7 days"
                ], color="success", className="m-3")

            hours = [row[0] for row in results]
            high = [row[2] or 0 for row in results]
            medium = [row[3] or 0 for row in results]
            low = [row[4] or 0 for row in results]

            # Get top anomaly sources
            query_sources = """
            SELECT
                c.device_ip,
                COUNT(*) as anomaly_count,
                AVG(p.anomaly_score) as avg_score
            FROM connections c
            INNER JOIN ml_predictions p ON c.id = p.connection_id
            WHERE p.is_anomaly = 1 AND c.timestamp > datetime('now', '-7 days')
            GROUP BY c.device_ip
            ORDER BY anomaly_count DESC
            LIMIT 5
            """
            cursor.execute(query_sources)
            top_sources = cursor.fetchall()

            # Create stacked bar chart for severity levels
            fig = ChartFactory.create_stacked_bar_chart(
                x_values=hours,
                y_data_list=[high, medium, low],
                labels=['High', 'Medium', 'Low'],
                colors=['#ff4444', '#ffaa00', '#ffdd00'],
                title='Anomaly Severity Timeline - Last 7 Days',
                x_title='Time',
                y_title='Anomaly Count'
            )

            # Top anomaly sources table
            sources_table = dbc.Table([
                html.Thead([
                    html.Tr([
                        html.Th("Source IP"),
                        html.Th("Anomaly Count"),
                        html.Th("Avg Score")
                    ])
                ]),
                html.Tbody([
                    html.Tr([
                        html.Td(ip, className="font-monospace"),
                        html.Td(html.Span(count, className="badge bg-danger" if count > 10 else "badge bg-warning")),
                        html.Td(f"{score:.2f}")
                    ]) for ip, count, score in top_sources
                ])
            ], bordered=True, dark=False, hover=True, className="mt-3 table-adaptive")

            return html.Div([
                dcc.Graph(figure=fig, config={'displayModeBar': True, 'displaylogo': False}),
                html.H6([html.I(className="fa fa-exclamation-circle me-2 text-danger"), "Top Anomaly Sources"], className="mt-4 mb-3"),
                sources_table
            ])

        except Exception as e:
            logger.error(f"Error loading anomaly timeline: {e}")
            return dbc.Alert(f"Error loading anomaly data: {str(e)}", color="danger", className="m-3")

    # ================================================================
    # Protocol Modal Toggle
    # ================================================================
    @app.callback(
        Output("protocol-modal", "is_open"),
        [Input("protocol-card-btn", "n_clicks"),
         Input("close-protocol-modal-btn", "n_clicks")],
        State("protocol-modal", "is_open"),
        prevent_initial_call=True
    )
    def toggle_protocol_modal(open_clicks, close_clicks, is_open):
        return not is_open

    # ================================================================
    # Protocol Modal - Timestamp Update
    # ================================================================
    @app.callback(
        [Output('protocol-timestamp-display', 'children'),
         Output('protocol-timestamp-store', 'data'),
         Output('toast-container', 'children', allow_duplicate=True)],
        [Input('protocol-modal', 'is_open'),
         Input('refresh-protocol-btn', 'n_clicks')],
        prevent_initial_call=True
    )
    def update_protocol_timestamp(is_open, refresh_clicks):
        """Update timestamp display for Protocol Modal"""
        from dash import callback_context
        ctx = callback_context

        # Check if refresh button was clicked
        show_toast = ctx.triggered and ctx.triggered[0]['prop_id'] == 'refresh-protocol-btn.n_clicks' if ctx.triggered else False

        if not is_open:
            raise dash.exceptions.PreventUpdate

        # Get current timestamp
        current_time = datetime.now()
        timestamp_str = current_time.isoformat()

        # Create timestamp display
        display = create_timestamp_display(current_time)

        # Generate toast if refresh was clicked
        toast = ToastManager.success(
            "Protocol analysis refreshed",
            detail_message="IoT protocol data updated successfully"
        ) if show_toast else dash.no_update

        return display, timestamp_str, toast

    # ================================================================
    # Protocol Modal - Export (Universal Format Support)
    # ================================================================
    @app.callback(
        [Output('download-protocol-csv', 'data'),
         Output('toast-container', 'children', allow_duplicate=True)],
        Input('export-protocol-csv-btn', 'n_clicks'),
        State('export-format-protocol', 'value'),
        prevent_initial_call=True
    )
    def export_protocol_csv(n_clicks, export_format):
        """Export protocol analysis data in selected format (connections)"""
        if not n_clicks:
            raise dash.exceptions.PreventUpdate

        try:
            # Normalize format (xlsx -> excel)
            format_map = {'xlsx': 'excel', 'csv': 'csv', 'json': 'json', 'pdf': 'pdf'}
            export_format = format_map.get(export_format or 'csv', 'csv')

            # Export connections data (protocol analysis uses connections)
            download_data = export_helper.export_connections(format=export_format, hours=168)

            if download_data:
                toast = ToastManager.success(
                    "Export Complete",
                    detail_message=f"Protocol data exported as {export_format.upper()}"
                )
                return download_data, toast
            else:
                toast = ToastManager.error(
                    "Export Failed",
                    detail_message="No data available or export failed"
                )
                return dash.no_update, toast

        except Exception as e:
            logger.error(f"Error exporting protocol analysis: {e}")
            toast = ToastManager.error(
                "Export Failed",
                detail_message=f"Error: {str(e)}"
            )
            return dash.no_update, toast

    # ================================================================
    # Protocol Analysis - MQTT/CoAP/Zigbee Overview
    # ================================================================
    @app.callback(
        [Output('protocol-mqtt-count', 'children'),
         Output('protocol-coap-count', 'children'),
         Output('protocol-zigbee-count', 'children'),
         Output('protocol-devices-count', 'children'),
         Output('protocol-distribution-chart', 'figure'),
         Output('protocol-timeline-chart', 'figure')],
        [Input('protocol-modal', 'is_open'),
         Input('refresh-protocol-btn', 'n_clicks')],
        prevent_initial_call=True
    )
    def update_protocol_overview(is_open, refresh_clicks):
        if not is_open:
            return dash.no_update, dash.no_update, dash.no_update, dash.no_update, dash.no_update, dash.no_update

        try:
            db = get_db_connection()
            cursor = db.cursor()

            # Get MQTT message count
            cursor.execute('SELECT COUNT(*) FROM mqtt_traffic')
            mqtt_count = cursor.fetchone()[0] or 0

            # Get CoAP request count
            cursor.execute('SELECT COUNT(*) FROM coap_traffic')
            coap_count = cursor.fetchone()[0] or 0

            # Get Zigbee packet count
            cursor.execute('SELECT COUNT(*) FROM zigbee_traffic')
            zigbee_count = cursor.fetchone()[0] or 0

            # Get active devices using IoT protocols
            cursor.execute('SELECT COUNT(DISTINCT device_ip) FROM iot_protocols')
            devices_count = cursor.fetchone()[0] or 0

            # Get protocol distribution
            cursor.execute('''
                SELECT protocol, SUM(total_messages) as total
                FROM iot_protocols
                GROUP BY protocol
                ORDER BY total DESC
            ''')
            protocol_dist = cursor.fetchall()

            # Get protocol activity timeline (last 7 days)
            cursor.execute(f'''
                SELECT DATE(timestamp) as day, COUNT(*) as count
                FROM mqtt_traffic
                WHERE timestamp > datetime('now', '-7 days')
                GROUP BY day
                ORDER BY day
            ''')
            mqtt_timeline = {row[0]: row[1] for row in cursor.fetchall()}

            cursor.execute(f'''
                SELECT DATE(timestamp) as day, COUNT(*) as count
                FROM coap_traffic
                WHERE timestamp > datetime('now', '-7 days')
                GROUP BY day
                ORDER BY day
            ''')
            coap_timeline = {row[0]: row[1] for row in cursor.fetchall()}

            cursor.execute(f'''
                SELECT DATE(timestamp) as day, COUNT(*) as count
                FROM zigbee_traffic
                WHERE timestamp > datetime('now', '-7 days')
                GROUP BY day
                ORDER BY day
            ''')
            zigbee_timeline = {row[0]: row[1] for row in cursor.fetchall()}


            # Prepare distribution pie chart using ChartFactory
            if protocol_dist:
                dist_fig = ChartFactory.create_pie_chart(
                    labels=[p[0].upper() for p in protocol_dist],
                    values=[p[1] for p in protocol_dist],
                    colors=['#28a745', '#17a2b8', '#ffc107', '#dc3545'],
                )
            else:
                dist_fig = ChartFactory.create_empty_chart('No protocol data available')

            # Prepare timeline chart
            all_dates = sorted(set(list(mqtt_timeline.keys()) + list(coap_timeline.keys()) + list(zigbee_timeline.keys())))
            if not all_dates:
                all_dates = ['No Data']
                mqtt_timeline = {'No Data': 0}
                coap_timeline = {'No Data': 0}
                zigbee_timeline = {'No Data': 0}

            # Prepare timeline chart using ChartFactory
            traces = [
                {'x': all_dates, 'y': [mqtt_timeline.get(d, 0) for d in all_dates], 'name': 'MQTT', 'color': '#28a745'},
                {'x': all_dates, 'y': [coap_timeline.get(d, 0) for d in all_dates], 'name': 'CoAP', 'color': '#17a2b8'},
                {'x': all_dates, 'y': [zigbee_timeline.get(d, 0) for d in all_dates], 'name': 'Zigbee', 'color': '#ffc107'}
            ]
            timeline_fig = ChartFactory.create_multi_line_chart(
                traces_data=traces,
                x_title='Date',
                y_title='Message Count'
            )

            return str(mqtt_count), str(coap_count), str(zigbee_count), str(devices_count), dist_fig, timeline_fig

        except Exception as e:
            logger.error(f"Error loading protocol overview: {e}")
            empty_fig = ChartFactory.create_empty_chart('Error loading data')
            return "0", "0", "0", "0", empty_fig, empty_fig

    # ================================================================
    # Protocol Analysis - MQTT Tab
    # ================================================================
    @app.callback(
        Output('protocol-mqtt-traffic', 'children'),
        [Input('protocol-modal', 'is_open'),
         Input('protocol-mqtt-time-range', 'value'),
         Input('refresh-protocol-btn', 'n_clicks')],
        prevent_initial_call=True
    )
    def update_mqtt_traffic(is_open, hours, refresh_clicks):
        if not is_open:
            return dash.no_update

        try:
            db = get_db_connection()
            cursor = db.cursor()

            cursor.execute(f'''
                SELECT timestamp, device_ip, broker_ip, broker_port, client_id,
                       topic, message_type, qos, payload_size, is_encrypted
                FROM mqtt_traffic
                WHERE timestamp > datetime('now', '-{hours} hours')
                ORDER BY timestamp DESC
                LIMIT 100
            ''')
            mqtt_messages = cursor.fetchall()

            if not mqtt_messages:
                return dbc.Alert([
                    html.I(className="fa fa-info-circle me-2"),
                    "No MQTT traffic detected in the selected time range."
                ], color="info")

            # Build message cards
            message_cards = []
            for msg in mqtt_messages:
                timestamp, device_ip, broker_ip, broker_port, client_id, topic, msg_type, qos, payload_size, is_encrypted = msg

                # Security badge
                security_badge = dbc.Badge("Encrypted", color="success", className="me-2") if is_encrypted else dbc.Badge("Unencrypted", color="danger", className="me-2")

                # QoS badge
                qos_colors = {0: 'secondary', 1: 'info', 2: 'warning'}
                qos_badge = dbc.Badge(f"QoS {qos}" if qos is not None else "QoS N/A", color=qos_colors.get(qos, 'secondary'), className="me-2")

                message_cards.append(
                    dbc.Card([
                        dbc.CardBody([
                            html.Div([
                                html.H6([
                                    security_badge,
                                    qos_badge,
                                    html.I(className="fa fa-comment-dots me-2 text-success"),
                                    html.Span(topic or "Unknown Topic", className="fw-bold text-primary")
                                ], className="mb-2"),
                                dbc.Row([
                                    dbc.Col([
                                        html.Small([
                                            html.Strong("Device: "), device_ip, html.Br(),
                                            html.Strong("Broker: "), f"{broker_ip}:{broker_port}" if broker_ip else "Unknown", html.Br(),
                                            html.Strong("Client ID: "), client_id or "N/A", html.Br(),
                                            html.Strong("Type: "), msg_type or "Unknown", html.Br(),
                                            html.Strong("Payload: "), f"{payload_size} bytes" if payload_size else "N/A", html.Br(),
                                            html.Strong("Time: "), timestamp
                                        ], className="text-muted")
                                    ], md=12)
                                ])
                            ])
                        ], className="p-3")
                    ], className="glass-card border-0 shadow-sm mb-2")
                )

            return html.Div(message_cards, style={'maxHeight': '500px', 'overflowY': 'auto'})

        except Exception as e:
            logger.error(f"Error loading MQTT traffic: {e}")
            return dbc.Alert(f"Error loading MQTT traffic: {str(e)}", color="danger")

    # ================================================================
    # Protocol Analysis - CoAP Tab
    # ================================================================
    @app.callback(
        Output('protocol-coap-traffic', 'children'),
        [Input('protocol-modal', 'is_open'),
         Input('protocol-coap-time-range', 'value'),
         Input('refresh-protocol-btn', 'n_clicks')],
        prevent_initial_call=True
    )
    def update_coap_traffic(is_open, hours, refresh_clicks):
        if not is_open:
            return dash.no_update

        try:
            db = get_db_connection()
            cursor = db.cursor()

            cursor.execute(f'''
                SELECT timestamp, device_ip, dest_ip, dest_port, method,
                       uri_path, message_type, payload_size, response_code, is_dtls
                FROM coap_traffic
                WHERE timestamp > datetime('now', '-{hours} hours')
                ORDER BY timestamp DESC
                LIMIT 100
            ''')
            coap_requests = cursor.fetchall()

            if not coap_requests:
                return dbc.Alert([
                    html.I(className="fa fa-info-circle me-2"),
                    "No CoAP traffic detected in the selected time range."
                ], color="info")

            # Build request cards
            request_cards = []
            for req in coap_requests:
                timestamp, device_ip, dest_ip, dest_port, method, uri_path, msg_type, payload_size, response_code, is_dtls = req

                # Security badge
                security_badge = dbc.Badge("DTLS", color="success", className="me-2") if is_dtls else dbc.Badge("No DTLS", color="danger", className="me-2")

                # Method badge
                method_colors = {'GET': 'info', 'POST': 'success', 'PUT': 'warning', 'DELETE': 'danger'}
                method_badge = dbc.Badge(method or "UNKNOWN", color=method_colors.get(method, 'secondary'), className="me-2")

                # Response code badge
                if response_code:
                    if response_code < 300:
                        resp_badge = dbc.Badge(f"Code {response_code}", color="success", className="me-2")
                    elif response_code < 400:
                        resp_badge = dbc.Badge(f"Code {response_code}", color="warning", className="me-2")
                    else:
                        resp_badge = dbc.Badge(f"Code {response_code}", color="danger", className="me-2")
                else:
                    resp_badge = None

                request_cards.append(
                    dbc.Card([
                        dbc.CardBody([
                            html.Div([
                                html.H6([
                                    security_badge,
                                    method_badge,
                                    resp_badge,
                                    html.I(className="fa fa-exchange-alt me-2 text-info"),
                                    html.Span(uri_path or "/", className="fw-bold text-primary")
                                ], className="mb-2"),
                                dbc.Row([
                                    dbc.Col([
                                        html.Small([
                                            html.Strong("Device: "), device_ip, html.Br(),
                                            html.Strong("Destination: "), f"{dest_ip}:{dest_port}" if dest_ip else "Unknown", html.Br(),
                                            html.Strong("Message Type: "), msg_type or "Unknown", html.Br(),
                                            html.Strong("Payload: "), f"{payload_size} bytes" if payload_size else "N/A", html.Br(),
                                            html.Strong("Time: "), timestamp
                                        ], className="text-muted")
                                    ], md=12)
                                ])
                            ])
                        ], className="p-3")
                    ], className="glass-card border-0 shadow-sm mb-2")
                )

            return html.Div(request_cards, style={'maxHeight': '500px', 'overflowY': 'auto'})

        except Exception as e:
            logger.error(f"Error loading CoAP traffic: {e}")
            return dbc.Alert(f"Error loading CoAP traffic: {str(e)}", color="danger")

    # ================================================================
    # Protocol Analysis - Device Summary Tab
    # ================================================================
    @app.callback(
        Output('protocol-device-summary', 'children'),
        [Input('protocol-modal', 'is_open'),
         Input('refresh-protocol-btn', 'n_clicks')],
        prevent_initial_call=True
    )
    def update_protocol_device_summary(is_open, refresh_clicks):
        if not is_open:
            return dash.no_update

        try:
            db = get_db_connection()
            cursor = db.cursor()

            cursor.execute('''
                SELECT ip.device_ip, d.device_name, d.device_type,
                       ip.protocol, ip.total_messages, ip.total_bytes,
                       ip.encryption_used, ip.authentication_used, ip.last_seen
                FROM iot_protocols ip
                LEFT JOIN devices d ON ip.device_ip = d.device_ip
                ORDER BY ip.total_messages DESC, ip.device_ip, ip.protocol
                LIMIT 100
            ''')
            device_protocols = cursor.fetchall()

            if not device_protocols:
                return dbc.Alert([
                    html.I(className="fa fa-info-circle me-2"),
                    "No IoT protocol usage data available. Devices using MQTT, CoAP, or Zigbee will appear here."
                ], color="info")

            # Group by device
            from collections import defaultdict
            devices = defaultdict(list)
            for row in device_protocols:
                device_ip = row[0]
                devices[device_ip].append(row)

            # Build device summary cards
            device_cards = []
            for device_ip, protocols in devices.items():
                device_name = protocols[0][1] or device_ip
                device_type = protocols[0][2] or "Unknown"

                # Protocol badges
                protocol_badges = []
                total_messages = 0
                total_bytes = 0
                has_encryption = False
                has_auth = False

                for proto in protocols:
                    protocol, msgs, bytes_val, enc, auth, last_seen = proto[3], proto[4], proto[5], proto[6], proto[7], proto[8]
                    protocol_colors = {'mqtt': 'success', 'coap': 'info', 'zigbee': 'warning'}
                    protocol_badges.append(
                        dbc.Badge(protocol.upper() if protocol else "UNKNOWN", color=protocol_colors.get(protocol, 'secondary'), className="me-1")
                    )
                    total_messages += msgs or 0
                    total_bytes += bytes_val or 0
                    has_encryption = has_encryption or enc
                    has_auth = has_auth or auth

                # Security badges
                enc_badge = dbc.Badge("Encrypted", color="success", className="me-1") if has_encryption else dbc.Badge("Unencrypted", color="danger", className="me-1")
                auth_badge = dbc.Badge("Authenticated", color="success", className="me-1") if has_auth else None

                device_cards.append(
                    dbc.Card([
                        dbc.CardBody([
                            html.Div([
                                html.H6([
                                    html.I(className="fa fa-laptop me-2 text-primary"),
                                    html.Span(device_name, className="fw-bold")
                                ], className="mb-2"),
                                html.Div([
                                    html.Strong("Protocols: "),
                                    *protocol_badges
                                ], className="mb-2"),
                                html.Div([
                                    html.Strong("Security: "),
                                    enc_badge,
                                    auth_badge
                                ], className="mb-2"),
                                dbc.Row([
                                    dbc.Col([
                                        html.Small([
                                            html.Strong("IP: "), device_ip, html.Br(),
                                            html.Strong("Type: "), device_type, html.Br(),
                                            html.Strong("Total Messages: "), f"{total_messages:,}", html.Br(),
                                            html.Strong("Total Bytes: "), f"{total_bytes:,}" if total_bytes else "N/A", html.Br(),
                                            html.Strong("Last Seen: "), protocols[0][8] or "Unknown"
                                        ], className="text-muted")
                                    ], md=12)
                                ])
                            ])
                        ], className="p-3")
                    ], className="glass-card border-0 shadow-sm mb-2")
                )

            return html.Div(device_cards, style={'maxHeight': '500px', 'overflowY': 'auto'})

        except Exception as e:
            logger.error(f"Error loading protocol device summary: {e}")
            return dbc.Alert(f"Error loading device summary: {str(e)}", color="danger")

    # ================================================================
    # Forensic Timeline Modal Toggle
    # ================================================================
    @app.callback(
        Output("forensic-timeline-modal", "is_open"),
        [Input("forensic-timeline-card-btn", "n_clicks"),
         Input("close-forensic-modal-btn", "n_clicks")],
        State("forensic-timeline-modal", "is_open"),
        prevent_initial_call=True
    )
    def toggle_forensic_timeline_modal(open_clicks, close_clicks, is_open):
        """Toggle Forensic Timeline modal."""
        return not is_open

    # ================================================================
    # Device Dropdown for Forensics
    # ================================================================
    @app.callback(
        Output('forensic-device-select', 'options'),
        Input('forensic-timeline-modal', 'is_open'),
        prevent_initial_call=True
    )
    def populate_forensic_device_select(is_open):
        """Populate device dropdown with devices from database."""
        if not is_open:
            return []

        try:
            conn = get_db_connection()
            cursor = conn.cursor()

            cursor.execute("""
                SELECT DISTINCT device_ip, device_name
                FROM devices
                ORDER BY last_seen DESC
                LIMIT 50
            """)
            devices = cursor.fetchall()

            options = [
                {"label": f"{row[0]} - {row[1] or 'Unknown'}", "value": row[0]}
                for row in devices
            ]

            return options if options else [{"label": "No devices found", "value": ""}]

        except Exception as e:
            logger.error(f"Error loading devices for forensic analysis: {e}")
            return [{"label": "Error loading devices", "value": ""}]

    # ================================================================
    # Forensic Timeline Stats + Chart
    # ================================================================
    @app.callback(
        [Output('forensic-total-events', 'children'),
         Output('forensic-critical-count', 'children'),
         Output('forensic-suspicious-count', 'children'),
         Output('forensic-timespan', 'children'),
         Output('forensic-timeline-graph', 'figure'),
         Output('toast-container', 'children', allow_duplicate=True)],
        [Input('forensic-device-select', 'value'),
         Input('forensic-time-range', 'value'),
         Input('refresh-forensic-btn', 'n_clicks')],
        prevent_initial_call=True
    )
    def update_forensic_timeline(device_ip, hours, refresh_clicks):
        """Update forensic timeline based on selected device."""
        from dash import callback_context

        # Check if refresh button was clicked
        show_toast = callback_context.triggered[0]['prop_id'] == 'refresh-forensic-btn.n_clicks'

        toast = ToastManager.success(
                "Forensic Data Refreshed",
                detail_message="Forensic Data Refreshed"
            ) if show_toast else None

        if not device_ip:
            empty_fig = ChartFactory.create_empty_chart('Select a device to analyze')
            return "0", "0", "0", "N/A", empty_fig, toast

        try:
            conn = get_db_connection()
            cursor = conn.cursor()

            # Get stats for the device
            query_stats = f"""
            SELECT
                COUNT(*) as total_events,
                COUNT(CASE WHEN a.severity = 'critical' THEN 1 END) as critical_count,
                COUNT(CASE WHEN p.is_anomaly = 1 THEN 1 END) as suspicious_count,
                MIN(c.timestamp) as first_event,
                MAX(c.timestamp) as last_event
            FROM connections c
            LEFT JOIN ml_predictions p ON c.id = p.connection_id
            LEFT JOIN alerts a ON c.device_ip = a.device_ip AND
                                 datetime(c.timestamp, '-5 minutes') <= a.timestamp AND
                                 a.timestamp <= datetime(c.timestamp, '+5 minutes')
            WHERE c.device_ip = ? AND c.timestamp > datetime('now', '-{hours} hours')
            """

            cursor.execute(query_stats, (device_ip,))
            stats = cursor.fetchone()

            total_events = stats[0] or 0
            critical_count = stats[1] or 0
            suspicious_count = stats[2] or 0
            first_event = stats[3]
            last_event = stats[4]

            # Calculate timespan
            if first_event and last_event:
                from datetime import datetime as dt
                first_dt = dt.strptime(first_event, '%Y-%m-%d %H:%M:%S')
                last_dt = dt.strptime(last_event, '%Y-%m-%d %H:%M:%S')
                diff = last_dt - first_dt
                hours_span = diff.total_seconds() / 3600
                timespan = f"{hours_span:.1f}h"
            else:
                timespan = "N/A"

            # Get timeline data
            query_timeline = f"""
            SELECT
                strftime('%Y-%m-%d %H:00', c.timestamp) as hour,
                COUNT(*) as total_connections,
                COUNT(CASE WHEN p.is_anomaly = 1 THEN 1 END) as anomalies,
                COUNT(CASE WHEN a.severity = 'critical' THEN 1 END) as critical_alerts
            FROM connections c
            LEFT JOIN ml_predictions p ON c.id = p.connection_id
            LEFT JOIN alerts a ON c.device_ip = a.device_ip AND
                                 datetime(c.timestamp, '-5 minutes') <= a.timestamp AND
                                 a.timestamp <= datetime(c.timestamp, '+5 minutes')
            WHERE c.device_ip = ? AND c.timestamp > datetime('now', '-{hours} hours')
            GROUP BY hour
            ORDER BY hour
            """

            cursor.execute(query_timeline, (device_ip,))
            timeline_data = cursor.fetchall()

            if not timeline_data:
                empty_fig = ChartFactory.create_empty_chart(f'No events found for {device_ip}')
                return str(total_events), str(critical_count), str(suspicious_count), timespan, empty_fig, toast

            hours_list = [row[0] for row in timeline_data]
            connections = [row[1] for row in timeline_data]
            anomalies = [row[2] for row in timeline_data]
            critical = [row[3] for row in timeline_data]

            traces = [
                {'x': hours_list, 'y': connections, 'name': 'Total Connections', 'color': '#00d4ff'},
                {'x': hours_list, 'y': anomalies, 'name': 'Anomalies', 'color': '#ffaa00'},
                {'x': hours_list, 'y': critical, 'name': 'Critical Alerts', 'color': '#ff4444'}
            ]

            fig = ChartFactory.create_multi_line_chart(
                traces_data=traces,
                title=f'Forensic Timeline - {device_ip}',
                x_title='Time',
                y_title='Count'
            )

            return str(total_events), str(critical_count), str(suspicious_count), timespan, fig, toast

        except Exception as e:
            logger.error(f"Error loading forensic timeline: {e}")
            empty_fig = ChartFactory.create_empty_chart(f'Error loading timeline: {str(e)}')
            return "Error", "Error", "Error", "Error", empty_fig, toast

    # ================================================================
    # Connection / Anomalous Patterns
    # ================================================================
    @app.callback(
        Output('forensic-attack-patterns', 'children'),
        [Input('forensic-device-select', 'value'),
         Input('forensic-time-range', 'value')],
        prevent_initial_call=True
    )
    def update_forensic_attack_patterns(device_ip, hours):
        """Analyze and display attack patterns for the selected device."""
        if not device_ip:
            return dbc.Alert("Select a device to analyze attack patterns", color="info", className="m-3")

        try:
            conn = get_db_connection()
            cursor = conn.cursor()

            # Get common attack patterns (port scanning, brute force indicators, etc.)
            query = f"""
            SELECT
                dest_port,
                protocol,
                COUNT(*) as connection_count,
                COUNT(DISTINCT dest_ip) as unique_destinations,
                AVG(duration) as avg_duration
            FROM connections
            WHERE device_ip = ? AND timestamp > datetime('now', '-{hours} hours')
            GROUP BY dest_port, protocol
            HAVING connection_count > 5
            ORDER BY connection_count DESC
            LIMIT 20
            """

            cursor.execute(query, (device_ip,))
            patterns = cursor.fetchall()

            # Get anomaly patterns
            query_anomalies = f"""
            SELECT
                c.protocol,
                c.dest_port,
                COUNT(*) as anomaly_count,
                AVG(p.anomaly_score) as avg_score,
                GROUP_CONCAT(DISTINCT c.dest_ip) as destinations
            FROM connections c
            INNER JOIN ml_predictions p ON c.id = p.connection_id
            WHERE c.device_ip = ? AND p.is_anomaly = 1 AND c.timestamp > datetime('now', '-{hours} hours')
            GROUP BY c.protocol, c.dest_port
            ORDER BY anomaly_count DESC
            LIMIT 10
            """

            cursor.execute(query_anomalies, (device_ip,))
            anomaly_patterns = cursor.fetchall()

            if not patterns and not anomaly_patterns:
                return dbc.Alert("No attack patterns detected for this device", color="success", className="m-3")

            # Create pattern cards
            pattern_cards = []

            if patterns:
                pattern_table = dbc.Table([
                    html.Thead([
                        html.Tr([
                            html.Th("Port"),
                            html.Th("Protocol"),
                            html.Th("Connections"),
                            html.Th("Unique Dests"),
                            html.Th("Avg Duration")
                        ])
                    ]),
                    html.Tbody([
                        html.Tr([
                            html.Td(str(row[0]), className="font-monospace"),
                            html.Td(str(row[1]).upper()),
                            html.Td(html.Span(str(row[2]), className="badge bg-info" if row[2] < 50 else "badge bg-warning")),
                            html.Td(str(row[3])),
                            html.Td(f"{row[4]:.2f}s" if row[4] else "N/A")
                        ]) for row in patterns
                    ])
                ], bordered=True, dark=False, hover=True, size="sm", className="table-adaptive")

                pattern_cards.append(html.Div([
                    html.H6([html.I(className="fa fa-search me-2 text-info"), "Connection Patterns"], className="mb-3"),
                    pattern_table
                ], className="mb-4"))

            if anomaly_patterns:
                anomaly_table = dbc.Table([
                    html.Thead([
                        html.Tr([
                            html.Th("Protocol"),
                            html.Th("Port"),
                            html.Th("Anomaly Count"),
                            html.Th("Avg Score"),
                            html.Th("Destinations")
                        ])
                    ]),
                    html.Tbody([
                        html.Tr([
                            html.Td(str(row[0]).upper()),
                            html.Td(str(row[1]), className="font-monospace"),
                            html.Td(html.Span(str(row[2]), className="badge bg-danger")),
                            html.Td(f"{row[3]:.2f}"),
                            html.Td(str(row[4])[:50] + "..." if len(str(row[4])) > 50 else str(row[4]), className="small")
                        ]) for row in anomaly_patterns
                    ])
                ], bordered=True, dark=False, hover=True, size="sm", className="table-adaptive")

                pattern_cards.append(html.Div([
                    html.H6([html.I(className="fa fa-exclamation-triangle me-2 text-danger"), "Anomalous Patterns"], className="mb-3 mt-4"),
                    anomaly_table
                ]))

            return html.Div(pattern_cards)

        except Exception as e:
            logger.error(f"Error loading attack patterns: {e}")
            return dbc.Alert(f"Error loading attack patterns: {str(e)}", color="danger", className="m-3")

    # ================================================================
    # Detailed Event Log w/ Filters
    # ================================================================
    @app.callback(
        [Output('forensic-event-log', 'children'),
         Output('toast-container', 'children', allow_duplicate=True)],
        [Input('forensic-device-select', 'value'),
         Input('forensic-time-range', 'value'),
         Input('forensic-timeline-tabs', 'active_tab'),
         Input('refresh-forensic-btn', 'n_clicks'),
         Input('refresh-forensic-log-btn', 'n_clicks'),
         Input('forensic-event-search-input', 'value'),
         Input('forensic-severity-filter', 'value'),
         Input('forensic-event-type-filter', 'value')],
        prevent_initial_call=True
    )
    def update_forensic_event_log(device_ip, hours, active_tab, refresh_clicks, log_refresh_clicks, search_text, severity_filter, event_type_filter):
        """Display detailed event log for forensic analysis."""
        from dash import callback_context
        ctx = callback_context

        # Check if refresh button was clicked
        show_toast = ctx.triggered and ctx.triggered[0]['prop_id'] in ['refresh-forensic-log-btn.n_clicks', 'refresh-forensic-btn.n_clicks'] if ctx.triggered else False

        # Generate toast for no device selected case
        if not device_ip:
            toast = ToastManager.warning(
                "No device selected",
                detail_message="Please select a device to view event log"
            ) if show_toast else dash.no_update
            return dbc.Alert("Select a device to view detailed event log", color="info", className="m-3"), toast

        if active_tab != 'forensic-log-tab' and not show_toast:
            return dash.no_update, dash.no_update

        try:
            conn = get_db_connection()
            cursor = conn.cursor()

            # Build query based on event type filter
            events = []

            # Include connections if event_type is 'all' or 'connection'
            if event_type_filter in ['all', 'connection']:
                conn_query = f"""
                SELECT
                    c.timestamp,
                    c.dest_ip,
                    c.dest_port,
                    c.protocol,
                    c.service,
                    c.bytes_sent,
                    c.bytes_received,
                    p.is_anomaly,
                    p.anomaly_score,
                    a.severity,
                    'connection' as event_type
                FROM connections c
                LEFT JOIN ml_predictions p ON c.id = p.connection_id
                LEFT JOIN alerts a ON c.device_ip = a.device_ip AND
                                     datetime(c.timestamp, '-5 minutes') <= a.timestamp AND
                                     a.timestamp <= datetime(c.timestamp, '+5 minutes')
                WHERE c.device_ip = ? AND c.timestamp > datetime('now', '-{hours} hours')
                """
                cursor.execute(conn_query, (device_ip,))
                events.extend(cursor.fetchall())

            # Include alerts if event_type is 'all' or 'alert'
            if event_type_filter in ['all', 'alert']:
                alert_query = f"""
                SELECT
                    a.timestamp,
                    NULL as dest_ip,
                    NULL as dest_port,
                    NULL as protocol,
                    a.explanation as service,
                    0 as bytes_sent,
                    0 as bytes_received,
                    1 as is_anomaly,
                    a.anomaly_score,
                    a.severity,
                    'alert' as event_type
                FROM alerts a
                WHERE a.device_ip = ? AND a.timestamp > datetime('now', '-{hours} hours')
                """
                cursor.execute(alert_query, (device_ip,))
                events.extend(cursor.fetchall())

            # Include exfiltration events if event_type is 'all' or 'exfiltration'
            if event_type_filter in ['all', 'exfiltration']:
                exfil_query = f"""
                SELECT
                    de.timestamp,
                    de.destination_ip as dest_ip,
                    NULL as dest_port,
                    de.protocol,
                    de.destination_domain as service,
                    de.bytes_transferred as bytes_sent,
                    0 as bytes_received,
                    1 as is_anomaly,
                    de.anomaly_score,
                    de.sensitivity_level as severity,
                    'exfiltration' as event_type
                FROM data_exfiltration_events de
                WHERE de.device_ip = ? AND de.timestamp > datetime('now', '-{hours} hours')
                """
                cursor.execute(exfil_query, (device_ip,))
                events.extend(cursor.fetchall())

            # Sort all events by timestamp descending
            events = sorted(events, key=lambda x: x[0] if x[0] else '', reverse=True)


            # Apply severity filter
            if severity_filter and severity_filter != 'all':
                events = [e for e in events if e[9] == severity_filter]

            # Apply search filter with None handling - search device IP, dest IP, protocol, service
            if search_text and search_text.strip():
                search_text = search_text.strip().lower()
                filtered_events = []
                for event in events:
                    device_ip_lower = (device_ip or '').lower()  # from function parameter
                    dest_ip = (event[1] or '').lower()
                    protocol = (event[3] or '').lower()
                    service = (event[4] or '').lower()

                    if (search_text in device_ip_lower or
                        search_text in dest_ip or
                        search_text in protocol or
                        search_text in service):
                        filtered_events.append(event)
                events = filtered_events

            # Generate toast if refresh was clicked
            toast = ToastManager.success(
                "Forensic event log refreshed",
                detail_message=f"Displaying {len(events)} event(s) for device {device_ip}"
            ) if show_toast else dash.no_update

            if not events:
                return dbc.Alert("No events found for this device in the selected time range", color="info", className="m-3"), toast

            # Helper function to get severity badge class
            def get_severity_class(severity):
                if severity == 'critical':
                    return 'badge bg-danger'
                elif severity == 'high':
                    return 'badge bg-warning'
                elif severity == 'medium':
                    return 'badge bg-info'
                else:
                    return 'badge bg-secondary'

            event_table = dbc.Table([
                html.Thead([
                    html.Tr([
                        html.Th("Timestamp"),
                        html.Th("Dest IP:Port"),
                        html.Th("Protocol"),
                        html.Th("Service"),
                        html.Th("Bytes"),
                        html.Th("Anomaly"),
                        html.Th("Alert")
                    ])
                ]),
                html.Tbody([
                    html.Tr([
                        html.Td(str(row[0])[:-3], className="small font-monospace"),
                        html.Td(f"{row[1]}:{row[2]}", className="small font-monospace"),
                        html.Td(html.Span(str(row[3]).upper(), className="badge bg-secondary")),
                        html.Td(str(row[4] or 'N/A'), className="small"),
                        html.Td(f"{(row[5] or 0) + (row[6] or 0):,}", className="small"),
                        html.Td(
                            html.Span(f"{row[8]:.2f}", className="badge bg-danger") if row[7] else html.Span("—", className="text-muted"),
                            className="small"
                        ),
                        html.Td(
                            html.Span(str(row[9]).upper(), className=get_severity_class(row[9])) if row[9] else html.Span("—", className="text-muted"),
                            className="small"
                        )
                    ], className="text-danger" if row[7] or row[9] == 'critical' else "") for row in events
                ])
            ], bordered=True, dark=False, hover=True, size="sm", className="table-adaptive", style={'fontSize': '0.85rem'})

            return html.Div([
                dbc.Alert([
                    html.I(className="fa fa-info-circle me-2"),
                    f"Showing {len(events)} event(s)"
                ], color="info", className="mb-3"),
                event_table
            ]), toast

        except Exception as e:
            logger.error(f"Error loading event log: {e}")
            return dbc.Alert(f"Error loading event log: {str(e)}", color="danger", className="m-3"), dash.no_update

    # ================================================================
    # Forensic Report Export
    # ================================================================
    @app.callback(
        [Output('toast-container', 'children', allow_duplicate=True),
         Output('download-export', 'data', allow_duplicate=True)],
        Input('forensic-export-btn', 'n_clicks'),
        [State('forensic-device-select', 'value'),
         State('forensic-time-range', 'value'),
         State('forensic-report-format', 'value'),
         State('forensic-report-sections', 'value')],
        prevent_initial_call=True
    )
    def export_forensic_report(n_clicks, device_ip, hours, report_format, sections):
        """Generate and download forensic report."""
        ctx = callback_context

        # Prevent spurious callbacks - must have actual button click
        if not ctx.triggered:
            raise dash.exceptions.PreventUpdate

        trigger_id = ctx.triggered[0]['prop_id'].split('.')[0]
        if trigger_id != 'forensic-export-btn':
            raise dash.exceptions.PreventUpdate

        if not n_clicks or n_clicks == 0:
            raise dash.exceptions.PreventUpdate

        if not device_ip or device_ip == "":
            logger.info("   ⚠️ No device selected")
            return ToastManager.warning(
                "No Device Selected",
                detail_message="Please select a device from the dropdown first before exporting the report."
            ), None

        try:
            import json
            from datetime import datetime

            conn = get_db_connection()
            cursor = conn.cursor()

            # Gather data for report
            report_data = {
                'device_ip': device_ip,
                'generated_at': datetime.now().isoformat(),
                'time_range_hours': hours
            }

            # Get device info
            cursor.execute("SELECT * FROM devices WHERE device_ip = ?", (device_ip,))
            device = cursor.fetchone()
            if device:
                report_data['device_info'] = dict(device)

            # Get events if requested
            if 'events' in sections:
                query = f"""
                SELECT c.timestamp, c.dest_ip, c.dest_port, c.protocol, c.service,
                       c.bytes_sent, c.bytes_received, p.is_anomaly, p.anomaly_score
                FROM connections c
                LEFT JOIN ml_predictions p ON c.id = p.connection_id
                WHERE c.device_ip = ? AND c.timestamp > datetime('now', '-{hours} hours')
                ORDER BY c.timestamp DESC
                LIMIT 500
                """
                cursor.execute(query, (device_ip,))
                events = cursor.fetchall()
                report_data['events'] = [dict(e) for e in events]

            # Get alerts if patterns requested
            if 'patterns' in sections:
                query_alerts = f"""
                    SELECT timestamp, severity, anomaly_score, explanation
                    FROM alerts
                    WHERE device_ip = ? AND timestamp > datetime('now', '-{hours} hours')
                    ORDER BY timestamp DESC
                    LIMIT 100
                """
                cursor.execute(query_alerts, (device_ip,))
                alerts = cursor.fetchall()
                report_data['alerts'] = [dict(a) for a in alerts]


            # Generate file content based on format
            filename = f"forensic_report_{device_ip}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

            # Normalize format (xlsx -> excel for export_helper)
            format_map = {'xlsx': 'excel', 'pdf': 'pdf', 'csv': 'csv', 'json': 'json'}
            normalized_format = format_map.get(report_format, report_format)

            if normalized_format in ['pdf', 'excel']:
                # Use universal export for PDF/Excel formats
                # Export connections for the specified device and time range
                download_data = export_helper.export_connections(
                    format=normalized_format,
                    device_ip=device_ip,
                    hours=hours
                )

                if download_data:
                    toast = ToastManager.success(
                        "Export Complete",
                        detail_message=f"Report downloaded successfully as {normalized_format.upper()}"
                    )
                    return toast, download_data
                else:
                    toast = ToastManager.error(
                        "Export Failed",
                        detail_message="Could not generate forensic report"
                    )
                    return toast, None

            elif report_format == 'json':
                # Generate JSON file
                file_content = json.dumps(report_data, indent=2, default=str)
                filename += ".json"

            elif report_format == 'csv':
                # Generate CSV file
                csv_lines = ["# Forensic Timeline Report", f"# Device: {device_ip}", f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ""]

                # Add device info
                if 'device_info' in report_data:
                    csv_lines.append("## Device Information")
                    csv_lines.append("Property,Value")
                    for key, value in report_data['device_info'].items():
                        csv_lines.append(f"{key},{value}")
                    csv_lines.append("")

                # Add events
                if 'events' in report_data and report_data['events']:
                    csv_lines.append("## Connection Events")
                    csv_lines.append("Timestamp,Destination IP,Port,Protocol,Service,Bytes Sent,Bytes Received,Is Anomaly,Anomaly Score")
                    for event in report_data['events']:
                        csv_lines.append(f"{event.get('timestamp','')},{event.get('dest_ip','')},{event.get('dest_port','')},{event.get('protocol','')},{event.get('service','')},{event.get('bytes_sent','')},{event.get('bytes_received','')},{event.get('is_anomaly','')},{event.get('anomaly_score','')}")
                    csv_lines.append("")

                # Add alerts
                if 'alerts' in report_data and report_data['alerts']:
                    csv_lines.append("## Security Alerts")
                    csv_lines.append("Timestamp,Severity,Anomaly Score,Explanation")
                    for alert in report_data['alerts']:
                        csv_lines.append(f"{alert.get('timestamp','')},{alert.get('severity','')},{alert.get('anomaly_score','')},{alert.get('explanation','')}")

                file_content = "\n".join(csv_lines)
                filename += ".csv"

            else:  # txt format as fallback (PDF requires additional libraries)
                txt_lines = [
                    "=" * 80,
                    "FORENSIC TIMELINE REPORT",
                    "=" * 80,
                    f"Device IP: {device_ip}",
                    f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                    f"Time Range: Last {hours} hours",
                    "=" * 80,
                    ""
                ]

                if 'device_info' in report_data:
                    txt_lines.append("DEVICE INFORMATION:")
                    txt_lines.append("-" * 40)
                    for key, value in report_data['device_info'].items():
                        txt_lines.append(f"{key}: {value}")
                    txt_lines.append("")

                if 'events' in report_data:
                    txt_lines.append(f"CONNECTION EVENTS: {len(report_data['events'])} total")
                    txt_lines.append("-" * 40)
                    for event in report_data['events'][:20]:  # Show first 20
                        txt_lines.append(f"[{event.get('timestamp','')}] {event.get('dest_ip','')}:{event.get('dest_port','')} - {event.get('protocol','')} {'[ANOMALY]' if event.get('is_anomaly') else ''}")
                    txt_lines.append("")

                if 'alerts' in report_data:
                    txt_lines.append(f"SECURITY ALERTS: {len(report_data['alerts'])} total")
                    txt_lines.append("-" * 40)
                    for alert in report_data['alerts']:
                        txt_lines.append(f"[{alert.get('timestamp','')}] {alert.get('severity','').upper()}: {alert.get('explanation','')}")

                file_content = "\n".join(txt_lines)
                filename += ".txt"

            # Log the report generation
            logger.info(f"Forensic report generated for {device_ip}: {len(report_data.get('events', []))} events, {len(report_data.get('alerts', []))} alerts")

            toast = ToastManager.success(
                f"{report_format.upper()} Report Downloaded",
                detail_message=f"Report downloaded successfully: {filename} ({len(report_data.get('events', []))} events, {len(report_data.get('alerts', []))} alerts)"
            )

            return toast, dict(content=file_content, filename=filename)

        except Exception as e:
            logger.error(f"Error generating forensic report: {e}")
            return ToastManager.error(
                "Export Error",
                detail_message=f"Failed to generate report: {str(e)}"
            ), None

    # ================================================================
    # Benchmark Modal Toggle
    # ================================================================
    @app.callback(
        Output("benchmark-modal", "is_open"),
        [Input("benchmark-card-btn", "n_clicks"),
         Input("close-benchmark-modal-btn", "n_clicks")],
        State("benchmark-modal", "is_open"),
        prevent_initial_call=True
    )
    def toggle_benchmark_modal(open_clicks, close_clicks, is_open):
        return not is_open

    # ================================================================
    # Benchmark Overview (Radar Chart)
    # ================================================================
    @app.callback(
        [Output('benchmark-overall-score', 'children'),
         Output('benchmark-industry-avg', 'children'),
         Output('benchmark-percentile', 'children'),
         Output('benchmark-radar-chart', 'figure'),
         Output('benchmark-timestamp-display', 'children'),
         Output('benchmark-timestamp-store', 'data'),
         Output('toast-container', 'children', allow_duplicate=True)],
        [Input('benchmark-modal', 'is_open'),
         Input('refresh-benchmark-btn', 'n_clicks')],
        prevent_initial_call=True
    )
    def update_benchmark_overview(is_open, refresh_clicks):
        from dash import callback_context

        # Check if refresh button was clicked
        show_toast = callback_context.triggered[0]['prop_id'] == 'refresh-benchmark-btn.n_clicks' if callback_context.triggered else False

        # Create toast if refresh was clicked
        toast = ToastManager.success(
                "Data Updated",
                detail_message="Data Updated"
            ) if show_toast else dash.no_update

        if not is_open and not show_toast:
            return dash.no_update, dash.no_update, dash.no_update, dash.no_update, dash.no_update, dash.no_update, dash.no_update

        # Get current timestamp
        current_time = datetime.now()
        timestamp_str = current_time.isoformat()
        timestamp_display = create_timestamp_display(current_time)

        # If modal closed but refresh was clicked, return toast with no_update for other values
        if not is_open and show_toast:
            return dash.no_update, dash.no_update, dash.no_update, dash.no_update, dash.no_update, dash.no_update, toast

        try:
            conn = get_db_connection()
            cursor = conn.cursor()

            # Calculate security metrics
            cursor.execute('SELECT COUNT(*) FROM devices')
            total_devices = cursor.fetchone()[0] or 1

            cursor.execute('SELECT COUNT(*) FROM devices WHERE is_trusted = 1')
            trusted_devices = cursor.fetchone()[0] or 0

            cursor.execute('SELECT COUNT(DISTINCT device_ip) FROM device_vulnerabilities_detected WHERE status = "active"')
            vulnerable_devices = cursor.fetchone()[0] or 0

            cursor.execute('SELECT COUNT(*) FROM devices WHERE is_blocked = 1')
            blocked_devices = cursor.fetchone()[0] or 0

            cursor.execute('SELECT COUNT(DISTINCT device_ip) FROM alerts WHERE timestamp >= datetime("now", "-24 hours")')
            devices_with_alerts = cursor.fetchone()[0] or 0

            cursor.execute('SELECT COUNT(DISTINCT device_ip) FROM iot_protocols WHERE encryption_used = 1')
            encrypted_devices = cursor.fetchone()[0] or 0


            # Calculate scores (0-100)
            trust_score = (trusted_devices / total_devices) * 100 if total_devices > 0 else 0
            vulnerability_score = max(0, 100 - (vulnerable_devices / total_devices) * 100) if total_devices > 0 else 100
            alert_score = max(0, 100 - (devices_with_alerts / total_devices) * 100) if total_devices > 0 else 100
            encryption_score = (encrypted_devices / total_devices) * 100 if total_devices > 0 else 0
            blocking_score = max(0, 100 - (blocked_devices / total_devices) * 50) if total_devices > 0 else 100

            overall_score = (trust_score + vulnerability_score + alert_score + encryption_score + blocking_score) / 5

            # Industry averages (benchmark values)
            industry_avg = 72.5
            percentile = min(100, max(0, (overall_score / industry_avg) * 50 + 25))

            # Create radar chart
            categories = ['Trust', 'Vulnerabilities', 'Alerts', 'Encryption', 'Security']
            your_scores = [trust_score, vulnerability_score, alert_score, encryption_score, blocking_score]
            industry_scores = [75, 80, 85, 70, 65]  # Industry benchmarks

            radar_fig = ChartFactory.create_radar_chart(
                categories=categories,
                your_scores=your_scores,
                industry_scores=industry_scores
            )

            return f"{overall_score:.1f}/100", f"{industry_avg:.1f}/100", f"{percentile:.0f}th", radar_fig, timestamp_display, timestamp_str, toast

        except Exception as e:
            logger.error(f"Error loading benchmark overview: {e}")
            empty_fig = ChartFactory.create_empty_chart('Error loading data')
            return "N/A", "N/A", "N/A", empty_fig, timestamp_display, timestamp_str, dash.no_update

    # ================================================================
    # Benchmark Metrics Comparison
    # ================================================================
    @app.callback(
        Output('benchmark-metrics-comparison', 'children'),
        [Input('benchmark-modal', 'is_open'),
         Input('refresh-benchmark-btn', 'n_clicks')],
        prevent_initial_call=True
    )
    def update_benchmark_metrics(is_open, refresh_clicks):
        if not is_open:
            return dash.no_update

        try:
            conn = get_db_connection()
            cursor = conn.cursor()

            # Get metrics
            metrics = []

            # Device Trust Ratio
            cursor.execute('SELECT COUNT(*) FROM devices WHERE is_trusted = 1')
            trusted = cursor.fetchone()[0] or 0
            cursor.execute('SELECT COUNT(*) FROM devices')
            total = cursor.fetchone()[0] or 1
            trust_pct = (trusted / total) * 100
            metrics.append(('Device Trust Ratio', trust_pct, 75, f"{trusted}/{total} devices trusted"))

            # Vulnerability Coverage
            cursor.execute('SELECT COUNT(DISTINCT device_ip) FROM device_vulnerabilities_detected WHERE status != "patched"')
            vuln_devices = cursor.fetchone()[0] or 0
            vuln_pct = max(0, 100 - (vuln_devices / total) * 100)
            metrics.append(('Vulnerability Management', vuln_pct, 80, f"{total - vuln_devices}/{total} devices patched"))

            # Encryption Adoption
            cursor.execute('SELECT COUNT(DISTINCT device_ip) FROM iot_protocols WHERE encryption_used = 1')
            encrypted = cursor.fetchone()[0] or 0
            enc_pct = (encrypted / total) * 100
            metrics.append(('Encryption Adoption', enc_pct, 70, f"{encrypted}/{total} devices use encryption"))

            # Alert Response Time
            cursor.execute('SELECT COUNT(*) FROM alerts WHERE acknowledged = 1')
            ack_alerts = cursor.fetchone()[0] or 0
            cursor.execute('SELECT COUNT(*) FROM alerts')
            total_alerts = cursor.fetchone()[0] or 1
            ack_pct = (ack_alerts / total_alerts) * 100
            metrics.append(('Alert Response Rate', ack_pct, 85, f"{ack_alerts}/{total_alerts} alerts acknowledged"))

            # Network Segmentation
            cursor.execute('SELECT COUNT(DISTINCT segment_id) FROM device_segments')
            segments = cursor.fetchone()[0] or 0
            seg_score = min(100, segments * 25)
            metrics.append(('Network Segmentation', seg_score, 65, f"{segments} active segments"))


            # Build comparison cards
            comparison_cards = []
            for metric_name, your_score, industry_avg, detail in metrics:
                if your_score >= industry_avg:
                    status_badge = dbc.Badge("Above Average", color="success", className="me-2")
                    progress_color = "success"
                elif your_score >= industry_avg * 0.8:
                    status_badge = dbc.Badge("At Average", color="warning", className="me-2")
                    progress_color = "warning"
                else:
                    status_badge = dbc.Badge("Below Average", color="danger", className="me-2")
                    progress_color = "danger"

                comparison_cards.append(
                    dbc.Card([
                        dbc.CardBody([
                            html.H6([
                                status_badge,
                                metric_name
                            ], className="mb-3"),
                            dbc.Row([
                                dbc.Col([
                                    html.P("Your Network", className="small text-muted mb-1"),
                                    dbc.Progress(value=your_score, max=100, color=progress_color, className="mb-2", style={"height": "20px"}, label=f"{your_score:.1f}%")
                                ], md=6),
                                dbc.Col([
                                    html.P("Industry Average", className="small text-muted mb-1"),
                                    dbc.Progress(value=industry_avg, max=100, color="secondary", className="mb-2", style={"height": "20px"}, label=f"{industry_avg}%")
                                ], md=6)
                            ]),
                            html.Small(detail, className="text-muted")
                        ], className="p-3")
                    ], className="glass-card border-0 shadow-sm mb-3")
                )

            return html.Div(comparison_cards, style={'maxHeight': '500px', 'overflowY': 'auto'})

        except Exception as e:
            logger.error(f"Error loading benchmark metrics: {e}")
            return dbc.Alert(f"Error loading metrics: {str(e)}", color="danger")

    # ================================================================
    # Best Practices Checklist
    # ================================================================
    @app.callback(
        Output('benchmark-best-practices', 'children'),
        [Input('benchmark-modal', 'is_open'),
         Input('refresh-benchmark-btn', 'n_clicks')],
        prevent_initial_call=True
    )
    def update_benchmark_best_practices(is_open, refresh_clicks):
        if not is_open:
            return dash.no_update

        try:
            conn = get_db_connection()
            cursor = conn.cursor()

            # Check best practices
            practices = []

            # 1. Device Trust Management
            cursor.execute('SELECT COUNT(*) FROM devices WHERE is_trusted = 1')
            trusted = cursor.fetchone()[0] or 0
            cursor.execute('SELECT COUNT(*) FROM devices')
            total = cursor.fetchone()[0] or 1
            practices.append(('Device Trust Management', trusted > total * 0.7, f"{trusted}/{total} devices trusted", "Maintain trusted device whitelist"))

            # 2. Vulnerability Patching
            cursor.execute('SELECT COUNT(DISTINCT device_ip) FROM device_vulnerabilities_detected WHERE status = "active"')
            active_vulns = cursor.fetchone()[0] or 0
            practices.append(('Vulnerability Patching', active_vulns < total * 0.1, f"{active_vulns} active vulnerabilities", "Patch vulnerabilities within 30 days"))

            # 3. Network Segmentation
            cursor.execute('SELECT COUNT(DISTINCT segment_id) FROM device_segments')
            segments = cursor.fetchone()[0] or 0
            practices.append(('Network Segmentation', segments >= 3, f"{segments} network segments configured", "Separate IoT devices from corporate network"))

            # 4. Encryption Usage
            cursor.execute('SELECT COUNT(DISTINCT device_ip) FROM iot_protocols WHERE encryption_used = 1')
            encrypted = cursor.fetchone()[0] or 0
            practices.append(('Encryption Enforcement', encrypted > total * 0.6, f"{encrypted}/{total} devices use encryption", "Enforce TLS/DTLS for IoT protocols"))

            # 5. Alert Monitoring
            cursor.execute('SELECT COUNT(*) FROM alerts WHERE acknowledged = 1')
            ack_alerts = cursor.fetchone()[0] or 0
            cursor.execute('SELECT COUNT(*) FROM alerts')
            total_alerts = cursor.fetchone()[0] or 1
            practices.append(('Alert Monitoring', ack_alerts > total_alerts * 0.8, f"{ack_alerts}/{total_alerts} alerts acknowledged", "Review and acknowledge all security alerts"))

            # 6. Automated Response
            cursor.execute('SELECT COUNT(*) FROM alert_rules WHERE is_enabled = 1')
            active_rules = cursor.fetchone()[0] or 0
            practices.append(('Automated Response Rules', active_rules >= 4, f"{active_rules} active response rules", "Enable automated blocking for critical threats"))

            # 7. Regular Auditing
            cursor.execute('SELECT COUNT(*) FROM devices WHERE last_seen >= datetime("now", "-7 days")')
            active_devices = cursor.fetchone()[0] or 0
            practices.append(('Device Inventory Auditing', active_devices == total, f"{active_devices}/{total} devices seen recently", "Audit device inventory weekly"))

            # 8. Firmware Updates
            cursor.execute('SELECT COUNT(*) FROM device_firmware_status WHERE update_available = 1')
            updates_needed = cursor.fetchone()[0] or 0
            practices.append(('Firmware Update Management', updates_needed < total * 0.2, f"{updates_needed} devices need updates", "Keep firmware up to date"))


            # Build checklist
            checklist_items = []
            completed_count = sum(1 for _, status, _, _ in practices if status)

            for practice_name, status, detail, description in practices:
                if status:
                    icon = html.I(className="fa fa-check-circle text-success fa-2x me-3")
                    badge = dbc.Badge("Compliant", color="success")
                    card_class = "border-success"
                else:
                    icon = html.I(className="fa fa-times-circle text-danger fa-2x me-3")
                    badge = dbc.Badge("Non-Compliant", color="danger")
                    card_class = "border-danger"

                checklist_items.append(
                    dbc.Card([
                        dbc.CardBody([
                            dbc.Row([
                                dbc.Col([
                                    icon
                                ], width="auto"),
                                dbc.Col([
                                    html.H6([badge, " ", practice_name], className="mb-2"),
                                    html.P(description, className="mb-1 small"),
                                    html.Small([html.Strong("Status: "), detail], className="text-muted")
                                ])
                            ])
                        ], className="p-3")
                    ], className=f"glass-card {card_class} shadow-sm mb-2")
                )

            summary = dbc.Alert([
                html.H5([html.I(className="fa fa-clipboard-check me-2"), f"Compliance Score: {completed_count}/{len(practices)}"], className="alert-heading"),
                html.Hr(),
                html.P(f"You are following {completed_count} out of {len(practices)} security best practices.", className="mb-0")
            ], color="success" if completed_count >= len(practices) * 0.7 else "warning")

            return html.Div([summary, html.Div(checklist_items, style={'maxHeight': '400px', 'overflowY': 'auto'})])

        except Exception as e:
            logger.error(f"Error loading best practices: {e}")
            return dbc.Alert(f"Error loading best practices: {str(e)}", color="danger")

    # ================================================================
    # Benchmark Recommendations
    # ================================================================
    @app.callback(
        Output('benchmark-recommendations', 'children'),
        [Input('benchmark-modal', 'is_open'),
         Input('refresh-benchmark-btn', 'n_clicks')],
        prevent_initial_call=True
    )
    def update_benchmark_recommendations(is_open, refresh_clicks):
        if not is_open:
            return dash.no_update

        try:
            conn = get_db_connection()
            cursor = conn.cursor()

            recommendations = []

            # Check for untrusted devices
            cursor.execute('SELECT COUNT(*) FROM devices WHERE is_trusted = 0')
            untrusted = cursor.fetchone()[0] or 0
            if untrusted > 0:
                recommendations.append({
                    'priority': 1,
                    'title': f'Review {untrusted} Untrusted Devices',
                    'severity': 'high',
                    'description': 'Untrusted devices pose security risks to your network.',
                    'actions': [
                        'Identify and verify all unknown devices',
                        'Mark legitimate devices as trusted',
                        'Block or quarantine suspicious devices',
                        'Enable automatic device discovery alerts'
                    ]
                })

            # Check for active vulnerabilities
            cursor.execute('SELECT COUNT(DISTINCT device_ip) FROM device_vulnerabilities_detected WHERE status = "active"')
            vuln_devices = cursor.fetchone()[0] or 0
            if vuln_devices > 0:
                recommendations.append({
                    'priority': 1,
                    'title': f'Patch Vulnerabilities on {vuln_devices} Devices',
                    'severity': 'critical',
                    'description': 'Active CVE vulnerabilities detected on network devices.',
                    'actions': [
                        'Review CVE details in Vulnerability Scanner',
                        'Apply firmware updates where available',
                        'Implement workarounds for unpatched vulnerabilities',
                        'Isolate vulnerable devices until patched'
                    ]
                })

            # Check network segmentation
            cursor.execute('SELECT COUNT(DISTINCT segment_id) FROM device_segments')
            segments = cursor.fetchone()[0] or 0
            if segments < 3:
                recommendations.append({
                    'priority': 2,
                    'title': 'Implement Network Segmentation',
                    'severity': 'medium',
                    'description': 'Network segmentation limits the blast radius of security incidents.',
                    'actions': [
                        'Create separate VLANs for IoT, corporate, and guest traffic',
                        'Configure firewall rules between segments',
                        'Implement zero-trust network access policies',
                        'Use the Network Segmentation tool for recommendations'
                    ]
                })

            # Check encryption
            cursor.execute('SELECT COUNT(DISTINCT device_ip) FROM iot_protocols WHERE encryption_used = 0')
            unencrypted = cursor.fetchone()[0] or 0
            if unencrypted > 0:
                recommendations.append({
                    'priority': 2,
                    'title': f'Enable Encryption for {unencrypted} Devices',
                    'severity': 'medium',
                    'description': 'Unencrypted IoT protocols expose data to interception.',
                    'actions': [
                        'Enable TLS for MQTT connections',
                        'Enable DTLS for CoAP connections',
                        'Configure device certificates',
                        'Monitor Protocol Analysis for unencrypted traffic'
                    ]
                })

            # Check alert response
            cursor.execute('SELECT COUNT(*) FROM alerts WHERE acknowledged = 0 AND timestamp >= datetime("now", "-7 days")')
            unack_alerts = cursor.fetchone()[0] or 0
            if unack_alerts > 10:
                recommendations.append({
                    'priority': 3,
                    'title': f'Review {unack_alerts} Unacknowledged Alerts',
                    'severity': 'low',
                    'description': 'Unacknowledged alerts may indicate missed security events.',
                    'actions': [
                        'Review all pending alerts in the dashboard',
                        'Acknowledge or dismiss false positives',
                        'Tune alert rules to reduce noise',
                        'Enable automated response for common threats'
                    ]
                })


            if not recommendations:
                return dbc.Alert([
                    html.I(className="fa fa-check-circle me-2"),
                    "Excellent! Your network security posture meets all best practice recommendations."
                ], color="success")

            # Build recommendation cards
            rec_cards = []
            severity_colors = {'critical': 'danger', 'high': 'warning', 'medium': 'info', 'low': 'secondary'}

            for rec in sorted(recommendations, key=lambda x: x['priority']):
                priority_badge = dbc.Badge(f"Priority #{rec['priority']}", color="dark", className="me-2")
                severity_badge = dbc.Badge(rec['severity'].upper(), color=severity_colors[rec['severity']], className="me-2")

                action_items = [html.Li(action) for action in rec['actions']]

                rec_cards.append(
                    dbc.Card([
                        dbc.CardHeader([
                            priority_badge,
                            severity_badge,
                            html.I(className="fa fa-lightbulb me-2"),
                            rec['title']
                        ], className="glass-card-header"),
                        dbc.CardBody([
                            html.P(rec['description'], className="mb-3"),
                            html.H6("Recommended Actions:", className="mb-2"),
                            html.Ul(action_items, className="mb-0")
                        ], className="p-3")
                    ], className="glass-card border-0 shadow-sm mb-3")
                )

            return html.Div(rec_cards, style={'maxHeight': '500px', 'overflowY': 'auto'})

        except Exception as e:
            logger.error(f"Error loading recommendations: {e}")
            return dbc.Alert(f"Error loading recommendations: {str(e)}", color="danger")

    # ================================================================
    # Performance Modal Toggle
    # ================================================================
    @app.callback(
        Output("performance-modal", "is_open"),
        [Input("performance-card-btn", "n_clicks"),
         Input("close-performance-modal-btn", "n_clicks")],
        State("performance-modal", "is_open"),
        prevent_initial_call=True
    )
    def toggle_performance_modal(open_clicks, close_clicks, is_open):
        return not is_open

    # ================================================================
    # Performance Overview (Latency / Throughput)
    # ================================================================
    @app.callback(
        [Output('perf-avg-latency', 'children', allow_duplicate=True),
         Output('perf-throughput', 'children', allow_duplicate=True),
         Output('perf-packet-loss', 'children', allow_duplicate=True),
         Output('perf-active-connections', 'children'),
         Output('performance-graph', 'figure', allow_duplicate=True),
         Output('toast-container', 'children', allow_duplicate=True)],
        [Input('performance-modal', 'is_open'),
         Input('refresh-performance-btn', 'n_clicks'),
         Input('refresh-interval', 'n_intervals')],
        prevent_initial_call=True
    )
    def update_performance_overview(is_open, refresh_clicks, n):
        from dash import callback_context

        # Check if refresh button was clicked (and it's a real click, not page load)
        show_toast = (
            callback_context.triggered and
            callback_context.triggered[0]['prop_id'] == 'refresh-performance-btn.n_clicks' and
            refresh_clicks is not None and
            refresh_clicks > 0
        )

        # If modal is not open and refresh wasn't explicitly clicked, don't update
        if not is_open and not show_toast:
            return dash.no_update, dash.no_update, dash.no_update, dash.no_update, dash.no_update, dash.no_update

        db = get_db_connection()

        # Get real network metrics (latency and packet loss)
        from utils.network_monitor import get_network_metrics

        # Auto-detect and ping your actual gateway
        try:
            network_metrics = get_network_metrics()  # Auto-detects gateway
            avg_latency = network_metrics['avg_latency']
            packet_loss = network_metrics['packet_loss']
        except Exception as e:
            logger.warning(f"Failed to get network metrics: {e}, using fallback")
            avg_latency = "N/A"
            packet_loss = "N/A"

        # Calculate throughput (connections per second over last hour)
        throughput_data = db.execute('''
            SELECT COUNT(*) as conn_count
            FROM connections
            WHERE timestamp > datetime('now', '-1 hour')
        ''').fetchone()

        conn_per_hour = throughput_data[0] if throughput_data else 0
        conn_per_sec = conn_per_hour / 3600
        throughput = f"{conn_per_sec:.1f}/s"

        # Active connections (recent connections in last 5 minutes)
        active_conn = db.execute('''
            SELECT COUNT(DISTINCT device_ip)
            FROM connections
            WHERE timestamp > datetime('now', '-5 minutes')
        ''').fetchone()[0]

        # Connection activity over time (last 24 hours, grouped by hour)
        activity_data = db.execute('''
            SELECT
                strftime('%H:00', timestamp) as hour,
                COUNT(*) as count
            FROM connections
            WHERE timestamp > datetime('now', '-24 hours')
            GROUP BY hour
            ORDER BY hour
        ''').fetchall()

        if activity_data:
            hours = [row[0] for row in activity_data]
            counts = [row[1] for row in activity_data]
        else:
            hours = []
            counts = []

        # Create line chart using ChartFactory
        perf_fig = ChartFactory.create_line_chart(
            x_values=hours,
            y_values=counts,
            line_color='#17a2b8',
            x_title='Time (Hour)',
            y_title='Connections',
            fill='tozeroy'
        )


        # Create toast if refresh was clicked
        toast = ToastManager.success(
            "Performance Metrics Updated",
            detail_message=f"Network performance metrics have been refreshed.\n\nMetrics:\n- Average Latency: {avg_latency}\n- Throughput: {throughput}\n- Packet Loss: {packet_loss}\n- Active Connections: {active_conn}\n\nData reflects current network conditions."
        ) if show_toast else dash.no_update

        return avg_latency, throughput, packet_loss, str(active_conn), perf_fig, toast

    # ================================================================
    # Bandwidth Analysis
    # ================================================================
    @app.callback(
        Output('performance-bandwidth-analysis', 'children'),
        [Input('performance-modal', 'is_open'),
         Input('refresh-performance-btn', 'n_clicks')],
        prevent_initial_call=True
    )
    def update_performance_bandwidth(is_open, refresh_clicks):
        if not is_open:
            return dash.no_update

        db = get_db_connection()

        # Top bandwidth consumers (by connection count)
        top_devices = db.execute('''
            SELECT
                d.device_ip,
                d.device_name,
                d.device_type,
                COUNT(*) as conn_count,
                COUNT(DISTINCT c.dest_port) as port_count
            FROM devices d
            JOIN connections c ON d.device_ip = c.device_ip
            GROUP BY d.device_ip
            ORDER BY conn_count DESC
            LIMIT 20
        ''').fetchall()

        # Protocol distribution
        protocol_dist = db.execute('''
            SELECT
                protocol,
                COUNT(*) as count
            FROM connections
            GROUP BY protocol
            ORDER BY count DESC
            LIMIT 10
        ''').fetchall()


        # Build bandwidth analysis UI
        device_cards = []
        for device_ip, device_name, device_type, conn_count, port_count in top_devices:
            # Calculate relative bandwidth usage (percentage of total)
            total_connections = sum([row[3] for row in top_devices])
            usage_percent = (conn_count / total_connections * 100) if total_connections > 0 else 0

            # Determine color based on usage
            if usage_percent > 20:
                color = "danger"
            elif usage_percent > 10:
                color = "warning"
            else:
                color = "info"

            device_cards.append(
                dbc.Card([
                    dbc.CardBody([
                        html.Div([
                            html.H6([
                                html.I(className="fa fa-laptop me-2"),
                                device_name or device_ip
                            ], className="mb-2"),
                            html.Div([
                                dbc.Badge(device_type or "Unknown", color="secondary", className="me-2"),
                                dbc.Badge(f"{conn_count} connections", color="primary", className="me-2"),
                                dbc.Badge(f"{port_count} ports", color="info")
                            ], className="mb-2"),
                            html.Div([
                                html.P("Bandwidth Usage:", className="text-muted mb-1", style={"fontSize": "0.85rem"}),
                                dbc.Progress(value=usage_percent, color=color, className="mb-1", style={"height": "8px"}),
                                html.Span(f"{usage_percent:.1f}% of total traffic", className="text-muted", style={"fontSize": "0.8rem"})
                            ])
                        ])
                    ], className="p-3")
                ], className="glass-card border-0 shadow-sm mb-2")
            )

        # Protocol distribution section
        protocol_items = []
        for protocol, count in protocol_dist:
            protocol_items.append(
                html.Div([
                    html.Div([
                        html.Span(protocol.upper(), className="fw-bold"),
                        dbc.Badge(f"{count} connections", color="info", className="ms-2")
                    ], className="d-flex align-items-center justify-content-between mb-2 p-2",
                       style={"backgroundColor": "rgba(255,255,255,0.05)", "borderRadius": "5px"})
                ])
            )

        return html.Div([
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader([
                            html.I(className="fa fa-network-wired me-2"),
                            "Top Bandwidth Consumers"
                        ], className="glass-card-header"),
                        dbc.CardBody([
                            html.Div(device_cards) if device_cards else html.P("No bandwidth data available.", className="text-muted")
                        ])
                    ], className="glass-card border-0 shadow-sm")
                ], md=8),
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader([
                            html.I(className="fa fa-chart-pie me-2"),
                            "Protocol Distribution"
                        ], className="glass-card-header"),
                        dbc.CardBody([
                            html.Div(protocol_items) if protocol_items else html.P("No protocol data available.", className="text-muted")
                        ])
                    ], className="glass-card border-0 shadow-sm")
                ], md=4)
            ])
        ])

    # ================================================================
    # Quality Metrics
    # ================================================================
    @app.callback(
        Output('performance-quality-metrics', 'children'),
        [Input('performance-modal', 'is_open'),
         Input('refresh-performance-btn', 'n_clicks')],
        prevent_initial_call=True
    )
    def update_performance_quality(is_open, refresh_clicks):
        if not is_open:
            return dash.no_update

        db = get_db_connection()

        # Connection statistics
        total_connections = db.execute('SELECT COUNT(*) FROM connections').fetchone()[0]

        # Recent connection success rate
        recent_connections = db.execute('''
            SELECT COUNT(*) FROM connections
            WHERE timestamp > datetime('now', '-1 hour')
        ''').fetchone()[0]

        # Failed connections (would need error tracking in production)
        # For now, we'll simulate based on blocked devices
        failed_est = db.execute('''
            SELECT COUNT(DISTINCT c.device_ip)
            FROM connections c
            JOIN devices d ON c.device_ip = d.device_ip
            WHERE d.is_blocked = 1
        ''').fetchone()[0]

        success_rate = ((recent_connections - failed_est) / recent_connections * 100) if recent_connections > 0 else 100

        # Connection distribution by protocol
        protocol_quality = db.execute('''
            SELECT
                protocol,
                COUNT(*) as count,
                COUNT(DISTINCT device_ip) as unique_devices
            FROM connections
            WHERE timestamp > datetime('now', '-24 hours')
            GROUP BY protocol
            ORDER BY count DESC
        ''').fetchall()


        # Quality metric cards
        quality_cards = [
            dbc.Col([
                dbc.Card([
                    dbc.CardBody([
                        html.Div([
                            html.I(className="fa fa-check-circle fa-2x text-success mb-2")
                        ]),
                        html.H3(f"{success_rate:.1f}%", className="mb-1"),
                        html.P("Success Rate", className="text-muted mb-0", style={"fontSize": "0.85rem"})
                    ], className="text-center p-3")
                ], className="glass-card border-0 shadow-sm mb-3")
            ], md=3),
            dbc.Col([
                dbc.Card([
                    dbc.CardBody([
                        html.Div([
                            html.I(className="fa fa-link fa-2x text-info mb-2")
                        ]),
                        html.H3(str(total_connections), className="mb-1"),
                        html.P("Total Connections", className="text-muted mb-0", style={"fontSize": "0.85rem"})
                    ], className="text-center p-3")
                ], className="glass-card border-0 shadow-sm mb-3")
            ], md=3),
            dbc.Col([
                dbc.Card([
                    dbc.CardBody([
                        html.Div([
                            html.I(className="fa fa-clock fa-2x text-warning mb-2")
                        ]),
                        html.H3(str(recent_connections), className="mb-1"),
                        html.P("Last Hour", className="text-muted mb-0", style={"fontSize": "0.85rem"})
                    ], className="text-center p-3")
                ], className="glass-card border-0 shadow-sm mb-3")
            ], md=3),
            dbc.Col([
                dbc.Card([
                    dbc.CardBody([
                        html.Div([
                            html.I(className="fa fa-times-circle fa-2x text-danger mb-2")
                        ]),
                        html.H3(str(failed_est), className="mb-1"),
                        html.P("Failed Attempts", className="text-muted mb-0", style={"fontSize": "0.85rem"})
                    ], className="text-center p-3")
                ], className="glass-card border-0 shadow-sm mb-3")
            ], md=3)
        ]

        # Protocol quality table
        protocol_rows = []
        for protocol, count, unique_devices in protocol_quality:
            # Calculate quality score (simulated)
            quality_score = min(100, (count / max(1, unique_devices)) * 10)

            if quality_score > 80:
                quality_badge = dbc.Badge("Excellent", color="success")
            elif quality_score > 60:
                quality_badge = dbc.Badge("Good", color="info")
            elif quality_score > 40:
                quality_badge = dbc.Badge("Fair", color="warning")
            else:
                quality_badge = dbc.Badge("Poor", color="danger")

            protocol_rows.append(
                html.Tr([
                    html.Td(protocol.upper(), className="fw-bold"),
                    html.Td(str(count)),
                    html.Td(str(unique_devices)),
                    html.Td(quality_badge)
                ])
            )

        return html.Div([
            dbc.Row(quality_cards, className="mb-3"),
            dbc.Card([
                dbc.CardHeader([
                    html.I(className="fa fa-table me-2"),
                    "Protocol Quality Analysis"
                ], className="glass-card-header"),
                dbc.CardBody([
                    dbc.Table([
                        html.Thead([
                            html.Tr([
                                html.Th("Protocol"),
                                html.Th("Connections"),
                                html.Th("Devices"),
                                html.Th("Quality")
                            ])
                        ]),
                        html.Tbody(protocol_rows)
                    ], bordered=True, hover=True, responsive=True, className="mb-0")
                ]) if protocol_rows else dbc.CardBody([
                    html.P("No protocol quality data available.", className="text-muted mb-0")
                ])
            ], className="glass-card border-0 shadow-sm")
        ])

    # ================================================================
    # Performance Optimization Recommendations
    # ================================================================
    @app.callback(
        Output('performance-optimization-list', 'children'),
        [Input('performance-modal', 'is_open'),
         Input('refresh-performance-btn', 'n_clicks')],
        prevent_initial_call=True
    )
    def update_performance_optimization(is_open, refresh_clicks):
        if not is_open:
            return dash.no_update

        db = get_db_connection()

        recommendations = []

        # 1. Check for devices with excessive connections
        high_conn_devices = db.execute('''
            SELECT COUNT(*) as device_count
            FROM (
                SELECT device_ip, COUNT(*) as conn_count
                FROM connections
                GROUP BY device_ip
                HAVING conn_count > 1000
            )
        ''').fetchone()[0]

        if high_conn_devices > 0:
            recommendations.append({
                'priority': 1,
                'title': f'Optimize {high_conn_devices} High-Traffic Devices',
                'severity': 'high',
                'description': 'Some devices are generating excessive network traffic, which may impact performance.',
                'actions': [
                    'Review connection patterns for anomalous behavior',
                    'Implement rate limiting for high-traffic devices',
                    'Check for misconfigured applications or services',
                    'Consider QoS policies to manage bandwidth allocation'
                ]
            })

        # 2. Check for protocol diversity
        protocol_count = db.execute('SELECT COUNT(DISTINCT protocol) FROM connections').fetchone()[0]

        if protocol_count > 10:
            recommendations.append({
                'priority': 2,
                'title': 'Reduce Protocol Complexity',
                'severity': 'medium',
                'description': f'{protocol_count} different protocols detected. Protocol diversity can complicate monitoring and optimization.',
                'actions': [
                    'Standardize on fewer protocols where possible',
                    'Document and justify each protocol in use',
                    'Implement protocol-specific monitoring',
                    'Consider application consolidation'
                ]
            })

        # 3. Connection concentration analysis
        total_devices = db.execute('SELECT COUNT(*) FROM devices').fetchone()[0]
        active_devices = db.execute('''
            SELECT COUNT(DISTINCT device_ip)
            FROM connections
            WHERE timestamp > datetime('now', '-24 hours')
        ''').fetchone()[0]

        inactive_ratio = ((total_devices - active_devices) / total_devices * 100) if total_devices > 0 else 0

        if inactive_ratio > 30:
            recommendations.append({
                'priority': 2,
                'title': 'High Number of Inactive Devices',
                'severity': 'medium',
                'description': f'{inactive_ratio:.0f}% of devices have not connected in 24 hours.',
                'actions': [
                    'Review and remove decommissioned devices from inventory',
                    'Investigate why devices are not connecting',
                    'Implement device health monitoring',
                    'Set up alerts for prolonged device inactivity'
                ]
            })

        # 4. Port usage optimization
        port_usage = db.execute('''
            SELECT COUNT(DISTINCT dest_port) FROM connections
        ''').fetchone()[0]

        if port_usage > 50:
            recommendations.append({
                'priority': 3,
                'title': 'Optimize Port Usage',
                'severity': 'low',
                'description': f'{port_usage} different ports in use. Consider consolidation for better performance.',
                'actions': [
                    'Review port usage and close unnecessary ports',
                    'Implement port standardization policies',
                    'Use application proxies to reduce port exposure',
                    'Document all required ports and services'
                ]
            })

        # 5. General optimization recommendations
        recommendations.append({
            'priority': 3,
            'title': 'Network Performance Best Practices',
            'severity': 'info',
            'description': 'General recommendations to maintain optimal network performance.',
            'actions': [
                'Regularly monitor network latency and throughput',
                'Implement traffic shaping and QoS policies',
                'Keep firmware and software up to date',
                'Use caching and CDN for frequently accessed resources',
                'Schedule bandwidth-intensive tasks during off-peak hours',
                'Regularly review and optimize firewall rules'
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

    # ================================================================
    # Alert Trend Chart (TrendAnalyzer)
    # ================================================================
    @app.callback(
        Output('alert-trend-chart', 'figure'),
        Input('analytics-modal-tabs', 'active_tab'),
        prevent_initial_call=False
    )
    def update_alert_trend_chart(active_tab):
        """Update the alert trends chart with latest data."""
        if not trend_analyzer:
            # Return empty chart if trend analyzer not available
            return ChartFactory.create_line_chart(
                x_values=[],
                y_values=[],
                title='Alert Trends Unavailable',
                x_title='Date',
                y_title='Alert Count'
            )

        try:
            # Analyze alert trends for last 7 days
            trends = trend_analyzer.analyze_alert_trends(days=7, granularity='daily')

            if not trends or 'time_series' not in trends:
                # Return empty chart
                return ChartFactory.create_line_chart(
                    x_values=[],
                    y_values=[],
                    title='No Alert Data',
                    x_title='Date',
                    y_title='Alert Count'
                )

            # Extract time series data (list of tuples: [(date, count), ...])
            time_series = trends['time_series']
            if time_series:
                dates, counts = zip(*time_series)
                dates = list(dates)
                counts = list(counts)
            else:
                dates = []
                counts = []

            # Create trend chart with moving average
            figure_dict = ChartFactory.create_trend_chart(
                x_values=dates,
                y_values=counts,
                show_moving_avg=True,
                ma_period=3,
                title='',
                x_title='',
                y_title='Alerts',
                trend_color='#6366f1',
                ma_color='#ec4899'
            )

            # Convert to Figure object and update layout for compact display
            figure = go.Figure(figure_dict)
            figure.update_layout(
                margin=dict(l=40, r=20, t=20, b=40),
                showlegend=True,
                legend=dict(
                    orientation="h",
                    yanchor="bottom",
                    y=1.02,
                    xanchor="right",
                    x=1
                )
            )

            return figure

        except Exception as e:
            logger.error(f"Error updating alert trend chart: {e}")
            return ChartFactory.create_line_chart(
                x_values=[],
                y_values=[],
                title='Error Loading Data',
                x_title='Date',
                y_title='Alert Count'
            )

    # ================================================================
    # Activity Heatmap (TrendAnalyzer)
    # ================================================================
    @app.callback(
        Output('activity-heatmap-chart', 'figure'),
        Input('analytics-modal-tabs', 'active_tab'),
        prevent_initial_call=False
    )
    def update_activity_heatmap(active_tab):
        """Update the network activity heatmap."""
        if not trend_analyzer:
            # Return empty heatmap
            return ChartFactory.create_heatmap(
                x_labels=[],
                y_labels=[],
                z_values=[],
                title='Activity Heatmap Unavailable',
                x_title='Hour',
                y_title='Day'
            )

        try:
            # Analyze device activity for last 7 days
            activity = trend_analyzer.analyze_device_activity(days=7)

            if not activity or 'activity_by_hour' not in activity:
                return ChartFactory.create_heatmap(
                    x_labels=[],
                    y_labels=[],
                    z_values=[],
                    title='No Activity Data',
                    x_title='Hour',
                    y_title='Day'
                )

            # Extract hourly activity data (dict with hour: count)
            hourly_activity = activity['activity_by_hour']

            # Create 24-hour heatmap data
            hours = list(range(24))
            hour_labels = [f"{h:02d}:00" for h in hours]

            # Get activity counts per hour from the dict
            activity_counts = [hourly_activity.get(hour, 0) for hour in hours]

            # Create single-row heatmap for 24-hour pattern
            z_values = [activity_counts]

            # Create heatmap
            figure_dict = ChartFactory.create_heatmap(
                x_labels=hour_labels,
                y_labels=['Activity'],
                z_values=z_values,
                title='',
                x_title='Hour of Day',
                y_title='',
                colorscale='Viridis'
            )

            # Convert to Figure object and update layout for compact display
            figure = go.Figure(figure_dict)
            figure.update_layout(
                margin=dict(l=60, r=20, t=20, b=50),
                height=200
            )

            return figure

        except Exception as e:
            logger.error(f"Error updating activity heatmap: {e}")
            return ChartFactory.create_heatmap(
                x_labels=[],
                y_labels=[],
                z_values=[],
                title='Error Loading Data',
                x_title='Hour',
                y_title='Day'
            )

    # ================================================================
    # Trend Statistics Display
    # ================================================================
    @app.callback(
        [Output('trend-statistics-display', 'children'),
         Output('toast-container', 'children', allow_duplicate=True)],
        Input('analytics-modal-tabs', 'active_tab'),
        prevent_initial_call=True
    )
    def update_trend_statistics(active_tab):
        """Update trend statistics when Trend Analysis tab is opened."""
        if active_tab != 'trend-analysis-tab':
            raise dash.exceptions.PreventUpdate

        if not trend_analyzer:
            return (
                dbc.Alert([
                    html.I(className="fa fa-exclamation-circle me-2"),
                    "Trend analysis unavailable"
                ], color="warning"),
                dash.no_update
            )

        try:
            # Get executive summary for statistics
            summary = trend_analyzer.get_executive_summary(days=7)

            if not summary:
                return (
                    dbc.Alert([
                        html.I(className="fa fa-info-circle me-2"),
                        "No trend data available"
                    ], color="info"),
                    dash.no_update
                )

            # Build statistics display
            stats_display = dbc.Row([
                # Security Posture Column
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader([
                            html.I(className="fa fa-shield-alt me-2", style={'color': '#6366f1'}),
                            "Security Posture"
                        ], className="bg-light border-bottom"),
                        dbc.CardBody([
                            html.Div([
                                html.Small("Total Alerts", className="text-muted d-block"),
                                html.H4(str(summary['security_posture']['total_alerts']), className="mb-0")
                            ], className="mb-3"),
                            html.Div([
                                html.Small("Critical Alerts", className="text-muted d-block"),
                                html.H5(str(summary['security_posture']['critical_alerts']),
                                       className="mb-0 text-danger")
                            ], className="mb-3"),
                            html.Div([
                                html.Small("Trend", className="text-muted d-block"),
                                dbc.Badge(
                                    [html.I(className=f"fa fa-arrow-{summary['security_posture']['alert_trend'].replace('ing', '').replace('increas', 'up').replace('decreas', 'down').replace('stable', 'right')} me-1"),
                                     f"{summary['security_posture']['percent_change']}%"],
                                    color="danger" if summary['security_posture']['alert_trend'] == 'increasing' else
                                          "success" if summary['security_posture']['alert_trend'] == 'decreasing' else "secondary"
                                )
                            ])
                        ])
                    ], className="glass-card border-0 shadow-sm h-100")
                ], width=4),

                # Network Activity Column
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader([
                            html.I(className="fa fa-network-wired me-2", style={'color': '#10b981'}),
                            "Network Activity"
                        ], className="bg-light border-bottom"),
                        dbc.CardBody([
                            html.Div([
                                html.Small("Total Connections", className="text-muted d-block"),
                                html.H4(str(summary['network_activity']['total_connections']), className="mb-0")
                            ], className="mb-3"),
                            html.Div([
                                html.Small("Unique Sources", className="text-muted d-block"),
                                html.H5(str(summary['network_activity']['unique_sources']), className="mb-0")
                            ], className="mb-3"),
                            html.Div([
                                html.Small("Suspicious Patterns", className="text-muted d-block"),
                                html.H5(str(summary['network_activity']['suspicious_patterns']),
                                       className="mb-0 text-warning")
                            ])
                        ])
                    ], className="glass-card border-0 shadow-sm h-100")
                ], width=4),

                # Device Status Column
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader([
                            html.I(className="fa fa-devices me-2", style={'color': '#f59e0b'}),
                            "Device Status"
                        ], className="bg-light border-bottom"),
                        dbc.CardBody([
                            html.Div([
                                html.Small("Total Devices", className="text-muted d-block"),
                                html.H4(str(summary['device_status']['device_count']), className="mb-0")
                            ], className="mb-3"),
                            html.Div([
                                html.Small("Active Devices", className="text-muted d-block"),
                                html.H5(str(summary['device_status']['active_devices']), className="mb-0 text-success")
                            ], className="mb-3"),
                            html.Div([
                                html.Small("New Devices (7d)", className="text-muted d-block"),
                                html.H5(str(summary['device_status']['new_devices']), className="mb-0 text-info")
                            ])
                        ])
                    ], className="glass-card border-0 shadow-sm h-100")
                ], width=4)
            ], className="mb-3")

            # Add top concerns if available
            if summary.get('top_concerns'):
                concerns_list = html.Div([
                    html.Hr(),
                    html.H6([
                        html.I(className="fa fa-exclamation-triangle me-2 text-warning"),
                        "Top Concerns"
                    ], className="mb-3"),
                    html.Ul([
                        html.Li(concern, className="mb-2")
                        for concern in summary['top_concerns']
                    ], className="text-muted")
                ])

                final_display = html.Div([stats_display, concerns_list])
            else:
                final_display = stats_display

            # Generate success toast
            toast = ToastManager.success(
                "Trend statistics updated",
                detail_message=f"Showing data for last 7 days"
            )

            return final_display, toast

        except Exception as e:
            logger.error(f"Error updating trend statistics: {e}")
            return (
                dbc.Alert([
                    html.I(className="fa fa-exclamation-circle me-2"),
                    f"Error loading statistics: {str(e)}"
                ], color="danger"),
                dash.no_update
            )
