"""
Overview-tab callbacks — Security score, network topology, alerts panel,
threat feed, metrics, real-time stat cards, system health, ML model info.

Extracted from app.py.  All callbacks are registered via ``register(app)``.
"""

import logging
from datetime import datetime

import dash
import dash_bootstrap_components as dbc
import pandas as pd
import plotly.express as px
import plotly.graph_objs as go
from dash import Input, Output, State, callback_context, html, ALL, no_update

from flask_login import current_user

from dashboard.shared import (
    db_manager,
    chart_factory,
    config,
    network_security_scorer,
    iot_protocol_analyzer,
    iot_threat_detector,
    logger as _shared_logger,
    get_db_connection,
    get_bandwidth_stats,
    get_threats_blocked,
    get_latest_alerts_content,
    create_status_indicator,
    create_device_icon,
    create_device_skeleton,
    create_device_list_skeleton,
    create_timestamp_display,
    DEVICE_STATUS_COLORS,
    DB_PATH,
    THREAT_INTEL_CACHE_HOURS,
    ToastManager,
    threat_intel,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Module-level helper (used by several overview callbacks)
# ---------------------------------------------------------------------------

def _format_time_ago(timestamp_str):
    """Helper function to format timestamp as 'X min/hours ago'."""
    try:
        timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
        time_diff = datetime.now() - timestamp
        if time_diff.seconds < 60:
            return "just now"
        elif time_diff.seconds < 3600:
            return f"{time_diff.seconds // 60}m ago"
        elif time_diff.seconds < 86400:
            return f"{time_diff.seconds // 3600}h ago"
        else:
            return f"{time_diff.days}d ago"
    except:
        return "recently"


# ---------------------------------------------------------------------------
# register() – called from app.py to wire up all overview callbacks
# ---------------------------------------------------------------------------

def register(app):
    """Register all Overview-tab callbacks on *app*."""

    # ========================================================================
    # SECURITY SCORE DASHBOARD CALLBACK
    # ========================================================================

    @app.callback(
        [Output('security-score-gauge', 'figure'),
         Output('security-score-health', 'children'),
         Output('security-score-health-detail', 'children'),
         Output('security-score-vulns', 'children'),
         Output('security-score-vulns-detail', 'children'),
         Output('security-score-encryption', 'children'),
         Output('security-score-encryption-detail', 'children'),
         Output('security-score-segmentation', 'children'),
         Output('security-score-segmentation-detail', 'children'),
         Output('security-score-history-chart', 'figure'),
         Output('security-score-last-updated', 'children'),
         Output('toast-container', 'children', allow_duplicate=True)],
        [Input('security-score-interval', 'n_intervals'),
         Input('security-score-refresh-btn', 'n_clicks')],
        prevent_initial_call=True
    )
    def update_security_score_dashboard(n_intervals, refresh_clicks):
        """Update the security score dashboard with current scores and historical data."""

        # Determine if this was triggered by refresh button
        ctx = callback_context
        triggered_by_refresh = False
        if ctx.triggered:
            triggered_id = ctx.triggered[0]['prop_id'].split('.')[0]
            # Only show toast if explicitly triggered by button click AND button was actually clicked
            triggered_by_refresh = (
                triggered_id == 'security-score-refresh-btn' and
                refresh_clicks is not None and
                refresh_clicks > 0
            )

        try:
            if network_security_scorer is None:
                # Return empty placeholders if scorer not available
                empty_fig = {'data': [], 'layout': {'template': 'plotly_white'}}
                toast = ToastManager.warning(
                    "Security scorer not available",
                    detail_message="The network security scorer module is not initialized. Please check system logs."
                ) if triggered_by_refresh else dash.no_update
                return (empty_fig, "--", "Not available", "--", "Not available",
                       "--", "Not available", "--", "Not available",
                       empty_fig, "Scorer not available", toast)

            # Calculate current network security score
            score_data = network_security_scorer.calculate_network_score()

            if 'error' in score_data:
                empty_fig = {'data': [], 'layout': {'template': 'plotly_white'}}
                error_msg = f"Error: {score_data.get('error', 'Unknown')}"
                toast = ToastManager.error(
                    "Score calculation failed",
                    detail_message=error_msg
                ) if triggered_by_refresh else dash.no_update
                return (empty_fig, "--", error_msg, "--", error_msg,
                       "--", error_msg, "--", error_msg,
                       empty_fig, error_msg, toast)

            overall_score = score_data.get('overall_score', 0)
            grade = score_data.get('grade', 'F')
            device_count = score_data.get('device_count', 0)
            dimensions = score_data.get('dimensions', {})

            # Create gauge chart using ChartFactory
            gauge_fig = chart_factory.create_gauge_chart(
                value=overall_score,
                max_value=100,
                title=f"Network Security Score: {grade}",
                thresholds=[50, 80, 100],  # Red 0-49, Yellow 50-79, Green 80-100
                colors=['#dc3545', '#ffc107', '#28a745']
            )

            # Extract dimensional data
            device_health = dimensions.get('device_health', {})
            vulnerabilities = dimensions.get('vulnerabilities', {})
            encryption = dimensions.get('encryption', {})
            segmentation = dimensions.get('segmentation', {})

            # Format dimensional scores
            health_score = f"{device_health.get('score', 0):.0f}/100"
            health_detail = f"{device_health.get('devices_online', 0)}/{device_health.get('total_devices', 0)} online"

            vulns_score = f"{vulnerabilities.get('score', 0):.0f}/100"
            vuln_critical = vulnerabilities.get('critical_vulns', 0)
            vuln_high = vulnerabilities.get('high_vulns', 0)
            vulns_detail = f"{vuln_critical} critical, {vuln_high} high"

            encryption_score = f"{encryption.get('score', 0):.0f}/100"
            secure_ratio = encryption.get('secure_ratio', 0)
            encryption_detail = f"{secure_ratio:.0f}% secure protocols"

            segmentation_score = f"{segmentation.get('score', 0):.0f}/100"
            subnet_count = segmentation.get('subnet_count', 0)
            segmentation_detail = f"{subnet_count} subnet(s)"

            # Get historical data (last 7 days)
            history = network_security_scorer.get_score_history(days=7)

            if history:
                # Create historical trend chart
                timestamps = [h.get('timestamp', '') for h in history]
                scores = [h.get('overall_score', 0) for h in history]

                # Parse timestamps for better display
                parsed_times = []
                for ts in timestamps:
                    try:
                        dt = datetime.fromisoformat(ts)
                        parsed_times.append(dt.strftime('%m/%d %H:%M'))
                    except:
                        parsed_times.append(ts)

                history_fig = go.Figure()
                history_fig.add_trace(go.Scatter(
                    x=parsed_times,
                    y=scores,
                    mode='lines+markers',
                    name='Security Score',
                    line=dict(color='#10b981', width=2),
                    marker=dict(size=6),
                    fill='tozeroy',
                    fillcolor='rgba(16, 185, 129, 0.1)'
                ))

                history_fig.update_layout(
                    template='plotly_white',
                    margin=dict(l=40, r=20, t=20, b=40),
                    xaxis=dict(title='Time', showgrid=True),
                    yaxis=dict(title='Score', range=[0, 100], showgrid=True),
                    hovermode='x unified'
                )
            else:
                # No historical data available
                history_fig = go.Figure()
                history_fig.add_annotation(
                    text="No historical data available yet",
                    xref="paper", yref="paper",
                    x=0.5, y=0.5, showarrow=False,
                    font=dict(size=14, color="gray")
                )
                history_fig.update_layout(
                    template='plotly_white',
                    margin=dict(l=40, r=20, t=20, b=40),
                    xaxis=dict(visible=False),
                    yaxis=dict(visible=False)
                )

            # Update timestamp
            last_updated = f"Last updated: {datetime.now().strftime('%I:%M:%S %p')}"

            # Create toast notification if triggered by refresh button
            if triggered_by_refresh:
                # Determine toast color based on score
                if overall_score >= 80:
                    toast = ToastManager.success(
                        f"Security Score: {grade} ({overall_score:.0f}/100)",
                        detail_message=f"Network security is strong!\n\n"
                                      f"• Device Health: {device_health.get('score', 0):.0f}/100\n"
                                      f"• Vulnerabilities: {vulnerabilities.get('score', 0):.0f}/100\n"
                                      f"• Encryption: {encryption.get('score', 0):.0f}/100\n"
                                      f"• Segmentation: {segmentation.get('score', 0):.0f}/100"
                    )
                elif overall_score >= 60:
                    toast = ToastManager.warning(
                        f"Security Score: {grade} ({overall_score:.0f}/100)",
                        detail_message=f"Some security improvements needed.\n\n"
                                      f"• Device Health: {device_health.get('score', 0):.0f}/100\n"
                                      f"• Vulnerabilities: {vulnerabilities.get('score', 0):.0f}/100\n"
                                      f"• Encryption: {encryption.get('score', 0):.0f}/100\n"
                                      f"• Segmentation: {segmentation.get('score', 0):.0f}/100"
                    )
                else:
                    toast = ToastManager.error(
                        f"Security Score: {grade} ({overall_score:.0f}/100)",
                        header="Danger",
                        detail_message=f"⚠️ Critical security issues detected!\n\n"
                                      f"• Device Health: {device_health.get('score', 0):.0f}/100\n"
                                      f"• Vulnerabilities: {vulnerabilities.get('score', 0):.0f}/100\n"
                                      f"• Encryption: {encryption.get('score', 0):.0f}/100\n"
                                      f"• Segmentation: {segmentation.get('score', 0):.0f}/100"
                    )
            else:
                toast = dash.no_update

            return (gauge_fig, health_score, health_detail,
                    vulns_score, vulns_detail,
                    encryption_score, encryption_detail,
                    segmentation_score, segmentation_detail,
                    history_fig, last_updated, toast)

        except Exception as e:
            logger.error(f"Error updating security score dashboard: {e}")
            empty_fig = {'data': [], 'layout': {'template': 'plotly_white'}}
            error_msg = f"Error: {str(e)}"
            toast = ToastManager.error(
                "Dashboard update failed",
                detail_message=f"Error updating security score: {str(e)}"
            ) if triggered_by_refresh else dash.no_update
            return (empty_fig, "--", error_msg, "--", error_msg,
                   "--", error_msg, "--", error_msg,
                   empty_fig, f"Error: {str(e)}", toast)

    # ========================================================================
    # CPU / RAM FROM WEBSOCKET
    # ========================================================================

    @app.callback(
        [Output('cpu-usage', 'children'),
         Output('ram-usage', 'children')],
        Input('ws', 'message'),
        prevent_initial_call=True  # Performance: Don't run on initial load
    )
    def update_system_metrics(ws_message):
        """Update CPU and RAM metrics from websocket data."""
        if ws_message is None:
            return "—", "—"

        cpu = ws_message.get('cpu_percent', 0)
        ram = ws_message.get('ram_percent', 0)

        return f"{cpu:.1f}%", f"{ram:.1f}%"

    # ========================================================================
    # BANDWIDTH, THREATS, CONNECTIONS
    # ========================================================================

    @app.callback(
        [Output('bandwidth-usage', 'children'),
         Output('threats-blocked', 'children'),
         Output('connection-count', 'children')],
        Input('ws', 'message'),
        prevent_initial_call=True  # Performance: Don't run on initial load
    )
    def update_header_stats(ws_message):
        """Update header stats using cached queries for performance"""
        if ws_message is None:
            return "—", "—", "—"

        # Use cached queries (30s TTL) - much faster than direct DB access
        try:
            bandwidth_stats = get_bandwidth_stats()
            threats_count = get_threats_blocked()
            connection_count = ws_message.get('connection_count', 0)

            return bandwidth_stats['formatted'], str(threats_count), str(connection_count)
        except Exception as e:
            logger.error(f"Error calculating bandwidth/threats: {e}")
            return "—", "—", "—"

    # ========================================================================
    # 2D NETWORK GRAPH
    # ========================================================================

    @app.callback(
        Output('network-graph', 'elements'),
        Input('ws', 'message'),
        prevent_initial_call=True  # Performance: Lazy load network graph
    )
    def update_network_graph(ws_message):
        if ws_message is None:
            # Return empty elements during initial load
            return []
        elements = ws_message.get('network_graph_elements', [])
        if not elements:
            return []
        return elements

    # ========================================================================
    # 2D / 3D GRAPH TOGGLE
    # ========================================================================

    @app.callback(
        [Output('2d-graph-container', 'style'), Output('3d-graph-container', 'style')],
        Input('graph-view-toggle', 'value')
    )
    def toggle_graph_view(is_3d_view):
        if is_3d_view:
            return {'display': 'none'}, {'display': 'block'}
        return {'display': 'block'}, {'display': 'none'}

    # ========================================================================
    # 3D NETWORK TOPOLOGY
    # ========================================================================

    @app.callback(
        Output('network-graph-3d', 'figure'),
        Input('ws', 'message'),
        prevent_initial_call=True  # Performance: Lazy load 3D graph only when data arrives
    )
    def update_network_graph_3d(ws_message):
        """Enhanced 3D graph with force-directed layout and better visuals"""
        if ws_message is None:
            # Return empty figure during initial load
            return go.Figure()

        devices = ws_message.get('all_devices_with_status', [])
        connections = ws_message.get('recent_connections_feed', [])

        if not devices:
            return go.Figure()

        device_map = {d['device_ip']: d for d in devices}

        # Use existing 3D coordinates (already in spherical layout from background thread)
        node_x, node_y, node_z = [], [], []
        node_colors, node_sizes, node_text, node_symbols = [], [], [], []

        for d in devices:
            node_text.append(f"{d.get('device_name') or d.get('device_ip')}<br>" +
                            f"Status: {d.get('status', 'unknown')}<br>" +
                            f"Connections: {d.get('recent_connections', 0)}")
            node_x.append(d.get('x', 0))
            node_y.append(d.get('y', 0))
            node_z.append(d.get('z', 0))

            # Color by status
            status = d.get('status', 'normal')
            status_color = DEVICE_STATUS_COLORS.get(status, '#6c757d')

            # Size by alert severity
            if d.get('critical_alerts', 0) > 0:
                node_sizes.append(25)
                node_colors.append('#dc3545')  # Red for critical
                node_symbols.append('diamond')
            elif d.get('minor_alerts', 0) > 0:
                node_sizes.append(18)
                node_colors.append('#ffc107')  # Yellow for warnings
                node_symbols.append('circle')
            else:
                node_sizes.append(15)
                node_colors.append(status_color)
                node_symbols.append('circle')

        # Create device nodes
        node_trace = go.Scatter3d(
            x=node_x, y=node_y, z=node_z,
            mode='markers+text',
            hoverinfo='text',
            text=node_text,
            marker=dict(
                showscale=False,
                color=node_colors,
                size=node_sizes,
                line=dict(width=2, color='#ffffff'),
                opacity=0.9
            ),
            textposition="top center",
            textfont=dict(size=8)
        )

        # Create edges (connections to router)
        edge_traces = []
        for device in devices:
            # Router connections (thinner, grey)
            edge_traces.append(go.Scatter3d(
                x=[0, device['x']],
                y=[0, device['y']],
                z=[0, device['z']],
                mode='lines',
                line=dict(color='rgba(150,150,150,0.3)', width=2),
                hoverinfo='none',
                showlegend=False
            ))

        # Device-to-device connections (recent traffic, thicker, cyan)
        connection_counts = {}

        for conn in connections[:100]:  # Increased from 50 to 100
            src = device_map.get(conn['device_ip'])
            dst = device_map.get(conn['dest_ip'])
            if src and dst:
                edge_key = tuple(sorted([conn['device_ip'], conn['dest_ip']]))
                connection_counts[edge_key] = connection_counts.get(edge_key, 0) + 1

        # Draw connections with width based on frequency
        for edge_key, count in connection_counts.items():
            src_ip, dst_ip = edge_key
            src = device_map[src_ip]
            dst = device_map[dst_ip]

            width = min(2 + count * 0.5, 8)  # Scale width by connection count

            edge_traces.append(go.Scatter3d(
                x=[src['x'], dst['x']],
                y=[src['y'], dst['y']],
                z=[src['z'], dst['z']],
                mode='lines',
                line=dict(color='rgba(0,255,204,0.6)', width=width),
                hoverinfo='text',
                text=f"{count} connection(s)",
                showlegend=False
            ))

        # Router node (center, larger, diamond shape)
        router_trace = go.Scatter3d(
            x=[0], y=[0], z=[0],
            mode='markers+text',
            hoverinfo='text',
            text=['🌐 Router<br>Gateway'],
            marker=dict(
                color='#007bff',
                size=30,
                symbol='diamond',
                line=dict(width=3, color='#ffffff')
            ),
            textposition="top center",
            textfont=dict(size=12, family='Arial Black')
        )

        # Layout with dark background
        layout = go.Layout(
            title=dict(
                text='3D Network Topology - Force-Directed Layout',
                font=dict(size=16)
            ),
            showlegend=False,
            scene=dict(
                xaxis=dict(
                    showbackground=False,
                    showticklabels=False,
                    title=''
                ),
                yaxis=dict(
                    showbackground=False,
                    showticklabels=False,
                    title=''
                ),
                zaxis=dict(
                    showbackground=False,
                    showticklabels=False,
                    title=''
                ),
                camera=dict(
                    eye=dict(x=1.5, y=1.5, z=1.5)
                )
            ),
            margin=dict(l=0, r=0, b=0, t=40),
            hovermode='closest'
        )

        return go.Figure(data=edge_traces + [node_trace, router_trace], layout=layout)

    # ========================================================================
    # TRAFFIC TIMELINE CHART
    # ========================================================================

    @app.callback(
        Output('traffic-timeline', 'figure'),
        Input('ws', 'message'),
        prevent_initial_call=True  # Performance: Lazy load traffic timeline
    )
    def update_traffic_timeline(ws_message):
        if ws_message is None:
            # Return empty figure during initial load
            fig = go.Figure()
            fig.update_layout(template='plotly_dark', plot_bgcolor='rgba(0,0,0,0)', paper_bgcolor='rgba(0,0,0,0)')
            return fig
        traffic_data = ws_message.get('traffic_timeline', [])
        if not traffic_data:
            fig = go.Figure()
            fig.update_layout(title="No traffic data available", xaxis_title="Hour", yaxis_title="Bytes", template='plotly_dark', plot_bgcolor='rgba(0,0,0,0)', paper_bgcolor='rgba(0,0,0,0)')
            return fig
        df = pd.DataFrame(traffic_data)
        fig = px.area(df, x='hour', y='total_bytes', title="Network Traffic by Hour", color_discrete_sequence=['#007bff'])
        fig.update_layout(xaxis_title="Hour", yaxis_title="Total Bytes", showlegend=False, template='plotly_dark', plot_bgcolor='rgba(0,0,0,0)', paper_bgcolor='rgba(0,0,0,0)')
        fig.update_traces(fill='tozeroy')
        return fig

    # ========================================================================
    # PROTOCOL DISTRIBUTION PIE
    # ========================================================================

    @app.callback(
        Output('protocol-pie', 'figure'),
        [Input('ws', 'message'),
         Input('global-device-filter', 'data')],
        prevent_initial_call=True  # Performance: Lazy load protocol chart
    )
    def update_protocol_pie(ws_message, device_filter):
        if ws_message is None:
            raise dash.exceptions.PreventUpdate
        protocol_data = ws_message.get('protocol_distribution', [])
        if not protocol_data:
            fig = go.Figure()
            fig.update_layout(title="No protocol data available", template='plotly_dark', plot_bgcolor='rgba(0,0,0,0)', paper_bgcolor='rgba(0,0,0,0)')
            return fig

        df = pd.DataFrame(protocol_data)

        # Create enhanced pie chart
        fig = px.pie(
            df, values='count', names='protocol',
            title='Protocol Distribution (Click to filter)',
            color_discrete_sequence=px.colors.qualitative.Set2
        )

        # Enhanced hover template with percentages and counts
        fig.update_traces(
            textposition='inside',
            textinfo='percent+label',
            hovertemplate="<b>%{label}</b><br>" +
                          "Count: %{value}<br>" +
                          "Percentage: %{percent}<br>" +
                          "<i>Click to filter connections</i><extra></extra>"
        )

        fig.update_layout(
            template='plotly_dark',
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)',
            hovermode='closest'
        )

        return fig

    # ========================================================================
    # COMPACT DEVICE CARDS
    # ========================================================================

    @app.callback(
        Output('devices-status-compact', 'children'),
        Input('ws', 'message')
    )
    def update_devices_status_compact(ws_message):
        if ws_message is None:
            # Show skeleton loader during initial load
            return create_device_skeleton(count=8)
        devices = ws_message.get('all_devices_with_status', [])[:8]
        if not devices:
            return dbc.Alert("No devices found.", color="info", className="compact-alert")
        cards = []
        for device in devices:
            status = device.get('status', 'normal')
            device_name = device.get('device_name') or device['device_ip'].split('.')[-1]
            device_ip = device['device_ip']
            device_type = device.get('device_type')

            # PHASE 2: Get IoT protocol and ecosystem data
            iot_protocol = device.get('iot_protocol')  # e.g., 'mqtt', 'coap'
            protocol_encrypted = device.get('protocol_encrypted', False)
            ecosystem = device.get('ecosystem')  # e.g., 'google_home', 'alexa'

            # Build card content
            card_content = [
                create_status_indicator(status, "0.8rem"),
                create_device_icon(device_type, use_emoji=True, use_fa=False, size="1rem"),
                html.Span(device_name, className="device-name-compact"),
            ]

            # PHASE 2: Add protocol badge if detected
            if iot_protocol:
                protocol_icon = "✅" if protocol_encrypted else "⚠️"
                card_content.append(
                    dbc.Badge(
                        [iot_protocol.upper(), " ", protocol_icon],
                        color="success" if protocol_encrypted else "warning",
                        pill=True,
                        className="protocol-badge-sm ms-1",
                        style={"fontSize": "0.65rem"}
                    )
                )

            # PHASE 2: Add ecosystem icon if detected
            if ecosystem:
                ecosystem_icons = {
                    'google_home': '🏠',
                    'alexa': '🔊',
                    'homekit': '🍎'
                }
                if ecosystem in ecosystem_icons:
                    card_content.append(
                        html.Span(ecosystem_icons[ecosystem], className="ms-1", title=ecosystem.replace('_', ' ').title())
                    )

            card_content.append(html.Span(device['device_ip'], className="device-ip-compact ms-auto"))

            # Make clickable with device icon
            cards.append(
                html.Div(card_content,
                    className="device-item-compact clickable-device",
                    id={'type': 'device-card', 'ip': device_ip},
                    n_clicks=0)
            )
        return html.Div(cards, className="fade-in")

    # ========================================================================
    # ACTIVE DEVICES LIST
    # ========================================================================

    @app.callback(
        Output('active-devices-list', 'children'),
        Input('ws', 'message')
    )
    def update_active_devices_list(ws_message):
        if ws_message is None:
            # Show skeleton loader during initial load
            return create_device_list_skeleton(count=10)
        devices = ws_message.get('all_devices_with_status', [])
        if not devices:
            return dbc.Alert("No active devices.", color="info", className="compact-alert")
        items = []
        for device in devices:
            status = device.get('status', 'normal')
            status_text = device.get('status_text', 'Unknown')
            device_name = device.get('device_name') or device['device_ip']
            device_ip = device['device_ip']
            device_type = device.get('device_type')
            badge_color = 'danger' if status == 'alert' else ('warning' if status == 'warning' else 'success')

            # Check if device is blocked
            is_blocked = bool(device.get('is_blocked', False))

            # PHASE 2: Get IoT protocol and ecosystem data
            iot_protocol = device.get('iot_protocol')
            protocol_encrypted = device.get('protocol_encrypted', False)
            ecosystem = device.get('ecosystem')

            # Build badges list
            badges = [dbc.Badge(status_text, color=badge_color, pill=True, className="badge-sm")]

            # PHASE 2: Add protocol badge
            if iot_protocol:
                protocol_icon = "✅" if protocol_encrypted else "⚠️"
                badges.append(
                    dbc.Badge(
                        [iot_protocol.upper(), " ", protocol_icon],
                        color="success" if protocol_encrypted else "warning",
                        pill=True,
                        className="badge-sm ms-1"
                    )
                )

            # Add blocked badge
            if is_blocked:
                badges.append(
                    dbc.Badge([html.I(className="fa fa-ban me-1"), "BLOCKED"],
                             color="danger", pill=True, className="badge-sm ms-1")
                )

            # PHASE 2: Build bottom info with ecosystem icon
            bottom_info = [html.I(className="fa fa-network-wired me-1"), device['device_ip']]
            if ecosystem:
                ecosystem_icons = {
                    'google_home': '🏠 Google Home',
                    'alexa': '🔊 Alexa',
                    'homekit': '🍎 HomeKit'
                }
                if ecosystem in ecosystem_icons:
                    bottom_info.extend([" • ", ecosystem_icons[ecosystem]])

            items.append(
                html.Div([
                    html.Div([
                        create_status_indicator(status, "0.9rem"),
                        create_device_icon(device_type, use_emoji=True, use_fa=False, size="1.1rem"),
                        html.Strong(device_name, className="me-2"),
                        *badges
                    ], className="d-flex align-items-center mb-1"),
                    html.Small(bottom_info, className="text-muted")
                ], className="active-device-item clickable-device" + (" border-danger" if is_blocked else ""),
                   id={'type': 'device-list-item', 'ip': device_ip},
                   n_clicks=0,
                   style=({"borderLeft": "4px solid #dc3545"} if is_blocked else {})
            )
            )
        return html.Div(items, className="fade-in")

    # ========================================================================
    # ALERTS BY DAY BAR CHART
    # ========================================================================

    @app.callback(
        Output('alert-timeline', 'figure'),
        [Input('ws', 'message'),
         Input('global-severity-filter', 'data')],
        prevent_initial_call=True
    )
    def update_alert_timeline(ws_message, severity_filter):
        if ws_message is None:
            # Return empty figure during initial load
            fig = go.Figure()
            fig.update_layout()
            return fig
        alert_timeline_data = ws_message.get('alert_timeline', [])
        if not alert_timeline_data:
            fig = go.Figure()
            fig.update_layout(title="No alerts in the last 7 days")
            return fig

        df = pd.DataFrame(alert_timeline_data)

        # Apply severity filter if active
        if severity_filter:
            df = df[df['severity'] == severity_filter]

        # Create interactive bar chart with enhanced tooltips
        fig = px.bar(df, x="day", y="count", color="severity", title="Alerts by Day (Click to filter)",
                     color_discrete_map={'critical': '#dc3545', 'high': '#fd7e14', 'medium': '#17a2b8', 'low': '#6c757d'},
                     hover_data={'count': True, 'severity': True, 'day': True})

        # Enhanced hover template with "View Details" hint
        fig.update_traces(
            hovertemplate="<b>%{x}</b><br>" +
                          "Severity: %{fullData.name}<br>" +
                          "Count: %{y}<br>" +
                          "<i>Click to filter by severity</i><extra></extra>"
        )

        # Enable zoom/pan/reset controls
        fig.update_layout(
            xaxis_title="Date",
            yaxis_title="Number of Alerts",
            barmode='stack',
            hovermode='closest',
            dragmode='zoom',  # Enable zoom by default
            modebar={'orientation': 'v'},
            modebar_add=['pan2d', 'select2d', 'lasso2d', 'resetScale2d']
        )

        return fig

    # ========================================================================
    # ANOMALY SCORE HISTOGRAM
    # ========================================================================

    @app.callback(
        Output('anomaly-distribution', 'figure'),
        Input('ws', 'message')
    )
    def update_anomaly_distribution(ws_message):
        if ws_message is None:
            raise dash.exceptions.PreventUpdate
        anomaly_data = ws_message.get('anomaly_distribution', [])
        if not anomaly_data:
            fig = go.Figure()
            fig.update_layout(title="No anomaly data available")
            return fig
        df = pd.DataFrame(anomaly_data)
        fig = px.histogram(df, x="anomaly_score", title="Anomaly Score Distribution", color_discrete_sequence=['#007bff'], nbins=30)
        fig.update_layout(xaxis_title="Anomaly Score", yaxis_title="Frequency")
        fig.add_vline(x=-0.5, line_dash="dash", line_color="red", annotation_text="Anomaly Threshold")
        return fig

    # ========================================================================
    # BANDWIDTH USAGE BAR
    # ========================================================================

    @app.callback(
        Output('bandwidth-chart', 'figure'),
        Input('ws', 'message')
    )
    def update_bandwidth_chart(ws_message):
        if ws_message is None:
            raise dash.exceptions.PreventUpdate
        bandwidth_data = ws_message.get('bandwidth_chart', [])
        if not bandwidth_data:
            fig = go.Figure()
            fig.update_layout(title="No Bandwidth Data Available", template='plotly_dark', plot_bgcolor='rgba(0,0,0,0)', paper_bgcolor='rgba(0,0,0,0)')
            return fig
        df = pd.DataFrame(bandwidth_data)
        fig = px.bar(df, x='device_ip', y='total_bytes', title="Top 10 Devices by Bandwidth Usage", color_discrete_sequence=['#28a745'])
        fig.update_layout(xaxis_title="Device IP", yaxis_title="Total Bytes", template='plotly_dark', plot_bgcolor='rgba(0,0,0,0)', paper_bgcolor='rgba(0,0,0,0)')
        return fig

    # ========================================================================
    # DEVICE ACTIVITY HEATMAP
    # ========================================================================

    @app.callback(
        Output('device-heatmap', 'figure'),
        [Input('ws', 'message'),
         Input('global-device-filter', 'data')],
        prevent_initial_call=True
    )
    def update_device_heatmap(ws_message, device_filter):
        if ws_message is None:
            raise dash.exceptions.PreventUpdate
        heatmap_data = ws_message.get('device_activity_heatmap', [])
        if not heatmap_data:
            fig = go.Figure()
            fig.update_layout(title="No activity data available")
            return fig

        df = pd.DataFrame(heatmap_data)

        # Apply device filter if active
        if device_filter:
            df = df[df['device_ip'] == device_filter]

        # Create enhanced heatmap with custom hover data
        fig = px.density_heatmap(
            df, x="hour", y="device_ip", z="count",
            title="Device Activity by Hour (Click device to filter)",
            color_continuous_scale="Blues",
            labels={'hour': 'Hour of Day', 'device_ip': 'Device IP', 'count': 'Connections'}
        )

        # Enhanced hover template
        fig.update_traces(
            hovertemplate="<b>%{y}</b><br>" +
                          "Hour: %{x}:00<br>" +
                          "Connections: %{z}<br>" +
                          "<i>Click to view device details</i><extra></extra>",
            customdata=df[['device_ip']].values if not df.empty else []
        )

        # Enable zoom/pan controls
        fig.update_layout(
            xaxis_title="Hour of Day",
            yaxis_title="Device IP",
            hovermode='closest',
            dragmode='zoom',
            modebar_add=['pan2d', 'zoomIn2d', 'zoomOut2d', 'resetScale2d']
        )

        return fig

    # ========================================================================
    # SECURITY SUMMARY REPORT
    # ========================================================================

    @app.callback(
        Output('security-summary-report', 'children'),
        Input('ws', 'message')
    )
    def update_security_summary_report(ws_message):
        """Generate comprehensive Security Summary Report with real data"""
        try:
            from utils.iot_security_checker import security_checker
            from datetime import datetime

            # Get all devices
            devices = db_manager.get_all_devices()

            # Get security assessment
            security_summary = security_checker.get_network_security_score(devices) if devices else None

            # Query database for alert statistics
            conn = db_manager.conn
            cursor = conn.cursor()

            # Alert statistics by severity (last 24 hours)
            cursor.execute('''
                SELECT severity, COUNT(*) as count
                FROM alerts
                WHERE timestamp >= datetime('now', '-24 hours')
                GROUP BY severity
            ''')
            alerts_24h = {row['severity']: row['count'] for row in cursor.fetchall()}

            # Alert statistics by severity (last 7 days)
            cursor.execute('''
                SELECT severity, COUNT(*) as count
                FROM alerts
                WHERE timestamp >= datetime('now', '-7 days')
                GROUP BY severity
            ''')
            alerts_7d = {row['severity']: row['count'] for row in cursor.fetchall()}

            # Total alerts
            cursor.execute('SELECT COUNT(*) as count FROM alerts')
            total_alerts = cursor.fetchone()['count']

            # Acknowledged vs unacknowledged
            cursor.execute('SELECT COUNT(*) as count FROM alerts WHERE acknowledged = 0')
            unacknowledged_alerts = cursor.fetchone()['count']

            # Blocked devices
            cursor.execute('SELECT COUNT(*) as count FROM devices WHERE is_blocked = 1')
            blocked_devices = cursor.fetchone()['count']

            # Trusted devices
            cursor.execute('SELECT COUNT(*) as count FROM devices WHERE is_trusted = 1')
            trusted_devices = cursor.fetchone()['count']

            # Most active alerting devices
            cursor.execute('''
                SELECT device_ip, COUNT(*) as alert_count
                FROM alerts
                WHERE timestamp >= datetime('now', '-7 days')
                GROUP BY device_ip
                ORDER BY alert_count DESC
                LIMIT 5
            ''')
            top_alerting_devices = cursor.fetchall()


            # Determine overall risk color
            if security_summary:
                risk_level = security_summary['risk_level']
                if risk_level == 'low':
                    risk_color = 'success'
                elif risk_level == 'medium':
                    risk_color = 'warning'
                elif risk_level == 'high':
                    risk_color = 'danger'
                else:  # critical
                    risk_color = 'danger'
            else:
                risk_color = 'secondary'
                risk_level = 'unknown'

            # Build report layout
            report_content = html.Div([
                # Header with timestamp
                dbc.Row([
                    dbc.Col([
                        html.H5([
                            html.I(className="fa fa-calendar me-2"),
                            f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                        ], className="text-muted mb-3")
                    ])
                ]),

                # Executive Summary
                dbc.Row([
                    dbc.Col([
                        dbc.Card([
                            dbc.CardHeader([
                                html.I(className="fa fa-shield-alt me-2"),
                                html.Strong("Executive Summary")
                            ], className="glass-card-header"),
                            dbc.CardBody([
                                dbc.Row([
                                    dbc.Col([
                                        html.Div([
                                            html.H2(security_summary['security_score'] if security_summary else 'N/A',
                                                   className=f"text-{risk_color} mb-0",
                                                   style={'fontSize': '3.5rem', 'fontWeight': 'bold'}),
                                            html.P("Overall Security Score", className="text-muted"),
                                            dbc.Badge(f"{risk_level.upper()} RISK", color=risk_color, className="mt-2")
                                        ], className="text-center")
                                    ], width=3),
                                    dbc.Col([
                                        html.Div([
                                            html.H4(security_summary['total_devices'] if security_summary else len(devices),
                                                   className="text-primary mb-1"),
                                            html.Small("Total Devices Monitored", className="text-muted")
                                        ], className="text-center mb-3"),
                                        html.Div([
                                            html.H4(security_summary['iot_devices_count'] if security_summary else 0,
                                                   className="text-info mb-1"),
                                            html.Small("IoT Devices", className="text-muted")
                                        ], className="text-center")
                                    ], width=3),
                                    dbc.Col([
                                        html.Div([
                                            html.H4(security_summary['vulnerable_count'] if security_summary else 0,
                                                   className="text-danger mb-1"),
                                            html.Small("Vulnerable Devices", className="text-muted")
                                        ], className="text-center mb-3"),
                                        html.Div([
                                            html.H4(blocked_devices, className="text-warning mb-1"),
                                            html.Small("Blocked Devices", className="text-muted")
                                        ], className="text-center")
                                    ], width=3),
                                    dbc.Col([
                                        html.Div([
                                            html.H4(total_alerts, className="text-secondary mb-1"),
                                            html.Small("Total Alerts (All Time)", className="text-muted")
                                        ], className="text-center mb-3"),
                                        html.Div([
                                            html.H4(unacknowledged_alerts, className="text-danger mb-1"),
                                            html.Small("Unacknowledged Alerts", className="text-muted")
                                        ], className="text-center")
                                    ], width=3)
                                ], className="align-items-center")
                            ])
                        ], className="mb-4 shadow-sm")
                    ])
                ]),

                # Alert Statistics
                dbc.Row([
                    dbc.Col([
                        dbc.Card([
                            dbc.CardHeader([
                                html.I(className="fa fa-exclamation-triangle me-2"),
                                html.Strong("Alert Statistics")
                            ], className="bg-danger text-white"),
                            dbc.CardBody([
                                html.H6("Last 24 Hours", className="mb-3"),
                                dbc.Row([
                                    dbc.Col([
                                        html.Div([
                                            html.H5(alerts_24h.get('critical', 0), className="text-danger mb-0"),
                                            html.Small("Critical", className="text-muted")
                                        ], className="text-center")
                                    ], width=3),
                                    dbc.Col([
                                        html.Div([
                                            html.H5(alerts_24h.get('high', 0), className="text-warning mb-0"),
                                            html.Small("High", className="text-muted")
                                        ], className="text-center")
                                    ], width=3),
                                    dbc.Col([
                                        html.Div([
                                            html.H5(alerts_24h.get('medium', 0), className="text-info mb-0"),
                                            html.Small("Medium", className="text-muted")
                                        ], className="text-center")
                                    ], width=3),
                                    dbc.Col([
                                        html.Div([
                                            html.H5(alerts_24h.get('low', 0), className="text-secondary mb-0"),
                                            html.Small("Low", className="text-muted")
                                        ], className="text-center")
                                    ], width=3)
                                ], className="mb-3"),
                                html.Hr(),
                                html.H6("Last 7 Days", className="mb-3"),
                                dbc.Row([
                                    dbc.Col([
                                        html.Div([
                                            html.H5(alerts_7d.get('critical', 0), className="text-danger mb-0"),
                                            html.Small("Critical", className="text-muted")
                                        ], className="text-center")
                                    ], width=3),
                                    dbc.Col([
                                        html.Div([
                                            html.H5(alerts_7d.get('high', 0), className="text-warning mb-0"),
                                            html.Small("High", className="text-muted")
                                        ], className="text-center")
                                    ], width=3),
                                    dbc.Col([
                                        html.Div([
                                            html.H5(alerts_7d.get('medium', 0), className="text-info mb-0"),
                                            html.Small("Medium", className="text-muted")
                                        ], className="text-center")
                                    ], width=3),
                                    dbc.Col([
                                        html.Div([
                                            html.H5(alerts_7d.get('low', 0), className="text-secondary mb-0"),
                                            html.Small("Low", className="text-muted")
                                        ], className="text-center")
                                    ], width=3)
                                ])
                            ])
                        ], className="mb-4 shadow-sm")
                    ], width=6),

                    dbc.Col([
                        dbc.Card([
                            dbc.CardHeader([
                                html.I(className="fa fa-network-wired me-2"),
                                html.Strong("Device Compliance")
                            ], className="glass-card-header"),
                            dbc.CardBody([
                                dbc.Row([
                                    dbc.Col([
                                        html.Div([
                                            html.I(className="fa fa-check-circle fa-3x text-success mb-2"),
                                            html.H4(trusted_devices, className="mb-0"),
                                            html.Small("Trusted Devices", className="text-muted")
                                        ], className="text-center")
                                    ], width=6),
                                    dbc.Col([
                                        html.Div([
                                            html.I(className="fa fa-ban fa-3x text-danger mb-2"),
                                            html.H4(blocked_devices, className="mb-0"),
                                            html.Small("Blocked Devices", className="text-muted")
                                        ], className="text-center")
                                    ], width=6)
                                ], className="mb-3"),
                                html.Hr(),
                                dbc.Progress([
                                    dbc.Progress(
                                        value=(trusted_devices / len(devices) * 100) if devices else 0,
                                        color="success",
                                        bar=True,
                                        label=f"{int((trusted_devices / len(devices) * 100) if devices else 0)}% Trusted"
                                    )
                                ], style={"height": "30px"})
                            ])
                        ], className="mb-4 shadow-sm")
                    ], width=6)
                ]),

                # Top Alerting Devices
                dbc.Row([
                    dbc.Col([
                        dbc.Card([
                            dbc.CardHeader([
                                html.I(className="fa fa-list-ol me-2"),
                                html.Strong("Top Alerting Devices (Last 7 Days)")
                            ], className="glass-card-header"),
                            dbc.CardBody([
                                dbc.Table([
                                    html.Thead([
                                        html.Tr([
                                            html.Th("#", style={'width': '10%'}),
                                            html.Th("Device IP"),
                                            html.Th("Alert Count", className="text-end")
                                        ])
                                    ]),
                                    html.Tbody([
                                        html.Tr([
                                            html.Td(str(idx + 1)),
                                            html.Td(device['device_ip']),
                                            html.Td(dbc.Badge(str(device['alert_count']), color="danger"), className="text-end")
                                        ]) for idx, device in enumerate(top_alerting_devices)
                                    ] if top_alerting_devices else [
                                        html.Tr([html.Td("No high-alert devices in the last 7 days", colSpan=3, className="text-center text-muted")])
                                    ])
                                ], bordered=True, hover=True, dark=False, size="sm", className="table-adaptive")
                            ])
                        ], className="mb-4 shadow-sm")
                    ], width=6),

                    # Recommendations
                    dbc.Col([
                        dbc.Card([
                            dbc.CardHeader([
                                html.I(className="fa fa-lightbulb me-2"),
                                html.Strong("Security Recommendations")
                            ], className="bg-info text-white"),
                            dbc.CardBody([
                                html.Ul([
                                    html.Li(rec, className="mb-2")
                                    for rec in (security_summary['top_recommendations'][:5] if security_summary else [
                                        "Add devices to your network to start monitoring",
                                        "Configure trusted devices for better security posture",
                                        "Review and acknowledge pending alerts"
                                    ])
                                ], style={'paddingLeft': '20px'})
                            ])
                        ], className="mb-4 shadow-sm")
                    ], width=6)
                ]),

                # Export Section
                dbc.Row([
                    dbc.Col([
                        html.Label("Export Format:", className="fw-bold mb-2"),
                        dbc.Select(
                            id='export-format-security',
                            options=[
                                {'label': '📄 CSV Format', 'value': 'csv'},
                                {'label': '📋 JSON Format', 'value': 'json'},
                                {'label': '📕 PDF Report', 'value': 'pdf'},
                                {'label': '📊 Excel Workbook', 'value': 'xlsx'}
                            ],
                            value='csv',
                            className="mb-2"
                        ),
                        dbc.Button([
                            html.I(className="fa fa-download me-2"),
                            "Export Security Report"
                        ], id='export-security-report-btn', color="primary", className="w-100")
                    ], md=6, className="mx-auto text-center")
                ], className="mt-3")
            ])

            return report_content

        except Exception as e:
            logger.error(f"Error generating security summary report: {e}")
            return dbc.Alert([
                html.I(className="fa fa-exclamation-triangle me-2"),
                f"Error generating report: {str(e)}"
            ], color="danger")

    # ========================================================================
    # SYSTEM HEALTH + SUSTAINABILITY
    # ========================================================================

    @app.callback(
        Output('system-info', 'children'),
        Input('ws', 'message')
    )
    def update_system_info(ws_message):
        if ws_message is None:
            raise dash.exceptions.PreventUpdate
        total_devices = ws_message.get('total_devices_db', 'N/A')
        total_connections = ws_message.get('total_connections_db', 'N/A')
        total_alerts = ws_message.get('total_alerts_db', 'N/A')

        # PHASE 3: Calculate sustainability metrics (UK-based)
        pi_watts = 3.0  # Raspberry Pi 5 typical power consumption
        desktop_watts = 150.0  # Typical desktop NVR/security system
        hours_per_year = 24 * 365
        kwh_per_year = (desktop_watts - pi_watts) * hours_per_year / 1000
        co2_kg = kwh_per_year * 0.233  # kg CO2 per kWh (UK grid 2024)
        cost_saved_gbp = kwh_per_year * 0.30  # £/kWh (UK average 2024)
        trees_equivalent = co2_kg / 22  # Average tree CO2 absorption per year

        # PHASE 5: Get CPU and RAM usage from websocket
        cpu_usage = ws_message.get('cpu_percent', 0)
        ram_usage = ws_message.get('ram_percent', 0)

        # Determine overall health status
        health_status = "Healthy ✅"
        health_color = "success"
        health_message = "All systems operating normally"

        if cpu_usage > 80 or ram_usage > 85:
            health_status = "Warning ⚠️"
            health_color = "warning"
            health_message = "High resource usage detected"
        elif cpu_usage > 95 or ram_usage > 95:
            health_status = "Critical ⚠️"
            health_color = "danger"
            health_message = "Critical resource usage"

        return [
            # PHASE 5: Simplified System Health Dashboard
            dbc.Card([
                dbc.CardHeader([
                    html.I(className="fa fa-heartbeat me-2"),
                    html.Strong("⚙️ System Health")
                ], className="bg-light"),
                dbc.CardBody([
                    # Overall health indicator
                    html.Div([
                        html.H3(health_status, className=f"text-{health_color} mb-3"),
                        html.P(health_message, className="text-muted")
                    ], className="text-center mb-4"),

                    # Resource usage (simplified)
                    dbc.Row([
                        dbc.Col([
                            html.H5(f"{cpu_usage:.0f}%", className="text-primary mb-2"),
                            html.P("CPU Usage", className="small text-muted mb-2"),
                            dbc.Progress(value=cpu_usage, color="primary" if cpu_usage < 70 else "warning" if cpu_usage < 90 else "danger", className="mb-2"),
                            html.Small("✓ Plenty of headroom" if cpu_usage < 70 else "⚠️ High usage" if cpu_usage < 90 else "❌ Critical",
                                      className=f"text-{'success' if cpu_usage < 70 else 'warning' if cpu_usage < 90 else 'danger'}")
                        ], width=6),
                        dbc.Col([
                            html.H5(f"{ram_usage:.0f}%", className="text-primary mb-2"),
                            html.P("Memory Usage", className="small text-muted mb-2"),
                            dbc.Progress(value=ram_usage, color="primary" if ram_usage < 70 else "warning" if ram_usage < 90 else "danger", className="mb-2"),
                            html.Small("✓ Efficient operation" if ram_usage < 70 else "⚠️ High usage" if ram_usage < 90 else "❌ Critical",
                                      className=f"text-{'success' if ram_usage < 70 else 'warning' if ram_usage < 90 else 'danger'}")
                        ], width=6)
                    ], className="mb-3"),

                    html.Hr(),

                    # Performance indicators (user-friendly)
                    dbc.Row([
                        dbc.Col([
                            html.Div([
                                html.I(className="fa fa-bolt fa-2x text-warning mb-2"),
                                html.H6("Real-Time", className="mb-0"),
                                html.Small("< 50ms detection", className="text-muted")
                            ], className="text-center")
                        ], width=4),
                        dbc.Col([
                            html.Div([
                                html.I(className="fa fa-network-wired fa-2x text-info mb-2"),
                                html.H6(f"{total_connections:,}" if isinstance(total_connections, int) else "Active", className="mb-0"),
                                html.Small("Connections tracked", className="text-muted")
                            ], className="text-center")
                        ], width=4),
                        dbc.Col([
                            html.Div([
                                html.I(className="fa fa-shield-alt fa-2x text-success mb-2"),
                                html.H6("High", className="mb-0"),
                                html.Small("Detection confidence", className="text-muted")
                            ], className="text-center")
                        ], width=4)
                    ]),

                    html.Hr(className="my-3"),

                    # Technical details in collapsible section
                    dbc.Accordion([
                        dbc.AccordionItem([
                            html.P([html.Strong("Database Path: "), html.Small(str(DB_PATH), className="text-muted")]),
                            html.P([html.Strong("Total Devices Tracked: "), str(total_devices)]),
                            html.P([html.Strong("Total Connections Logged: "), f"{total_connections:,}" if isinstance(total_connections, int) else str(total_connections)]),
                            html.P([html.Strong("Total Alerts Generated: "), str(total_alerts)]),
                            html.P([html.Strong("Last Updated: "), datetime.now().strftime('%Y-%m-%d %H:%M:%S')])
                        ], title="🔧 Technical Details (Advanced)")
                    ], start_collapsed=True, className="mt-2")
                ])
            ], className="mb-3 border-primary"),

            # PHASE 3: Sustainability Widget (UK pricing)
            html.Hr(className="my-4"),
            dbc.Card([
                dbc.CardHeader([
                    html.I(className="fa fa-leaf me-2 text-success"),
                    html.Strong("Environmental Impact")
                ], className="glass-card-header"),
                dbc.CardBody([
                    dbc.Row([
                        dbc.Col([
                            html.H4(f"{pi_watts:.0f}W", className="text-success mb-1", style={"fontSize": "1.5rem"}),
                            html.P("Power Usage", className="small text-muted mb-0"),
                            html.Small(f"vs {desktop_watts:.0f}W", className="text-muted", style={"fontSize": "0.7rem"})
                        ], xs=6, sm=6, md=3, className="text-center mb-2 mb-md-0"),
                        dbc.Col([
                            html.H4(f"{co2_kg:.0f} kg", className="text-success mb-1", style={"fontSize": "1.5rem"}),
                            html.P("CO₂ Saved/Year", className="small text-muted mb-0"),
                            html.Small(f"{trees_equivalent:.0f} trees", className="text-muted", style={"fontSize": "0.7rem"})
                        ], xs=6, sm=6, md=3, className="text-center mb-2 mb-md-0"),
                        dbc.Col([
                            html.H4(f"£{cost_saved_gbp:.0f}", className="text-success mb-1", style={"fontSize": "1.5rem"}),
                            html.P("Cost Saved/Year", className="small text-muted mb-0"),
                            html.Small("at £0.30/kWh", className="text-muted", style={"fontSize": "0.7rem"})
                        ], xs=6, sm=6, md=3, className="text-center mb-2 mb-md-0"),
                        dbc.Col([
                            html.P("UN SDGs:", className="small mb-1 text-muted", style={"fontSize": "0.75rem"}),
                            html.Div([
                                dbc.Badge("SDG 7", color="warning", className="me-1", title="Affordable & Clean Energy", style={"fontSize": "0.65rem"}),
                                dbc.Badge("SDG 12", color="warning", className="me-1", title="Responsible Consumption", style={"fontSize": "0.65rem"}),
                                dbc.Badge("SDG 13", color="warning", title="Climate Action", style={"fontSize": "0.65rem"})
                            ])
                        ], xs=6, sm=6, md=3, className="text-center mb-2 mb-md-0")
                    ], className="g-2")
                ])
            ], className="mb-3 border-success"),

            # PHASE 7: Enterprise Tool Selection - Zeek Justification
            html.Hr(className="my-4"),
            dbc.Card([
                dbc.CardHeader([
                    html.Img(src="https://zeek.org/wp-content/uploads/2019/09/logo.png", height="25px", className="me-2"),
                    html.Strong("Powered by Zeek - Enterprise-Grade Analysis")
                ], className="bg-info text-white"),
                dbc.CardBody([
                    html.P([
                        html.Strong("Why Zeek? "),
                        "IoTSentinel uses Zeek, the same network security monitor trusted by ",
                        html.A("Google, Amazon, and US National Labs",
                               href="https://zeek.org/users/", target="_blank", className="text-primary fw-bold"),
                        " for production security monitoring."
                    ], className="mb-3"),
                    html.Hr(),
                    dbc.Row([
                        dbc.Col([
                            html.H5("8+", className="text-primary mb-1"),
                            html.P("Protocols Analyzed", className="small text-muted mb-0")
                        ], width=3, className="text-center"),
                        dbc.Col([
                            html.H5("12", className="text-primary mb-1"),
                            html.P("Log Types Generated", className="small text-muted mb-0")
                        ], width=3, className="text-center"),
                        dbc.Col([
                            html.H5("20+ years", className="text-primary mb-1"),
                            html.P("Battle-Tested", className="small text-muted mb-0")
                        ], width=3, className="text-center"),
                        dbc.Col([
                            html.H5("2.3ms", className="text-primary mb-1"),
                            html.P("Parse Speed", className="small text-muted mb-0")
                        ], width=3, className="text-center")
                    ], className="mb-3"),
                    html.Hr(),
                    dbc.Alert([
                        html.Strong("💼 Professional Engineering: "),
                        "Rather than reinventing the wheel with custom Python parsers, "
                        "IoTSentinel leverages proven, enterprise-tested tools. This "
                        "ensures reliability while focusing development on what makes us "
                        "unique: educational transparency and machine learning insights."
                    ], color="light", className="mb-0 border-info")
                ])
            ], className="mb-3 border-info")
        ]

    # ========================================================================
    # ML MODEL INFO
    # ========================================================================

    @app.callback(
        Output('model-info', 'children'),
        Input('ws', 'message')
    )
    def update_model_info(ws_message):
        if ws_message is None:
            raise dash.exceptions.PreventUpdate
        models = ws_message.get('model_info', [])
        if not models:
            return dbc.Alert("No trained models found.", color="warning")
        return [html.Ul([html.Li([html.Strong(m['name']), f" - Size: {m['size']}, Updated: {m['modified']}"]) for m in models])]

    # ========================================================================
    # RIVER MODEL COMPARISON
    # ========================================================================

    @app.callback(
        Output('model-comparison', 'children'),
        Input('ws', 'message')
    )
    def update_model_comparison(ws_message):
        """Display River model performance metrics."""
        if ws_message is None:
            raise dash.exceptions.PreventUpdate

        # River models - show current performance stats
        from ml.river_engine import RiverEngine

        try:
            stats = {
                "HalfSpaceTrees": {
                    "Type": "Anomaly Detection",
                    "Learning": "Incremental",
                    "Status": "Active"
                },
                "HoeffdingAdaptive": {
                    "Type": "Attack Classification",
                    "Learning": "Incremental",
                    "Status": "Active"
                },
                "SNARIMAX": {
                    "Type": "Traffic Forecasting",
                    "Learning": "Incremental",
                    "Status": "Active"
                }
            }

            table_header = [html.Thead(html.Tr([html.Th("Model"), html.Th("Type"), html.Th("Learning"), html.Th("Status")]))]
            table_body = [html.Tbody([
                html.Tr([
                    html.Td(model),
                    html.Td(metrics.get('Type', 'N/A')),
                    html.Td(dbc.Badge(metrics.get('Learning', 'N/A'), color="success")),
                    html.Td(dbc.Badge(metrics.get('Status', 'N/A'), color="success"))
                ]) for model, metrics in stats.items()
            ])]

            table = dbc.Table(table_header + table_body, bordered=True, hover=True, dark=False, size="sm", className="table-adaptive")

            return html.Div([
                html.H6("River ML Models", className="mb-3"),
                dbc.Alert([
                    html.I(className="fa fa-info-circle me-2"),
                    "River models learn incrementally from streaming data - no batch comparison needed!"
                ], color="info", className="mb-3"),
                table
            ])

        except Exception as e:
            logger.error(f"Error displaying model stats: {e}")
            return dbc.Alert("Unable to load model information.", color="warning")

    # ========================================================================
    # IOT SECURITY STATUS
    # ========================================================================

    @app.callback(
        Output('iot-security-widget', 'children'),
        Input('ws', 'message')
    )
    def update_iot_security_widget(ws_message):
        """Update IoT Security Status widget"""
        from utils.iot_security_checker import security_checker

        # Get all devices
        devices = db_manager.get_all_devices()

        if not devices:
            return dbc.Alert("No devices to analyze", color="info")

        # Get security assessment
        security_summary = security_checker.get_network_security_score(devices)

        # Determine color based on risk level
        risk_level = security_summary['risk_level']
        if risk_level == 'low':
            score_color = 'success'
            badge_color = 'success'
        elif risk_level == 'medium':
            score_color = 'warning'
            badge_color = 'warning'
        elif risk_level == 'high':
            score_color = 'danger'
            badge_color = 'warning'
        else:  # critical
            score_color = 'danger'
            badge_color = 'danger'

        return html.Div([
            dbc.Row([
                # Security Score
                dbc.Col([
                    html.Div([
                        html.H2(f"{security_summary['security_score']}", className=f"text-{score_color} mb-0",
                               style={'fontSize': '3rem', 'fontWeight': 'bold'}),
                        html.P("Security Score", className="text-muted mb-2"),
                        dbc.Badge(f"{risk_level.upper()} RISK", color=badge_color, className="mt-1")
                    ], className="text-center")
                ], width=3),

                # Metrics
                dbc.Col([
                    dbc.Row([
                        dbc.Col([
                            html.Div([
                                html.H4(security_summary['iot_devices_count'], className="text-primary mb-0"),
                                html.Small("IoT Devices", className="text-muted")
                            ], className="text-center")
                        ], width=4),
                        dbc.Col([
                            html.Div([
                                html.H4(security_summary['vulnerable_count'], className="text-danger mb-0"),
                                html.Small("Vulnerable", className="text-muted")
                            ], className="text-center")
                        ], width=4),
                        dbc.Col([
                            html.Div([
                                html.H4(security_summary['total_devices'], className="text-info mb-0"),
                                html.Small("Total Devices", className="text-muted")
                            ], className="text-center")
                        ], width=4)
                    ])
                ], width=5),

                # Recommendations
                dbc.Col([
                    html.Div([
                        html.H6([html.I(className="fa fa-lightbulb me-2"), "Top Recommendations"], className="mb-2"),
                        html.Ul([
                            html.Li(rec, className="small") for rec in security_summary['top_recommendations'][:3]
                        ], className="mb-0", style={'paddingLeft': '20px'})
                    ])
                ], width=4)
            ], className="align-items-center")
        ])

    # ========================================================================
    # NETWORK HEALTH
    # ========================================================================

    @app.callback(
        [Output('network-health', 'children'),
         Output('network-icon', 'className')],
        [Input('refresh-interval', 'n_intervals')]
    )
    def update_network_health(n):
        """Update network health status based on activity and alerts."""
        try:
            conn = get_db_connection()

            cursor = conn.cursor()

            # Get active devices in last hour
            cursor.execute('SELECT COUNT(DISTINCT device_ip) as count FROM devices WHERE last_seen >= datetime("now", "-1 hour")')
            active_devices = cursor.fetchone()['count']

            # Get connection count in last hour
            cursor.execute('SELECT COUNT(*) as count FROM connections WHERE timestamp >= datetime("now", "-1 hour")')
            connections = cursor.fetchone()['count']

            # Get recent critical/high alerts
            cursor.execute('''
                SELECT COUNT(*) as count FROM alerts
                WHERE severity IN ('critical', 'high')
                AND timestamp >= datetime("now", "-1 hour")
            ''')
            critical_alerts = cursor.fetchone()['count']


            # Determine health status
            if critical_alerts > 5:
                health = "Poor"
                icon_class = "fa fa-wifi fa-2x mb-2 text-danger"
            elif critical_alerts > 2:
                health = "Fair"
                icon_class = "fa fa-wifi fa-2x mb-2 text-warning"
            elif active_devices > 5 and connections > 100:
                health = "Excellent"
                icon_class = "fa fa-wifi fa-2x mb-2 text-success"
            elif active_devices > 0 or connections > 0:
                health = "Good"
                icon_class = "fa fa-wifi fa-2x mb-2 text-info"
            else:
                health = "Idle"
                icon_class = "fa fa-wifi fa-2x mb-2 text-secondary"

            return health, icon_class

        except Exception as e:
            logger.error(f"Error calculating network health: {e}")
            return "—", "fa fa-wifi fa-2x mb-2 text-muted"

    # ========================================================================
    # SANKEY TRAFFIC FLOW DIAGRAM
    # ========================================================================

    @app.callback(
        Output('traffic-flow-sankey', 'figure'),
        [Input('refresh-interval', 'n_intervals')]
    )
    def update_traffic_flow_sankey(n):
        """Update Sankey diagram showing network traffic flow."""
        try:
            conn = get_db_connection()

            cursor = conn.cursor()

            # Get traffic flows: Device → Protocol → Destination
            cursor.execute('''
                SELECT
                    device_ip,
                    protocol,
                    dest_ip,
                    SUM(bytes_sent + bytes_received) as total_bytes,
                    COUNT(*) as connection_count
                FROM connections
                WHERE timestamp >= datetime("now", "-1 hour")
                GROUP BY device_ip, protocol, dest_ip
                ORDER BY total_bytes DESC
                LIMIT 50
            ''')

            flows = cursor.fetchall()

            if not flows:
                fig = go.Figure()
                fig.update_layout(title="No Traffic Data Available", height=500)
                return fig

            # Build Sankey nodes and links
            nodes = {}
            node_labels = []
            node_colors = []

            def add_node(label, color):
                if label not in nodes:
                    nodes[label] = len(node_labels)
                    node_labels.append(label)
                    node_colors.append(color)
                return nodes[label]

            # Create links
            link_sources = []
            link_targets = []
            link_values = []
            link_colors = []

            for flow in flows:
                # Shorten device IP for display
                device_label = f"Device-{flow['device_ip'].split('.')[-1]}"
                proto_label = flow['protocol'] or 'tcp'
                dest_label = f"→ {flow['dest_ip'].split('.')[-1]}"

                # Add nodes with colors
                device_idx = add_node(device_label, 'rgba(59, 130, 246, 0.8)')  # Blue for devices
                proto_idx = add_node(proto_label, 'rgba(16, 185, 129, 0.8)')    # Green for protocols
                dest_idx = add_node(dest_label, 'rgba(245, 158, 11, 0.8)')      # Orange for destinations

                # Device → Protocol
                link_sources.append(device_idx)
                link_targets.append(proto_idx)
                link_values.append(flow['total_bytes'] / 1024)  # Convert to KB
                link_colors.append('rgba(59, 130, 246, 0.4)')

                # Protocol → Destination
                link_sources.append(proto_idx)
                link_targets.append(dest_idx)
                link_values.append(flow['total_bytes'] / 1024)  # Convert to KB
                link_colors.append('rgba(16, 185, 129, 0.4)')

            # Create Sankey diagram
            fig = go.Figure(data=[go.Sankey(
                node=dict(
                    pad=15,
                    thickness=20,
                    line=dict(color="black", width=0.5),
                    label=node_labels,
                    color=node_colors
                ),
                link=dict(
                    source=link_sources,
                    target=link_targets,
                    value=link_values,
                    color=link_colors
                )
            )])

            fig.update_layout(
                title=dict(
                    text="Network Traffic Flow - Last Hour",
                    x=0.5,
                    xanchor='center'
                ),
                font=dict(size=10),
                height=500,
                margin=dict(l=20, r=20, t=40, b=20)
            )

            return fig

        except Exception as e:
            logger.error(f"Error updating traffic flow sankey: {e}")
            fig = go.Figure()
            fig.update_layout(title=f"Error: {str(e)}", height=500)
            return fig

    # ========================================================================
    # ATTACK SURFACE LIST (OVERVIEW)
    # ========================================================================

    @app.callback(
        Output('attack-surface-list', 'children'),
        [Input('refresh-interval', 'n_intervals')]
    )
    def update_attack_surface(n):
        """Analyze and display attack surface - potential entry points."""
        try:
            conn = get_db_connection()

            cursor = conn.cursor()
            vulnerabilities = []

            # 1. Check for untrusted devices
            cursor.execute('SELECT COUNT(*) as count FROM devices WHERE is_trusted = 0 AND is_blocked = 0')
            untrusted = cursor.fetchone()['count']
            if untrusted > 0:
                vulnerabilities.append(dbc.Card([
                    dbc.CardBody([
                        html.Div([
                            html.I(className="fa fa-exclamation-triangle text-warning me-2", style={"fontSize": "1.5rem"}),
                            html.Div([
                                html.H6(f"{untrusted} Untrusted Devices", className="mb-1"),
                                html.P("Unverified devices can be exploited as entry points", className="mb-0 small text-muted"),
                                dbc.Badge("MEDIUM RISK", color="warning", className="mt-2")
                            ])
                        ], className="d-flex")
                    ])
                ], className="mb-3 border-warning"))

            # 2. Check for devices with critical alerts
            cursor.execute('''
                SELECT COUNT(DISTINCT device_ip) as count FROM alerts
                WHERE severity = 'critical' AND timestamp >= datetime("now", "-24 hours")
            ''')
            critical_devices = cursor.fetchone()['count']
            if critical_devices > 0:
                vulnerabilities.append(dbc.Card([
                    dbc.CardBody([
                        html.Div([
                            html.I(className="fa fa-skull-crossbones text-danger me-2", style={"fontSize": "1.5rem"}),
                            html.Div([
                                html.H6(f"{critical_devices} Devices Under Attack", className="mb-1"),
                                html.P("Devices with active critical alerts are vulnerable", className="mb-0 small text-muted"),
                                dbc.Badge("HIGH RISK", color="danger", className="mt-2")
                            ])
                        ], className="d-flex")
                    ])
                ], className="mb-3 border-danger"))

            # 3. Check for high-traffic devices (potential C2)
            cursor.execute('''
                SELECT COUNT(DISTINCT device_ip) as count FROM connections
                WHERE timestamp >= datetime("now", "-1 hour")
                GROUP BY device_ip
                HAVING COUNT(*) > 500
            ''')
            high_traffic = len(cursor.fetchall())
            if high_traffic > 0:
                vulnerabilities.append(dbc.Card([
                    dbc.CardBody([
                        html.Div([
                            html.I(className="fa fa-wifi text-info me-2", style={"fontSize": "1.5rem"}),
                            html.Div([
                                html.H6(f"{high_traffic} High-Activity Devices", className="mb-1"),
                                html.P("Unusually high connection rates may indicate compromise", className="mb-0 small text-muted"),
                                dbc.Badge("MEDIUM RISK", color="info", className="mt-2")
                            ])
                        ], className="d-flex")
                    ])
                ], className="mb-3 border-info"))


            if not vulnerabilities:
                return dbc.Alert([
                    html.I(className="fa fa-shield-alt me-2"),
                    html.Strong("No Major Vulnerabilities Detected"),
                    html.P("Your network appears secure with minimal attack surface.", className="mb-0 mt-2")
                ], color="success")

            return html.Div([
                html.H5([html.I(className="fa fa-exclamation-circle me-2"), "Identified Entry Points"], className="mb-3"),
                *vulnerabilities,
                dbc.Alert([
                    html.I(className="fa fa-lightbulb me-2"),
                    "Recommendation: Review and address these vulnerabilities to reduce attack surface."
                ], color="warning", className="mt-3")
            ])

        except Exception as e:
            logger.error(f"Error analyzing attack surface: {e}")
            return html.P(f"Error: {str(e)}", className="text-danger")

    # ========================================================================
    # DEVICE COUNT + BANDWIDTH STAT CARDS
    # ========================================================================

    @app.callback(
        [Output('device-count-stat', 'children'),
         Output('bandwidth-stat', 'children')],
        [Input('refresh-interval', 'n_intervals')]
    )
    def update_network_stats(n):
        """Update network activity card with active devices and connection counts."""
        try:
            conn = get_db_connection()

            cursor = conn.cursor()

            # Get device count
            cursor.execute('SELECT COUNT(DISTINCT device_ip) as count FROM devices WHERE last_seen >= datetime("now", "-1 hour")')
            device_count = cursor.fetchone()['count']

            # Get total connections in last hour
            cursor.execute('SELECT COUNT(*) as count FROM connections WHERE timestamp >= datetime("now", "-1 hour")')
            connections = cursor.fetchone()['count']
            bandwidth = f"{connections//1000}K" if connections >= 1000 else str(connections)

            return str(device_count), bandwidth
        except Exception as e:
            logger.error(f"Error updating network stats: {e}")
            return "—", "—"

    # ========================================================================
    # SECURITY SCORE + LAST SCAN TIME
    # ========================================================================

    @app.callback(
        [Output('security-score', 'children'),
         Output('last-scan-time', 'children')],
        [Input('refresh-interval', 'n_intervals')]
    )
    def update_security_status(n):
        """Update security status card."""
        try:
            conn = get_db_connection()

            cursor = conn.cursor()

            # Calculate security score (100 - weighted alerts)
            cursor.execute('''
                SELECT
                    SUM(CASE WHEN severity = 'critical' THEN 20
                             WHEN severity = 'high' THEN 10
                             WHEN severity = 'medium' THEN 5
                             WHEN severity = 'low' THEN 2
                             ELSE 0 END) as threat_points
                FROM alerts
                WHERE timestamp >= datetime("now", "-24 hours")
            ''')
            result = cursor.fetchone()
            threat_points = result['threat_points'] if result['threat_points'] else 0
            security_score = max(0, min(100, 100 - threat_points))

            # Get last scan time
            cursor.execute('SELECT MAX(timestamp) as last_scan FROM connections')
            last_scan = cursor.fetchone()['last_scan']


            # Format score
            score_text = f"{security_score}/100"

            # Format time
            if last_scan:
                last_scan_dt = datetime.strptime(last_scan, '%Y-%m-%d %H:%M:%S')
                time_diff = datetime.now() - last_scan_dt
                if time_diff.seconds < 60:
                    time_text = "Just now"
                elif time_diff.seconds < 3600:
                    time_text = f"{time_diff.seconds // 60}m ago"
                else:
                    time_text = f"{time_diff.seconds // 3600}h ago"
            else:
                time_text = "Never"

            return score_text, time_text
        except Exception as e:
            logger.error(f"Error updating security status: {e}")
            return "—", "—"

    # ========================================================================
    # RECENT ACTIVITY LIST
    # ========================================================================

    @app.callback(
        Output('recent-activity-list', 'children'),
        [Input('refresh-interval', 'n_intervals')]
    )
    def update_recent_activity(n):
        """Update recent activity list."""
        try:
            conn = get_db_connection()

            cursor = conn.cursor()
            activities = []

            # Get last device connected
            cursor.execute('''
                SELECT device_ip, last_seen
                FROM devices
                ORDER BY last_seen DESC
                LIMIT 1
            ''')
            last_device = cursor.fetchone()
            if last_device:
                time_ago = _format_time_ago(last_device['last_seen'])
                activities.append(html.Div([
                    html.I(className="fa fa-laptop text-primary me-2", style={"fontSize": "0.9rem"}),
                    html.Span(f"Device {last_device['device_ip']}", className="fw-bold"),
                    html.Span(f" connected {time_ago}", className="text-muted")
                ], className="mb-2"))

            # Get last alert
            cursor.execute('''
                SELECT severity, explanation, timestamp
                FROM alerts
                ORDER BY timestamp DESC
                LIMIT 1
            ''')
            last_alert = cursor.fetchone()
            if last_alert:
                time_ago = _format_time_ago(last_alert['timestamp'])
                severity_icon = "fa-skull-crossbones" if last_alert['severity'] == 'critical' else "fa-exclamation-triangle"
                activities.append(html.Div([
                    html.I(className=f"fa {severity_icon} text-danger me-2", style={"fontSize": "0.9rem"}),
                    html.Span(f"{last_alert['severity'].title()} alert", className="fw-bold"),
                    html.Span(f" {time_ago}", className="text-muted")
                ], className="mb-2"))

            # Get last scan
            cursor.execute('''
                SELECT MAX(timestamp) as last_scan
                FROM connections
            ''')
            last_scan = cursor.fetchone()
            if last_scan and last_scan['last_scan']:
                time_ago = _format_time_ago(last_scan['last_scan'])
                activities.append(html.Div([
                    html.I(className="fa fa-search text-success me-2", style={"fontSize": "0.9rem"}),
                    html.Span("Network scan", className="fw-bold"),
                    html.Span(f" completed {time_ago}", className="text-muted")
                ], className="mb-0"))


            return activities if activities else html.P("No recent activity", className="text-muted text-center mb-0")
        except Exception as e:
            logger.error(f"Error updating recent activity: {e}")
            return html.P("Unable to load activity", className="text-muted text-center mb-0")

    # ========================================================================
    # SECURITY RECOMMENDATIONS LIST
    # ========================================================================

    @app.callback(
        Output('recommendations-list', 'children'),
        [Input('refresh-interval', 'n_intervals')]
    )
    def update_recommendations(n):
        """Update security recommendations."""
        try:
            conn = get_db_connection()

            cursor = conn.cursor()
            recommendations = []

            # Check for critical alerts
            cursor.execute('''
                SELECT COUNT(*) as count
                FROM alerts
                WHERE severity = 'critical'
                AND timestamp >= datetime("now", "-24 hours")
            ''')
            critical_count = cursor.fetchone()['count']
            if critical_count > 0:
                recommendations.append(html.Div([
                    html.I(className="fa fa-exclamation-circle text-danger me-2"),
                    html.Span(f"Address {critical_count} critical alert(s) immediately", className="small")
                ], className="mb-2"))

            # Check for unprotected devices
            cursor.execute('''
                SELECT COUNT(*) as count
                FROM devices
                WHERE is_trusted = 0 AND is_blocked = 0
            ''')
            unknown_devices = cursor.fetchone()['count']
            if unknown_devices > 0:
                recommendations.append(html.Div([
                    html.I(className="fa fa-shield-alt text-warning me-2"),
                    html.Span(f"Review {unknown_devices} unverified device(s)", className="small")
                ], className="mb-2"))

            # General recommendations
            if not recommendations:
                recommendations.append(html.Div([
                    html.I(className="fa fa-check-circle text-success me-2"),
                    html.Span("System is secure. Keep monitoring active.", className="small")
                ], className="mb-0"))

            return recommendations
        except Exception as e:
            logger.error(f"Error updating recommendations: {e}")
            return html.P("Unable to load", className="text-muted text-center mb-0")

    # ========================================================================
    # LIVE THREAT FEED
    # ========================================================================

    @app.callback(
        Output('live-threat-feed', 'children'),
        [Input('refresh-interval', 'n_intervals')]
    )
    def update_live_threat_feed(n):
        """Update live threat feed with recent security events."""
        try:
            conn = get_db_connection()

            cursor = conn.cursor()

            # Get recent threats (alerts + suspicious connections)
            cursor.execute('''
                SELECT
                    timestamp,
                    severity,
                    device_ip,
                    explanation,
                    'alert' as event_type
                FROM alerts
                WHERE timestamp >= datetime("now", "-1 hour")
                UNION ALL
                SELECT
                    c.timestamp,
                    'medium' as severity,
                    c.device_ip,
                    'Suspicious connection to ' || c.dest_ip || ':' || c.dest_port as explanation,
                    'connection' as event_type
                FROM connections c
                WHERE c.timestamp >= datetime("now", "-1 hour")
                AND (c.dest_port IN (22, 23, 3389, 445) OR c.bytes_sent > 10000000)
                ORDER BY timestamp DESC
                LIMIT 15
            ''')

            threats = cursor.fetchall()

            if not threats:
                return html.P("No threats detected", className="text-success text-center mb-0 py-3 small")

            feed_items = []
            for threat in threats:
                time_ago = _format_time_ago(threat['timestamp'])
                severity = threat['severity']

                # Severity styling
                severity_config = {
                    'critical': {'icon': 'fa-skull-crossbones', 'color': '#ef4444', 'bg': 'rgba(239, 68, 68, 0.1)'},
                    'high': {'icon': 'fa-exclamation-triangle', 'color': '#f59e0b', 'bg': 'rgba(245, 158, 11, 0.1)'},
                    'medium': {'icon': 'fa-exclamation-circle', 'color': '#3b82f6', 'bg': 'rgba(59, 130, 246, 0.1)'},
                    'low': {'icon': 'fa-info-circle', 'color': '#6b7280', 'bg': 'rgba(107, 114, 128, 0.1)'}
                }

                config_item = severity_config.get(severity, severity_config['low'])

                feed_items.append(
                    html.Div([
                        html.Div([
                            html.I(className=f"fa {config_item['icon']} me-2", style={"color": config_item['color'], "fontSize": "0.9rem"}),
                            html.Div([
                                html.Div([
                                    html.Span(f"{threat['device_ip']}", className="fw-bold", style={"fontSize": "0.75rem"}),
                                    html.Span(f" • {time_ago}", className="text-muted ms-1", style={"fontSize": "0.65rem"})
                                ]),
                                html.P(threat['explanation'], className="mb-0 text-muted", style={
                                    "fontSize": "0.7rem",
                                    "lineHeight": "1.3",
                                    "marginTop": "2px"
                                })
                            ], className="flex-grow-1")
                        ], className="d-flex align-items-start")
                    ], className="threat-feed-item", style={
                        "padding": "8px",
                        "marginBottom": "6px",
                        "borderRadius": "6px",
                        "backgroundColor": config_item['bg'],
                        "borderLeft": f"3px solid {config_item['color']}",
                        "animation": "slideInRight 0.3s ease-out"
                    })
                )

            return feed_items

        except Exception as e:
            logger.error(f"Error updating live threat feed: {e}")
            return html.P("Unable to load threats", className="text-muted text-center mb-0 py-3 small")

    # ========================================================================
    # USER ROLE STORE ON PAGE LOAD
    # ========================================================================

    @app.callback(
        Output('user-role-store', 'data'),
        Input('url', 'pathname'),
        prevent_initial_call=False
    )
    def update_user_role(pathname):
        """Store current user's role for permission checks."""
        if current_user.is_authenticated:
            return {'role': current_user.role}
        return {'role': 'viewer'}

    # ========================================================================
    # AI THREAT PREDICTIONS
    # ========================================================================

    @app.callback(
        Output('threat-forecast-content', 'children'),
        [Input('refresh-interval', 'n_intervals')]
    )
    def update_threat_forecast(n):
        """AI-powered threat predictions based on historical patterns."""
        try:
            conn = get_db_connection()

            cursor = conn.cursor()

            # Analyze alert patterns from last 7 days
            cursor.execute('''
                SELECT
                    DATE(timestamp) as date,
                    severity,
                    COUNT(*) as count
                FROM alerts
                WHERE timestamp >= datetime("now", "-7 days")
                GROUP BY DATE(timestamp), severity
                ORDER BY date DESC
            ''')
            patterns = cursor.fetchall()

            # Get most common attack types
            cursor.execute('''
                SELECT explanation, COUNT(*) as frequency
                FROM alerts
                WHERE timestamp >= datetime("now", "-7 days")
                GROUP BY explanation
                ORDER BY frequency DESC
                LIMIT 3
            ''')
            common_attacks = cursor.fetchall()


            # Simple prediction logic based on trends
            predictions = []

            if patterns:
                # Check if alerts are increasing
                recent_count = sum(p['count'] for p in patterns[:2])  # Last 2 days
                older_count = sum(p['count'] for p in patterns[2:4])  # Days 3-4

                if recent_count > older_count * 1.5:
                    predictions.append(html.Div([
                        html.I(className="fa fa-arrow-up text-danger me-2"),
                        html.Strong("Rising Threat Level", className="text-danger"),
                        html.P("Alert frequency increased 50% - expect continued attacks",
                               className="mb-0 mt-1 small text-muted")
                    ], className="mb-3"))

            # Predict likely attack types
            if common_attacks:
                top_attack = common_attacks[0]
                predictions.append(html.Div([
                    html.I(className="fa fa-crosshairs text-warning me-2"),
                    html.Strong("Likely Attack Vector", className="text-warning"),
                    html.P(f"High probability: {top_attack['explanation'][:50]}...",
                           className="mb-0 mt-1 small text-muted")
                ], className="mb-3"))

            # Time-based prediction
            from datetime import datetime
            hour = datetime.now().hour
            if 0 <= hour < 6:
                predictions.append(html.Div([
                    html.I(className="fa fa-moon text-info me-2"),
                    html.Strong("Off-Hours Activity", className="text-info"),
                    html.P("Unusual activity during night hours may indicate automated attacks",
                           className="mb-0 mt-1 small text-muted")
                ], className="mb-3"))

            if not predictions:
                return html.Div([
                    html.I(className="fa fa-shield-alt text-success me-2"),
                    html.P("No immediate threats predicted", className="mb-0 small")
                ], className="text-center py-3")

            return html.Div([
                html.H6([html.I(className="fa fa-crystal-ball me-2"), "Next 24h Forecast"],
                        className="mb-3 text-muted", style={"fontSize": "0.85rem"}),
                *predictions,
                html.Small([
                    html.I(className="fa fa-info-circle me-1"),
                    "Based on 7-day pattern analysis"
                ], className="text-muted")
            ])

        except Exception as e:
            logger.error(f"Error generating threat forecast: {e}")
            return html.P("Forecast unavailable", className="text-muted small")
