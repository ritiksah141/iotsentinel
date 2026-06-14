"""
Overview-tab callbacks — Security score, network topology, alerts panel,
threat feed, metrics, real-time stat cards, system health, ML model info.

Extracted from app.py.  All callbacks are registered via ``register(app)``.
"""

import logging
from datetime import datetime, timedelta

from utils.alert_explainer import source_label as _source_label, source_badge_class as _source_badge_class

import dash
import dash_bootstrap_components as dbc
import pandas as pd
import plotly.express as px
import plotly.graph_objs as go
from dash import Input, Output, State, callback_context, html, ALL, no_update

from flask_login import current_user

import time

from dashboard.shared import (
    db_manager,
    chart_factory,
    config,
    network_security_scorer,
    iot_protocol_analyzer,
    iot_threat_detector,
    logger as _shared_logger,
    ai_assistant,
    get_db_connection,
    get_bandwidth_stats,
    get_threats_blocked,
    get_latest_alerts_content,
    get_devices_with_status,
    get_latest_alerts,
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
# Security-score memo — shared between update_security_summary_report and
# update_iot_security_widget so both callbacks reuse one computation per tick.
# TTL matches the WS cycle (10 s gives safe overlap with the 3 s interval).
# ---------------------------------------------------------------------------
_SCORE_MEMO_TTL = 10  # seconds
_score_memo: dict = {'ts': 0.0, 'devices': None, 'summary': None}


def _get_security_summary_cached():
    """Return (devices, security_summary) reusing the cached result within TTL."""
    now = time.time()
    if now - _score_memo['ts'] < _SCORE_MEMO_TTL and _score_memo['summary'] is not None:
        return _score_memo['devices'], _score_memo['summary']
    from utils.iot_security_checker import security_checker
    devices = db_manager.get_all_devices()
    summary = security_checker.get_network_security_score(devices) if devices else None
    _score_memo.update({'ts': now, 'devices': devices, 'summary': summary})
    return devices, summary


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
        [State('resolved-theme-store', 'data')],
        prevent_initial_call='initial_duplicate'
    )
    def update_security_score_dashboard(n_intervals, refresh_clicks, theme_data):
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
            is_dark = (theme_data or {}).get('theme') == 'dark'
            gauge_fig = chart_factory.create_gauge_chart(
                value=overall_score,
                max_value=100,
                title=f"Network Security Score: {grade}",
                thresholds=[50, 80, 100],  # Red 0-49, Yellow 50-79, Green 80-100
                colors=['#dc3545', '#ffc107', '#28a745'],
                dark_mode=is_dark
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
            insecure_conns = encryption.get('insecure_connections', 0)
            if insecure_conns == 0 and secure_ratio == 0:
                encryption_detail = "No insecure protocols detected"
            else:
                encryption_detail = f"{secure_ratio:.0f}% identified as secure"

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

                text_color = '#e4e4e7' if is_dark else '#333333'
                history_fig.update_layout(
                    paper_bgcolor='rgba(0,0,0,0)',
                    plot_bgcolor='rgba(0,0,0,0)',
                    font={'color': text_color},
                    margin=dict(l=40, r=20, t=20, b=40),
                    xaxis=dict(title='Time', showgrid=True),
                    yaxis=dict(title='Score', range=[0, 100], showgrid=True),
                    hovermode='x unified'
                )
            else:
                # No historical data available
                history_fig = go.Figure()
                text_color = '#e4e4e7' if is_dark else '#333333'
                history_fig.add_annotation(
                    text="No historical data available yet",
                    xref="paper", yref="paper",
                    x=0.5, y=0.5, showarrow=False,
                    font=dict(size=14, color=text_color)
                )
                history_fig.update_layout(
                    paper_bgcolor='rgba(0,0,0,0)',
                    plot_bgcolor='rgba(0,0,0,0)',
                    font={'color': text_color},
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
            return "-", "-"

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
            return "-", "-", "-"

        # Use cached queries (30s TTL) - much faster than direct DB access
        try:
            bandwidth_stats = get_bandwidth_stats()
            threats_count = get_threats_blocked()
            connection_count = ws_message.get('connection_count', 0)

            return bandwidth_stats['formatted'], str(threats_count), str(connection_count)
        except Exception as e:
            logger.error(f"Error calculating bandwidth/threats: {e}")
            return "-", "-", "-"

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
        State('resolved-theme-store', 'data'),
        prevent_initial_call=True  # Performance: Lazy load 3D graph only when data arrives
    )
    def update_network_graph_3d(ws_message, theme_data):
        """Enhanced 3D graph with force-directed layout and better visuals"""
        is_dark = (theme_data or {}).get('theme') == 'dark'
        text_color = '#e4e4e7' if is_dark else '#333333'
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
            node_text.append(f"{d.get('custom_name') or d.get('device_name') or d.get('device_ip')}<br>" +
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

        # Layout — transparent so glass card shows through, text adapts to theme
        layout = go.Layout(
            title=dict(
                text='3D Network Topology - Force-Directed Layout',
                font=dict(size=16, color=text_color)
            ),
            paper_bgcolor='rgba(0,0,0,0)',
            showlegend=False,
            font=dict(color=text_color),
            scene=dict(
                bgcolor='rgba(0,0,0,0)',
                xaxis=dict(showbackground=False, showticklabels=False, title=''),
                yaxis=dict(showbackground=False, showticklabels=False, title=''),
                zaxis=dict(showbackground=False, showticklabels=False, title=''),
                camera=dict(eye=dict(x=1.5, y=1.5, z=1.5))
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
        State('resolved-theme-store', 'data'),
        prevent_initial_call=True  # Performance: Lazy load traffic timeline
    )
    def update_traffic_timeline(ws_message, theme_data):
        is_dark = (theme_data or {}).get('theme') == 'dark'
        text_color = '#e4e4e7' if is_dark else '#333333'
        base_layout = dict(plot_bgcolor='rgba(0,0,0,0)', paper_bgcolor='rgba(0,0,0,0)',
                           font={'color': text_color})
        if ws_message is None:
            # Return empty figure during initial load
            fig = go.Figure()
            fig.update_layout(**base_layout)
            return fig
        traffic_data = ws_message.get('traffic_timeline', [])
        if not traffic_data:
            fig = go.Figure()
            fig.update_layout(title="No traffic data available", xaxis_title="Hour",
                              yaxis_title="Bytes", **base_layout)
            return fig
        df = pd.DataFrame(traffic_data)
        fig = px.area(df, x='hour', y='total_bytes', title="Network Traffic by Hour",
                      color_discrete_sequence=['#007bff'])
        fig.update_layout(xaxis_title="Hour", yaxis_title="Total Bytes",
                          showlegend=False, **base_layout)
        fig.update_traces(fill='tozeroy')
        return fig

    # ========================================================================
    # PROTOCOL DISTRIBUTION PIE
    # ========================================================================

    @app.callback(
        Output('protocol-pie', 'figure'),
        [Input('ws', 'message'),
         Input('global-device-filter', 'data')],
        State('resolved-theme-store', 'data'),
        prevent_initial_call=True  # Performance: Lazy load protocol chart
    )
    def update_protocol_pie(ws_message, device_filter, theme_data):
        is_dark = (theme_data or {}).get('theme') == 'dark'
        text_color = '#e4e4e7' if is_dark else '#333333'
        if ws_message is None:
            raise dash.exceptions.PreventUpdate
        protocol_data = ws_message.get('protocol_distribution', [])
        if not protocol_data:
            fig = go.Figure()
            fig.update_layout(title="No protocol data available",
                              plot_bgcolor='rgba(0,0,0,0)', paper_bgcolor='rgba(0,0,0,0)',
                              font={'color': text_color})
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
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)',
            font={'color': text_color},
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
            return dbc.Alert([html.I(className="fa fa-satellite-dish me-2"), "No devices found."], color="info", className="compact-alert")
        cards = []
        for device in devices:
            status = device.get('status', 'normal')
            device_name = device.get('custom_name') or device.get('device_name') or device['device_ip']
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
                        className="protocol-badge-sm ms-1 u-text-badge"
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
            return dbc.Alert([html.I(className="fa fa-network-wired me-2"), "No active devices."], color="info", className="compact-alert")
        items = []
        for device in devices:
            status = device.get('status', 'normal')
            status_text = device.get('status_text', 'Unknown')
            device_name = device.get('custom_name') or device.get('device_name') or device['device_ip']
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
        State('resolved-theme-store', 'data'),
        prevent_initial_call=True
    )
    def update_alert_timeline(ws_message, severity_filter, theme_data):
        is_dark = (theme_data or {}).get('theme') == 'dark'
        text_color = '#e4e4e7' if is_dark else '#333333'
        base_layout = dict(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
                           font={'color': text_color})
        if ws_message is None:
            # Return empty figure during initial load
            fig = go.Figure()
            fig.update_layout(**base_layout)
            return fig
        alert_timeline_data = ws_message.get('alert_timeline', [])
        if not alert_timeline_data:
            fig = go.Figure()
            fig.update_layout(title="No alerts in the last 7 days", **base_layout)
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
            dragmode='zoom',
            modebar={'orientation': 'v'},
            modebar_add=['pan2d', 'select2d', 'lasso2d', 'resetScale2d'],
            **base_layout
        )

        return fig

    # ========================================================================
    # ANOMALY SCORE HISTOGRAM
    # ========================================================================

    @app.callback(
        Output('anomaly-distribution', 'figure'),
        Input('ws', 'message'),
        State('resolved-theme-store', 'data'),
        prevent_initial_call=True  # W15: skip page-load spike; WS data arrives shortly after
    )
    def update_anomaly_distribution(ws_message, theme_data):
        is_dark = (theme_data or {}).get('theme') == 'dark'
        text_color = '#e4e4e7' if is_dark else '#333333'
        base_layout = dict(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
                           font={'color': text_color})
        if ws_message is None:
            raise dash.exceptions.PreventUpdate
        anomaly_data = ws_message.get('anomaly_distribution', [])
        if not anomaly_data:
            fig = go.Figure()
            fig.update_layout(title="No anomaly data available", **base_layout)
            return fig
        df = pd.DataFrame(anomaly_data)
        fig = px.histogram(df, x="anomaly_score", title="Anomaly Score Distribution",
                           color_discrete_sequence=['#007bff'], nbins=30)
        fig.update_layout(xaxis_title="Anomaly Score", yaxis_title="Frequency", **base_layout)
        fig.add_vline(x=-0.5, line_dash="dash", line_color="red", annotation_text="Anomaly Threshold")
        return fig

    # ========================================================================
    # BANDWIDTH USAGE BAR
    # ========================================================================

    @app.callback(
        Output('bandwidth-chart', 'figure'),
        Input('ws', 'message'),
        State('resolved-theme-store', 'data'),
        prevent_initial_call=True  # W15: skip page-load spike
    )
    def update_bandwidth_chart(ws_message, theme_data):
        is_dark = (theme_data or {}).get('theme') == 'dark'
        text_color = '#e4e4e7' if is_dark else '#333333'
        base_layout = dict(plot_bgcolor='rgba(0,0,0,0)', paper_bgcolor='rgba(0,0,0,0)',
                           font={'color': text_color})
        if ws_message is None:
            raise dash.exceptions.PreventUpdate
        bandwidth_data = ws_message.get('bandwidth_chart', [])
        if not bandwidth_data:
            fig = go.Figure()
            fig.update_layout(title="No Bandwidth Data Available", **base_layout)
            return fig
        df = pd.DataFrame(bandwidth_data)
        fig = px.bar(df, x='device_ip', y='total_bytes',
                     title="Top 10 Devices by Bandwidth Usage",
                     color_discrete_sequence=['#28a745'])
        fig.update_layout(xaxis_title="Device IP", yaxis_title="Total Bytes", **base_layout)
        return fig

    # ========================================================================
    # DEVICE ACTIVITY HEATMAP
    # ========================================================================

    @app.callback(
        Output('device-heatmap', 'figure'),
        [Input('ws', 'message'),
         Input('global-device-filter', 'data')],
        State('resolved-theme-store', 'data'),
        prevent_initial_call=True
    )
    def update_device_heatmap(ws_message, device_filter, theme_data):
        is_dark = (theme_data or {}).get('theme') == 'dark'
        text_color = '#e4e4e7' if is_dark else '#333333'
        base_layout = dict(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
                           font={'color': text_color})
        if ws_message is None:
            raise dash.exceptions.PreventUpdate
        heatmap_data = ws_message.get('device_activity_heatmap', [])
        if not heatmap_data:
            fig = go.Figure()
            fig.update_layout(title="No activity data available", **base_layout)
            return fig

        df = pd.DataFrame(heatmap_data)

        # Apply device filter if active
        if device_filter:
            df = df[df['device_ip'] == device_filter]

        # Create enhanced heatmap with custom hover data
        cs = 'Blues' if not is_dark else 'Viridis'
        fig = px.density_heatmap(
            df, x="hour", y="device_ip", z="count",
            title="Device Activity by Hour (Click device to filter)",
            color_continuous_scale=cs,
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
            modebar_add=['pan2d', 'zoomIn2d', 'zoomOut2d', 'resetScale2d'],
            **base_layout
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
            from datetime import datetime

            # Get devices + security assessment (shared memo — avoids duplicate compute)
            devices, security_summary = _get_security_summary_cached()

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
                                                   className=f"text-{risk_color} mb-0 u-text-display"),
                                            html.P("Overall Security Score", className="text-muted"),
                                            dbc.Badge(f"{risk_level.upper()} RISK", color=risk_color, className="mt-2")
                                        ], className="text-center")
                                    ], xs=6, sm=3),
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
                                    ], xs=6, sm=3),
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
                                    ], xs=6, sm=3),
                                    dbc.Col([
                                        html.Div([
                                            html.H4(total_alerts, className="text-secondary mb-1"),
                                            html.Small("Total Alerts (All Time)", className="text-muted")
                                        ], className="text-center mb-3"),
                                        html.Div([
                                            html.H4(unacknowledged_alerts, className="text-danger mb-1"),
                                            html.Small("Unacknowledged Alerts", className="text-muted")
                                        ], className="text-center")
                                    ], xs=6, sm=3)
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
                                html.I(className="fa fa-exclamation-triangle me-2 text-danger"),
                                html.Strong("Alert Statistics")
                            ], className="glass-card-header"),
                            dbc.CardBody([
                                html.H6("Last 24 Hours", className="mb-3"),
                                dbc.Row([
                                    dbc.Col([
                                        html.Div([
                                            html.H5(alerts_24h.get('critical', 0), className="text-danger mb-0"),
                                            html.Small("Critical", className="text-muted")
                                        ], className="text-center")
                                    ], xs=6, sm=3),
                                    dbc.Col([
                                        html.Div([
                                            html.H5(alerts_24h.get('high', 0), className="text-warning mb-0"),
                                            html.Small("High", className="text-muted")
                                        ], className="text-center")
                                    ], xs=6, sm=3),
                                    dbc.Col([
                                        html.Div([
                                            html.H5(alerts_24h.get('medium', 0), className="text-info mb-0"),
                                            html.Small("Medium", className="text-muted")
                                        ], className="text-center")
                                    ], xs=6, sm=3),
                                    dbc.Col([
                                        html.Div([
                                            html.H5(alerts_24h.get('low', 0), className="text-secondary mb-0"),
                                            html.Small("Low", className="text-muted")
                                        ], className="text-center")
                                    ], xs=6, sm=3)
                                ], className="mb-3"),
                                html.Hr(),
                                html.H6("Last 7 Days", className="mb-3"),
                                dbc.Row([
                                    dbc.Col([
                                        html.Div([
                                            html.H5(alerts_7d.get('critical', 0), className="text-danger mb-0"),
                                            html.Small("Critical", className="text-muted")
                                        ], className="text-center")
                                    ], xs=6, sm=3),
                                    dbc.Col([
                                        html.Div([
                                            html.H5(alerts_7d.get('high', 0), className="text-warning mb-0"),
                                            html.Small("High", className="text-muted")
                                        ], className="text-center")
                                    ], xs=6, sm=3),
                                    dbc.Col([
                                        html.Div([
                                            html.H5(alerts_7d.get('medium', 0), className="text-info mb-0"),
                                            html.Small("Medium", className="text-muted")
                                        ], className="text-center")
                                    ], xs=6, sm=3),
                                    dbc.Col([
                                        html.Div([
                                            html.H5(alerts_7d.get('low', 0), className="text-secondary mb-0"),
                                            html.Small("Low", className="text-muted")
                                        ], className="text-center")
                                    ], xs=6, sm=3)
                                ])
                            ])
                        ], className="mb-4 shadow-sm")
                    ], xs=12, md=6),

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
                                    ], xs=12, md=6),
                                    dbc.Col([
                                        html.Div([
                                            html.I(className="fa fa-ban fa-3x text-danger mb-2"),
                                            html.H4(blocked_devices, className="mb-0"),
                                            html.Small("Blocked Devices", className="text-muted")
                                        ], className="text-center")
                                    ], xs=12, md=6)
                                ], className="mb-3"),
                                html.Hr(),
                                dbc.Progress([
                                    dbc.Progress(
                                        value=(trusted_devices / len(devices) * 100) if devices else 0,
                                        color="success",
                                        bar=True,
                                        label=f"{int((trusted_devices / len(devices) * 100) if devices else 0)}% Trusted"
                                    )
                                ], className="progress-lg")
                            ])
                        ], className="mb-4 shadow-sm")
                    ], xs=12, md=6)
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
                                            html.Th("#", className="u-col-w-sm"),
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
                                ], bordered=True, hover=True, dark=False, size="sm", responsive=True, className="table-adaptive")
                            ])
                        ], className="mb-4 shadow-sm")
                    ], xs=12, md=6),

                    # Recommendations
                    dbc.Col([
                        dbc.Card([
                            dbc.CardHeader([
                                html.I(className="fa fa-lightbulb me-2 text-success"),
                                html.Strong("Security Recommendations")
                            ], className="glass-card-header"),
                            dbc.CardBody([
                                html.Ul([
                                    html.Li(rec, className="mb-2")
                                    for rec in (security_summary['top_recommendations'][:5] if security_summary else [
                                        "Add devices to your network to start monitoring",
                                        "Configure trusted devices for better security posture",
                                        "Review and acknowledge pending alerts"
                                    ])
                                ], className="ps-4")
                            ])
                        ], className="mb-4 shadow-sm")
                    ], xs=12, md=6)
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
                        ], xs=12, md=6),
                        dbc.Col([
                            html.H5(f"{ram_usage:.0f}%", className="text-primary mb-2"),
                            html.P("Memory Usage", className="small text-muted mb-2"),
                            dbc.Progress(value=ram_usage, color="primary" if ram_usage < 70 else "warning" if ram_usage < 90 else "danger", className="mb-2"),
                            html.Small("✓ Efficient operation" if ram_usage < 70 else "⚠️ High usage" if ram_usage < 90 else "❌ Critical",
                                      className=f"text-{'success' if ram_usage < 70 else 'warning' if ram_usage < 90 else 'danger'}")
                        ], xs=12, md=6)
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
                        ], xs=12, sm=4),
                        dbc.Col([
                            html.Div([
                                html.I(className="fa fa-network-wired fa-2x text-info mb-2"),
                                html.H6(f"{total_connections:,}" if isinstance(total_connections, int) else "Active", className="mb-0"),
                                html.Small("Connections tracked", className="text-muted")
                            ], className="text-center")
                        ], xs=12, sm=4),
                        dbc.Col([
                            html.Div([
                                html.I(className="fa fa-shield-alt fa-2x text-success mb-2"),
                                html.H6("High", className="mb-0"),
                                html.Small("Detection confidence", className="text-muted")
                            ], className="text-center")
                        ], xs=12, sm=4)
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
                            html.H4(f"{pi_watts:.0f}W", className="text-success mb-1 u-text-xl"),
                            html.P("Power Usage", className="small text-muted mb-0"),
                            html.Small(f"vs {desktop_watts:.0f}W", className="text-muted u-text-xs")
                        ], xs=6, sm=6, md=3, className="text-center mb-2 mb-md-0"),
                        dbc.Col([
                            html.H4(f"{co2_kg:.0f} kg", className="text-success mb-1 u-text-xl"),
                            html.P("CO₂ Saved/Year", className="small text-muted mb-0"),
                            html.Small(f"{trees_equivalent:.0f} trees", className="text-muted u-text-xs")
                        ], xs=6, sm=6, md=3, className="text-center mb-2 mb-md-0"),
                        dbc.Col([
                            html.H4(f"£{cost_saved_gbp:.0f}", className="text-success mb-1 u-text-xl"),
                            html.P("Cost Saved/Year", className="small text-muted mb-0"),
                            html.Small("at £0.30/kWh", className="text-muted u-text-xs")
                        ], xs=6, sm=6, md=3, className="text-center mb-2 mb-md-0"),
                        dbc.Col([
                            html.P("UN SDGs:", className="small mb-1 text-muted u-text-xs"),
                            html.Div([
                                dbc.Badge("SDG 7", color="warning", className="me-1 u-text-badge", title="Affordable & Clean Energy"),
                                dbc.Badge("SDG 12", color="warning", className="me-1 u-text-badge", title="Responsible Consumption"),
                                dbc.Badge("SDG 13", color="warning", className="u-text-badge", title="Climate Action")
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
                ], className="glass-card-header"),
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
                        ], xs=6, sm=3, className="text-center"),
                        dbc.Col([
                            html.H5("12", className="text-primary mb-1"),
                            html.P("Log Types Generated", className="small text-muted mb-0")
                        ], xs=6, sm=3, className="text-center"),
                        dbc.Col([
                            html.H5("20+ years", className="text-primary mb-1"),
                            html.P("Battle-Tested", className="small text-muted mb-0")
                        ], xs=6, sm=3, className="text-center"),
                        dbc.Col([
                            html.H5("2.3ms", className="text-primary mb-1"),
                            html.P("Parse Speed", className="small text-muted mb-0")
                        ], xs=6, sm=3, className="text-center")
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
            return dbc.Alert([html.I(className="fa fa-brain me-2"), "No trained models found."], color="warning")
        return [html.Ul([html.Li([html.Strong(m['name']), f" - Size: {m['size']}, Updated: {m['modified']}"]) for m in models])]

    # ========================================================================
    # IOT SECURITY STATUS
    # ========================================================================

    @app.callback(
        Output('iot-security-widget', 'children'),
        Input('ws', 'message')
    )
    def update_iot_security_widget(ws_message):
        """Update IoT Security Status widget"""
        # Get devices + security assessment (shared memo — avoids duplicate compute)
        devices, security_summary = _get_security_summary_cached()

        if not devices:
            return dbc.Alert([html.I(className="fa fa-chart-bar me-2"), "No devices to analyze"], color="info")

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
                        html.H2(f"{security_summary['security_score']}", className=f"text-{score_color} mb-0 u-text-hero fw-bold"),
                        html.P("Security Score", className="text-muted mb-2"),
                        dbc.Badge(f"{risk_level.upper()} RISK", color=badge_color, className="mt-1")
                    ], className="text-center")
                ], xs=6, sm=3),

                # Metrics
                dbc.Col([
                    dbc.Row([
                        dbc.Col([
                            html.Div([
                                html.H4(security_summary['iot_devices_count'], className="text-primary mb-0"),
                                html.Small("IoT Devices", className="text-muted")
                            ], className="text-center")
                        ], xs=12, sm=4),
                        dbc.Col([
                            html.Div([
                                html.H4(security_summary['vulnerable_count'], className="text-danger mb-0"),
                                html.Small("Vulnerable", className="text-muted")
                            ], className="text-center")
                        ], xs=12, sm=4),
                        dbc.Col([
                            html.Div([
                                html.H4(security_summary['total_devices'], className="text-info mb-0"),
                                html.Small("Total Devices", className="text-muted")
                            ], className="text-center")
                        ], xs=12, sm=4)
                    ])
                ], width=5),

                # Recommendations
                dbc.Col([
                    html.Div([
                        html.H6([html.I(className="fa fa-lightbulb me-2"), "Top Recommendations"], className="mb-2"),
                        html.Ul([
                            html.Li(rec, className="small") for rec in security_summary['top_recommendations'][:3]
                        ], className="mb-0 ps-4")
                    ])
                ], xs=12, sm=4)
            ], className="align-items-center")
        ])

    # ========================================================================
    # OVERVIEW STATS — BATCHED (W15)
    # Replaced 8 separate interval callbacks with one: single DB connection,
    # deduplicated queries, and one React render per tick instead of 8.
    # ========================================================================

    @app.callback(
        [Output('network-health', 'children'),
         Output('network-icon', 'className'),
         Output('attack-surface-list', 'children'),
         Output('device-count-stat', 'children'),
         Output('bandwidth-stat', 'children'),
         Output('security-score', 'children'),
         Output('last-scan-time', 'children'),
         Output('recent-activity-list', 'children'),
         Output('recommendations-list', 'children'),
         Output('live-threat-feed', 'children'),
         Output('threat-forecast-content', 'children')],
        Input('refresh-interval', 'n_intervals')
    )
    def update_overview_stats(n):
        """Batch all overview stat-card DB work into a single connection."""
        _err = ("-", "fa fa-wifi fa-2x mb-2 text-muted",
                html.P("Loading...", className="text-muted small"),
                "-", "-", "-", "-",
                html.P("Loading...", className="text-muted small"),
                [html.P("Loading...", className="text-muted small")],
                html.P("Loading...", className="text-muted small"),
                html.P("Loading...", className="text-muted small"))
        try:
            conn = get_db_connection()
            cur = conn.cursor()

            # ── shared counters (reused across multiple sections) ─────────
            cur.execute('SELECT COUNT(DISTINCT device_ip) as count FROM devices WHERE last_seen >= datetime("now", "-1 hour")')
            active_devices = cur.fetchone()['count']

            cur.execute('SELECT COUNT(*) as count FROM connections WHERE timestamp >= datetime("now", "-1 hour")')
            conn_count = cur.fetchone()['count']

            cur.execute('''SELECT COUNT(*) as count FROM alerts
                WHERE severity IN ("critical","high") AND timestamp >= datetime("now", "-1 hour")''')
            critical_1h = cur.fetchone()['count']

            cur.execute('SELECT COUNT(*) as count FROM devices WHERE is_trusted = 0 AND is_blocked = 0')
            untrusted = cur.fetchone()['count']

            cur.execute('SELECT MAX(timestamp) as last_scan FROM connections')
            _row = cur.fetchone()
            last_scan_ts = _row['last_scan'] if _row else None

            cur.execute('''SELECT COUNT(*) as count FROM alerts
                WHERE severity = "critical" AND timestamp >= datetime("now", "-24 hours")''')
            critical_24h = cur.fetchone()['count']

            # ── network-health ────────────────────────────────────────────
            if critical_1h > 5:
                health, icon_class = "Poor", "fa fa-wifi fa-2x mb-2 text-danger"
            elif critical_1h > 2:
                health, icon_class = "Fair", "fa fa-wifi fa-2x mb-2 text-warning"
            elif active_devices > 5 and conn_count > 100:
                health, icon_class = "Excellent", "fa fa-wifi fa-2x mb-2 text-success"
            elif active_devices > 0 or conn_count > 0:
                health, icon_class = "Good", "fa fa-wifi fa-2x mb-2 text-info"
            else:
                health, icon_class = "Idle", "fa fa-wifi fa-2x mb-2 text-secondary"

            # ── attack-surface-list ───────────────────────────────────────
            vulns = []
            if untrusted > 0:
                vulns.append(dbc.Card([dbc.CardBody([html.Div([
                    html.I(className="fa fa-exclamation-triangle text-warning me-2 u-text-xl"),
                    html.Div([html.H6(f"{untrusted} Untrusted Devices", className="mb-1"),
                              html.P("Unverified devices can be exploited as entry points",
                                     className="mb-0 small text-muted"),
                              dbc.Badge("MEDIUM RISK", color="warning", className="mt-2")])
                ], className="d-flex")])], className="mb-3 border-warning"))

            cur.execute('''SELECT COUNT(DISTINCT device_ip) as count FROM alerts
                WHERE severity = "critical" AND timestamp >= datetime("now", "-24 hours")''')
            critical_devices = cur.fetchone()['count']
            if critical_devices > 0:
                vulns.append(dbc.Card([dbc.CardBody([html.Div([
                    html.I(className="fa fa-skull-crossbones text-danger me-2 u-text-xl"),
                    html.Div([html.H6(f"{critical_devices} Devices Under Attack", className="mb-1"),
                              html.P("Devices with active critical alerts are vulnerable",
                                     className="mb-0 small text-muted"),
                              dbc.Badge("HIGH RISK", color="danger", className="mt-2")])
                ], className="d-flex")])], className="mb-3 border-danger"))

            # Devices with elevated ML anomaly rate (≥20% of connections flagged, min 5 preds)
            cur.execute('''
                SELECT COUNT(DISTINCT c.device_ip) as count
                FROM (
                    SELECT c.device_ip,
                           COUNT(*) AS total_preds,
                           SUM(p.is_anomaly) AS anomaly_count
                    FROM ml_predictions p
                    JOIN connections c ON p.connection_id = c.id
                    WHERE p.timestamp >= datetime("now", "-1 hour")
                    GROUP BY c.device_ip
                    HAVING total_preds >= 5
                       AND (100.0 * anomaly_count / total_preds) >= 20.0
                ) c
            ''')
            _har = cur.fetchone()
            high_anomaly_devices = _har['count'] if _har else 0
            if high_anomaly_devices > 0:
                vulns.append(dbc.Card([dbc.CardBody([html.Div([
                    html.I(className="fa fa-exclamation-circle text-info me-2 u-text-xl"),
                    html.Div([html.H6(f"{high_anomaly_devices} Devices with Elevated Anomaly Rate",
                                      className="mb-1"),
                              html.P("River ML flagged ≥20% of recent connections as anomalous",
                                     className="mb-0 small text-muted"),
                              dbc.Badge("MEDIUM RISK", color="info", className="mt-2")])
                ], className="d-flex")])], className="mb-3 border-info"))

            attack_surface = html.Div([
                html.H5([html.I(className="fa fa-exclamation-circle me-2"), "Identified Entry Points"],
                        className="mb-3"),
                *vulns,
                dbc.Alert([html.I(className="fa fa-lightbulb me-2"),
                           "Recommendation: Review and address these vulnerabilities to reduce attack surface."],
                          color="warning", className="mt-3")
            ]) if vulns else dbc.Alert([
                html.I(className="fa fa-shield-alt me-2"),
                html.Strong("No Major Vulnerabilities Detected"),
                html.P("Your network appears secure with minimal attack surface.", className="mb-0 mt-2")
            ], color="success")

            # ── device-count-stat + bandwidth-stat ────────────────────────
            bandwidth = f"{conn_count // 1000}K" if conn_count >= 1000 else str(conn_count)

            # ── security-score + last-scan-time ──────────────────────────
            # ML component: average anomaly score over last 24 h (contributes 0–60 pts)
            cur.execute('''
                SELECT ROUND(AVG(anomaly_score), 4) AS avg_score,
                       COUNT(*) AS total_preds
                FROM ml_predictions
                WHERE timestamp >= datetime("now", "-24 hours")
            ''')
            _ml_sc = cur.fetchone()
            _sc_ml_avg   = float(_ml_sc['avg_score']  or 0) if _ml_sc else 0.0
            _sc_ml_total = int(_ml_sc['total_preds']  or 0) if _ml_sc else 0
            _ml_penalty  = round(_sc_ml_avg * 60) if _sc_ml_total >= 10 else 0

            # Alert component: recalibrated weights, capped at 40 pts
            cur.execute('''SELECT SUM(CASE WHEN severity = "critical" THEN 8
                                          WHEN severity = "high"     THEN 4
                                          WHEN severity = "medium"   THEN 2
                                          WHEN severity = "low"      THEN 1
                                          ELSE 0 END) as alert_pts
                FROM alerts WHERE timestamp >= datetime("now", "-24 hours")''')
            _ap = cur.fetchone()
            _alert_penalty = min(40, int(_ap['alert_pts'] or 0)) if _ap else 0

            score_text = f"{max(0, 100 - _ml_penalty - _alert_penalty)}/100"

            if last_scan_ts:
                diff = datetime.now() - datetime.strptime(last_scan_ts, '%Y-%m-%d %H:%M:%S')
                if diff.seconds < 60:
                    time_text = "Just now"
                elif diff.seconds < 3600:
                    time_text = f"{diff.seconds // 60}m ago"
                else:
                    time_text = f"{diff.seconds // 3600}h ago"
            else:
                time_text = "Never"

            # ── recent-activity-list ──────────────────────────────────────
            activities = []
            cur.execute('SELECT device_ip, last_seen FROM devices ORDER BY last_seen DESC LIMIT 1')
            row = cur.fetchone()
            if row:
                activities.append(html.Div([
                    html.I(className="fa fa-laptop text-primary me-2 u-text-sm"),
                    html.Span(f"Device {row['device_ip']}", className="fw-bold"),
                    html.Span(f" connected {_format_time_ago(row['last_seen'])}", className="text-muted")
                ], className="mb-2"))

            cur.execute('SELECT severity, explanation, timestamp FROM alerts ORDER BY timestamp DESC LIMIT 1')
            row = cur.fetchone()
            if row:
                sev_icon = "fa-skull-crossbones" if row['severity'] == 'critical' else "fa-exclamation-triangle"
                activities.append(html.Div([
                    html.I(className=f"fa {sev_icon} text-danger me-2 u-text-sm"),
                    html.Span(f"{row['severity'].title()} alert", className="fw-bold"),
                    html.Span(f" {_format_time_ago(row['timestamp'])}", className="text-muted")
                ], className="mb-2"))

            if last_scan_ts:
                activities.append(html.Div([
                    html.I(className="fa fa-search text-success me-2 u-text-sm"),
                    html.Span("Network scan", className="fw-bold"),
                    html.Span(f" completed {_format_time_ago(last_scan_ts)}", className="text-muted")
                ], className="mb-0"))

            recent_activity = activities or html.P("No recent activity", className="text-muted text-center mb-0")

            # ── recommendations-list ──────────────────────────────────────
            recs = []
            if critical_24h > 0:
                recs.append(html.Div([
                    html.I(className="fa fa-exclamation-circle text-danger me-2"),
                    html.Span(f"Address {critical_24h} critical alert(s) immediately", className="small")
                ], className="mb-2"))
            if untrusted > 0:
                recs.append(html.Div([
                    html.I(className="fa fa-shield-alt text-warning me-2"),
                    html.Span(f"Review {untrusted} unverified device(s)", className="small")
                ], className="mb-2"))
            if not recs:
                recs.append(html.Div([
                    html.I(className="fa fa-check-circle text-success me-2"),
                    html.Span("System is secure. Keep monitoring active.", className="small")
                ], className="mb-0"))

            # ── live-threat-feed ──────────────────────────────────────────
            # Real alerts + River ML-flagged anomalous connections (score ≥ 0.60)
            cur.execute('''
                SELECT timestamp, severity, device_ip, explanation
                FROM alerts
                WHERE timestamp >= datetime("now", "-1 hour")
                UNION ALL
                SELECT p.timestamp,
                       CASE WHEN p.anomaly_score >= 0.75 THEN "high"
                            WHEN p.anomaly_score >= 0.60 THEN "medium"
                            ELSE "low" END,
                       c.device_ip,
                       COALESCE(d.custom_name, d.device_name, c.device_ip)
                           || " → " || c.dest_ip || ":" || CAST(c.dest_port AS TEXT)
                           || " (anomaly " || CAST(ROUND(p.anomaly_score * 100) AS INTEGER) || "%)"
                FROM ml_predictions p
                JOIN connections c  ON p.connection_id = c.id
                LEFT JOIN devices d ON c.device_ip = d.device_ip
                WHERE p.timestamp >= datetime("now", "-1 hour")
                  AND p.is_anomaly = 1
                  AND p.anomaly_score >= 0.60
                ORDER BY timestamp DESC LIMIT 15''')
            threats = cur.fetchall()

            _sev = {
                'critical': ('fa-skull-crossbones',     '#ef4444', 'rgba(239,68,68,0.1)'),
                'high':     ('fa-exclamation-triangle', '#f59e0b', 'rgba(245,158,11,0.1)'),
                'medium':   ('fa-exclamation-circle',   '#3b82f6', 'rgba(59,130,246,0.1)'),
                'low':      ('fa-info-circle',           '#6b7280', 'rgba(107,114,128,0.1)'),
            }
            if threats:
                feed_items = []
                for t in threats:
                    icon, color, bg = _sev.get(t['severity'], _sev['low'])
                    feed_items.append(html.Div([
                        html.Div([
                            html.I(className=f"fa {icon} me-2 u-text-sm", style={"color": color}),
                            html.Div([
                                html.Div([html.Span(t['device_ip'], className="fw-bold threat-feed-meta"),
                                          html.Span(f" • {_format_time_ago(t['timestamp'])}",
                                                    className="text-muted ms-1 threat-feed-time")]),
                                html.P(t['explanation'], className="mb-0 text-muted threat-feed-text")
                            ], className="flex-grow-1")
                        ], className="d-flex align-items-start")
                    ], className="threat-feed-item",
                       style={"backgroundColor": bg, "borderLeft": f"3px solid {color}"}))
                threat_feed = feed_items
            else:
                threat_feed = html.P("No threats detected",
                                     className="text-success text-center mb-0 py-3 small")

            # ── threat-forecast-content (River ML anomaly forecast) ──────
            # Query 1: anomaly momentum — last 6 h vs previous 6 h window
            cur.execute('''
                SELECT
                    ROUND(AVG(CASE WHEN p.timestamp >= datetime("now", "-6 hours")
                                   THEN p.anomaly_score END), 4) AS recent_avg,
                    ROUND(AVG(CASE WHEN p.timestamp <  datetime("now", "-6 hours")
                                   THEN p.anomaly_score END), 4) AS prior_avg,
                    COUNT(*)                                       AS total_preds,
                    MAX(p.anomaly_score)                           AS peak_score,
                    SUM(CASE WHEN p.is_anomaly = 1
                                  AND p.timestamp >= datetime("now", "-6 hours")
                             THEN 1 ELSE 0 END)                   AS recent_anomalies
                FROM ml_predictions p
                WHERE p.timestamp >= datetime("now", "-12 hours")
            ''')
            ml_row = cur.fetchone()

            _recent_avg      = float(ml_row['recent_avg']      or 0)
            _prior_avg       = float(ml_row['prior_avg']       or 0)
            _total_preds     = int(ml_row['total_preds']       or 0)
            _peak_score      = float(ml_row['peak_score']      or 0)
            _recent_anomalies = int(ml_row['recent_anomalies'] or 0)

            # Query 2: top anomalous devices (last 12 h, min 3 predictions each)
            cur.execute('''
                SELECT
                    COALESCE(d.custom_name, d.device_name, c.device_ip) AS label,
                    ROUND(AVG(p.anomaly_score), 3)                       AS avg_score,
                    COUNT(*)                                              AS total_preds
                FROM ml_predictions p
                JOIN connections c  ON p.connection_id = c.id
                LEFT JOIN devices d ON c.device_ip = d.device_ip
                WHERE p.timestamp >= datetime("now", "-12 hours")
                GROUP BY c.device_ip
                HAVING total_preds >= 3
                ORDER BY avg_score DESC
                LIMIT 2
            ''')
            _top_devices = cur.fetchall()

            # ── build forecast component ──────────────────────────────────
            _MIN_PREDS = 5   # minimum predictions to trust the output

            if _total_preds == 0:
                # Monitoring not started or no connections scored yet — static, no spinner
                forecast = html.Div([
                    html.I(className="fa fa-brain fa-2x text-muted mb-2"),
                    html.Br(),
                    html.Span("Waiting for traffic",
                              className="text-muted small fw-semibold d-block"),
                    html.Small(
                        "Forecast activates once the IoTSentinel service "
                        "starts scoring network connections.",
                        className="text-muted"
                    )
                ], className="text-center py-3")
            elif _total_preds < _MIN_PREDS:
                # Data is flowing — actively building baseline, show progress
                forecast = html.Div([
                    html.I(className="fa fa-circle-notch fa-spin me-2 text-muted"),
                    html.Span("Building baseline",
                              className="text-muted small fw-semibold"),
                    html.Br(),
                    html.Small(
                        f"{_total_preds}/{_MIN_PREDS} predictions collected.",
                        className="text-muted"
                    )
                ], className="text-center py-3")
            else:
                # Proportional momentum between the two 6-hour windows
                _momentum = ((_recent_avg - _prior_avg) / _prior_avg
                             if _prior_avg > 0 else 0.0)

                # Risk level
                if _recent_avg >= 0.75 or _peak_score >= 0.90:
                    _risk_label, _risk_color, _risk_icon = (
                        "Critical", "danger", "fa-exclamation-circle")
                elif _recent_avg >= 0.55 or (_momentum > 0.4 and _recent_avg >= 0.35):
                    _risk_label, _risk_color, _risk_icon = (
                        "High", "warning", "fa-exclamation-triangle")
                elif _recent_avg >= 0.30 or _momentum > 0.2:
                    _risk_label, _risk_color, _risk_icon = (
                        "Moderate", "info", "fa-shield-alt")
                else:
                    _risk_label, _risk_color, _risk_icon = (
                        "Low", "success", "fa-check-circle")

                # Trend direction
                if _momentum > 0.25:
                    _trend_label, _trend_icon, _trend_cls = (
                        "Rising", "fa-arrow-up", "text-danger")
                elif _momentum < -0.25:
                    _trend_label, _trend_icon, _trend_cls = (
                        "Easing", "fa-arrow-down", "text-success")
                else:
                    _trend_label, _trend_icon, _trend_cls = (
                        "Stable", "fa-minus", "text-warning")

                # Confidence label from sample count
                _conf = ("High" if _total_preds >= 200 else
                         "Medium" if _total_preds >= 50 else "Low")

                # Per-device anomaly bars (only surface devices above 0.30)
                _dev_rows = []
                for _dev in _top_devices:
                    if (_dev['avg_score'] or 0) >= 0.30:
                        _bc = ("danger"  if _dev['avg_score'] >= 0.75 else
                               "warning" if _dev['avg_score'] >= 0.55 else "info")
                        _dev_rows.append(html.Div([
                            html.Span(
                                str(_dev['label']),
                                className="small text-truncate me-2",
                                style={"maxWidth": "110px", "display": "inline-block",
                                       "verticalAlign": "middle"}
                            ),
                            dbc.Progress(
                                value=int(_dev['avg_score'] * 100),
                                color=_bc,
                                style={"height": "5px", "flex": "1"}
                            ),
                            html.Span(f" {_dev['avg_score']:.2f}",
                                      className=f"small ms-1 text-{_bc}"),
                        ], className="d-flex align-items-center mb-1"))

                forecast = html.Div([
                    # Row 1: horizon label + risk badge
                    html.Div([
                        html.Span("Next 24h", className="text-muted small me-2"),
                        dbc.Badge(
                            [html.I(className=f"fa {_risk_icon} me-1"), _risk_label],
                            color=_risk_color, className="u-text-badge"
                        ),
                    ], className="d-flex align-items-center mb-2"),

                    # Row 2: trend arrow + momentum %
                    html.Div([
                        html.I(className=f"fa {_trend_icon} me-2 {_trend_cls}"),
                        html.Span(_trend_label,
                                  className=f"small fw-semibold {_trend_cls}"),
                        html.Span(f"  {_momentum:+.0%}",
                                  className="small text-muted ms-1")
                        if _prior_avg > 0 else "",
                    ], className="mb-2"),

                    # Row 3: anomaly-index mini progress bar
                    html.Div([
                        html.Span("Anomaly index",
                                  className="small text-muted me-2",
                                  style={"whiteSpace": "nowrap"}),
                        dbc.Progress(
                            value=int(_recent_avg * 100),
                            color=_risk_color,
                            style={"height": "5px", "flex": "1"}
                        ),
                        html.Span(f" {_recent_avg:.2f}",
                                  className=f"small ms-1 text-{_risk_color}"),
                    ], className="d-flex align-items-center mb-2"),

                    # Row 4: at-risk device breakdown (conditional)
                    html.Div(_dev_rows, className="mb-2") if _dev_rows else None,

                    # Footer: attribution + confidence
                    html.Small([
                        html.I(className="fa fa-brain me-1"),
                        f"River ML · {_total_preds:,} predictions · {_conf} confidence"
                    ], className="text-muted"),
                ])

            return (health, icon_class, attack_surface, str(active_devices), bandwidth,
                    score_text, time_text, recent_activity, recs, threat_feed, forecast)

        except Exception as e:
            logger.error(f"Error in overview stats batch: {e}")
            return _err

    # ========================================================================
    # SANKEY TRAFFIC FLOW DIAGRAM
    # ========================================================================

    @app.callback(
        Output('traffic-flow-sankey', 'figure'),
        [Input('refresh-interval', 'n_intervals')],
        prevent_initial_call=True  # W15: skip n_intervals=0 DB query on page load
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
                fig.update_layout(title="No Traffic Data Available", height=500,
                                  paper_bgcolor='rgba(0,0,0,0)')
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
                title=dict(text="Network Traffic Flow - Last Hour", x=0.5, xanchor='center'),
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                font=dict(size=10),
                height=500,
                margin=dict(l=20, r=20, t=40, b=20)
            )

            return fig

        except Exception as e:
            logger.error(f"Error updating traffic flow sankey: {e}")
            fig = go.Figure()
            fig.update_layout(title=f"Error: {str(e)}", height=500,
                              paper_bgcolor='rgba(0,0,0,0)')
            return fig

    # attack-surface-list, device-count-stat, bandwidth-stat, security-score,
    # last-scan-time, recent-activity-list, recommendations-list, live-threat-feed
    # → all merged into update_overview_stats above (W15 batch).

    # (dead function bodies removed — W15 batch merge)
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

    # -------------------------------------------------------------------------
    # Traffic-light badge: updates the badge in the security-score card header
    # -------------------------------------------------------------------------
    @app.callback(
        Output('traffic-light-badge', 'children'),
        Output('traffic-light-badge', 'className'),
        Input('security-score-interval', 'n_intervals'),
        Input('dashboard-template-store', 'data'),
    )
    def update_traffic_light_badge(n, template_data):
        from dashboard.shared import TEMPLATE_ALIASES
        raw = template_data if isinstance(template_data, str) else 'advanced'
        template = TEMPLATE_ALIASES.get(raw, raw)
        if template != 'simple':
            return '', 'badge ms-2 d-none'
        try:
            result = network_security_scorer.calculate_network_score()
            score = result.get('overall_score', 0)
            if score >= 80:
                return '● SECURE', 'tl-secure ms-2'
            elif score >= 50:
                return '● CAUTION', 'tl-caution ms-2'
            return '● ALERT', 'tl-alert ms-2'
        except Exception:
            return '● UNKNOWN', 'badge bg-secondary ms-2'

    # ── AI Network Briefing + Proactive Insights ──────────────────────────────
    _BRIEFING_TTL = 900  # regenerate after 15 minutes

    @app.callback(
        [Output('ai-briefing-content', 'children'),
         Output('ai-briefing-timestamp', 'children'),
         Output('ai-briefing-source-badge', 'children'),
         Output('ai-briefing-source-badge', 'className'),
         Output('ai-insights-content', 'children'),
         Output('ai-briefing-cache', 'data')],
        [Input('ws', 'message'),
         Input('ai-briefing-refresh-btn', 'n_clicks')],
        State('ai-briefing-cache', 'data'),
        prevent_initial_call=False,
    )
    def update_ai_briefing_and_insights(ws_message, refresh_clicks, cache):
        from dash import callback_context as ctx
        cache = cache or {}
        is_manual_refresh = ctx.triggered_id == 'ai-briefing-refresh-btn'
        age = time.time() - cache.get('ts', 0)

        # Invalidate cache when open alert count changes (e.g. alert addressed/created)
        live_alert_count = None
        if isinstance(ws_message, dict):
            live_alert_count = ws_message.get('alert_count')
        if (live_alert_count is not None
                and cache.get('alert_count') is not None
                and live_alert_count != cache.get('alert_count')):
            age = _BRIEFING_TTL  # force regeneration

        # Return cached content if still fresh and not a manual refresh
        if not is_manual_refresh and age < _BRIEFING_TTL and cache.get('briefing'):
            ts_label = f"Updated {int(age // 60)} min ago"
            source = cache.get('source', '')
            src_cls = _source_badge_class(source)
            src_label = _source_label(source)
            # Keep alert_count current so next change is detected immediately
            updated_cache = {**cache, 'alert_count': live_alert_count if live_alert_count is not None else cache.get('alert_count')}
            return (
                _render_briefing(cache['briefing']),
                ts_label,
                src_label, src_cls,
                _render_insights(cache.get('insights', [])),
                updated_cache,
            )

        # --- Gather live context ---
        try:
            devices = get_devices_with_status()
            total = len(devices)
            # Count devices seen in the last 24 h — same window as the security scorer
            # (get_devices_with_status never sets status='offline' so it can't be used here)
            _cutoff = (datetime.now() - timedelta(hours=24)).isoformat()
            _row = db_manager.conn.cursor().execute(
                "SELECT COUNT(*) FROM devices WHERE last_seen > ?", (_cutoff,)
            ).fetchone()
            online = _row[0] if _row else 0
            alerted = [d for d in devices if d.get('status') == 'alert']
        except Exception:
            devices, total, online, alerted = [], 0, 0, []

        try:
            alerts = get_latest_alerts(limit=10)
            crit = sum(1 for a in alerts if a.get('severity') == 'critical')
            high = sum(1 for a in alerts if a.get('severity') == 'high')
            med  = sum(1 for a in alerts if a.get('severity') == 'medium')
        except Exception:
            alerts, crit, high, med = [], 0, 0, 0

        try:
            bw = get_bandwidth_stats()
            bw_summary = bw.get('summary', 'normal')
        except Exception:
            bw_summary = 'unavailable'

        # New devices in last 48h
        try:
            cur = db_manager.conn.cursor()
            cur.execute(
                "SELECT device_ip, custom_name, device_name FROM devices "
                "WHERE first_seen >= datetime('now','-48 hours') ORDER BY first_seen DESC LIMIT 3"
            )
            new_devices = [dict(r) for r in cur.fetchall()]
        except Exception:
            new_devices = []

        # Anomalous devices (today traffic vs baseline)
        try:
            cur.execute(
                """SELECT d.device_ip, COALESCE(d.custom_name, d.device_name, d.device_ip) AS name,
                          b.metric_value AS baseline_val,
                          COALESCE(c.bytes_sent, 0) AS today_bytes
                   FROM devices d
                   JOIN device_behavior_baselines b ON d.device_ip = b.device_ip
                        AND b.metric_name = 'bytes_sent_per_connection'
                   LEFT JOIN (
                       SELECT device_ip, SUM(bytes_sent) AS bytes_sent
                       FROM connections WHERE timestamp >= date('now') GROUP BY device_ip
                   ) c ON d.device_ip = c.device_ip
                   WHERE b.metric_value > 0
                     AND COALESCE(c.bytes_sent, 0) > b.metric_value * 2.5
                   LIMIT 2"""
            )
            anomalous = [dict(r) for r in cur.fetchall()]
        except Exception:
            anomalous = []

        # --- Build single AI call for both briefing + insights ---
        alert_summary = ""
        if alerts:
            top = next((a for a in alerts if not a.get('acknowledged')), None)
            if top:
                alert_summary = (
                    f"Most recent: {top.get('plain_explanation') or top.get('explanation','')[:80]} "
                    f"({top.get('device_name') or top.get('device_ip','?')}, {top.get('severity','')})"
                )

        insight_facts = []
        if new_devices:
            names = ", ".join(d.get('name') or d.get('device_ip', '?') for d in new_devices[:2])
            insight_facts.append(f"New device(s) joined in the last 48h: {names}")
        if anomalous:
            for a in anomalous[:1]:
                insight_facts.append(
                    f"{a['name']} is sending {int(a['today_bytes'] / max(a['baseline_val'], 1)):.0f}× "
                    "more data than its normal baseline today"
                )
        if crit + high == 0 and not new_devices:
            insight_facts.append("No critical or high alerts in the last 24 hours")

        facts_str = "\n".join(f"- {f}" for f in insight_facts) if insight_facts else "- No unusual activity detected"

        prompt = (
            f"You are the IoTSentinel AI. Write a response in exactly this format.\n"
            f"Use plain sentences. No em dashes, no markdown bold, no bullet points.\n\n"
            f"BRIEFING: [2-3 sentences, plain English, friendly, specific. Start with overall status. "
            f"Mention the most important thing. Avoid jargon.]\n\n"
            f"INSIGHT_1: [One sentence about the first fact below, friendly and specific]\n"
            f"INSIGHT_2: [One sentence about the second fact, or 'Your network looks healthy today.' if no fact]\n\n"
            f"Network state: {total} devices ({online} active), "
            f"{len(alerts)} alerts (critical={crit}, high={high}, medium={med}). "
            f"{alert_summary}\nBandwidth: {bw_summary}\n"
            f"Key facts:\n{facts_str}"
        )

        # Only call the LLM on an explicit manual refresh. Auto (WS) triggers use
        # the rules template so the card populates instantly without an HTTP round-trip.
        # The refresh button upgrades to LLM quality and caches the result for 15 min.
        if is_manual_refresh:
            try:
                raw, source = ai_assistant.get_response(
                    prompt=prompt, max_tokens=220, temperature=0.5, prefer_local=False
                )
            except Exception:
                raw, source = "", "rules"
        else:
            raw, source = "", "rules"

        def _clean_overview(text):
            return (text or '').replace('—', '-').replace('–', '-').replace('**', '')

        # Parse BRIEFING / INSIGHT_N sections from response
        briefing_text = ""
        insight_texts = []
        if raw:
            for line in raw.splitlines():
                if line.startswith("BRIEFING:"):
                    briefing_text = _clean_overview(line[len("BRIEFING:"):].strip())
                elif line.startswith("INSIGHT_1:"):
                    insight_texts.append(_clean_overview(line[len("INSIGHT_1:"):].strip()))
                elif line.startswith("INSIGHT_2:"):
                    insight_texts.append(_clean_overview(line[len("INSIGHT_2:"):].strip()))

        # Fallback to rule-based if parsing failed
        if not briefing_text:
            if crit + high > 0:
                briefing_text = (
                    f"Your network has {len(alerts)} open alert(s): "
                    f"{crit} critical and {high} high severity. "
                    "Check the Alerts tab for details and recommended actions."
                )
            else:
                briefing_text = (
                    f"Your network looks healthy. {online} of {total} device(s) are active "
                    f"and there are no critical alerts right now."
                )
            source = "rules"

        if not insight_texts:
            insight_texts = [f[2:] for f in insight_facts[:2]] or ["No unusual activity detected."]

        new_cache = {'briefing': briefing_text, 'insights': insight_texts, 'source': source, 'ts': time.time(),
                     'alert_count': live_alert_count}
        src_label = _source_label(source)
        src_cls = _source_badge_class(source)

        return (
            _render_briefing(briefing_text),
            "Just now",
            src_label, src_cls,
            _render_insights(insight_texts),
            new_cache,
        )

    # ── Report-sent in-app notification ──────────────────────────────────────
    # The report scheduler writes `last_report_sent` to settings after each
    # successful send.  This callback detects a new stamp and shows a toast
    # so the user knows without checking email.
    @app.callback(
        Output('toast-container', 'children', allow_duplicate=True),
        Input('refresh-interval', 'n_intervals'),
        State('ai-briefing-cache', 'data'),  # harmless state — just ensures unique signature
        prevent_initial_call=True,
    )
    def notify_report_sent(_n, _cache):
        import json as _j, time as _t
        try:
            raw = db_manager.get_setting('last_report_sent', '')
            if not raw:
                raise dash.exceptions.PreventUpdate
            data = _j.loads(raw)
            ts = int(data.get('ts', 0))
            # Only show toast once — within the 60-second refresh window
            if _t.time() - ts > 90:
                raise dash.exceptions.PreventUpdate
            report_type = data.get('type', 'report').title()
            channels = data.get('channels', 0)
            ch_text = f"Sent to {channels} channel{'s' if channels != 1 else ''}." if channels else ""
            return ToastManager.success(
                message=f"{ch_text} Check your email for the full report.",
                header=f"{report_type} Security Report Ready",
                duration=6000,
            )
        except dash.exceptions.PreventUpdate:
            raise
        except Exception:
            raise dash.exceptions.PreventUpdate

    # Register the weekly story callback
    _register_weekly_story(app)


def _prose_variant(text: str) -> str:
    """Infer severity accent from text keywords — mirrors app severity language.

    Success/negation patterns run first so 'no critical alerts' stays green,
    not red — the 'critical' substring must not hijack negated phrases.
    """
    t = text.lower()
    # Check negations / good-health phrases first
    if any(w in t for w in ('healthy', 'all clear', 'no critical', 'no alert', 'no high',
                             'looks good', 'protected', 'quiet', 'normal', 'safe',
                             'resolved', 'handled', 'looks healthy')):
        return 'success'
    if any(w in t for w in ('critical', 'blocked', 'attack', 'breach', 'malware', 'intrusion')):
        return 'danger'
    if any(w in t for w in ('high', 'warning', 'anomal', 'unusual', 'spike', 'suspicious',
                             'sending', '×', 'more data', 'new device', 'joined')):
        return 'warning'
    return 'info'


def _render_prose(text, variant='auto'):
    """Split AI text into paragraphs and render each as a severity-coloured prose line."""
    from dash import html
    lines = [p.strip() for p in (text or '').split('\n\n') if p.strip()]
    if not lines:
        lines = [text or '']
    items = []
    for line in lines:
        v = _prose_variant(line) if variant == 'auto' else variant
        items.append(html.Div(line, className=f"ai-prose-line ai-prose-line--{v}"))
    return html.Div(items, className="mb-0")


def _render_briefing(text):
    return _render_prose(text, variant='auto')


def _render_insights(insights):
    from dash import html
    items = []
    for text in (insights or [])[:3]:
        items.append(html.Div(text, className=f"ai-prose-line ai-prose-line--{_prose_variant(text)}"))
    return html.Div(items) if items else html.Span("All clear.", className="text-muted small")


# ---------------------------------------------------------------------------
# Weekly story helpers (used by the callback registered inside register())
# ---------------------------------------------------------------------------

_STORY_TTL = 6 * 60 * 60  # 6 hours — refresh once or on manual click


def _register_weekly_story(app):
    """Register the 'This Week on Your Network' callback."""
    import time as _time
    from dash import (Input, Output, State, html, callback_context as _ctx, no_update)
    import dash_bootstrap_components as dbc
    from utils.weekly_story import build_facts, generate_story
    from dashboard.shared import db_manager as _db, ai_assistant as _ai
    from utils.alert_explainer import source_label as _sl, source_badge_class as _sbc

    _story_logger = logging.getLogger(__name__)

    @app.callback(
        [Output('weekly-story-content', 'children'),
         Output('weekly-story-timestamp', 'children'),
         Output('weekly-story-source-badge', 'children'),
         Output('weekly-story-source-badge', 'className'),
         Output('weekly-story-cache', 'data'),
         Output('toast-container', 'children', allow_duplicate=True)],
        [Input('weekly-story-refresh-btn', 'n_clicks'),
         Input('security-score-interval', 'n_intervals')],
        State('weekly-story-cache', 'data'),
        prevent_initial_call=True,
    )
    def update_weekly_story(refresh_n, _interval, cache):
        cache = cache or {}
        age = _time.time() - float(cache.get('ts', 0))
        is_manual = (
            _ctx.triggered_id == 'weekly-story-refresh-btn'
            if _ctx.triggered else False
        )

        # Return cached if still fresh and not a manual refresh
        if not is_manual and age < _STORY_TTL and cache.get('story'):
            hrs = int(age // 3600)
            mins = int((age % 3600) // 60)
            ts_label = f"Updated {hrs}h {mins}m ago" if hrs else f"Updated {mins}m ago"
            src = cache.get('source', '')
            return (
                _render_prose(cache['story'], variant='auto'),
                ts_label,
                _sl(src),
                _sbc(src),
                cache,
                no_update,
            )

        # Generate fresh story
        try:
            facts = build_facts(_db)
            story, source = generate_story(facts, _ai)
        except Exception as exc:
            _story_logger.warning(f"[weekly_story] generation failed: {exc}")
            story = "Your network is being monitored. Check back soon for your weekly summary."
            source = 'rules'

        new_cache = {'story': story, 'source': source, 'ts': _time.time()}
        src_cls = _sbc(source)

        toast = no_update
        if is_manual:
            toast = ToastManager.success(
                message=f"Weekly story generated by {_sl(source)}.",
                header="This Week on Your Network",
                duration=3000,
            )

        return (
            _render_prose(story, variant='auto'),
            "Just now",
            _sl(source),
            src_cls,
            new_cache,
            toast,
        )
