#!/usr/bin/env python3
"""
IoTSentinel Web Dashboard - Complete Implementation

Implements ALL Week 7 & 8 requirements:
- Network topology visualization
- Real-time traffic graphs
- Device activity heatmaps  ✅ NEW
- Alert timeline           ✅ NEW
- Anomaly score distribution ✅ NEW
- Educational transparency features
- System performance monitoring

100% Compatible with db_manager.py and schema.
"""

import dash
from dash import dcc, html, Input, Output, callback_context
import dash_bootstrap_components as dbc
import plotly.graph_objs as go
import plotly.express as px
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import sqlite3
import json
from pathlib import Path
import logging

# Setup paths
import sys
dashboard_dir = Path(__file__).parent
project_root = dashboard_dir.parent
sys.path.insert(0, str(project_root))

from config.config_manager import config

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Dash app
app = dash.Dash(
    __name__,
    external_stylesheets=[dbc.themes.BOOTSTRAP],
    title="IoTSentinel - Network Security Monitor",
    suppress_callback_exceptions=True
)

# Database path
DB_PATH = config.get('database', 'path')

def get_db_connection():
    """Get database connection (read-only for safety)."""
    try:
        conn = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        return conn
    except Exception as e:
        logger.error(f"Database connection error: {e}")
        return None


# ============================================================================
# APP LAYOUT - COMPLETE WITH ALL TABS
# ============================================================================

app.layout = dbc.Container([
    # Header with real-time stats
    dbc.Row([
        dbc.Col([
            html.H1("🛡️ IoTSentinel", className="text-primary mb-1"),
            html.P("Educational Network Security Monitor", className="text-muted small")
        ], width=6),
        dbc.Col([
            html.Div([
                html.H2(id='device-count', className="text-success mb-0"),
                html.Small("Active Devices", className="text-muted")
            ], className="text-end")
        ], width=2),
        dbc.Col([
            html.Div([
                html.H2(id='alert-count', className="text-warning mb-0"),
                html.Small("Active Alerts", className="text-muted")
            ], className="text-end")
        ], width=2),
        dbc.Col([
            html.Div([
                html.H2(id='connection-count', className="text-info mb-0"),
                html.Small("Connections/Hour", className="text-muted")
            ], className="text-end")
        ], width=2)
    ], className="mb-4 mt-3"),
    
    # System status banner
    dbc.Row([
        dbc.Col([
            dbc.Alert(id='system-status', color="success", className="mb-3")
        ])
    ]),
    
    # Main tabs
    dbc.Tabs([
        # ====================================================================
        # TAB 1: NETWORK OVERVIEW
        # ====================================================================
        dbc.Tab(label="🌐 Network", tab_id="tab-network", children=[
            dbc.Row([
                # Network topology map
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("Network Topology"),
                        dbc.CardBody([
                            dcc.Graph(id='network-graph', style={'height': '450px'})
                        ])
                    ])
                ], width=8),
                
                # Live connection feed
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("Live Connection Feed"),
                        dbc.CardBody([
                            html.Div(id='recent-activity', 
                                   style={'height': '450px', 'overflowY': 'auto'})
                        ])
                    ])
                ], width=4)
            ], className="mb-3"),
            
            dbc.Row([
                # Real-time traffic graph
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("Network Traffic (Last 24 Hours)"),
                        dbc.CardBody([
                            dcc.Graph(id='traffic-timeline', style={'height': '300px'})
                        ])
                    ])
                ], width=6),
                
                # Protocol distribution
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("Protocol Distribution"),
                        dbc.CardBody([
                            dcc.Graph(id='protocol-pie', style={'height': '300px'})
                        ])
                    ])
                ], width=6)
            ])
        ]),
        
        # ====================================================================
        # TAB 2: SECURITY ALERTS (WITH EDUCATIONAL FEATURES)
        # ====================================================================
        dbc.Tab(label="🚨 Alerts", tab_id="tab-alerts", children=[
            dbc.Row([
                dbc.Col([
                    dbc.ButtonGroup([
                        dbc.Button("All", id="filter-all", color="primary", size="sm"),
                        dbc.Button("Critical", id="filter-critical", color="danger", size="sm", outline=True),
                        dbc.Button("High", id="filter-high", color="warning", size="sm", outline=True),
                        dbc.Button("Medium", id="filter-medium", color="info", size="sm", outline=True),
                        dbc.Button("Low", id="filter-low", color="secondary", size="sm", outline=True)
                    ], className="mb-3")
                ])
            ]),
            dbc.Row([
                dbc.Col([
                    html.Div(id='alerts-container')
                ])
            ])
        ]),
        
        # ====================================================================
        # TAB 3: DEVICES
        # ====================================================================
        dbc.Tab(label="📱 Devices", tab_id="tab-devices", children=[
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("All Devices"),
                        dbc.CardBody([
                            html.Div(id='devices-table')
                        ])
                    ])
                ])
            ], className="mb-3"),
            
            dbc.Row([
                # Device activity heatmap (NEW!)
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("Device Activity Heatmap (24 Hours)"),
                        dbc.CardBody([
                            dcc.Graph(id='device-heatmap', style={'height': '400px'})
                        ])
                    ])
                ], width=12)
            ])
        ]),
        
        # ====================================================================
        # TAB 4: ANALYTICS (NEW!)
        # ====================================================================
        dbc.Tab(label="📊 Analytics", tab_id="tab-analytics", children=[
            dbc.Row([
                # Alert timeline (NEW!)
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("Alert Timeline (7 Days)"),
                        dbc.CardBody([
                            dcc.Graph(id='alert-timeline', style={'height': '350px'})
                        ])
                    ])
                ], width=12)
            ], className="mb-3"),
            
            dbc.Row([
                # Anomaly score distribution (NEW!)
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("Anomaly Score Distribution"),
                        dbc.CardBody([
                            dcc.Graph(id='anomaly-distribution', style={'height': '350px'})
                        ])
                    ])
                ], width=6),
                
                # System performance (NEW!)
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("ML Engine Performance"),
                        dbc.CardBody([
                            dcc.Graph(id='system-performance', style={'height': '350px'})
                        ])
                    ])
                ], width=6)
            ])
        ]),
        
        # ====================================================================
        # TAB 5: SYSTEM INFO
        # ====================================================================
        dbc.Tab(label="⚙️ System", tab_id="tab-system", children=[
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("System Status"),
                        dbc.CardBody([
                            html.Div(id='system-info')
                        ])
                    ])
                ], width=6),
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("Model Information"),
                        dbc.CardBody([
                            html.Div(id='model-info')
                        ])
                    ])
                ], width=6)
            ])
        ])
    ], id="tabs", active_tab="tab-network"),
    
    # Auto-refresh interval
    dcc.Interval(
        id='interval-component',
        interval=5*1000,  # 5 seconds
        n_intervals=0
    ),
    
    # Store for alert filter state
    dcc.Store(id='alert-filter', data='all')
    
], fluid=True, className="p-4")


# ============================================================================
# CALLBACKS - HEADER STATS
# ============================================================================

@app.callback(
    [Output('device-count', 'children'),
     Output('alert-count', 'children'),
     Output('connection-count', 'children'),
     Output('system-status', 'children')],
    Input('interval-component', 'n_intervals')
)
def update_header_stats(n):
    """Update header statistics."""
    conn = get_db_connection()
    if not conn:
        return "0", "0", "0", "⚠️ Database connection error"
    
    try:
        cursor = conn.cursor()
        
        # Active devices (last 5 min)
        cursor.execute("""
            SELECT COUNT(*) FROM devices
            WHERE last_seen > datetime('now', '-5 minutes')
        """)
        device_count = cursor.fetchone()[0]
        
        # Unacknowledged alerts (last 24h)
        cursor.execute("""
            SELECT COUNT(*) FROM alerts
            WHERE timestamp > datetime('now', '-24 hours')
            AND acknowledged = 0
        """)
        alert_count = cursor.fetchone()[0]
        
        # Connections per hour
        cursor.execute("""
            SELECT COUNT(*) FROM connections
            WHERE timestamp > datetime('now', '-1 hour')
        """)
        conn_count = cursor.fetchone()[0]
        
        # Status message
        if alert_count == 0:
            status = [
                html.Strong("🟢 System Active - All Clear"),
                f" | Monitoring {device_count} devices"
            ]
        elif alert_count < 5:
            status = [
                html.Strong(f"🟡 System Active - {alert_count} Alert(s)"),
                f" | Review alerts tab"
            ]
        else:
            status = [
                html.Strong(f"🔴 High Alert - {alert_count} Alerts"),
                f" | Immediate attention required"
            ]
        
        return str(device_count), str(alert_count), str(conn_count), status
        
    except Exception as e:
        logger.error(f"Error updating header: {e}")
        return "0", "0", "0", "⚠️ Error loading stats"
    finally:
        conn.close()


# ============================================================================
# CALLBACKS - NETWORK TAB
# ============================================================================

@app.callback(
    Output('network-graph', 'figure'),
    Input('interval-component', 'n_intervals')
)
def update_network_graph(n):
    """Network topology visualization with alert color coding."""
    conn = get_db_connection()
    if not conn:
        return go.Figure()
    
    query = """
        SELECT 
            d.device_ip,
            d.device_name,
            d.device_type,
            COUNT(a.id) as alert_count,
            MAX(CASE a.severity 
                WHEN 'critical' THEN 4 
                WHEN 'high' THEN 3 
                WHEN 'medium' THEN 2 
                WHEN 'low' THEN 1 
                ELSE 0 
            END) as max_severity
        FROM devices d
        LEFT JOIN alerts a ON d.device_ip = a.device_ip 
             AND a.timestamp > datetime('now', '-1 hour')
             AND a.acknowledged = 0
        WHERE d.last_seen > datetime('now', '-5 minutes')
        GROUP BY d.device_ip
    """
    
    try:
        df = pd.read_sql_query(query, conn)
    except Exception as e:
        logger.error(f"Error fetching network data: {e}")
        df = pd.DataFrame()
    finally:
        conn.close()
    
    if len(df) == 0:
        return {
            'data': [],
            'layout': {
                'title': 'No active devices detected',
                'xaxis': {'visible': False},
                'yaxis': {'visible': False},
                'height': 450
            }
        }
    
    # Circular layout
    n_devices = len(df)
    angles = np.linspace(0, 2*np.pi, n_devices, endpoint=False)
    
    # Router at center
    router_x, router_y = [0], [0]
    device_x = np.cos(angles).tolist()
    device_y = np.sin(angles).tolist()
    
    # Edge traces (router to devices)
    edge_traces = []
    for x, y in zip(device_x, device_y):
        edge_traces.append(go.Scatter(
            x=[0, x, None],
            y=[0, y, None],
            mode='lines',
            line=dict(width=1, color='#ccc'),
            hoverinfo='none',
            showlegend=False
        ))
    
    # Router node
    router_trace = go.Scatter(
        x=router_x,
        y=router_y,
        mode='markers+text',
        marker=dict(size=40, color='lightblue', symbol='square',
                   line=dict(width=2, color='white')),
        text=['Router'],
        textposition='bottom center',
        hoverinfo='text',
        hovertext='Home Router',
        showlegend=False
    )
    
    # Device nodes with color coding
    device_colors = []
    device_text = []
    device_hover = []
    
    for _, row in df.iterrows():
        # Color by alert severity
        if row['alert_count'] == 0:
            color = '#28a745'  # Green - normal
            status = 'Normal'
        elif row['max_severity'] <= 2:
            color = '#ffc107'  # Yellow - warning
            status = 'Warning'
        else:
            color = '#dc3545'  # Red - critical
            status = 'ALERT'
        
        device_colors.append(color)
        name = row['device_name'] or row['device_ip']
        device_text.append(name[:20])  # Truncate
        
        hover = f"<b>{name}</b><br>"
        hover += f"IP: {row['device_ip']}<br>"
        hover += f"Type: {row['device_type'] or 'Unknown'}<br>"
        hover += f"Status: {status}"
        if row['alert_count'] > 0:
            hover += f"<br>⚠️ {row['alert_count']} active alert(s)"
        device_hover.append(hover)
    
    device_trace = go.Scatter(
        x=device_x,
        y=device_y,
        mode='markers+text',
        marker=dict(
            size=25,
            color=device_colors,
            line=dict(width=2, color='white')
        ),
        text=device_text,
        textposition='top center',
        textfont=dict(size=10),
        hovertext=device_hover,
        hoverinfo='text',
        showlegend=False
    )
    
    fig = go.Figure(data=edge_traces + [router_trace, device_trace])
    fig.update_layout(
        title='Network Topology',
        showlegend=False,
        hovermode='closest',
        margin=dict(l=20, r=20, t=40, b=20),
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        plot_bgcolor='#f8f9fa',
        height=450
    )
    return fig


@app.callback(
    Output('recent-activity', 'children'),
    Input('interval-component', 'n_intervals')
)
def update_recent_activity(n):
    """Live connection feed."""
    conn = get_db_connection()
    if not conn:
        return html.P("Database error", className="text-danger")
    
    query = """
        SELECT 
            c.timestamp,
            c.device_ip,
            d.device_name,
            c.dest_ip,
            c.dest_port,
            c.protocol,
            c.bytes_sent + c.bytes_received as total_bytes
        FROM connections c
        LEFT JOIN devices d ON c.device_ip = d.device_ip
        WHERE c.timestamp > datetime('now', '-5 minutes')
        ORDER BY c.timestamp DESC
        LIMIT 30
    """
    
    try:
        df = pd.read_sql_query(query, conn)
    except Exception as e:
        logger.error(f"Error fetching activity: {e}")
        df = pd.DataFrame()
    finally:
        conn.close()
    
    if len(df) == 0:
        return html.P("No recent activity", className="text-muted")
    
    items = []
    for _, row in df.iterrows():
        try:
            timestamp = datetime.fromisoformat(row['timestamp'])
            time_str = timestamp.strftime('%H:%M:%S')
        except:
            time_str = "Unknown"
        
        device_name = row['device_name'] or row['device_ip']
        
        # Format bytes
        bytes_val = row['total_bytes']
        if bytes_val < 1024:
            bytes_str = f"{bytes_val} B"
        elif bytes_val < 1024**2:
            bytes_str = f"{bytes_val/1024:.1f} KB"
        else:
            bytes_str = f"{bytes_val/(1024**2):.2f} MB"
        
        items.append(html.Div([
            html.Small([
                html.Strong(f"{time_str} "),
                device_name[:25],
                html.Br(),
                f"→ {row['dest_ip']}:{row['dest_port']} ({row['protocol']}) - {bytes_str}"
            ]),
            html.Hr(className="my-2")
        ]))
    
    return items


@app.callback(
    Output('traffic-timeline', 'figure'),
    Input('interval-component', 'n_intervals')
)
def update_traffic_timeline(n):
    """Real-time traffic graph (24 hours)."""
    conn = get_db_connection()
    if not conn:
        return go.Figure()
    
    query = """
        SELECT 
            strftime('%H:00', timestamp) as hour,
            SUM(bytes_sent + bytes_received) / (1024.0 * 1024.0) as mb
        FROM connections
        WHERE timestamp > datetime('now', '-24 hours')
        GROUP BY strftime('%Y-%m-%d %H', timestamp)
        ORDER BY hour
    """
    
    try:
        df = pd.read_sql_query(query, conn)
    except Exception as e:
        logger.error(f"Error fetching traffic: {e}")
        df = pd.DataFrame()
    finally:
        conn.close()
    
    if len(df) == 0:
        return go.Figure().update_layout(title="No traffic data")
    
    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=df['hour'],
        y=df['mb'],
        mode='lines+markers',
        fill='tozeroy',
        line=dict(color='#007bff', width=2),
        fillcolor='rgba(0,123,255,0.1)',
        name='Traffic'
    ))
    fig.update_layout(
        title='Network Traffic Volume',
        xaxis_title='Hour',
        yaxis_title='MB Transferred',
        hovermode='x unified',
        height=300,
        margin=dict(l=40, r=20, t=40, b=40)
    )
    return fig


@app.callback(
    Output('protocol-pie', 'figure'),
    Input('interval-component', 'n_intervals')
)
def update_protocol_pie(n):
    """Protocol distribution pie chart."""
    conn = get_db_connection()
    if not conn:
        return go.Figure()
    
    query = """
        SELECT protocol, COUNT(*) as count
        FROM connections
        WHERE timestamp > datetime('now', '-24 hours')
        GROUP BY protocol
        ORDER BY count DESC
    """
    
    try:
        df = pd.read_sql_query(query, conn)
    except Exception as e:
        logger.error(f"Error fetching protocols: {e}")
        df = pd.DataFrame()
    finally:
        conn.close()
    
    if len(df) == 0:
        return go.Figure().update_layout(title="No data")
    
    fig = go.Figure(data=[go.Pie(
        labels=df['protocol'],
        values=df['count'],
        hole=0.3,
        marker=dict(colors=px.colors.qualitative.Set3)
    )])
    fig.update_layout(
        title='Protocol Distribution',
        height=300,
        margin=dict(l=20, r=20, t=40, b=20)
    )
    return fig


# ============================================================================
# CALLBACKS - ALERTS TAB (WITH EDUCATIONAL FEATURES)
# ============================================================================

@app.callback(
    Output('alerts-container', 'children'),
    [Input('interval-component', 'n_intervals'),
     Input('alert-filter', 'data')]
)
def update_alerts(n, filter_severity):
    """Display alerts with educational explanations."""
    conn = get_db_connection()
    if not conn:
        return dbc.Alert("Database error", color="danger")
    
    # Build query with optional filter
    query = """
        SELECT 
            a.id,
            a.timestamp,
            a.device_ip,
            d.device_name,
            a.severity,
            a.anomaly_score,
            a.explanation,
            a.top_features,
            a.acknowledged
        FROM alerts a
        LEFT JOIN devices d ON a.device_ip = d.device_ip
        WHERE a.timestamp > datetime('now', '-24 hours')
    """
    
    if filter_severity != 'all':
        query += f" AND a.severity = '{filter_severity}'"
    
    query += """
        ORDER BY 
            CASE a.severity
                WHEN 'critical' THEN 1
                WHEN 'high' THEN 2
                WHEN 'medium' THEN 3
                WHEN 'low' THEN 4
            END,
            a.timestamp DESC
    """
    
    try:
        df = pd.read_sql_query(query, conn)
    except Exception as e:
        logger.error(f"Error fetching alerts: {e}")
        df = pd.DataFrame()
    finally:
        conn.close()
    
    if len(df) == 0:
        return dbc.Alert([
            html.H4("✅ All Clear!", className="alert-heading"),
            html.P("No security alerts in the last 24 hours.")
        ], color="success")
    
    alert_cards = []
    severity_colors = {
        'critical': 'danger',
        'high': 'warning',
        'medium': 'info',
        'low': 'secondary'
    }
    
    for _, alert in df.iterrows():
        device_name = alert['device_name'] or alert['device_ip']
        
        try:
            timestamp = datetime.fromisoformat(alert['timestamp'])
            time_str = timestamp.strftime('%Y-%m-%d %H:%M:%S')
        except:
            time_str = "Unknown time"
        
        severity = alert['severity']
        color = severity_colors.get(severity, 'secondary')
        
        # Parse top features
        try:
            top_features = json.loads(alert['top_features'])
            if isinstance(top_features, dict):
                features_list = [
                    {'name': k, 'value': v}
                    for k, v in list(top_features.items())[:3]
                ]
            else:
                features_list = top_features[:3] if isinstance(top_features, list) else []
        except:
            features_list = []
        
        # Create alert card with educational features
        card = dbc.Card([
            dbc.CardHeader([
                dbc.Badge(severity.upper(), color=color, className="me-2"),
                html.Strong(f"{device_name} - Unusual Activity Detected"),
                html.Span(time_str, className="float-end text-muted small")
            ]),
            dbc.CardBody([
                # Plain English explanation
                html.P(alert['explanation'], className="lead mb-3"),
                
                # Educational drill-down
                dbc.Accordion([
                    dbc.AccordionItem([
                        html.H6("Why is this flagged as unusual?"),
                        html.P(
                            "Our machine learning model learned what's 'normal' "
                            "for this device during the 7-day baseline period. "
                            "This connection significantly deviates from that learned pattern."
                        ),
                        
                        html.H6("Anomaly Score:", className="mt-3"),
                        dbc.Progress(
                            value=abs(alert['anomaly_score']) * 100,
                            label=f"{alert['anomaly_score']:.4f}",
                            color="danger" if abs(alert['anomaly_score']) > 0.5 else "warning",
                            className="mb-3"
                        ),
                        html.Small(
                            "Scores further from 0 indicate more unusual behavior. "
                            "Negative scores indicate anomalies detected by Isolation Forest.",
                            className="text-muted"
                        ),
                        
                        # Top contributing features
                        html.H6("Top Contributing Factors:", className="mt-3"),
                        html.Ul([
                            html.Li(
                                f"{feat['name'].replace('_', ' ').title()}: "
                                f"{feat['value']:.2f}" if isinstance(feat.get('value'), (int, float))
                                else f"{feat['name'].replace('_', ' ').title()}"
                            )
                            for feat in features_list
                        ]) if features_list else html.P("Details not available", className="text-muted"),
                        
                        # Visual comparison (if we have baseline data)
                        html.H6("What makes this different?", className="mt-3"),
                        html.P(
                            "This connection's characteristics (data volume, duration, "
                            "timing, destination) differ significantly from the typical "
                            "patterns we've observed for this device."
                        )
                        
                    ], title="📊 Technical Details & Explanation")
                ], start_collapsed=True),
                
                # Action buttons
                html.Div([
                    dbc.Button(
                        "✓ Acknowledge" if not alert['acknowledged'] else "✓ Acknowledged",
                        color="success" if alert['acknowledged'] else "primary",
                        size="sm",
                        className="me-2",
                        disabled=bool(alert['acknowledged'])
                    ),
                    dbc.Button(
                        "View Device",
                        color="info",
                        size="sm",
                        outline=True
                    )
                ], className="mt-3")
            ])
        ], className="mb-3", color=color, outline=True)
        
        alert_cards.append(card)
    
    return alert_cards


# Filter button callbacks
@app.callback(
    Output('alert-filter', 'data'),
    [Input('filter-all', 'n_clicks'),
     Input('filter-critical', 'n_clicks'),
     Input('filter-high', 'n_clicks'),
     Input('filter-medium', 'n_clicks'),
     Input('filter-low', 'n_clicks')]
)
def update_alert_filter(all_clicks, crit_clicks, high_clicks, med_clicks, low_clicks):
    """Update alert filter based on button clicks."""
    ctx = callback_context
    if not ctx.triggered:
        return 'all'
    
    button_id = ctx.triggered[0]['prop_id'].split('.')[0]
    filter_map = {
        'filter-all': 'all',
        'filter-critical': 'critical',
        'filter-high': 'high',
        'filter-medium': 'medium',
        'filter-low': 'low'
    }
    return filter_map.get(button_id, 'all')


# ============================================================================
# CALLBACKS - DEVICES TAB
# ============================================================================

@app.callback(
    Output('devices-table', 'children'),
    Input('interval-component', 'n_intervals')
)
def update_devices_table(n):
    """Device list with comprehensive stats."""
    conn = get_db_connection()
    if not conn:
        return html.P("Database error", className="text-danger")
    
    query = """
        SELECT 
            d.device_ip,
            d.device_name,
            d.device_type,
            d.mac_address,
            d.last_seen,
            COUNT(DISTINCT c.id) as conn_count,
            SUM(c.bytes_sent + c.bytes_received) / (1024.0 * 1024.0) as mb,
            COUNT(DISTINCT a.id) as alert_count
        FROM devices d
        LEFT JOIN connections c ON d.device_ip = c.device_ip 
             AND c.timestamp > datetime('now', '-24 hours')
        LEFT JOIN alerts a ON d.device_ip = a.device_ip 
             AND a.timestamp > datetime('now', '-24 hours')
             AND a.acknowledged = 0
        GROUP BY d.device_ip
        ORDER BY d.last_seen DESC
    """
    
    try:
        df = pd.read_sql_query(query, conn)
    except Exception as e:
        logger.error(f"Error fetching devices: {e}")
        df = pd.DataFrame()
    finally:
        conn.close()
    
    if len(df) == 0:
        return html.P("No devices detected", className="text-muted")
    
    table_rows = []
    for _, device in df.iterrows():
        try:
            last_seen = datetime.fromisoformat(device['last_seen'])
            time_diff = datetime.now()
            time_diff = datetime.now() - last_seen
        except:
            time_diff = timedelta(hours=999)
        
        # Status indicator
        if time_diff < timedelta(minutes=5):
            status = html.Span("🟢 Active", className="text-success")
        elif time_diff < timedelta(hours=1):
            status = html.Span("🟡 Idle", className="text-warning")
        else:
            status = html.Span("⚪ Offline", className="text-muted")
        
        # Alert badge
        alert_badge = dbc.Badge(
            str(device['alert_count']),
            color="danger" if device['alert_count'] > 0 else "success",
            pill=True
        )
        
        table_rows.append(html.Tr([
            html.Td(status),
            html.Td(device['device_name'] or "Unknown"),
            html.Td(html.Code(device['device_ip'])),
            html.Td(device['device_type'] or "Unknown"),
            html.Td(f"{device['conn_count']:,}"),
            html.Td(f"{device['mb'] or 0:.2f} MB"),
            html.Td(alert_badge),
            html.Td([
                dbc.ButtonGroup([
                    dbc.Button("📊", size="sm", color="info", outline=True, title="View Details"),
                    dbc.Button("🚫", size="sm", color="danger", outline=True, title="Block Device")
                ], size="sm")
            ])
        ]))
    
    table = dbc.Table([
        html.Thead(html.Tr([
            html.Th("Status"),
            html.Th("Name"),
            html.Th("IP Address"),
            html.Th("Type"),
            html.Th("Connections (24h)"),
            html.Th("Data (24h)"),
            html.Th("Alerts"),
            html.Th("Actions")
        ])),
        html.Tbody(table_rows)
    ], bordered=True, hover=True, responsive=True, striped=True)
    
    return table


@app.callback(
    Output('device-heatmap', 'figure'),
    Input('interval-component', 'n_intervals')
)
def update_device_heatmap(n):
    """Device activity heatmap (hour of day vs device) - NEW!"""
    conn = get_db_connection()
    if not conn:
        return go.Figure()
    
    query = """
        SELECT 
            COALESCE(d.device_name, d.device_ip) as device,
            strftime('%H', c.timestamp) as hour,
            COUNT(*) as count
        FROM connections c
        JOIN devices d ON c.device_ip = d.device_ip
        WHERE c.timestamp > datetime('now', '-24 hours')
        GROUP BY device, hour
        HAVING count > 0
    """
    
    try:
        df = pd.read_sql_query(query, conn)
    except Exception as e:
        logger.error(f"Error fetching heatmap data: {e}")
        df = pd.DataFrame()
    finally:
        conn.close()
    
    if len(df) == 0:
        return go.Figure().update_layout(
            title="No activity data available",
            height=400
        )
    
    # Pivot data for heatmap
    pivot = df.pivot(index='device', columns='hour', values='count').fillna(0)
    
    # Limit to top 10 devices for readability
    if len(pivot) > 10:
        row_sums = pivot.sum(axis=1).sort_values(ascending=False)
        pivot = pivot.loc[row_sums.index[:10]]
    
    fig = go.Figure(data=go.Heatmap(
        z=pivot.values,
        x=[f"{int(h):02d}:00" for h in pivot.columns],
        y=pivot.index,
        colorscale='YlOrRd',
        hovertemplate='<b>%{y}</b><br>%{x}<br>Connections: %{z}<extra></extra>',
        colorbar=dict(title="Connections")
    ))
    
    fig.update_layout(
        title='Device Activity by Hour of Day',
        xaxis_title='Hour',
        yaxis_title='Device',
        height=400,
        margin=dict(l=150, r=20, t=40, b=40)
    )
    return fig


# ============================================================================
# CALLBACKS - ANALYTICS TAB (NEW!)
# ============================================================================

@app.callback(
    Output('alert-timeline', 'figure'),
    Input('interval-component', 'n_intervals')
)
def update_alert_timeline(n):
    """Alert timeline over past 7 days - NEW!"""
    conn = get_db_connection()
    if not conn:
        return go.Figure()
    
    query = """
        SELECT 
            DATE(timestamp) as date,
            severity,
            COUNT(*) as count
        FROM alerts
        WHERE timestamp > datetime('now', '-7 days')
        GROUP BY date, severity
        ORDER BY date
    """
    
    try:
        df = pd.read_sql_query(query, conn)
    except Exception as e:
        logger.error(f"Error fetching alert timeline: {e}")
        df = pd.DataFrame()
    finally:
        conn.close()
    
    if len(df) == 0:
        return go.Figure().update_layout(
            title="No alerts in past 7 days",
            height=350
        )
    
    fig = go.Figure()
    
    severity_colors = {
        'critical': '#dc3545',
        'high': '#fd7e14',
        'medium': '#ffc107',
        'low': '#6c757d'
    }
    
    for severity in ['critical', 'high', 'medium', 'low']:
        severity_data = df[df['severity'] == severity]
        if not severity_data.empty:
            fig.add_trace(go.Bar(
                x=severity_data['date'],
                y=severity_data['count'],
                name=severity.capitalize(),
                marker_color=severity_colors.get(severity, '#6c757d')
            ))
    
    fig.update_layout(
        title='Alert Timeline (Past 7 Days)',
        xaxis_title='Date',
        yaxis_title='Number of Alerts',
        barmode='stack',
        hovermode='x unified',
        height=350,
        margin=dict(l=40, r=20, t=40, b=40),
        legend=dict(orientation='h', yanchor='bottom', y=1.02, xanchor='right', x=1)
    )
    return fig


@app.callback(
    Output('anomaly-distribution', 'figure'),
    Input('interval-component', 'n_intervals')
)
def update_anomaly_distribution(n):
    """Histogram of anomaly scores - NEW!"""
    conn = get_db_connection()
    if not conn:
        return go.Figure()
    
    query = """
        SELECT anomaly_score, is_anomaly
        FROM ml_predictions
        WHERE timestamp > datetime('now', '-7 days')
        LIMIT 10000
    """
    
    try:
        df = pd.read_sql_query(query, conn)
    except Exception as e:
        logger.error(f"Error fetching anomaly scores: {e}")
        df = pd.DataFrame()
    finally:
        conn.close()
    
    if len(df) == 0:
        return go.Figure().update_layout(
            title="No prediction data available",
            height=350
        )
    
    # Separate normal and anomalous
    normal_scores = df[df['is_anomaly'] == 0]['anomaly_score']
    anomaly_scores = df[df['is_anomaly'] == 1]['anomaly_score']
    
    fig = go.Figure()
    
    if len(normal_scores) > 0:
        fig.add_trace(go.Histogram(
            x=normal_scores,
            name='Normal',
            marker_color='rgba(40, 167, 69, 0.7)',
            opacity=0.7,
            nbinsx=40
        ))
    
    if len(anomaly_scores) > 0:
        fig.add_trace(go.Histogram(
            x=anomaly_scores,
            name='Anomaly',
            marker_color='rgba(220, 53, 69, 0.7)',
            opacity=0.7,
            nbinsx=40
        ))
    
    fig.update_layout(
        title='Anomaly Score Distribution',
        xaxis_title='Anomaly Score',
        yaxis_title='Count',
        barmode='overlay',
        hovermode='x unified',
        height=350,
        margin=dict(l=40, r=20, t=40, b=40),
        legend=dict(orientation='h', yanchor='bottom', y=1.02, xanchor='right', x=1)
    )
    return fig


@app.callback(
    Output('system-performance', 'figure'),
    Input('interval-component', 'n_intervals')
)
def update_system_performance(n):
    """ML engine performance metrics - NEW!"""
    conn = get_db_connection()
    if not conn:
        return go.Figure()
    
    query = """
        SELECT 
            strftime('%Y-%m-%d %H:00', timestamp) as hour,
            COUNT(*) as processed,
            SUM(CASE WHEN is_anomaly = 1 THEN 1 ELSE 0 END) as anomalies
        FROM ml_predictions
        WHERE timestamp > datetime('now', '-24 hours')
        GROUP BY hour
        ORDER BY hour
    """
    
    try:
        df = pd.read_sql_query(query, conn)
    except Exception as e:
        logger.error(f"Error fetching performance: {e}")
        df = pd.DataFrame()
    finally:
        conn.close()
    
    if len(df) == 0:
        return go.Figure().update_layout(
            title="No performance data available",
            height=350
        )
    
    fig = go.Figure()
    
    fig.add_trace(go.Scatter(
        x=df['hour'],
        y=df['processed'],
        name='Connections Processed',
        mode='lines+markers',
        line=dict(color='#007bff', width=2),
        marker=dict(size=6)
    ))
    
    fig.add_trace(go.Scatter(
        x=df['hour'],
        y=df['anomalies'],
        name='Anomalies Detected',
        mode='lines+markers',
        line=dict(color='#dc3545', width=2),
        marker=dict(size=6)
    ))
    
    fig.update_layout(
        title='ML Engine Performance (24 Hours)',
        xaxis_title='Time',
        yaxis_title='Count',
        hovermode='x unified',
        height=350,
        margin=dict(l=40, r=20, t=40, b=40),
        legend=dict(orientation='h', yanchor='bottom', y=1.02, xanchor='right', x=1)
    )
    return fig


# ============================================================================
# CALLBACKS - SYSTEM TAB
# ============================================================================

@app.callback(
    Output('system-info', 'children'),
    Input('interval-component', 'n_intervals')
)
def update_system_info(n):
    """System status information."""
    conn = get_db_connection()
    if not conn:
        return html.P("Database error", className="text-danger")
    
    try:
        cursor = conn.cursor()
        
        # Database stats
        cursor.execute("SELECT COUNT(*) FROM devices")
        total_devices = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM connections")
        total_connections = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM alerts")
        total_alerts = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM ml_predictions")
        total_predictions = cursor.fetchone()[0]
        
        # Database size
        db_size = Path(DB_PATH).stat().st_size / (1024**2)  # MB
        
        info = [
            html.H5("Database Statistics", className="mb-3"),
            dbc.Row([
                dbc.Col([
                    html.Div([
                        html.H3(f"{total_devices:,}", className="text-primary"),
                        html.P("Total Devices Seen", className="text-muted small")
                    ])
                ], width=3),
                dbc.Col([
                    html.Div([
                        html.H3(f"{total_connections:,}", className="text-info"),
                        html.P("Total Connections", className="text-muted small")
                    ])
                ], width=3),
                dbc.Col([
                    html.Div([
                        html.H3(f"{total_alerts:,}", className="text-warning"),
                        html.P("Total Alerts", className="text-muted small")
                    ])
                ], width=3),
                dbc.Col([
                    html.Div([
                        html.H3(f"{total_predictions:,}", className="text-success"),
                        html.P("ML Predictions", className="text-muted small")
                    ])
                ], width=3)
            ], className="mb-3"),
            
            html.Hr(),
            
            html.H5("System Health", className="mb-3"),
            dbc.ListGroup([
                dbc.ListGroupItem([
                    html.Strong("Database Size: "),
                    f"{db_size:.2f} MB"
                ]),
                dbc.ListGroupItem([
                    html.Strong("Database Path: "),
                    html.Code(str(DB_PATH))
                ]),
                dbc.ListGroupItem([
                    html.Strong("Status: "),
                    html.Span("🟢 Operational", className="text-success")
                ])
            ])
        ]
        
    except Exception as e:
        logger.error(f"Error fetching system info: {e}")
        info = [html.P("Error loading system info", className="text-danger")]
    finally:
        conn.close()
    
    return info


@app.callback(
    Output('model-info', 'children'),
    Input('interval-component', 'n_intervals')
)
def update_model_info(n):
    """ML model information."""
    conn = get_db_connection()
    if not conn:
        return html.P("Database error", className="text-danger")
    
    try:
        cursor = conn.cursor()
        
        # Get model stats
        cursor.execute("""
            SELECT 
                model_type,
                COUNT(*) as predictions,
                AVG(anomaly_score) as avg_score,
                SUM(is_anomaly) as anomalies
            FROM ml_predictions
            WHERE timestamp > datetime('now', '-7 days')
            GROUP BY model_type
        """)
        
        model_stats = cursor.fetchall()
        
        info = [
            html.H5("ML Models", className="mb-3"),
            dbc.ListGroup([
                dbc.ListGroupItem([
                    html.Strong("Primary Model: "),
                    "Isolation Forest"
                ]),
                dbc.ListGroupItem([
                    html.Strong("Model Version: "),
                    "v1.0"
                ]),
                dbc.ListGroupItem([
                    html.Strong("Baseline Period: "),
                    "7 days"
                ]),
                dbc.ListGroupItem([
                    html.Strong("Features: "),
                    "15+ network features"
                ])
            ], className="mb-3"),
            
            html.H5("Performance (7 Days)", className="mb-3"),
        ]
        
        if model_stats:
            for row in model_stats:
                model_type, predictions, avg_score, anomalies = row
                anomaly_rate = (anomalies / predictions * 100) if predictions > 0 else 0
                
                info.append(dbc.Card([
                    dbc.CardHeader(f"{model_type.replace('_', ' ').title()}"),
                    dbc.CardBody([
                        html.P(f"Predictions: {predictions:,}"),
                        html.P(f"Anomalies Detected: {anomalies:,}"),
                        html.P(f"Anomaly Rate: {anomaly_rate:.2f}%"),
                        html.P(f"Avg Score: {avg_score:.4f}")
                    ])
                ], className="mb-2"))
        else:
            info.append(html.P("No model data available", className="text-muted"))
            
    except Exception as e:
        logger.error(f"Error fetching model info: {e}")
        info = [html.P("Error loading model info", className="text-danger")]
    finally:
        conn.close()
    
    return info


# ============================================================================
# MAIN
# ============================================================================

def main():
    """Run the dashboard server."""
    host = config.get('dashboard', 'host')
    port = config.get('dashboard', 'port')
    debug = config.get('dashboard', 'debug', default=False)
    
    logger.info("=" * 70)
    logger.info("IoTSentinel Dashboard - Complete Edition")
    logger.info("=" * 70)
    logger.info(f"🌐 URL: http://{host}:{port}")
    logger.info(f"📊 Database: {DB_PATH}")
    logger.info("=" * 70)
    logger.info("Features:")
    logger.info("  ✅ Network topology visualization")
    logger.info("  ✅ Real-time traffic graphs")
    logger.info("  ✅ Device activity heatmap")
    logger.info("  ✅ Alert timeline (7 days)")
    logger.info("  ✅ Anomaly score distribution")
    logger.info("  ✅ Educational alert explanations")
    logger.info("  ✅ System performance monitoring")
    logger.info("=" * 70)
    
    app.run_server(host=host, port=port, debug=debug)


if __name__ == '__main__':
    main()