#!/usr/bin/env python3
"""
IoTSentinel Web Dashboard

Educational transparency-focused user interface for network security monitoring.
This version is 100% compatible with your db_manager.py and schema.
"""
import dash
from dash import dcc, html, Input, Output, State, callback
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

# --- Setup Project Path ---
import sys
dashboard_dir = Path(__file__).parent
project_root = dashboard_dir.parent
sys.path.insert(0, str(project_root))

from database.db_manager import DatabaseManager
from config.config_manager import config

logger = logging.getLogger(__name__)

# Initialize Dash app
app = dash.Dash(
    __name__,
    external_stylesheets=[dbc.themes.BOOTSTRAP],
    title="IoTSentinel Dashboard"
)

# --- Database Connection ---
# Use the path from your config file
DB_PATH = config.get('database', 'path')

def get_db_connection():
    """Get a read-only SQLite database connection."""
    try:
        # Connect in read-only mode (mode=ro) for safety
        conn = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        return conn
    except Exception as e:
        logger.error(f"Error connecting to database: {e}")
        return None

# --- App Layout ---
# This is the full layout from your plan
app.layout = dbc.Container([
    # Header
    dbc.Row([
        dbc.Col([
            html.H1("🛡️ IoTSentinel", className="text-primary"),
            html.P("Home Network Security Monitor", className="text-muted")
        ], width=8),
        dbc.Col([
            html.Div([
                html.H3(id='device-count', children="0", className="text-success"),
                html.P("Connected Devices", className="text-muted small")
            ], className="text-end")
        ], width=4)
    ], className="mb-4 mt-3"),
    
    # Status indicator
    dbc.Row([
        dbc.Col([
            dbc.Alert([
                html.Strong("🟢 System Active"),
                " - Monitoring your network for unusual activity"
            ], color="success", className="mb-3")
        ])
    ]),
    
    # Main content tabs
    dbc.Tabs([
        # Tab 1: Network Overview
        dbc.Tab(label="Network Overview", tab_id="tab-network", children=[
            dbc.Row([
                # Network map
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("Network Map"),
                        dbc.CardBody([
                            dcc.Graph(id='network-graph', style={'height': '400px'})
                        ])
                    ], className="mb-3")
                ], width=8),
                
                # Recent activity
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("Recent Activity"),
                        dbc.CardBody([
                            html.Div(id='recent-activity-list', style={'height': '400px', 'overflowY': 'scroll'})
                        ])
                    ])
                ], width=4)
            ]),
            
            dbc.Row([
                # Traffic volume chart
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("Network Traffic (Last Hour)"),
                        dbc.CardBody([
                            dcc.Graph(id='traffic-chart', style={'height': '300px'})
                        ])
                    ])
                ], width=12)
            ], className="mt-3")
        ]),
        
        # Tab 2: Alerts
        dbc.Tab(label="Security Alerts", tab_id="tab-alerts", children=[
            dbc.Row([
                dbc.Col([
                    html.Div(id='alerts-container')
                ])
            ])
        ]),
        
        # Tab 3: Devices
        dbc.Tab(label="Devices", tab_id="tab-devices", children=[
            dbc.Row([
                dbc.Col([
                    html.Div(id='devices-container')
                ])
            ])
        ]),
        
        # Tab 4: Statistics
        dbc.Tab(label="Statistics", tab_id="tab-stats", children=[
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("System Performance"),
                        dbc.CardBody([
                            dcc.Graph(id='performance-chart')
                        ])
                    ])
                ], width=6),
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("Detection Metrics"),
                        dbc.CardBody([
                            html.Div(id='metrics-display')
                        ])
                    ])
                ], width=6)
            ])
        ])
    ], id="tabs", active_tab="tab-network"),

    # Auto-refresh interval
    dcc.Interval(
        id='interval-component',
        interval=5*1000,  # Update every 5 seconds
        n_intervals=0)
], fluid=True, className="p-4")

# --- Callbacks (NOW 100% COMPATIBLE with db_manager.py) ---

@app.callback(
    Output('device-count', 'children'),
    Input('interval-component', 'n_intervals')
)
def update_device_count(n):
    """Update count of connected devices."""
    conn = get_db_connection()
    if not conn: return "Error"
    
    try:
        cursor = conn.cursor()
        # FIXED: Uses 'devices' table and 'device_ip' as the key
        cursor.execute("""
            SELECT COUNT(DISTINCT device_ip) 
            FROM devices 
            WHERE last_seen > datetime('now', '-5 minutes')
        """)
        count = cursor.fetchone()[0]
    except Exception as e:
        logger.warning(f"DB Error update_device_count: {e}")
        count = 0
    finally:
        conn.close()
        
    return str(count)

@app.callback(
    Output('network-graph', 'figure'),
    Input('interval-component', 'n_intervals')
)
def update_network_graph(n):
    """Generate network topology visualization."""
    conn = get_db_connection()
    if not conn: return go.Figure()
    
    # FIXED: Uses 'devices' and 'alerts' tables
    query = """
        SELECT 
            d.device_ip,
            d.device_name,
            d.device_type,
            COUNT(a.id) as alert_count,
            MAX(CASE a.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END) as max_severity_num
        FROM devices d
        LEFT JOIN alerts a ON d.device_ip = a.device_ip 
             AND a.timestamp > datetime('now', '-1 hour')
        WHERE d.last_seen > datetime('now', '-5 minutes')
        GROUP BY d.device_ip
    """
    try:
        df = pd.read_sql_query(query, conn)
    except Exception as e:
        logger.warning(f"DB Error update_network_graph: {e}")
        df = pd.DataFrame()
    finally:
        conn.close()

    if len(df) == 0:
        return {'data': [], 'layout': {'title': 'No active devices', 'xaxis': {'visible': False}, 'yaxis': {'visible': False}}}

    # ... (Graphing logic is the same) ...
    n_devices = len(df)
    angles = np.linspace(0, 2*np.pi, n_devices, endpoint=False)
    router_x, router_y = [0], [0]
    device_x = np.cos(angles).tolist()
    device_y = np.sin(angles).tolist()

    edge_traces = [
        go.Scatter(x=[0, x, None], y=[0, y, None], mode='lines', line=dict(width=1, color='#888'), hoverinfo='none', showlegend=False)
        for x, y in zip(device_x, device_y)
    ]
    router_trace = go.Scatter(x=router_x, y=router_y, mode='markers+text', marker=dict(size=30, color='lightblue', symbol='square'), text=['Router'], textposition='bottom center', hoverinfo='text', showlegend=False)

    device_colors = []
    device_text = []
    device_hover = []
    for _, row in df.iterrows():
        if row['alert_count'] == 0:
            color, status = '#28a745', 'Normal'  # Green
        elif row['max_severity_num'] <= 2:
            color, status = '#ffc107', 'Warning' # Yellow
        else:
            color, status = '#dc3545', 'Alert'   # Red
            
        device_colors.append(color)
        name = row['device_name'] or row['device_ip']
        device_text.append(name)
        hover_text = f"{name}<br>IP: {row['device_ip']}<br>Type: {row['device_type']}<br>Status: {status}"
        if row['alert_count'] > 0:
            hover_text += f"<br>Alerts: {row['alert_count']}"
        device_hover.append(hover_text)

    device_trace = go.Scatter(
        x=device_x, y=device_y, mode='markers+text',
        marker=dict(size=20, color=device_colors, line=dict(width=2, color='white')),
        text=device_text, textposition='top center', hovertext=device_hover, hoverinfo='text', showlegend=False
    )

    fig = go.Figure(data=edge_traces + [router_trace, device_trace])
    fig.update_layout(
        title='Network Topology', showlegend=False, hovermode='closest',
        margin=dict(l=20, r=20, t=40, b=20),
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        plot_bgcolor='#f8f9fa', height=400
    )
    return fig

@app.callback(
    Output('recent-activity-list', 'children'),
    Input('interval-component', 'n_intervals')
)
def update_recent_activity(n):
    """Display recent network connections."""
    conn = get_db_connection()
    if not conn: return html.P("Database connection error.", className="text-danger")

    # FIXED: Uses 'connections' table and joins on 'device_ip'
    query = """
        SELECT 
            c.timestamp,
            d.device_name,
            c.device_ip,
            c.dest_ip,
            c.dest_port,
            c.protocol,
            c.bytes_sent + c.bytes_received as total_bytes
        FROM connections c
        LEFT JOIN devices d ON c.device_ip = d.device_ip
        WHERE c.timestamp > datetime('now', '-5 minutes')
        ORDER BY c.timestamp DESC
        LIMIT 20
    """
    try:
        df = pd.read_sql_query(query, conn)
    except Exception as e:
        logger.warning(f"DB Error update_recent_activity: {e}")
        df = pd.DataFrame()
    finally:
        conn.close()

    if len(df) == 0:
        return html.P("No recent activity", className="text-muted")

    items = []
    for _, row in df.iterrows():
        device_name = row['device_name'] or row['device_ip']
        # FIXED: Reads 'timestamp' as a string
        timestamp = datetime.fromisoformat(row['timestamp'])
        time_str = timestamp.strftime('%H:%M:%S')
        
        bytes_mb = row['total_bytes'] / (1024 * 1024)
        bytes_str = f"{bytes_mb:.2f} MB" if bytes_mb >= 1 else f"{row['total_bytes'] / 1024:.1f} KB"
            
        items.append(
            html.Div([
                html.Strong(f"{time_str} - {device_name}"),
                html.Br(),
                html.Small(f"→ {row['dest_ip']}:{row['dest_port']} ({row['protocol']}) - {bytes_str}"),
                html.Hr()
            ])
        )
    return items

@app.callback(
    Output('traffic-chart', 'figure'),
    Input('interval-component', 'n_intervals')
)
def update_traffic_chart(n):
    """Display network traffic volume over time."""
    conn = get_db_connection()
    if not conn: return go.Figure()

    # FIXED: Uses 'connections' table and 'bytes_sent' / 'bytes_received'
    query = """
        SELECT 
            strftime('%Y-%m-%d %H:%M', timestamp) as time_bucket,
            SUM(bytes_sent + bytes_received) / 1024.0 / 1024.0 as mb_transferred
        FROM connections
        WHERE timestamp > datetime('now', '-1 hour')
        GROUP BY time_bucket
        ORDER BY time_bucket
    """
    try:
        df = pd.read_sql_query(query, conn)
    except Exception as e:
        logger.warning(f"DB Error update_traffic_chart: {e}")
        df = pd.DataFrame()
    finally:
        conn.close()

    if len(df) == 0:
        return {'data': [], 'layout': {'title': 'No traffic data'}}

    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=df['time_bucket'], y=df['mb_transferred'], mode='lines+markers',
        name='Traffic', line=dict(color='#007bff', width=2),
        fill='tozeroy', fillcolor='rgba(0, 123, 255, 0.2)'
    ))
    fig.update_layout(
        title='Network Traffic Volume (Last Hour)',
        xaxis_title='Time', yaxis_title='Data Transferred (MB)',
        hovermode='x unified', height=300,
        margin=dict(l=40, r=20, t=40, b=40)
    )
    return fig

@app.callback(
    Output('alerts-container', 'children'),
    Input('interval-component', 'n_intervals')
)
def update_alerts(n):
    """Display security alerts with educational explanations."""
    conn = get_db_connection()
    if not conn: return dbc.Alert("Database connection error.", color="danger")

    # FIXED: Uses 'alerts' table
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
        logger.warning(f"DB Error update_alerts: {e}")
        df = pd.DataFrame()
    finally:
        conn.close()

    if len(df) == 0:
        return dbc.Alert([
            html.H4("✅ All Clear!", className="alert-heading"),
            html.P("No security alerts in the last 24 hours.")
        ], color="success")

    alerts_by_severity = {
        'critical': df[df['severity'] == 'critical'],
        'high': df[df['severity'] == 'high'],
        'medium': df[df['severity'] == 'medium'],
        'low': df[df['severity'] == 'low']
    }
    
    alert_cards = []
    for severity, color in [('critical', 'danger'), ('high', 'warning'), 
                         ('medium', 'info'), ('low', 'secondary')]:
        alerts = alerts_by_severity[severity]
        if len(alerts) == 0: continue
            
        for _, alert in alerts.iterrows():
            device_name = alert['device_name'] or alert['device_ip']
            timestamp = datetime.fromisoformat(alert['timestamp'])
            time_str = timestamp.strftime('%Y-%m-%d %H:%M:%S')
            
            try:
                top_features = json.loads(alert['top_features'])
            except:
                top_features = []
            
            alert_card = dbc.Card([
                dbc.CardHeader([
                    dbc.Badge(severity.upper(), color=color, className="me-2"),
                    html.Strong(f"{device_name} - Unusual Activity"),
                    html.Span(time_str, className="float-end text-muted small")
                ]),
                dbc.CardBody([
                    html.P(alert['explanation'], className="lead"),
                    dbc.Accordion([
                        dbc.AccordionItem([
                            html.P("This activity was flagged by the machine learning model as a significant deviation from this device's 'normal' learned behavior."),
                            html.H6("Anomaly Score:", className="mt-3"),
                            html.P(f"{alert['anomaly_score']:.4f} (Higher is more anomalous)"),
                            # Educational feature from your plan
                            html.H6("Top Contributing Factors:", className="mt-3"),
                            html.Ul([
                                html.Li(f"{feat.replace('_', ' ').title()}")
                                for feat in top_features[:3]
                            ]) if top_features else html.P("Details not available"),
                        ], title="📊 Technical Details")
                    ], start_collapsed=True),
                    html.Div([
                        dbc.Button(
                            "✓ Mark as Resolved", color="primary", size="sm", className="me-2",
                            id={'type': 'ack-button', 'index': alert['id']},
                            disabled=bool(alert['acknowledged'])
                        ),
                    ], className="mt-3")
                ])
            ], className="mb-3", color=color, outline=True)
            
            alert_cards.append(alert_card)
            
    return alert_cards

@app.callback(
    Output('devices-container', 'children'),
    Input('interval-component', 'n_intervals')
)
def update_devices(n):
    """Display comprehensive device list with status."""
    conn = get_db_connection()
    if not conn: return html.P("Database connection error.", className="text-danger")

    # FIXED: Querying 'devices', 'connections', and 'alerts'
    query = """
        SELECT 
            d.device_ip,
            d.device_name,
            d.device_type,
            d.mac_address,
            d.first_seen,
            d.last_seen,
            COUNT(DISTINCT c.id) as connection_count,
            SUM(c.bytes_sent + c.bytes_received) / 1024.0 / 1024.0 as total_mb,
            COUNT(DISTINCT a.id) as alert_count
        FROM devices d
        LEFT JOIN connections c ON d.device_ip = c.device_ip 
             AND c.timestamp > datetime('now', '-24 hours')
        LEFT JOIN alerts a ON d.device_ip = a.device_ip 
             AND a.timestamp > datetime('now', '-24 hours')
        GROUP BY d.device_ip
        ORDER BY d.last_seen DESC
    """
    try:
        df = pd.read_sql_query(query, conn)
    except Exception as e:
        logger.warning(f"DB Error update_devices: {e}")
        df = pd.DataFrame()
    finally:
        conn.close()

    if len(df) == 0:
        return html.P("No devices detected", className="text-muted")

    table_header = [
        html.Thead(html.Tr([
            html.Th("Status"), html.Th("Device Name"), html.Th("IP Address"),
            html.Th("Type"), html.Th("Connections (24h)"), html.Th("Data (24h)"),
            html.Th("Alerts"), html.Th("Actions")
        ]))
    ]
    
    rows = []
    for _, device in df.iterrows():
        last_seen = datetime.fromisoformat(device['last_seen'])
        time_since = datetime.now() - last_seen
        
        if time_since < timedelta(minutes=5):
            status_icon, status_text = "🟢", "Active"
        elif time_since < timedelta(hours=1):
            status_icon, status_text = "🟡", "Idle"
        else:
            status_icon, status_text = "⚪", "Offline"
            
        alert_badge = dbc.Badge(str(device['alert_count']), color="danger" if device['alert_count'] > 0 else "success", pill=True)
            
        row = html.Tr([
            html.Td([status_icon, " ", status_text]),
            html.Td(device['device_name'] or "Unknown"),
            html.Td(device['device_ip']),
            html.Td(device['device_type'] or "Unknown"),
            html.Td(str(device['connection_count'])),
            html.Td(f"{device['total_mb'] or 0:.2f} MB"),
            html.Td(alert_badge),
            html.Td([
                dbc.Button("Block", size="sm", color="danger", outline=True)
            ])
        ])
        rows.append(row)
        
    table_body = [html.Tbody(rows)]
    return dbc.Table(table_header + table_body, bordered=True, hover=True, responsive=True, striped=True)

@app.callback(
    Output('metrics-display', 'children'),
    Input('interval-component', 'n_intervals')
)
def update_metrics(n):
    """Display ML model performance metrics."""
    conn = get_db_connection()
    if not conn: return html.P("Database connection error.", className="text-danger")

    try:
        cursor = conn.cursor()
        # FIXED: Querying 'ml_predictions' and 'alerts'
        cursor.execute("SELECT COUNT(*) FROM ml_predictions WHERE timestamp > datetime('now', '-24 hours')")
        total_predictions = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM alerts WHERE timestamp > datetime('now', '-24 hours')")
        anomalies_detected = cursor.fetchone()[0]
        
        anomaly_rate = (anomalies_detected / total_predictions * 100) if total_predictions > 0 else 0
        
        metrics = [
            dbc.Row([
                dbc.Col(html.Div([html.H3(f"{total_predictions:,}"), html.P("Connections Analyzed", className="text-muted")]), width=4),
                dbc.Col(html.Div([html.H3(f"{anomalies_detected:,}", className="text-danger"), html.P("Anomalies Detected", className="text-muted")]), width=4),
                dbc.Col(html.Div([html.H3(f"{anomaly_rate:.2f}%", className="text-warning"), html.P("Anomaly Rate", className="text-muted")]), width=4)
            ]),
            html.Hr(),
            html.H5("Model Information", className="mt-3"),
            html.P([
                html.Strong("Algorithm: "), "Isolation Forest (primary)",
                html.Br(),
                html.Strong("Baseline Period: "), "7 days",
            ])
        ]
    except Exception as e:
        logger.warning(f"DB Error update_metrics: {e}")
        metrics = [html.P("No metrics data available.", className="text-muted")]
    finally:
        conn.close()
        
    return metrics

# Run server
if __name__ == '__main__':
    # Get host/port from config
    host = config.get('dashboard', 'host')
    port = config.get('dashboard', 'port')
    debug = config.get('dashboard', 'debug', default=False)
    
    logger.info(f"Starting IoTSentinel Dashboard on http://{host}:{port}")
    app.run_server(debug=debug, host=host, port=port)