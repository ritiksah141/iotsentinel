#!/usr/bin/env python3
"""
IoTSentinel Web Dashboard - Advanced Version

Implements several key enhancements:
- Displays detailed model comparison metrics on the System tab.
- Shows the specific model that triggered an alert.
- Presents the top contributing features for an alert in a readable format.
- Encodes and displays the model comparison visualization.
"""

import base64
import json
import logging
import sqlite3
import subprocess
import sys
from datetime import datetime
from pathlib import Path

import dash
import dash_bootstrap_components as dbc
import pandas as pd
import plotly.express as px
import plotly.graph_objs as go
from dash import dcc, html, Input, Output, State, callback_context

# Setup paths
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from config.config_manager import config
from database.db_manager import DatabaseManager

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
    except sqlite3.Error as e:
        logger.error(f"Database connection error: {e}")
        return None

# ============================================================================
# Data Loading for Model Comparison
# ============================================================================

def load_model_comparison_data():
    """Loads data from the model comparison reports."""
    report_path = project_root / 'comparison_report.json'
    image_path = project_root / 'model_comparison_visualization.png'
    
    report_data = {}
    encoded_image = None

    if report_path.exists():
        with open(report_path, 'r', encoding='utf-8') as f:
            report_data = json.load(f)
    
    if image_path.exists():
        with open(image_path, 'rb') as f:
            encoded_image = base64.b64encode(f.read()).decode()

    return report_data, encoded_image

# ============================================================================
# APP LAYOUT
# ============================================================================

app.layout = dbc.Container([
    # Header
    dbc.Row([
        dbc.Col(html.H1("🛡️ IoTSentinel", className="text-primary mb-1"), width=5),
        dbc.Col(dbc.Button("Pause Monitoring", id="pause-button", color="warning"), width=2),
        dbc.Col(html.Div([html.H2(id='device-count'), html.Small("Active Devices")], className="text-end"), width=2),
        dbc.Col(html.Div([html.H2(id='alert-count'), html.Small("Active Alerts")], className="text-end"), width=1),
        dbc.Col(html.Div([html.H2(id='connection-count'), html.Small("Connections/Hour")], className="text-end"), width=2)
    ], className="mb-4 mt-3"),
    
    # System status banner
    dbc.Row([dbc.Col(dbc.Alert(id='system-status', color="success", className="mb-3"))]),
    
    # Main tabs
    dbc.Tabs([
        dbc.Tab(label="🌐 Network", tab_id="tab-network", children=[
            dbc.Row([
                dbc.Col(dbc.Card([dbc.CardHeader("Network Topology"), dbc.CardBody(dcc.Graph(id='network-graph', style={'height': '450px'}))]), width=8),
                dbc.Col(dbc.Card([dbc.CardHeader("Live Connection Feed"), dbc.CardBody(html.Div(id='recent-activity', style={'height': '450px', 'overflowY': 'auto'}))]), width=4)
            ], className="mb-3"),
            dbc.Row([
                dbc.Col(dbc.Card([dbc.CardHeader("Network Traffic (Last 24 Hours)"), dbc.CardBody(dcc.Graph(id='traffic-timeline', style={'height': '300px'}))]), width=6),
                dbc.Col(dbc.Card([dbc.CardHeader("Protocol Distribution"), dbc.CardBody(dcc.Graph(id='protocol-pie', style={'height': '300px'}))]), width=6)
            ])
        ]),
        dbc.Tab(label="🚨 Alerts", tab_id="tab-alerts", children=[
            dbc.Row(dbc.Col(dbc.ButtonGroup([
                dbc.Button("All", id="filter-all", color="primary", size="sm"),
                dbc.Button("Critical", id="filter-critical", color="danger", size="sm", outline=True),
                dbc.Button("High", id="filter-high", color="warning", size="sm", outline=True),
                dbc.Button("Medium", id="filter-medium", color="info", size="sm", outline=True),
                dbc.Button("Low", id="filter-low", color="secondary", size="sm", outline=True)
            ], className="mb-3"))),
            dbc.Row(dbc.Col(html.Div(id='alerts-container')))
        ]),
        dbc.Tab(label="📱 Devices", tab_id="tab-devices", children=[
            dbc.Row(dbc.Col(dbc.Card([dbc.CardHeader("All Devices"), dbc.CardBody(html.Div(id='devices-table'))])), className="mb-3"),
            dbc.Row(dbc.Col(dbc.Card([dbc.CardHeader("Device Activity Heatmap (24 Hours)"), dbc.CardBody(dcc.Graph(id='device-heatmap', style={'height': '400px'}))]), width=12))
        ]),
        dbc.Tab(label="📊 Analytics", tab_id="tab-analytics", children=[
            dbc.Row([
                dbc.Col(dbc.Button("Download Connections (24h) as CSV", id="btn-download-csv", color="info", className="mb-3"), width={"size": 4, "offset": 8},)
            ]),
            dbc.Row([
                dbc.Col(dbc.Card([dbc.CardHeader("Alert Timeline (7 Days)"), dbc.CardBody(dcc.Graph(id='alert-timeline', style={'height': '350px'}))]), width=12)
            ], className="mb-3"),
            dbc.Row([
                dbc.Col(dbc.Card([dbc.CardHeader("Anomaly Score Distribution"), dbc.CardBody(dcc.Graph(id='anomaly-distribution', style={'height': '350px'}))]), width=6),
                dbc.Col(dbc.Card([dbc.CardHeader("Top Devices by Bandwidth (24h)"), dbc.CardBody(dcc.Graph(id='bandwidth-chart', style={'height': '350px'}))]), width=6)
            ], className="mb-3"),
            dbc.Row([
                dbc.Col(dbc.Card([dbc.CardHeader("ML Engine Performance"), dbc.CardBody(dcc.Graph(id='system-performance', style={'height': '350px'}))]), width=12)
            ])
        ]),
        dbc.Tab(label="⚙️ System", tab_id="tab-system", children=[
            dbc.Row([
                dbc.Col(dbc.Card([dbc.CardHeader("System Status"), dbc.CardBody(html.Div(id='system-info'))]), width=6),
                dbc.Col([
                    dbc.Card([dbc.CardHeader("Model Information"), dbc.CardBody(html.Div(id='model-info'))]),
                    html.Br(),
                    dbc.Card([dbc.CardHeader("Model Comparison"), dbc.CardBody(html.Div(id='model-comparison'))])
                ], width=6)
            ]),
            dbc.Row([
                dbc.Col(dbc.Card([dbc.CardHeader("Model Performance Over Time"), dbc.CardBody(dcc.Graph(id='model-performance-graph'))]), width=12)
            ], className="mt-3"),
            dbc.Row([
                dbc.Col(dbc.Card([
                    dbc.CardHeader("Firewall Control"),
                    dbc.CardBody([
                        dbc.Switch(id='lockdown-switch', label="Enable Lockdown Mode", value=False),
                        html.P("When enabled, only 'Trusted' devices can access the network.", className="small text-muted"),
                        dbc.Modal([
                            dbc.ModalHeader(dbc.ModalTitle("Confirm Lockdown Mode")),
                            dbc.ModalBody("Are you sure you want to enable Lockdown Mode? This will block all untrusted devices from accessing the network."),
                            dbc.ModalFooter([
                                dbc.Button("Cancel", id="lockdown-cancel", color="secondary"),
                                dbc.Button("Enable", id="lockdown-confirm", color="danger"),
                            ]),
                        ], id="lockdown-modal")
                    ])
                ]), width=12)
            ], className="mt-3")
        ]),
        dbc.Tab(label="⚙️ Settings", tab_id="tab-settings", children=[
            dbc.Row([
                dbc.Col(dbc.Card([
                    dbc.CardHeader("Email Settings"),
                    dbc.CardBody([
                        dbc.Row([
                            dbc.Col(dbc.Label("Recipient Email"), width=3),
                            dbc.Col(dbc.Input(id='setting-recipient-email', type='email', value=config.get('email', 'recipient_email')), width=9)
                        ], className="mb-3"),
                        dbc.Row([
                            dbc.Col(dbc.Label("SMTP Host"), width=3),
                            dbc.Col(dbc.Input(id='setting-smtp-host', type='text', value=config.get('email', 'smtp_host')), width=9)
                        ]),
                        html.Hr(),
                        dbc.Button("Save Settings", id="save-settings-button", color="primary"),
                        html.Div(id="settings-saved-status", className="mt-3")
                    ])
                ]), width=12)
            ])
        ])
    ], id="tabs", active_tab="tab-network"),
    
    dcc.Interval(id='interval-component', interval=5*1000, n_intervals=0),
    dcc.Store(id='alert-filter', data='all'),
    dcc.Store(id='onboarding-store', storage_type='local'),
    dcc.Store(id='onboarding-step-store', data=0),
    dcc.Download(id="download-csv"),
    dbc.Modal([
        dbc.ModalHeader(dbc.ModalTitle(id='onboarding-title')),
        dbc.ModalBody(id='onboarding-body'),
        dbc.ModalFooter([
            dbc.Button("Previous", id="onboarding-prev", color="secondary", className="me-auto", disabled=True),
            dbc.Button("Next", id="onboarding-next", color="primary")
        ]),
    ], id="onboarding-modal", is_open=False, backdrop="static"),
    dbc.Modal([
        dbc.ModalHeader(dbc.ModalTitle(id="device-details-title")),
        dbc.ModalBody(id="device-details-body"),
    ], id="device-details-modal", is_open=False),
    
], fluid=True, className="p-4")

# ============================================================================
# ALL CALLBACKS
# ============================================================================

# ============================================================================
# ONBOARDING WIZARD CALLBACKS
# ============================================================================

ONBOARDING_STEPS = [
    {
        "title": "Welcome to IoTSentinel!",
        "body": html.Div([
            html.P("This quick tour will guide you through the main features of the dashboard."),
            html.P("Use the 'Next' and 'Previous' buttons to navigate."),
        ])
    },
    {
        "title": "The Network Tab",
        "body": html.Div([
            html.P("The 'Network' tab gives you a real-time overview of your network."),
            html.Strong("Network Topology:"), " Shows which devices are communicating.", html.Br(),
            html.Strong("Live Connection Feed:"), " A live list of all connections.", html.Br(),
            html.Strong("Network Traffic Timeline:"), " A graph of your network traffic over the last 24 hours.",
        ])
    },
    {
        "title": "The Alerts Tab",
        "body": html.Div([
            html.P("The 'Alerts' tab is where you'll see any suspicious activity detected by the ML engine."),
            html.P("Alerts are color-coded by severity: Critical, High, Medium, and Low."),
        ])
    },
    {
        "title": "Initial Setup: Baseline Training",
        "body": html.Div([
            html.P("Before IoTSentinel can detect anomalies, it needs to learn what's 'normal' for your network."),
            html.P("To do this, you need to run the baseline collection script from your terminal:"),
            html.Pre(html.Code("python3 scripts/baseline_collector.py")),
            html.P("This will collect data for 7 days to train the models."),
        ])
    },
    {
        "title": "You're All Set!",
        "body": html.Div([
            html.P("The dashboard is now ready to use."),
            html.P("Remember to run the baseline collector to enable anomaly detection."),
        ])
    }
]

@app.callback(
    Output('onboarding-modal', 'is_open'),
    Input('tabs', 'active_tab'),
    State('onboarding-store', 'data')
)
def launch_onboarding_modal(_, onboarding_data):
    """Launch the onboarding modal on first visit."""
    if onboarding_data is None:
        return True
    return False

@app.callback(
    [Output('onboarding-title', 'children'),
     Output('onboarding-body', 'children'),
     Output('onboarding-prev', 'disabled'),
     Output('onboarding-next', 'children')],
    Input('onboarding-step-store', 'data')
)
def update_onboarding_content(step):
    """Update the content of the onboarding modal based on the current step."""
    if step < 0:
        step = 0
    if step >= len(ONBOARDING_STEPS):
        step = len(ONBOARDING_STEPS) - 1
        
    content = ONBOARDING_STEPS[step]
    prev_disabled = (step == 0)
    next_text = "Next"
    if step == len(ONBOARDING_STEPS) - 1:
        next_text = "Finish"
        
    return content['title'], content['body'], prev_disabled, next_text

@app.callback(
    [Output('onboarding-step-store', 'data'),
     Output('onboarding-modal', 'is_open', allow_duplicate=True),
     Output('onboarding-store', 'data')],
    [Input('onboarding-next', 'n_clicks'),
     Input('onboarding-prev', 'n_clicks')],
    [State('onboarding-step-store', 'data'),
     State('onboarding-store', 'data')],
    prevent_initial_call=True
)
def update_onboarding_step(_, __, step, ___):
    """Handle the next/previous buttons of the onboarding modal."""
    ctx = callback_context
    if not ctx.triggered:
        return 0, dash.no_update, dash.no_update

    button_id = ctx.triggered[0]['prop_id'].split('.')[0]
    
    if button_id == 'onboarding-next':
        if step == len(ONBOARDING_STEPS) - 1:
            # Finish
            return 0, False, {'completed': True}
        else:
            return step + 1, dash.no_update, dash.no_update
    elif button_id == 'onboarding-prev':
        return step - 1, dash.no_update, dash.no_update
        
    return 0, dash.no_update, dash.no_update

@app.callback(
    [Output('pause-button', 'children'),
     Output('pause-button', 'color')],
    [Input('pause-button', 'n_clicks')],
    [dash.dependencies.State('pause-button', 'children')]
)
def toggle_pause_monitoring(n_clicks, button_text):
    """Toggle the monitoring status when the pause/resume button is clicked."""
    if n_clicks is None:
        # On page load, set button based on current status
        status_file = project_root / config.get('system', 'status_file_path')
        try:
            with open(status_file, 'r', encoding='utf-8') as f:
                status = json.load(f).get('status', 'running')
        except (FileNotFoundError, json.JSONDecodeError):
            status = 'running'
        
        if status == 'paused':
            return "Resume Monitoring", "success"
        else:
            return "Pause Monitoring", "warning"

    status_file = project_root / config.get('system', 'status_file_path')
    
    # Determine new state
    if "Pause" in button_text:
        new_status = 'paused'
        new_button_text = "Resume Monitoring"
        new_color = "success"
    else:
        new_status = 'running'
        new_button_text = "Pause Monitoring"
        new_color = "warning"
        
    # Write new state to file
    try:
        with open(status_file, 'w', encoding='utf-8') as f:
            json.dump({'status': new_status}, f)
        logger.info(f"Monitoring status set to: {new_status}")
    except IOError as e:
        logger.error(f"Error writing status file: {e}")
        # Revert button on error
        return button_text, "danger"

    return new_button_text, new_color

# Header Stats Callback (no changes needed)
@app.callback(
    [Output('device-count', 'children'),
     Output('alert-count', 'children'),
     Output('connection-count', 'children'),
     Output('system-status', 'children')],
    Input('interval-component', 'n_intervals')
)
def update_header_stats(_):
    """Update the main statistics in the header."""
    conn = get_db_connection()
    if not conn: return "0", "0", "0", "⚠️ DB Error"
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM devices WHERE last_seen > datetime('now', '-5 minutes')")
        device_count = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM alerts WHERE timestamp > datetime('now', '-24 hours') AND acknowledged = 0")
        alert_count = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM connections WHERE timestamp > datetime('now', '-1 hour')")
        conn_count = cursor.fetchone()[0]
        status = [html.Strong("🟢 System Active - All Clear" if alert_count == 0 else f"🟡 {alert_count} Active Alert(s)"), f" | Monitoring {device_count} devices"]
        return str(device_count), str(alert_count), str(conn_count), status
    except sqlite3.Error as e:
        logger.error(f"Error in header: {e}")
        return "0", "0", "0", "⚠️ Error"
    finally:
        if conn: conn.close()

# Network Tab Callbacks (no changes needed)
@app.callback(
    Output('network-graph', 'figure'),
    Input('interval-component', 'n_intervals')
)
def update_network_graph(_):
    """Updates the network graph."""
    db = DatabaseManager(DB_PATH)
    connections = db.get_recent_connections(hours=1)
    db.close()

    if not connections:
        return go.Figure().update_layout(title="No recent connections")

    df = pd.DataFrame(connections)
    nodes = pd.unique(df[['device_ip', 'dest_ip']].values.ravel('K'))
    
    node_map = {node: i for i, node in enumerate(nodes)}
    
    edges_x = []
    edges_y = []
    for _, row in df.iterrows():
        source = node_map.get(row['device_ip'])
        target = node_map.get(row['dest_ip'])
        if source is not None and target is not None:
            edges_x.extend([source, target, None])
            edges_y.extend([list(nodes).index(row['device_ip']), list(nodes).index(row['dest_ip']), None])

    node_trace = go.Scatter(
        x=list(range(len(nodes))), y=list(range(len(nodes))),
        mode='markers+text',
        hoverinfo='text',
        text=nodes,
        textposition="bottom center",
        marker=dict(
            showscale=False,
            color='lightblue',
            size=10,
            line_width=2))
            
    edge_trace = go.Scatter(
        x=edges_x, y=edges_y,
        line=dict(width=0.5, color='#888'),
        hoverinfo='none',
        mode='lines')

    fig = go.Figure(data=[edge_trace, node_trace],
                 layout=go.Layout(
                    title='<br>Network Graph (Last Hour)',
                    titlefont_size=16,
                    showlegend=False,
                    hovermode='closest',
                    margin=dict(b=20,l=5,r=5,t=40),
                    xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                    yaxis=dict(showgrid=False, zeroline=False, showticklabels=False))
                    )
    return fig

@app.callback(
    [Output('device-details-modal', 'is_open'),
     Output('device-details-title', 'children'),
     Output('device-details-body', 'children')],
    [Input('network-graph', 'clickData')],
    [State('device-details-modal', 'is_open')],
    prevent_initial_call=True
)
def display_device_details(clickData, _):
    """Display details of a device when clicked on the network graph."""
    if not clickData:
        return False, "", ""

    node_label = clickData['points'][0]['text']
    
    db = DatabaseManager(DB_PATH)
    # This is a simplified details fetch. A dedicated function would be better.
    device_info = db.get_all_devices()
    db.close()
    
    device = next((d for d in device_info if d['device_ip'] == node_label), None)
    
    if device:
        body = [
            html.P(f"IP Address: {device['device_ip']}"),
            html.P(f"MAC Address: {device['mac_address']}"),
            html.P(f"Name: {device['device_name']}"),
            html.P(f"First Seen: {device['first_seen']}"),
            html.P(f"Last Seen: {device['last_seen']}"),
            html.P(f"Trusted: {'Yes' if device['is_trusted'] else 'No'}"),
        ]
        return True, f"Device Details: {node_label}", body
    else:
        return True, f"Device Details: {node_label}", "No details found for this device."

@app.callback(Output('recent-activity', 'children'), Input('interval-component', 'n_intervals'))
def update_recent_activity(_):
    """Placeholder for recent activity feed."""
    return [html.P("Recent activity feed...")]

@app.callback(Output('traffic-timeline', 'figure'), Input('interval-component', 'n_intervals'))
def update_traffic_timeline(_):
    """Placeholder for traffic timeline."""
    return go.Figure().update_layout(title="Traffic Timeline (Placeholder)")

@app.callback(Output('protocol-pie', 'figure'), Input('interval-component', 'n_intervals'))
def update_protocol_pie(_):
    """Placeholder for protocol distribution."""
    return go.Figure().update_layout(title="Protocol Pie (Placeholder)")


# ** ENHANCED ALERTS TAB CALLBACK **
@app.callback(
    Output('alerts-container', 'children'),
    [Input('interval-component', 'n_intervals'),
     Input('alert-filter', 'data')]
)
def update_alerts(_, filter_severity):
    """Display alerts with enhanced educational explanations."""
    conn = get_db_connection()
    if not conn: return dbc.Alert("Database error", color="danger")
    
    query = """
        SELECT 
            a.id, a.timestamp, a.device_ip, d.device_name, a.severity,
            a.anomaly_score, a.explanation, a.top_features, a.acknowledged,
            (SELECT GROUP_CONCAT(mp.model_type) FROM ml_predictions mp JOIN connections c ON mp.connection_id = c.id WHERE a.device_ip = c.device_ip AND mp.is_anomaly = 1 AND ABS(JULIANDAY(c.timestamp) - JULIANDAY(a.timestamp)) * 86400 < 5) as model_types
        FROM alerts a
        LEFT JOIN devices d ON a.device_ip = d.device_ip
        WHERE a.timestamp > datetime('now', '-24 hours')
    """
    if filter_severity != 'all':
        query += f" AND a.severity = '{filter_severity}'"
    query += " ORDER BY a.timestamp DESC"
    
    try:
        df = pd.read_sql_query(query, conn)
    except (sqlite3.Error, pd.io.sql.DatabaseError) as e:
        logger.error(f"Error fetching alerts: {e}")
        df = pd.DataFrame()
    finally:
        if conn: conn.close()

    if len(df) == 0:
        return dbc.Alert([html.H4("✅ All Clear!"), html.P("No security alerts in the last 24 hours.")], color="success")
    
    severity_colors = {'critical': 'danger', 'high': 'warning', 'medium': 'info', 'low': 'secondary'}
    alert_cards = []
    for _, alert in df.iterrows():
        device_name = alert['device_name'] or alert['device_ip']
        time_str = datetime.fromisoformat(alert['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
        color = severity_colors.get(alert['severity'], 'secondary')
        
        try:
            top_features = json.loads(alert['top_features'])
            features_list = [f"{k.replace('_', ' ').title()}: {v:.2f}" if isinstance(v, float) else f"{k.replace('_', ' ').title()}: {v}" for k, v in top_features.items()]
        except:
            features_list = ["Not available"]

        card = dbc.Card([
            dbc.CardHeader([
                dbc.Badge(alert['severity'].upper(), color=color, className="me-2"),
                html.Strong(f"{device_name} - Unusual Activity"),
                html.Span(time_str, className="float-end text-muted small")
            ]),
            dbc.CardBody([
                html.P(alert['explanation'], className="lead mb-3"),
                dbc.Accordion([
                    dbc.AccordionItem([
                        html.H6("Anomaly Score:", className="mt-3"),
                        dbc.Progress(value=abs(alert['anomaly_score']) * 100, label=f"{alert['anomaly_score']:.4f}", color="danger", className="mb-3"),
                        html.H6("Detection Models:", className="mt-3"),
                        html.P(alert['model_types'] or "N/A"),
                        html.H6("Top Contributing Factors:", className="mt-3"),
                        html.Ul([html.Li(item) for item in features_list]),
                    ], title="📊 Technical Details & Explanation")
                ], start_collapsed=True),
            ])
        ], className="mb-3", color=color, outline=True)
        alert_cards.append(card)
    
    return alert_cards

def get_all_devices_data():
    """Fetches all devices from the database."""
    conn = get_db_connection()
    if not conn:
        return pd.DataFrame()
    try:
        df = pd.read_sql_query("SELECT * FROM devices ORDER BY last_seen DESC", conn)
        return df
    except (sqlite3.Error, pd.io.sql.DatabaseError) as e:
        logger.error(f"Error fetching all devices data: {e}")
        return pd.DataFrame()
    finally:
        if conn:
            conn.close()

@app.callback(
    Output('devices-table', 'children'),
    Input('interval-component', 'n_intervals')
)
def update_devices_table(_):
    """Updates the devices table."""
    df = get_all_devices_data()
    
    if df.empty:
        return dbc.Alert("No devices found.", color="info")
        
    table_header = [
        html.Thead(html.Tr([
            html.Th("IP Address"),
            html.Th("Name"),
            html.Th("MAC Address"),
            html.Th("Last Seen"),
            html.Th("Trusted")
        ]))
    ]
    
    table_body = [html.Tbody([
        html.Tr([
            html.Td(row['device_ip']),
            html.Td(row['device_name']),
            html.Td(row['mac_address']),
            html.Td(datetime.fromisoformat(row['last_seen']).strftime('%Y-%m-%d %H:%M:%S')),
            html.Td(dbc.Switch(id={'type': 'trust-switch', 'ip': row['device_ip']}, value=bool(row['is_trusted'])))
        ]) for _, row in df.iterrows()
    ])]
    
    return dbc.Table(table_header + table_body, bordered=True, striped=True, hover=True, size="sm")

@app.callback(
    Output({'type': 'trust-switch', 'ip': dash.dependencies.ALL}, 'value'),
    Input({'type': 'trust-switch', 'ip': dash.dependencies.ALL}, 'value'),
    prevent_initial_call=True
)
def update_device_trust(values):
    """Update the trust status of a device when the switch is toggled."""
    ctx = callback_context
    if not ctx.triggered:
        return dash.no_update

    switch_id = ctx.triggered[0]['prop_id'].split('.')[0]
    switch_id = json.loads(switch_id)
    device_ip = switch_id['ip']
    is_trusted = ctx.triggered[0]['value']
    
    db = DatabaseManager(DB_PATH)
    db.set_device_trust(device_ip, is_trusted)
    db.close()
    
    # This is a bit of a hack to prevent the callback from firing again
    # and creating a loop. We return the values as they are.
    return values

# Devices and Analytics Tab Callbacks (no changes needed)
@app.callback(Output('device-heatmap', 'figure'), Input('interval-component', 'n_intervals'))
def update_device_heatmap(_):
    """Placeholder for device activity heatmap."""
    return go.Figure().update_layout(title="Device Heatmap (Placeholder)")
@app.callback(Output('alert-timeline', 'figure'), Input('interval-component', 'n_intervals'))
def update_alert_timeline(_):
    """Placeholder for alert timeline."""
    return go.Figure().update_layout(title="Alert Timeline (Placeholder)")
@app.callback(Output('anomaly-distribution', 'figure'), Input('interval-component', 'n_intervals'))
def update_anomaly_distribution(_):
    """Placeholder for anomaly score distribution."""
    return go.Figure().update_layout(title="Anomaly Distribution (Placeholder)")

def get_bandwidth_data(hours=24):
    """Fetches bandwidth data from the database."""
    db = DatabaseManager(DB_PATH)
    data = db.get_bandwidth_stats(hours=hours)
    db.close()
    return pd.DataFrame(data)

@app.callback(
    Output('bandwidth-chart', 'figure'),
    Input('interval-component', 'n_intervals')
)
def update_bandwidth_chart(_):
    """Updates the bandwidth chart."""
    df = get_bandwidth_data()
    
    if df.empty:
        return go.Figure().update_layout(title="No Bandwidth Data Available")
        
    fig = px.bar(df, x='device_ip', y='total_bytes', title="Top 10 Devices by Bandwidth Usage")
    fig.update_layout(xaxis_title="Device IP", yaxis_title="Total Bytes")
    return fig

@app.callback(Output('system-performance', 'figure'), Input('interval-component', 'n_intervals'))
def update_system_performance(_):
    """Placeholder for system performance."""
    return go.Figure().update_layout(title="System Performance (Placeholder)")

# System Info Callbacks
@app.callback(Output('system-info', 'children'), Input('interval-component', 'n_intervals'))
def update_system_info(_):
    """Placeholder for system info."""
    return [html.P("System info...")]

@app.callback(Output('model-info', 'children'), Input('interval-component', 'n_intervals'))
def update_model_info(_):
    """Placeholder for model info."""
    return [html.P("Model info...")]

def get_model_performance_metrics_data(days=30):
    """Fetches model performance metrics from the database."""
    conn = get_db_connection()
    if not conn:
        return pd.DataFrame()
    try:
        query = f"SELECT * FROM model_performance WHERE timestamp > datetime('now', '-{days} days') ORDER BY timestamp ASC"
        df = pd.read_sql_query(query, conn)
        return df
    except (sqlite3.Error, pd.io.sql.DatabaseError) as e:
        logger.error(f"Error fetching model performance data: {e}")
        return pd.DataFrame()
    finally:
        if conn:
            conn.close()

@app.callback(
    Output('model-performance-graph', 'figure'),
    Input('interval-component', 'n_intervals')
)
def update_model_performance_graph(_):
    """Updates the model performance graph."""
    df = get_model_performance_metrics_data()
    
    if df.empty:
        return go.Figure().update_layout(
            title="No Model Performance Data Available",
            xaxis_title="Date",
            yaxis_title="Score",
            showlegend=True
        )
    
    fig = go.Figure()
    fig.add_trace(go.Scatter(x=df['timestamp'], y=df['precision'], mode='lines+markers', name='Precision'))
    fig.add_trace(go.Scatter(x=df['timestamp'], y=df['recall'], mode='lines+markers', name='Recall'))
    fig.add_trace(go.Scatter(x=df['timestamp'], y=df['f1_score'], mode='lines+markers', name='F1-Score'))
    
    fig.update_layout(
        title="Model Performance Over Time",
        xaxis_title="Date",
        yaxis_title="Score",
        yaxis_range=[0, 1],
        legend_title="Metric",
        template="plotly_white"
    )
    
    return fig

@app.callback(
    Output("download-csv", "data"),
    Input("btn-download-csv", "n_clicks"),
    prevent_initial_call=True,
)
def download_csv(_):
    """Handle CSV download button."""
    conn = get_db_connection()
    if not conn:
        return None
    
    try:
        df = pd.read_sql_query("SELECT * FROM connections WHERE timestamp > datetime('now', '-24 hours')", conn)
        return dcc.send_data_frame(df.to_csv, "connections.csv")
    except (sqlite3.Error, pd.io.sql.DatabaseError) as e:
        logger.error(f"Error generating CSV: {e}")
        return None
    finally:
        if conn:
            conn.close()

import subprocess

@app.callback(
    [Output('lockdown-modal', 'is_open'),
     Output('lockdown-switch', 'value')],
    [Input('lockdown-switch', 'value'),
     Input('lockdown-confirm', 'n_clicks'),
     Input('lockdown-cancel', 'n_clicks')],
    [State('lockdown-modal', 'is_open')],
    prevent_initial_call=True
)
def handle_lockdown_mode(switch_on, __, ___, is_open):
    """Handle the logic for the firewall lockdown mode switch and modal."""
    ctx = callback_context
    if not ctx.triggered:
        return False, False

    trigger_id = ctx.triggered[0]['prop_id'].split('.')[0]

    if trigger_id == 'lockdown-switch':
        if switch_on:
            # User wants to turn it on, show modal
            return True, True
        else:
            # User turned it off, clear rules
            logger.info("Lockdown mode disabled. Clearing firewall rules...")
            subprocess.run(["python3", "scripts/firewall_manager.py", "--clear"])
            return False, False

    elif trigger_id == 'lockdown-confirm':
        # User confirmed, apply rules
        logger.info("Lockdown mode enabled. Applying firewall rules...")
        db = DatabaseManager(DB_PATH)
        trusted_devices = db.get_trusted_devices()
        db.close()
        
        trusted_macs = [d['mac_address'] for d in trusted_devices if d['mac_address']]
        
        cmd = ["python3", "scripts/firewall_manager.py", "--apply"] + trusted_macs
        subprocess.run(cmd)
        
        return False, True

    elif trigger_id == 'lockdown-cancel':
        # User cancelled, turn switch off
        return False, False

    return False, False

@app.callback(
    Output('config-display', 'children'),
    Input('interval-component', 'n_intervals')
)
def update_config_display(_):
    """Displays the current system configuration."""
    config_path = project_root / 'config' / 'default_config.json'
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            config_data = json.load(f)
        
        # Exclude sensitive fields from display
        if 'firewall' in config_data:
            config_data['firewall']['router_password'] = "********"
        if 'email' in config_data:
            config_data['email']['smtp_password'] = "********"
            
        config_str = json.dumps(config_data, indent=2)
        return f"```json\n{config_str}\n```"
    except (IOError, json.JSONDecodeError) as e:
        logger.error(f"Error reading config file: {e}")
        return "Error loading configuration."

# ** NEW MODEL COMPARISON CALLBACK **
@app.callback(
    Output('settings-saved-status', 'children'),
    Input('save-settings-button', 'n_clicks'),
    [State('setting-recipient-email', 'value'),
     State('setting-smtp-host', 'value')],
    prevent_initial_call=True
)
def save_settings(n_clicks, recipient_email, smtp_host):
    if n_clicks is None:
        return ""

    # Basic validation
    if not recipient_email or '@' not in recipient_email:
        return dbc.Alert("Invalid recipient email.", color="danger")
    if not smtp_host:
        return dbc.Alert("SMTP Host cannot be empty.", color="danger")

    new_settings = {
        "email": {
            "recipient_email": recipient_email,
            "smtp_host": smtp_host
        }
    }
    
    config.save_user_config(new_settings)
    
    return dbc.Alert("Settings saved successfully! The application may need to be restarted for all changes to take effect.", color="success")

@app.callback(
    Output('model-comparison', 'children'),
    Input('interval-component', 'n_intervals')
)
def update_model_comparison(_):
    """Displays the model comparison report and visualization."""
    report_data, encoded_image = load_model_comparison_data()

    if not report_data or not encoded_image:
        return dbc.Alert("Model comparison report not found. Run 'scripts/compare_models.py' to generate it.", color="warning")

    table_header = [html.Thead(html.Tr([html.Th("Model"), html.Th("Precision"), html.Th("Recall"), html.Th("F1-Score")]))]
    table_body = [html.Tbody([
        html.Tr([
            html.Td(model),
            html.Td(f"{metrics['Precision']:.3f}"),
            html.Td(f"{metrics['Recall']:.3f}"),
            html.Td(f"{metrics['F1-Score']:.3f}")
        ]) for model, metrics in report_data.items()
    ])]
    table = dbc.Table(table_header + table_body, bordered=True, striped=True, hover=True, size="sm")

    return html.Div([
        html.H5("Model Performance Metrics", className="mb-3"),
        table,
        html.Hr(),
        html.H5("F1-Score Visualization", className="mb-3"),
        html.Img(src=f'data:image/png;base64,{encoded_image}', style={'width': '100%'})
    ])

# Filter button callback (no changes needed)
@app.callback(
    Output('alert-filter', 'data'),
    [Input('filter-all', 'n_clicks'), Input('filter-critical', 'n_clicks'), Input('filter-high', 'n_clicks'), Input('filter-medium', 'n_clicks'), Input('filter-low', 'n_clicks')]
)
def update_alert_filter(_, __, ___, ____, _____):
    ctx = callback_context
    if not ctx.triggered: return 'all'
    button_id = ctx.triggered[0]['prop_id'].split('.')[0]
    return button_id.split('-')[1]

# ============================================================================
# MAIN
# ============================================================================

def main():
    """Run the dashboard server."""
    host = config.get('dashboard', 'host')
    port = config.get('dashboard', 'port')
    debug = config.get('dashboard', 'debug', default=False)
    
    logger.info("=" * 70)
    logger.info("IoTSentinel Dashboard - Advanced Edition")
    logger.info(f"URL: http://{host}:{port}")
    logger.info("=" * 70)
    
    app.run_server(host=host, port=port, debug=debug)

if __name__ == '__main__':
    main()
