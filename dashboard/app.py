#!/usr/bin/env python3

import base64
import json
import logging
import sqlite3
import subprocess
import sys
import math
import time # Added for AI response simulation
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any

import dash
import dash_bootstrap_components as dbc
import pandas as pd
import plotly.express as px
import plotly.graph_objs as go
import dash_cytoscape as cyto
from dash import dcc, html, Input, Output, State, callback_context

# Setup paths
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from config.config_manager import config
from database.db_manager import DatabaseManager
from flask_socketio import SocketIO, emit
from dash_extensions import WebSocket
import threading # Added import

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Dash app with Bootstrap theme
app = dash.Dash(
    __name__,
    external_stylesheets=[dbc.themes.BOOTSTRAP, dbc.themes.GRID, dbc.icons.FONT_AWESOME, '/assets/skeleton.css'],
    title="IoTSentinel - Network Security Monitor",
    suppress_callback_exceptions=True
)

# Initialize Flask-SocketIO
socketio = SocketIO(app.server, cors_allowed_origins="*")

# Database path
DB_PATH = config.get('database', 'path')
db_manager = DatabaseManager(DB_PATH)

# ============================================================================
# CONSTANTS AND MAPPINGS
# ============================================================================

# MITRE ATT&CK Mapping for educational context
MITRE_ATTACK_MAPPING = {
    "High Outbound Traffic": {
        "tactic": "Exfiltration (TA0010)",
        "description": "Data is being sent out from your network at unusually high volumes.",
        "user_explanation": "This device is sending much more data than usual, which could indicate data theft or a compromised device uploading your information."
    },
    "Unusual Port Activity": {
        "tactic": "Lateral Movement (TA0008)",
        "description": "Device is communicating on unusual network ports.",
        "user_explanation": "This device is trying to communicate using channels it doesn't normally use, similar to someone trying to enter through a window instead of the door."
    },
    "Anomalous Connection Time": {
        "tactic": "Execution (TA0002)",
        "description": "Device is active at unusual times.",
        "user_explanation": "This device is connecting to the internet at times when it's usually inactive - like your smart TV browsing the web at 3 AM."
    },
    "High Ratio of Outbound to Inbound Bytes": {
        "tactic": "Exfiltration (TA0010)",
        "description": "Device is sending far more data than it receives.",
        "user_explanation": "This device is uploading much more than it downloads, which is unusual for most home devices and could indicate data being stolen."
    },
    "Scanning Behavior Detected": {
        "tactic": "Discovery (TA0007)",
        "description": "Device is probing other devices or services.",
        "user_explanation": "This device is checking what other devices and services exist on your network, like someone going door-to-door checking which houses are occupied."
    },
    "Connection to Known Malicious IP": {
        "tactic": "Command and Control (TA0011)",
        "description": "Device communicated with a known threat actor.",
        "user_explanation": "This device connected to an internet address known to be used by hackers. This is a serious concern that needs immediate attention."
    },
    "Unusual Protocol Usage": {
        "tactic": "Defense Evasion (TA0005)",
        "description": "Device using unexpected communication protocols.",
        "user_explanation": "This device is speaking a 'language' it doesn't normally use, which could be an attempt to hide malicious activity."
    },
    "Excessive Connection Attempts": {
        "tactic": "Initial Access (TA0001)",
        "description": "Many failed or rapid connection attempts detected.",
        "user_explanation": "This device is rapidly trying to connect to many places, which could indicate it's been compromised and is trying to spread or attack other systems."
    }
}

# Severity configuration
SEVERITY_CONFIG = {
    'critical': {'color': 'danger', 'icon': 'fa-skull-crossbones', 'badge_color': '#dc3545'},
    'high': {'color': 'warning', 'icon': 'fa-exclamation-triangle', 'badge_color': '#fd7e14'},
    'medium': {'color': 'info', 'icon': 'fa-exclamation-circle', 'badge_color': '#17a2b8'},
    'low': {'color': 'secondary', 'icon': 'fa-info-circle', 'badge_color': '#6c757d'}
}

# Device status colors for network graph
DEVICE_STATUS_COLORS = {
    'normal': '#28a745',      # Green
    'warning': '#ffc107',     # Yellow
    'alert': '#dc3545',       # Red
    'unknown': '#6c757d'      # Gray
}


# ============================================================================
# DATABASE HELPER FUNCTIONS
# ============================================================================

def get_db_connection():
    """Get database connection (read-only for safety)."""
    try:
        conn = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        return conn
    except sqlite3.Error as e:
        logger.error(f"Database connection error: {e}")
        return None


def get_device_status(device_ip: str, hours: int = 24) -> str:
    """
    Determine device security status based on recent alerts.

    Returns: 'normal', 'warning', 'alert', or 'unknown'
    """
    conn = get_db_connection()
    if not conn:
        return 'unknown'

    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT severity, COUNT(*) as count
            FROM alerts
            WHERE device_ip = ?
            AND timestamp > datetime('now', ? || ' hours')
            AND acknowledged = 0
            GROUP BY severity
        """, (device_ip, f'-{hours}'))

        alerts = {row['severity']: row['count'] for row in cursor.fetchall()}

        if alerts.get('critical', 0) > 0 or alerts.get('high', 0) > 0:
            return 'alert'
        elif alerts.get('medium', 0) > 0:
            return 'warning'
        elif alerts.get('low', 0) > 0:
            return 'warning'
        else:
            return 'normal'

    except sqlite3.Error as e:
        logger.error(f"Error getting device status: {e}")
        return 'unknown'
    finally:
        conn.close()


def get_device_baseline(device_ip: str, days: int = 7) -> Dict[str, Any]:
    """
    Get baseline statistics for a device from historical data.

    This is the KEY function for educational transparency - it calculates
    what "normal" looks like for each device.
    """
    conn = get_db_connection()
    if not conn:
        return {}

    try:
        cursor = conn.cursor()

        # Get daily averages for the baseline period (excluding today)
        cursor.execute("""
            SELECT
                AVG(daily_bytes_sent) as avg_bytes_sent,
                AVG(daily_bytes_received) as avg_bytes_received,
                AVG(daily_connections) as avg_connections,
                AVG(daily_unique_destinations) as avg_unique_destinations,
                COALESCE(STDEV(daily_bytes_sent), 0) as std_bytes_sent,
                COALESCE(STDEV(daily_bytes_received), 0) as std_bytes_received,
                COALESCE(STDEV(daily_connections), 0) as std_connections
            FROM (
                SELECT
                    DATE(timestamp) as day,
                    SUM(bytes_sent) as daily_bytes_sent,
                    SUM(bytes_received) as daily_bytes_received,
                    COUNT(*) as daily_connections,
                    COUNT(DISTINCT dest_ip) as daily_unique_destinations
                FROM connections
                WHERE device_ip = ?
                AND timestamp BETWEEN datetime('now', ? || ' days') AND datetime('now', '-1 day')
                GROUP BY DATE(timestamp)
            )
        """, (device_ip, f'-{days}'))

        row = cursor.fetchone()

        if row and row['avg_bytes_sent'] is not None:
            baseline = {
                'avg_bytes_sent': row['avg_bytes_sent'] or 0,
                'avg_bytes_received': row['avg_bytes_received'] or 0,
                'avg_connections': row['avg_connections'] or 0,
                'avg_unique_destinations': row['avg_unique_destinations'] or 0,
                'std_bytes_sent': row['std_bytes_sent'] or 0,
                'std_bytes_received': row['std_bytes_received'] or 0,
                'std_connections': row['std_connections'] or 0,
                'baseline_days': days,
                'has_baseline': True
            }
        else:
            # No baseline data available
            baseline = {
                'avg_bytes_sent': 0,
                'avg_bytes_received': 0,
                'avg_connections': 0,
                'avg_unique_destinations': 0,
                'std_bytes_sent': 0,
                'std_bytes_received': 0,
                'std_connections': 0,
                'baseline_days': 0,
                'has_baseline': False
            }

        return baseline

    except sqlite3.Error as e:
        logger.error(f"Error getting device baseline: {e}")
        return {'has_baseline': False}
    finally:
        conn.close()


def get_device_today_stats(device_ip: str) -> Dict[str, Any]:
    """
    Get today's statistics for a device.
    Used for comparison with baseline in educational drill-down.
    """
    conn = get_db_connection()
    if not conn:
        return {}

    try:
        cursor = conn.cursor()

        cursor.execute("""
            SELECT
                COALESCE(SUM(bytes_sent), 0) as today_bytes_sent,
                COALESCE(SUM(bytes_received), 0) as today_bytes_received,
                COUNT(*) as today_connections,
                COUNT(DISTINCT dest_ip) as today_unique_destinations,
                COUNT(DISTINCT dest_port) as today_unique_ports
            FROM connections
            WHERE device_ip = ?
            AND DATE(timestamp) = DATE('now')
        """, (device_ip,))

        row = cursor.fetchone()

        if row:
            return {
                'today_bytes_sent': row['today_bytes_sent'],
                'today_bytes_received': row['today_bytes_received'],
                'today_connections': row['today_connections'],
                'today_unique_destinations': row['today_unique_destinations'],
                'today_unique_ports': row['today_unique_ports']
            }
        return {}

    except sqlite3.Error as e:
        logger.error(f"Error getting today's stats: {e}")
        return {}
    finally:
        conn.close()


def get_alert_with_context(alert_id: int) -> Dict[str, Any]:
    """
    Get full alert details with device baseline for educational explanation.
    """
    conn = get_db_connection()
    if not conn:
        return {}

    try:
        cursor = conn.cursor()

        cursor.execute("""
            SELECT
                a.*,
                d.device_name,
                d.device_type,
                d.manufacturer
            FROM alerts a
            LEFT JOIN devices d ON a.device_ip = d.device_ip
            WHERE a.id = ?
        """, (alert_id,))

        row = cursor.fetchone()
        if not row:
            return {}

        alert = dict(row)

        # Get baseline and today's stats for context
        alert['baseline'] = get_device_baseline(alert['device_ip'])
        alert['today_stats'] = get_device_today_stats(alert['device_ip'])

        return alert

    except sqlite3.Error as e:
        logger.error(f"Error getting alert context: {e}")
        return {}
    finally:
        conn.close()


def get_devices_with_status() -> List[Dict]:
    """
    Get all devices with their current security status.
    This powers the main overview with status indicators.
    """
    conn = get_db_connection()
    if not conn:
        return []

    try:
        cursor = conn.cursor()

        # Get all devices
        cursor.execute("""
            SELECT
                d.*,
                (SELECT COUNT(*) FROM alerts a
                 WHERE a.device_ip = d.device_ip
                 AND a.timestamp > datetime('now', '-24 hours')
                 AND a.acknowledged = 0
                 AND a.severity IN ('critical', 'high')) as critical_alerts,
                (SELECT COUNT(*) FROM alerts a
                 WHERE a.device_ip = d.device_ip
                 AND a.timestamp > datetime('now', '-24 hours')
                 AND a.acknowledged = 0
                 AND a.severity IN ('medium', 'low')) as minor_alerts,
                (SELECT COUNT(*) FROM connections c
                 WHERE c.device_ip = d.device_ip
                 AND c.timestamp > datetime('now', '-1 hour')) as recent_connections
            FROM devices d
            ORDER BY d.last_seen DESC
        """)

        devices = []
        for row in cursor.fetchall():
            device = dict(row)

            # Determine status
            if device['critical_alerts'] > 0:
                device['status'] = 'alert'
                device['status_text'] = f"{device['critical_alerts']} critical alert(s)"
            elif device['minor_alerts'] > 0:
                device['status'] = 'warning'
                device['status_text'] = f"{device['minor_alerts']} warning(s)"
            else:
                device['status'] = 'normal'
                device['status_text'] = 'All clear'

            devices.append(device)

        return devices

    except sqlite3.Error as e:
        logger.error(f"Error getting devices with status: {e}")
        return []
    finally:
        conn.close()


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
# HELPER FUNCTIONS FOR UI COMPONENTS
# ============================================================================

def format_bytes(bytes_value: float) -> str:
    """Format bytes into human-readable string."""
    if bytes_value is None:
        return "0 B"

    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if abs(bytes_value) < 1024.0:
            return f"{bytes_value:.1f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.1f} PB"


def create_status_indicator(status: str, size: str = "1.5rem") -> html.Span:
    """
    Create a colored status dot indicator.

    This is KEY FEATURE #1: Visual status indicators
    """
    color = DEVICE_STATUS_COLORS.get(status, DEVICE_STATUS_COLORS['unknown'])

    pulse_class = ""
    if status == 'alert':
        pulse_class = "pulse-animation"

    return html.Span(
        html.I(className="fa fa-circle"),
        style={
            'color': color,
            'fontSize': size,
            'marginRight': '8px'
        },
        className=pulse_class,
        title=f"Status: {status.capitalize()}"
    )


def create_baseline_comparison_chart(
    baseline: Dict,
    today_stats: Dict,
    metric_name: str,
    baseline_key: str,
    today_key: str,
    title: str
) -> go.Figure:
    """
    Create a bar chart comparing today's value to the baseline.

    This is KEY FEATURE #3: Educational visualization showing
    "Your device sent X today vs Y normally"
    """
    baseline_value = baseline.get(baseline_key, 0)
    today_value = today_stats.get(today_key, 0)

    # Calculate percentage difference
    if baseline_value > 0:
        pct_diff = ((today_value - baseline_value) / baseline_value) * 100
    else:
        pct_diff = 100 if today_value > 0 else 0

    # Determine bar color based on deviation
    if abs(pct_diff) < 50:
        today_color = '#28a745'  # Green - within normal range
    elif abs(pct_diff) < 150:
        today_color = '#ffc107'  # Yellow - somewhat elevated
    else:
        today_color = '#dc3545'  # Red - significantly elevated

    fig = go.Figure()

    fig.add_trace(go.Bar(
        name='Normal (7-day avg)',
        x=[metric_name],
        y=[baseline_value],
        marker_color='#6c757d',
        text=[format_bytes(baseline_value) if 'bytes' in baseline_key.lower() else f"{baseline_value:.0f}"],
        textposition='outside'
    ))

    fig.add_trace(go.Bar(
        name='Today',
        x=[metric_name],
        y=[today_value],
        marker_color=today_color,
        text=[format_bytes(today_value) if 'bytes' in today_key.lower() else f"{today_value:.0f}"],
        textposition='outside'
    ))

    fig.update_layout(
        title=dict(
            text=title,
            font=dict(size=14)
        ),
        barmode='group',
        height=250,
        margin=dict(l=40, r=40, t=60, b=40),
        showlegend=True,
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=1.02,
            xanchor="center",
            x=0.5
        ),
        yaxis_title="",
        xaxis_title=""
    )

    # Add annotation showing percentage change
    direction = "higher" if pct_diff > 0 else "lower"
    annotation_color = today_color

    if abs(pct_diff) > 10:  # Only show annotation if significant
        fig.add_annotation(
            x=metric_name,
            y=max(baseline_value, today_value),
            text=f"{abs(pct_diff):.0f}% {direction}",
            showarrow=False,
            font=dict(size=12, color=annotation_color, weight='bold'),
            yshift=30
        )

    return fig


def create_educational_explanation(alert: Dict) -> html.Div:
    """
    Create an educational explanation for an alert.

    This is the CORE of the educational transparency feature.
    It explains WHY the alert was triggered in plain English.
    """
    baseline = alert.get('baseline', {})
    today_stats = alert.get('today_stats', {})
    explanation_type = alert.get('explanation', 'Unknown')
    device_name = alert.get('device_name') or alert.get('device_ip', 'Unknown Device')

    # Get MITRE ATT&CK context
    mitre_info = MITRE_ATTACK_MAPPING.get(explanation_type, {
        'tactic': 'Unknown',
        'description': 'Unusual activity detected.',
        'user_explanation': 'This device is behaving differently than expected.'
    })

    # Build the explanation sections
    sections = []

    # 1. Plain English Summary (THE KEY!)
    if baseline.get('has_baseline', False):
        # We have baseline data - create detailed comparison
        avg_bytes_sent = baseline.get('avg_bytes_sent', 0)
        today_bytes_sent = today_stats.get('today_bytes_sent', 0)

        avg_connections = baseline.get('avg_connections', 0)
        today_connections = today_stats.get('today_connections', 0)

        # Create the key educational message
        if today_bytes_sent > avg_bytes_sent * 2:
            data_explanation = f"""
            **{device_name}** typically sends about **{format_bytes(avg_bytes_sent)}** of data per day.
            Today, it has already sent **{format_bytes(today_bytes_sent)}** — that's
            **{(today_bytes_sent/avg_bytes_sent*100):.0f}%** of what it normally sends in an entire day!
            """
        else:
            data_explanation = f"""
            **{device_name}** has sent **{format_bytes(today_bytes_sent)}** today, compared to a
            normal daily average of **{format_bytes(avg_bytes_sent)}**.
            """

        sections.append(
            dbc.Alert([
                html.H5("📊 What We Detected", className="alert-heading"),
                dcc.Markdown(data_explanation),
                html.Hr(),
                html.H6("🔍 Why This Matters"),
                html.P(mitre_info['user_explanation'], className="mb-0")
            ], color="info", className="mb-3")
        )

        # 2. Visual Comparison Charts (THE EDUCATIONAL VISUALIZATIONS)
        sections.append(html.H5("📈 Comparison with Normal Behavior", className="mt-4 mb-3"))

        sections.append(
            dbc.Row([
                dbc.Col([
                    dcc.Graph(
                        figure=create_baseline_comparison_chart(
                            baseline, today_stats,
                            "Data Sent",
                            "avg_bytes_sent", "today_bytes_sent",
                            "Data Sent: Normal vs Today"
                        ),
                        config={'displayModeBar': False}
                    )
                ], width=6),
                dbc.Col([
                    dcc.Graph(
                        figure=create_baseline_comparison_chart(
                            baseline, today_stats,
                            "Connections",
                            "avg_connections", "today_connections",
                            "Connection Count: Normal vs Today"
                        ),
                        config={'displayModeBar': False}
                    )
                ], width=6)
            ], className="mb-3")
        )

        # Additional metrics
        sections.append(
            dbc.Row([
                dbc.Col([
                    dcc.Graph(
                        figure=create_baseline_comparison_chart(
                            baseline, today_stats,
                            "Data Received",
                            "avg_bytes_received", "today_bytes_received",
                            "Data Received: Normal vs Today"
                        ),
                        config={'displayModeBar': False}
                    )
                ], width=6),
                dbc.Col([
                    dcc.Graph(
                        figure=create_baseline_comparison_chart(
                            baseline, today_stats,
                            "Destinations",
                            "avg_unique_destinations", "today_unique_destinations",
                            "Unique Destinations: Normal vs Today"
                        ),
                        config={'displayModeBar': False}
                    )
                ], width=6)
            ])
        )

    else:
        # No baseline data available yet
        sections.append(
            dbc.Alert([
                html.H5("⚠️ Limited Baseline Data", className="alert-heading"),
                html.P([
                    "We're still learning what's normal for this device. ",
                    "The baseline is built from 7 days of network activity. ",
                    "Once we have more history, we can show you detailed comparisons."
                ]),
                html.Hr(),
                html.P(mitre_info['user_explanation'], className="mb-0")
            ], color="warning", className="mb-3")
        )

    # 3. What Should You Do? (Actionable guidance)
    sections.append(html.H5("🛡️ Recommended Actions", className="mt-4 mb-3"))

    severity = alert.get('severity', 'medium')

    if severity in ['critical', 'high']:
        actions = [
            "Consider temporarily disconnecting this device from your network",
            "Check if the device has any pending software updates",
            "Review what apps or services are running on the device",
            "If the device shouldn't be sending data, it may be compromised"
        ]
        action_color = "danger"
    elif severity == 'medium':
        actions = [
            "Monitor this device over the next few hours",
            "Check if someone is actively using the device",
            "Review if any new apps were recently installed",
            "Mark as 'reviewed' if this activity was expected"
        ]
        action_color = "warning"
    else:
        actions = [
            "This is likely normal but unusual activity",
            "No immediate action required",
            "Consider marking as 'acknowledged' to dismiss"
        ]
        action_color = "info"

    sections.append(
        dbc.Alert([
            html.Ul([html.Li(action) for action in actions])
        ], color=action_color)
    )

    # 4. Technical Details (for advanced users)
    sections.append(
        dbc.Accordion([
            dbc.AccordionItem([
                html.P([
                    html.Strong("MITRE ATT&CK Tactic: "),
                    mitre_info['tactic']
                ]),
                html.P([
                    html.Strong("Technical Description: "),
                    mitre_info['description']
                ]),
                html.P([
                    html.Strong("Anomaly Score: "),
                    f"{alert.get('anomaly_score', 0):.4f}"
                ]),
                html.P([
                    html.Strong("Detection Model: "),
                    alert.get('model_types', 'N/A')
                ]),
                html.Hr(),
                html.H6("Raw Feature Contributions:"),
                html.Pre(json.dumps(json.loads(alert.get('top_features', '{}')), indent=2))
            ], title="🔬 Technical Details (Advanced)")
        ], start_collapsed=True, className="mt-3")
    )

    return html.Div(sections)


# ============================================================================
# APP LAYOUT
# ============================================================================

# Custom CSS for pulse animation
app.index_string = '''
<!DOCTYPE html>
<html>
    <head>
        {%metas%}
        <title>{%title%}</title>
        {%favicon%}
        {%css%}
        <style>
            .pulse-animation {
                animation: pulse 1.5s infinite;
            }
            @keyframes pulse {
                0% { opacity: 1; }
                50% { opacity: 0.5; }
                100% { opacity: 1; }
            }
            .device-card:hover {
                transform: translateY(-2px);
                box-shadow: 0 4px 12px rgba(0,0,0,0.15);
                transition: all 0.2s ease;
            }
            .alert-card {
                transition: all 0.2s ease;
            }
            .alert-card:hover {
                box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            }
        </style>
    </head>
    <body>
        {%app_entry%}
        <footer>
            {%config%}
            {%scripts%}
            {%renderer%}
        </footer>
    </body>
</html>
'''

app.layout = dbc.Container([
    # ========================================================================
    # HEADER
    # ========================================================================
    dbc.Row([
        dbc.Col([
            html.H1([
                html.I(className="fa fa-shield-alt me-2"),
                "IoTSentinel"
            ], className="text-primary mb-1"),
            html.Small("Educational Network Security Monitor", className="text-muted")
        ], width=5),
        dbc.Col(
            dbc.Button([
                html.I(className="fa fa-pause me-2"),
                "Pause Monitoring"
            ], id="pause-button", color="warning", outline=True),
            width=2,
            className="d-flex align-items-center"
        ),
        dbc.Col([
            dbc.Button(
                [
                    html.I(className="fa fa-bell"),
                    dbc.Badge(id="notification-badge", color="danger", className="ms-1", pill=True),
                ],
                id="notification-bell-button",
                color="secondary",
                outline=True
            ),
            dbc.Button(
                [html.I(className="fa fa-robot")],
                id="open-chat-button",
                color="secondary",
                outline=True,
                className="ms-2"
            )
        ],
            width=2,
            className="d-flex align-items-center"
        ),
        dbc.Col([
            html.Div([
                html.H2(id='device-count', className="mb-0"),
                html.Small("Active Devices", className="text-muted")
            ], className="text-end")
        ], width=2),
        dbc.Col([
            html.Div([
                html.H2(id='alert-count', className="mb-0"),
                html.Small("Active Alerts", className="text-muted")
            ], className="text-end")
        ], width=1),
        dbc.Col([
            html.Div([
                html.H2(id='connection-count', className="mb-0"),
                html.Small("Conn/Hour", className="text-muted")
            ], className="text-end")
        ], width=2)
    ], className="mb-4 mt-3 align-items-center"),

    # System status banner
    dbc.Row([
        dbc.Col(dbc.Alert(id='system-status', color="success", className="mb-3"))
    ]),

    # Theme Selector
    dbc.Row([
        dbc.Col([
            dbc.RadioItems(
                id="theme-selector",
                options=[
                    {"label": "Light", "value": "light"},
                    {"label": "Dark", "value": "dark"},
                    {"label": "Cyberpunk", "value": "cyberpunk"},
                ],
                value="light",
                inline=True,
            ),
            dbc.Switch(
                id="voice-alert-toggle",
                label="Voice Alerts",
                value=False,
                className="ms-3"
            ),
        ],
            width={"size": "auto", "offset": 6},
            className="text-end d-flex align-items-center"
        )
    ]),

    # ========================================================================
    # MAIN TABS
    # ========================================================================
    dbc.Tabs([
        # ====================================================================
        # TAB 1: NETWORK OVERVIEW (Main View with Status Indicators)
        # ====================================================================
        dbc.Tab(label="🌐 Network", tab_id="tab-network", children=[
            dbc.Row([
                # Network Topology Graph (with colored nodes)
                dbc.Col(dbc.Card([
                    dbc.CardHeader([
                        html.I(className="fa fa-project-diagram me-2"),
                        "Network Topology",
                        dbc.Badge("Live", color="success", className="ms-2"),
                        dbc.Switch(
                            id="graph-view-toggle",
                            label="3D View",
                            value=False,
                            className="float-end"
                        )
                    ]),
                    dbc.CardBody([
                        # Container for 2D Graph
                        html.Div(id='2d-graph-container', children=[
                            dbc.Spinner(
                                cyto.Cytoscape(
                                    id='network-graph',
                                    layout={'name': 'cose', 'animate': True},
                                    style={'width': '100%', 'height': '450px'},
                                    stylesheet=[
                                        # ... (stylesheet content remains the same)
                                    ]
                                ),
                                color="primary", type="grow"
                            )
                        ]),
                        # Container for 3D Graph
                        html.Div(id='3d-graph-container', children=[
                            dbc.Spinner(
                                dcc.Graph(id='network-graph-3d', style={'height': '450px'}),
                                color="primary", type="grow"
                            )
                        ], style={'display': 'none'}) # Hidden by default
                    ])
                ]), width=8),
                # Live Connection Feed
                dbc.Col(dbc.Card([
                    dbc.CardHeader([
                        html.I(className="fa fa-stream me-2"),
                        "Live Connection Feed"
                    ]),
                    dbc.CardBody(
                        dbc.Spinner(
                            html.Div(
                                id='recent-activity',
                                style={'height': '450px', 'overflowY': 'auto'}
                            ),
                                                        color="primary", type="grow"
                        )
                    )
                ]), width=4)
            ], className="mb-3"),

            # Traffic charts
            dbc.Row([
                dbc.Col(dbc.Card([
                    dbc.CardHeader([
                        html.I(className="fa fa-chart-line me-2"),
                        "Network Traffic (Last 24 Hours)"
                    ]),
                    dbc.CardBody(dcc.Graph(id='traffic-timeline', style={'height': '300px'}))
                ]), width=6),
                dbc.Col(dbc.Card([
                    dbc.CardHeader([
                        html.I(className="fa fa-chart-pie me-2"),
                        "Protocol Distribution"
                    ]),
                    dbc.CardBody(dcc.Graph(id='protocol-pie', style={'height': '300px'}))
                ]), width=6)
            ])
        ]),

        # ====================================================================
        # TAB 2: ALERTS (Chronological List with Educational Drill-Down)
        # ====================================================================
        dbc.Tab(label="🚨 Alerts", tab_id="tab-alerts", children=[
            # Filter buttons
            dbc.Row([
                dbc.Col([
                    dbc.ButtonGroup([
                        dbc.Button([
                            html.I(className="fa fa-list me-1"),
                            "All"
                        ], id="filter-all", color="primary", size="sm"),
                        dbc.Button([
                            html.I(className="fa fa-skull-crossbones me-1"),
                            "Critical"
                        ], id="filter-critical", color="danger", size="sm", outline=True),
                        dbc.Button([
                            html.I(className="fa fa-exclamation-triangle me-1"),
                            "High"
                        ], id="filter-high", color="warning", size="sm", outline=True),
                        dbc.Button([
                            html.I(className="fa fa-exclamation-circle me-1"),
                            "Medium"
                        ], id="filter-medium", color="info", size="sm", outline=True),
                        dbc.Button([
                            html.I(className="fa fa-info-circle me-1"),
                            "Low"
                        ], id="filter-low", color="secondary", size="sm", outline=True)
                    ], className="mb-3")
                ])
            ]),

            # Alerts container
            dbc.Row([
                dbc.Col(
                    dbc.Spinner(
                        html.Div(id='alerts-container'),
                                                    color="primary", type="grow"
                    )
                )
            ])
        ]),

        # ====================================================================
        # TAB 3: DEVICES (Overview with Status Indicators)
        # ====================================================================
        dbc.Tab(label="📱 Devices", tab_id="tab-devices", children=[
            # Device Status Overview (KEY FEATURE #1)
            dbc.Row([
                dbc.Col(dbc.Card([
                    dbc.CardHeader([
                        html.I(className="fa fa-desktop me-2"),
                        "Device Status Overview",
                        html.Span([
                            html.Span("●", style={'color': DEVICE_STATUS_COLORS['normal'], 'marginLeft': '20px'}),
                            " Normal  ",
                            html.Span("●", style={'color': DEVICE_STATUS_COLORS['warning']}),
                            " Warning  ",
                            html.Span("●", style={'color': DEVICE_STATUS_COLORS['alert']}),
                            " Alert"
                        ], className="float-end small")
                    ]),
                    dbc.CardBody(
                        dbc.Spinner(
                            html.Div(id='devices-status-grid'),
                                                        color="primary", type="grow"
                        )
                    )
                ]))
            ], className="mb-3"),

            # Detailed device table
            dbc.Row([
                dbc.Col(dbc.Card([
                    dbc.CardHeader([
                        html.I(className="fa fa-table me-2"),
                        "All Devices"
                    ]),
                    dbc.CardBody(
                        dbc.Spinner(
                            html.Div(id='devices-table'),
                                                        color="primary", type="grow"
                        )
                    )
                ]))
            ], className="mb-3"),

            # Activity heatmap
            dbc.Row([
                dbc.Col(dbc.Card([
                    dbc.CardHeader([
                        html.I(className="fa fa-th me-2"),
                        "Device Activity Heatmap (24 Hours)"
                    ]),
                    dbc.CardBody(dcc.Graph(id='device-heatmap', style={'height': '400px'}))
                ]), width=12)
            ])
        ]),

        # ====================================================================
        # TAB 4: ANALYTICS
        # ====================================================================
        dbc.Tab(label="📊 Analytics", tab_id="tab-analytics", children=[
            dbc.Row([
                dbc.Col(
                    dbc.Button([
                        html.I(className="fa fa-download me-2"),
                        "Download Connections (24h) as CSV"
                    ], id="btn-download-csv", color="info", className="mb-3"),
                    width={"size": 4, "offset": 8}
                )
            ]),
            dbc.Row([
                dbc.Col(dbc.Card([
                    dbc.CardHeader("Alert Timeline (7 Days)"),
                    dbc.CardBody(dcc.Graph(id='alert-timeline', style={'height': '350px'}))
                ]), width=12)
            ], className="mb-3"),
            dbc.Row([
                dbc.Col(dbc.Card([
                    dbc.CardHeader("Anomaly Score Distribution"),
                    dbc.CardBody(dcc.Graph(id='anomaly-distribution', style={'height': '350px'}))
                ]), width=6),
                dbc.Col(dbc.Card([
                    dbc.CardHeader("Top Devices by Bandwidth (24h)"),
                    dbc.CardBody(dcc.Graph(id='bandwidth-chart', style={'height': '350px'}))
                ]), width=6)
            ], className="mb-3"),
            dbc.Row([
                dbc.Col(dbc.Card([
                    dbc.CardHeader("ML Engine Performance"),
                    dbc.CardBody(dcc.Graph(id='system-performance', style={'height': '350px'}))
                ]), width=12)
            ])
        ]),

        # ====================================================================
        # TAB 5: SYSTEM
        # ====================================================================
        dbc.Tab(label="⚙️ System", tab_id="tab-system", children=[
            dbc.Row([
                dbc.Col(dbc.Card([
                    dbc.CardHeader("System Status"),
                    dbc.CardBody(html.Div(id='system-info'))
                ]), width=6),
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("Model Information"),
                        dbc.CardBody(html.Div(id='model-info'))
                    ]),
                    html.Br(),
                    dbc.Card([
                        dbc.CardHeader("Model Comparison"),
                        dbc.CardBody(html.Div(id='model-comparison'))
                    ])
                ], width=6)
            ]),
            dbc.Row([
                dbc.Col(dbc.Card([
                    dbc.CardHeader("Model Performance Over Time"),
                    dbc.CardBody(dcc.Graph(id='model-performance-graph'))
                ]), width=12)
            ], className="mt-3"),
            dbc.Row([
                dbc.Col(dbc.Card([
                    dbc.CardHeader("Firewall Control"),
                    dbc.CardBody([
                        dbc.Switch(id='lockdown-switch', label="Enable Lockdown Mode", value=False),
                        html.P("When enabled, only 'Trusted' devices can access the network.",
                               className="small text-muted"),
                        dbc.Modal([
                            dbc.ModalHeader(dbc.ModalTitle("Confirm Lockdown Mode")),
                            dbc.ModalBody("Are you sure you want to enable Lockdown Mode? "
                                        "This will block all untrusted devices."),
                            dbc.ModalFooter([
                                dbc.Button("Cancel", id="lockdown-cancel", color="secondary"),
                                dbc.Button("Enable", id="lockdown-confirm", color="danger"),
                            ]),
                        ], id="lockdown-modal")
                    ])
                ]), width=12)
            ], className="mt-3")
        ]),

        # ====================================================================
        # TAB 6: SETTINGS
        # ====================================================================
        dbc.Tab(label="⚙️ Settings", tab_id="tab-settings", children=[
            dbc.Row([
                dbc.Col(dbc.Card([
                    dbc.CardHeader("Email Settings"),
                    dbc.CardBody([
                        dbc.Row([
                            dbc.Col(dbc.Label("Recipient Email"), width=3),
                            dbc.Col(dbc.Input(
                                id='setting-recipient-email',
                                type='email',
                                value=config.get('email', 'recipient_email', default='')
                            ), width=9)
                        ], className="mb-3"),
                        dbc.Row([
                            dbc.Col(dbc.Label("SMTP Host"), width=3),
                            dbc.Col(dbc.Input(
                                id='setting-smtp-host',
                                type='text',
                                value=config.get('email', 'smtp_host', default='')
                            ), width=9)
                        ]),
                        html.Hr(),
                        dbc.Button("Save Settings", id="save-settings-button", color="primary"),
                        html.Div(id="settings-saved-status", className="mt-3")
                    ])
                ]), width=12)
            ])
        ])

    ], id="tabs", active_tab="tab-network"),

    # ========================================================================
    # HIDDEN COMPONENTS AND MODALS
    # ========================================================================
    # dcc.Interval(id='interval-component', interval=5*1000, n_intervals=0), # Replaced by WebSocket
    WebSocket(id="ws", url="ws://127.0.0.1:8050/ws"), # Assuming default Dash port
    dcc.Store(id='alert-filter', data='all'),
    dcc.Store(id='selected-alert-id', data=None),
    dcc.Store(id='onboarding-store', storage_type='local'),
    dcc.Store(id='onboarding-step-store', data=0),
    dcc.Store(id='theme-store', storage_type='local'),
    dcc.Store(id='keyboard-shortcut-store', data=None),
    dcc.Store(id='voice-alert-store', storage_type='local'),
    dcc.Store(id='announced-alerts-store', storage_type='session', data={}),
    dcc.Location(id='url', refresh=False),
    dcc.Download(id="download-csv"),

    # Onboarding Modal
    dbc.Modal([
        dbc.ModalHeader(dbc.ModalTitle(id='onboarding-title')),
        dbc.ModalBody(id='onboarding-body'),
        dbc.ModalFooter([
            dbc.Button("Previous", id="onboarding-prev", color="secondary",
                      className="me-auto", disabled=True),
            dbc.Button("Next", id="onboarding-next", color="primary")
        ]),
    ], id="onboarding-modal", is_open=False, backdrop="static"),

    # Device Details Modal
    dbc.Modal([
        dbc.ModalHeader(dbc.ModalTitle(id="device-details-title")),
        dbc.ModalBody(id="device-details-body"),
    ], id="device-details-modal", is_open=False, size="lg"),

    # Alert Details Modal (Educational Drill-Down)
    dbc.Modal([
        dbc.ModalHeader(dbc.ModalTitle(id="alert-details-title")),
        dbc.ModalBody(id="alert-details-body"),
        dbc.ModalFooter([
            dbc.Button("Mark as Reviewed", id="alert-acknowledge-btn", color="success"),
            dbc.Button("Close", id="alert-close-btn", color="secondary")
        ])
    ], id="alert-details-modal", is_open=False, size="xl"),

    # Container for toast notifications
    html.Div(id="toast-container", style={"position": "fixed", "top": 66, "right": 10, "width": 350, "zIndex": 9999}),

    # Notification Drawer
    dbc.Offcanvas(
        [
            html.H5("Recent Alerts"),
            html.Hr(),
            html.Div(id="notification-drawer-body")
        ],
        id="notification-drawer",
        title="Notifications",
        is_open=False,
        placement="end",
        backdrop=False,
        scrollable=True,
    ),

    # AI Chat Modal
    dbc.Modal([
        dbc.ModalHeader(dbc.ModalTitle("🤖 AI Assistant")),
        dbc.ModalBody(html.Div(id='chat-history', style={'height': '400px', 'overflowY': 'auto'})),
        dbc.ModalFooter(
            dbc.InputGroup([
                dbc.Input(id='chat-input', placeholder="Ask about your network..."),
                dbc.Button("Send", id='chat-send-button', color="primary"),
            ])
        ),
    ], id="chat-modal", is_open=False, size="lg"),

    dcc.Store(id='chat-history-store', storage_type='session', data={'history': []})

], fluid=True, className="p-4")


# ============================================================================
# CALLBACKS
# ============================================================================

# ============================================================================
# HEADER STATS CALLBACK
# ============================================================================

@app.callback(
    [Output('device-count', 'children'),
     Output('alert-count', 'children'),
     Output('connection-count', 'children'),
     Output('system-status', 'children')],
    Input('ws', 'message') # Listen to WebSocket messages
)
def update_header_stats(ws_message):
    """Update the main statistics in the header from WebSocket."""
    if ws_message is None:
        raise dash.exceptions.PreventUpdate

    try:
        device_count = ws_message.get('device_count', 0)
        alert_count = ws_message.get('alert_count', 0)
        conn_count = ws_message.get('connection_count', 0)

        # Build status message
        if alert_count == 0:
            status = [
                html.I(className="fa fa-check-circle me-2"),
                html.Strong("All Clear"),
                f" — Monitoring {device_count} devices"
            ]
        elif alert_count <= 3:
            status = [
                html.I(className="fa fa-exclamation-triangle me-2"),
                html.Strong(f"{alert_count} Active Alert(s)"),
                f" — Monitoring {device_count} devices"
            ]
        else:
            status = [
                html.I(className="fa fa-exclamation-circle me-2"),
                html.Strong(f"{alert_count} Active Alerts - Review Recommended"),
                f" — Monitoring {device_count} devices"
            ]

        return str(device_count), str(alert_count), str(conn_count), status

    except (KeyError) as e:
        logger.error(f"Error processing header stats from WebSocket: {e}")
        raise dash.exceptions.PreventUpdate


@app.callback(
    [Output('notification-badge', 'children'),
     Output('notification-drawer-body', 'children')],
    Input('ws', 'message')
)
def update_notifications(ws_message):
    """Update notification badge and drawer content from WebSocket."""
    if ws_message is None:
        raise dash.exceptions.PreventUpdate

    alert_count = ws_message.get('alert_count', 0)
    recent_alerts = ws_message.get('recent_alerts', [])

    if alert_count == 0:
        badge_count = ""
    else:
        badge_count = str(alert_count)

    if not recent_alerts:
        drawer_content = [dbc.Alert("No new alerts.", color="info")]
    else:
        drawer_content = []
        for alert in recent_alerts[:10]: # Show top 10 in drawer
            device_name = alert.get('device_name') or alert.get('device_ip')
            severity = alert.get('severity', 'medium')
            config = SEVERITY_CONFIG.get(severity, SEVERITY_CONFIG['medium'])

            drawer_content.append(
                dbc.Card(
                    dbc.CardBody([
                        html.Strong(device_name),
                        html.P(alert.get('explanation'), className="small mb-0")
                    ]),
                    color=config['color'],
                    inverse=True,
                    className="mb-2"
                )
            )

    return badge_count, drawer_content


# ============================================================================
# NETWORK TAB CALLBACKS
# ============================================================================

@app.callback(
    Output('network-graph', 'elements'),
    Input('ws', 'message')
)
def update_network_graph(ws_message):
    """
    Updates the network graph with color-coded nodes based on device status
    using data received from the WebSocket.
    """
    if ws_message is None:
        raise dash.exceptions.PreventUpdate

    elements = ws_message.get('network_graph_elements', [])

    if not elements:
        raise dash.exceptions.PreventUpdate

    return elements


@app.callback(
    [Output('2d-graph-container', 'style'),
     Output('3d-graph-container', 'style')],
    Input('graph-view-toggle', 'value')
)
def toggle_graph_view(is_3d_view):
    """Toggle between 2D and 3D network graph views."""
    if is_3d_view:
        return {'display': 'none'}, {'display': 'block'}
    else:
        return {'display': 'block'}, {'display': 'none'}


@app.callback(
    Output('network-graph-3d', 'figure'),
    Input('ws', 'message')
)
def update_network_graph_3d(ws_message):
    """Updates the 3D network graph using WebSocket data."""
    if ws_message is None:
        raise dash.exceptions.PreventUpdate

    devices = ws_message.get('all_devices_with_status', [])
    connections = ws_message.get('recent_connections_feed', [])

    if not devices:
        return go.Figure()

    # Create a mapping of IP to device for quick lookup
    device_map = {d['device_ip']: d for d in devices}

    # --- Create Node Trace ---
    node_colors = []
    node_sizes = []
    node_symbols = []
    node_x = []
    node_y = []
    node_z = []
    node_text = []

    for d in devices:
        # Text label for hover
        node_text.append(d.get('device_name') or d.get('device_ip'))

        # Coordinates (set to 0 if not provided)
        x = d.get('x', 0)
        y = d.get('y', 0)
        z = d.get('z', 0)
        node_x.append(x)
        node_y.append(y)
        node_z.append(z)

        # Color / sizing based on status/alerts
        status_color = DEVICE_STATUS_COLORS.get(d.get('status'), '#6c757d')
        if d.get('has_critical_alert'):
            node_sizes.append(20)  # Larger size for critical alerts
            node_symbols.append('circle')
            node_colors.append('#ff0000')  # Bright red for critical alerts
        else:
            node_sizes.append(12)
            node_symbols.append('circle')
            node_colors.append(status_color)

    node_trace = go.Scatter3d(
        x=node_x, y=node_y, z=node_z,
        mode='markers',
        hoverinfo='text',
        text=node_text,
        marker=dict(
            showscale=False,
            color=node_colors,
            size=node_sizes,
            symbol=node_symbols,
            line=dict(width=2, color='#222')
        )
    )

    # --- Create Edge Traces ---
    edge_traces = []
    # Router to device edges
    for device in devices:
        edge_traces.append(go.Scatter3d(
            x=[0, device['x']], y=[0, device['y']], z=[0, device['z']],
            mode='lines',
            line=dict(color='#888', width=2),
            hoverinfo='none'
        ))

    # Inter-device edges
    for conn in connections:
        src = device_map.get(conn['device_ip'])
        dst = device_map.get(conn['dest_ip'])
        if src and dst:
            edge_traces.append(go.Scatter3d(
                x=[src['x'], dst['x']], y=[src['y'], dst['y']], z=[src['z'], dst['z']],
                mode='lines',
                line=dict(color='#00ffcc', width=4), # Highlight inter-device comms
                hoverinfo='none'
            ))

    # --- Create Router Trace ---
    router_trace = go.Scatter3d(
        x=[0], y=[0], z=[0],
        mode='markers',
        hoverinfo='text',
        text=['Router'],
        marker=dict(color='#007bff', size=20, symbol='diamond')
    )

    layout = go.Layout(
        title='3D Network Topology',
        showlegend=False,
        scene=dict(
            xaxis=dict(showbackground=False, showticklabels=False, title=''),
            yaxis=dict(showbackground=False, showticklabels=False, title=''),
            zaxis=dict(showbackground=False, showticklabels=False, title=''),
        ),
        margin=dict(l=0, r=0, b=0, t=40)
    )

    fig = go.Figure(data=edge_traces + [node_trace, router_trace], layout=layout)

    return fig


@app.callback(
    Output('recent-activity', 'children'),
    Input('ws', 'message')
)
def update_recent_activity(ws_message):
    """Updates the recent activity feed with status indicators using WebSocket data."""
    if ws_message is None:
        raise dash.exceptions.PreventUpdate

    connections = ws_message.get('recent_connections_feed', [])
    devices_with_status = ws_message.get('all_devices_with_status', [])

    # Create a mapping of device_ip to status for quick lookup
    device_status_map = {device['device_ip']: device['status'] for device in devices_with_status}

    if not connections:
        return [
            dbc.Alert([
                html.I(className="fa fa-info-circle me-2"),
                "No recent network activity"
            ], color="info")
        ]

    feed_items = []
    for conn in connections[:30]:
        device_status = device_status_map.get(conn['device_ip'], 'unknown')

        feed_items.append(
            html.Div([
                create_status_indicator(device_status, "0.8rem"),
                html.Span(conn['device_ip'], className="fw-bold"),
                html.Span(" → ", className="text-muted"),
                html.Span(conn['dest_ip']),
                html.Span(f" :{conn.get('dest_port', '?')}", className="text-muted small"),
            ], className="py-1 border-bottom")
        )

    return feed_items


@app.callback(
    Output('traffic-timeline', 'figure'),
    Input('ws', 'message')
)
def update_traffic_timeline(ws_message):
    """Updates the traffic timeline chart using WebSocket data."""
    if ws_message is None:
        raise dash.exceptions.PreventUpdate

    traffic_data = ws_message.get('traffic_timeline', [])

    if not traffic_data:
        fig = go.Figure()
        fig.update_layout(
            title="No traffic data available",
            xaxis_title="Hour",
            yaxis_title="Bytes"
        )
        return fig

    df = pd.DataFrame(traffic_data)

    fig = px.area(
        df, x='hour', y='total_bytes',
        title="Network Traffic by Hour",
        color_discrete_sequence=['#007bff']
    )
    fig.update_layout(
        xaxis_title="Hour",
        yaxis_title="Total Bytes",
        showlegend=False
    )
    fig.update_traces(fill='tozeroy')

    return fig


@app.callback(
    Output('protocol-pie', 'figure'),
    Input('ws', 'message')
)
def update_protocol_pie(ws_message):
    """Updates the protocol distribution pie chart using WebSocket data."""
    if ws_message is None:
        raise dash.exceptions.PreventUpdate

    protocol_data = ws_message.get('protocol_distribution', [])

    if not protocol_data:
        fig = go.Figure()
        fig.update_layout(title="No protocol data available")
        return fig

    df = pd.DataFrame(protocol_data)

    fig = px.pie(
        df, values='count', names='protocol',
        title='Protocol Distribution',
        color_discrete_sequence=px.colors.qualitative.Set2
    )
    fig.update_traces(textposition='inside', textinfo='percent+label')

    return fig


# ============================================================================
# DEVICES TAB CALLBACKS (with Status Indicators)
# ============================================================================

@app.callback(
    Output('devices-status-grid', 'children'),
    Input('ws', 'message')
)
def update_devices_status_grid(ws_message):
    """
    Creates the device status overview grid using WebSocket data.
    """
    if ws_message is None:
        raise dash.exceptions.PreventUpdate

    devices = ws_message.get('all_devices_with_status', [])

    if not devices:
        return dbc.Alert("No devices found.", color="info")

    # Create a grid of device cards with status indicators
    cards = []
    for device in devices:
        status = device.get('status', 'normal')
        status_text = device.get('status_text', 'Unknown')
        device_name = device.get('device_name') or device['device_ip']

        card = dbc.Card([
            dbc.CardBody([
                html.Div([
                    create_status_indicator(status, "1.2rem"),
                    html.Strong(device_name, className="mb-0")
                ], className="d-flex align-items-center mb-2"),
                html.P(device['device_ip'], className="text-muted small mb-1"),
                html.P(status_text, className="small mb-0",
                      style={'color': DEVICE_STATUS_COLORS.get(status, '#6c757d')})
            ], className="p-3")
        ], className="device-card mb-2", style={
            'borderLeft': f"4px solid {DEVICE_STATUS_COLORS.get(status, '#6c757d')}"
        })

        cards.append(dbc.Col(card, width=3, className="mb-2"))

    return dbc.Row(cards)


@app.callback(
    Output('devices-table', 'children'),
    Input('ws', 'message')
)
def update_devices_table(ws_message):
    """Updates the devices table with status column using WebSocket data."""
    if ws_message is None:
        raise dash.exceptions.PreventUpdate

    devices = ws_message.get('all_devices_with_status', [])

    if not devices:
        return dbc.Alert("No devices found.", color="info")

    table_header = [
        html.Thead(html.Tr([
            html.Th("Status"),
            html.Th("IP Address"),
            html.Th("Name"),
            html.Th("MAC Address"),
            html.Th("Manufacturer"),
            html.Th("Last Seen"),
            html.Th("Trusted")
        ]))
    ]

    table_rows = []
    for device in devices:
        status = device.get('status', 'normal')

        try:
            last_seen = datetime.fromisoformat(device['last_seen']).strftime('%Y-%m-%d %H:%M:%S')
        except (ValueError, TypeError):
            last_seen = device.get('last_seen', 'Unknown')

        table_rows.append(html.Tr([
            html.Td(create_status_indicator(status)),
            html.Td(device['device_ip']),
            html.Td(device.get('device_name') or '-'),
            html.Td(device.get('mac_address') or '-'),
            html.Td(device.get('manufacturer') or '-'),
            html.Td(last_seen),
            html.Td(
                dbc.Switch(
                    id={'type': 'trust-switch', 'ip': device['device_ip']},
                    value=bool(device.get('is_trusted', False))
                )
            )
        ]))

    table_body = [html.Tbody(table_rows)]

    return dbc.Table(
        table_header + table_body,
        bordered=True, striped=True, hover=True, size="sm", responsive=True
    )


@app.callback(
    Output('device-heatmap', 'figure'),
    Input('ws', 'message')
)
def update_device_heatmap(ws_message):
    """Updates the device activity heatmap using WebSocket data."""
    if ws_message is None:
        raise dash.exceptions.PreventUpdate

    heatmap_data = ws_message.get('device_activity_heatmap', [])

    if not heatmap_data:
        fig = go.Figure()
        fig.update_layout(title="No activity data available")
        return fig

    df = pd.DataFrame(heatmap_data)

    fig = px.density_heatmap(
        df, x="hour", y="device_ip", z="count",
        title="Device Activity by Hour",
        color_continuous_scale="Blues"
    )
    fig.update_layout(
        xaxis_title="Hour of Day",
        yaxis_title="Device IP"
    )

    return fig


# ============================================================================
# ALERTS TAB CALLBACKS (with Educational Drill-Down)
# ============================================================================

@app.callback(
    Output('alerts-container', 'children'),
    [Input('ws', 'message'), # Listen to WebSocket messages
     Input('alert-filter', 'data')]
)
def update_alerts(ws_message, filter_severity):
    """
    Display alerts with clickable cards for educational drill-down using WebSocket data.
    """
    if ws_message is None:
        raise dash.exceptions.PreventUpdate

    recent_alerts_raw = ws_message.get('recent_alerts', [])

    # Convert to DataFrame for easier filtering
    df = pd.DataFrame(recent_alerts_raw)

    if filter_severity != 'all' and not df.empty:
        df = df[df['severity'] == filter_severity]

    if len(df) == 0:
        return dbc.Alert([
            html.H4([
                html.I(className="fa fa-check-circle me-2"),
                "All Clear!"
            ], className="alert-heading"),
            html.P("No security alerts in the last 24 hours. Your network is behaving normally.")
        ], color="success")

    alert_cards = []
    for _, alert in df.iterrows():
        device_name = alert['device_name'] or alert['device_ip']
        time_str = datetime.fromisoformat(alert['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
        severity = alert['severity']
        config = SEVERITY_CONFIG.get(severity, SEVERITY_CONFIG['medium'])

        # Get MITRE info for subtitle
        mitre_info = MITRE_ATTACK_MAPPING.get(alert['explanation'], {})
        tactic = mitre_info.get('tactic', 'Unknown')

        card = dbc.Card([
            dbc.CardHeader([
                html.Span([
                    create_status_indicator('alert' if severity in ['critical', 'high'] else 'warning'),
                    dbc.Badge(severity.upper(), color=config['color'], className="me-2"),
                    html.Strong(f"{device_name}")
                ]),
                dbc.Badge(tactic, color="dark", className="ms-2"),
                html.Span(time_str, className="float-end text-muted small")
            ]),
            dbc.CardBody([
                html.P(alert['explanation'], className="lead mb-2"),
                html.P(
                    mitre_info.get('user_explanation', 'Unusual activity detected on this device.'),
                    className="text-muted small mb-3"
                ),
                dbc.Button([
                    html.I(className="fa fa-search-plus me-2"),
                    "View Details & Explanation"
                ], id={'type': 'alert-detail-btn', 'index': int(alert['id'])},
                   color="primary", size="sm", outline=True)
            ])
        ], className="alert-card mb-3", color=config['color'], outline=True)

        alert_cards.append(card)

    return alert_cards


@app.callback(
    [Output('alert-details-modal', 'is_open'),
     Output('alert-details-title', 'children'),
     Output('alert-details-body', 'children')],
    [Input({'type': 'alert-detail-btn', 'index': dash.dependencies.ALL}, 'n_clicks'),
     Input('alert-close-btn', 'n_clicks')],
    [State('alert-details-modal', 'is_open')],
    prevent_initial_call=True
)
def toggle_alert_details(btn_clicks, close_click, is_open):
    """
    Opens the educational drill-down modal when an alert is clicked.

    KEY FEATURE #3: Educational drill-down with baseline comparison
    """
    ctx = callback_context
    if not ctx.triggered:
        return False, "", ""

    trigger_id = ctx.triggered[0]['prop_id']

    # Handle close button
    if 'alert-close-btn' in trigger_id:
        return False, "", ""

    # Handle alert detail button click
    if 'alert-detail-btn' in trigger_id:
        # Extract alert ID from the trigger
        try:
            trigger_data = json.loads(trigger_id.split('.')[0])
            alert_id = trigger_data['index']
        except (json.JSONDecodeError, KeyError):
            return False, "", ""

        # Get alert with full context
        alert = get_alert_with_context(alert_id)

        if not alert:
            return True, "Alert Not Found", html.P("Could not load alert details.")

        device_name = alert.get('device_name') or alert.get('device_ip', 'Unknown')
        title = f"🔍 Alert Details: {device_name}"

        # Create the educational explanation
        body = create_educational_explanation(alert)

        return True, title, body

    return False, "", ""


@app.callback(
    Output("chat-modal", "is_open"),
    Input("open-chat-button", "n_clicks"),
    [State("chat-modal", "is_open")],
    prevent_initial_call=True,
)
def toggle_chat_modal(n, is_open):
    if n:
        return not is_open
    return is_open


@app.callback(
    [Output('chat-history-store', 'data', allow_duplicate=True),
     Output('chat-input', 'value')],
    [Input('chat-send-button', 'n_clicks'),
     Input('chat-input', 'n_submit')],
    [State('chat-input', 'value'),
     State('chat-history-store', 'data')],
    prevent_initial_call=True
)
def handle_chat_message(send_clicks, input_submit, text, chat_data):
    if (send_clicks is None and input_submit is None) or not text:
        raise dash.exceptions.PreventUpdate

    history = chat_data.get('history', [])
    history.append({'sender': 'user', 'message': text})

    # Placeholder for AI thinking
    history.append({'sender': 'ai', 'message': '...'})

    return {'history': history}, ''


@app.callback(
    Output('chat-history', 'children'),
    Input('chat-history-store', 'data')
)
def update_chat_history(chat_data):
    if not chat_data:
        return []

    history = chat_data.get('history', [])
    messages = []
    for msg in history:
        if msg['sender'] == 'user':
            messages.append(
                dbc.Alert(msg['message'], color="primary", className="text-end")
            )
        else:
            messages.append(
                dbc.Alert(msg['message'], color="secondary", className="text-start")
            )
    return messages


@app.callback(
    Output('chat-history-store', 'data'),
    Input('chat-history-store', 'data'),
    prevent_initial_call=True
)
def simulate_ai_response(chat_data):
    if not chat_data or not chat_data['history']:
        raise dash.exceptions.PreventUpdate

    history = chat_data['history']
    last_message = history[-1]

    if last_message['sender'] == 'ai' and last_message['message'] == '...':
        time.sleep(1) # Simulate thinking

        # Placeholder response logic
        user_message = history[-2]['message'].lower()
        if 'how many devices' in user_message:
            response = "Device count is visible on the main dashboard."
        elif 'show alerts' in user_message:
            response = "Alerts are available in the 'Alerts' tab."
        else:
            response = "This is a placeholder AI response. Full functionality is pending."

        history[-1] = {'sender': 'ai', 'message': response}
        return {'history': history}

    raise dash.exceptions.PreventUpdate


@app.callback(
    Output('alert-filter', 'data'),
    [Input('filter-all', 'n_clicks'),
     Input('filter-critical', 'n_clicks'),
     Input('filter-high', 'n_clicks'),
     Input('filter-medium', 'n_clicks'),
     Input('filter-low', 'n_clicks')]
)
def update_alert_filter(*_):
    """Update alert filter based on button clicks."""
    ctx = callback_context
    if not ctx.triggered:
        return 'all'

    button_id = ctx.triggered[0]['prop_id'].split('.')[0]
    return button_id.split('-')[1]


# ============================================================================
# ANALYTICS TAB CALLBACKS
# ============================================================================

@app.callback(
    Output('alert-timeline', 'figure'),
    Input('ws', 'message')
)
def update_alert_timeline(ws_message):
    """Updates the alert timeline chart using WebSocket data."""
    if ws_message is None:
        raise dash.exceptions.PreventUpdate

    alert_timeline_data = ws_message.get('alert_timeline', [])

    if not alert_timeline_data:
        fig = go.Figure()
        fig.update_layout(title="No alerts in the last 7 days")
        return fig

    df = pd.DataFrame(alert_timeline_data)

    fig = px.bar(
        df, x="day", y="count", color="severity",
        title="Alerts by Day",
        color_discrete_map={
            'critical': '#dc3545',
            'high': '#fd7e14',
            'medium': '#17a2b8',
            'low': '#6c757d'
        }
    )
    fig.update_layout(
        xaxis_title="Date",
        yaxis_title="Number of Alerts",
        barmode='stack'
    )

    return fig


@app.callback(
    Output('anomaly-distribution', 'figure'),
    Input('ws', 'message')
)
def update_anomaly_distribution(ws_message):
    """Updates the anomaly score distribution chart using WebSocket data."""
    if ws_message is None:
        raise dash.exceptions.PreventUpdate

    anomaly_data = ws_message.get('anomaly_distribution', [])

    if not anomaly_data:
        fig = go.Figure()
        fig.update_layout(title="No anomaly data available")
        return fig

    df = pd.DataFrame(anomaly_data)

    fig = px.histogram(
        df, x="anomaly_score",
        title="Anomaly Score Distribution",
        color_discrete_sequence=['#007bff'],
        nbins=30
    )
    fig.update_layout(
        xaxis_title="Anomaly Score",
        yaxis_title="Frequency"
    )

    # Add threshold line
    fig.add_vline(x=-0.5, line_dash="dash", line_color="red",
                  annotation_text="Anomaly Threshold")

    return fig


@app.callback(
    Output('bandwidth-chart', 'figure'),
    Input('ws', 'message')
)
def update_bandwidth_chart(ws_message):
    """Updates the bandwidth chart using WebSocket data."""
    if ws_message is None:
        raise dash.exceptions.PreventUpdate

    bandwidth_data = ws_message.get('bandwidth_chart', [])

    if not bandwidth_data:
        fig = go.Figure()
        fig.update_layout(title="No Bandwidth Data Available")
        return fig

    df = pd.DataFrame(bandwidth_data)

    fig = px.bar(
        df, x='device_ip', y='total_bytes',
        title="Top 10 Devices by Bandwidth Usage",
        color_discrete_sequence=['#28a745']
    )
    fig.update_layout(
        xaxis_title="Device IP",
        yaxis_title="Total Bytes"
    )

    return fig


@app.callback(
    Output('system-performance', 'figure'),
    Input('ws', 'message')
)
def update_system_performance(ws_message):
    """System performance metrics placeholder (using WebSocket input)."""
    if ws_message is None:
        raise dash.exceptions.PreventUpdate

    # This would typically come from system monitoring, or a more detailed
    # data payload from the background thread. For now, we keep it static.

    fig = go.Figure()

    fig.add_trace(go.Indicator(
        mode="gauge+number",
        value=85,
        title={'text': "ML Engine Health"},
        gauge={
            'axis': {'range': [0, 100]},
            'bar': {'color': "#28a745"},
            'steps': [
                {'range': [0, 50], 'color': "#dc3545"},
                {'range': [50, 75], 'color': "#ffc107"},
                {'range': [75, 100], 'color': "#28a745"}
            ]
        }
    ))

    fig.update_layout(height=350)

    return fig


# ============================================================================
# SYSTEM TAB CALLBACKS
# ============================================================================

@app.callback(
    Output('system-info', 'children'),
    Input('ws', 'message')
)
def update_system_info(ws_message):
    """Displays system information using WebSocket data."""
    if ws_message is None:
        raise dash.exceptions.PreventUpdate

    # Extract data from the payload
    total_devices = ws_message.get('total_devices_db', 'N/A')
    total_connections = ws_message.get('total_connections_db', 'N/A')
    total_alerts = ws_message.get('total_alerts_db', 'N/A')

    return [
        html.P([html.Strong("Database Path: "), str(DB_PATH)]),
        html.P([html.Strong("Total Devices: "), str(total_devices)]),
        html.P([html.Strong("Total Connections: "), str(total_connections)]),
        html.P([html.Strong("Total Alerts: "), str(total_alerts)]),
        html.P([html.Strong("Last Updated: "), datetime.now().strftime('%Y-%m-%d %H:%M:%S')])
    ]


@app.callback(
    Output('model-info', 'children'),
    Input('ws', 'message')
)
def update_model_info(ws_message):
    """Displays ML model information using WebSocket data."""
    if ws_message is None:
        raise dash.exceptions.PreventUpdate

    models = ws_message.get('model_info', [])

    if not models:
        return dbc.Alert("No trained models found.", color="warning")

    return [
        html.Ul([
            html.Li([
                html.Strong(m['name']),
                f" - Size: {m['size']}, Updated: {m['modified']}"
            ]) for m in models
        ])
    ]


@app.callback(
    Output('model-comparison', 'children'),
    Input('ws', 'message')
)
def update_model_comparison(ws_message):
    """Displays the model comparison report and visualization using WebSocket data."""
    if ws_message is None:
        raise dash.exceptions.PreventUpdate

    report_data = ws_message.get('model_comparison_data', {})
    encoded_image = ws_message.get('model_comparison_image', None)

    if not report_data:
        return dbc.Alert(
            "Model comparison report not found. Run 'scripts/compare_models.py' to generate it.",
            color="warning"
        )

    table_header = [
        html.Thead(html.Tr([
            html.Th("Model"),
            html.Th("Precision"),
            html.Th("Recall"),
            html.Th("F1-Score")
        ]))
    ]

    table_body = [html.Tbody([
        html.Tr([
            html.Td(model),
            html.Td(f"{metrics.get('Precision', 0):.3f}"),
            html.Td(f"{metrics.get('Recall', 0):.3f}"),
            html.Td(f"{metrics.get('F1-Score', 0):.3f}")
        ]) for model, metrics in report_data.items()
    ])]

    table = dbc.Table(table_header + table_body, bordered=True, striped=True, hover=True, size="sm")

    children = [
        html.H6("Model Performance Metrics", className="mb-3"),
        table
    ]

    if encoded_image:
        children.extend([
            html.Hr(),
            html.H6("F1-Score Visualization", className="mb-3"),
            html.Img(src=f'data:image/png;base64,{encoded_image}', style={'width': '100%'})
        ])

    return html.Div(children)


@app.callback(
    Output('model-performance-graph', 'figure'),
    Input('ws', 'message')
)
def update_model_performance_graph(ws_message):
    """Updates the model performance graph over time using WebSocket data."""
    if ws_message is None:
        raise dash.exceptions.PreventUpdate

    performance_data = ws_message.get('model_performance_metrics', [])

    if not performance_data:
        fig = go.Figure()
        fig.update_layout(
            title="No Model Performance Data Available",
            xaxis_title="Date",
            yaxis_title="Score"
        )
        return fig

    df = pd.DataFrame(performance_data)

    fig = go.Figure()
    fig.add_trace(go.Scatter(x=df['timestamp'], y=df['precision'],
                             mode='lines+markers', name='Precision'))
    fig.add_trace(go.Scatter(x=df['timestamp'], y=df['recall'],
                             mode='lines+markers', name='Recall'))
    fig.add_trace(go.Scatter(x=df['timestamp'], y=df['f1_score'],
                             mode='lines+markers', name='F1-Score'))

    fig.update_layout(
        title="Model Performance Over Time",
        xaxis_title="Date",
        yaxis_title="Score",
        yaxis_range=[0, 1],
        legend_title="Metric",
        template="plotly_white"
    )

    return fig


# ============================================================================
# UTILITY CALLBACKS
# ============================================================================

@app.callback(
    [Output('pause-button', 'children'),
     Output('pause-button', 'color')],
    [Input('pause-button', 'n_clicks')],
    [State('pause-button', 'children')]
)
def toggle_pause_monitoring(n_clicks, button_content):
    """Toggle the monitoring status."""
    status_file = project_root / config.get('system', 'status_file_path', default='data/system_status.json')

    if n_clicks is None:
        # Initial load
        try:
            with open(status_file, 'r', encoding='utf-8') as f:
                status = json.load(f).get('status', 'running')
        except (FileNotFoundError, json.JSONDecodeError):
            status = 'running'

        if status == 'paused':
            return [html.I(className="fa fa-play me-2"), "Resume Monitoring"], "success"
        return [html.I(className="fa fa-pause me-2"), "Pause Monitoring"], "warning"

    # Toggle status
    try:
        with open(status_file, 'r', encoding='utf-8') as f:
            current = json.load(f).get('status', 'running')
    except (FileNotFoundError, json.JSONDecodeError):
        current = 'running'

    new_status = 'paused' if current == 'running' else 'running'

    try:
        status_file.parent.mkdir(parents=True, exist_ok=True)
        with open(status_file, 'w', encoding='utf-8') as f:
            json.dump({'status': new_status}, f)
    except IOError as e:
        logger.error(f"Error writing status file: {e}")

    if new_status == 'paused':
        return [html.I(className="fa fa-play me-2"), "Resume Monitoring"], "success"
    return [html.I(className="fa fa-pause me-2"), "Pause Monitoring"], "warning"


@app.callback(
    Output("notification-drawer", "is_open"),
    Input("notification-bell-button", "n_clicks"),
    [State("notification-drawer", "is_open")],
    prevent_initial_call=True,
)
def toggle_notification_drawer(n, is_open):
    if n:
        return not is_open
    return is_open


@app.callback(
    [Output('notification-drawer', 'is_open', allow_duplicate=True),
     Output('tabs', 'active_tab')],
    Input('keyboard-shortcut-store', 'data'),
    State('notification-drawer', 'is_open'),
    prevent_initial_call=True
)
def handle_keyboard_shortcuts(shortcut_data, is_open):
    if not shortcut_data or 'action' not in shortcut_data:
        raise dash.exceptions.PreventUpdate

    action = shortcut_data['action']

    if action == 'toggle-notifications':
        return not is_open, dash.no_update
    elif action == 'go-to-devices':
        return dash.no_update, 'tab-devices'
    elif action == 'go-to-alerts':
        return dash.no_update, 'tab-alerts'

    raise dash.exceptions.PreventUpdate


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
        df = pd.read_sql_query(
            "SELECT * FROM connections WHERE timestamp > datetime('now', '-24 hours')",
            conn
        )
        return dcc.send_data_frame(df.to_csv, "iotsentinel_connections_24h.csv", index=False)
    except (sqlite3.Error, pd.io.sql.DatabaseError) as e:
        logger.error(f"Error generating CSV: {e}")
        return None
    finally:
        conn.close()


@app.callback(
    Output('settings-saved-status', 'children'),
    Input('save-settings-button', 'n_clicks'),
    [State('setting-recipient-email', 'value'),
     State('setting-smtp-host', 'value')],
    prevent_initial_call=True
)
def save_settings(n_clicks, recipient_email, smtp_host):
    """Save user settings."""
    if n_clicks is None:
        return ""

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

    try:
        config.save_user_config(new_settings)
        return dbc.Alert("Settings saved successfully!", color="success")
    except Exception as e:
        logger.error(f"Error saving settings: {e}")
        return dbc.Alert(f"Error saving settings: {e}", color="danger")


@app.callback(
    Output('toast-container', 'children'),
    Input({'type': 'trust-switch', 'ip': dash.dependencies.ALL}, 'value'),
    State({'type': 'trust-switch', 'ip': dash.dependencies.ALL}, 'id'),
    prevent_initial_call=True
)
def toggle_device_trust(values, ids):
    """Callback to handle device trust switch toggles."""
    ctx = callback_context
    if not ctx.triggered:
        raise dash.exceptions.PreventUpdate

    # Get the ID of the switch that triggered the callback
    trigger_id = ctx.triggered[0]['prop_id']

    # Extract the IP from the ID string
    try:
        # trigger_id will be like {"ip":"192.168.1.1","type":"trust-switch"}.value
        # We need to parse the JSON part
        id_dict = json.loads(trigger_id.split('.')[0])
        device_ip = id_dict['ip']

        # The 'value' list will contain the values of all switches.
        # We need to find the value corresponding to the triggered switch.
        # A simpler way is to map ids to values if they are always in the same order
        # or iterate to find the matching value.
        # Given how dash works, ctx.triggered[0]['value'] gives the new value of the triggered component.
        is_trusted = ctx.triggered[0]['value']

    except (json.JSONDecodeError, KeyError) as e:
        logger.error(f"Error parsing trust switch ID or value: {e}")
        return dbc.Toast(
            "Error processing request.",
            header="Error",
            icon="danger",
            duration=3000,
        )

    success = db_manager.set_device_trust(device_ip, is_trusted)

    if success:
        status_text = "Trusted" if is_trusted else "Untrusted"
        return dbc.Toast(
            f"Device {device_ip} set to {status_text}.",
            header="Success",
            icon="success",
            duration=3000,
        )
    else:
        return dbc.Toast(
            f"Failed to update trust status for {device_ip}.",
            header="Error",
            icon="danger",
            duration=3000,
        )


@app.callback(
    Output('theme-selector', 'value'),
    Input('theme-store', 'data'),
    prevent_initial_call=False
)
def load_theme_on_startup(theme_data):
    """Load theme preference from store on startup."""
    if theme_data and 'theme' in theme_data:
        return theme_data['theme']
    return 'light' # Default to light mode


@app.callback(
    Output('theme-store', 'data'),
    Input('theme-selector', 'value'),
    prevent_initial_call=True
)
def update_theme_store(theme):
    """Save theme preference to store."""
    return {'theme': theme}


app.clientside_callback(
    """
    function(theme_data) {
        if (!theme_data) {
            return window.dash_clientside.no_update;
        }
        const theme = theme_data.theme;
        document.body.classList.remove('dark-theme', 'cyberpunk-theme');
        if (theme === 'dark') {
            document.body.classList.add('dark-theme');
        } else if (theme === 'cyberpunk') {
            document.body.classList.add('cyberpunk-theme');
        }
        return window.dash_clientside.no_update;
    }
    """,
    Output('theme-selector', 'id'), # Dummy output
    Input('theme-store', 'data')
)


@app.callback(
    Output('voice-alert-toggle', 'value'),
    Input('voice-alert-store', 'data'),
    prevent_initial_call=False
)
def load_voice_alert_setting(data):
    """Load voice alert setting from store on startup."""
    if data and 'enabled' in data:
        return data['enabled']
    return False

@app.callback(
    Output('voice-alert-store', 'data'),
    Input('voice-alert-toggle', 'value'),
    prevent_initial_call=True
)
def update_voice_alert_store(is_enabled):
    """Save voice alert setting to store."""
    return {'enabled': is_enabled}


app.clientside_callback(
    """
    function(_) {
        document.addEventListener('keydown', function(event) {
            // Check if focus is on an input field, if so, disable shortcuts
            if (event.target.tagName === 'INPUT' || event.target.tagName === 'TEXTAREA') {
                return;
            }

            let action = null;
            if (event.key === 'n') {
                action = 'toggle-notifications';
            } else if (event.key === 'd') {
                action = 'go-to-devices';
            } else if (event.key === 'a') {
                action = 'go-to-alerts';
            }

            if (action) {
                // To trigger the callback, we need to set a new value.
                // We use an object with a timestamp to ensure it's always new.
                dash_clientside.setProps('keyboard-shortcut-store', {
                    data: { action: action, ts: new Date().getTime() }
                });
            }
        });
        return window.dash_clientside.no_update;
    }
    """,
    Output('keyboard-shortcut-store', 'id'), # Dummy output
    Input('url', 'pathname') # Trigger once on page load
)

app.clientside_callback(
    """
    function(ws_message, voice_setting, announced_data) {
        if (!ws_message || !voice_setting || !voice_setting.enabled) {
            return window.dash_clientside.no_update;
        }

        const alerts = ws_message.recent_alerts || [];
        let announced_ids = announced_data.ids || [];
        let new_announcements = false;

        alerts.forEach(alert => {
            if (alert.severity === 'critical' && !announced_ids.includes(alert.id)) {
                const deviceName = alert.device_name || alert.device_ip;
                const msg = `Critical alert for device: ${deviceName}. Reason: ${alert.explanation}`;

                const utterance = new SpeechSynthesisUtterance(msg);
                window.speechSynthesis.speak(utterance);

                announced_ids.push(alert.id);
                new_announcements = true;
            }
        });

        if (new_announcements) {
            // Prune old IDs to prevent the store from growing indefinitely
            if (announced_ids.length > 50) {
                announced_ids = announced_ids.slice(announced_ids.length - 50);
            }
            return { ids: announced_ids };
        }

        return window.dash_clientside.no_update;
    }
    """,
    Output('announced-alerts-store', 'data'),
    Input('ws', 'message'),
    State('voice-alert-store', 'data'),
    State('announced-alerts-store', 'data'),
    prevent_initial_call=True
)

# ============================================================================
# ONBOARDING WIZARD
# ============================================================================

ONBOARDING_STEPS = [
    {
        "title": "Welcome to IoTSentinel!",
        "body": html.Div([
            html.P("This quick tour will guide you through the main features of the dashboard."),
            html.P("IoTSentinel monitors your home network and uses machine learning to detect unusual activity."),
            html.P("Use the 'Next' and 'Previous' buttons to navigate."),
        ])
    },
    {
        "title": "Understanding Device Status",
        "body": html.Div([
            html.P("Each device on your network has a status indicator:"),
            html.Ul([
                html.Li([
                    html.Span("●", style={'color': '#28a745', 'fontSize': '1.2rem'}),
                    " Green: Device is behaving normally"
                ]),
                html.Li([
                    html.Span("●", style={'color': '#ffc107', 'fontSize': '1.2rem'}),
                    " Yellow: Minor unusual activity detected"
                ]),
                html.Li([
                    html.Span("●", style={'color': '#dc3545', 'fontSize': '1.2rem'}),
                    " Red: Significant alerts - review recommended"
                ])
            ])
        ])
    },
    {
        "title": "The Alerts Tab",
        "body": html.Div([
            html.P("When IoTSentinel detects unusual activity, it creates an alert."),
            html.P([
                html.Strong("Click on any alert"),
                " to see a detailed explanation of:"
            ]),
            html.Ul([
                html.Li("What was detected"),
                html.Li("Why it's unusual (compared to normal behavior)"),
                html.Li("Visual charts showing the difference"),
                html.Li("Recommended actions you can take")
            ])
        ])
    },
    {
        "title": "Initial Setup: Baseline Training",
        "body": html.Div([
            html.P("Before IoTSentinel can detect anomalies, it needs to learn what's 'normal'."),
            html.P("To do this, run the baseline collection script:"),
            html.Pre(html.Code("python3 scripts/baseline_collector.py")),
            html.P("This collects 7 days of data to train the ML models.")
        ])
    },
    {
        "title": "You're All Set!",
        "body": html.Div([
            html.P("The dashboard is now ready to use."),
            html.P("Key tips:"),
            html.Ul([
                html.Li("Check the 'Devices' tab to see all connected devices"),
                html.Li("Green dots mean everything is normal"),
                html.Li("Click alerts to understand what's happening"),
                html.Li("The 'Analytics' tab shows trends over time")
            ])
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
    """Update the content of the onboarding modal."""
    if step < 0:
        step = 0
    if step >= len(ONBOARDING_STEPS):
        step = len(ONBOARDING_STEPS) - 1

    content = ONBOARDING_STEPS[step]
    prev_disabled = (step == 0)
    next_text = "Finish" if step == len(ONBOARDING_STEPS) - 1 else "Next"

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
    """Handle navigation in the onboarding modal."""
    ctx = callback_context
    if not ctx.triggered:
        return 0, dash.no_update, dash.no_update

    button_id = ctx.triggered[0]['prop_id'].split('.')[0]

    if button_id == 'onboarding-next':
        if step == len(ONBOARDING_STEPS) - 1:
            return 0, False, {'completed': True}
        return step + 1, dash.no_update, dash.no_update
    elif button_id == 'onboarding-prev':
        return step - 1, dash.no_update, dash.no_update

    return 0, dash.no_update, dash.no_update


# ============================================================================
# WEBSOCKET SERVER-SIDE LOGIC
# ============================================================================

thread = None
thread_lock = threading.Lock()

def background_thread():
    """Continuously fetches and sends updated dashboard data to connected clients."""
    while True:
        socketio.sleep(3) # Emit data every 3 seconds

        data_payload = {}

        # --- 1. Fetch Header Stats ---
        conn = get_db_connection()
        if conn:
            try:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM devices WHERE last_seen > datetime('now', '-5 minutes')")
                data_payload['device_count'] = cursor.fetchone()[0]
                cursor.execute("SELECT COUNT(*) FROM alerts WHERE timestamp > datetime('now', '-24 hours') AND acknowledged = 0")
                data_payload['alert_count'] = cursor.fetchone()[0]
                cursor.execute("SELECT COUNT(*) FROM connections WHERE timestamp > datetime('now', '-1 hour')")
                data_payload['connection_count'] = cursor.fetchone()[0]
            except sqlite3.Error as e:
                logger.error(f"Error fetching header stats for WebSocket: {e}")
            finally:
                conn.close()

        # --- 2. Fetch Network Graph & Recent Activity Data ---
        devices_with_status = get_devices_with_status()
        connections_for_graph = db_manager.get_recent_connections(hours=1)

        # Generate 3D coordinates for devices
        num_devices = len(devices_with_status)
        phi = math.pi * (3. - math.sqrt(5.))  # Golden angle in radians
        for i, device in enumerate(devices_with_status):
            # Add has_critical_alert flag
            device['has_critical_alert'] = (device.get('status') == 'alert')

            y = 1 - (i / (num_devices - 1)) * 2 if num_devices > 1 else 0 # y goes from 1 to -1
            radius = math.sqrt(1 - y * y)
            theta = phi * i
            x = math.cos(theta) * radius
            z = math.sin(theta) * radius
            device['x'] = x * 10 # Scale up for better visualization
            device['y'] = y * 10
            device['z'] = z * 10

        elements = []
        # Add router node (central)
        elements.append({
            'data': {
                'id': 'router',
                'label': 'Router',
                'type': 'router',
                'color': '#007bff',
                'borderColor': '#0056b3'
            }
        })
        device_ips = set()
        for device in devices_with_status:
            device_ip = device['device_ip']
            device_ips.add(device_ip)
            status = device.get('status', 'normal')
            color = DEVICE_STATUS_COLORS.get(status, DEVICE_STATUS_COLORS['unknown'])
            border_colors = {
                'normal': '#1e7b34', 'warning': '#d39e00', 'alert': '#bd2130', 'unknown': '#545b62'
            }
            elements.append({
                'data': {
                    'id': device_ip,
                    'label': device.get('device_name') or device_ip.split('.')[-1],
                    'type': 'device',
                    'color': color,
                    'borderColor': border_colors.get(status, '#545b62'),
                    'status': status
                }
            })
            elements.append({'data': {'source': 'router', 'target': device_ip}})

        if connections_for_graph:
            seen_edges = set()
            for conn in connections_for_graph[:50]:
                src = conn['device_ip']
                dst = conn['dest_ip']
                if src in device_ips and dst in device_ips:
                    edge_key = tuple(sorted([src, dst]))
                    if edge_key not in seen_edges:
                        elements.append({
                            'data': {'source': src, 'target': dst},
                            'classes': 'animated-edge' # Add class for animation
                        })
                        seen_edges.add(edge_key)
        data_payload['network_graph_elements'] = elements
        data_payload['recent_connections_feed'] = connections_for_graph # for recent activity feed

        # --- 3. Fetch Traffic Timeline ---
        data_payload['traffic_timeline'] = db_manager.get_traffic_timeline(hours=24)

        # --- 4. Fetch Protocol Distribution ---
        data_payload['protocol_distribution'] = db_manager.get_protocol_distribution(hours=24)

        # --- 5. Fetch Devices Tab Data ---
        data_payload['all_devices_with_status'] = devices_with_status # Re-use data for device status grid & table
        data_payload['device_activity_heatmap'] = db_manager.get_device_activity_heatmap(hours=24)

        # --- 6. Fetch Alerts Tab Data ---
        # Note: Alerts callback has its own filter logic, so we send all recent alerts.
        # It's better to fetch filtered data here to reduce payload size if possible,
        # but for now, sending all recent (24h) and filtering on client side.
        conn = get_db_connection()
        if conn:
            try:
                query = """
                    SELECT
                        a.id, a.timestamp, a.device_ip, d.device_name, a.severity,
                        a.anomaly_score, a.explanation, a.top_features, a.acknowledged,
                        d.is_trusted # Include is_trusted for alert context
                    FROM alerts a
                    LEFT JOIN devices d ON a.device_ip = d.device_ip
                    WHERE a.timestamp > datetime('now', '-24 hours')
                    ORDER BY a.timestamp DESC
                """
                df_alerts = pd.read_sql_query(query, conn)
                data_payload['recent_alerts'] = df_alerts.to_dict('records')
            except (sqlite3.Error, pd.io.sql.DatabaseError) as e:
                logger.error(f"Error fetching alerts for WebSocket: {e}")
            finally:
                conn.close()

        # --- 7. Fetch Analytics Tab Data ---
        data_payload['alert_timeline'] = db_manager.get_alert_timeline(days=7)
        data_payload['anomaly_distribution'] = db_manager.get_anomaly_distribution(hours=24)
        data_payload['bandwidth_chart'] = db_manager.get_bandwidth_stats(hours=24)

        # --- 8. Fetch System Tab Data ---
        conn = get_db_connection()
        if conn:
            try:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM devices")
                data_payload['total_devices_db'] = cursor.fetchone()[0]
                cursor.execute("SELECT COUNT(*) FROM connections")
                data_payload['total_connections_db'] = cursor.fetchone()[0]
                cursor.execute("SELECT COUNT(*) FROM alerts")
                data_payload['total_alerts_db'] = cursor.fetchone()[0]
            except sqlite3.Error:
                pass
            finally:
                conn.close()

        # Fetch model info from filesystem
        model_dir = project_root / 'data' / 'models'
        models_list = []
        if model_dir.exists():
            for model_file in model_dir.glob('*.pkl'):
                stat = model_file.stat()
                models_list.append({
                    'name': model_file.stem,
                    'size': f"{stat.st_size / 1024:.1f} KB",
                    'modified': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M')
                })
        data_payload['model_info'] = models_list

        data_payload['model_comparison_data'], data_payload['model_comparison_image'] = load_model_comparison_data()
        data_payload['model_performance_metrics'] = db_manager.get_model_performance_metrics(days=30)

        # Emit the comprehensive data payload
        socketio.emit('update_data', data_payload)
        logger.debug(f"Emitted comprehensive data update.")


@socketio.on('connect')
def test_connect(auth):
    global thread
    with thread_lock:
        if thread is None:
            thread = socketio.start_background_task(background_thread)
    emit('my response', {'data': 'Connected', 'count': 0})
    logger.info("Client connected to WebSocket.")


@socketio.on('disconnect')
def test_disconnect():
    logger.info("Client disconnected from WebSocket.")


# ============================================================================
# MAIN
# ============================================================================

def main():
    """Run the dashboard server."""
    host = config.get('dashboard', 'host', default='0.0.0.0')
    port = config.get('dashboard', 'port', default=8050)
    debug = config.get('dashboard', 'debug', default=False)

    logger.info("=" * 70)
    logger.info("IoTSentinel Dashboard - Educational Transparency Edition")
    logger.info("=" * 70)
    logger.info(f"Dashboard URL: http://{host}:{port}")
    logger.info("")
    logger.info("KEY FEATURES:")
    logger.info("  ✓ Device status indicators (green/yellow/red)")
    logger.info("  ✓ Color-coded network topology graph")
    logger.info("  ✓ Educational drill-down with baseline comparisons")
    logger.info("  ✓ Plain English explanations of anomalies")
    logger.info("  ✓ Visual 'Normal vs Today' comparison charts")
    logger.info("=" * 70)

    # Use socketio.run instead of app.run
    socketio.run(app.server, host=host, port=port, debug=debug, allow_unsafe_werkzeug=True)


if __name__ == '__main__':
    # Import threading here since it's used in the server-side logic
    import threading
    main()
