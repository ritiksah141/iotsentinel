#!/usr/bin/env python3
"""
IoTSentinel Dashboard - Enhanced Educational Transparency Edition
Complete implementation with onboarding, trust management, lockdown mode,
voice alerts, enhanced 3D visualizations, and AI assistant.
"""

import base64
import json
import logging
import sqlite3
import math
import time
import threading
import subprocess
import requests
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any
import sys

import dash
import dash_bootstrap_components as dbc
import pandas as pd
import plotly.express as px
import plotly.graph_objs as go
import dash_cytoscape as cyto
from dash import dcc, html, Input, Output, State, callback_context
from dash_extensions import WebSocket
from flask_socketio import SocketIO

# Setup paths
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from config.config_manager import config
from database.db_manager import DatabaseManager
from utils.threat_intel import ThreatIntelligence

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize app
app = dash.Dash(
    __name__,
    external_stylesheets=[dbc.themes.BOOTSTRAP, dbc.icons.FONT_AWESOME, '/assets/skeleton.css'],
    title="IoTSentinel - Network Security Monitor",
    suppress_callback_exceptions=True
)

socketio = SocketIO(app.server, cors_allowed_origins="*")

# Database setup
DB_PATH = config.get('database', 'path')
db_manager = DatabaseManager(DB_PATH)

# Threat Intelligence setup
THREAT_INTEL_ENABLED = config.get('threat_intelligence', 'enabled', default=False)
ABUSEIPDB_API_KEY = config.get('threat_intelligence', 'abuseipdb_api_key', default='')
THREAT_INTEL_CACHE_HOURS = config.get('threat_intelligence', 'cache_hours', default=24)

threat_intel = ThreatIntelligence(
    api_key=ABUSEIPDB_API_KEY,
    db_path=DB_PATH,
    cache_hours=THREAT_INTEL_CACHE_HOURS
)

# ============================================================================
# AI ASSISTANT CONFIGURATION
# ============================================================================

# Ollama configuration
OLLAMA_ENABLED = True  # Set to False to use rule-based fallback only
OLLAMA_API_URL = "http://192.168.1.206:11434/api/generate"
OLLAMA_MODEL = "mistral:7b"  # Options: llama3.2:3b, phi3:mini, mistral:7b, etc.
OLLAMA_TIMEOUT = 30  # seconds

def call_ollama_api(prompt: str, context: str, max_tokens: int = 300) -> Optional[str]:
    """
    Call local Ollama API for AI-powered responses.
    Returns None if Ollama is unavailable or errors occur.
    """
    if not OLLAMA_ENABLED:
        return None

    try:
        full_prompt = f"{context}\n\nUser: {prompt}\n\nAssistant:"

        response = requests.post(
            OLLAMA_API_URL,
            json={
                'model': OLLAMA_MODEL,
                'prompt': full_prompt,
                'stream': False,
                'options': {
                    'temperature': 0.7,
                    'num_predict': max_tokens,
                }
            },
            timeout=OLLAMA_TIMEOUT
        )

        if response.status_code == 200:
            result = response.json()
            return result.get('response', '').strip()
        else:
            logger.warning(f"Ollama API returned status {response.status_code}")
            return None

    except requests.exceptions.ConnectionError:
        logger.warning("Ollama not available. Is it running? (ollama serve)")
        return None
    except requests.exceptions.Timeout:
        logger.warning(f"Ollama request timed out after {OLLAMA_TIMEOUT}s")
        return None
    except Exception as e:
        logger.error(f"Error calling Ollama API: {e}")
        return None

def get_rule_based_response(message: str, device_count: int, alert_count: int, recent_alerts: List[Dict]) -> str:
    """
    Fallback rule-based responses when Ollama is unavailable.
    """
    user_msg_lower = message.lower()

    # Security-related queries
    if any(word in user_msg_lower for word in ['safe', 'secure', 'protected', 'risk']):
        if alert_count == 0:
            return f"✅ Your network appears secure! All {device_count} devices are behaving normally with no active alerts. Keep monitoring enabled for continuous protection."
        else:
            return f"⚠️ I've detected {alert_count} security alert(s) requiring attention. Click on any alert in the right panel to see detailed explanations and recommended actions."

    # Device queries
    elif any(word in user_msg_lower for word in ['device', 'connected', 'what is']):
        return f"📱 You have {device_count} devices currently connected to your network. You can click on any device in the left panel to see detailed information, activity statistics, and trust settings."

    # Alert explanation queries
    elif any(word in user_msg_lower for word in ['alert', 'warning', 'unusual', 'detected']):
        if alert_count > 0 and recent_alerts:
            alert = recent_alerts[0]
            return f"🚨 Most recent alert: {alert.get('explanation', 'Unknown activity')} on device {alert.get('device_name') or alert.get('device_ip', 'Unknown')}. Click the 'Details' button to see educational breakdown with baseline comparisons."
        else:
            return "✅ No active alerts! Your network has been quiet. IoTSentinel uses ML models (Autoencoder + Isolation Forest) to detect anomalies in real-time."

    # How-to queries
    elif any(word in user_msg_lower for word in ['how', 'what does', 'explain']):
        return "📚 IoTSentinel monitors your network using Zeek for traffic analysis and dual ML models for anomaly detection. When unusual activity is detected, you'll see color-coded alerts with plain English explanations and visual baseline comparisons showing 'Normal vs Today'."

    # Lockdown mode queries
    elif any(word in user_msg_lower for word in ['lockdown', 'block', 'emergency']):
        return "🔐 Lockdown Mode is available in Settings → Firewall Control. When enabled, it blocks ALL untrusted devices from accessing your network. Mark important devices as 'Trusted' first by clicking on them and toggling the trust switch."

    # Voice alerts
    elif any(word in user_msg_lower for word in ['voice', 'speak', 'audio', 'sound']):
        return "🔊 Voice Alerts can be enabled using the toggle in the header. When turned on, critical and high-severity alerts will be announced using text-to-speech, so you'll hear about security issues even if you're not watching the dashboard."

    # General greeting
    elif any(word in user_msg_lower for word in ['hello', 'hi', 'hey']):
        return f"👋 Hello! I'm your IoTSentinel AI Assistant. Your network has {device_count} active devices and {alert_count} alert(s). How can I help you today?"

    # Default response
    else:
        return f"I can help you understand your network security! Try asking about:\n\n• Current security status\n• Device information\n• Alert explanations\n• How IoTSentinel works\n• Lockdown mode\n• Voice alerts\n\nYour network: {device_count} devices, {alert_count} active alert(s)."

# ============================================================================
# CONSTANTS
# ============================================================================

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

SEVERITY_CONFIG = {
    'critical': {'color': 'danger', 'icon': 'fa-skull-crossbones', 'badge_color': '#dc3545'},
    'high': {'color': 'warning', 'icon': 'fa-exclamation-triangle', 'badge_color': '#fd7e14'},
    'medium': {'color': 'info', 'icon': 'fa-exclamation-circle', 'badge_color': '#17a2b8'},
    'low': {'color': 'secondary', 'icon': 'fa-info-circle', 'badge_color': '#6c757d'}
}

DEVICE_STATUS_COLORS = {
    'normal': '#28a745', 'warning': '#ffc107', 'alert': '#dc3545', 'unknown': '#6c757d'
}

# Device Type Icon Mapping (Emoji + Font Awesome)
DEVICE_TYPE_ICONS = {
    # Mobile Devices
    'smartphone': {'emoji': '📱', 'fa': 'fa-mobile-alt', 'color': '#007bff'},
    'phone': {'emoji': '📱', 'fa': 'fa-mobile-alt', 'color': '#007bff'},
    'iphone': {'emoji': '📱', 'fa': 'fa-mobile-alt', 'color': '#007bff'},
    'android': {'emoji': '📱', 'fa': 'fa-mobile-alt', 'color': '#28a745'},
    'tablet': {'emoji': '📱', 'fa': 'fa-tablet-alt', 'color': '#6f42c1'},
    'ipad': {'emoji': '📱', 'fa': 'fa-tablet-alt', 'color': '#6f42c1'},

    # Computers
    'laptop': {'emoji': '💻', 'fa': 'fa-laptop', 'color': '#6c757d'},
    'computer': {'emoji': '💻', 'fa': 'fa-desktop', 'color': '#6c757d'},
    'desktop': {'emoji': '🖥️', 'fa': 'fa-desktop', 'color': '#6c757d'},
    'pc': {'emoji': '🖥️', 'fa': 'fa-desktop', 'color': '#6c757d'},
    'mac': {'emoji': '💻', 'fa': 'fa-laptop', 'color': '#6c757d'},
    'workstation': {'emoji': '🖥️', 'fa': 'fa-desktop', 'color': '#495057'},

    # Smart Home
    'smart tv': {'emoji': '📺', 'fa': 'fa-tv', 'color': '#e83e8c'},
    'tv': {'emoji': '📺', 'fa': 'fa-tv', 'color': '#e83e8c'},
    'streaming device': {'emoji': '📺', 'fa': 'fa-tv', 'color': '#fd7e14'},
    'roku': {'emoji': '📺', 'fa': 'fa-tv', 'color': '#6f2da8'},
    'chromecast': {'emoji': '📺', 'fa': 'fa-chromecast', 'color': '#4285f4'},
    'apple tv': {'emoji': '📺', 'fa': 'fa-tv', 'color': '#000000'},
    'fire stick': {'emoji': '📺', 'fa': 'fa-tv', 'color': '#ff9900'},

    # Smart Speakers & Assistants
    'smart speaker': {'emoji': '🔊', 'fa': 'fa-volume-up', 'color': '#17a2b8'},
    'speaker': {'emoji': '🔊', 'fa': 'fa-volume-up', 'color': '#17a2b8'},
    'alexa': {'emoji': '🔊', 'fa': 'fa-amazon', 'color': '#00a8e1'},
    'echo': {'emoji': '🔊', 'fa': 'fa-amazon', 'color': '#00a8e1'},
    'google home': {'emoji': '🔊', 'fa': 'fa-google', 'color': '#4285f4'},
    'homepod': {'emoji': '🔊', 'fa': 'fa-volume-up', 'color': '#000000'},

    # Gaming
    'gaming console': {'emoji': '🎮', 'fa': 'fa-gamepad', 'color': '#20c997'},
    'playstation': {'emoji': '🎮', 'fa': 'fa-playstation', 'color': '#003087'},
    'xbox': {'emoji': '🎮', 'fa': 'fa-xbox', 'color': '#107c10'},
    'nintendo': {'emoji': '🎮', 'fa': 'fa-gamepad', 'color': '#e60012'},
    'switch': {'emoji': '🎮', 'fa': 'fa-gamepad', 'color': '#e60012'},

    # Network Equipment
    'router': {'emoji': '🌐', 'fa': 'fa-wifi', 'color': '#007bff'},
    'access point': {'emoji': '📡', 'fa': 'fa-broadcast-tower', 'color': '#6c757d'},
    'switch': {'emoji': '🔀', 'fa': 'fa-network-wired', 'color': '#6c757d'},
    'gateway': {'emoji': '🌐', 'fa': 'fa-door-open', 'color': '#007bff'},
    'modem': {'emoji': '📡', 'fa': 'fa-broadcast-tower', 'color': '#6c757d'},

    # IoT Devices
    'smart camera': {'emoji': '📷', 'fa': 'fa-camera', 'color': '#dc3545'},
    'camera': {'emoji': '📷', 'fa': 'fa-video', 'color': '#dc3545'},
    'security camera': {'emoji': '📹', 'fa': 'fa-video', 'color': '#dc3545'},
    'doorbell': {'emoji': '🔔', 'fa': 'fa-bell', 'color': '#ffc107'},
    'smart lock': {'emoji': '🔐', 'fa': 'fa-lock', 'color': '#28a745'},
    'thermostat': {'emoji': '🌡️', 'fa': 'fa-thermometer-half', 'color': '#fd7e14'},
    'smart plug': {'emoji': '🔌', 'fa': 'fa-plug', 'color': '#17a2b8'},
    'light bulb': {'emoji': '💡', 'fa': 'fa-lightbulb', 'color': '#ffc107'},
    'sensor': {'emoji': '📊', 'fa': 'fa-sensor', 'color': '#6f42c1'},

    # Printers & Peripherals
    'printer': {'emoji': '🖨️', 'fa': 'fa-print', 'color': '#6c757d'},
    'scanner': {'emoji': '🖨️', 'fa': 'fa-print', 'color': '#6c757d'},
    'nas': {'emoji': '💾', 'fa': 'fa-hdd', 'color': '#495057'},
    'storage': {'emoji': '💾', 'fa': 'fa-database', 'color': '#495057'},

    # Wearables
    'smartwatch': {'emoji': '⌚', 'fa': 'fa-clock', 'color': '#6f42c1'},
    'watch': {'emoji': '⌚', 'fa': 'fa-clock', 'color': '#6f42c1'},
    'fitness tracker': {'emoji': '⌚', 'fa': 'fa-heartbeat', 'color': '#dc3545'},

    # Default/Unknown
    'unknown': {'emoji': '❓', 'fa': 'fa-question-circle', 'color': '#6c757d'},
    'other': {'emoji': '📱', 'fa': 'fa-microchip', 'color': '#6c757d'},
}

# Onboarding Steps
ONBOARDING_STEPS = [
    {
        "title": "Welcome to IoTSentinel! 🛡️",
        "body": html.Div([
            html.P("This quick tour will guide you through the main features of your network security dashboard."),
            html.P("IoTSentinel monitors your home network and uses machine learning to detect unusual activity."),
            html.Hr(),
            html.H6("What makes IoTSentinel different?"),
            html.Ul([
                html.Li("🎓 Educational explanations - understand WHY alerts happen"),
                html.Li("📊 Visual baselines - see what's normal vs unusual"),
                html.Li("🔍 Real-time monitoring - powered by Zeek on Raspberry Pi 5"),
                html.Li("🤖 Dual ML models - Autoencoder & Isolation Forest")
            ]),
            html.P("Use the 'Next' and 'Previous' buttons to navigate.", className="text-muted small")
        ])
    },
    {
        "title": "Understanding Device Status 🚦",
        "body": html.Div([
            html.P("Each device on your network has a color-coded status indicator:"),
            html.Div([
                html.Div([
                    html.Span("●", style={'color': '#28a745', 'fontSize': '1.5rem', 'marginRight': '10px'}),
                    html.Strong("Green (Normal): "),
                    html.Span("Device is behaving normally - no concerns")
                ], className="mb-2"),
                html.Div([
                    html.Span("●", style={'color': '#ffc107', 'fontSize': '1.5rem', 'marginRight': '10px'}),
                    html.Strong("Yellow (Warning): "),
                    html.Span("Minor unusual activity detected - worth checking")
                ], className="mb-2"),
                html.Div([
                    html.Span("●", style={'color': '#dc3545', 'fontSize': '1.5rem', 'marginRight': '10px'}),
                    html.Strong("Red (Alert): "),
                    html.Span("Significant security alerts - review recommended immediately")
                ], className="mb-2")
            ], className="p-3 bg-dark rounded"),
            html.Hr(),
            html.P("💡 Tip: Click on any device to see detailed information and set trust levels.", className="text-info")
        ])
    },
    {
        "title": "The Alerts System 🚨",
        "body": html.Div([
            html.P("When IoTSentinel detects unusual activity, it creates an alert with detailed context."),
            html.H6("Click on any alert to see:", className="mt-3"),
            html.Ul([
                html.Li("📊 What was detected (in plain English)"),
                html.Li("📈 Visual charts comparing to normal behavior"),
                html.Li("🔍 Why it's unusual (with 7-day baseline)"),
                html.Li("🛡️ Recommended actions you can take"),
                html.Li("🔬 Technical details (MITRE ATT&CK mapping)")
            ]),
            html.Hr(),
            html.Div([
                html.Strong("Educational Transparency: "),
                html.P("Unlike commercial products, IoTSentinel explains the 'why' behind every alert.", className="mb-0")
            ], className="alert alert-info")
        ])
    },
    {
        "title": "Trust Management & Lockdown Mode 🔐",
        "body": html.Div([
            html.H6("Trust Management"),
            html.P("Mark devices as 'Trusted' to reduce false positives and customize monitoring:"),
            html.Ul([
                html.Li("Click on a device → Toggle 'Trusted' switch"),
                html.Li("Trusted devices get different alert thresholds"),
                html.Li("Useful for known-safe IoT devices like printers")
            ]),
            html.Hr(),
            html.H6("Lockdown Mode"),
            html.P("Emergency security mode that blocks all untrusted devices:"),
            html.Ul([
                html.Li("Toggle the switch in Settings → Firewall Control"),
                html.Li("Only trusted devices can access the network"),
                html.Li("Useful during suspected security incidents")
            ]),
            html.Div([
                html.I(className="fa fa-exclamation-triangle me-2"),
                html.Strong("Warning: "),
                html.Span("Lockdown mode can disrupt normal network activity!")
            ], className="alert alert-warning")
        ])
    },
    {
        "title": "Initial Setup: Baseline Training 📚",
        "body": html.Div([
            html.P("Before IoTSentinel can detect anomalies effectively, it needs to learn what's 'normal' for your network."),
            html.H6("To build the baseline:", className="mt-3"),
            html.Ol([
                html.Li("Run the baseline collector script:"),
                html.Pre(html.Code("python3 scripts/baseline_collector.py"), className="bg-dark p-2 rounded"),
                html.Li("Let it collect data for 7 days (24/7 monitoring)"),
                html.Li("The ML models will train on this 'normal' behavior"),
                html.Li("After 7 days, anomaly detection becomes highly accurate")
            ]),
            html.Hr(),
            html.Div([
                html.H6("During the baseline period:"),
                html.Ul([
                    html.Li("✅ Network monitoring is active"),
                    html.Li("✅ Device discovery works"),
                    html.Li("⚠️ Alert quality improves over time"),
                    html.Li("📊 Baseline charts become available after day 7")
                ])
            ], className="alert alert-info")
        ])
    },
    {
        "title": "You're All Set! 🎉",
        "body": html.Div([
            html.H5("Dashboard Overview:", className="text-cyber"),
            html.Ul([
                html.Li("📱 Left Panel: Connected devices overview"),
                html.Li("🌐 Center Panel: Real-time network traffic visualization"),
                html.Li("🚨 Right Panel: Security alerts with educational insights"),
                html.Li("📊 Analytics: Expandable section with detailed metrics")
            ]),
            html.Hr(),
            html.H6("Keyboard Shortcuts:", className="mt-3"),
            html.Ul([
                html.Li(html.Kbd("N"), " - Toggle notification drawer"),
                html.Li(html.Kbd("D"), " - Jump to devices"),
                html.Li(html.Kbd("A"), " - Jump to alerts")
            ]),
            html.Hr(),
            html.Div([
                html.H6("Need Help?"),
                html.P("Click the 🤖 robot icon in the header to open the AI assistant.", className="mb-0")
            ], className="alert alert-success"),
            html.P("You can always restart this tour from Settings. Happy monitoring! 🛡️",
                   className="text-center text-muted mt-3")
        ])
    }
]

# ============================================================================
# DATABASE HELPERS
# ============================================================================

def get_db_connection():
    try:
        conn = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        return conn
    except sqlite3.Error as e:
        logger.error(f"Database connection error: {e}")
        return None

def get_device_status(device_ip: str, hours: int = 24) -> str:
    conn = get_db_connection()
    if not conn:
        return 'unknown'
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT severity, COUNT(*) as count FROM alerts
            WHERE device_ip = ? AND timestamp > datetime('now', ? || ' hours') AND acknowledged = 0
            GROUP BY severity
        """, (device_ip, f'-{hours}'))
        alerts = {row['severity']: row['count'] for row in cursor.fetchall()}
        if alerts.get('critical', 0) > 0 or alerts.get('high', 0) > 0:
            return 'alert'
        elif alerts.get('medium', 0) > 0 or alerts.get('low', 0) > 0:
            return 'warning'
        return 'normal'
    except sqlite3.Error as e:
        logger.error(f"Error getting device status: {e}")
        return 'unknown'
    finally:
        conn.close()

def get_device_baseline(device_ip: str, days: int = 7) -> Dict[str, Any]:
    conn = get_db_connection()
    if not conn:
        return {'has_baseline': False}
    try:
        cursor = conn.cursor()
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
                SELECT DATE(timestamp) as day,
                    SUM(bytes_sent) as daily_bytes_sent,
                    SUM(bytes_received) as daily_bytes_received,
                    COUNT(*) as daily_connections,
                    COUNT(DISTINCT dest_ip) as daily_unique_destinations
                FROM connections
                WHERE device_ip = ? AND timestamp BETWEEN datetime('now', ? || ' days') AND datetime('now', '-1 day')
                GROUP BY DATE(timestamp)
            )
        """, (device_ip, f'-{days}'))
        row = cursor.fetchone()
        if row and row['avg_bytes_sent'] is not None:
            return {
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
        return {'has_baseline': False}
    except sqlite3.Error as e:
        logger.error(f"Error getting device baseline: {e}")
        return {'has_baseline': False}
    finally:
        conn.close()

def get_device_today_stats(device_ip: str) -> Dict[str, Any]:
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
            WHERE device_ip = ? AND DATE(timestamp) = DATE('now')
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
    conn = get_db_connection()
    if not conn:
        return {}
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT a.*, d.device_name, d.device_type, d.manufacturer
            FROM alerts a LEFT JOIN devices d ON a.device_ip = d.device_ip
            WHERE a.id = ?
        """, (alert_id,))
        row = cursor.fetchone()
        if not row:
            return {}
        alert = dict(row)
        alert['baseline'] = get_device_baseline(alert['device_ip'])
        alert['today_stats'] = get_device_today_stats(alert['device_ip'])
        return alert
    except sqlite3.Error as e:
        logger.error(f"Error getting alert context: {e}")
        return {}
    finally:
        conn.close()

def get_device_details(device_ip: str) -> Dict[str, Any]:
    """Get comprehensive device information"""
    conn = get_db_connection()
    if not conn:
        return {}
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT d.*,
                (SELECT COUNT(*) FROM connections c WHERE c.device_ip = d.device_ip) as total_connections,
                (SELECT COUNT(*) FROM alerts a WHERE a.device_ip = d.device_ip) as total_alerts,
                (SELECT COUNT(*) FROM alerts a WHERE a.device_ip = d.device_ip AND a.acknowledged = 0) as active_alerts
            FROM devices d WHERE d.device_ip = ?
        """, (device_ip,))
        row = cursor.fetchone()
        if not row:
            return {}
        device = dict(row)
        device['baseline'] = get_device_baseline(device_ip)
        device['today_stats'] = get_device_today_stats(device_ip)
        device['status'] = get_device_status(device_ip)
        return device
    except sqlite3.Error as e:
        logger.error(f"Error getting device details: {e}")
        return {}
    finally:
        conn.close()

def get_devices_with_status() -> List[Dict]:
    conn = get_db_connection()
    if not conn:
        return []
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT d.*,
                (SELECT COUNT(*) FROM alerts a WHERE a.device_ip = d.device_ip
                 AND a.timestamp > datetime('now', '-24 hours') AND a.acknowledged = 0
                 AND a.severity IN ('critical', 'high')) as critical_alerts,
                (SELECT COUNT(*) FROM alerts a WHERE a.device_ip = d.device_ip
                 AND a.timestamp > datetime('now', '-24 hours') AND a.acknowledged = 0
                 AND a.severity IN ('medium', 'low')) as minor_alerts,
                (SELECT COUNT(*) FROM connections c WHERE c.device_ip = d.device_ip
                 AND c.timestamp > datetime('now', '-1 hour')) as recent_connections
            FROM devices d ORDER BY d.last_seen DESC
        """)
        devices = []
        for row in cursor.fetchall():
            device = dict(row)
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
    report_path = project_root / 'comparison_report.json'
    image_path = project_root / 'model_comparison_visualization.png'
    report_data, encoded_image = {}, None
    if report_path.exists():
        with open(report_path, 'r', encoding='utf-8') as f:
            report_data = json.load(f)
    if image_path.exists():
        with open(image_path, 'rb') as f:
            encoded_image = base64.b64encode(f.read()).decode()
    return report_data, encoded_image

# ============================================================================
# UI HELPERS
# ============================================================================

def format_bytes(bytes_value: float) -> str:
    if bytes_value is None:
        return "0 B"
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if abs(bytes_value) < 1024.0:
            return f"{bytes_value:.1f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.1f} PB"

def create_status_indicator(status: str, size: str = "1.5rem") -> html.Span:
    color = DEVICE_STATUS_COLORS.get(status, DEVICE_STATUS_COLORS['unknown'])
    pulse_class = "pulse-animation" if status == 'alert' else ""
    return html.Span(
        html.I(className="fa fa-circle"),
        style={'color': color, 'fontSize': size, 'marginRight': '8px'},
        className=pulse_class,
        title=f"Status: {status.capitalize()}"
    )

def get_device_icon_data(device_type: Optional[str]) -> Dict[str, str]:
    """
    Get icon data (emoji, font awesome class, color) for a device type.
    Matches device_type case-insensitively against DEVICE_TYPE_ICONS.
    """
    if not device_type:
        return DEVICE_TYPE_ICONS['unknown']

    # Normalize device type for matching
    device_type_lower = device_type.lower().strip()

    # Direct match
    if device_type_lower in DEVICE_TYPE_ICONS:
        return DEVICE_TYPE_ICONS[device_type_lower]

    # Partial match (e.g., "Samsung Smart TV" matches "smart tv")
    for key, value in DEVICE_TYPE_ICONS.items():
        if key in device_type_lower or device_type_lower in key:
            return value

    # Default to unknown
    return DEVICE_TYPE_ICONS['unknown']

def create_device_icon(device_type: Optional[str], use_emoji: bool = True,
                       use_fa: bool = False, size: str = "1.2rem") -> html.Span:
    """
    Create device icon component with optional emoji and/or Font Awesome icon.

    Args:
        device_type: Device type string from database
        use_emoji: Include emoji icon (default True)
        use_fa: Include Font Awesome icon (default False)
        size: Font size for icons

    Returns:
        html.Span with the appropriate icon(s)
    """
    icon_data = get_device_icon_data(device_type)

    children = []

    if use_emoji:
        children.append(
            html.Span(
                icon_data['emoji'],
                style={'fontSize': size, 'marginRight': '6px'},
                title=device_type or 'Unknown Device'
            )
        )

    if use_fa:
        children.append(
            html.I(
                className=f"fa {icon_data['fa']}",
                style={'color': icon_data['color'], 'fontSize': size, 'marginRight': '6px'},
                title=device_type or 'Unknown Device'
            )
        )

    if not children:
        # Fallback if both are False
        children.append(
            html.Span(
                icon_data['emoji'],
                style={'fontSize': size, 'marginRight': '6px'}
            )
        )

    return html.Span(children)

def create_threat_intel_badge(reputation_data: Dict[str, Any]) -> html.Div:
    """
    Create a visual badge/alert for IP reputation data.

    Args:
        reputation_data: Threat intelligence data from ThreatIntelligence.get_ip_reputation()

    Returns:
        html.Div with formatted threat intelligence display
    """
    level = reputation_data.get('reputation_level', 'unknown')
    score = reputation_data.get('abuse_confidence_score', 0)
    ip = reputation_data.get('ip_address', 'Unknown')

    # Color and icon based on reputation level
    level_config = {
        'malicious': {'color': 'danger', 'icon': 'fa-skull-crossbones', 'emoji': '⛔', 'text': 'MALICIOUS'},
        'suspicious': {'color': 'warning', 'icon': 'fa-exclamation-triangle', 'emoji': '⚠️', 'text': 'SUSPICIOUS'},
        'low_risk': {'color': 'info', 'icon': 'fa-info-circle', 'emoji': 'ℹ️', 'text': 'LOW RISK'},
        'safe': {'color': 'success', 'icon': 'fa-check-circle', 'emoji': '✅', 'text': 'SAFE'},
        'private': {'color': 'secondary', 'icon': 'fa-home', 'emoji': '🏠', 'text': 'PRIVATE'},
        'unknown': {'color': 'secondary', 'icon': 'fa-question-circle', 'emoji': '❓', 'text': 'UNKNOWN'}
    }

    config_data = level_config.get(level, level_config['unknown'])

    # Build the display
    children = []

    # Header with reputation level
    children.append(
        html.Div([
            html.Span(config_data['emoji'], style={'fontSize': '1.5rem', 'marginRight': '10px'}),
            html.Strong(f"Threat Intelligence: {config_data['text']}", className="me-2"),
            dbc.Badge(f"Score: {score}/100", color=config_data['color'], className="ms-2")
        ], className="d-flex align-items-center mb-3")
    )

    # Details
    if level not in ['private', 'unknown']:
        details = [
            html.P([html.Strong("IP Address: "), ip]),
            html.P([html.Strong("Country: "), reputation_data.get('country_code', 'Unknown')]),
            html.P([html.Strong("ISP: "), reputation_data.get('isp', 'Unknown')]),
            html.P([html.Strong("Total Reports: "), str(reputation_data.get('total_reports', 0))]),
        ]

        # Categories
        categories = reputation_data.get('categories', [])
        if categories:
            category_badges = [dbc.Badge(cat, color="dark", className="me-1 mb-1") for cat in categories[:5]]
            details.append(
                html.Div([
                    html.Strong("Threat Categories: "),
                    html.Div(category_badges, className="d-inline")
                ], className="mb-2")
            )

        # Last reported
        last_reported = reputation_data.get('last_reported_at', '')
        if last_reported:
            details.append(html.P([html.Strong("Last Reported: "), last_reported], className="small text-muted"))

        children.append(html.Div(details))

    # Recommendation
    recommendation = reputation_data.get('recommendation', '')
    if recommendation:
        children.append(
            dbc.Alert([
                html.I(className=f"fa {config_data['icon']} me-2"),
                recommendation
            ], color=config_data['color'], className="mt-3 mb-0")
        )

    # Cached indicator
    if reputation_data.get('is_cached', False):
        children.append(
            html.Small("🔄 Cached result", className="text-muted d-block mt-2")
        )

    return html.Div(children, className="threat-intel-display")

def create_device_skeleton(count: int = 8) -> html.Div:
    """Create skeleton placeholders for device cards"""
    skeletons = []
    for _ in range(count):
        skeletons.append(
            html.Div([
                html.Div(className="skeleton skeleton-device-indicator"),
                html.Div(className="skeleton skeleton-device-name"),
                html.Div(className="skeleton skeleton-device-ip")
            ], className="skeleton-device-item")
        )
    return html.Div(skeletons, className="skeleton-container")

def create_alert_skeleton(count: int = 5) -> html.Div:
    """Create skeleton placeholders for alert cards"""
    skeletons = []
    for _ in range(count):
        skeletons.append(
            html.Div([
                html.Div([
                    html.Div(className="skeleton skeleton-alert-icon"),
                    html.Div(className="skeleton skeleton-alert-title")
                ], className="skeleton-alert-header"),
                html.Div(className="skeleton skeleton-alert-description"),
                html.Div(className="skeleton skeleton-alert-description", style={'width': '60%'}),
                html.Div(className="skeleton skeleton-alert-metadata")
            ], className="skeleton-alert-card")
        )
    return html.Div(skeletons, className="skeleton-container")

def create_graph_skeleton() -> html.Div:
    """Create skeleton placeholder for network graph"""
    return html.Div([
        html.Div([
            html.Div(className="skeleton skeleton-graph-inner")
        ], className="skeleton-graph"),
        html.P("Loading network visualization...", className="skeleton-loading-text")
    ], className="skeleton-container")

def create_stat_skeleton() -> html.Div:
    """Create skeleton placeholder for stat card"""
    return html.Div([
        html.Div(className="skeleton skeleton-stat-icon"),
        html.Div(className="skeleton skeleton-stat-number"),
        html.Div(className="skeleton skeleton-stat-label")
    ], className="skeleton-stat-card")

def create_device_list_skeleton(count: int = 10) -> html.Div:
    """Create skeleton placeholders for device list (expanded view)"""
    skeletons = []
    for _ in range(count):
        skeletons.append(
            html.Div([
                html.Div([
                    html.Div(className="skeleton skeleton-device-indicator"),
                    html.Div(className="skeleton skeleton-device-name"),
                    html.Div(className="skeleton skeleton-device-badge")
                ], className="skeleton-device-list-header"),
                html.Div(className="skeleton skeleton-device-ip", style={'width': '60%'})
            ], className="skeleton-device-list-item")
        )
    return html.Div(skeletons, className="skeleton-container")

def create_baseline_comparison_chart(baseline: Dict, today_stats: Dict, metric_name: str,
                                     baseline_key: str, today_key: str, title: str) -> go.Figure:
    baseline_value = baseline.get(baseline_key, 0)
    today_value = today_stats.get(today_key, 0)
    pct_diff = ((today_value - baseline_value) / baseline_value) * 100 if baseline_value > 0 else (100 if today_value > 0 else 0)

    today_color = '#28a745' if abs(pct_diff) < 50 else ('#ffc107' if abs(pct_diff) < 150 else '#dc3545')

    fig = go.Figure()
    fig.add_trace(go.Bar(
        name='Normal (7-day avg)', x=[metric_name], y=[baseline_value], marker_color='#6c757d',
        text=[format_bytes(baseline_value) if 'bytes' in baseline_key.lower() else f"{baseline_value:.0f}"],
        textposition='outside'
    ))
    fig.add_trace(go.Bar(
        name='Today', x=[metric_name], y=[today_value], marker_color=today_color,
        text=[format_bytes(today_value) if 'bytes' in today_key.lower() else f"{today_value:.0f}"],
        textposition='outside'
    ))

    fig.update_layout(
        title=dict(text=title, font=dict(size=14)),
        barmode='group', height=250, margin=dict(l=40, r=40, t=60, b=40),
        showlegend=True, legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="center", x=0.5),
        yaxis_title="", xaxis_title=""
    )

    if abs(pct_diff) > 10:
        direction = "higher" if pct_diff > 0 else "lower"
        fig.add_annotation(
            x=metric_name, y=max(baseline_value, today_value),
            text=f"{abs(pct_diff):.0f}% {direction}",
            showarrow=False, font=dict(size=12, color=today_color, weight='bold'), yshift=30
        )

    return fig

def create_educational_explanation(alert: Dict) -> html.Div:
    baseline = alert.get('baseline', {})
    today_stats = alert.get('today_stats', {})
    explanation_type = alert.get('explanation', 'Unknown')
    device_name = alert.get('device_name') or alert.get('device_ip', 'Unknown Device')

    mitre_info = MITRE_ATTACK_MAPPING.get(explanation_type, {
        'tactic': 'Unknown',
        'description': 'Unusual activity detected.',
        'user_explanation': 'This device is behaving differently than expected.'
    })

    sections = []

    if baseline.get('has_baseline', False):
        avg_bytes_sent = baseline.get('avg_bytes_sent', 0)
        today_bytes_sent = today_stats.get('today_bytes_sent', 0)

        if today_bytes_sent > avg_bytes_sent * 2:
            data_explanation = f"""**{device_name}** typically sends about **{format_bytes(avg_bytes_sent)}** of data per day.
            Today, it has already sent **{format_bytes(today_bytes_sent)}** — that's **{(today_bytes_sent/avg_bytes_sent*100):.0f}%** of what it normally sends in an entire day!"""
        else:
            data_explanation = f"""**{device_name}** has sent **{format_bytes(today_bytes_sent)}** today, compared to a normal daily average of **{format_bytes(avg_bytes_sent)}**."""

        sections.append(
            dbc.Alert([
                html.H5("📊 What We Detected", className="alert-heading"),
                dcc.Markdown(data_explanation),
                html.Hr(),
                html.H6("🔍 Why This Matters"),
                html.P(mitre_info['user_explanation'], className="mb-0")
            ], color="info", className="mb-3")
        )

        sections.append(html.H5("📈 Comparison with Normal Behavior", className="mt-4 mb-3"))
        sections.append(
            dbc.Row([
                dbc.Col([
                    dcc.Graph(
                        figure=create_baseline_comparison_chart(
                            baseline, today_stats, "Data Sent",
                            "avg_bytes_sent", "today_bytes_sent", "Data Sent: Normal vs Today"
                        ),
                        config={'displayModeBar': False}
                    )
                ], width=6),
                dbc.Col([
                    dcc.Graph(
                        figure=create_baseline_comparison_chart(
                            baseline, today_stats, "Connections",
                            "avg_connections", "today_connections", "Connection Count: Normal vs Today"
                        ),
                        config={'displayModeBar': False}
                    )
                ], width=6)
            ], className="mb-3")
        )

        sections.append(
            dbc.Row([
                dbc.Col([
                    dcc.Graph(
                        figure=create_baseline_comparison_chart(
                            baseline, today_stats, "Data Received",
                            "avg_bytes_received", "today_bytes_received", "Data Received: Normal vs Today"
                        ),
                        config={'displayModeBar': False}
                    )
                ], width=6),
                dbc.Col([
                    dcc.Graph(
                        figure=create_baseline_comparison_chart(
                            baseline, today_stats, "Destinations",
                            "avg_unique_destinations", "today_unique_destinations", "Unique Destinations: Normal vs Today"
                        ),
                        config={'displayModeBar': False}
                    )
                ], width=6)
            ])
        )
    else:
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

    # Add Threat Intelligence for connection-based alerts
    if threat_intel.enabled and explanation_type in ["Connection to Known Malicious IP", "Unusual Port Activity"]:
        # Try to extract destination IP from alert features
        top_features = alert.get('top_features', '{}')
        try:
            features = json.loads(top_features) if isinstance(top_features, str) else top_features
            dest_ip = None

            # Look for dest_ip in features
            for key in features.keys():
                if 'dest_ip' in key.lower() or 'destination' in key.lower():
                    # Extract IP from feature name (e.g., "dest_ip_45.142.213.111")
                    parts = key.split('_')
                    for part in parts:
                        if '.' in part and len(part.split('.')) == 4:
                            dest_ip = part
                            break
                    if dest_ip:
                        break

            if dest_ip:
                logger.info(f"Checking threat intelligence for destination IP: {dest_ip}")
                reputation = threat_intel.get_ip_reputation(dest_ip)

                sections.append(html.H5("🌐 Threat Intelligence", className="mt-4 mb-3"))
                sections.append(create_threat_intel_badge(reputation))

        except (json.JSONDecodeError, Exception) as e:
            logger.error(f"Error extracting dest_ip from alert features: {e}")

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

    sections.append(dbc.Alert([html.Ul([html.Li(action) for action in actions])], color=action_color))

    sections.append(
        dbc.Accordion([
            dbc.AccordionItem([
                html.P([html.Strong("MITRE ATT&CK Tactic: "), mitre_info['tactic']]),
                html.P([html.Strong("Technical Description: "), mitre_info['description']]),
                html.P([html.Strong("Anomaly Score: "), f"{alert.get('anomaly_score', 0):.4f}"]),
                html.P([html.Strong("Detection Model: "), alert.get('model_types', 'N/A')]),
                html.Hr(),
                html.H6("Raw Feature Contributions:"),
                html.Pre(json.dumps(json.loads(alert.get('top_features', '{}')), indent=2))
            ], title="🔬 Technical Details (Advanced)")
        ], start_collapsed=True, className="mt-3")
    )

    return html.Div(sections)

# ============================================================================
# LAYOUT
# ============================================================================

app.layout = dbc.Container([
    # Header
    dbc.Row([
        dbc.Col([
            html.Div([
                html.H2([
                    html.I(className="fa fa-shield-alt me-2 glow-icon"),
                    "IoTSentinel: ",
                    html.Span("Network Guardian", className="gradient-text")
                ], className="mb-0 dashboard-title"),
                html.P("Zeek-Powered Analysis on Raspberry Pi 5 - Educational Transparency", className="subtitle mb-0")
            ])
        ], width=7),
        dbc.Col([
            html.Div([
                dbc.ButtonGroup([
                    dbc.Button([html.I(className="fa fa-bell"),
                               dbc.Badge(id="notification-badge", color="danger", className="ms-1", pill=True)],
                              id="notification-bell-button", color="secondary", outline=True, size="sm", className="cyber-button"),
                    dbc.Button([html.I(className="fa fa-robot")], id="open-chat-button",
                              color="secondary", outline=True, size="sm", className="cyber-button ms-1"),
                    dbc.Button([html.I(className="fa fa-pause me-1"), "Pause"],
                              id="pause-button", color="warning", outline=True, size="sm", className="cyber-button ms-1")
                ], size="sm")
            ], className="float-end")
        ], width=5, className="text-end")
    ], className="header-row mb-2 align-items-center"),

    # Status Bar
    dbc.Row([
        dbc.Col([
            html.Div([
                html.I(className="fa fa-microchip me-2 status-icon"),
                html.Span("Pi 5 CPU: ", className="metric-label"),
                html.Span("35%", id="cpu-usage", className="metric-value cyber-glow")
            ], className="status-metric-card")
        ], width=2),
        dbc.Col([
            html.Div([
                html.I(className="fa fa-memory me-2 status-icon"),
                html.Span("RAM: ", className="metric-label"),
                html.Span("2.5GB/8GB", id="ram-usage", className="metric-value cyber-glow")
            ], className="status-metric-card")
        ], width=2),
        dbc.Col([
            html.Div([
                html.I(className="fa fa-wifi me-2 status-icon"),
                html.Span("Network Health: ", className="metric-label"),
                html.Span("STABLE", id="network-health", className="metric-value text-success")
            ], className="status-metric-card")
        ], width=3),
        dbc.Col([
            dbc.RadioItems(
                id="theme-selector",
                options=[
                    {"label": "💡", "value": "light"},
                    {"label": "🌙", "value": "dark"},
                    {"label": "⚡", "value": "cyberpunk"},
                ],
                value="cyberpunk",
                inline=True,
                className="theme-selector-compact"
            )
        ], width=3, className="text-center"),
        dbc.Col([
            dbc.Switch(id="voice-alert-toggle", label="🔊 Voice", value=False, className="compact-switch")
        ], width=2, className="text-end")
    ], className="status-bar mb-3"),

    # Three Panel Layout
    dbc.Row([
        # LEFT: Devices
        dbc.Col([
            dbc.Card([
                dbc.CardHeader([
                    html.I(className="fa fa-network-wired me-2"),
                    "Connected Devices",
                    html.Div([
                        html.Span(id='device-count', className="badge-count me-2"),
                        html.Small("devices", className="text-muted")
                    ], className="float-end")
                ], className="cyber-card-header"),
                dbc.CardBody([
                    html.Div(id='devices-status-compact', className="device-grid-compact"),
                    html.Hr(className="my-3 cyber-hr"),
                    html.H6([html.I(className="fa fa-list me-2"), "Active Devices"], className="section-title"),
                    html.Div(id='active-devices-list', style={'height': '250px', 'overflowY': 'auto'}, className="custom-scrollbar")
                ], className="p-3")
            ], className="cyber-card h-100")
        ], width=4, className="left-panel"),

        # CENTER: Network Graph
        dbc.Col([
            dbc.Card([
                dbc.CardHeader([
                    html.I(className="fa fa-chart-area me-2"),
                    "Real-Time Network Traffic",
                    html.Span("(Zeek Analysis)", className="text-muted ms-2"),
                    dbc.Switch(id="graph-view-toggle", label="3D", value=False, className="float-end compact-switch")
                ], className="cyber-card-header"),
                dbc.CardBody([
                    html.Div(id='2d-graph-container', children=[
                        cyto.Cytoscape(
                            id='network-graph',
                            layout={'name': 'cose', 'animate': True},
                            style={'width': '100%', 'height': '400px'},
                            stylesheet=[
                                {'selector': 'node', 'style': {
                                    'content': 'data(label)', 'text-valign': 'center', 'text-halign': 'center',
                                    'background-color': 'data(color)', 'border-width': 2, 'border-color': 'data(borderColor)',
                                    'font-size': '10px', 'color': '#fff', 'text-outline-color': '#000', 'text-outline-width': 1
                                }},
                                {'selector': 'node[type="router"]', 'style': {'shape': 'diamond', 'width': 60, 'height': 60}},
                                {'selector': 'node[type="device"]', 'style': {'width': 40, 'height': 40}},
                                {'selector': 'edge', 'style': {
                                    'width': 2, 'line-color': '#666', 'target-arrow-shape': 'triangle',
                                    'target-arrow-color': '#666', 'curve-style': 'bezier'
                                }},
                                {'selector': '.animated-edge', 'style': {'line-color': '#00ffcc', 'width': 3}}
                            ],
                            # Make graph clickable
                            tapNodeData={'id': None}
                        )
                    ]),
                    html.Div(id='3d-graph-container', children=[
                        dcc.Graph(id='network-graph-3d', style={'height': '400px'})
                    ], style={'display': 'none'}),
                    dbc.Row([
                        dbc.Col([
                            html.Div([
                                html.Div([html.I(className="fa fa-arrow-up me-2 text-info"),
                                         html.Span(id='total-outbound', children="0 MB")], className="traffic-metric"),
                                html.Small("Outbound", className="text-muted")
                            ], className="text-center")
                        ], width=4),
                        dbc.Col([
                            html.Div([
                                html.Div([html.I(className="fa fa-arrow-down me-2 text-success"),
                                         html.Span(id='total-inbound', children="0 MB")], className="traffic-metric"),
                                html.Small("Inbound", className="text-muted")
                            ], className="text-center")
                        ], width=4),
                        dbc.Col([
                            html.Div([
                                html.Div([html.I(className="fa fa-exchange-alt me-2 text-warning"),
                                         html.Span(id='connection-count', children="0")], className="traffic-metric"),
                                html.Small("Connections/Hour", className="text-muted")
                            ], className="text-center")
                        ], width=4)
                    ], className="mt-3 traffic-stats-row")
                ], className="p-3")
            ], className="cyber-card mb-3"),
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("Protocol Distribution", className="cyber-card-header-sm"),
                        dbc.CardBody(dcc.Graph(id='protocol-pie', style={'height': '200px'}, config={'displayModeBar': False}), className="p-2")
                    ], className="cyber-card")
                ], width=6),
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader("Traffic Timeline (24h)", className="cyber-card-header-sm"),
                        dbc.CardBody(dcc.Graph(id='traffic-timeline', style={'height': '200px'}, config={'displayModeBar': False}), className="p-2")
                    ], className="cyber-card")
                ], width=6)
            ])
        ], width=5, className="center-panel"),

        # RIGHT: Alerts
        dbc.Col([
            dbc.Card([
                dbc.CardHeader([
                    html.I(className="fa fa-exclamation-triangle me-2"),
                    "Alerts & Insights",
                    html.Span("(Educational Mode)", className="text-muted ms-2"),
                    html.Span([dbc.Badge(id='alert-count', color="danger", pill=True, className="ms-2")], className="float-end")
                ], className="cyber-card-header"),
                dbc.CardBody([
                    dbc.ButtonGroup([
                        dbc.Button("All", id="filter-all", color="primary", size="sm", className="pill-btn active"),
                        dbc.Button([html.I(className="fa fa-skull-crossbones")],
                                  id="filter-critical", color="danger", size="sm", outline=True, className="pill-btn"),
                        dbc.Button([html.I(className="fa fa-exclamation-triangle")],
                                  id="filter-high", color="warning", size="sm", outline=True, className="pill-btn"),
                        dbc.Button([html.I(className="fa fa-exclamation-circle")],
                                  id="filter-medium", color="info", size="sm", outline=True, className="pill-btn"),
                        dbc.Button([html.I(className="fa fa-info-circle")],
                                  id="filter-low", color="secondary", size="sm", outline=True, className="pill-btn")
                    ], size="sm", className="mb-3 w-100"),
                    html.Div(id='alerts-container-compact', style={'height': '640px', 'overflowY': 'auto'}, className="custom-scrollbar")
                ], className="p-3")
            ], className="cyber-card h-100")
        ], width=3, className="right-panel")
    ], className="main-content-row"),

    # Expandable Sections
    dbc.Row([
        dbc.Col([
            dbc.Accordion([
                dbc.AccordionItem([
                    dbc.Row([
                        dbc.Col([dbc.Card([
                            dbc.CardHeader("Alert Timeline (7 Days)"),
                            dbc.CardBody(dcc.Graph(id='alert-timeline', style={'height': '300px'}))
                        ], className="cyber-card")], width=6),
                        dbc.Col([dbc.Card([
                            dbc.CardHeader("Anomaly Score Distribution"),
                            dbc.CardBody(dcc.Graph(id='anomaly-distribution', style={'height': '300px'}))
                        ], className="cyber-card")], width=6)
                    ]),
                    dbc.Row([
                        dbc.Col([dbc.Card([
                            dbc.CardHeader("Top Devices by Bandwidth"),
                            dbc.CardBody(dcc.Graph(id='bandwidth-chart', style={'height': '300px'}))
                        ], className="cyber-card")], width=6),
                        dbc.Col([dbc.Card([
                            dbc.CardHeader("Device Activity Heatmap"),
                            dbc.CardBody(dcc.Graph(id='device-heatmap', style={'height': '300px'}))
                        ], className="cyber-card")], width=6)
                    ], className="mt-3")
                ], title="📊 Analytics & Deep Insights", class_name="cyber-accordion-item"),
                dbc.AccordionItem([
                    dbc.Row([
                        dbc.Col([dbc.Card([
                            dbc.CardHeader("System Status"),
                            dbc.CardBody(html.Div(id='system-info'))
                        ], className="cyber-card")], width=6),
                        dbc.Col([dbc.Card([
                            dbc.CardHeader("Model Information"),
                            dbc.CardBody([html.Div(id='model-info'), html.Hr(), html.Div(id='model-comparison')])
                        ], className="cyber-card")], width=6)
                    ])
                ], title="⚙️ System & ML Models", class_name="cyber-accordion-item"),
                dbc.AccordionItem([
                    dbc.Row([
                        dbc.Col([dbc.Card([
                            dbc.CardHeader([
                                html.Div([
                                    html.Span("📧 Email Notifications"),
                                    dbc.Badge("", id="email-status-badge", className="ms-2")
                                ], className="d-flex align-items-center justify-content-between")
                            ]),
                            dbc.CardBody([
                                # Enable/Disable Toggle
                                dbc.Row([
                                    dbc.Col([
                                        dbc.Switch(
                                            id='email-enabled-switch',
                                            label="Enable Email Notifications",
                                            value=False
                                        )
                                    ])
                                ], className="mb-3"),

                                html.Hr(),

                                # SMTP Settings
                                html.H6("SMTP Server Settings", className="text-muted mb-3"),
                                dbc.Row([
                                    dbc.Col([
                                        dbc.Label("SMTP Host", className="small"),
                                        dbc.Input(id='email-smtp-host', type='text', placeholder='smtp.gmail.com', className="cyber-input")
                                    ], width=8),
                                    dbc.Col([
                                        dbc.Label("Port", className="small"),
                                        dbc.Input(id='email-smtp-port', type='number', placeholder='587', className="cyber-input")
                                    ], width=4)
                                ], className="mb-3"),

                                dbc.Row([
                                    dbc.Col([
                                        dbc.Label("SMTP Username", className="small"),
                                        dbc.Input(id='email-smtp-user', type='text', placeholder='your-email@gmail.com', className="cyber-input")
                                    ], width=6),
                                    dbc.Col([
                                        dbc.Label("SMTP Password", className="small"),
                                        dbc.Input(id='email-smtp-password', type='password', placeholder='••••••••', className="cyber-input")
                                    ], width=6)
                                ], className="mb-3"),

                                html.Hr(),

                                # Email Addresses
                                html.H6("Email Addresses", className="text-muted mb-3"),
                                dbc.Row([
                                    dbc.Col([
                                        dbc.Label("Sender Email", className="small"),
                                        dbc.Input(id='email-sender', type='email', placeholder='iotsentinel@gmail.com', className="cyber-input")
                                    ], width=6),
                                    dbc.Col([
                                        dbc.Label("Recipient Email", className="small"),
                                        dbc.Input(id='email-recipient', type='email', placeholder='your-email@gmail.com', className="cyber-input")
                                    ], width=6)
                                ], className="mb-3"),

                                html.Hr(),

                                # Action Buttons
                                dbc.Row([
                                    dbc.Col([
                                        dbc.Button([html.I(className="fa fa-save me-2"), "Save Settings"],
                                                  id="save-email-settings-btn", color="primary", className="cyber-button w-100")
                                    ], width=6),
                                    dbc.Col([
                                        dbc.Button([html.I(className="fa fa-envelope me-2"), "Send Test Email"],
                                                  id="test-email-btn", color="success", outline=True, className="cyber-button w-100")
                                    ], width=6)
                                ]),

                                # Status Messages
                                html.Div(id="email-settings-status", className="mt-3")
                            ])
                        ], className="cyber-card")], width=12)
                    ]),
                    dbc.Row([
                        dbc.Col([dbc.Card([
                            dbc.CardHeader("🔥 Firewall Control"),
                            dbc.CardBody([
                                dbc.Switch(id='lockdown-switch', label="Enable Lockdown Mode", value=False),
                                html.P("When enabled, only trusted devices can access the network.", className="small text-muted mt-2"),
                                html.Div(id='lockdown-status', className="mt-2")
                            ])
                        ], className="cyber-card")], width=12)
                    ], className="mt-3"),
                    dbc.Row([
                        dbc.Col([
                            dbc.Button([html.I(className="fa fa-question-circle me-2"), "Restart Tour"],
                                       id="restart-tour-button", color="info", outline=True, className="cyber-button mt-3")
                        ])
                    ])
                ], title="⚙️ Settings & Controls", class_name="cyber-accordion-item")
            ], start_collapsed=True, className="mt-3 cyber-accordion")
        ])
    ]),

    # Hidden Components & Modals
    WebSocket(id="ws", url="ws://127.0.0.1:8050/ws"),
    dcc.Store(id='alert-filter', data='all'),
    dcc.Store(id='selected-device-ip', data=None),
    dcc.Store(id='theme-store', storage_type='local', data={'theme': 'cyberpunk'}),
    dcc.Store(id='voice-alert-store', storage_type='local'),
    dcc.Store(id='announced-alerts-store', storage_type='session', data={}),
    dcc.Store(id='onboarding-store', storage_type='local'),
    dcc.Store(id='onboarding-step-store', data=0),
    dcc.Store(id='keyboard-shortcut-store', data=None),
    dcc.Location(id='url', refresh=False),

    # Onboarding Modal
    dbc.Modal([
        dbc.ModalHeader(dbc.ModalTitle(id='onboarding-title')),
        dbc.ModalBody(id='onboarding-body'),
        dbc.ModalFooter([
            dbc.Button("Previous", id="onboarding-prev", color="secondary", className="me-auto cyber-button", disabled=True),
            dbc.Button("Next", id="onboarding-next", color="primary", className="cyber-button")
        ]),
    ], id="onboarding-modal", is_open=False, backdrop="static", size="lg"),

    # Device Details Modal
    dbc.Modal([
        dbc.ModalHeader(dbc.ModalTitle(id="device-details-title")),
        dbc.ModalBody(id="device-details-body"),
        dbc.ModalFooter([
            dbc.Button("Close", id="device-details-close-btn", color="secondary", className="cyber-button")
        ])
    ], id="device-details-modal", is_open=False, size="xl"),

    # Alert Details Modal
    dbc.Modal([
        dbc.ModalHeader(dbc.ModalTitle(id="alert-details-title")),
        dbc.ModalBody(id="alert-details-body"),
        dbc.ModalFooter([
            dbc.Button("Mark as Reviewed", id="alert-acknowledge-btn", color="success", className="cyber-button"),
            dbc.Button("Close", id="alert-close-btn", color="secondary", className="cyber-button")
        ])
    ], id="alert-details-modal", is_open=False, size="xl"),

    # Lockdown Confirmation Modal
    dbc.Modal([
        dbc.ModalHeader(dbc.ModalTitle("⚠️ Confirm Lockdown Mode")),
        dbc.ModalBody([
            html.Div([
                html.I(className="fa fa-exclamation-triangle fa-3x text-warning mb-3"),
                html.H5("Are you sure you want to enable Lockdown Mode?"),
                html.P("This will block all untrusted devices from accessing your network."),
                html.Hr(),
                html.P([
                    html.Strong("Trusted devices: "),
                    html.Span(id='lockdown-trusted-count', children="0")
                ]),
                html.P([
                    html.Strong("Will be blocked: "),
                    html.Span(id='lockdown-blocked-count', children="0", className="text-danger")
                ])
            ], className="text-center")
        ]),
        dbc.ModalFooter([
            dbc.Button("Cancel", id="lockdown-cancel", color="secondary", className="cyber-button"),
            dbc.Button("Enable Lockdown", id="lockdown-confirm", color="danger", className="cyber-button"),
        ]),
    ], id="lockdown-modal", is_open=False),

    html.Div(id="toast-container", style={"position": "fixed", "top": 66, "right": 10, "width": 350, "zIndex": 9999}),

    dbc.Offcanvas([
        html.H5("Recent Alerts"),
        html.Hr(),
        html.Div(id="notification-drawer-body")
    ], id="notification-drawer", title="Notifications", is_open=False, placement="end", backdrop=False, scrollable=True),

    dbc.Modal([
        dbc.ModalHeader(dbc.ModalTitle("🤖 AI Assistant")),
        dbc.ModalBody(html.Div(id='chat-history', style={'height': '400px', 'overflowY': 'auto'})),
        dbc.ModalFooter(
            dbc.InputGroup([
                dbc.Input(id='chat-input', placeholder="Ask about your network...", className="cyber-input"),
                dbc.Button("Send", id='chat-send-button', color="primary", className="cyber-button"),
            ])
        ),
    ], id="chat-modal", is_open=False, size="lg"),

    dcc.Store(id='chat-history-store', storage_type='session', data={'history': []})

], fluid=True, className="dashboard-container p-3")

# ============================================================================
# CALLBACKS - HEADER & NOTIFICATIONS
# ============================================================================

@app.callback(
    [Output('device-count', 'children'),
     Output('alert-count', 'children'),
     Output('connection-count', 'children')],
    Input('ws', 'message')
)
def update_header_stats(ws_message):
    if ws_message is None:
        # Show loading placeholders
        return "—", "—", "—"
    return str(ws_message.get('device_count', 0)), str(ws_message.get('alert_count', 0)), str(ws_message.get('connection_count', 0))

@app.callback(
    [Output('notification-badge', 'children'), Output('notification-drawer-body', 'children')],
    Input('ws', 'message')
)
def update_notifications(ws_message):
    if ws_message is None:
        # Show empty state during initial load
        return "", [dbc.Alert("Loading...", color="info")]
    alert_count = ws_message.get('alert_count', 0)
    recent_alerts = ws_message.get('recent_alerts', [])
    badge_count = "" if alert_count == 0 else str(alert_count)

    if not recent_alerts:
        drawer_content = [dbc.Alert("No new alerts.", color="info")]
    else:
        drawer_content = []
        for alert in recent_alerts[:10]:
            device_name = alert.get('device_name') or alert.get('device_ip')
            severity = alert.get('severity', 'medium')
            config = SEVERITY_CONFIG.get(severity, SEVERITY_CONFIG['medium'])
            drawer_content.append(
                dbc.Card(dbc.CardBody([
                    html.Strong(device_name),
                    html.P(alert.get('explanation'), className="small mb-0")
                ]), color=config['color'], inverse=True, className="mb-2")
            )
    return badge_count, drawer_content

@app.callback(
    Output("notification-drawer", "is_open"),
    Input("notification-bell-button", "n_clicks"),
    [State("notification-drawer", "is_open")],
    prevent_initial_call=True,
)
def toggle_notification_drawer(n_clicks, is_open):
    if n_clicks:
        return not is_open
    return is_open

# ============================================================================
# CALLBACKS - NETWORK GRAPH
# ============================================================================

@app.callback(
    Output('network-graph', 'elements'),
    Input('ws', 'message')
)
def update_network_graph(ws_message):
    if ws_message is None:
        # Return empty elements during initial load
        return []
    elements = ws_message.get('network_graph_elements', [])
    if not elements:
        return []
    return elements

@app.callback(
    [Output('2d-graph-container', 'style'), Output('3d-graph-container', 'style')],
    Input('graph-view-toggle', 'value')
)
def toggle_graph_view(is_3d_view):
    if is_3d_view:
        return {'display': 'none'}, {'display': 'block'}
    return {'display': 'block'}, {'display': 'none'}

@app.callback(
    Output('network-graph-3d', 'figure'),
    Input('ws', 'message')
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
        textfont=dict(size=8, color='#ffffff')
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
        textfont=dict(size=12, color='#ffffff', family='Arial Black')
    )

    # Layout with dark background
    layout = go.Layout(
        title=dict(
            text='3D Network Topology - Force-Directed Layout',
            font=dict(size=16, color='#ffffff')
        ),
        showlegend=False,
        scene=dict(
            xaxis=dict(
                showbackground=True,
                backgroundcolor="rgb(20, 20, 30)",
                gridcolor="rgb(50, 50, 60)",
                showticklabels=False,
                title=''
            ),
            yaxis=dict(
                showbackground=True,
                backgroundcolor="rgb(20, 20, 30)",
                gridcolor="rgb(50, 50, 60)",
                showticklabels=False,
                title=''
            ),
            zaxis=dict(
                showbackground=True,
                backgroundcolor="rgb(20, 20, 30)",
                gridcolor="rgb(50, 50, 60)",
                showticklabels=False,
                title=''
            ),
            camera=dict(
                eye=dict(x=1.5, y=1.5, z=1.5)
            )
        ),
        paper_bgcolor='rgb(10, 10, 20)',
        plot_bgcolor='rgb(10, 10, 20)',
        margin=dict(l=0, r=0, b=0, t=40),
        hovermode='closest'
    )

    return go.Figure(data=edge_traces + [node_trace, router_trace], layout=layout)

@app.callback(
    Output('traffic-timeline', 'figure'),
    Input('ws', 'message')
)
def update_traffic_timeline(ws_message):
    if ws_message is None:
        # Return empty figure during initial load
        return go.Figure()
    traffic_data = ws_message.get('traffic_timeline', [])
    if not traffic_data:
        fig = go.Figure()
        fig.update_layout(title="No traffic data available", xaxis_title="Hour", yaxis_title="Bytes")
        return fig
    df = pd.DataFrame(traffic_data)
    fig = px.area(df, x='hour', y='total_bytes', title="Network Traffic by Hour", color_discrete_sequence=['#007bff'])
    fig.update_layout(xaxis_title="Hour", yaxis_title="Total Bytes", showlegend=False)
    fig.update_traces(fill='tozeroy')
    return fig

@app.callback(
    Output('protocol-pie', 'figure'),
    Input('ws', 'message')
)
def update_protocol_pie(ws_message):
    if ws_message is None:
        raise dash.exceptions.PreventUpdate
    protocol_data = ws_message.get('protocol_distribution', [])
    if not protocol_data:
        fig = go.Figure()
        fig.update_layout(title="No protocol data available")
        return fig
    df = pd.DataFrame(protocol_data)
    fig = px.pie(df, values='count', names='protocol', title='Protocol Distribution', color_discrete_sequence=px.colors.qualitative.Set2)
    fig.update_traces(textposition='inside', textinfo='percent+label')
    return fig

# ============================================================================
# CALLBACKS - DEVICES
# ============================================================================

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

        # Make clickable with device icon
        cards.append(
            html.Div([
                create_status_indicator(status, "0.8rem"),
                create_device_icon(device_type, use_emoji=True, use_fa=False, size="1rem"),
                html.Span(device_name, className="device-name-compact"),
                html.Span(device['device_ip'], className="device-ip-compact ms-auto")
            ], className="device-item-compact clickable-device",
               id={'type': 'device-card', 'ip': device_ip},
               n_clicks=0)
        )
    return html.Div(cards, className="fade-in")

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

        items.append(
            html.Div([
                html.Div([
                    create_status_indicator(status, "0.9rem"),
                    create_device_icon(device_type, use_emoji=True, use_fa=False, size="1.1rem"),
                    html.Strong(device_name, className="me-2"),
                    dbc.Badge(status_text, color=badge_color, pill=True, className="badge-sm"),
                    dbc.Badge([html.I(className="fa fa-ban me-1"), "BLOCKED"],
                             color="danger", pill=True, className="badge-sm ms-1") if is_blocked else html.Span()
                ], className="d-flex align-items-center mb-1"),
                html.Small([html.I(className="fa fa-network-wired me-1"), device['device_ip']], className="text-muted")
            ], className="active-device-item clickable-device" + (" border-danger" if is_blocked else ""),
               id={'type': 'device-list-item', 'ip': device_ip},
               n_clicks=0,
               style={"borderLeft": "4px solid #dc3545" if is_blocked else ""}
        )
        )
    return html.Div(items, className="fade-in")

# Device Details Modal Callback
@app.callback(
    [Output('device-details-modal', 'is_open'),
     Output('device-details-title', 'children'),
     Output('device-details-body', 'children'),
     Output('selected-device-ip', 'data')],
    [Input({'type': 'device-card', 'ip': dash.dependencies.ALL}, 'n_clicks'),
     Input({'type': 'device-list-item', 'ip': dash.dependencies.ALL}, 'n_clicks'),
     Input('network-graph', 'tapNodeData'),
     Input('device-details-close-btn', 'n_clicks')],
    [State('device-details-modal', 'is_open'),
     State('selected-device-ip', 'data')],
    prevent_initial_call=True
)
def toggle_device_details(card_clicks, list_clicks, tap_data, close_click, is_open, current_ip):
    ctx = callback_context
    if not ctx.triggered:
        return False, "", "", None

    trigger_id = ctx.triggered[0]['prop_id']

    # Handle close button
    if 'device-details-close-btn' in trigger_id:
        return False, "", "", None

    # Determine which device was clicked
    device_ip = None

    if 'device-card' in trigger_id or 'device-list-item' in trigger_id:
        try:
            trigger_data = json.loads(trigger_id.split('.')[0])
            device_ip = trigger_data['ip']
        except (json.JSONDecodeError, KeyError):
            return False, "", "", None
    elif 'network-graph' in trigger_id and tap_data:
        # Clicked on graph node
        device_ip = tap_data.get('id')
        if device_ip == 'router':
            return False, "", "", None

    if not device_ip:
        return False, "", "", None

    # Get device details
    device = get_device_details(device_ip)
    if not device:
        return True, "Device Not Found", html.P("Could not load device details."), None

    device_name = device.get('device_name') or device_ip
    device_type = device.get('device_type')

    # Create title with device icon (both emoji and FA for modal)
    title = html.Div([
        create_device_icon(device_type, use_emoji=True, use_fa=True, size="1.5rem"),
        html.Span(f"Device Details: {device_name}", className="ms-2")
    ], className="d-flex align-items-center")

    # Build device details body
    baseline = device.get('baseline', {})
    today_stats = device.get('today_stats', {})

    body = html.Div([
        # Basic Info
        dbc.Row([
            dbc.Col([
                html.H5("Basic Information", className="text-cyber mb-3"),
                html.P([html.Strong("IP Address: "), device_ip]),
                html.P([html.Strong("MAC Address: "), device.get('mac_address', 'Unknown')]),
                html.P([html.Strong("Manufacturer: "), device.get('manufacturer', 'Unknown')]),
                html.P([html.Strong("Device Type: "), device.get('device_type', 'Unknown')]),
                html.P([html.Strong("First Seen: "), device.get('first_seen', 'Unknown')]),
                html.P([html.Strong("Last Seen: "), device.get('last_seen', 'Unknown')]),
            ], width=6),
            dbc.Col([
                html.H5("Security Status", className="text-cyber mb-3"),
                html.Div([
                    html.Span("Current Status: "),
                    create_status_indicator(device.get('status', 'unknown'), "1.2rem"),
                    html.Strong(device.get('status', 'unknown').upper())
                ], className="mb-2"),
                html.P([html.Strong("Total Connections: "), f"{device.get('total_connections', 0):,}"]),
                html.P([html.Strong("Total Alerts: "), device.get('total_alerts', 0)]),
                html.P([html.Strong("Active Alerts: "), device.get('active_alerts', 0)]),
                html.Hr(),
                html.Div([
                    html.Strong("Trust Status: "),
                    dbc.Switch(
                        id={'type': 'device-trust-switch', 'ip': device_ip},
                        label="Trusted Device",
                        value=bool(device.get('is_trusted', False)),
                        className="d-inline-block ms-2"
                    )
                ], className="mb-2"),
                html.Small("Trusted devices have different alert thresholds", className="text-muted"),
                html.Hr(),
                html.Div([
                    html.Strong("Network Access: ", className="mb-2"),
                    html.Div([
                        dbc.Button(
                            [html.I(className="fa fa-ban me-2"), "Block Device"] if not device.get('is_blocked', False) else [html.I(className="fa fa-check-circle me-2"), "Unblock Device"],
                            id={'type': 'device-block-btn', 'ip': device_ip},
                            color="danger" if not device.get('is_blocked', False) else "success",
                            outline=True,
                            size="sm",
                            className="w-100 mt-2"
                        ),
                        html.Div(id={'type': 'block-status', 'ip': device_ip}, className="mt-2")
                    ])
                ], className="mb-2"),
                dbc.Alert(
                    [html.I(className="fa fa-exclamation-triangle me-2"), "This device is currently BLOCKED from network access"],
                    color="danger",
                    className="mt-2"
                ) if device.get('is_blocked', False) else html.Div(),
                html.Small("Blocking requires firewall integration to be enabled", className="text-muted")
            ], width=6)
        ]),

        html.Hr(),

        # Activity Statistics
        html.H5("Activity Statistics", className="text-cyber mb-3"),
        dbc.Row([
            dbc.Col([
                dcc.Graph(
                    figure=create_baseline_comparison_chart(
                        baseline, today_stats, "Data Sent",
                        "avg_bytes_sent", "today_bytes_sent", "Data Sent: Normal vs Today"
                    ) if baseline.get('has_baseline') else go.Figure().update_layout(title="No baseline data yet"),
                    config={'displayModeBar': False}
                )
            ], width=6),
            dbc.Col([
                dcc.Graph(
                    figure=create_baseline_comparison_chart(
                        baseline, today_stats, "Connections",
                        "avg_connections", "today_connections", "Connections: Normal vs Today"
                    ) if baseline.get('has_baseline') else go.Figure().update_layout(title="No baseline data yet"),
                    config={'displayModeBar': False}
                )
            ], width=6)
        ])
    ])

    return True, title, body, device_ip

# Trust Switch Callback
@app.callback(
    Output('toast-container', 'children'),
    Input({'type': 'device-trust-switch', 'ip': dash.dependencies.ALL}, 'value'),
    State({'type': 'device-trust-switch', 'ip': dash.dependencies.ALL}, 'id'),
    prevent_initial_call=True
)
def toggle_device_trust(values, ids):
    ctx = callback_context
    if not ctx.triggered:
        raise dash.exceptions.PreventUpdate

    trigger_id = ctx.triggered[0]['prop_id']

    try:
        id_dict = json.loads(trigger_id.split('.')[0])
        device_ip = id_dict['ip']
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
            header="✅ Success",
            icon="success",
            duration=3000,
        )
    else:
        return dbc.Toast(
            f"Failed to update trust status for {device_ip}.",
            header="❌ Error",
            icon="danger",
            duration=3000,
        )

# Block Device Callback
@app.callback(
    Output({'type': 'block-status', 'ip': dash.dependencies.MATCH}, 'children'),
    Input({'type': 'device-block-btn', 'ip': dash.dependencies.MATCH}, 'n_clicks'),
    State({'type': 'device-block-btn', 'ip': dash.dependencies.MATCH}, 'id'),
    prevent_initial_call=True
)
def toggle_device_block(n_clicks, button_id):
    """Handle device blocking/unblocking via firewall"""
    if n_clicks is None:
        raise dash.exceptions.PreventUpdate

    device_ip = button_id['ip']

    try:
        # Get device details including MAC address and current blocked status
        device = get_device_details(device_ip)
        if not device:
            return dbc.Alert("Device not found", color="danger", dismissable=True)

        mac_address = device.get('mac_address')
        if not mac_address:
            return dbc.Alert("Cannot block device: MAC address unknown", color="warning", dismissable=True)

        current_blocked = bool(device.get('is_blocked', False))
        new_blocked_status = not current_blocked

        # Update database first
        db = DatabaseManager()
        db.set_device_blocked(device_ip, new_blocked_status)

        # Call firewall manager to apply/remove block
        import subprocess
        from pathlib import Path

        project_root = Path(__file__).parent.parent
        firewall_script = project_root / 'scripts' / 'firewall_manager.py'

        if new_blocked_status:
            # Block the device
            command = [sys.executable, str(firewall_script), '--block', mac_address]
            action_text = "blocked"
            alert_color = "danger"
        else:
            # Unblock the device
            command = [sys.executable, str(firewall_script), '--unblock', mac_address]
            action_text = "unblocked"
            alert_color = "success"

        try:
            result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=10)
            logger.info(f"Device {device_ip} ({mac_address}) {action_text}: {result.stdout}")

            return dbc.Alert([
                html.I(className=f"fa fa-check-circle me-2"),
                f"Device successfully {action_text}! Refresh page to see updated status."
            ], color=alert_color, dismissable=True)

        except subprocess.CalledProcessError as e:
            error_msg = e.stderr if e.stderr else str(e)
            logger.error(f"Failed to {action_text} device {device_ip}: {error_msg}")

            # Check if firewall is disabled
            if not config.get('firewall', 'enabled', default=False):
                return dbc.Alert([
                    html.I(className="fa fa-exclamation-triangle me-2"),
                    "Firewall integration is disabled in config. Enable it to block devices."
                ], color="warning", dismissable=True)

            return dbc.Alert([
                html.I(className="fa fa-times-circle me-2"),
                f"Failed to {action_text} device: {error_msg}"
            ], color="danger", dismissable=True)

        except subprocess.TimeoutExpired:
            logger.error(f"Timeout while trying to {action_text} device {device_ip}")
            return dbc.Alert([
                html.I(className="fa fa-clock me-2"),
                f"Operation timed out. Check firewall configuration."
            ], color="warning", dismissable=True)

    except Exception as e:
        logger.error(f"Error toggling block for device {device_ip}: {e}")
        return dbc.Alert([
            html.I(className="fa fa-times-circle me-2"),
            f"Error: {str(e)}"
        ], color="danger", dismissable=True)

# ============================================================================
# CALLBACKS - ALERTS
# ============================================================================

@app.callback(
    Output('alerts-container-compact', 'children'),
    [Input('ws', 'message'), Input('alert-filter', 'data')]
)
def update_alerts_compact(ws_message, filter_severity):
    if ws_message is None:
        # Show skeleton loader during initial load
        return create_alert_skeleton(count=5)
    recent_alerts_raw = ws_message.get('recent_alerts', [])
    df = pd.DataFrame(recent_alerts_raw)

    if filter_severity != 'all' and not df.empty:
        df = df[df['severity'] == filter_severity]

    if len(df) == 0:
        return dbc.Alert([
            html.Div([
                html.I(className="fa fa-check-circle me-2", style={'fontSize': '1.5rem'}),
                html.Div([
                    html.H5("All Clear!", className="mb-1"),
                    html.P("No security alerts detected in the last 24 hours.", className="mb-0 small text-muted")
                ])
            ], className="d-flex align-items-center")
        ], color="success", className="compact-alert")

    alert_items = []
    for _, alert in df.iterrows():
        device_name = alert['device_name'] or alert['device_ip']
        severity = alert['severity']
        config = SEVERITY_CONFIG.get(severity, SEVERITY_CONFIG['medium'])

        try:
            dt = datetime.fromisoformat(alert['timestamp'])
            time_str = dt.strftime('%H:%M')
        except:
            time_str = "N/A"

        mitre_info = MITRE_ATTACK_MAPPING.get(alert['explanation'], {})
        tactic = mitre_info.get('tactic', 'Unknown').split('(')[0].strip()

        alert_items.append(
            dbc.Card([
                dbc.CardBody([
                    html.Div([
                        html.Div([
                            dbc.Badge([html.I(className=f"fa {config['icon']} me-1"), severity.upper()],
                                     color=config['color'], className="me-2"),
                            dbc.Badge(tactic, color="dark", outline=True, className="badge-sm")
                        ]),
                        html.Small(time_str, className="text-cyber")
                    ], className="d-flex justify-content-between mb-2"),
                    html.Strong(device_name, className="d-block mb-1"),
                    html.P(alert['explanation'][:80] + "..." if len(alert['explanation']) > 80 else alert['explanation'],
                           className="alert-text-compact mb-2"),
                    dbc.Button([html.I(className="fa fa-info-circle me-1"), "Details"],
                              id={'type': 'alert-detail-btn', 'index': int(alert['id'])},
                              size="sm", color=config['color'], outline=True, className="w-100 cyber-button")
                ], className="p-2")
            ], className=f"alert-card-compact mb-2 border-{config['color']}")
        )
    return html.Div(alert_items, className="fade-in")

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
    ctx = callback_context
    if not ctx.triggered:
        return False, "", ""
    trigger_id = ctx.triggered[0]['prop_id']
    if 'alert-close-btn' in trigger_id:
        return False, "", ""
    if 'alert-detail-btn' in trigger_id:
        try:
            trigger_data = json.loads(trigger_id.split('.')[0])
            alert_id = trigger_data['index']
        except (json.JSONDecodeError, KeyError):
            return False, "", ""
        alert = get_alert_with_context(alert_id)
        if not alert:
            return True, "Alert Not Found", html.P("Could not load alert details.")
        device_name = alert.get('device_name') or alert.get('device_ip', 'Unknown')
        title = f"🔍 Alert Details: {device_name}"
        body = create_educational_explanation(alert)
        return True, title, body
    return False, "", ""

@app.callback(
    Output('alert-filter', 'data'),
    [Input('filter-all', 'n_clicks'), Input('filter-critical', 'n_clicks'),
     Input('filter-high', 'n_clicks'), Input('filter-medium', 'n_clicks'), Input('filter-low', 'n_clicks')]
)
def update_alert_filter(*_):
    ctx = callback_context
    if not ctx.triggered:
        return 'all'
    button_id = ctx.triggered[0]['prop_id'].split('.')[0]
    return button_id.split('-')[1]

# ============================================================================
# CALLBACKS - ONBOARDING
# ============================================================================

@app.callback(
    Output('onboarding-modal', 'is_open'),
    [Input('url', 'pathname'),
     Input('restart-tour-button', 'n_clicks')],
    [State('onboarding-store', 'data')],
    prevent_initial_call='initial_duplicate'
)
def launch_onboarding_modal(_, restart_clicks, onboarding_data):
    """Launch onboarding on first visit or when restart button is clicked"""
    ctx = callback_context
    if not ctx.triggered:
        # Initial load - check if first visit
        if onboarding_data is None:
            return True
        return False

    trigger_id = ctx.triggered[0]['prop_id']

    if 'restart-tour-button' in trigger_id:
        return True

    # First visit
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
    """Update the content of the onboarding modal"""
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
    [State('onboarding-step-store', 'data')],
    prevent_initial_call=True
)
def update_onboarding_step(next_clicks, prev_clicks, step):
    """Handle navigation in the onboarding modal"""
    ctx = callback_context
    if not ctx.triggered:
        return 0, dash.no_update, dash.no_update

    button_id = ctx.triggered[0]['prop_id'].split('.')[0]

    if button_id == 'onboarding-next':
        if step == len(ONBOARDING_STEPS) - 1:
            # Finished tour
            return 0, False, {'completed': True, 'timestamp': datetime.now().isoformat()}
        return step + 1, dash.no_update, dash.no_update
    elif button_id == 'onboarding-prev':
        return max(0, step - 1), dash.no_update, dash.no_update

    return 0, dash.no_update, dash.no_update

# ============================================================================
# CALLBACKS - LOCKDOWN MODE
# ============================================================================

@app.callback(
    [Output('lockdown-modal', 'is_open'),
     Output('lockdown-trusted-count', 'children'),
     Output('lockdown-blocked-count', 'children')],
    [Input('lockdown-switch', 'value'),
     Input('lockdown-cancel', 'n_clicks'),
     Input('lockdown-confirm', 'n_clicks')],
    [State('lockdown-modal', 'is_open'),
     State('ws', 'message')],
    prevent_initial_call=True
)
def toggle_lockdown_modal(switch_value, cancel_clicks, confirm_clicks, is_open, ws_message):
    """Show confirmation modal when lockdown is toggled"""
    ctx = callback_context
    if not ctx.triggered:
        return False, "0", "0"

    trigger_id = ctx.triggered[0]['prop_id'].split('.')[0]

    if trigger_id == 'lockdown-switch' and switch_value:
        # User is trying to enable lockdown - show confirmation
        devices = ws_message.get('all_devices_with_status', []) if ws_message else []
        trusted_count = sum(1 for d in devices if d.get('is_trusted', False))
        blocked_count = len(devices) - trusted_count
        return True, str(trusted_count), str(blocked_count)

    if trigger_id == 'lockdown-cancel':
        # User cancelled - revert switch (handled by separate callback)
        return False, "0", "0"

    if trigger_id == 'lockdown-confirm':
        # User confirmed - actually enable lockdown
        return False, "0", "0"

    return False, "0", "0"

@app.callback(
    [Output('lockdown-switch', 'value'),
     Output('lockdown-status', 'children')],
    [Input('lockdown-cancel', 'n_clicks'),
     Input('lockdown-confirm', 'n_clicks'),
     Input('lockdown-switch', 'value')],
    prevent_initial_call=True
)
def handle_lockdown_confirmation(cancel_clicks, confirm_clicks, current_value):
    """Handle the actual lockdown mode toggle by calling the firewall script."""
    ctx = callback_context
    if not ctx.triggered:
        raise dash.exceptions.PreventUpdate

    trigger_id = ctx.triggered[0]['prop_id'].split('.')[0]
    firewall_script = project_root / 'scripts' / 'firewall_manager.py'

    # Case 1: User cancels the confirmation modal
    if trigger_id == 'lockdown-cancel':
        logger.info("Lockdown mode cancelled by user.")
        return False, dbc.Alert("Lockdown mode remains disabled.", color="secondary", className="mt-2")

    # Case 2: User confirms enabling lockdown mode
    if trigger_id == 'lockdown-confirm':
        if not config.get('firewall', 'enabled', default=False):
            logger.warning("Firewall management is disabled in config. Cannot enable lockdown.")
            return False, dbc.Alert("Firewall management is disabled in configuration.", color="danger", className="mt-2")

        logger.info("Lockdown mode ENABLED - applying firewall rules.")

        trusted_devices = db_manager.get_trusted_devices()
        trusted_macs = [d['mac_address'] for d in trusted_devices if d.get('mac_address')]

        if not trusted_macs:
            logger.warning("No trusted MAC addresses found. Lockdown will block all devices.")

        command = [sys.executable, str(firewall_script), '--apply'] + trusted_macs

        try:
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            logger.info(f"Firewall script output: {result.stdout}")
            status_alert = dbc.Alert([
                html.I(className="fa fa-shield-alt me-2"),
                html.Strong("Lockdown Mode Active"),
                html.P(f"Firewall rules applied. {len(trusted_macs)} device(s) allowed.", className="mb-0 small")
            ], color="danger", className="mt-2")
            return True, status_alert
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            logger.error(f"Failed to apply firewall rules: {e}")
            error_message = f"Error: {e.stderr}" if hasattr(e, 'stderr') else str(e)
            status_alert = dbc.Alert(f"Failed to apply firewall rules. {error_message}", color="danger", className="mt-2")
            return False, status_alert

    # Case 3: User toggles the switch to OFF
    if trigger_id == 'lockdown-switch' and not current_value:
        logger.info("Lockdown mode DISABLED - clearing firewall rules.")
        command = [sys.executable, str(firewall_script), '--clear']

        try:
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            logger.info(f"Firewall clear script output: {result.stdout}")
            status_alert = dbc.Alert("Lockdown mode disabled and firewall rules cleared.", color="success", className="mt-2")
            return False, status_alert
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            logger.error(f"Failed to clear firewall rules: {e}")
            error_message = f"Error: {e.stderr}" if hasattr(e, 'stderr') else str(e)
            status_alert = dbc.Alert(f"Failed to clear firewall rules. {error_message}", color="warning", className="mt-2")
            # Keep switch on to indicate rules might still be active
            return True, status_alert

    raise dash.exceptions.PreventUpdate

# ============================================================================
# CALLBACKS - EMAIL SETTINGS
# ============================================================================

@app.callback(
    [Output('email-enabled-switch', 'value'),
     Output('email-smtp-host', 'value'),
     Output('email-smtp-port', 'value'),
     Output('email-smtp-user', 'value'),
     Output('email-sender', 'value'),
     Output('email-recipient', 'value'),
     Output('email-status-badge', 'children'),
     Output('email-status-badge', 'color')],
    Input('url', 'pathname')
)
def load_email_settings(pathname):
    """Load email settings from config file on page load"""
    try:
        import json
        from pathlib import Path

        config_path = Path(__file__).parent.parent / 'config' / 'default_config.json'
        with open(config_path, 'r') as f:
            config = json.load(f)

        email_config = config.get('email', {})
        enabled = email_config.get('enabled', False)
        smtp_host = email_config.get('smtp_host', 'smtp.gmail.com')
        smtp_port = email_config.get('smtp_port', 587)
        smtp_user = email_config.get('smtp_user', '')
        sender_email = email_config.get('sender_email', '')
        recipient_email = email_config.get('recipient_email', '')

        # Determine status
        if enabled and all([smtp_host, smtp_user, sender_email, recipient_email]):
            badge_text = "ENABLED"
            badge_color = "success"
        elif enabled:
            badge_text = "INCOMPLETE"
            badge_color = "warning"
        else:
            badge_text = "DISABLED"
            badge_color = "secondary"

        return enabled, smtp_host, smtp_port, smtp_user, sender_email, recipient_email, badge_text, badge_color

    except Exception as e:
        logger.error(f"Error loading email settings: {e}")
        return False, 'smtp.gmail.com', 587, '', '', '', "ERROR", "danger"


@app.callback(
    [Output('email-settings-status', 'children'),
     Output('email-status-badge', 'children', allow_duplicate=True),
     Output('email-status-badge', 'color', allow_duplicate=True)],
    Input('save-email-settings-btn', 'n_clicks'),
    [State('email-enabled-switch', 'value'),
     State('email-smtp-host', 'value'),
     State('email-smtp-port', 'value'),
     State('email-smtp-user', 'value'),
     State('email-smtp-password', 'value'),
     State('email-sender', 'value'),
     State('email-recipient', 'value')],
    prevent_initial_call=True
)
def save_email_settings(n_clicks, enabled, smtp_host, smtp_port, smtp_user, smtp_password, sender_email, recipient_email):
    """Save email settings to config file"""
    if n_clicks is None:
        raise dash.exceptions.PreventUpdate

    try:
        import json
        from pathlib import Path

        config_path = Path(__file__).parent.parent / 'config' / 'default_config.json'

        # Load current config
        with open(config_path, 'r') as f:
            config = json.load(f)

        # Update email settings
        if 'email' not in config:
            config['email'] = {}

        config['email']['enabled'] = enabled
        config['email']['smtp_host'] = smtp_host or 'smtp.gmail.com'
        config['email']['smtp_port'] = int(smtp_port) if smtp_port else 587
        config['email']['smtp_user'] = smtp_user or ''
        # Only update password if it's provided (not just placeholder dots)
        if smtp_password and not all(c == '•' for c in smtp_password):
            config['email']['smtp_password'] = smtp_password
        config['email']['sender_email'] = sender_email or ''
        config['email']['recipient_email'] = recipient_email or ''

        # Save config
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=4)

        # Determine status
        if enabled and all([smtp_host, smtp_user, sender_email, recipient_email]):
            badge_text = "ENABLED"
            badge_color = "success"
            status_msg = dbc.Alert([
                html.I(className="fa fa-check-circle me-2"),
                "Email settings saved successfully!"
            ], color="success", dismissable=True)
        elif enabled:
            badge_text = "INCOMPLETE"
            badge_color = "warning"
            status_msg = dbc.Alert([
                html.I(className="fa fa-exclamation-triangle me-2"),
                "Settings saved, but some required fields are missing."
            ], color="warning", dismissable=True)
        else:
            badge_text = "DISABLED"
            badge_color = "secondary"
            status_msg = dbc.Alert([
                html.I(className="fa fa-info-circle me-2"),
                "Email notifications disabled."
            ], color="info", dismissable=True)

        logger.info(f"Email settings saved: enabled={enabled}")
        return status_msg, badge_text, badge_color

    except Exception as e:
        logger.error(f"Error saving email settings: {e}")
        return dbc.Alert([
            html.I(className="fa fa-times-circle me-2"),
            f"Error saving settings: {str(e)}"
        ], color="danger", dismissable=True), "ERROR", "danger"


@app.callback(
    Output('email-settings-status', 'children', allow_duplicate=True),
    Input('test-email-btn', 'n_clicks'),
    [State('email-smtp-host', 'value'),
     State('email-smtp-port', 'value'),
     State('email-smtp-user', 'value'),
     State('email-smtp-password', 'value'),
     State('email-sender', 'value'),
     State('email-recipient', 'value')],
    prevent_initial_call=True
)
def send_test_email(n_clicks, smtp_host, smtp_port, smtp_user, smtp_password, sender_email, recipient_email):
    """Send a test email to verify configuration"""
    if n_clicks is None:
        raise dash.exceptions.PreventUpdate

    try:
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart
        from datetime import datetime

        # Validate inputs
        if not all([smtp_host, smtp_user, smtp_password, sender_email, recipient_email]):
            return dbc.Alert([
                html.I(className="fa fa-exclamation-triangle me-2"),
                "Please fill in all required fields before sending test email."
            ], color="warning", dismissable=True)

        # Don't send if password is placeholder
        if all(c == '•' for c in smtp_password):
            return dbc.Alert([
                html.I(className="fa fa-exclamation-triangle me-2"),
                "Please enter your actual SMTP password (not placeholder)."
            ], color="warning", dismissable=True)

        # Create test email
        message = MIMEMultipart("alternative")
        message["Subject"] = "🛡️ IoTSentinel Test Email"
        message["From"] = sender_email
        message["To"] = recipient_email

        text_content = f"""
IoTSentinel Test Email
======================

This is a test email from your IoTSentinel dashboard.

Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

If you received this email, your email notification settings are configured correctly!

---
IoTSentinel Network Security Monitor
"""

        html_content = f"""
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: Arial, sans-serif; padding: 20px; background-color: #f5f5f5;">
    <div style="max-width: 600px; margin: 0 auto; background: white; border-radius: 8px; padding: 30px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
        <div style="text-align: center; margin-bottom: 20px;">
            <h1 style="color: #667eea; margin: 0;">🛡️ IoTSentinel</h1>
            <p style="color: #666; margin: 10px 0;">Test Email Successful</p>
        </div>

        <div style="background: #e8f5e9; padding: 20px; border-radius: 8px; border-left: 4px solid #4caf50;">
            <p style="margin: 0; color: #2e7d32;"><strong>✅ Configuration Verified</strong></p>
            <p style="margin: 10px 0 0 0; color: #555;">Your email notification settings are working correctly!</p>
        </div>

        <div style="margin-top: 20px; padding: 15px; background: #f8f9fa; border-radius: 8px;">
            <p style="margin: 0; font-size: 14px; color: #666;">
                <strong>Timestamp:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            </p>
        </div>

        <div style="margin-top: 20px; text-align: center; color: #999; font-size: 12px;">
            <p style="margin: 0;">IoTSentinel Network Security Monitor</p>
        </div>
    </div>
</body>
</html>
"""

        message.attach(MIMEText(text_content, "plain"))
        message.attach(MIMEText(html_content, "html"))

        # Send email
        server = smtplib.SMTP(smtp_host, int(smtp_port), timeout=30)
        server.ehlo()
        server.starttls()
        server.ehlo()
        server.login(smtp_user, smtp_password)
        server.send_message(message)
        server.quit()

        logger.info(f"Test email sent successfully to {recipient_email}")
        return dbc.Alert([
            html.I(className="fa fa-check-circle me-2"),
            html.Strong("Test email sent successfully!"),
            html.P(f"Check {recipient_email} for the test message.", className="mb-0 small mt-1")
        ], color="success", dismissable=True)

    except smtplib.SMTPAuthenticationError:
        return dbc.Alert([
            html.I(className="fa fa-times-circle me-2"),
            html.Strong("Authentication failed"),
            html.P("Check your SMTP username and password. For Gmail, you may need an App Password.", className="mb-0 small mt-1")
        ], color="danger", dismissable=True)
    except Exception as e:
        logger.error(f"Error sending test email: {e}")
        return dbc.Alert([
            html.I(className="fa fa-times-circle me-2"),
            html.Strong("Failed to send test email"),
            html.P(str(e), className="mb-0 small mt-1")
        ], color="danger", dismissable=True)

# ============================================================================
# CALLBACKS - ANALYTICS
# ============================================================================

@app.callback(
    Output('alert-timeline', 'figure'),
    Input('ws', 'message')
)
def update_alert_timeline(ws_message):
    if ws_message is None:
        # Return empty figure during initial load
        return go.Figure()
    alert_timeline_data = ws_message.get('alert_timeline', [])
    if not alert_timeline_data:
        fig = go.Figure()
        fig.update_layout(title="No alerts in the last 7 days")
        return fig
    df = pd.DataFrame(alert_timeline_data)
    fig = px.bar(df, x="day", y="count", color="severity", title="Alerts by Day",
                 color_discrete_map={'critical': '#dc3545', 'high': '#fd7e14', 'medium': '#17a2b8', 'low': '#6c757d'})
    fig.update_layout(xaxis_title="Date", yaxis_title="Number of Alerts", barmode='stack')
    return fig

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
        fig.update_layout(title="No Bandwidth Data Available")
        return fig
    df = pd.DataFrame(bandwidth_data)
    fig = px.bar(df, x='device_ip', y='total_bytes', title="Top 10 Devices by Bandwidth Usage", color_discrete_sequence=['#28a745'])
    fig.update_layout(xaxis_title="Device IP", yaxis_title="Total Bytes")
    return fig

@app.callback(
    Output('device-heatmap', 'figure'),
    Input('ws', 'message')
)
def update_device_heatmap(ws_message):
    if ws_message is None:
        raise dash.exceptions.PreventUpdate
    heatmap_data = ws_message.get('device_activity_heatmap', [])
    if not heatmap_data:
        fig = go.Figure()
        fig.update_layout(title="No activity data available")
        return fig
    df = pd.DataFrame(heatmap_data)
    fig = px.density_heatmap(df, x="hour", y="device_ip", z="count", title="Device Activity by Hour", color_continuous_scale="Blues")
    fig.update_layout(xaxis_title="Hour of Day", yaxis_title="Device IP")
    return fig

# ============================================================================
# CALLBACKS - SYSTEM INFO
# ============================================================================

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
    if ws_message is None:
        raise dash.exceptions.PreventUpdate
    models = ws_message.get('model_info', [])
    if not models:
        return dbc.Alert("No trained models found.", color="warning")
    return [html.Ul([html.Li([html.Strong(m['name']), f" - Size: {m['size']}, Updated: {m['modified']}"]) for m in models])]

@app.callback(
    Output('model-comparison', 'children'),
    Input('ws', 'message')
)
def update_model_comparison(ws_message):
    if ws_message is None:
        raise dash.exceptions.PreventUpdate
    report_data = ws_message.get('model_comparison_data', {})
    encoded_image = ws_message.get('model_comparison_image', None)
    if not report_data:
        return dbc.Alert("Model comparison report not found. Run 'scripts/compare_models.py' to generate it.", color="warning")

    table_header = [html.Thead(html.Tr([html.Th("Model"), html.Th("Precision"), html.Th("Recall"), html.Th("F1-Score")]))]
    table_body = [html.Tbody([
        html.Tr([
            html.Td(model),
            html.Td(f"{metrics.get('Precision', 0):.3f}"),
            html.Td(f"{metrics.get('Recall', 0):.3f}"),
            html.Td(f"{metrics.get('F1-Score', 0):.3f}")
        ]) for model, metrics in report_data.items()
    ])]
    table = dbc.Table(table_header + table_body, bordered=True, striped=True, hover=True, size="sm")
    children = [html.H6("Model Performance Metrics", className="mb-3"), table]
    if encoded_image:
        children.extend([
            html.Hr(),
            html.H6("F1-Score Visualization", className="mb-3"),
            html.Img(src=f'data:image/png;base64,{encoded_image}', style={'width': '100%'})
        ])
    return html.Div(children)

# ============================================================================
# CALLBACKS - VOICE ALERTS
# ============================================================================

app.clientside_callback(
    """
    function(ws_message, voice_enabled, announced_alerts) {
        if (!ws_message || !voice_enabled || !window.speechSynthesis) {
            return window.dash_clientside.no_update;
        }

        const recent_alerts = ws_message.recent_alerts || [];
        const announced = announced_alerts || {};
        const now = Date.now();

        // Clean up old entries (older than 1 hour)
        Object.keys(announced).forEach(id => {
            if (now - announced[id] > 3600000) {
                delete announced[id];
            }
        });

        // Find new critical/high alerts that haven't been announced
        const new_alerts = recent_alerts.filter(alert => {
            return (alert.severity === 'critical' || alert.severity === 'high') &&
                   !announced[alert.id] &&
                   !alert.acknowledged;
        });

        if (new_alerts.length > 0) {
            const alert = new_alerts[0]; // Announce first one
            const device_name = alert.device_name || alert.device_ip;
            const severity = alert.severity;
            const explanation = alert.explanation;

            // Create speech message
            let message = `Security alert! ${severity} severity detected on ${device_name}. ${explanation}`;

            // Speak it
            const utterance = new SpeechSynthesisUtterance(message);
            utterance.rate = 0.9;
            utterance.pitch = 1.0;
            utterance.volume = 1.0;

            // Use different voice characteristics based on severity
            if (severity === 'critical') {
                utterance.rate = 1.1; // Faster for urgency
                utterance.pitch = 1.2; // Higher pitch for urgency
            }

            window.speechSynthesis.speak(utterance);

            // Mark as announced
            announced[alert.id] = now;

            console.log(`[Voice Alert] Announced ${severity} alert for ${device_name}`);
        }

        return announced;
    }
    """,
    Output('announced-alerts-store', 'data'),
    [Input('ws', 'message'),
     Input('voice-alert-toggle', 'value')],
    State('announced-alerts-store', 'data')
)

@app.callback(
    Output('voice-alert-store', 'data'),
    Input('voice-alert-toggle', 'value'),
    prevent_initial_call=True
)
def update_voice_alert_store(value):
    """Persist voice alert toggle state"""
    return {'enabled': value}

# ============================================================================
# CALLBACKS - UTILITIES
# ============================================================================

@app.callback(
    [Output('pause-button', 'children'), Output('pause-button', 'color')],
    [Input('pause-button', 'n_clicks')],
    [State('pause-button', 'children')]
)
def toggle_pause_monitoring(n_clicks, button_content):
    status_file = project_root / config.get('system', 'status_file_path', default='data/system_status.json')
    if n_clicks is None:
        try:
            with open(status_file, 'r', encoding='utf-8') as f:
                status = json.load(f).get('status', 'running')
        except (FileNotFoundError, json.JSONDecodeError):
            status = 'running'
        if status == 'paused':
            return [html.I(className="fa fa-play me-2"), "Resume Monitoring"], "success"
        return [html.I(className="fa fa-pause me-2"), "Pause Monitoring"], "warning"

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
    [Output('chat-history', 'children'),
     Output('chat-input', 'value'),
     Output('chat-history-store', 'data')],
    [Input('chat-send-button', 'n_clicks'),
     Input('chat-input', 'n_submit')],
    [State('chat-input', 'value'),
     State('chat-history-store', 'data'),
     State('ws', 'message')],
    prevent_initial_call=True
)
def handle_chat_message(send_clicks, input_submit, message, chat_data, ws_message):
    """AI Chat Assistant with Ollama LLM integration and rule-based fallback"""
    if not message or not message.strip():
        raise dash.exceptions.PreventUpdate

    history = chat_data.get('history', []) if chat_data else []

    # Add user message
    history.append({'role': 'user', 'content': message})

    # Get network context
    device_count = ws_message.get('device_count', 0) if ws_message else 0
    alert_count = ws_message.get('alert_count', 0) if ws_message else 0
    recent_alerts = ws_message.get('recent_alerts', [])[:3] if ws_message else []

    # Build context for AI
    context = f"""You are IoTSentinel AI Assistant, a helpful and concise network security expert.

Current Network Status:
- Active Devices: {device_count}
- Active Alerts: {alert_count}"""

    if recent_alerts:
        context += "\nRecent Alerts:\n"
        for alert in recent_alerts:
            context += f"- {alert.get('severity', 'unknown').upper()}: {alert.get('explanation', 'Unknown')} on {alert.get('device_name') or alert.get('device_ip', 'Unknown')}\n"

    context += """\n
Your role:
- Answer questions about network security, IoTSentinel features, and device behavior
- Be concise (2-4 sentences max unless explaining complex topics)
- Use emojis sparingly (only when relevant)
- If asked about features, explain: Lockdown Mode, Trust Management, Voice Alerts, Baseline Statistics, MITRE ATT&CK mapping
- Always prioritize user security and privacy

Keep responses helpful, accurate, and actionable."""

    # Try Ollama first, fall back to rule-based
    ai_response = call_ollama_api(message, context)

    if ai_response is None:
        # Ollama unavailable - use rule-based fallback
        ai_response = get_rule_based_response(message, device_count, alert_count, recent_alerts)
        # Add indicator that this is fallback mode
        if OLLAMA_ENABLED:
            ai_response = "⚠️ *[AI mode unavailable - using basic responses]*\n\n" + ai_response

    # Add AI response
    history.append({'role': 'assistant', 'content': ai_response})

    # Build chat UI
    chat_messages = []
    for msg in history[-10:]:  # Show last 10 messages
        if msg['role'] == 'user':
            chat_messages.append(
                dbc.Card(
                    dbc.CardBody([
                        html.Div([
                            html.I(className="fa fa-user-circle me-2"),
                            html.Strong("You")
                        ], className="mb-2"),
                        html.P(msg['content'], className="mb-0")
                    ]),
                    color="primary",
                    outline=True,
                    className="mb-2"
                )
            )
        else:
            chat_messages.append(
                dbc.Card(
                    dbc.CardBody([
                        html.Div([
                            html.I(className="fa fa-robot me-2"),
                            html.Strong("IoTSentinel AI")
                        ], className="mb-2"),
                        dcc.Markdown(msg['content'], className="mb-0")
                    ]),
                    color="info",
                    outline=True,
                    className="mb-2"
                )
            )

    return chat_messages, "", {'history': history}

app.clientside_callback(
    """
    function(theme_data) {
        if (!theme_data) return window.dash_clientside.no_update;
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
    Output('theme-selector', 'className'),
    Input('theme-store', 'data')
)

@app.callback(
    Output('theme-store', 'data'),
    Input('theme-selector', 'value'),
    prevent_initial_call=True
)
def update_theme_store(theme):
    return {'theme': theme}

# Keyboard Shortcuts
app.clientside_callback(
    """
    function(_) {
        document.addEventListener('keydown', function(event) {
            if (event.target.tagName === 'INPUT' || event.target.tagName === 'TEXTAREA') {
                return;
            }
            let action = null;
            if (event.key === 'n' || event.key === 'N') {
                action = 'toggle-notifications';
            } else if (event.key === 'd' || event.key === 'D') {
                action = 'scroll-to-devices';
            } else if (event.key === 'a' || event.key === 'A') {
                action = 'scroll-to-alerts';
            }
            if (action) {
                if (action === 'toggle-notifications') {
                    document.getElementById('notification-bell-button').click();
                } else if (action === 'scroll-to-devices') {
                    document.querySelector('.left-panel').scrollIntoView({behavior: 'smooth'});
                } else if (action === 'scroll-to-alerts') {
                    document.querySelector('.right-panel').scrollIntoView({behavior: 'smooth'});
                }
            }
        });
        return window.dash_clientside.no_update;
    }
    """,
    Output('keyboard-shortcut-store', 'id'),
    Input('url', 'pathname')
)

app.clientside_callback(
    """
    function(n) {
        // Allow Enter key to send chat message
        const chatInput = document.getElementById('chat-input');
        if (chatInput) {
            chatInput.addEventListener('keypress', function(event) {
                if (event.key === 'Enter' && !event.shiftKey) {
                    event.preventDefault();
                    document.getElementById('chat-send-button').click();
                }
            });
        }
        return window.dash_clientside.no_update;
    }
    """,
    Output('chat-input', 'id'),
    Input('chat-modal', 'is_open')
)

# ============================================================================
# WEBSOCKET BACKGROUND THREAD
# ============================================================================
thread = None
thread_lock = threading.Lock()

def background_thread():
    while True:
        socketio.sleep(3)
        data_payload = {}

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

        devices_with_status = get_devices_with_status()
        connections_for_graph = db_manager.get_recent_connections(hours=1)
        num_devices = len(devices_with_status)

        phi = math.pi * (3. - math.sqrt(5.))
        for i, device in enumerate(devices_with_status):
            device['has_critical_alert'] = (device.get('status') == 'alert')
            y = 1 - (i / (num_devices - 1)) * 2 if num_devices > 1 else 0
            radius = math.sqrt(1 - y * y)
            theta = phi * i
            x = math.cos(theta) * radius
            z = math.sin(theta) * radius
            device['x'] = x * 10
            device['y'] = y * 10
            device['z'] = z * 10

        elements = []
        elements.append({'data': {'id': 'router', 'label': 'Router', 'type': 'router', 'color': '#007bff', 'borderColor': '#0056b3'}})
        device_ips = set()
        for device in devices_with_status:
            device_ip = device['device_ip']
            device_ips.add(device_ip)
            status = device.get('status', 'normal')
            color = DEVICE_STATUS_COLORS.get(status, DEVICE_STATUS_COLORS['unknown'])
            border_colors = {'normal': '#1e7b34', 'warning': '#d39e00', 'alert': '#bd2130', 'unknown': '#545b62'}
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
                        elements.append({'data': {'source': src, 'target': dst}, 'classes': 'animated-edge'})
                        seen_edges.add(edge_key)

        data_payload['network_graph_elements'] = elements
        data_payload['recent_connections_feed'] = connections_for_graph
        data_payload['traffic_timeline'] = db_manager.get_traffic_timeline(hours=24)
        data_payload['protocol_distribution'] = db_manager.get_protocol_distribution(hours=24)
        data_payload['all_devices_with_status'] = devices_with_status
        data_payload['device_activity_heatmap'] = db_manager.get_device_activity_heatmap(hours=24)

        conn = get_db_connection()
        if conn:
            try:
                query = """
                    SELECT a.id, a.timestamp, a.device_ip, d.device_name, a.severity,
                        a.anomaly_score, a.explanation, a.top_features, a.acknowledged, d.is_trusted
                    FROM alerts a LEFT JOIN devices d ON a.device_ip = d.device_ip
                    WHERE a.timestamp > datetime('now', '-24 hours')
                    ORDER BY a.timestamp DESC
                """
                df_alerts = pd.read_sql_query(query, conn)
                data_payload['recent_alerts'] = df_alerts.to_dict('records')
            except (sqlite3.Error, pd.io.sql.DatabaseError) as e:
                logger.error(f"Error fetching alerts for WebSocket: {e}")
            finally:
                conn.close()

        data_payload['alert_timeline'] = db_manager.get_alert_timeline(days=7)
        data_payload['anomaly_distribution'] = db_manager.get_anomaly_distribution(hours=24)
        data_payload['bandwidth_chart'] = db_manager.get_bandwidth_stats(hours=24)

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

        socketio.emit('update_data', data_payload)

@socketio.on('connect')
def test_connect(auth):
    global thread
    with thread_lock:
        if thread is None:
            thread = socketio.start_background_task(background_thread)
    logger.info("Client connected to WebSocket.")

@socketio.on('disconnect')
def test_disconnect():
    logger.info("Client disconnected from WebSocket.")

# ============================================================================
# MAIN
# ============================================================================

def main():
    host = config.get('dashboard', 'host', default='0.0.0.0')
    port = config.get('dashboard', 'port', default=8050)
    debug = config.get('dashboard', 'debug', default=False)

    logger.info("=" * 70)
    logger.info("IoTSentinel Dashboard - Enhanced Educational Edition")
    logger.info("=" * 70)
    logger.info(f"Dashboard URL: http://{host}:{port}")
    logger.info("")

    # Check AI Assistant status
    ai_status = "🤖 AI Chat: "
    if OLLAMA_ENABLED:
        try:
            # Quick check if Ollama is available
            test_response = requests.get("http://localhost:11434/api/tags", timeout=2)
            if test_response.status_code == 200:
                ai_status += f"✅ ENABLED (Ollama with {OLLAMA_MODEL})"
            else:
                ai_status += "⚠️ ENABLED but Ollama not responding"
        except:
            ai_status += "⚠️ ENABLED but Ollama not running (will use fallback)"
    else:
        ai_status += "❌ DISABLED (rule-based only)"
    logger.info(ai_status)

    # Check Threat Intelligence status
    threat_status = "🌐 Threat Intelligence: "
    if threat_intel.enabled:
        threat_status += f"✅ ENABLED (AbuseIPDB with {THREAT_INTEL_CACHE_HOURS}h cache)"
    else:
        threat_status += "❌ DISABLED (Configure AbuseIPDB API key to enable)"
    logger.info(threat_status)
    logger.info("")

    logger.info("✨ NEW FEATURES:")
    logger.info("  ✓ Interactive onboarding wizard (6 steps)")
    logger.info("  ✓ Device details modal with trust management")
    logger.info("  ✓ Lockdown mode with confirmation")
    logger.info("  ✓ Keyboard shortcuts (N/D/A)")
    logger.info("  ✓ Clickable device cards & network graph")
    logger.info("")
    logger.info("KEY FEATURES:")
    logger.info("  ✓ Device status indicators (green/yellow/red)")
    logger.info("  ✓ Color-coded network topology graph")
    logger.info("  ✓ Educational drill-down with baseline comparisons")
    logger.info("  ✓ Plain English explanations of anomalies")
    logger.info("  ✓ Visual 'Normal vs Today' comparison charts")
    logger.info("=" * 70)

# Try running with SocketIO, fall back if needed
    try:
        socketio.run(app.server, host=host, port=port, debug=debug, allow_unsafe_werkzeug=True)
    except Exception as e:
        logger.error(f"SocketIO failed to start: {e}")
        logger.info("Falling back to standard Dash server (WebSockets disabled)...")
        app.run(host=host, port=port, debug=debug)

if __name__ == '__main__':
    main()
