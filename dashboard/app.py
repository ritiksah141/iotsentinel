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
from dash import dcc, html, Input, Output, State, callback_context, ALL
import requests
import os
import secrets
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any
import sys
from dotenv import load_dotenv

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
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from utils.auth import AuthManager, User
from utils.rate_limiter import LoginRateLimiter

# Import new IoT-specific modules
from utils.iot_device_intelligence import get_intelligence
from utils.iot_protocol_analyzer import get_protocol_analyzer
from utils.iot_threat_detector import get_threat_detector
from utils.iot_features import (
    get_smart_home_manager,
    get_privacy_monitor,
    get_network_segmentation,
    get_firmware_manager
)

load_dotenv()
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

# Device group manager import
from utils.device_group_manager import DeviceGroupManager

# Initialize device group manager
group_manager = DeviceGroupManager(DB_PATH)

# Authentication setup
auth_manager = AuthManager(DB_PATH)

# Rate limiting for login attempts (5 attempts, 5-minute lockout)
login_rate_limiter = LoginRateLimiter(max_attempts=5, lockout_duration=300)

# Initialize IoT-specific modules
try:
    iot_intelligence = get_intelligence(db_manager)
    iot_protocol_analyzer = get_protocol_analyzer(db_manager)
    iot_threat_detector = get_threat_detector(db_manager)
    smart_home_manager = get_smart_home_manager(db_manager)
    privacy_monitor = get_privacy_monitor(db_manager)
    network_segmentation = get_network_segmentation(db_manager)
    firmware_manager = get_firmware_manager(db_manager)
    logger.info("IoT-specific modules initialized successfully")
except Exception as e:
    logger.warning(f"Failed to initialize IoT modules: {e}. IoT features may not be available.")
    iot_intelligence = None
    iot_protocol_analyzer = None
    iot_threat_detector = None
    smart_home_manager = None
    privacy_monitor = None
    network_segmentation = None
    firmware_manager = None

server = app.server

# Set Flask secret key for sessions (required for Flask-Login)
# Read from environment variable or generate a random one
secret_key = os.getenv('FLASK_SECRET_KEY')
if not secret_key or secret_key == 'your-secret-key-change-this-in-production-please-use-at-least-32-characters': # pragma: allowlist secret
    logger.warning("Using auto-generated SECRET_KEY. Set FLASK_SECRET_KEY in .env for production!")
    secret_key = secrets.token_hex(32)
server.config['SECRET_KEY'] = secret_key

login_manager = LoginManager()
login_manager.init_app(server)
login_manager.login_view = '/login'

@login_manager.user_loader
def load_user(user_id):
    """Load user by ID for Flask-Login"""
    return auth_manager.get_user_by_id(int(user_id))

# Health check endpoint for monitoring
@server.route('/health')
def health_check():
    """
    Health check endpoint for monitoring and deployment verification.
    Returns JSON with status of various system components.
    """
    from flask import jsonify

    health_status = {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "components": {}
    }

    # Check database connectivity
    try:
        conn = sqlite3.connect(DB_PATH, timeout=5)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM devices")
        device_count = cursor.fetchone()[0]
        conn.close()
        health_status["components"]["database"] = {
            "status": "healthy",
            "device_count": device_count
        }
    except Exception as e:
        health_status["status"] = "unhealthy"
        health_status["components"]["database"] = {
            "status": "unhealthy",
            "error": str(e)
        }

    # Check authentication system
    try:
        users = auth_manager.get_all_users()
        health_status["components"]["authentication"] = {
            "status": "healthy",
            "user_count": len(users)
        }
    except Exception as e:
        health_status["status"] = "degraded"
        health_status["components"]["authentication"] = {
            "status": "unhealthy",
            "error": str(e)
        }

    # Check if .env file exists
    env_path = Path(__file__).parent.parent / '.env'
    health_status["components"]["configuration"] = {
        "status": "healthy" if env_path.exists() else "warning",
        "env_file_exists": env_path.exists()
    }

    # Overall health determination
    component_statuses = [c.get("status") for c in health_status["components"].values()]
    if "unhealthy" in component_statuses:
        health_status["status"] = "unhealthy"
    elif "warning" in component_statuses:
        health_status["status"] = "degraded"

    # Set HTTP status code based on health
    status_code = 200
    if health_status["status"] == "degraded":
        status_code = 200  # Still return 200 but indicate degraded state
    elif health_status["status"] == "unhealthy":
        status_code = 503  # Service Unavailable

    return jsonify(health_status), status_code

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
    'smart lock': {'emoji': '🔒', 'fa': 'fa-lock', 'color': '#28a745'},
    'smart_lock': {'emoji': '🔒', 'fa': 'fa-lock', 'color': '#28a745'},
    'thermostat': {'emoji': '🌡️', 'fa': 'fa-thermometer-half', 'color': '#fd7e14'},
    'smart plug': {'emoji': '🔌', 'fa': 'fa-plug', 'color': '#17a2b8'},
    'smart_plug': {'emoji': '🔌', 'fa': 'fa-plug', 'color': '#17a2b8'},
    'smart bulb': {'emoji': '💡', 'fa': 'fa-lightbulb', 'color': '#ffc107'},
    'smart_bulb': {'emoji': '💡', 'fa': 'fa-lightbulb', 'color': '#ffc107'},
    'light bulb': {'emoji': '💡', 'fa': 'fa-lightbulb', 'color': '#ffc107'},
    'sensor': {'emoji': '📊', 'fa': 'fa-sensor', 'color': '#6f42c1'},
    'smart_speaker': {'emoji': '🔊', 'fa': 'fa-volume-up', 'color': '#17a2b8'},
    'streaming_device': {'emoji': '📱', 'fa': 'fa-tv', 'color': '#fd7e14'},
    'iot_hub': {'emoji': '🏠', 'fa': 'fa-home', 'color': '#6f42c1'},
    'raspberry_pi': {'emoji': '🥧', 'fa': 'fa-microchip', 'color': '#c51a4a'},

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

    conn.create_function("sqrt", 1, math.sqrt)

    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT
                AVG(daily_bytes_sent) as avg_bytes_sent,
                AVG(daily_bytes_received) as avg_bytes_received,
                AVG(daily_connections) as avg_connections,
                AVG(daily_unique_destinations) as avg_unique_destinations,
                COALESCE(sqrt(ABS(AVG(daily_bytes_sent*daily_bytes_sent) - AVG(daily_bytes_sent)*AVG(daily_bytes_sent))), 0) as std_bytes_sent,
                COALESCE(sqrt(ABS(AVG(daily_bytes_received*daily_bytes_received) - AVG(daily_bytes_received)*AVG(daily_bytes_received))), 0) as std_bytes_received,
                COALESCE(sqrt(ABS(AVG(daily_connections*daily_connections) - AVG(daily_connections)*AVG(daily_connections))), 0) as std_connections
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
# LOGIN PAGE LAYOUT
# ============================================================================

login_layout = dbc.Container([
    dbc.Row([
        dbc.Col([
            # Login/Register Card
            dbc.Card([
                dbc.CardHeader([
                    html.Div([
                        html.I(className="fa fa-shield-alt fa-3x mb-3", style={"color": "var(--accent-color)"}),
                        html.H2("IoTSentinel", className="mb-1", style={"color": "var(--accent-color)", "fontWeight": "700"}),
                        html.P("Network Security Dashboard", className="text-muted mb-0")
                    ], className="text-center")
                ], style={"backgroundColor": "var(--bg-secondary)", "border": "none", "padding": "2rem 1rem 1rem"}),

                dbc.CardBody([
                    # Tabs for Login/Register
                    dbc.Tabs([
                        # Login Tab
                        dbc.Tab([
                            html.Div([
                                dbc.Alert(id="login-alert", is_open=False, duration=4000, className="mt-3"),

                                # Username Input
                                dbc.InputGroup([
                                    dbc.InputGroupText(html.I(className="fa fa-user"), style={"backgroundColor": "var(--bg-tertiary)", "border": "1px solid var(--border-color)"}),
                                    dbc.Input(
                                        id="login-username",
                                        type="text",
                                        placeholder="Username",
                                        autocomplete="username",
                                        style={"border": "1px solid var(--border-color)"}
                                    )
                                ], className="mb-3 mt-3"),

                                # Password Input with Eye Icon
                                dbc.InputGroup([
                                    dbc.InputGroupText(html.I(className="fa fa-lock"), style={"backgroundColor": "var(--bg-tertiary)", "border": "1px solid var(--border-color)"}),
                                    dbc.Input(
                                        id="login-password",
                                        type="password",
                                        placeholder="Password",
                                        autocomplete="current-password",
                                        n_submit=0,
                                        style={"border": "1px solid var(--border-color)", "borderRight": "none"}
                                    ),
                                    dbc.Button(
                                        html.I(id="login-password-toggle", className="fa fa-eye"),
                                        id="login-password-toggle-btn",
                                        color="light",
                                        outline=False,
                                        style={"border": "1px solid var(--border-color)", "backgroundColor": "var(--bg-tertiary)"}
                                    )
                                ], className="mb-3"),

                                # Login Button
                                dbc.Button(
                                    [html.I(className="fa fa-sign-in-alt me-2"), "Sign In"],
                                    id="login-button",
                                    color="primary",
                                    className="w-100 mt-2",
                                    size="lg",
                                    style={"fontWeight": "600"}
                                ),

                                # Default Credentials Hint
                                html.Div([
                                    html.Small([
                                        html.I(className="fa fa-info-circle me-1"),
                                        "First time? Use: ",
                                        html.Code("admin / admin", style={"color": "var(--accent-color)"})
                                    ], className="text-muted")
                                ], className="text-center mt-3")
                            ])
                        ], label="Login", tab_id="login-tab", activeTabClassName="fw-bold"),

                        # Register Tab
                        dbc.Tab([
                            html.Div([
                                dbc.Alert(id="register-alert", is_open=False, duration=4000, className="mt-3"),

                                # New Username Input
                                dbc.InputGroup([
                                    dbc.InputGroupText(html.I(className="fa fa-user"), style={"backgroundColor": "var(--bg-tertiary)", "border": "1px solid var(--border-color)"}),
                                    dbc.Input(
                                        id="register-username",
                                        type="text",
                                        placeholder="Choose username",
                                        autocomplete="off",
                                        style={"border": "1px solid var(--border-color)"}
                                    )
                                ], className="mb-3 mt-3"),

                                # New Password Input
                                dbc.InputGroup([
                                    dbc.InputGroupText(html.I(className="fa fa-lock"), style={"backgroundColor": "var(--bg-tertiary)", "border": "1px solid var(--border-color)"}),
                                    dbc.Input(
                                        id="register-password",
                                        type="password",
                                        placeholder="Choose password",
                                        autocomplete="new-password",
                                        style={"border": "1px solid var(--border-color)", "borderRight": "none"}
                                    ),
                                    dbc.Button(
                                        html.I(id="register-password-toggle", className="fa fa-eye"),
                                        id="register-password-toggle-btn",
                                        color="light",
                                        outline=False,
                                        style={"border": "1px solid var(--border-color)", "backgroundColor": "var(--bg-tertiary)"}
                                    )
                                ], className="mb-3"),

                                # Confirm Password Input
                                dbc.InputGroup([
                                    dbc.InputGroupText(html.I(className="fa fa-lock"), style={"backgroundColor": "var(--bg-tertiary)", "border": "1px solid var(--border-color)"}),
                                    dbc.Input(
                                        id="register-password-confirm",
                                        type="password",
                                        placeholder="Confirm password",
                                        autocomplete="new-password",
                                        style={"border": "1px solid var(--border-color)", "borderRight": "none"}
                                    ),
                                    dbc.Button(
                                        html.I(id="register-password-confirm-toggle", className="fa fa-eye"),
                                        id="register-password-confirm-toggle-btn",
                                        color="light",
                                        outline=False,
                                        style={"border": "1px solid var(--border-color)", "backgroundColor": "var(--bg-tertiary)"}
                                    )
                                ], className="mb-3"),

                                # Role Selection
                                dbc.Label("Account Type", className="small text-muted mb-1"),
                                dbc.RadioItems(
                                    id="register-role",
                                    options=[
                                        {"label": "Admin (Full access)", "value": "admin"},
                                        {"label": "Viewer (Read-only)", "value": "viewer"}
                                    ],
                                    value="viewer",
                                    className="mb-3"
                                ),

                                # Register Button
                                dbc.Button(
                                    [html.I(className="fa fa-user-plus me-2"), "Create Account"],
                                    id="register-button",
                                    color="success",
                                    className="w-100 mt-2",
                                    size="lg",
                                    style={"fontWeight": "600"}
                                )
                            ])
                        ], label="Register", tab_id="register-tab", activeTabClassName="fw-bold")
                    ], id="auth-tabs", active_tab="login-tab", className="mb-0")
                ], style={"padding": "1.5rem"})
            ], className="cyber-card shadow-lg", style={"maxWidth": "480px", "width": "100%"})
        ], width=12, className="d-flex justify-content-center align-items-center", style={"minHeight": "100vh", "padding": "2rem"})
    ], className="min-vh-100", style={"background": "linear-gradient(135deg, #667eea 0%, #764ba2 100%)"})
], fluid=True)

# ============================================================================
# DASHBOARD LAYOUT
# ============================================================================

dashboard_layout = dbc.Container([
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
                              id="pause-button", color="warning", outline=True, size="sm", className="cyber-button ms-1"),
                    dbc.Button([html.I(className="fa fa-sign-out-alt me-1"), "Logout"],
                              color="danger", outline=True, size="sm", className="cyber-button ms-1", href="/logout", external_link=True)
                ], size="sm")
            ], className="float-end")
        ], width=5, className="text-end")
    ], className="header-row mb-2 align-items-center"),

    # Status Bar
    # System Status Bar - Improved Layout
    dbc.Card([
        dbc.CardBody([
            dbc.Row([
                # Pi5 System Stats - Better Organized
                dbc.Col([
                    html.Div([
                        html.H6([
                            html.I(className="fa fa-server me-2", style={"color": "var(--accent-color)"}),
                            "System Status"
                        ], className="mb-2", style={"fontSize": "0.9rem"}),
                        dbc.Row([
                            dbc.Col([
                                dbc.Card([
                                    dbc.CardBody([
                                        html.Div([
                                            html.I(className="fa fa-microchip me-2"),
                                            "CPU"
                                        ], className="small text-muted mb-1"),
                                        html.H5(id="cpu-usage", className="mb-0", style={"color": "var(--accent-color)"})
                                    ], className="text-center p-2")
                                ], style={"backgroundColor": "var(--bg-tertiary)", "border": "1px solid var(--border-color)"})
                            ], width=4),
                            dbc.Col([
                                dbc.Card([
                                    dbc.CardBody([
                                        html.Div([
                                            html.I(className="fa fa-memory me-2"),
                                            "RAM"
                                        ], className="small text-muted mb-1"),
                                        html.H6(id="ram-usage", className="mb-0", style={"color": "var(--accent-color)", "fontSize": "0.85rem"})
                                    ], className="text-center p-2")
                                ], style={"backgroundColor": "var(--bg-tertiary)", "border": "1px solid var(--border-color)"})
                            ], width=4),
                            dbc.Col([
                                dbc.Card([
                                    dbc.CardBody([
                                        html.Div([
                                            html.I(className="fa fa-wifi me-2"),
                                            "Network"
                                        ], className="small text-muted mb-1"),
                                        html.H6(id="network-health", className="mb-0 text-success", style={"fontSize": "0.75rem"})
                                    ], className="text-center p-2")
                                ], style={"backgroundColor": "var(--bg-tertiary)", "border": "1px solid var(--border-color)"})
                            ], width=4)
                        ], className="g-2")
                    ])
                ], width=5),

                # Voice Alerts - Better Toggle
                dbc.Col([
                    html.Div([
                        html.H6([
                            html.I(className="fa fa-volume-up me-2", style={"color": "var(--accent-color)"}),
                            "Voice Alerts"
                        ], className="mb-2", style={"fontSize": "0.9rem"}),
                        dbc.Card([
                            dbc.CardBody([
                                dbc.Row([
                                    dbc.Col([
                                        html.Div([
                                            html.I(className="fa fa-bullhorn me-2"),
                                            "Enable Voice Notifications"
                                        ], className="small")
                                    ], width=8, className="d-flex align-items-center"),
                                    dbc.Col([
                                        dbc.Switch(
                                            id="voice-alert-toggle",
                                            value=False,
                                            className="float-end"
                                        )
                                    ], width=4)
                                ], className="align-items-center")
                            ], className="p-2")
                        ], style={"backgroundColor": "var(--bg-tertiary)", "border": "1px solid var(--border-color)"})
                    ])
                ], width=4),


            ], className="align-items-center")
        ], className="p-3")
    ], className="mb-3", style={"backgroundColor": "var(--bg-secondary)", "border": "1px solid var(--border-color)"}),

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
                    html.I(
                        className="fa fa-question-circle ms-2",
                        id="network-graph-help",
                        style={"cursor": "pointer", "fontSize": "14px"}
                    ),
                    dbc.Tooltip(
                        "This network graph shows all devices connected to your network and how they communicate. "
                        "Each circle (node) represents a device, and lines (edges) show connections between devices. "
                        "The router is shown as a diamond in the center. Watch for unusual connections between devices "
                        "that normally don't talk to each other - this could indicate suspicious activity!",
                        target="network-graph-help",
                        placement="bottom"
                    ),
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
                        dbc.CardHeader([
                            "Protocol Distribution",
                            html.I(
                                className="fa fa-question-circle ms-2",
                                id="protocol-help",
                                style={"cursor": "pointer", "fontSize": "12px"}
                            ),
                            dbc.Tooltip(
                                "This pie chart shows what types of network protocols your devices are using. "
                                "TCP is for reliable connections (like web browsing), UDP is for faster but less reliable traffic (like video calls), "
                                "and ICMP is for network diagnostics (like ping). If you see unusual protocol activity, it might indicate scanning or attacks.",
                                target="protocol-help",
                                placement="top"
                            )
                        ], className="cyber-card-header-sm"),
                        dbc.CardBody(dcc.Graph(id='protocol-pie', style={'height': '200px'}, config={'displayModeBar': False}), className="p-2")
                    ], className="cyber-card")
                ], width=6),
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader([
                            "Traffic Timeline (24h)",
                            html.I(
                                className="fa fa-question-circle ms-2",
                                id="timeline-help",
                                style={"cursor": "pointer", "fontSize": "12px"}
                            ),
                            dbc.Tooltip(
                                "This timeline shows your network traffic over the past 24 hours. "
                                "Look for unusual spikes in activity - high traffic at odd hours (like 3 AM) could indicate "
                                "malware, data exfiltration, or unauthorized access. Normal patterns usually show activity during business hours.",
                                target="timeline-help",
                                placement="top"
                            )
                        ], className="cyber-card-header-sm"),
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
                    html.Span("(Guidance)", className="text-muted ms-2"),
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
                    # IoT Security Status Widget - NEW
                    dbc.Row([
                        dbc.Col([
                            dbc.Card([
                                dbc.CardHeader([
                                    html.I(className="fa fa-shield-alt me-2"),
                                    "IoT Security Status"
                                ]),
                                dbc.CardBody([
                                    html.Div(id='iot-security-widget')
                                ])
                            ], className="cyber-card mb-3", style={"borderLeft": "4px solid var(--accent-color)"})
                        ], width=12)
                    ]),
                    dbc.Row([
                        dbc.Col([dbc.Card([
                            dbc.CardHeader([
                                "Alert Timeline (7 Days)",
                                html.I(
                                    className="fa fa-question-circle ms-2",
                                    id="alert-timeline-help",
                                    style={"cursor": "pointer", "fontSize": "14px"}
                                ),
                                dbc.Tooltip(
                                    "This timeline shows when security alerts were triggered over the past week. "
                                    "Look for patterns - if you see many alerts at similar times each day, it could indicate "
                                    "automated attacks or scheduled malicious activity. A sudden spike in alerts "
                                    "might mean an active attack is happening now!",
                                    target="alert-timeline-help",
                                    placement="top"
                                )
                            ]),
                            dbc.CardBody(dcc.Graph(id='alert-timeline', style={'height': '300px'}))
                        ], className="cyber-card")], width=6),
                        dbc.Col([dbc.Card([
                            dbc.CardHeader([
                                "Anomaly Score Distribution",
                                html.I(
                                    className="fa fa-question-circle ms-2",
                                    id="anomaly-help",
                                    style={"cursor": "pointer", "fontSize": "14px"}
                                ),
                                dbc.Tooltip(
                                    "This chart shows how unusual each device's behavior is compared to normal patterns. "
                                    "The Anomaly Score is calculated by our AI model - higher scores mean more unusual behavior. "
                                    "Most devices should have low scores (near 0). If you see devices with high scores, "
                                    "they might be acting suspiciously and should be investigated further.",
                                    target="anomaly-help",
                                    placement="top"
                                )
                            ]),
                            dbc.CardBody(dcc.Graph(id='anomaly-distribution', style={'height': '300px'}))
                        ], className="cyber-card")], width=6)
                    ]),
                    dbc.Row([
                        dbc.Col([dbc.Card([
                            dbc.CardHeader([
                                "Top Devices by Bandwidth",
                                html.I(
                                    className="fa fa-question-circle ms-2",
                                    id="bandwidth-help",
                                    style={"cursor": "pointer", "fontSize": "14px"}
                                ),
                                dbc.Tooltip(
                                    "This chart ranks your devices by how much data they're using. "
                                    "Normally, computers and streaming devices use the most bandwidth. "
                                    "If a device you rarely use suddenly appears at the top, or if a simple IoT device "
                                    "(like a smart bulb) is using a lot of data, it could be compromised and sending data to attackers.",
                                    target="bandwidth-help",
                                    placement="top"
                                )
                            ]),
                            dbc.CardBody(dcc.Graph(id='bandwidth-chart', style={'height': '300px'}))
                        ], className="cyber-card")], width=6),
                        dbc.Col([dbc.Card([
                            dbc.CardHeader([
                                "Device Activity Heatmap",
                                html.I(
                                    className="fa fa-question-circle ms-2",
                                    id="heatmap-help",
                                    style={"cursor": "pointer", "fontSize": "14px"}
                                ),
                                dbc.Tooltip(
                                    "This heatmap shows when each device is most active throughout the day. "
                                    "Darker colors mean more network activity during that hour. "
                                    "Look for unusual patterns - for example, if a security camera is very active at 3 AM when nobody's home, "
                                    "or if an IoT device shows activity at times when it shouldn't be in use. "
                                    "These could be signs of compromise or malware.",
                                    target="heatmap-help",
                                    placement="top"
                                )
                            ]),
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

                # Email Notifications - Separate Section
                dbc.AccordionItem([
                    dbc.Card([
                        dbc.CardHeader([
                            html.Div([
                                html.Span("📧 Email Notifications"),
                                dbc.Badge("", id="email-status-badge", className="ms-2")
                            ], className="d-flex align-items-center justify-content-between")
                        ]),
                        dbc.CardBody([
                            dbc.Switch(
                                id='email-enabled-switch',
                                label="Enable Email Notifications",
                                value=False,
                                className="mb-3"
                            ),

                            html.Hr(),

                            html.H6("SMTP Server Settings", className="text-muted mb-3"),
                            dbc.Row([
                                dbc.Col([
                                    dbc.Label("SMTP Host", className="small"),
                                    dbc.Input(id='email-smtp-host', type='text', placeholder='smtp.gmail.com', disabled=True)
                                ], width=8),
                                dbc.Col([
                                    dbc.Label("Port", className="small"),
                                    dbc.Input(id='email-smtp-port', type='number', placeholder='587', disabled=True)
                                ], width=4)
                            ], className="mb-3"),

                            dbc.Row([
                                dbc.Col([
                                    dbc.Label("SMTP Username", className="small"),
                                    dbc.Input(id='email-smtp-user', type='text', placeholder='your-email@gmail.com', disabled=True)
                                ], width=6),
                                dbc.Col([
                                    dbc.Label("SMTP Password", className="small"),
                                    dbc.Input(id='email-smtp-password', type='password', placeholder='••••••••', disabled=True)
                                ], width=6)
                            ], className="mb-3"),

                            html.Hr(),

                            html.H6("Email Addresses", className="text-muted mb-3"),
                            dbc.Row([
                                dbc.Col([
                                    dbc.Label("Sender Email", className="small"),
                                    dbc.Input(id='email-sender', type='email', placeholder='iotsentinel@gmail.com', disabled=True)
                                ], width=6),
                                dbc.Col([
                                    dbc.Label("Recipient Email", className="small"),
                                    dbc.Input(id='email-recipient', type='email', placeholder='your-email@gmail.com', disabled=False)
                                ], width=6)
                            ], className="mb-3"),

                            html.Hr(),
                                dbc.Row([
                                dbc.Col([
                                    dbc.Button([html.I(className="fa fa-save me-2"), "Save Settings"],
                                              id="save-email-settings-btn", color="primary", className="w-100")
                                ], width=6),
                                dbc.Col([
                                    dbc.Button([html.I(className="fa fa-envelope me-2"), "Send Test Email"],
                                                id="test-email-btn", color="success", outline=True, className="w-100")
                                ], width=6)
                            ]),
                            html.Div(id="email-settings-status", className="mt-3")
                        ])

                    ], className="cyber-card")
                ], title="📧 Email Notifications", class_name="cyber-accordion-item"),

                # Firewall Control - Separate Section
                dbc.AccordionItem([
                    dbc.Card([
                        dbc.CardHeader("🔥 Firewall & Security"),
                        dbc.CardBody([
                            html.H6("Lockdown Mode", className="mb-3"),
                            dbc.Switch(
                                id='lockdown-switch',
                                label="Enable Lockdown Mode",
                                value=False,
                                className="mb-2"
                            ),
                            dbc.Alert([
                                html.I(className="fa fa-info-circle me-2"),
                                "When enabled, only trusted devices can access the network. Mark devices as trusted before enabling."
                            ], color="info", className="mt-3"),
                            html.Div(id='lockdown-status', className="mt-3")
                        ])
                    ], className="cyber-card")
                ], title="🔥 Firewall Control", class_name="cyber-accordion-item"),

                # User Management - New Section
                dbc.AccordionItem([
                    dbc.Card([
                        dbc.CardHeader("👤 User Management"),
                        dbc.CardBody([
                            # Change Password Section
                            html.H6("Change Password", className="mb-3"),
                            dbc.Row([
                                dbc.Col([
                                    dbc.Label("Current Password", className="small"),
                                    dbc.Input(id='current-password', type='password', placeholder='Enter current password')
                                ], width=12)
                            ], className="mb-3"),
                            dbc.Row([
                                dbc.Col([
                                    dbc.Label("New Password", className="small"),
                                    dbc.Input(id='new-password', type='password', placeholder='Enter new password')
                                ], width=6),
                                dbc.Col([
                                    dbc.Label("Confirm New Password", className="small"),
                                    dbc.Input(id='new-password-confirm', type='password', placeholder='Confirm new password')
                                ], width=6)
                            ], className="mb-3"),
                            dbc.Button([html.I(className="fa fa-key me-2"), "Change Password"],
                                      id="change-password-btn", color="warning", className="w-100"),
                            html.Div(id="change-password-status", className="mt-3"),

                            html.Hr(className="my-4"),

                            # User List Section (Admin only)
                            html.H6("Active Users", className="mb-3"),
                            html.Div(id="user-list-container"),
                            html.Small("Only administrators can view all users", className="text-muted")
                        ])
                    ], className="cyber-card")
                ], title="👤 User Management", class_name="cyber-accordion-item"),

                # Device Management - NEW
                dbc.AccordionItem([
                    dbc.Card([
                        dbc.CardHeader("📱 Device Management"),
                        dbc.CardBody([
                            html.Div(id='device-management-container', children=[
                                # Load and Bulk Action Buttons
                                dbc.Row([
                                    dbc.Col([
                                        dbc.Button([html.I(className="fa fa-sync me-2"), "Load Devices"],
                                                  id="load-devices-btn", color="primary", className="mb-3")
                                    ], width=3),
                                    dbc.Col([
                                        html.Div(id='bulk-actions-container', children=[
                                            dbc.ButtonGroup([
                                                dbc.Button([html.I(className="fa fa-check me-1"), "Trust Selected"],
                                                          id="bulk-trust-btn", color="success", size="sm", disabled=True),
                                                dbc.Button([html.I(className="fa fa-ban me-1"), "Block Selected"],
                                                          id="bulk-block-btn", color="danger", size="sm", disabled=True),
                                                dbc.Button([html.I(className="fa fa-trash me-1"), "Delete Selected"],
                                                          id="bulk-delete-btn", color="warning", size="sm", disabled=True)
                                            ])
                                        ])
                                    ], width=9, className="text-end")
                                ], className="mb-2"),

                                # Status message
                                html.Div(id='bulk-action-status'),

                                # Device table
                                html.Div(id='device-management-table'),

                                # Store for selected devices
                                dcc.Store(id='selected-devices-store', data=[])
                            ])
                        ])
                    ], className="cyber-card")
                ], title="📱 Device Management", class_name="cyber-accordion-item"),

                # General Settings - Enhanced
                dbc.AccordionItem([
                    dbc.Card([
                        dbc.CardHeader("⚙️ Dashboard Preferences"),
                        dbc.CardBody([
                            # Auto-refresh interval
                            html.Div([
                                html.Label("Auto-refresh Interval", className="form-label"),
                                dcc.Dropdown(
                                    id='refresh-interval-dropdown',
                                    options=[
                                        {'label': '5 seconds', 'value': 5000},
                                        {'label': '10 seconds (default)', 'value': 10000},
                                        {'label': '30 seconds', 'value': 30000},
                                        {'label': '1 minute', 'value': 60000},
                                        {'label': 'Manual only', 'value': -1}
                                    ],
                                    value=10000,
                                    className="mb-3"
                                ),
                            ]),

                            # Data retention
                            html.Div([
                                html.Label("Data Retention Period", className="form-label"),
                                dcc.Dropdown(
                                    id='retention-dropdown',
                                    options=[
                                        {'label': '7 days', 'value': 7},
                                        {'label': '30 days (default)', 'value': 30},
                                        {'label': '90 days', 'value': 90}
                                    ],
                                    value=30,
                                    className="mb-3"
                                ),
                            ]),

                            # Alert threshold
                            html.Div([
                                html.Label("Anomaly Score Threshold", className="form-label"),
                                html.P("Adjust sensitivity of anomaly detection", className="small text-muted mb-2"),
                                dcc.Slider(
                                    id='anomaly-threshold-slider',
                                    min=0.5,
                                    max=0.9,
                                    step=0.01,
                                    value=0.7,
                                    marks={
                                        0.5: {'label': 'Low', 'style': {'color': '#77b0b1'}},
                                        0.7: {'label': 'Medium', 'style': {'color': '#ffc107'}},
                                        0.9: {'label': 'High', 'style': {'color': '#dc3545'}}
                                    },
                                    tooltip={"placement": "bottom", "always_visible": False},
                                    className="mb-3"
                                ),
                            ]),

                            # Display density - NEW
                            html.Div([
                                html.Label("Display Density", className="form-label"),
                                html.P("Adjust information density on dashboard", className="small text-muted mb-2"),
                                dcc.Dropdown(
                                    id='display-density-dropdown',
                                    options=[
                                        {'label': 'Compact - More data per screen', 'value': 'compact'},
                                        {'label': 'Comfortable (default) - Balanced', 'value': 'comfortable'},
                                        {'label': 'Spacious - Easier to read', 'value': 'spacious'}
                                    ],
                                    value='comfortable',
                                    className="mb-3"
                                ),
                            ]),

                            # Timezone configuration - NEW
                            html.Div([
                                html.Label("Timezone", className="form-label"),
                                html.P("Select your local timezone for accurate timestamps", className="small text-muted mb-2"),
                                dcc.Dropdown(
                                    id='timezone-dropdown',
                                    options=[
                                        {'label': 'UTC', 'value': 'UTC'},
                                        {'label': 'America/New_York (EST/EDT)', 'value': 'America/New_York'},
                                        {'label': 'America/Chicago (CST/CDT)', 'value': 'America/Chicago'},
                                        {'label': 'America/Denver (MST/MDT)', 'value': 'America/Denver'},
                                        {'label': 'America/Los_Angeles (PST/PDT)', 'value': 'America/Los_Angeles'},
                                        {'label': 'Europe/London (GMT/BST)', 'value': 'Europe/London'},
                                        {'label': 'Europe/Paris (CET/CEST)', 'value': 'Europe/Paris'},
                                        {'label': 'Asia/Tokyo (JST)', 'value': 'Asia/Tokyo'},
                                        {'label': 'Asia/Shanghai (CST)', 'value': 'Asia/Shanghai'},
                                        {'label': 'Australia/Sydney (AEDT/AEST)', 'value': 'Australia/Sydney'}
                                    ],
                                    value='UTC',
                                    className="mb-3"
                                ),
                            ]),

                            # Per-alert notification preferences - NEW
                            html.Div([
                                html.Label("Alert Notification Preferences", className="form-label"),
                                html.P("Choose which alert types trigger notifications", className="small text-muted mb-2"),
                                dbc.Checklist(
                                    id='alert-notification-prefs',
                                    options=[
                                        {'label': ' High Severity Alerts (Critical threats)', 'value': 'high'},
                                        {'label': ' Medium Severity Alerts (Warnings)', 'value': 'medium'},
                                        {'label': ' Low Severity Alerts (Info)', 'value': 'low'},
                                        {'label': ' IoT Security Alerts (Vulnerable devices)', 'value': 'iot_security'},
                                        {'label': ' New Device Discovered', 'value': 'new_device'},
                                        {'label': ' Excessive Traffic Alerts', 'value': 'traffic'},
                                        {'label': ' Suspicious Port Activity', 'value': 'port'}
                                    ],
                                    value=['high', 'medium', 'iot_security', 'new_device'],
                                    inline=False,
                                    className="mb-3"
                                ),
                            ]),

                            html.Hr(),

                            # Dashboard Tour
                            html.Div([
                                html.H6("Dashboard Tour", className="mb-2"),
                                html.P("Restart the interactive tour to learn about dashboard features.", className="small text-muted"),
                                dbc.Button([html.I(className="fa fa-question-circle me-2"), "Restart Tour"],
                                          id="restart-tour-button", color="info", outline=True, className="w-100 mb-3")
                            ]),

                            # Save preferences
                            dbc.Button([html.I(className="fa fa-save me-2"), "Save Preferences"],
                                      id="save-preferences-btn", color="success", className="w-100"),
                            html.Div(id='preferences-status', className="mt-2")
                        ])
                    ], className="cyber-card")
                ], title="⚙️ Dashboard Preferences", class_name="cyber-accordion-item"),

                # IoT Protocol Dashboard - NEW
                dbc.AccordionItem([
                    dbc.Card([
                        dbc.CardHeader("📡 IoT Protocol Activity"),
                        dbc.CardBody([
                            html.Div(id='iot-protocol-dashboard', children=[
                                dbc.Alert([
                                    html.I(className="fa fa-check-circle me-2"),
                                    "IoT Protocol Analysis is now active! This dashboard monitors MQTT, CoAP, and Zigbee traffic."
                                ], color="success"),
                                html.Div(id='mqtt-coap-stats'),
                                html.Div(id='protocol-charts')
                            ])
                        ])
                    ], className="cyber-card")
                ], title="📡 IoT Protocol Analysis", class_name="cyber-accordion-item"),

                # IoT Threat Intelligence - NEW
                dbc.AccordionItem([
                    dbc.Card([
                        dbc.CardHeader("🛡️ IoT Threat Detection"),
                        dbc.CardBody([
                            html.Div(id='iot-threat-dashboard', children=[
                                dbc.Alert([
                                    html.I(className="fa fa-shield-alt me-2"),
                                    "Advanced threat detection active: Mirai, botnet, and DDoS monitoring enabled."
                                ], color="info"),
                                html.Div(id='threat-detection-stats'),
                                html.Div(id='botnet-ddos-tables')
                            ])
                        ])
                    ], className="cyber-card")
                ], title="🛡️ IoT Threat Intelligence", class_name="cyber-accordion-item"),

                # Privacy Monitoring - NEW
                dbc.AccordionItem([
                    dbc.Card([
                        dbc.CardHeader("🔒 Privacy & Data Monitoring"),
                        dbc.CardBody([
                            html.Div(id='privacy-dashboard', children=[
                                html.Div(id='privacy-score-section'),
                                html.Div(id='cloud-tracking-section'),
                                html.Div(id='tracker-detection-section')
                            ])
                        ])
                    ], className="cyber-card")
                ], title="🔒 Privacy Monitoring", class_name="cyber-accordion-item"),

                # Smart Home Context - NEW
                dbc.AccordionItem([
                    dbc.Card([
                        dbc.CardHeader("🏠 Smart Home Overview"),
                        dbc.CardBody([
                            html.Div(id='smart-home-dashboard', children=[
                                html.Div(id='hub-detection-section'),
                                html.Div(id='ecosystem-section'),
                                html.Div(id='room-management-section')
                            ])
                        ])
                    ], className="cyber-card")
                ], title="🏠 Smart Home Context", class_name="cyber-accordion-item"),

                # Network Segmentation - NEW
                dbc.AccordionItem([
                    dbc.Card([
                        dbc.CardHeader("🌐 Network Segmentation"),
                        dbc.CardBody([
                            html.Div(id='segmentation-dashboard', children=[
                                html.Div(id='segmentation-stats'),
                                html.Div(id='vlan-recommendations'),
                                html.Div(id='segmentation-violations')
                            ])
                        ])
                    ], className="cyber-card")
                ], title="🌐 Network Segmentation", class_name="cyber-accordion-item"),

                # Firmware & Lifecycle - NEW
                dbc.AccordionItem([
                    dbc.Card([
                        dbc.CardHeader("⚙️ Firmware & Lifecycle"),
                        dbc.CardBody([
                            html.Div(id='firmware-dashboard', children=[
                                html.Div(id='firmware-status-section'),
                                html.Div(id='eol-devices-section'),
                                html.Div(id='provisioning-section')
                            ])
                        ])
                    ], className="cyber-card")
                ], title="⚙️ Firmware Management", class_name="cyber-accordion-item"),

                # Educational Content - NEW
                dbc.AccordionItem([
                    dbc.Card([
                        dbc.CardHeader("📚 IoT Security Education"),
                        dbc.CardBody([
                            html.Div(id='education-dashboard', children=[
                                dbc.Alert([
                                    html.I(className="fa fa-graduation-cap me-2"),
                                    "Learn about IoT threats like Mirai botnet, unauthorized cloud uploads, and more!"
                                ], color="warning"),
                                html.Div(id='threat-scenarios-section'),
                                html.Div(id='security-tips-section')
                            ])
                        ])
                    ], className="cyber-card")
                ], title="📚 Security Education", class_name="cyber-accordion-item")
            ], start_collapsed=True, className="mt-3 cyber-accordion")
        ])
    ]),

    # Hidden Components & Modals
    WebSocket(id="ws", url="ws://127.0.0.1:8050/ws"),
    dcc.Interval(id='refresh-interval', interval=10*1000, n_intervals=0),  # 10 second refresh for IoT stats
    dcc.Store(id='alert-filter', data='all'),
    dcc.Store(id='selected-device-ip', data=None),
    dcc.Store(id='theme-store', storage_type='local', data={'theme': 'cyberpunk'}),
    dcc.Store(id='voice-alert-store', storage_type='local'),
    dcc.Store(id='announced-alerts-store', storage_type='session', data={}),
    dcc.Store(id='onboarding-store', storage_type='local'),
    dcc.Store(id='onboarding-step-store', data=0),
    dcc.Store(id='keyboard-shortcut-store', data=None),

    # Onboarding Modal
    dbc.Modal([
        dbc.ModalHeader(dbc.ModalTitle(id='onboarding-title')),
        dbc.ModalBody(id='onboarding-body'),
        dbc.ModalFooter([
            dbc.Button("Previous", id="onboarding-prev", color="secondary", className="me-auto cyber-button", disabled=True),
            dbc.Button("Next", id="onboarding-next", color="primary", className="cyber-button")
        ]),
    ], id="onboarding-modal", is_open=False, backdrop="static", size="lg"),

    # Edit Device Modal - NEW
    dbc.Modal([
        dbc.ModalHeader(dbc.ModalTitle("Edit Device")),
        dbc.ModalBody(id="edit-device-modal-body"),
        dbc.ModalFooter([
            dbc.Button("Save Changes", id="save-device-changes-btn", color="primary"),
            dbc.Button("Cancel", id="cancel-edit-device-btn", color="secondary"),
        ]),
    ], id="edit-device-modal", is_open=False, size="lg"),

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

    # Edit Device Modal - NEW
    dbc.Modal([
        dbc.ModalHeader(dbc.ModalTitle("Edit Device")),
        dbc.ModalBody(id="edit-device-modal-body"),
        dbc.ModalFooter([
            dbc.Button("Save Changes", id="save-device-changes-btn", color="primary"),
            dbc.Button("Cancel", id="cancel-edit-device-btn", color="secondary"),
        ]),
    ], id="edit-device-modal", is_open=False, size="lg"),

    html.Div(id="toast-container", style={"position": "fixed", "top": 66, "right": 10, "width": 350, "zIndex": 9999}),

    dbc.Offcanvas([
        dcc.Loading(id="notification-loader", type="default", children=html.Div(id="notification-drawer-body"))
    ], id="notification-drawer", title="Notifications", is_open=False, placement="end", backdrop=True, scrollable=True,
       className="notification-drawer-custom"),

    html.Div(id='backdrop-overlay', style={'position': 'fixed', 'top': 0, 'left': 0, 'width': '100%', 'height': '100%', 'backgroundColor': 'rgba(0,0,0,0.5)', 'display': 'none', 'zIndex': 1040}),


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
# MAIN APP LAYOUT - WITH AUTHENTICATION
# ============================================================================

app.layout = html.Div([
    dcc.Location(id='url', refresh=False),
    dcc.Store(id='user-session', storage_type='session'),
    html.Div(id='page-content')
])

# ============================================================================
# EDIT DEVICE CALLBACKS
# ============================================================================

@app.callback(
    [Output('edit-device-modal', 'is_open'),
     Output('edit-device-modal-body', 'children')],
    [Input({'type': 'edit-device-btn', 'ip': ALL}, 'n_clicks'),
     Input('cancel-edit-device-btn', 'n_clicks')],
    [State('edit-device-modal', 'is_open')],
    prevent_initial_call=True
)
def open_edit_device_modal(n_clicks, cancel_clicks, is_open):
    ctx = callback_context
    if not ctx.triggered or (all(c is None for c in n_clicks) and cancel_clicks is None):
        raise dash.exceptions.PreventUpdate

    triggered_id = ctx.triggered_id

    if triggered_id == 'cancel-edit-device-btn':
        return False, None

    if not isinstance(triggered_id, dict):
        return False, None

    try:
        ip = triggered_id['ip']
        logger.info(f"Editing device with IP: {ip}")

        device = db_manager.get_device(ip)
        if not device:
            logger.error(f"Device not found for IP: {ip}")
            return True, dbc.Alert("Device not found.", color="danger")
        logger.info(f"Device details fetched for {ip}")

        all_groups = group_manager.get_all_groups()
        group_options = [{'label': g['name'], 'value': g['id']} for g in all_groups]
        logger.info(f"All groups fetched: {len(all_groups)} groups")

        device_groups = group_manager.get_device_groups(ip)
        current_group_id = device_groups[0]['id'] if device_groups else None
        logger.info(f"Current group for {ip}: {current_group_id}")

        form = dbc.Form([
            dcc.Store(id='edit-device-ip', data=ip),
            dbc.Row([
                dbc.Label("Custom Name", width=2),
                dbc.Col(
                    dbc.Input(
                        id='edit-device-name',
                        value=device.get('custom_name') or device.get('device_name') or ip
                    ),
                    width=10,
                ),
            ], className="mb-3"),
            dbc.Row([
                dbc.Label("Device Type", width=2),
                dbc.Col(
                    dcc.Dropdown(
                        id='edit-device-type',
                        options=[{'label': k.replace('_', ' ').title(), 'value': k} for k in DEVICE_TYPE_ICONS.keys()],
                        value=device.get('device_type', 'unknown')
                    ),
                    width=10,
                ),
            ], className="mb-3"),
            dbc.Row([
                dbc.Label("Device Group", width=2),
                dbc.Col(
                    dcc.Dropdown(
                        id='edit-device-group',
                        options=group_options,
                        value=current_group_id
                    ),
                    width=10,
                ),
            ], className="mb-3"),
            dbc.Row([
                dbc.Label("Notes", width=2),
                dbc.Col(
                    dbc.Textarea(
                        id='edit-device-notes',
                        value=device.get('notes', ''),
                        style={'height': '100px'}
                    ),
                    width=10,
                ),
            ]),
        ])

        logger.info(f"Form created for {ip}. Opening modal.")
        return True, form

    except Exception as e:
        logger.error(f"Error in open_edit_device_modal: {e}", exc_info=True)
        return True, dbc.Alert(f"An error occurred: {e}", color="danger")


@app.callback(
    [Output('edit-device-modal', 'is_open', allow_duplicate=True),
     Output('device-management-table', 'children', allow_duplicate=True)],
    [Input('save-device-changes-btn', 'n_clicks')],
    [State('edit-device-ip', 'data'),
     State('edit-device-name', 'value'),
     State('edit-device-type', 'value'),
     State('edit-device-group', 'value'),
     State('edit-device-notes', 'value')],
    prevent_initial_call=True
)
def save_device_changes(n_clicks, ip, name, device_type, group_id, notes):
    if not n_clicks:
        raise dash.exceptions.PreventUpdate

    db_manager.update_device_metadata(device_ip=ip, custom_name=name, device_type=device_type, notes=notes)

    if group_id:
        current_groups = group_manager.get_device_groups(ip)
        for group in current_groups:
            group_manager.remove_device_from_group(ip, group['id'])
        group_manager.add_device_to_group(ip, group_id)

    return False, load_device_management_table(1)

# ============================================================================
# CALLBACKS - HEADER & NOTIFICATIONS
# ============================================================================

def get_latest_alerts_content():
    """Helper function to fetch and format recent alerts for the notification drawer."""
    conn = get_db_connection()
    recent_alerts_raw = []
    if conn:
        try:
            query = """
                SELECT a.id, a.timestamp, a.device_ip, d.device_name, a.severity,
                    a.anomaly_score, a.explanation, a.top_features, a.acknowledged, d.is_trusted
                FROM alerts a LEFT JOIN devices d ON a.device_ip = d.device_ip
                WHERE a.timestamp > datetime('now', '-24 hours') AND a.acknowledged = 0
                ORDER BY a.timestamp DESC
                LIMIT 10
            """
            df_alerts = pd.read_sql_query(query, conn)
            recent_alerts_raw = df_alerts.to_dict('records')
        except (sqlite3.Error, pd.io.sql.DatabaseError) as e:
            logger.error(f"Error fetching alerts for notification drawer: {e}")
        finally:
            conn.close()

    if not recent_alerts_raw:
        return [dbc.Alert("No new alerts.", color="info")]
    else:
        drawer_content = []
        for alert in recent_alerts_raw:
            device_name = alert.get('device_name') or alert.get('device_ip')
            severity = alert.get('severity', 'medium')
            config = SEVERITY_CONFIG.get(severity, SEVERITY_CONFIG['medium'])

            time_ago = "just now"
            try:
                alert_time = datetime.fromisoformat(alert['timestamp'])
                now = datetime.now()
                diff = now - alert_time
                if diff.seconds < 60:
                    time_ago = f"{diff.seconds} seconds ago"
                elif diff.days == 0:
                    minutes = diff.seconds // 60
                    time_ago = f"{minutes} minutes ago"
                elif diff.days < 7:
                    time_ago = f"{diff.days} days ago"
                else:
                    time_ago = alert_time.strftime('%Y-%m-%d %H:%M')
            except ValueError:
                pass # Invalid timestamp format

            drawer_content.append(
                dbc.Card([
                    dbc.CardBody([
                        html.Div([
                            html.Strong(device_name),
                            html.Small(time_ago, className="text-muted ms-auto")
                        ], className="d-flex justify-content-between mb-1"),
                        html.P(alert.get('explanation'), className="small mb-0 text-truncate"),
                        dbc.Button("View Details", size="sm", color=config['color'], outline=True,
                                   className="mt-2", id={'type': 'alert-detail-btn', 'index': int(alert['id'])})
                    ])
                ], color=config['color'], inverse=True, className="mb-2 shadow-sm notification-card")
            )
    return drawer_content

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
    [Output('notification-badge', 'children'),
     Output('notification-drawer-body', 'children', allow_duplicate=True)],
    Input('ws', 'message'),
    prevent_initial_call=True
)
def update_notifications_from_ws(ws_message):
    if ws_message is None:
        return dash.no_update, dash.no_update
    alert_count = ws_message.get('alert_count', 0)
    badge_count = "" if alert_count == 0 else str(alert_count)

    # This callback only updates the badge and does not re-render the drawer content
    # unless a fresh open is triggered via the bell button or a click outside.
    return badge_count, dash.no_update

@app.callback(
    [Output("notification-drawer", "is_open"),
     Output("notification-drawer-body", "children", allow_duplicate=True)],
    [Input("notification-bell-button", "n_clicks")],
    [State("notification-drawer", "is_open")],
    prevent_initial_call=True,
)
def toggle_notification_drawer(n_clicks, is_open):
    if n_clicks:
        if not is_open:
            # If opening, load fresh alerts
            return not is_open, get_latest_alerts_content()
        # If closing, no need to update content
        return not is_open, dash.no_update
    return is_open, dash.no_update

# Clientside callback to close offcanvas on outside click
app.clientside_callback(
    """
    function(pathname) {
        // This is a dummy output that is never used.
        // It's here because clientside callbacks must have at least one output.
        // The real work is done in the event listener.
        const offcanvas = document.getElementById('notification-drawer');
        const bellButton = document.getElementById('notification-bell-button');

        document.addEventListener('click', function(event) {
            // Check if the offcanvas is open
            if (offcanvas && offcanvas.classList.contains('show')) {
                // Check if the click is outside the offcanvas and not on the bell button
                if (!offcanvas.contains(event.target) && !bellButton.contains(event.target)) {
                    // Trigger a click on the backdrop to close the offcanvas
                    const backdrop = document.querySelector('.offcanvas-backdrop');
                    if (backdrop) {
                        backdrop.click();
                    }
                }
            }
        });

        return window.dash_clientside.no_update; // Return no_update
    }
    """,
    Output('dummy-output-clientside-callback', 'children'), # Output to dummy div
    Input('url', 'pathname'),
    prevent_initial_call=False
)

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
    [Input({'type': 'device-card', 'ip': ALL}, 'n_clicks'),
     Input({'type': 'device-list-item', 'ip': ALL}, 'n_clicks'),
     Input({'type': 'view-device-btn', 'ip': ALL}, 'n_clicks'),
     Input('network-graph', 'tapNodeData'),
     Input('device-details-close-btn', 'n_clicks')],
    [State('device-details-modal', 'is_open'),
     State('selected-device-ip', 'data')],
    prevent_initial_call=True
)
def toggle_device_details(card_clicks, list_clicks, view_clicks, tap_data, close_click, is_open, current_ip):
    ctx = callback_context
    if not ctx.triggered or not ctx.triggered[0].get('value'):
        return False, "", "", None

    triggered_id = ctx.triggered_id

    # Handle close button
    if triggered_id == 'device-details-close-btn':
        return False, "", "", None

    # Determine which device was clicked
    device_ip = None

    if isinstance(triggered_id, dict):
        device_ip = triggered_id.get('ip')
    elif triggered_id == 'network-graph.tapNodeData' and tap_data:
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
    Input({'type': 'device-trust-switch', 'ip': ALL}, 'value'),
    prevent_initial_call=True
)
def toggle_device_trust(value):
    ctx = callback_context
    if not ctx.triggered:
        raise dash.exceptions.PreventUpdate

    triggered_id = ctx.triggered_id
    if not isinstance(triggered_id, dict):
        return dbc.Toast("Invalid trigger for trust switch.", header="Error", icon="danger", duration=3000)

    try:
        device_ip = triggered_id['ip']
        is_trusted = ctx.triggered[0]['value']
    except (TypeError, KeyError) as e:
        logger.error(f"Error parsing trust switch ID or value: {e}")
        return dbc.Toast("Error processing request.", header="Error", icon="danger", duration=3000)

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
        db_manager.set_device_blocked(device_ip, new_blocked_status)

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
    Input('url', 'pathname'),
    prevent_initial_call=True
)
def load_email_settings(pathname):
    """Load email settings for the current user."""
    if not current_user.is_authenticated:
        return False, '', '', '', '', '', "DISABLED", "secondary"

    # Fetch user preference for email enabled
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT preference_value FROM user_preferences WHERE user_id = ? AND preference_key = 'email_enabled'", (current_user.id,))
        result = cursor.fetchone()
        conn.close()

        # If preference is stored, use it. Otherwise, use env var as default.
        if result:
            enabled = result[0].lower() == 'true'
        else:
            enabled = os.environ.get('EMAIL_ENABLED', 'false').lower() == 'true'

    except Exception as e:
        logger.error(f"Error loading email preference from DB: {e}")
        enabled = os.environ.get('EMAIL_ENABLED', 'false').lower() == 'true'

    # Load other settings from environment variables for display
    smtp_host = os.environ.get('EMAIL_SMTP_HOST', '')
    smtp_port = os.environ.get('EMAIL_SMTP_PORT', '')
    smtp_user = os.environ.get('EMAIL_SMTP_USER', '')
    sender_email = os.environ.get('EMAIL_SENDER_EMAIL', 'iotsentinel908@gmail.com')
    recipient_email = os.environ.get('EMAIL_RECIPIENT_EMAIL', '')

    # Determine status badge
    if enabled and all([smtp_host, smtp_port, smtp_user, sender_email, recipient_email]):
        badge_text = "ENABLED"
        badge_color = "success"
    elif enabled:
        badge_text = "INCOMPLETE"
        badge_color = "warning"
    else:
        badge_text = "DISABLED"
        badge_color = "danger"

    return enabled, smtp_host, smtp_port, smtp_user, sender_email, recipient_email, badge_text, badge_color

@app.callback(
    [Output('email-settings-status', 'children'),
     Output('email-status-badge', 'children', allow_duplicate=True),
     Output('email-status-badge', 'color', allow_duplicate=True)],
    Input('save-email-settings-btn', 'n_clicks'),
    [State('email-enabled-switch', 'value')],
    prevent_initial_call=True
)
def save_email_settings(n_clicks, enabled):
    """Save the enabled state of email notifications for the current user."""
    if n_clicks is None or not current_user.is_authenticated:
        raise dash.exceptions.PreventUpdate

    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO user_preferences (user_id, preference_key, preference_value)
            VALUES (?, ?, ?)
            ON CONFLICT(user_id, preference_key) DO UPDATE SET preference_value = excluded.preference_value
        """, (current_user.id, 'email_enabled', str(enabled)))
        conn.commit()
        conn.close()

        logger.info(f"Email 'enabled' preference for user {current_user.id} set to {enabled}")

        status_msg = dbc.Alert("✅ Email notification setting saved!", color="success", dismissable=True)

        # Update badge based on new state
        if enabled:
            badge_text = "ENABLED"
            badge_color = "success"
        else:
            badge_text = "DISABLED"
            badge_color = "danger"

        return status_msg, badge_text, badge_color

    except Exception as e:
        logger.error(f"Error saving email preference: {e}")
        return dbc.Alert(f"❌ Error saving setting: {e}", color="danger", dismissable=True), "ERROR", "danger"
@app.callback(
    Output('email-settings-status', 'children', allow_duplicate=True),
    Input('test-email-btn', 'n_clicks'),
    prevent_initial_call=True
)
def send_test_email(n_clicks):
    """Send a test email to verify configuration from environment variables"""
    if n_clicks is None:
        raise dash.exceptions.PreventUpdate

    try:
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart
        from datetime import datetime

        # Load from environment variables
        smtp_host = os.environ.get('EMAIL_SMTP_HOST')
        smtp_port = os.environ.get('EMAIL_SMTP_PORT')
        smtp_user = os.environ.get('EMAIL_SMTP_USER')
        smtp_password = os.environ.get('EMAIL_SMTP_PASSWORD')
        sender_email = os.environ.get('EMAIL_SENDER_EMAIL', 'iotsentinel908@gmail.com')
        recipient_email = os.environ.get('EMAIL_RECIPIENT_EMAIL')

        # Validate inputs
        if not all([smtp_host, smtp_port, smtp_user, smtp_password, sender_email, recipient_email]):
            return dbc.Alert([
                html.I(className="fa fa-exclamation-triangle me-2"),
                "Please ensure all email-related environment variables are set in your .env file."
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
        server = smtplib.SMTP(smtp_host, int(smtp_port), timeout=60)
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
# AUTHENTICATION CALLBACKS
# ============================================================================

@app.callback(
    Output('page-content', 'children'),
    [Input('url', 'pathname')],
    prevent_initial_call=False
)
def display_page(pathname):
    """Route to login or dashboard based on authentication"""
    # Check if user is authenticated
    if current_user.is_authenticated:
        # User is logged in
        if pathname == '/logout':
            logout_user()
            return login_layout
        # Show dashboard for any other path when authenticated
        return dashboard_layout
    else:
        # User not logged in, show login page
        return login_layout


@app.callback(
    [Output('login-alert', 'children'),
     Output('login-alert', 'is_open'),
     Output('login-alert', 'color'),
     Output('url', 'pathname', allow_duplicate=True)],
    [Input('login-button', 'n_clicks'),
     Input('login-password', 'n_submit')],
    [State('login-username', 'value'),
     State('login-password', 'value')],
    prevent_initial_call=True
)
def handle_login(n_clicks, n_submit, username, password):
    """Handle login button click or Enter key"""
    if n_clicks is None and n_submit is None:
        raise dash.exceptions.PreventUpdate

    # Validate inputs
    if not username or not password:
        return "Please enter both username and password", True, "warning", dash.no_update

    # Check if username is locked out due to too many failed attempts
    is_locked, remaining_time = login_rate_limiter.is_locked_out(username)
    if is_locked:
        minutes = remaining_time // 60
        seconds = remaining_time % 60
        logger.warning(f"Login attempt for locked account '{username}' (locked for {minutes}m {seconds}s)")
        return (
            f"Too many failed attempts. Account locked for {minutes} minute(s) and {seconds} second(s).",
            True,
            "danger",
            dash.no_update
        )

    # Verify credentials
    user = auth_manager.verify_user(username, password)

    if user:
        # Login successful - reset rate limiter for this username
        login_rate_limiter.record_successful_login(username)
        login_user(user)
        logger.info(f"User '{username}' logged in successfully")
        return "Login successful! Loading dashboard...", True, "success", "/"
    else:
        # Login failed - record failed attempt
        is_now_locked, remaining_attempts = login_rate_limiter.record_failed_attempt(username)

        if is_now_locked:
            logger.warning(f"Account '{username}' locked due to too many failed attempts")
            return (
                "Too many failed attempts. Account locked for 5 minutes.",
                True,
                "danger",
                dash.no_update
            )
        else:
            logger.warning(f"Failed login attempt for username '{username}' ({remaining_attempts} attempts remaining)")
            return (
                f"Invalid username or password. {remaining_attempts} attempt(s) remaining before lockout.",
                True,
                "danger",
                dash.no_update
            )


# Password toggle callbacks for login page
@app.callback(
    [Output('login-password', 'type'),
     Output('login-password-toggle', 'className')],
    Input('login-password-toggle-btn', 'n_clicks'),
    State('login-password', 'type'),
    prevent_initial_call=True
)
def toggle_login_password(n_clicks, current_type):
    """Toggle password visibility on login page"""
    if current_type == 'password':
        return 'text', 'fa fa-eye-slash'
    return 'password', 'fa fa-eye'


@app.callback(
    [Output('register-password', 'type'),
     Output('register-password-toggle', 'className')],
    Input('register-password-toggle-btn', 'n_clicks'),
    State('register-password', 'type'),
    prevent_initial_call=True
)
def toggle_register_password(n_clicks, current_type):
    """Toggle password visibility on register page"""
    if current_type == 'password':
        return 'text', 'fa fa-eye-slash'
    return 'password', 'fa fa-eye'


@app.callback(
    [Output('register-password-confirm', 'type'),
     Output('register-password-confirm-toggle', 'className')],
    Input('register-password-confirm-toggle-btn', 'n_clicks'),
    State('register-password-confirm', 'type'),
    prevent_initial_call=True
)
def toggle_register_confirm_password(n_clicks, current_type):
    """Toggle confirm password visibility"""
    if current_type == 'password':
        return 'text', 'fa fa-eye-slash'
    return 'password', 'fa fa-eye'


# Registration callback
@app.callback(
    [Output('register-alert', 'children'),
     Output('register-alert', 'is_open'),
     Output('register-alert', 'color'),
     Output('auth-tabs', 'active_tab', allow_duplicate=True)],
    Input('register-button', 'n_clicks'),
    [State('register-username', 'value'),
     State('register-password', 'value'),
     State('register-password-confirm', 'value'),
     State('register-role', 'value')],
    prevent_initial_call=True
)
def handle_registration(n_clicks, username, password, password_confirm, role):
    """Handle user registration"""
    if n_clicks is None:
        raise dash.exceptions.PreventUpdate

    # Validation
    if not username or not password or not password_confirm:
        return "Please fill in all fields", True, "warning", dash.no_update

    if len(username) < 3:
        return "Username must be at least 3 characters", True, "warning", dash.no_update

    if len(password) < 4:
        return "Password must be at least 4 characters", True, "warning", dash.no_update

    if password != password_confirm:
        return "Passwords do not match", True, "danger", dash.no_update

    # Attempt to create user
    success = auth_manager.create_user(username, password, role)

    if success:
        logger.info(f"New user registered: {username} (role: {role})")
        return "Account created successfully! Please login.", True, "success", "login-tab"
    else:
        return "Username already exists", True, "danger", dash.no_update


# Change Password callback
@app.callback(
    [Output('change-password-status', 'children'),
     Output('current-password', 'value'),
     Output('new-password', 'value'),
     Output('new-password-confirm', 'value')],
    Input('change-password-btn', 'n_clicks'),
    [State('current-password', 'value'),
     State('new-password', 'value'),
     State('new-password-confirm', 'value')],
    prevent_initial_call=True
)
def change_password(n_clicks, current_pwd, new_pwd, new_pwd_confirm):
    """Handle password change for logged-in user"""
    if n_clicks is None:
        raise dash.exceptions.PreventUpdate

    # Check if user is authenticated
    if not current_user.is_authenticated:
        return dbc.Alert("You must be logged in to change password", color="danger"), dash.no_update, dash.no_update, dash.no_update

    # Validation
    if not current_pwd or not new_pwd or not new_pwd_confirm:
        return dbc.Alert("Please fill in all fields", color="warning"), dash.no_update, dash.no_update, dash.no_update

    if len(new_pwd) < 4:
        return dbc.Alert("New password must be at least 4 characters", color="warning"), dash.no_update, dash.no_update, dash.no_update

    if new_pwd != new_pwd_confirm:
        return dbc.Alert("New passwords do not match", color="danger"), dash.no_update, dash.no_update, dash.no_update

    # Verify current password
    user = auth_manager.verify_user(current_user.username, current_pwd)
    if not user:
        return dbc.Alert("Current password is incorrect", color="danger"), dash.no_update, dash.no_update, dash.no_update

    # Change password
    success = auth_manager.change_password(current_user.id, new_pwd)

    if success:
        logger.info(f"Password changed for user: {current_user.username}")
        return dbc.Alert([
            html.I(className="fa fa-check-circle me-2"),
            "Password changed successfully!"
        ], color="success"), "", "", ""
    else:
        return dbc.Alert("Error changing password. Please try again.", color="danger"), dash.no_update, dash.no_update, dash.no_update


# User list callback (Admin only)
@app.callback(
    Output('user-list-container', 'children'),
    Input('url', 'pathname'),
    prevent_initial_call=False
)
def display_user_list(pathname):
    """Display list of active users (admin only)"""
    if not current_user.is_authenticated:
        return html.Div()

    # Check if user is admin
    if not current_user.is_admin():
        return dbc.Alert("Only administrators can view user list", color="info", className="mt-3")

    # Get all users
    users = auth_manager.get_all_users()

    if not users:
        return html.P("No users found", className="text-muted")

    # Create user cards
    user_cards = []
    for user in users:
        user_cards.append(
            dbc.Card([
                dbc.CardBody([
                    dbc.Row([
                        dbc.Col([
                            html.H6([
                                html.I(className="fa fa-user me-2"),
                                user['username']
                            ]),
                            html.Small(f"Role: {user['role'].title()}", className="text-muted")
                        ], width=8),
                        dbc.Col([
                            dbc.Badge(
                                "Active" if user['is_active'] else "Inactive",
                                color="success" if user['is_active'] else "secondary",
                                className="float-end"
                            )
                        ], width=4)
                    ])
                ])
            ], className="mb-2", style={"backgroundColor": "var(--bg-tertiary)"})
        )

    return html.Div(user_cards)

# ============================================================================
# DEVICE MANAGEMENT & PREFERENCES CALLBACKS
# ============================================================================

@app.callback(
    Output('device-management-table', 'children'),
    Input('load-devices-btn', 'n_clicks'),
    prevent_initial_call=True
)
def load_device_management_table(n_clicks):
    """Load all devices for management"""
    devices = db_manager.get_all_devices()

    if not devices:
        return dbc.Alert("No devices found", color="info")

    # Create device management table
    rows = []
    for device in devices:
        device_ip = device['device_ip']
        device_type = device.get('device_type', 'unknown')
        manufacturer = device.get('manufacturer', 'Unknown')
        custom_name = device.get('custom_name') or device.get('device_name') or device_ip
        category = device.get('category', 'other')
        icon = device.get('icon', '❓')

        # Get device groups
        groups = db_manager.get_device_groups(device_ip)
        group_names = ', '.join([g['name'] for g in groups]) if groups else 'None'

        row = dbc.Card([
            dbc.CardBody([
                dbc.Row([
                    # Checkbox - NEW
                    dbc.Col([
                        dbc.Checkbox(
                            id={'type': 'device-checkbox', 'ip': device_ip},
                            className="device-select-checkbox"
                        )
                    ], width=1, className="d-flex align-items-center justify-content-center"),

                    # Icon & Name
                    dbc.Col([
                        html.Div([
                            html.Span(icon, style={'fontSize': '1.5rem', 'marginRight': '10px'}),
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
                        dbc.ButtonGroup([
                            dbc.Button([html.I(className="fa fa-edit")],
                                      id={'type': 'edit-device-btn', 'ip': device_ip},
                                      color="primary", size="sm", outline=True,
                                      title="Edit device"),
                            dbc.Button([html.I(className="fa fa-info-circle")],
                                      id={'type': 'view-device-btn', 'ip': device_ip},
                                      color="info", size="sm", outline=True,
                                      title="View details")
                        ], size="sm")
                    ], width=2, className="text-end")
                ])
            ])
        ], className="mb-2")

        rows.append(row)

    return html.Div([
        dbc.Row([
            dbc.Col([
                html.H6(f"Total Devices: {len(devices)}", className="mb-0")
            ], width=6),
        ], className="mb-3"),
        html.Div(rows, id='device-rows-container')
    ])


@app.callback(
    [Output('preferences-status', 'children'),
     Output('ws', 'message', allow_duplicate=True)],
    Input('save-preferences-btn', 'n_clicks'),
    [State('refresh-interval-dropdown', 'value'),
     State('retention-dropdown', 'value'),
     State('anomaly-threshold-slider', 'value'),
     State('display-density-dropdown', 'value'),
     State('timezone-dropdown', 'value'),
     State('alert-notification-prefs', 'value')],
    prevent_initial_call=True
)
def save_preferences(n_clicks, refresh_interval, retention, threshold, display_density, timezone, alert_prefs):
    """Save user preferences to database"""
    if not current_user.is_authenticated:
        return dbc.Alert("Please login to save preferences", color="warning"), dash.no_update

    # Save to user_preferences table
    user_id = current_user.id

    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        # Insert or update preferences
        preferences = {
            'refresh_interval': str(refresh_interval),
            'data_retention': str(retention),
            'anomaly_threshold': str(threshold),
            'display_density': display_density,
            'timezone': timezone,
            'alert_notifications': ','.join(alert_prefs) if alert_prefs else ''
        }

        for key, value in preferences.items():
            cursor.execute("""
                INSERT INTO user_preferences (user_id, preference_key, preference_value)
                VALUES (?, ?, ?)
                ON CONFLICT(user_id, preference_key) DO UPDATE SET preference_value = excluded.preference_value
            """, (user_id, key, value))

        conn.commit()
        conn.close()

        return dbc.Alert([
            html.I(className="fa fa-check-circle me-2"),
            "Preferences saved successfully! Alert notifications and other settings will apply on next refresh."
        ], color="success", dismissable=True), dash.no_update

    except Exception as e:
        logger.error(f"Error saving preferences: {e}")
        return dbc.Alert(f"Error saving preferences: {e}", color="danger", dismissable=True), dash.no_update


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


# Bulk Device Operations Callbacks - NEW
@app.callback(
    Output('bulk-action-status', 'children'),
    [Input('bulk-trust-btn', 'n_clicks'),
     Input('bulk-block-btn', 'n_clicks'),
     Input('bulk-delete-btn', 'n_clicks')],
    [State({'type': 'device-checkbox', 'ip': ALL}, 'value'),
     State({'type': 'device-checkbox', 'ip': ALL}, 'id')],
    prevent_initial_call=True
)
def handle_bulk_operations(trust_clicks, block_clicks, delete_clicks, checkbox_values, checkbox_ids):
    """Handle bulk device operations"""
    ctx = dash.callback_context
    if not ctx.triggered:
        return dash.no_update

    button_id = ctx.triggered[0]['prop_id'].split('.')[0]

    # Get selected device IPs
    selected_ips = [
        checkbox_ids[i]['ip']
        for i, checked in enumerate(checkbox_values)
        if checked
    ]

    if not selected_ips:
        return dbc.Alert("No devices selected", color="warning", duration=3000)

    try:
        count = len(selected_ips)

        if 'bulk-trust-btn' in button_id:
            # Trust selected devices
            for ip in selected_ips:
                db_manager.set_device_trust(ip, is_trusted=True)
            return dbc.Alert(f"✅ Trusted {count} device(s)", color="success", duration=3000)

        elif 'bulk-block-btn' in button_id:
            # Block selected devices
            for ip in selected_ips:
                db_manager.set_device_blocked(ip, is_blocked=True)
            return dbc.Alert(f"🚫 Blocked {count} device(s)", color="danger", duration=3000)

        elif 'bulk-delete-btn' in button_id:
            # Delete selected devices
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            for ip in selected_ips:
                cursor.execute("DELETE FROM devices WHERE device_ip = ?", (ip,))
            conn.commit()
            conn.close()
            return dbc.Alert(f"🗑️ Deleted {count} device(s)", color="warning", duration=3000)

    except Exception as e:
        logger.error(f"Bulk operation error: {e}")
        return dbc.Alert(f"Error: {e}", color="danger", duration=5000)

    return dash.no_update


@app.callback(
    [Output('bulk-trust-btn', 'disabled'),
     Output('bulk-block-btn', 'disabled'),
     Output('bulk-delete-btn', 'disabled')],
    Input({'type': 'device-checkbox', 'ip': ALL}, 'value')
)
def toggle_bulk_buttons(checkbox_values):
    """Enable/disable bulk action buttons based on selections"""
    has_selection = any(checkbox_values) if checkbox_values else False
    # Disabled = NOT has_selection
    return not has_selection, not has_selection, not has_selection



@app.callback(
    Output({'type': 'device-checkbox', 'ip': ALL}, 'checked'),
    Input('select-all-devices-checkbox', 'checked'),
    prevent_initial_call=True
)
def select_all_devices(select_all):
    """Select or deselect all device checkboxes"""
    if select_all is None:
        return dash.no_update

    # Get all device checkbox IDs
    all_checkbox_ids = callback_context.outputs_list[0]['id']

    # Return a list of True or False values for each checkbox
    return [select_all] * len(all_checkbox_ids)



# ============================================================================
# IOT-SPECIFIC FEATURE CALLBACKS
# ============================================================================

@app.callback(
    Output('mqtt-coap-stats', 'children'),
    [Input('refresh-interval', 'n_intervals')]
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
                ], width=4)
            )

        return dbc.Row(cards, className="mt-3")
    except Exception as e:
        logger.error(f"Error updating protocol stats: {e}")
        return dbc.Alert(f"Error loading protocol stats", color="warning")


@app.callback(
    Output('threat-detection-stats', 'children'),
    [Input('refresh-interval', 'n_intervals')]
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
                ], className="cyber-card text-center", style={"borderLeft": "4px solid #dc3545"})
            ], width=4),
            dbc.Col([
                dbc.Card([
                    dbc.CardBody([
                        html.H2(str(ddos_count), className="text-warning mb-0"),
                        html.P("⚡ DDoS Events", className="text-muted small")
                    ])
                ], className="cyber-card text-center", style={"borderLeft": "4px solid #ffc107"})
            ], width=4),
            dbc.Col([
                dbc.Card([
                    dbc.CardBody([
                        html.H2(str(summary.get('total_threats', 0)), className="text-info mb-0"),
                        html.P("📊 Total Threats", className="text-muted small")
                    ])
                ], className="cyber-card text-center", style={"borderLeft": "4px solid #17a2b8"})
            ], width=4)
        ], className="mt-3")
    except Exception as e:
        logger.error(f"Error updating threat stats: {e}")
        return dbc.Alert("No threat data available yet", color="info")


@app.callback(
    Output('privacy-score-section', 'children'),
    [Input('refresh-interval', 'n_intervals')]
)
def update_privacy_score(n):
    """Update overall privacy score."""
    try:
        conn = get_db_connection()
        if not conn:
            return dbc.Alert("Database connection failed", color="danger")

        cursor = conn.cursor()
        cursor.execute('''
            SELECT privacy_concern_level, COUNT(DISTINCT device_ip) as count
            FROM cloud_connections
            GROUP BY privacy_concern_level
        ''')

        concerns = {row['privacy_concern_level']: row['count'] for row in cursor.fetchall()}
        conn.close()

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
                html.H1(f"{privacy_score:.0f}", className=f"text-center text-{score_color} mb-1", style={"fontSize": "3rem"}),
                html.P("Privacy Score", className="text-center text-muted mb-1"),
                html.Small(f"{high_concern} of {total_devices} devices with privacy concerns",
                          className="text-center d-block text-muted")
            ])
        ], className="cyber-card mt-3", style={"borderLeft": "4px solid #6f42c1"})
    except Exception as e:
        logger.error(f"Error calculating privacy score: {e}")
        return dbc.Alert("Privacy monitoring active", color="info")


@app.callback(
    Output('segmentation-stats', 'children'),
    [Input('refresh-interval', 'n_intervals')]
)
def update_segmentation_stats(n):
    """Update network segmentation statistics."""
    try:
        conn = get_db_connection()
        if not conn:
            return dbc.Alert("Database connection failed", color="danger")

        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) as total FROM devices')
        total_devices = cursor.fetchone()['total']

        cursor.execute('''
            SELECT COUNT(DISTINCT device_ip) as segmented
            FROM device_segments
            WHERE current_segment = 1
        ''')
        segmented = cursor.fetchone()['segmented']

        cursor.execute('''
            SELECT COUNT(*) as violations
            FROM segmentation_violations
            WHERE timestamp >= datetime('now', '-24 hours')
        ''')
        violations = cursor.fetchone()['violations']

        conn.close()

        if total_devices == 0:
            return dbc.Alert("No devices detected yet", color="info")

        segmentation_pct = (segmented / total_devices) * 100

        return dbc.Row([
            dbc.Col([
                dbc.Card([
                    dbc.CardBody([
                        html.H3(str(segmented), className="text-success mb-0"),
                        html.P("✅ Segmented", className="text-muted small")
                    ])
                ], className="cyber-card text-center")
            ], width=3),
            dbc.Col([
                dbc.Card([
                    dbc.CardBody([
                        html.H3(str(total_devices - segmented), className="text-warning mb-0"),
                        html.P("⚠️ Unsegmented", className="text-muted small")
                    ])
                ], className="cyber-card text-center")
            ], width=3),
            dbc.Col([
                dbc.Card([
                    dbc.CardBody([
                        html.H3(f"{segmentation_pct:.0f}%", className="text-info mb-0"),
                        html.P("📊 Coverage", className="text-muted small")
                    ])
                ], className="cyber-card text-center")
            ], width=3),
            dbc.Col([
                dbc.Card([
                    dbc.CardBody([
                        html.H3(str(violations), className="text-danger mb-0"),
                        html.P("🚨 Violations", className="text-muted small")
                    ])
                ], className="cyber-card text-center")
            ], width=3)
        ], className="mt-3")
    except Exception as e:
        logger.error(f"Error updating segmentation stats: {e}")
        return dbc.Alert("Network segmentation monitoring active", color="info")


@app.callback(
    Output('firmware-status-section', 'children'),
    [Input('refresh-interval', 'n_intervals')]
)
def update_firmware_status(n):
    """Update firmware status overview."""
    try:
        conn = get_db_connection()
        if not conn:
            return dbc.Alert("Database connection failed", color="danger")

        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) as total FROM device_firmware_status')
        total = cursor.fetchone()['total']

        if total == 0:
            conn.close()
            return dbc.Alert([
                html.I(className="fa fa-microchip me-2"),
                "Firmware tracking will appear as devices are discovered and classified."
            ], color="info")

        cursor.execute('SELECT COUNT(*) as updates FROM device_firmware_status WHERE update_available = 1')
        updates_available = cursor.fetchone()['updates']

        cursor.execute('SELECT COUNT(*) as eol FROM device_firmware_status WHERE is_eol = 1')
        eol_devices = cursor.fetchone()['eol']

        conn.close()

        up_to_date = total - updates_available - eol_devices

        return dbc.Row([
            dbc.Col([
                dbc.Card([
                    dbc.CardBody([
                        html.H3(str(updates_available), className="text-primary mb-0"),
                        html.P("🔄 Updates Available", className="text-muted small")
                    ])
                ], className="cyber-card text-center")
            ], width=4),
            dbc.Col([
                dbc.Card([
                    dbc.CardBody([
                        html.H3(str(eol_devices), className="text-danger mb-0"),
                        html.P("⏰ End-of-Life", className="text-muted small")
                    ])
                ], className="cyber-card text-center")
            ], width=4),
            dbc.Col([
                dbc.Card([
                    dbc.CardBody([
                        html.H3(str(up_to_date), className="text-success mb-0"),
                        html.P("✅ Up-to-Date", className="text-muted small")
                    ])
                ], className="cyber-card text-center")
            ], width=4)
        ], className="mt-3")
    except Exception as e:
        logger.error(f"Error updating firmware status: {e}")
        return dbc.Alert("Firmware monitoring active", color="info")


@app.callback(
    Output('threat-scenarios-section', 'children'),
    [Input('refresh-interval', 'n_intervals')]
)
def update_threat_scenarios(n):
    """Display threat scenarios from educational library."""
    try:
        conn = get_db_connection()
        if not conn:
            return dbc.Alert("Database connection failed", color="danger")

        cursor = conn.cursor()
        cursor.execute('''
            SELECT scenario_name, category, severity, description
            FROM threat_scenarios
            ORDER BY severity DESC, created_at DESC
            LIMIT 5
        ''')

        scenarios = cursor.fetchall()
        conn.close()

        if not scenarios:
            return dbc.Alert([
                html.I(className="fa fa-book me-2"),
                "Educational threat scenarios will appear here. Run migration with --populate to load examples."
            ], color="info")

        cards = []
        severity_icons = {
            'critical': '🔴',
            'high': '🟠',
            'medium': '🟡',
            'low': '🟢'
        }
        severity_colors = {
            'critical': 'danger',
            'high': 'warning',
            'medium': 'info',
            'low': 'secondary'
        }

        for scenario in scenarios:
            icon = severity_icons.get(scenario['severity'], '⚪')
            cards.append(
                dbc.Card([
                    dbc.CardHeader([
                        html.Span(icon + " ", style={"fontSize": "1.2rem"}),
                        html.Strong(scenario['scenario_name']),
                        dbc.Badge(scenario['severity'].upper(),
                                color=severity_colors.get(scenario['severity'], 'secondary'),
                                className="ms-2")
                    ]),
                    dbc.CardBody([
                        html.P(scenario['description'], className="small mb-2"),
                        dbc.Badge(f"📂 {scenario['category']}", color="light", text_color="dark")
                    ])
                ], className="mb-2 cyber-card")
            )

        return html.Div(cards, className="mt-3")
    except Exception as e:
        logger.error(f"Error loading threat scenarios: {e}")
        return dbc.Alert("Educational content library active", color="info")


@app.callback(
    Output('security-tips-section', 'children'),
    [Input('refresh-interval', 'n_intervals')]
)
def update_security_tips(n):
    """Display security tips and best practices."""
    try:
        conn = get_db_connection()
        if not conn:
            return dbc.Alert("Database connection failed", color="danger")

        cursor = conn.cursor()
        cursor.execute('''
            SELECT tip_category, device_type, tip_title, tip_content,
                   importance, difficulty, time_required
            FROM security_tips
            ORDER BY
                CASE importance
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                END,
                CASE difficulty
                    WHEN 'easy' THEN 1
                    WHEN 'moderate' THEN 2
                    WHEN 'advanced' THEN 3
                END
            LIMIT 10
        ''')

        tips = cursor.fetchall()
        conn.close()

        if not tips:
            return dbc.Alert([
                html.I(className="fa fa-lightbulb me-2"),
                "Security tips will appear here."
            ], color="info")

        cards = []
        importance_colors = {
            'critical': 'danger',
            'high': 'warning',
            'medium': 'info',
            'low': 'secondary'
        }

        difficulty_icons = {
            'easy': '✅',
            'moderate': '⚙️',
            'advanced': '🔧'
        }

        for tip in tips:
            difficulty_icon = difficulty_icons.get(tip['difficulty'], '⚙️')
            cards.append(
                dbc.Card([
                    dbc.CardHeader([
                        html.Strong(f"{tip['tip_title']}", className="me-2"),
                        dbc.Badge(tip['importance'].upper(),
                                color=importance_colors.get(tip['importance'], 'secondary'),
                                className="me-2"),
                        dbc.Badge(f"{difficulty_icon} {tip['difficulty']}",
                                color="light", text_color="dark")
                    ]),
                    dbc.CardBody([
                        html.P(tip['tip_content'], className="small mb-2"),
                        html.Div([
                            dbc.Badge(f"🎯 {tip['device_type']}", color="primary", className="me-2"),
                            dbc.Badge(f"⏱️ {tip['time_required']}", color="light", text_color="dark")
                        ])
                    ])
                ], className="mb-2 cyber-card")
            )

        return html.Div([
            dbc.Alert([
                html.I(className="fa fa-shield-alt me-2"),
                f"Showing {len(tips)} actionable security recommendations"
            ], color="success", className="mb-3"),
            html.Div(cards)
        ], className="mt-3")

    except Exception as e:
        logger.error(f"Error loading security tips: {e}")
        return dbc.Alert("Security tips library active", color="info")


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

    # Check IoT Security Features status
    iot_features_status = "🔐 IoT Security Suite: "
    if iot_intelligence and iot_protocol_analyzer and iot_threat_detector:
        iot_features_status += "✅ FULLY OPERATIONAL"
    else:
        iot_features_status += "⚠️ PARTIALLY AVAILABLE (check logs)"
    logger.info(iot_features_status)
    logger.info("")

    logger.info("✨ NEW IOT SECURITY FEATURES:")
    logger.info("  ✓ 📡 IoT Protocol Analysis (MQTT, CoAP, Zigbee)")
    logger.info("  ✓ 🛡️ Threat Detection (Mirai, Botnets, DDoS)")
    logger.info("  ✓ 🔒 Privacy Monitoring (Cloud uploads, Trackers)")
    logger.info("  ✓ 🏠 Smart Home Context (Hub detection, Ecosystems)")
    logger.info("  ✓ 🌐 Network Segmentation (VLAN recommendations)")
    logger.info("  ✓ ⚙️ Firmware Lifecycle (Updates, EOL tracking)")
    logger.info("  ✓ 📚 Security Education (Threat scenarios)")
    logger.info("")

    logger.info("✨ CORE FEATURES:")
    logger.info("  ✓ Interactive onboarding wizard (6 steps)")
    logger.info("  ✓ Device details modal with trust management")
    logger.info("  ✓ Lockdown mode with confirmation")
    logger.info("  ✓ Keyboard shortcuts (N/D/A)")
    logger.info("  ✓ Clickable device cards & network graph")
    logger.info("")
    logger.info("📊 MONITORING CAPABILITIES:")
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
