"""
IoTSentinel Dashboard - Shared State & Utilities
=================================================
This module contains all shared state, service initializations, constants,
database helpers, UI helpers, and utility functions used across all dashboard tabs.

All tab modules and component modules import from here to avoid circular imports.
The `app` variable is set by app.py after Dash initialization.

NOTE: Services are also initialized in app.py independently. This is intentional:
app.py services run before callback registration; shared.py services provide
references for callback modules. Both are needed. A future optimization could
have app.py import services from shared.py instead.
"""
# Eventlet monkey-patching MUST be done before any other imports
import eventlet
eventlet.monkey_patch()

import base64
import json
import logging
import sqlite3
import math
import time
import threading
import subprocess
import smtplib
import random
import psutil
import re
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dash import dcc, html, Input, Output, State, callback_context, ALL, no_update
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
from dash_extensions import WebSocket
from flask_socketio import SocketIO

# Setup paths
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from config.config_manager import config
from database.db_manager import DatabaseManager
from utils.threat_intel import ThreatIntelligence
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask import request, redirect, session as flask_session, jsonify, send_file
from utils.auth import AuthManager, User
from utils.rate_limiter import LoginRateLimiter, RateLimiter
from utils.audit_logger import (
    AuditLogger, log_device_action, log_bulk_action,
    log_emergency_mode, log_user_action, log_settings_change
)
from utils.rbac_manager import (
    PermissionManager, can_export_data, can_manage_devices,
    can_block_devices, can_delete_data, ROLES
)
from utils.security_audit_logger import get_audit_logger
from utils.totp_manager import TOTPManager
from utils.oauth_handler import GoogleOAuthHandler, is_oauth_configured
from utils.webauthn_handler import WebAuthnHandler, is_webauthn_available

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

# Import sustainability and lifecycle features
from utils.sustainability_calculator import get_sustainability_calculator
from utils.hardware_lifecycle import HardwareLifecycleManager

# Import enhanced toast management system
from utils.toast_manager import ToastManager, TOAST_POSITION_STYLE, TOAST_DURATIONS

# Import chart factory for centralized chart generation
from utils.chart_factory import ChartFactory, SEVERITY_COLORS, RISK_COLORS

# Bootstrap badge-color mapping (use in dbc.Badge color= everywhere)
SEVERITY_BADGE_COLORS = {
    'critical': 'danger',
    'high': 'warning',
    'medium': 'info',
    'low': 'secondary',
}

# Import export helper for universal export functionality (CSV, JSON, PDF, Excel)
from utils.export_helpers import DashExportHelper

# Import innovation features
from utils.network_security_scorer import get_security_scorer
from utils.privacy_analyzer import get_privacy_analyzer

# Import Advanced Reporting & Analytics components
from utils.trend_analyzer import TrendAnalyzer
from utils.report_builder import ReportBuilder
from utils.report_templates import ReportTemplateManager
from alerts.report_scheduler import ReportScheduler

# Import Alert and Notification Services
from alerts.alert_service import AlertService
from alerts.notification_dispatcher import NotificationDispatcher
from alerts.email_notifier import EmailNotifier

# Import AI-Powered Intelligence components
from utils.ai_assistant import HybridAIAssistant
from ml.inference_engine import InferenceEngine
from ml.smart_recommender import SmartRecommender
from ml.traffic_forecaster import TrafficForecaster
from ml.attack_sequence_tracker import AttackSequenceTracker
from utils.nl_to_sql import NLtoSQLGenerator

load_dotenv()

# ============================================================================
# APP INSTANCE PLACEHOLDER
# ============================================================================
# This will be set by app.py after creating the Dash app instance.
# All tab/component modules import `app` from here to register callbacks.
app = None
socketio_instance = None

# ============================================================================
# COMPREHENSIVE LOGGING CONFIGURATION
# ============================================================================
log_dir = 'data/logs'
os.makedirs(log_dir, exist_ok=True)

# Standard formatter for all logs
log_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
audit_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

# 1. Main application logger (dashboard & general operations)
main_handler = logging.FileHandler(os.path.join(log_dir, 'iotsentinel.log'))
main_handler.setFormatter(log_formatter)
console_handler = logging.StreamHandler()
console_handler.setFormatter(log_formatter)

logging.basicConfig(
    level=logging.INFO,
    handlers=[main_handler, console_handler]
)
logger = logging.getLogger(__name__)

# 2. Audit logger (authentication, user actions, security events)
audit_file_logger = logging.getLogger('audit')
audit_file_logger.setLevel(logging.INFO)
audit_handler = logging.FileHandler(os.path.join(log_dir, 'audit.log'))
audit_handler.setFormatter(audit_formatter)
audit_file_logger.addHandler(audit_handler)

# 3. ML logger (machine learning, anomaly detection, forecasting)
ml_logger = logging.getLogger('ml')
ml_logger.setLevel(logging.INFO)
ml_handler = logging.FileHandler(os.path.join(log_dir, 'ml.log'))
ml_handler.setFormatter(log_formatter)
ml_logger.addHandler(ml_handler)

# 4. Alerts logger (alert generation, notifications, integrations)
alerts_logger = logging.getLogger('alerts')
alerts_logger.setLevel(logging.INFO)
alerts_handler = logging.FileHandler(os.path.join(log_dir, 'alerts.log'))
alerts_handler.setFormatter(log_formatter)
alerts_logger.addHandler(alerts_handler)

# 5. Hardware logger (GPIO, LED, physical monitoring)
hardware_logger = logging.getLogger('hardware')
hardware_logger.setLevel(logging.INFO)
hardware_handler = logging.FileHandler(os.path.join(log_dir, 'hardware.log'))
hardware_handler.setFormatter(log_formatter)
hardware_logger.addHandler(hardware_handler)

# 6. Database logger (DB operations, maintenance, queries)
db_logger = logging.getLogger('database')
db_logger.setLevel(logging.INFO)
db_handler = logging.FileHandler(os.path.join(log_dir, 'database.log'))
db_handler.setFormatter(log_formatter)
db_logger.addHandler(db_handler)

# 7. Error logger (centralized ERROR and CRITICAL from all modules)
error_logger = logging.getLogger('errors')
error_logger.setLevel(logging.ERROR)
error_handler = logging.FileHandler(os.path.join(log_dir, 'error.log'))
error_handler.setFormatter(log_formatter)
error_logger.addHandler(error_handler)

# 8. API logger (external API calls, webhooks, integrations)
api_logger = logging.getLogger('api')
api_logger.setLevel(logging.INFO)
api_handler = logging.FileHandler(os.path.join(log_dir, 'api.log'))
api_handler.setFormatter(log_formatter)
api_logger.addHandler(api_handler)

# Configure root logger to also send ERROR+ to error.log
logging.getLogger().addHandler(error_handler)

logger.info("=" * 70)
logger.info("IoTSentinel Logging System Initialized")
logger.info(f"Log Directory: {os.path.abspath(log_dir)}")
logger.info("Active Logs: iotsentinel.log, audit.log, ml.log, alerts.log,")
logger.info("             hardware.log, database.log, error.log, api.log")
logger.info("=" * 70)

# Import atexit for cleanup handlers
import atexit

# ============================================================================
# DATABASE & SERVICE INITIALIZATION
# ============================================================================

# Database setup
DB_PATH = config.get('database', 'path')
db_manager = DatabaseManager(DB_PATH)

# Initialize Audit Logger and Rate Limiter for security
audit_logger = AuditLogger(db_manager)
rate_limiter = RateLimiter(db_manager)

# Initialize Security Audit Logger for RBAC and compliance
security_audit_logger = get_audit_logger(db_manager)
logger.info("Security audit logger initialized for RBAC compliance")

# Initialize TOTP Manager for 2FA
totp_manager = TOTPManager(db_manager, issuer_name="IoTSentinel")

# Device group manager import
from utils.device_group_manager import DeviceGroupManager

# Initialize device group manager
group_manager = DeviceGroupManager(db_manager=db_manager)

# Initialize chart factory for centralized chart generation
chart_factory = ChartFactory()

# Initialize universal export helper (supports CSV, JSON, PDF, Excel)
export_helper = DashExportHelper(db_manager=db_manager)

# Initialize Advanced Reporting & Analytics
try:
    trend_analyzer = TrendAnalyzer(DB_PATH)
    report_builder = ReportBuilder(DB_PATH, enable_cache=True, cache_ttl_minutes=15)
    template_manager = ReportTemplateManager()

    # Initialize Report Queue for async report generation with progress tracking
    from utils.report_queue import ReportQueue
    report_queue = ReportQueue(
        report_builder=report_builder,
        max_workers=2,
        max_queue_size=50,
        results_dir='data/reports/generated'
    )

    logger.info("Advanced Reporting & Analytics initialized successfully")
except Exception as e:
    logger.warning(f"Failed to initialize reporting modules: {e}. Advanced reporting may not be available.")
    trend_analyzer = None
    report_builder = None
    template_manager = None
    report_queue = None

# Initialize Alert and Notification Services
try:
    # 1. Initialize NotificationDispatcher
    notification_dispatcher = NotificationDispatcher(config)

    # 2. Initialize AlertService
    alert_service = AlertService(db_manager, config)

    # 3. Initialize and register EmailNotifier with dispatcher
    # Build email config from environment variables
    email_section_config = config.get_section('email')
    if email_section_config and email_section_config.get('enabled', False):
        # Create email config from environment variables
        class EmailConfig:
            """Wrapper to provide config-like interface for environment variables"""
            def get(self, section, key, default=None):
                if section == 'email':
                    env_map = {
                        'enabled': 'EMAIL_ENABLED',
                        'smtp_host': 'EMAIL_SMTP_HOST',
                        'smtp_port': 'EMAIL_SMTP_PORT',
                        'smtp_user': 'EMAIL_SMTP_USER',
                        'smtp_password': 'EMAIL_SMTP_PASSWORD',  # pragma: allowlist secret
                        'sender_email': 'EMAIL_SENDER_EMAIL',
                        'recipient_email': 'EMAIL_RECIPIENT_EMAIL'
                    }
                    env_var = env_map.get(key)
                    if env_var:
                        value = os.getenv(env_var, default)
                        # Special handling for enabled flag
                        if key == 'enabled' and value is None:
                            return True  # Default to enabled if in config
                        return value
                return default

        email_config = EmailConfig()

        # Validate required environment variables
        required_vars = ['EMAIL_SMTP_HOST', 'EMAIL_SMTP_USER', 'EMAIL_SMTP_PASSWORD', 'EMAIL_SENDER_EMAIL']
        missing_vars = [var for var in required_vars if not os.getenv(var)]

        if missing_vars:
            logger.warning(f"Email notifications disabled - missing environment variables: {', '.join(missing_vars)}")
            logger.warning("Please set these variables in your .env file")
            email_notifier = None
        else:
            email_notifier = EmailNotifier(email_config, db_path=DB_PATH)
            notification_dispatcher.register_handler(email_notifier)
            logger.info("EmailNotifier registered with dispatcher (using environment variables)")
    else:
        logger.warning("Email notifications disabled in config")
        email_notifier = None

    # 4. Set dispatcher on AlertService
    alert_service.set_dispatcher(notification_dispatcher)

    # 5. Initialize ReportScheduler with all services
    report_scheduler = ReportScheduler(
        db_manager=db_manager,
        alert_service=alert_service,
        notification_dispatcher=notification_dispatcher,
        db_path=DB_PATH,
        email_notifier=email_notifier  # Pass email_notifier directly
    )

    # 6. Start the scheduler (schedules will be active)
    report_scheduler.start()

    # 7. Register shutdown handler for graceful cleanup
    def shutdown_scheduler():
        """Gracefully shutdown the report scheduler on app exit."""
        if report_scheduler:
            logger.info("Shutting down Report Scheduler...")
            try:
                report_scheduler.stop()
                logger.info("Report Scheduler stopped successfully")
            except Exception as e:
                logger.error(f"Error stopping scheduler: {e}")

    atexit.register(shutdown_scheduler)

    logger.info("Alert and Notification Services fully initialized")
    logger.info("Report Scheduler initialized and started")
    logger.info("Shutdown handler registered for graceful cleanup")

except Exception as e:
    logger.error(f"Failed to initialize Alert/Notification services: {e}", exc_info=True)
    notification_dispatcher = None
    alert_service = None
    email_notifier = None
    report_scheduler = None

# Authentication setup
auth_manager = AuthManager(db_manager=db_manager)

# Rate limiting for login attempts (5 attempts, 5-minute lockout)
login_rate_limiter = LoginRateLimiter(max_attempts=5, lockout_duration=300)

# Google OAuth handler (will be initialized after Flask app is configured)
oauth_handler = None

# WebAuthn handler placeholder
webauthn_handler = None

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

# Initialize innovation feature modules (use db_manager for database access)
try:
    network_security_scorer = get_security_scorer(db_manager=db_manager)
    privacy_analyzer = get_privacy_analyzer(db_manager=db_manager)
    logger.info("Innovation features initialized successfully")
except Exception as e:
    logger.warning(f"Failed to initialize innovation features: {e}")
    network_security_scorer = None
    privacy_analyzer = None

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
# AI ASSISTANT CONFIGURATION (HybridAI with 3-tier fallback)
# ============================================================================

# Initialize AI Assistant with Groq → Ollama → Rules fallback
ai_assistant = HybridAIAssistant()

# Initialize ML components (no alerting_system for dashboard)
inference_engine = InferenceEngine()  # Uses config for db_path internally
smart_recommender = SmartRecommender(inference_engine.db)

# Initialize Traffic Forecaster (24h bandwidth predictions)
traffic_forecaster = TrafficForecaster(db_manager=db_manager)
traffic_forecaster.load_model()
traffic_forecaster.train_on_historical_data(hours=168)  # Train on 7 days

# Initialize Attack Sequence Tracker (pattern-based prediction)
attack_tracker = AttackSequenceTracker(db_manager=db_manager)
attack_tracker.load_sequences()

# Initialize NL to SQL Generator (natural language database queries)
nl_to_sql = NLtoSQLGenerator(db_manager=db_manager)

# Log initialization status
ai_stats = ai_assistant.get_stats()
logger.info(f"✓ AI Assistant initialized")
logger.info(f"  - Groq API: {'✅ Available' if ai_stats['groq_available'] else '❌ Not configured'}")
logger.info(f"  - Ollama Local: {'✅ Enabled' if ai_stats['ollama_enabled'] else '❌ Disabled'}")
logger.info(f"✓ Inference Engine: {inference_engine.river_engine.__class__.__name__}")
logger.info(f"✓ Smart Recommender ready")
logger.info(f"✓ Traffic Forecaster: {traffic_forecaster.get_stats()['status']}")
logger.info(f"✓ Attack Tracker: {attack_tracker.get_stats()['tracked_devices']} devices tracked")
logger.info(f"✓ NL to SQL Generator: {len(nl_to_sql.QUERY_TEMPLATES)} query templates")


# ============================================================================
# AI FALLBACK RESPONSE FUNCTION
# ============================================================================

def get_rule_based_response(message: str, device_count: int, alert_count: int, recent_alerts: List[Dict]) -> str:
    """
    Basic fallback responses (backup for HybridAI).
    Note: HybridAI already has intelligent rules fallback built-in.
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
            return "✅ No active alerts! Your network has been quiet. IoTSentinel uses River ML (HalfSpaceTrees + HoeffdingAdaptive) for real-time incremental learning and anomaly detection."

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

# Dashboard Templates for Role-Based Views
DASHBOARD_TEMPLATES = {
    'security_admin': {
        'name': 'Security Admin',
        'description': 'Optimized for security professionals monitoring threats',
        'visible_features': [
            'analytics-card-btn', 'threat-card-btn', 'firewall-card-btn',
            'threat-map-card-btn', 'forensic-timeline-card-btn', 'attack-surface-card-btn',
            'auto-response-card-btn', 'vuln-scanner-card-btn', 'device-mgmt-card-btn',
            'timeline-card-btn', 'system-card-btn'
        ],
        'widget_prefs': {
            'metrics': True,
            'features': True,
            'rightPanel': True
        }
    },
    'home_user': {
        'name': 'Home User',
        'description': 'Simplified view for non-technical home users',
        'visible_features': [
            'device-mgmt-card-btn', 'privacy-card-btn', 'system-card-btn',
            'smarthome-card-btn', 'threat-map-card-btn', 'analytics-card-btn',
            'preferences-card-btn', 'quick-settings-btn'
        ],
        'widget_prefs': {
            'metrics': True,
            'features': True,
            'rightPanel': True
        }
    },
    'developer': {
        'name': 'Developer/Auditor',
        'description': 'Full access to all features and advanced analytics',
        'visible_features': 'all',  # Show everything
        'widget_prefs': {
            'metrics': True,
            'features': True,
            'rightPanel': True
        }
    },
    'custom': {
        'name': 'Custom',
        'description': 'User-defined custom layout',
        'visible_features': 'custom',  # Use widget-preferences store
        'widget_prefs': {
            'metrics': True,
            'features': True,
            'rightPanel': True
        }
    }
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
                html.Li("🤖 River ML framework - Incremental learning (HalfSpaceTrees, HoeffdingAdaptive, SNARIMAX)")
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
            ], className="p-3 border rounded"),
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
        "title": "Initial Setup: River ML Training 📚",
        "body": html.Div([
            html.P("IoTSentinel uses River ML for continuous, incremental learning, adapting to your network's normal behavior in real-time."),
            html.H6("How River ML learns:", className="mt-3"),
            html.Ol([
                html.Li("Start IoTSentinel: The system immediately begins learning and monitoring."),
                html.Li("Continuous Adaptation: Models like HalfSpaceTrees and HoeffdingAdaptive constantly update as your network evolves."),
                html.Li("Initial Learning Phase: Anomaly detection quality improves significantly within the first 24-48 hours of continuous operation."),
                html.Li("No Manual Baseline: No specific 'baseline collection script' is needed; learning is automatic and ongoing.")
            ]),
            html.Hr(),
            html.Div([
                html.H6("What to expect:"),
                html.Ul([
                    html.Li("✅ Network monitoring is active from the start"),
                    html.Li("✅ Device discovery works continuously"),
                    html.Li("⚠️ Anomaly detection improves rapidly with initial data"),
                    html.Li("📊 Detailed trend analytics become richer over time")
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
            html.Div([
                html.H6("Navigation:", className="small text-muted mt-2"),
                html.Ul([
                    html.Li([html.Kbd("N"), " - Toggle notification drawer"]),
                    html.Li([html.Kbd("D"), " - Jump to devices section"]),
                    html.Li([html.Kbd("A"), " - Jump to alerts section"])
                ], className="mb-2"),
                html.H6("Quick Actions:", className="small text-muted mt-2"),
                html.Ul([
                    html.Li([html.Kbd("P"), " - Open preferences"]),
                    html.Li([html.Kbd("C"), " - Open AI chat assistant"]),
                    html.Li([html.Kbd("S"), " - Open system info"]),
                    html.Li([html.Kbd("F"), " - Open firewall settings"]),
                    html.Li([html.Kbd("U"), " - Open user management"]),
                    html.Li([html.Kbd("T"), " - Open timeline"]),
                    html.Li([html.Kbd("H"), " or ", html.Kbd("?"), " - Restart tour/help"]),
                    html.Li([html.Kbd("Esc"), " - Close any open modal"])
                ])
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

# Feature Card Categorization for Enhanced Masonry Layout
FEATURE_CATEGORIES = {
    'Security': [
        'analytics-card-btn', 'firewall-card-btn', 'threat-map-card-btn',
        'threat-card-btn', 'privacy-card-btn', 'attack-surface-card-btn',
        'forensic-timeline-card-btn', 'auto-response-card-btn', 'vuln-scanner-card-btn'
    ],
    'Management': [
        'device-mgmt-card-btn', 'user-card-btn', 'firmware-card-btn',
        'segmentation-card-btn', 'email-card-btn', 'preferences-card-btn',
        'quick-settings-btn'
    ],
    'Analytics': [
        'system-card-btn', 'timeline-card-btn', 'protocol-card-btn',
        'smarthome-card-btn', 'risk-heatmap-card-btn', 'compliance-card-btn',
        'api-hub-card-btn', 'benchmark-card-btn', 'performance-card-btn',
        'education-card-btn'
    ]
}

# Card Size Priority (for visual hierarchy)
CARD_PRIORITIES = {
    'primary': ['analytics-card-btn', 'device-mgmt-card-btn', 'firmware-card-btn'],
    'secondary': ['system-card-btn', 'threat-map-card-btn', 'protocol-card-btn',
                  'smarthome-card-btn', 'compliance-card-btn'],
    'tertiary': []
}

# ============================================================================
# DATABASE HELPERS
# ============================================================================

def get_db_connection():
    """Get the shared database connection from db_manager"""
    return db_manager.conn


def format_timestamp_relative(timestamp_str):
    """Format a timestamp as a relative time string (e.g., '2 minutes ago')"""
    try:
        if isinstance(timestamp_str, str):
            dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        elif isinstance(timestamp_str, datetime):
            dt = timestamp_str
        else:
            return "Unknown"

        now = datetime.now()
        diff = now - dt
        seconds = diff.total_seconds()

        if seconds < 60:
            return "Just now"
        elif seconds < 3600:
            minutes = int(seconds / 60)
            return f"{minutes} minute{'s' if minutes != 1 else ''} ago"
        elif seconds < 86400:
            hours = int(seconds / 3600)
            return f"{hours} hour{'s' if hours != 1 else ''} ago"
        elif seconds < 604800:
            days = int(seconds / 86400)
            return f"{days} day{'s' if days != 1 else ''} ago"
        else:
            return dt.strftime("%b %d, %Y at %I:%M %p")
    except Exception as e:
        logger.error(f"Error formatting timestamp: {e}")
        return "Unknown"


def generate_csv_content(headers, rows, filename_prefix="export"):
    """Generate CSV content from headers and rows for download"""
    try:
        import csv
        from io import StringIO

        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(headers)
        for row in rows:
            writer.writerow(row)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{filename_prefix}_{timestamp}.csv"

        return {
            'content': output.getvalue(),
            'filename': filename,
            'type': 'text/csv'
        }
    except Exception as e:
        logger.error(f"Error generating CSV: {e}")
        return None


def create_timestamp_display(timestamp=None):
    """Create a timestamp display component"""
    if timestamp is None:
        timestamp = datetime.now()
    formatted_time = format_timestamp_relative(timestamp)
    return html.Div([
        html.I(className="fa fa-clock me-1"),
        html.Span(f"Last updated: {formatted_time}", className="text-muted small")
    ], className="text-end mb-2")


def get_device_today_stats(device_ip: str) -> Dict[str, Any]:
    conn = get_db_connection()
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


def get_alert_with_context(alert_id: int) -> Dict[str, Any]:
    conn = get_db_connection()
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


def get_device_details(device_ip: str) -> Dict[str, Any]:
    """Get comprehensive device information"""
    conn = get_db_connection()
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


def get_devices_with_status() -> List[Dict]:
    conn = get_db_connection()
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


def get_latest_alerts(limit=10):
    """Get recent alerts without caching"""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT a.id, a.timestamp, a.device_ip, d.device_name, a.severity,
                a.anomaly_score, a.explanation, a.top_features, a.acknowledged, d.is_trusted
            FROM alerts a LEFT JOIN devices d ON a.device_ip = d.device_ip
            WHERE a.timestamp > datetime('now', '-24 hours') AND a.acknowledged = 0
            ORDER BY a.timestamp DESC LIMIT ?
        """, (limit,))
        return [dict(row) for row in cursor.fetchall()]
    except Exception as e:
        logger.error(f"Error fetching alerts: {e}")
        return []


def get_bandwidth_stats():
    """Get bandwidth statistics"""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT SUM(bytes_sent + bytes_received) as total FROM connections WHERE timestamp > datetime('now', '-1 hour')")
        row = cursor.fetchone()
        total = row['total'] or 0
        for unit in ['B', 'KB', 'MB', 'GB']:
            if total < 1024:
                return {'total': total, 'formatted': f"{total:.1f} {unit}"}
            total /= 1024
        return {'total': total * 1024**4, 'formatted': f"{total:.1f} TB"}
    except Exception as e:
        logger.error(f"Error fetching bandwidth: {e}")
        return {'total': 0, 'formatted': '0 B'}


def get_threats_blocked():
    """Get count of threats blocked"""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) as count FROM alerts WHERE severity IN ('high', 'critical') AND timestamp > datetime('now', '-24 hours')")
        row = cursor.fetchone()
        return row['count'] or 0
    except Exception as e:
        logger.error(f"Error fetching threats: {e}")
        return 0


def get_device_status(device_ip, hours=24):
    """Get device alert status"""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT severity, COUNT(*) as count FROM alerts
            WHERE device_ip = ? AND timestamp > datetime('now', ? || ' hours') AND acknowledged = 0
            GROUP BY severity
        """, (device_ip, f'-{hours}'))
        rows = cursor.fetchall()
        for row in rows:
            if row['severity'] in ['critical', 'high']:
                return row['severity']
        return 'normal'
    except Exception as e:
        logger.error(f"Error fetching device status: {e}")
        return 'normal'


def get_device_baseline(device_ip):
    """Get device baseline (placeholder)"""
    return None


def get_latest_alerts_content():
    """Helper function to fetch and format recent alerts for the notification drawer."""
    recent_alerts_raw = get_latest_alerts(limit=10)

    if not recent_alerts_raw:
        return [dbc.Alert("No new alerts.", color="info")]
    else:
        drawer_content = []
        for alert in recent_alerts_raw:
            device_name = alert.get('device_name') or alert.get('device_ip')
            severity = alert.get('severity', 'medium')
            config_data = SEVERITY_CONFIG.get(severity, SEVERITY_CONFIG['medium'])

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
                pass

            drawer_content.append(
                dbc.Card([
                    dbc.CardBody([
                        html.Div([
                            html.Strong(device_name),
                            html.Small(time_ago, className="text-muted ms-auto")
                        ], className="d-flex justify-content-between mb-1"),
                        html.P(alert.get('explanation'), className="small mb-0 text-truncate"),
                        dbc.Button("View Details", size="sm", color=config_data['color'], outline=True,
                                   className="mt-2", id={'type': 'alert-detail-btn', 'index': int(alert['id'])})
                    ])
                ], color=config_data['color'], inverse=True, className="mb-2 shadow-sm notification-card")
            )
    return drawer_content


def get_non_eol_devices():
    """Get list of non-EOL devices"""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT device_ip, device_name FROM devices WHERE device_ip IS NOT NULL")
        return [dict(row) for row in cursor.fetchall()]
    except Exception as e:
        logger.error(f"Error fetching devices: {e}")
        return []


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
    """Get icon data for a device type."""
    if not device_type:
        return DEVICE_TYPE_ICONS['unknown']
    device_type_lower = device_type.lower().strip()
    if device_type_lower in DEVICE_TYPE_ICONS:
        return DEVICE_TYPE_ICONS[device_type_lower]
    for key, value in DEVICE_TYPE_ICONS.items():
        if key in device_type_lower or device_type_lower in key:
            return value
    return DEVICE_TYPE_ICONS['unknown']


def create_device_icon(device_type: Optional[str], use_emoji: bool = True,
                       use_fa: bool = False, size: str = "1.2rem") -> html.Span:
    """Create device icon component."""
    icon_data = get_device_icon_data(device_type)
    children = []
    if use_emoji:
        children.append(
            html.Span(icon_data['emoji'], style={'fontSize': size, 'marginRight': '6px'},
                      title=device_type or 'Unknown Device')
        )
    if use_fa:
        children.append(
            html.I(className=f"fa {icon_data['fa']}",
                   style={'color': icon_data['color'], 'fontSize': size, 'marginRight': '6px'},
                   title=device_type or 'Unknown Device')
        )
    if not children:
        children.append(
            html.Span(icon_data['emoji'], style={'fontSize': size, 'marginRight': '6px'})
        )
    return html.Span(children)


def create_threat_intel_badge(reputation_data: Dict[str, Any]) -> html.Div:
    """Create a visual badge/alert for IP reputation data."""
    level = reputation_data.get('reputation_level', 'unknown')
    score = reputation_data.get('abuse_confidence_score', 0)
    ip = reputation_data.get('ip_address', 'Unknown')

    level_config = {
        'malicious': {'color': 'danger', 'icon': 'fa-skull-crossbones', 'emoji': '⛔', 'text': 'MALICIOUS'},
        'suspicious': {'color': 'warning', 'icon': 'fa-exclamation-triangle', 'emoji': '⚠️', 'text': 'SUSPICIOUS'},
        'low_risk': {'color': 'info', 'icon': 'fa-info-circle', 'emoji': 'ℹ️', 'text': 'LOW RISK'},
        'safe': {'color': 'success', 'icon': 'fa-check-circle', 'emoji': '✅', 'text': 'SAFE'},
        'private': {'color': 'secondary', 'icon': 'fa-home', 'emoji': '🏠', 'text': 'PRIVATE'},
        'unknown': {'color': 'secondary', 'icon': 'fa-question-circle', 'emoji': '❓', 'text': 'UNKNOWN'}
    }

    config_data = level_config.get(level, level_config['unknown'])
    children = []
    children.append(
        html.Div([
            html.Span(config_data['emoji'], style={'fontSize': '1.5rem', 'marginRight': '10px'}),
            html.Strong(f"Threat Intelligence: {config_data['text']}", className="me-2"),
            dbc.Badge(f"Score: {score}/100", color=config_data['color'], className="ms-2")
        ], className="d-flex align-items-center mb-3")
    )
    if level not in ['private', 'unknown']:
        details = [
            html.P([html.Strong("IP Address: "), ip]),
            html.P([html.Strong("Country: "), reputation_data.get('country_code', 'Unknown')]),
            html.P([html.Strong("ISP: "), reputation_data.get('isp', 'Unknown')]),
            html.P([html.Strong("Total Reports: "), str(reputation_data.get('total_reports', 0))]),
        ]
        categories = reputation_data.get('categories', [])
        if categories:
            category_badges = [dbc.Badge(cat, color="dark", className="me-1 mb-1") for cat in categories[:5]]
            details.append(
                html.Div([html.Strong("Threat Categories: "), html.Div(category_badges, className="d-inline")],
                         className="mb-2")
            )
        last_reported = reputation_data.get('last_reported_at', '')
        if last_reported:
            details.append(html.P([html.Strong("Last Reported: "), last_reported], className="small text-muted"))
        children.append(html.Div(details))

    recommendation = reputation_data.get('recommendation', '')
    if recommendation:
        children.append(
            dbc.Alert([html.I(className=f"fa {config_data['icon']} me-2"), recommendation],
                      color=config_data['color'], className="mt-3 mb-0")
        )
    if reputation_data.get('is_cached', False):
        children.append(html.Small("🔄 Cached result", className="text-muted d-block mt-2"))

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
        html.Div([html.Div(className="skeleton skeleton-graph-inner")], className="skeleton-graph"),
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
    """Create skeleton placeholders for device list"""
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

    baseline_color = 'var(--border-color)'
    if abs(pct_diff) < 50:
        today_color = 'var(--success-color)'
    elif abs(pct_diff) < 150:
        today_color = 'var(--warning-color)'
    else:
        today_color = 'var(--danger-color)'

    font_family = 'var(--font-family, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif)'
    font_color = 'var(--text-primary)'

    fig = go.Figure()
    fig.add_trace(go.Bar(
        name='Normal (7-day avg)', x=[metric_name], y=[baseline_value], marker_color=baseline_color,
        text=[format_bytes(baseline_value) if 'bytes' in baseline_key.lower() else f"{baseline_value:.0f}"],
        textposition='outside'
    ))
    fig.add_trace(go.Bar(
        name='Today', x=[metric_name], y=[today_value], marker_color=today_color,
        text=[format_bytes(today_value) if 'bytes' in today_key.lower() else f"{today_value:.0f}"],
        textposition='outside'
    ))

    fig.update_layout(
        title=dict(text=title, font=dict(size=14, family=font_family, color=font_color)),
        barmode='group', height=250, margin=dict(l=40, r=40, t=60, b=40),
        showlegend=True, legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="center", x=0.5),
        yaxis_title="", xaxis_title="",
        font=dict(family=font_family, color=font_color),
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)'
    )

    if abs(pct_diff) > 10:
        direction = "higher" if pct_diff > 0 else "lower"
        fig.add_annotation(
            x=metric_name, y=max(baseline_value, today_value),
            text=f"{abs(pct_diff):.0f}% {direction}",
            showarrow=False, font=dict(size=12, color=today_color, family=font_family), yshift=30
        )

    return fig


def create_educational_explanation(alert: Dict) -> html.Div:
    baseline = alert.get('baseline') or {}
    today_stats = alert.get('today_stats') or {}
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

        # PHASE 1: Enhanced Detection Methodology Section
        sections.append(
            dbc.Card([
                dbc.CardHeader([
                    html.I(className="fa fa-microscope me-2"),
                    html.Strong("🔬 How IoTSentinel Detected This")
                ], className="bg-primary text-white"),
                dbc.CardBody([
                    html.H6("Detection Methodology:", className="mb-3"),
                    html.Ol([
                        html.Li([
                            html.Strong("Baseline Establishment: "),
                            f"7-day average = {format_bytes(avg_bytes_sent)}"
                        ]),
                        html.Li([
                            html.Strong("Current Activity: "),
                            f"{format_bytes(today_bytes_sent)} detected today"
                        ]),
                        html.Li([
                            html.Strong("Statistical Analysis: "),
                            f"{((today_bytes_sent/avg_bytes_sent - 1) * 100):.1f}% deviation from baseline" if avg_bytes_sent > 0 else "Significant deviation detected"
                        ]),
                        html.Li([
                            "ML Analysis:",
                            html.Ul([
                                html.Li([
                                    html.Strong("Anomaly Score: "),
                                    html.Span(f"{alert.get('anomaly_score', 0):.3f}", className="text-danger fw-bold"),
                                    " (threshold: 0.350)",
                                    html.Span([
                                        html.I(className="fa fa-question-circle ms-2 text-muted",
                                               id="anomaly-score-help", style={"cursor": "pointer"})
                                    ])
                                ]),
                                html.Li([
                                    html.Strong("Detection Models: "),
                                    alert.get('model_types', 'Dual ML Models'),
                                    html.Span([
                                        html.I(className="fa fa-question-circle ms-2 text-muted",
                                               id="ml-models-help", style={"cursor": "pointer"})
                                    ])
                                ])
                            ], className="mt-2")
                        ]),
                        html.Li([
                            html.Strong("Confidence Level: "),
                            html.Span([
                                dbc.Badge(
                                    "HIGH" if alert.get('anomaly_score', 0) > 0.7 else "MEDIUM" if alert.get('anomaly_score', 0) > 0.4 else "LOW",
                                    color="danger" if alert.get('anomaly_score', 0) > 0.7 else "warning" if alert.get('anomaly_score', 0) > 0.4 else "info",
                                    className="ms-2"
                                ),
                                html.Small(" (Both models agree)" if alert.get('anomaly_score', 0) > 0.7 else " (Single model detection)", className="text-muted ms-2")
                            ])
                        ])
                    ], className="mb-3"),
                    html.Hr(),
                    dbc.Alert([
                        html.Div([
                            html.Strong("🔐 Commercial Systems: ", className="text-dark"),
                            html.Span("'Threat Blocked' ", className="text-muted"),
                            html.Em("(no explanation)", className="text-muted small")
                        ], className="mb-2"),
                        html.Div([
                            html.Strong("📊 IoTSentinel: ", className="text-primary"),
                            html.Span("Full detection breakdown with evidence", className="text-dark")
                        ])
                    ], color="light", className="mb-0 border-primary")
                ])
            ], className="mb-3 border-primary")
        )

        # Add tooltips for educational terms
        sections.append(html.Div([
            dbc.Tooltip(
                "Measures how unusual this behavior is compared to normal patterns. "
                "Scores above 0.350 indicate suspicious activity. IoTSentinel uses two "
                "River ML models (HalfSpaceTrees + HoeffdingAdaptive) with incremental learning.",
                target="anomaly-score-help",
                placement="top"
            ),
            dbc.Tooltip(
                "IoTSentinel uses River ML framework: (1) HalfSpaceTrees - learns "
                "normal patterns and flags deviations, (2) HoeffdingAdaptive - classifies "
                "attack patterns in real-time. Both models use incremental learning for continuous improvement.",
                target="ml-models-help",
                placement="top"
            )
        ], style={"display": "none"}))  # Hidden div to hold tooltips

        # PHASE 6: Add baseline explanation with tooltip
        sections.append(
            html.H5([
                "📈 Comparison with Normal Behavior",
                html.I(className="fa fa-question-circle ms-2 text-muted",
                       id="baseline-comparison-help", style={"cursor": "pointer", "fontSize": "0.9rem"})
            ], className="mt-4 mb-3")
        )
        sections.append(html.Div([
            dbc.Tooltip(
                "Baseline: The 'normal' behavior pattern established from 7 days of monitoring. "
                "Think of it as 'what's typical for this device'. We compare today's activity "
                "against this baseline to detect unusual patterns.",
                target="baseline-comparison-help",
                placement="top"
            )
        ], style={"display": "none"}))
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
        top_features = alert.get('top_features', '{}')
        try:
            features = json.loads(top_features) if isinstance(top_features, str) else top_features
            dest_ip = None

            for key in features.keys():
                if 'dest_ip' in key.lower() or 'destination' in key.lower():
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

    # Get AI-powered recommendations from SmartRecommender
    alert_id = alert.get('id')
    if alert_id:
        try:
            recommendations = smart_recommender.recommend_for_alert(alert_id)
            if recommendations:
                sections.append(
                    dbc.Alert([
                        html.Div([
                            html.I(className="fa fa-robot me-2"),
                            html.Strong("AI-Powered Security Recommendations"),
                            dbc.Badge("SMART", color="success", className="ms-2")
                        ], className="mb-3"),
                        html.P("Context-aware actions based on device history, threat intelligence, and network patterns:",
                               className="text-muted small mb-3"),
                        html.Div([
                            dbc.Card([
                                dbc.CardHeader([
                                    dbc.Badge(f"Priority {rec['priority']}",
                                             color="danger" if rec['priority'] == 1 else "warning" if rec['priority'] == 2 else "info",
                                             className="me-2"),
                                    html.Strong(rec['action']),
                                    dbc.Badge(f"{rec['confidence']*100:.0f}% confident",
                                             color="light", text_color="dark", className="float-end")
                                ], className="py-2"),
                                dbc.CardBody([
                                    html.P(rec['reason'], className="mb-2"),
                                    html.Div([
                                        html.Small("Command:", className="text-muted me-2"),
                                        dbc.Input(value=rec['command'], readonly=True, size="sm", className="font-monospace")
                                    ]) if rec.get('command') else None
                                ], className="py-2")
                            ], className="mb-2 border-start border-3" +
                               (" border-danger" if rec['priority'] == 1 else " border-warning" if rec['priority'] == 2 else " border-info"))
                            for rec in recommendations[:3]
                        ])
                    ], color="light", className="border-primary")
                )
            else:
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
        except Exception as e:
            logger.error(f"Error getting smart recommendations: {e}")
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
    else:
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

    # PHASE 6: Enhanced Technical Details with Educational Tooltips
    sections.append(
        dbc.Accordion([
            dbc.AccordionItem([
                html.P([
                    html.Strong("MITRE ATT&CK Tactic: "),
                    mitre_info['tactic'],
                    html.I(className="fa fa-question-circle ms-2 text-muted",
                           id="mitre-attack-help", style={"cursor": "pointer"})
                ]),
                html.P([
                    html.Strong("Technical Description: "),
                    mitre_info['description']
                ]),
                html.P([
                    html.Strong("Anomaly Score: "),
                    f"{alert.get('anomaly_score') or 0:.4f}",
                    html.I(className="fa fa-question-circle ms-2 text-muted",
                           id="anomaly-score-technical-help", style={"cursor": "pointer"})
                ]),
                html.P([
                    html.Strong("Detection Model: "),
                    alert.get('model_types') or 'N/A',
                    html.I(className="fa fa-question-circle ms-2 text-muted",
                           id="detection-model-help", style={"cursor": "pointer"})
                ]),
                html.Hr(),
                html.H6([
                    "Raw Feature Contributions:",
                    html.I(className="fa fa-question-circle ms-2 text-muted",
                           id="feature-contrib-help", style={"cursor": "pointer"})
                ]),
                html.Pre(json.dumps(json.loads(alert.get('top_features') or '{}'), indent=2))
            ], title="🔬 Technical Details (Advanced)")
        ], start_collapsed=True, className="mt-3")
    )

    # PHASE 6: Add tooltips for technical terms
    sections.append(html.Div([
        dbc.Tooltip(
            "MITRE ATT&CK is a globally-accessible knowledge base of adversary tactics and techniques. "
            "It helps categorize what attackers are trying to accomplish. Think of it as a 'playbook' "
            "of hacker strategies used by security professionals worldwide.",
            target="mitre-attack-help",
            placement="top"
        ),
        dbc.Tooltip(
            "A numerical score from 0 to 1 indicating how unusual this behavior is. "
            "Higher scores (closer to 1) mean more unusual activity. Scores above 0.35 "
            "are considered suspicious and trigger alerts.",
            target="anomaly-score-technical-help",
            placement="top"
        ),
        dbc.Tooltip(
            "IoTSentinel uses River ML framework with incremental learning models: "
            "(1) HalfSpaceTrees - detects anomalies in streaming data, "
            "(2) HoeffdingAdaptive - classifies attack patterns, "
            "(3) SNARIMAX - forecasts traffic trends. Models learn continuously from live data.",
            target="detection-model-help",
            placement="top"
        ),
        dbc.Tooltip(
            "These are the specific network behaviors (features) that contributed most to this alert. "
            "Each feature shows a value indicating how much it influenced the anomaly score. "
            "Higher values mean that feature was more unusual.",
            target="feature-contrib-help",
            placement="top"
        )
    ], style={"display": "none"}))

    return html.Div(sections)
