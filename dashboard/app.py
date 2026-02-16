#!/usr/bin/env python3
"""
IoTSentinel Dashboard - Enhanced Educational Transparency Edition
Complete implementation with onboarding, trust management, lockdown mode,
voice alerts, enhanced 3D visualizations, and AI assistant.
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

logger.info("="*70)
logger.info("IoTSentinel Logging System Initialized")
logger.info(f"Log Directory: {os.path.abspath(log_dir)}")
logger.info("Active Logs: iotsentinel.log, audit.log, ml.log, alerts.log,")
logger.info("             hardware.log, database.log, error.log, api.log")
logger.info("="*70)


# Import atexit for cleanup handlers
import atexit

# Initialize app
app = dash.Dash(
    __name__,
    external_stylesheets=[dbc.themes.BOOTSTRAP, dbc.icons.FONT_AWESOME],  # Load critical styles first
    external_scripts=[],  # Scripts will be loaded via custom strategy
    title="IoTSentinel - Network Security Monitor",
    suppress_callback_exceptions=True,
    # Performance optimizations
    compress=True,  # Enable gzip compression (requires: pip install dash[compress])
    update_title=None,  # Disable title updates for performance
)

# Keep default index_string for better compatibility
# app.index_string remains default

socketio = SocketIO(app.server, cors_allowed_origins="*")
socketio = SocketIO(
    app.server,
    cors_allowed_origins="*",
    async_mode='eventlet',
    logger=True,
    engineio_logger=True,
    websocket_ping_interval=25, # Ping every 25 seconds
    websocket_ping_timeout=60   # Timeout if no pong in 30 seconds
)


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

# Remember Me cookie configuration (7-day duration)
server.config['REMEMBER_COOKIE_DURATION'] = timedelta(days=7)
server.config['REMEMBER_COOKIE_SECURE'] = True  # HTTPS only in production
server.config['REMEMBER_COOKIE_HTTPONLY'] = True  # Prevent XSS attacks
server.config['REMEMBER_COOKIE_SAMESITE'] = 'Lax'  # CSRF protection

@login_manager.user_loader
def load_user(user_id):
    """Load user by ID for Flask-Login"""
    return auth_manager.get_user_by_id(int(user_id))

# Initialize Google OAuth handler
try:
    oauth_handler = GoogleOAuthHandler(server, db_manager=db_manager)
    if oauth_handler.enabled:
        logger.info("Google OAuth initialized successfully")
    else:
        logger.warning("Google OAuth credentials not configured")
except Exception as e:
    logger.error(f"Failed to initialize OAuth: {e}")
    oauth_handler = None

# Initialize WebAuthn handler for biometric authentication
try:
    webauthn_handler = WebAuthnHandler(db_manager=db_manager)
    if is_webauthn_available():
        logger.info("WebAuthn initialized successfully")
    else:
        logger.warning("WebAuthn requires HTTPS (except localhost)")
except Exception as e:
    logger.error(f"Failed to initialize WebAuthn: {e}")
    webauthn_handler = None

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
        conn = db_manager.conn
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM devices")
        device_count = cursor.fetchone()[0]
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


# Download generated report
@server.route('/download-report')
@login_required
def download_report():
    """
    Download a generated report file.
    Requires authentication and validates the file path is within reports directory.
    """
    from pathlib import Path
    import os

    file_path = request.args.get('path', '')

    if not file_path:
        return jsonify({"error": "No file path provided"}), 400

    # Security: Ensure the path is within the reports directory
    reports_dir = Path('data/reports/generated').resolve()
    requested_file = Path(file_path).resolve()

    try:
        # Check if requested file is within reports directory
        requested_file.relative_to(reports_dir)
    except ValueError:
        logger.warning(f"Attempted access to file outside reports directory: {file_path}")
        return jsonify({"error": "Invalid file path"}), 403

    # Check if file exists
    if not requested_file.exists():
        return jsonify({"error": "File not found"}), 404

    # Determine mimetype based on extension
    mimetype_map = {
        '.pdf': 'application/pdf',
        '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        '.json': 'application/json'
    }

    file_ext = requested_file.suffix.lower()
    mimetype = mimetype_map.get(file_ext, 'application/octet-stream')

    return send_file(
        requested_file,
        mimetype=mimetype,
        as_attachment=True,
        download_name=requested_file.name
    )


# ============================================================================
# GOOGLE OAUTH ROUTES
# ============================================================================

@server.route('/auth/google')
def google_login():
    """Initiate Google OAuth login flow"""
    if not oauth_handler or not oauth_handler.enabled:
        logger.error("OAuth attempted but not configured")
        return redirect('/?error=oauth_not_configured')

    try:
        return oauth_handler.get_authorization_url()
    except Exception as e:
        logger.error(f"Error initiating OAuth: {e}")
        return redirect('/?error=oauth_failed')


@server.route('/auth/google/callback')
def google_callback():
    """Handle Google OAuth callback"""
    from flask import jsonify

    if not oauth_handler or not oauth_handler.enabled:
        logger.error("OAuth callback received but OAuth not configured")
        return redirect('/?error=oauth_not_configured')

    try:
        # Handle OAuth callback
        oauth_data = oauth_handler.handle_callback(request)

        if not oauth_data:
            logger.error("Failed to get OAuth user data")
            return redirect('/?error=oauth_failed')

        # Create or update user from OAuth data
        user_id = oauth_handler.create_or_update_oauth_user(oauth_data)

        if not user_id:
            logger.error("Failed to create/update OAuth user")
            return redirect('/?error=user_creation_failed')

        # Get user object
        user_data = oauth_handler.get_user_by_id(user_id)

        if not user_data:
            logger.error(f"Failed to load user {user_id}")
            return redirect('/?error=user_not_found')

        # Create User object for Flask-Login
        user = User(
            id=user_data['id'],
            username=user_data['username'],
            email=user_data['email'],
            role=user_data['role']
        )

        # Log in the user (remember=True for OAuth users)
        login_user(user, remember=True)

        # Record login in history
        user_ip = request.remote_addr or 'Unknown'
        user_agent = request.headers.get('User-Agent', 'Unknown')

        conn = db_manager.conn
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO user_login_history
            (user_id, login_timestamp, ip_address, user_agent, login_method, success)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (user_id, datetime.now(), user_ip, user_agent, 'oauth_google', 1))
        conn.commit()

        logger.info(f"User {user_data['username']} logged in via Google OAuth")

        # Redirect to dashboard
        return redirect('/')

    except Exception as e:
        logger.error(f"Error in OAuth callback: {e}")
        return redirect('/?error=oauth_callback_failed')


# ============================================================================
# WEBAUTHN BIOMETRIC AUTHENTICATION ROUTES
# ============================================================================

@server.route('/api/webauthn/register/start', methods=['POST'])
@login_required
def webauthn_register_start():
    """Start WebAuthn registration"""
    if not webauthn_handler:
        return jsonify({'error': 'WebAuthn not available'}), 503

    try:
        user_id = current_user.id
        username = current_user.username

        # Get email from database (User object doesn't have email attribute)
        conn = db_manager.conn
        cursor = conn.cursor()
        cursor.execute("SELECT email FROM users WHERE id = ?", (user_id,))
        result = cursor.fetchone()

        email = result[0] if result else username  # Fallback to username if no email

        options = webauthn_handler.generate_registration_options(user_id, username, email)
        return jsonify(options), 200

    except Exception as e:
        logger.error(f"WebAuthn registration start error: {e}")
        return jsonify({'error': str(e)}), 500


@server.route('/api/webauthn/register/verify', methods=['POST'])
@login_required
def webauthn_register_verify():
    """Verify WebAuthn registration"""
    if not webauthn_handler:
        return jsonify({'error': 'WebAuthn not available'}), 503

    try:
        data = request.get_json()
        credential = data.get('credential')
        challenge_key = data.get('challenge_key')
        device_name = data.get('device_name', 'My Device')

        success = webauthn_handler.verify_registration(
            current_user.id,
            credential,
            challenge_key,
            device_name
        )

        if success:
            return jsonify({'success': True, 'message': 'Biometric registered successfully'}), 200
        else:
            return jsonify({'error': 'Registration verification failed'}), 400

    except Exception as e:
        logger.error(f"WebAuthn registration verify error: {e}")
        return jsonify({'error': str(e)}), 500


@server.route('/api/webauthn/login/start', methods=['POST'])
def webauthn_login_start():
    """Start WebAuthn authentication"""
    if not webauthn_handler:
        return jsonify({'error': 'WebAuthn not available'}), 503

    try:
        data = request.get_json()
        username = data.get('username')

        options = webauthn_handler.generate_authentication_options(username)
        return jsonify(options), 200

    except Exception as e:
        logger.error(f"WebAuthn login start error: {e}")
        return jsonify({'error': str(e)}), 500


@server.route('/api/webauthn/login/verify', methods=['POST'])
def webauthn_login_verify():
    """Verify WebAuthn authentication"""
    if not webauthn_handler:
        return jsonify({'error': 'WebAuthn not available'}), 503

    try:
        data = request.get_json()
        credential = data.get('credential')
        challenge_key = data.get('challenge_key')

        user_id = webauthn_handler.verify_authentication(credential, challenge_key)

        if user_id:
            # Get user object
            user = auth_manager.get_user_by_id(user_id)

            if user:
                # Log in the user
                login_user(user, remember=True)

                # Record login in history
                user_ip = request.remote_addr or 'Unknown'
                user_agent = request.headers.get('User-Agent', 'Unknown')

                conn = db_manager.conn
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO user_login_history
                    (user_id, login_timestamp, ip_address, user_agent, login_method, success)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (user_id, datetime.now(), user_ip, user_agent, 'webauthn_biometric', 1))
                conn.commit()

                logger.info(f"User {user.username} logged in via WebAuthn biometric")
                return jsonify({'success': True, 'redirect': '/'}), 200
            else:
                return jsonify({'error': 'User not found'}), 404
        else:
            return jsonify({'error': 'Authentication failed'}), 401

    except Exception as e:
        logger.error(f"WebAuthn login verify error: {e}")
        return jsonify({'error': str(e)}), 500


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

# ============================================================================
# DATABASE HELPERS
# ============================================================================

def get_db_connection():
    """Get the shared database connection from db_manager"""
    return db_manager.conn

# =============================================================================
# UTILITY FUNCTIONS - Timestamps and CSV Export
# =============================================================================

def format_timestamp_relative(timestamp_str):
    """
    Format a timestamp as a relative time string (e.g., '2 minutes ago')

    Args:
        timestamp_str: Timestamp string in ISO format or datetime object

    Returns:
        str: Formatted relative time string
    """
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
    """
    Generate CSV content from headers and rows for download

    Args:
        headers: List of column headers
        rows: List of rows (each row is a list/tuple of values)
        filename_prefix: Prefix for the filename

    Returns:
        dict: Download data dict for dcc.Download component
    """
    try:
        import csv
        from io import StringIO

        # Create CSV content
        output = StringIO()
        writer = csv.writer(output)

        # Write headers
        writer.writerow(headers)

        # Write rows
        for row in rows:
            writer.writerow(row)

        # Generate filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{filename_prefix}_{timestamp}.csv"

        # Return download dict
        return {
            'content': output.getvalue(),
            'filename': filename,
            'type': 'text/csv'
        }
    except Exception as e:
        logger.error(f"Error generating CSV: {e}")
        return None

def create_timestamp_display(timestamp=None):
    """
    Create a timestamp display component

    Args:
        timestamp: Optional timestamp to display, defaults to now

    Returns:
        html.Div: Timestamp display component
    """
    if timestamp is None:
        timestamp = datetime.now()

    formatted_time = format_timestamp_relative(timestamp)

    return html.Div([
        html.I(className="fa fa-clock me-1"),
        html.Span(f"Last updated: {formatted_time}", className="text-muted small")
    ], className="text-end mb-2")

# Note: get_device_status and get_device_baseline are now imported from cached_queries
# for better performance with TTL-based caching

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

    # Use CSS variable colors for theme consistency
    # These will be picked up by Plotly if set as 'var(--color-name)' and handled in Dash via custom CSS
    baseline_color = 'var(--border-color)'
    # Today color: success/warning/danger based on deviation, using theme variables
    if abs(pct_diff) < 50:
        today_color = 'var(--success-color)'
    elif abs(pct_diff) < 150:
        today_color = 'var(--warning-color)'
    else:
        today_color = 'var(--danger-color)'

    # Font family from CSS variable
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

    # Get AI-powered recommendations from SmartRecommender
    alert_id = alert.get('id')
    if alert_id:
        try:
            recommendations = smart_recommender.recommend_for_alert(alert_id)
            if recommendations:
                # AI-powered recommendations
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
                            for rec in recommendations[:3]  # Top 3
                        ])
                    ], color="light", className="border-primary")
                )
            else:
                # Fallback to generic recommendations
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
            # Fallback to generic if error
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
        # No alert ID - use generic recommendations
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

# ============================================================================
# LOGIN PAGE LAYOUT
# ============================================================================

login_layout = dbc.Container([
    dbc.Row([
        # LEFT SIDE - Branding with Liquid Glass
        dbc.Col([
            html.Div([
                # Logo with glow effect
                html.Div([
                    html.Img(
                        src="/assets/logo.png",
                        style={
                            "height": "120px",
                            "filter": "drop-shadow(0 0 40px rgba(102, 126, 234, 0.8))",
                            "animation": "logoGlow 3s ease-in-out infinite"
                        }
                    )
                ], className="text-center mb-3"),

                # Main title
                html.H1("IoTSentinel", className="text-center mb-2 text-gradient", style={
                    "fontSize": "2.5rem",
                    "fontWeight": "800",
                    "letterSpacing": "-2px",
                    "lineHeight": "1.1"
                }),

                html.H2("Network Security Monitoring", className="text-center mb-3", style={
                    "fontSize": "1.3rem",
                    "fontWeight": "600",
                    "letterSpacing": "-0.5px",
                    "color": "var(--text-secondary)"
                }),

                # Features list with badge design
                html.Div([
                    html.Div([
                        html.I(className="fa fa-diagram-project", style={
                            "fontSize": "1.5rem",
                            "color": "#667eea",
                            "marginBottom": "0.4rem"
                        }),
                        html.Div("Real-time Monitoring", style={
                            "fontSize": "0.85rem",
                            "fontWeight": "600",
                            "color": "var(--text-primary)",
                            "marginBottom": "0.2rem"
                        }),
                        html.Div("Track connected devices", style={
                            "fontSize": "0.75rem",
                            "color": "var(--text-secondary)"
                        })
                    ], className="text-center p-2", style={
                        "background": "rgba(102, 126, 234, 0.08)",
                        "borderRadius": "10px",
                        "border": "1px solid rgba(102, 126, 234, 0.2)"
                    }),

                    html.Div([
                        html.I(className="fa fa-brain", style={
                            "fontSize": "1.5rem",
                            "color": "#f093fb",
                            "marginBottom": "0.4rem"
                        }),
                        html.Div("AI Threat Detection", style={
                            "fontSize": "0.85rem",
                            "fontWeight": "600",
                            "color": "var(--text-primary)",
                            "marginBottom": "0.2rem"
                        }),
                        html.Div("ML-powered analysis", style={
                            "fontSize": "0.75rem",
                            "color": "var(--text-secondary)"
                        })
                    ], className="text-center p-2", style={
                        "background": "rgba(240, 147, 251, 0.08)",
                        "borderRadius": "10px",
                        "border": "1px solid rgba(240, 147, 251, 0.2)"
                    }),

                    html.Div([
                        html.I(className="fa fa-chart-network", style={
                            "fontSize": "1.5rem",
                            "color": "#4facfe",
                            "marginBottom": "0.4rem"
                        }),
                        html.Div("Network Analytics", style={
                            "fontSize": "0.85rem",
                            "fontWeight": "600",
                            "color": "var(--text-primary)",
                            "marginBottom": "0.2rem"
                        }),
                        html.Div("Deep traffic insights", style={
                            "fontSize": "0.75rem",
                            "color": "var(--text-secondary)"
                        })
                    ], className="text-center p-2", style={
                        "background": "rgba(79, 172, 254, 0.08)",
                        "borderRadius": "10px",
                        "border": "1px solid rgba(79, 172, 254, 0.2)"
                    }),

                    html.Div([
                        html.I(className="fa fa-gauge-high", style={
                            "fontSize": "1.5rem",
                            "color": "#10b981",
                            "marginBottom": "0.4rem"
                        }),
                        html.Div("Security Dashboard", style={
                            "fontSize": "0.85rem",
                            "fontWeight": "600",
                            "color": "var(--text-primary)",
                            "marginBottom": "0.2rem"
                        }),
                        html.Div("Complete visibility", style={
                            "fontSize": "0.75rem",
                            "color": "var(--text-secondary)"
                        })
                    ], className="text-center p-2", style={
                        "background": "rgba(16, 185, 129, 0.08)",
                        "borderRadius": "10px",
                        "border": "1px solid rgba(16, 185, 129, 0.2)"
                    })
                ], className="mt-3", style={
                    "display": "grid",
                    "gridTemplateColumns": "repeat(2, 1fr)",
                    "gap": "0.6rem",
                    "maxWidth": "650px",
                    "margin": "0 auto"
                }),

                # Trust Signals & Security Badges
                html.Div([
                    html.Div([
                        html.I(className="fa fa-shield-halved", style={
                            "fontSize": "1.5rem",
                            "color": "#10b981",
                            "marginBottom": "0.4rem"
                        }),
                        html.Div("End-to-End Encryption", style={
                            "fontSize": "0.85rem",
                            "fontWeight": "600",
                            "color": "var(--text-primary)",
                            "marginBottom": "0.2rem"
                        }),
                        html.Div("256-bit AES", style={
                            "fontSize": "0.75rem",
                            "color": "var(--text-secondary)"
                        })
                    ], className="text-center p-2", style={
                        "background": "rgba(16, 185, 129, 0.08)",
                        "borderRadius": "10px",
                        "border": "1px solid rgba(16, 185, 129, 0.2)"
                    }),

                    html.Div([
                        html.I(className="fa fa-shield-keyhole", style={
                            "fontSize": "1.5rem",
                            "color": "#3b82f6",
                            "marginBottom": "0.4rem"
                        }),
                        html.Div("Data Stays Local", style={
                            "fontSize": "0.85rem",
                            "fontWeight": "600",
                            "color": "var(--text-primary)",
                            "marginBottom": "0.2rem"
                        }),
                        html.Div("Never shared", style={
                            "fontSize": "0.75rem",
                            "color": "var(--text-secondary)"
                        })
                    ], className="text-center p-2", style={
                        "background": "rgba(59, 130, 246, 0.08)",
                        "borderRadius": "10px",
                        "border": "1px solid rgba(59, 130, 246, 0.2)"
                    }),

                    html.Div([
                        html.I(className="fab fa-github", style={
                            "fontSize": "1.5rem",
                            "color": "#a855f7",
                            "marginBottom": "0.4rem"
                        }),
                        html.Div("Open Source", style={
                            "fontSize": "0.85rem",
                            "fontWeight": "600",
                            "color": "var(--text-primary)",
                            "marginBottom": "0.2rem"
                        }),
                        html.Div("Auditable code", style={
                            "fontSize": "0.75rem",
                            "color": "var(--text-secondary)"
                        })
                    ], className="text-center p-2", style={
                        "background": "rgba(168, 85, 247, 0.08)",
                        "borderRadius": "10px",
                        "border": "1px solid rgba(168, 85, 247, 0.2)"
                    })
                ], className="mt-3", style={
                    "display": "grid",
                    "gridTemplateColumns": "repeat(3, 1fr)",
                    "gap": "0.6rem",
                    "maxWidth": "650px",
                    "margin": "0 auto"
                })
            ], className="d-flex flex-column justify-content-center", style={
                "height": "100%",
                "padding": "2rem 2rem"
            })
        ], md=6, className="d-none d-md-flex align-items-center justify-content-center", style={
            "minHeight": "100vh",
            "position": "relative"
        }),

        # RIGHT SIDE - Login/Register Form
        dbc.Col([
            # Login/Register Card with Liquid Glass Effect
            dbc.Card([
                dbc.CardBody([
                    # Welcome message at top with better styling
                    html.Div([
                        html.Div([
                            html.I(className="fa fa-sign-in-alt", style={
                                "fontSize": "2rem",
                                "color": "var(--accent-color)",
                                "marginRight": "0.75rem",
                                "filter": "drop-shadow(0 0 10px rgba(102, 126, 234, 0.5))"
                            }),
                            html.H2("Sign In", className="mb-0", style={
                                "fontWeight": "700",
                                "fontSize": "2rem",
                                "color": "var(--text-primary)",
                                "letterSpacing": "-0.5px"
                            })
                        ], className="d-flex align-items-center justify-content-center mb-2"),
                        html.P("Sign in to access the dashboard", className="mb-0", style={
                            "color": "var(--text-secondary)",
                            "fontSize": "0.9rem",
                            "fontWeight": "500"
                        })
                    ], className="text-center mb-4"),

                    # Tabs for Login/Register
                    dbc.Tabs([
                        # Login Tab
                        dbc.Tab([
                            html.Form([
                                # Username Input with Floating Label
                                html.Div([
                                    html.I(className="fa fa-user input-icon"),
                                    dbc.Input(
                                        id="login-username",
                                        type="text",
                                        placeholder=" ",
                                        autocomplete="username",
                                        className="form-control",
                                        style={"border": "1px solid var(--border-color)"}
                                    ),
                                    html.Label("Username", htmlFor="login-username")
                                ], className="floating-input-group mt-3"),

                                # Password Input with Floating Label
                                html.Div([
                                    html.I(className="fa fa-lock input-icon"),
                                    dbc.Input(
                                        id="login-password",
                                        type="password",
                                        placeholder=" ",
                                        autocomplete="current-password",
                                        n_submit=0,
                                        className="form-control",
                                        style={"border": "1px solid var(--border-color)", "paddingRight": "3rem"}
                                    ),
                                    html.Label("Password", htmlFor="login-password"),
                                    dbc.Button(
                                        html.I(id="login-password-toggle", className="fa fa-eye"),
                                        id="login-password-toggle-btn",
                                        className="password-toggle-btn"
                                    )
                                ], className="floating-input-group"),

                                # 2FA Verification (hidden by default, shown when needed)
                                html.Div([
                                    html.Div([
                                        html.I(className="fa fa-shield-alt me-2 text-success"),
                                        html.Strong("Two-Factor Authentication Required"),
                                    ], className="d-flex align-items-center mb-2"),
                                    html.P("Enter the 6-digit code from your authenticator app:", className="text-muted small mb-2"),
                                    dbc.InputGroup([
                                        dbc.InputGroupText(html.I(className="fa fa-mobile-alt")),
                                        dbc.Input(
                                            id="login-totp-code",
                                            type="text",
                                            placeholder="000000",
                                            maxLength=6,
                                            className="text-center font-monospace",
                                            style={"fontSize": "1.5rem", "letterSpacing": "0.5rem"}
                                        )
                                    ], className="mb-2"),
                                    html.Div([
                                        dbc.Checkbox(
                                            id="use-backup-code-checkbox",
                                            label="Use backup code instead",
                                            value=False,
                                            className="small"
                                        )
                                    ], className="mb-2"),
                                    html.Div(id='totp-login-status')
                                ], id='login-totp-section', style={'display': 'none'}, className="mb-3 p-3 border rounded bg-light"),

                                # Remember Me & Forgot Password Row
                                html.Div([
                                    html.Div([
                                        dbc.Checkbox(
                                            id="remember-me-checkbox",
                                            label="Remember me",
                                            value=False
                                        )
                                    ], className="custom-checkbox"),
                                    html.A(
                                        "Forgot password?",
                                        id="forgot-password-link",
                                        href="#"
                                    )
                                ], className="auth-options-container"),

                                # Login Button
                                dbc.Button(
                                    [html.I(className="fa fa-sign-in-alt me-2"), "Sign In"],
                                    id="login-button",
                                    className="w-100 mt-2 cyber-button-modern",
                                    size="lg",
                                ),

                                # OAuth Divider
                                html.Div([
                                    html.Div(style={
                                        "borderTop": "1px solid var(--border-color)",
                                        "position": "relative",
                                        "margin": "1rem 0"
                                    }),
                                    html.Span("OR", style={
                                        "position": "absolute",
                                        "top": "-0.6rem",
                                        "left": "50%",
                                        "transform": "translateX(-50%)",
                                        "background": "var(--bg-secondary)",
                                        "padding": "0 0.75rem",
                                        "color": "var(--text-secondary)",
                                        "fontSize": "0.8rem",
                                        "fontWeight": "600"
                                    })
                                ], style={"position": "relative"}),

                                # Google Sign-In Button
                                html.Div([
                                    html.A(
                                        [
                                            html.Img(
                                                src="https://www.google.com/favicon.ico",
                                                style={
                                                    "width": "20px",
                                                    "height": "20px",
                                                    "marginRight": "0.75rem",
                                                    "verticalAlign": "middle"
                                                }
                                            ),
                                            html.Span("Continue with Google", style={"verticalAlign": "middle"})
                                        ],
                                        href="/auth/google",
                                        className="w-100 btn btn-outline-light",
                                        style={
                                            "display": "flex",
                                            "alignItems": "center",
                                            "justifyContent": "center",
                                            "padding": "0.75rem",
                                            "fontSize": "0.95rem",
                                            "fontWeight": "600",
                                            "border": "1px solid var(--border-color)",
                                            "borderRadius": "8px",
                                            "background": "var(--bg-tertiary)",
                                            "color": "var(--text-primary)",
                                            "textDecoration": "none",
                                            "transition": "all 0.3s ease"
                                        },
                                        id="google-signin-btn"
                                    )
                                ], className="mb-2", id="oauth-section"),

                                # Biometric Login Button (shown if WebAuthn supported)
                                html.Div([
                                    dbc.Button(
                                        [
                                            html.I(className="fa fa-fingerprint me-2", style={"fontSize": "1.25rem"}),
                                            html.Span("Sign in with Biometrics")
                                        ],
                                        id="biometric-login-btn",
                                        className="w-100",
                                        color="primary",
                                        outline=True,
                                        style={
                                            "padding": "0.75rem",
                                            "fontSize": "0.95rem",
                                            "fontWeight": "600",
                                            "border": "1px solid var(--accent-color)",
                                            "borderRadius": "8px",
                                            "background": "rgba(102, 126, 234, 0.1)",
                                            "color": "var(--accent-color)",
                                            "transition": "all 0.3s ease",
                                            "display": "none"  # Hidden by default, shown via JS if WebAuthn available
                                        }
                                    )
                                ], className="mb-3", id="biometric-section"),

                                # Security Guarantees Below Login Form
                                html.Div([
                                    html.Div([
                                        html.I(className="fa fa-shield-check", style={
                                            "color": "#10b981",
                                            "fontSize": "1rem",
                                            "marginRight": "0.5rem"
                                        }),
                                        html.Span("Encrypted passwords with bcrypt", style={
                                            "fontSize": "0.85rem",
                                            "color": "var(--text-primary)",
                                            "fontWeight": "500"
                                        })
                                    ], className="d-flex align-items-center mb-2"),
                                    html.Div([
                                        html.I(className="fa fa-user-shield", style={
                                            "color": "#3b82f6",
                                            "fontSize": "1rem",
                                            "marginRight": "0.5rem"
                                        }),
                                        html.Span("We never share your data", style={
                                            "fontSize": "0.85rem",
                                            "color": "var(--text-primary)",
                                            "fontWeight": "500"
                                        })
                                    ], className="d-flex align-items-center")
                                ], className="mt-3", style={
                                    "padding": "0.875rem 1rem",
                                    "background": "rgba(59, 130, 246, 0.05)",
                                    "borderRadius": "10px",
                                    "border": "1px solid rgba(59, 130, 246, 0.15)"
                                }),

                            ])
                        ], label="Login", tab_id="login-tab", activeTabClassName="fw-bold", className="glass-card"),

                        # Register Tab
                        dbc.Tab([
                            html.Form([
                                dbc.Alert(id="register-alert", is_open=False, duration=4000, className="mt-3"),

                                # Email Input with Floating Label
                                html.Div([
                                    html.I(className="fa fa-envelope input-icon"),
                                    dbc.Input(
                                        id="register-email",
                                        type="email",
                                        placeholder=" ",
                                        autocomplete="email",
                                        className="form-control",
                                        style={"border": "1px solid var(--border-color)"}
                                    ),
                                    html.Label("Email Address", htmlFor="register-email")
                                ], className="floating-input-group mt-3"),
                                html.Div(id="email-validation-feedback", className="validation-feedback mb-2"),

                                # Username Input with Floating Label
                                html.Div([
                                    html.I(className="fa fa-user input-icon"),
                                    dbc.Input(
                                        id="register-username",
                                        type="text",
                                        placeholder=" ",
                                        autocomplete="off",
                                        className="form-control",
                                        style={"border": "1px solid var(--border-color)"}
                                    ),
                                    html.Label("Username", htmlFor="register-username")
                                ], className="floating-input-group"),
                                html.Div(id="username-validation-feedback", className="validation-feedback mb-2"),

                                # New Password Input with Floating Label
                                html.Div([
                                    html.I(className="fa fa-lock input-icon"),
                                    dbc.Input(
                                        id="register-password",
                                        type="password",
                                        placeholder=" ",  # Space required for :not(:placeholder-shown)
                                        autocomplete="new-password",
                                        className="form-control",
                                        style={"border": "1px solid var(--border-color)", "paddingRight": "3rem"}
                                    ),
                                    html.Label("Password", htmlFor="register-password"),
                                    dbc.Button(
                                        html.I(id="register-password-toggle", className="fa fa-eye"),
                                        id="register-password-toggle-btn",
                                        className="password-toggle-btn"
                                    )
                                ], className="floating-input-group"),

                                # Password Strength Meter & Requirements
                                html.Div([
                                    html.Div([
                                        html.Small("Password Strength:", className="text-secondary d-block mb-1", style={"fontSize": "0.85rem"}),
                                        html.Div([
                                            html.Div(id="password-strength-bar", style={
                                                "height": "8px",
                                                "borderRadius": "4px",
                                                "backgroundColor": "var(--border-color)",
                                                "transition": "all 0.3s ease",
                                                "width": "0%"
                                            })
                                        ], style={"width": "100%", "backgroundColor": "var(--bg-tertiary)", "borderRadius": "4px", "height": "8px"}),
                                        html.Small(id="password-strength-text", className="text-muted d-block mt-1", style={"fontSize": "0.8rem"})
                                    ], id="password-strength-container", style={"display": "block"}), # Always show strength container
                                    html.Div([
                                        html.Small("Password must contain:", className="text-secondary d-block mt-2 fw-bold"),
                                        html.Ul([
                                            html.Li([html.I(className="fa fa-times-circle me-2 text-danger", id="req-length"), "At least 8 characters"]),
                                            html.Li([html.I(className="fa fa-times-circle me-2 text-danger", id="req-upper"), "An uppercase letter (A-Z)"]),
                                            html.Li([html.I(className="fa fa-times-circle me-2 text-danger", id="req-lower"), "A lowercase letter (a-z)"]),
                                            html.Li([html.I(className="fa fa-times-circle me-2 text-danger", id="req-digit"), "A number (0-9)"]),
                                            html.Li([html.I(className="fa fa-times-circle me-2 text-danger", id="req-special"), "A special character (!@#$...)"])
                                        ], className="list-unstyled text-muted password-requirements", style={"fontSize": "0.8rem", "paddingLeft": "1rem"})
                                    ])
                                ], className="mb-2"),

                                # Confirm Password Input with Floating Label
                                html.Div([
                                    html.I(className="fa fa-lock input-icon"),
                                    dbc.Input(
                                        id="register-password-confirm",
                                        type="password",
                                        placeholder=" ",  # Space required for :not(:placeholder-shown)
                                        autocomplete="new-password",
                                        className="form-control",
                                        style={"border": "1px solid var(--border-color)", "paddingRight": "3rem"}
                                    )
                                    ,html.Label("Confirm Password", htmlFor="register-password-confirm"),
                                    dbc.Button(
                                        html.I(id="register-password-confirm-toggle", className="fa fa-eye"),
                                        id="register-password-confirm-toggle-btn",
                                        className="password-toggle-btn"
                                    )
                                ], className="floating-input-group mb-0"), # Adjusted mb-3 to mb-0
                                html.Div(id="password-match-feedback", className="validation-feedback mb-3"), # Added password match feedback


                                # Send Verification Code Button
                                dbc.Button(
                                    [html.I(className="fa fa-paper-plane me-2"), "Send Verification Code"],
                                    id="send-verification-btn",
                                    className="w-100 mb-3",
                                    color="info",
                                    outline=True,
                                    style={"fontWeight": "600"}
                                ),

                                # Verification Code Input (initially hidden) with Floating Label
                                html.Div([
                                    html.Div([
                                        html.I(className="fa fa-key input-icon"),
                                        dbc.Input(
                                            id="verification-code",
                                            type="text",
                                            placeholder=" ",  # Space required for :not(:placeholder-shown)
                                            maxLength=6,
                                            className="form-control",
                                            style={"border": "1px solid var(--border-color)"}
                                        ),
                                        html.Label("Verification Code", htmlFor="verification-code")
                                    ], className="floating-input-group mb-3")
                                ], id="verification-code-container", style={"display": "none"}),

                                # Dashboard Template Selection
                                html.Div([
                                    html.Label([
                                        html.I(className="fa fa-layout me-2 text-primary"),
                                        "Choose Your Dashboard Template"
                                    ], className="fw-bold mb-2 d-block"),
                                    html.Small("Select a pre-configured layout (you can change this later)", className="text-muted d-block mb-2"),
                                    dbc.Select(
                                        id='register-template-select',
                                        options=[
                                            {'label': '🏠 Home User - Simplified & easy to use', 'value': 'home_user'},
                                            {'label': '💻 Developer - All features & advanced tools', 'value': 'developer'},
                                            {'label': '⚙️ Custom - I\'ll customize it myself', 'value': 'custom'}
                                        ],
                                        value='home_user',
                                        className="mb-3"
                                    )
                                ], className="mb-3"),

                                # Family Role Selection (for Home Users)
                                html.Div([
                                    html.Label([
                                        html.I(className="fa fa-users me-2 text-info"),
                                        "Family Member Role"
                                    ], className="fw-bold mb-2 d-block"),
                                    html.Small("Select your role in the family (affects available features)", className="text-muted d-block mb-2"),
                                    dbc.Select(
                                        id='register-family-role-select',
                                        options=[
                                            {'label': '👨‍👩‍👧‍👦 Parent/Guardian - Full access to all features', 'value': 'parent'},
                                            {'label': '👶 Child - Restricted access for safety', 'value': 'kid'}
                                        ],
                                        value='parent',
                                        className="mb-3"
                                    ),
                                    html.Small([
                                        html.I(className="fa fa-info-circle me-1 text-info"),
                                        "Children cannot activate emergency mode or change critical security settings"
                                    ], className="text-muted d-block")
                                ], className="mb-3"),

                                # Hidden role field - always viewer for self-registration
                                dcc.Store(id="register-role", data="viewer"),
                                dcc.Store(id='verification-code-sent', storage_type='memory'),
                                dcc.Store(id='email-verified', storage_type='memory'),

                                # 2FA Login State Store
                                dcc.Store(id='totp-login-state', storage_type='memory'),  # Stores username during 2FA verification

                                # Register Button
                                dbc.Button(
                                    [html.I(className="fa fa-user-plus me-2"), "Create Account"],
                                    id="register-button",
                                    className="w-100 mt-2 cyber-button-modern",
                                    size="lg",
                                    disabled=False,
                                ),

                                # Security Guarantees Below Register Form
                                html.Div([
                                    html.Div("🔒 Your Security Guarantees", style={
                                        "fontSize": "0.9rem",
                                        "fontWeight": "700",
                                        "color": "var(--text-primary)",
                                        "textAlign": "center",
                                        "marginBottom": "0.75rem"
                                    }),
                                    html.Div([
                                        html.I(className="fa fa-check-circle me-2", style={"color": "#10b981", "fontSize": "0.85rem"}),
                                        html.Span("End-to-end encryption protects all data", style={
                                            "fontSize": "0.8rem",
                                            "color": "var(--text-secondary)"
                                        })
                                    ], className="d-flex align-items-start mb-2"),
                                    html.Div([
                                        html.I(className="fa fa-check-circle me-2", style={"color": "#10b981", "fontSize": "0.85rem"}),
                                        html.Span("Passwords hashed with bcrypt (never stored in plain text)", style={
                                            "fontSize": "0.8rem",
                                            "color": "var(--text-secondary)"
                                        })
                                    ], className="d-flex align-items-start mb-2"),
                                    html.Div([
                                        html.I(className="fa fa-check-circle me-2", style={"color": "#10b981", "fontSize": "0.85rem"}),
                                        html.Span("Your data stays local - never shared or sold", style={
                                            "fontSize": "0.8rem",
                                            "color": "var(--text-secondary)"
                                        })
                                    ], className="d-flex align-items-start mb-2"),
                                    html.Div([
                                        html.I(className="fa fa-check-circle me-2", style={"color": "#10b981", "fontSize": "0.85rem"}),
                                        html.Span("Open source code - fully auditable", style={
                                            "fontSize": "0.8rem",
                                            "color": "var(--text-secondary)"
                                        })
                                    ], className="d-flex align-items-start")
                                ], className="mt-4", style={
                                    "padding": "1.25rem",
                                    "background": "rgba(16, 185, 129, 0.05)",
                                    "borderRadius": "10px",
                                    "border": "1px solid rgba(16, 185, 129, 0.2)"
                                })
                            ])
                        ], label="Register", tab_id="register-tab", activeTabClassName="fw-bold", className="glass-card")
                    ], id="auth-tabs", active_tab="login-tab", className="mb-0")
                ], style={"padding": "2.5rem 2rem"})
            ], className="glass-card hover-lift", style={
                "maxWidth": "520px",
                "width": "100%",
                "boxShadow": "0 20px 80px rgba(0, 0, 0, 0.3), 0 0 60px var(--accent-glow)",
                "border": "1px solid var(--border-color)"
            })
        ], width=12, md=6, className="d-flex justify-content-center align-items-center", style={
            "minHeight": "100vh",
            "padding": "2rem"
        })
    ], className="g-0 min-vh-100"),

    # Forgot Password Modal
    dbc.Modal([
        dbc.ModalHeader(
            dbc.ModalTitle([
                html.I(className="fa fa-key me-2", style={"color": "var(--accent-color)"}),
                "Reset Your Password"
            ]),
            close_button=True
        ),
        dbc.ModalBody([
            # Step 1: Email Input with Floating Label
            html.Div([
                html.P("Enter your email address and we'll send you a password reset link.",
                       className="text-secondary mb-3", style={"fontSize": "0.95rem"}),
                html.Div([
                    html.I(className="fa fa-envelope input-icon"),
                    dbc.Input(
                        id="forgot-password-email",
                        type="email",
                        placeholder=" ",  # Space required for :not(:placeholder-shown)
                        autocomplete="email",
                        className="form-control",
                        style={"border": "1px solid var(--border-color)"}
                    ),
                    html.Label("Email Address", htmlFor="forgot-password-email")
                ], className="floating-input-group mb-3"),
                html.Div(id="forgot-password-message")
            ], id="forgot-password-step-1"),

            # Step 2: Success Message (initially hidden)
            html.Div([
                html.Div([
                    html.I(className="fa fa-check-circle fa-3x text-success mb-3"),
                    html.H5("Check Your Email", className="mb-2"),
                    html.P([
                        "We've sent a password reset link to ",
                        html.Strong(id="reset-email-display", className="text-primary")
                    ], className="text-secondary mb-2"),
                    html.P("The link will expire in 1 hour.",
                           className="text-muted small")
                ], className="text-center")
            ], id="forgot-password-step-2", style={"display": "none"})
        ]),
        dbc.ModalFooter([
            dbc.Button("Cancel", id="forgot-password-cancel", color="secondary", outline=True),
            dbc.Button(
                [html.I(className="fa fa-paper-plane me-2"), "Send Reset Link"],
                id="forgot-password-submit",
                color="primary",
                className="cyber-button-modern"
            )
        ], id="forgot-password-footer")
    ], id="forgot-password-modal", size="md", is_open=False, className="glass-modal")

], fluid=True, style={
    "position": "relative",
    "minHeight": "100vh"
})

# ============================================================================
# DASHBOARD LAYOUT
# ============================================================================

# ============================================================================
# SPOTLIGHT SEARCH - FEATURE CATALOG & HELPER FUNCTIONS
# ============================================================================

# Universal Search Feature Catalog for Spotlight-like navigation
SEARCH_FEATURE_CATALOG = [
    # Analytics (2 features)
    {"id": "analytics-modal", "name": "Analytics Dashboard", "description": "View security status, alert timelines, anomaly distribution, and device analytics", "icon": "fa-chart-pie", "category": "Analytics", "keywords": ["analytics", "charts", "statistics", "security status", "alerts", "anomaly", "insights", "visualization", "viz"], "action_type": "modal"},
    {"id": "risk-heatmap-modal", "name": "Risk Heatmap", "description": "Visual heatmap showing network risk distribution and vulnerable areas", "icon": "fa-fire-flame-curved", "category": "Analytics", "keywords": ["risk", "heatmap", "visualization", "viz", "vulnerable", "areas", "security"], "action_type": "modal"},
    # Device Management (2 features)
    {"id": "device-mgmt-modal", "name": "Device Management", "description": "Manage network devices, trust levels, groups, and device information", "icon": "fa-diagram-project", "category": "Device Management", "keywords": ["devices", "manage", "trust", "network", "groups", "mac", "ip"], "action_type": "modal"},
    {"id": "user-modal", "name": "User Management", "description": "Manage user accounts, roles, permissions, and access control (Admin only)", "icon": "fa-users-gear", "category": "Device Management", "keywords": ["users", "accounts", "roles", "admin", "permissions", "access"], "action_type": "modal"},
    # Security (5 features)
    {"id": "firewall-modal", "name": "Firewall Rules", "description": "Configure and manage firewall rules for network protection", "icon": "fa-shield-halved", "category": "Security", "keywords": ["firewall", "rules", "protection", "block", "allow", "security"], "action_type": "modal"},
    {"id": "threat-modal", "name": "Threat Intelligence", "description": "View threat analysis, malicious IPs, and security intelligence data", "icon": "fa-shield-virus", "category": "Security", "keywords": ["threat", "intelligence", "malicious", "ips", "security", "analysis"], "action_type": "modal"},
    {"id": "vuln-scanner-modal", "name": "Vulnerability Scanner", "description": "Scan network for vulnerabilities and security weaknesses", "icon": "fa-magnifying-glass-chart", "category": "Security", "keywords": ["vulnerability", "scanner", "scan", "weaknesses", "security", "cve"], "action_type": "modal"},
    {"id": "privacy-modal", "name": "Privacy Monitor", "description": "Monitor privacy risks, data exposure, and privacy score", "icon": "fa-user-shield", "category": "Security", "keywords": ["privacy", "monitor", "data", "exposure", "score", "risks"], "action_type": "modal"},
    {"id": "compliance-modal", "name": "Compliance Dashboard", "description": "Track compliance with security standards and regulations", "icon": "fa-list-check", "category": "Security", "keywords": ["compliance", "standards", "regulations", "gdpr", "hipaa", "audit"], "action_type": "modal"},
    # System & Configuration (5 features)
    {"id": "system-modal", "name": "System Information", "description": "View system resources, performance metrics, and hardware details", "icon": "fa-server", "category": "System", "keywords": ["system", "resources", "performance", "cpu", "memory", "hardware"], "action_type": "modal"},
    {"id": "email-modal", "name": "Email Notifications", "description": "Configure SMTP settings and email alert preferences", "icon": "fa-envelope", "category": "System", "keywords": ["email", "smtp", "notifications", "alerts", "mail", "settings"], "action_type": "modal"},
    {"id": "preferences-modal", "name": "Dashboard Preferences", "description": "Customize dashboard layout, widgets, and display preferences", "icon": "fa-sliders-h", "category": "System", "keywords": ["preferences", "settings", "customize", "layout", "widgets", "display"], "action_type": "modal"},
    {"id": "quick-settings-modal", "name": "Quick Settings", "description": "Fast access to common settings: network, notifications, display, and performance", "icon": "fa-cog", "category": "System", "keywords": ["quick", "settings", "config", "preferences", "network", "notifications"], "action_type": "modal"},
    {"id": "profile-edit-modal", "name": "Edit Profile", "description": "Update your user profile, password, and account settings", "icon": "fa-user-edit", "category": "System", "keywords": ["profile", "edit", "account", "password", "settings", "user"], "action_type": "modal"},
    # IoT Features (4 features)
    {"id": "smarthome-modal", "name": "Smart Home Hub Detection", "description": "Detect and manage smart home hubs and IoT devices", "icon": "fa-house-signal", "category": "IoT", "keywords": ["smart home", "hub", "iot", "devices", "detection", "alexa", "google home"], "action_type": "modal"},
    {"id": "segmentation-modal", "name": "Network Segmentation", "description": "Configure network segmentation and VLAN isolation for IoT devices", "icon": "fa-layer-group", "category": "IoT", "keywords": ["segmentation", "vlan", "isolation", "network", "iot", "zones"], "action_type": "modal"},
    {"id": "firmware-modal", "name": "Firmware Management", "description": "Track device firmware versions and security updates", "icon": "fa-microchip", "category": "IoT", "keywords": ["firmware", "updates", "versions", "security", "patches", "iot"], "action_type": "modal"},
    {"id": "protocol-modal", "name": "Protocol Analyzer", "description": "Analyze network protocols and IoT communication patterns", "icon": "fa-network-wired", "category": "IoT", "keywords": ["protocol", "analyzer", "mqtt", "http", "coap", "communication", "iot"], "action_type": "modal"},
    # Intelligence & Analysis (4 features)
    {"id": "threat-map-modal", "name": "3D Threat Map", "description": "Interactive 3D visualization of global threat origins and attack patterns", "icon": "fa-earth-americas", "category": "Intelligence", "keywords": ["threat", "map", "3d", "visualization", "viz", "global", "attacks", "origins"], "action_type": "modal"},
    {"id": "attack-surface-modal", "name": "Attack Surface Analysis", "description": "Analyze exposed services, open ports, and potential attack vectors", "icon": "fa-bullseye", "category": "Intelligence", "keywords": ["attack", "surface", "analysis", "ports", "services", "exposure", "vectors"], "action_type": "modal"},
    {"id": "forensic-timeline-modal", "name": "Forensic Timeline", "description": "Detailed forensic timeline for incident investigation and analysis", "icon": "fa-microscope", "category": "Intelligence", "keywords": ["forensic", "timeline", "investigation", "incident", "analysis", "events", "visualization", "viz"], "action_type": "modal"},
    {"id": "auto-response-modal", "name": "Automated Response", "description": "Configure automated responses to security threats and incidents", "icon": "fa-wand-magic-sparkles", "category": "Intelligence", "keywords": ["automated", "response", "automation", "threats", "incident", "action"], "action_type": "modal"},
    # Notifications & Alerts (3 features)
    {"id": "alert-details-modal", "name": "Alert Details", "description": "View detailed information about security alerts and incidents", "icon": "fa-triangle-exclamation", "category": "Notifications", "keywords": ["alert", "details", "incident", "security", "notification", "warning"], "action_type": "modal"},
    {"id": "toast-history-modal", "name": "Toast History", "description": "View complete history of toast notifications with filtering", "icon": "fa-clock-rotate-left", "category": "Notifications", "keywords": ["toast", "history", "notifications", "messages", "log"], "action_type": "modal"},
    {"id": "toast-detail-modal", "name": "Toast Details", "description": "View detailed information about a specific toast notification", "icon": "fa-circle-info", "category": "Notifications", "keywords": ["toast", "details", "notification", "info", "message"], "action_type": "modal"},
    # Performance & Monitoring (2 features)
    {"id": "performance-modal", "name": "Performance Analytics", "description": "Monitor network performance, latency, and throughput metrics", "icon": "fa-gauge-high", "category": "Performance", "keywords": ["performance", "analytics", "latency", "throughput", "metrics", "monitoring"], "action_type": "modal"},
    {"id": "benchmark-modal", "name": "Security Benchmark", "description": "Compare your security posture against industry benchmarks", "icon": "fa-chart-column", "category": "Performance", "keywords": ["benchmark", "security", "comparison", "standards", "posture", "metrics"], "action_type": "modal"},
    # Other Features (7 features)
    {"id": "education-modal", "name": "Security Education", "description": "Learn about threat scenarios, security best practices, and educational content", "icon": "fa-user-graduate", "category": "Education", "keywords": ["education", "learning", "security", "threats", "best practices", "training"], "action_type": "modal"},
    {"id": "api-hub-modal", "name": "API Hub", "description": "Access API documentation and integration endpoints", "icon": "fa-code", "category": "Developer", "keywords": ["api", "hub", "documentation", "integration", "endpoints", "developer"], "action_type": "modal"},
    {"id": "quick-actions-modal", "name": "Quick Actions", "description": "Fast access to common actions: scan, export, backup, and system controls", "icon": "fa-bolt-lightning", "category": "Actions", "keywords": ["quick", "actions", "scan", "export", "backup", "controls"], "action_type": "modal"},
    {"id": "customize-layout-modal", "name": "Customize Layout", "description": "Customize dashboard layout, widgets visibility, and display density", "icon": "fa-gears", "category": "Customization", "keywords": ["customize", "layout", "widgets", "visibility", "density", "display"], "action_type": "modal"},
    {"id": "chat-modal", "name": "AI Assistant", "description": "Chat with AI assistant for network security guidance and troubleshooting", "icon": "fa-robot", "category": "Assistance", "keywords": ["ai", "assistant", "chat", "help", "guidance", "troubleshooting"], "action_type": "modal"},
    {"id": "onboarding-modal", "name": "Onboarding Tour", "description": "Interactive tour of dashboard features and capabilities", "icon": "fa-circle-play", "category": "Help", "keywords": ["onboarding", "tour", "tutorial", "guide", "help", "introduction"], "action_type": "modal"},
    {"id": "lockdown-modal", "name": "Lockdown Mode", "description": "Emergency lockdown mode to block all untrusted devices", "icon": "fa-shield-keyhole", "category": "Emergency", "keywords": ["lockdown", "emergency", "block", "security", "protection", "untrusted"], "action_type": "modal"}
]

def create_spotlight_result_item(feature, index, is_selected=False, is_top_hit=False):
    """Create a single search result item for spotlight search with enhanced metadata"""
    return html.Div([
        dbc.Card([
            dbc.CardBody([
                dbc.Row([
                    # Icon (larger for top hit)
                    dbc.Col([
                        html.Div([
                            html.I(className=f"fa {feature['icon']} {'fa-3x' if is_top_hit else 'fa-2x'}",
                                  style={"color": "var(--accent-color)"})
                        ], className="spotlight-result-icon")
                    ], width=2, className="d-flex align-items-center justify-content-center"),

                    # Content
                    dbc.Col([
                        html.Div([
                            # Top Hit Badge + Name
                            html.Div([
                                dbc.Badge("Top Hit", color="success", className="me-2 spotlight-top-hit-badge",
                                         style={"display": "inline-block"}) if is_top_hit else None,
                                html.H6(feature['name'],
                                       className="d-inline-block mb-1 fw-bold",
                                       style={"fontSize": "1.1rem" if is_top_hit else "1rem"})
                            ], className="mb-1"),
                            html.P(feature['description'],
                                  className="mb-1 text-muted small",
                                  style={"fontSize": "0.9rem" if is_top_hit else "0.85rem"}),
                            dbc.Badge(feature['category'],
                                     color="info",
                                     className="me-2 spotlight-category-badge",
                                     pill=True)
                        ])
                    ], width=8),

                    # Action Button
                    dbc.Col([
                        dbc.Button(
                            html.I(className="fa fa-arrow-right"),
                        id={"type": "spotlight-go-to-btn", "index": index, "modal_id": feature['id']},
                        color="primary",
                        size="sm",
                        outline=True,
                        className="spotlight-action-button",
                        title="Open"  # Tooltip
                        )
                    ], width=2, className="d-flex align-items-center justify-content-end")
                ])
            ], className="p-3")
        ], className=f"spotlight-result-card {'spotlight-top-hit-card' if is_top_hit else ''} {'spotlight-result-selected' if is_selected else ''} mb-2")
    ],
    id={"type": "spotlight-result-item", "index": index},
    className="spotlight-result-wrapper"
    )

dashboard_layout = dbc.Container([
    # Modern Header with Glass Effect
    dbc.Card([
        dbc.CardBody([
            dbc.Row([
                dbc.Col([
                    html.Div([
                        html.Img(
                            src="/assets/logo.png",
                            style={
                                "height": "70px",
                                "filter": "drop-shadow(0 0 20px rgba(102, 126, 234, 0.6))",
                                "animation": "logoGlow 3s ease-in-out infinite"
                            },
                            className="me-3"
                        ),
                        html.Div([
                            html.H1([
                                html.Span("IoTSentinel", className="gradient-text fw-bold"),
                            ], className="mb-1", style={"fontSize": "2.2rem", "letterSpacing": "-0.5px"}),
                            html.P([
                                html.I(className="fa fa-microchip me-2 text-primary"),
                                "AI-Powered Network Security | Raspberry Pi 5"
                            ], className="text-muted mb-0", style={"fontSize": "0.95rem"})
                        ])
                    ], className="d-flex align-items-center")
                ], width=6, className="d-flex align-items-center"),
                dbc.Col([
                    html.Div([
                        dbc.Button([
                            html.I(className="fa fa-bell fa-lg"),
                            dbc.Badge(id="notification-badge", color="danger", className="position-absolute top-0 start-100 translate-middle", pill=True, style={"fontSize": "0.6rem"})
                        ], color="link", id="notification-bell-button", className="text-white position-relative px-3"),
                        dbc.Button(html.I(className="fa fa-history fa-lg"), color="link", id="toast-history-toggle-btn", className="text-white px-3 ms-1", title="Toast History"),
                        dbc.Button(html.I(className="fa fa-robot fa-lg"), color="link", id="open-chat-button", className="text-white px-3 ms-1"),
                        dbc.Button(html.I(className="fa fa-pause fa-lg", id="pause-icon"), color="link", id="pause-button", className="text-white px-3 ms-1"),
                        dbc.Button(html.I(className="fa fa-volume-up fa-lg", id="voice-alert-icon"), color="link", id="voice-alert-toggle", className="text-white px-3 ms-1", title="Toggle Voice Alerts"),
                        dbc.Button(html.I(className="fa fa-moon fa-lg", id="dark-mode-icon"), color="link", id="dark-mode-toggle", className="text-white px-3 ms-1", title="Toggle Dark Mode"),
                        dbc.Button(html.I(className="fa fa-th fa-lg"), color="link", id="customize-layout-button", className="text-white px-3 ms-1", title="Customize Layout"),
                        dbc.Button(html.I(className="fa fa-bolt fa-lg"), color="link", id="quick-actions-button", className="text-white px-3 ms-1", title="Quick Actions"),
                        dbc.DropdownMenu([
                            dbc.DropdownMenuItem(
                                html.Div([
                                    html.I(className="fa fa-user me-2"),
                                    html.Span(id="current-user-display-dropdown", children="User")
                                ], className="d-flex align-items-center"),
                                header=True, style={"fontSize": "0.95rem", "fontWeight": "600"}),
                            dbc.DropdownMenuItem(divider=True),
                            dbc.DropdownMenuItem([
                                html.I(className="fa fa-user-edit me-2"),
                                "Edit Profile"
                            ], id="edit-profile-btn"),
                            dbc.DropdownMenuItem([
                                html.I(className="fa fa-play-circle me-2"),
                                "Restart Tour"
                            ], id="restart-tour-button"),
                            html.Div([
                                dbc.DropdownMenuItem(divider=True, id="admin-divider", style={"display": "none"}),
                                dbc.DropdownMenuItem([
                                    html.I(className="fa fa-users-cog me-2"),
                                    "User Management"
                                ], id="profile-user-mgmt-btn", style={"display": "none"})
                            ], id="admin-menu-items"),
                            dbc.DropdownMenuItem(divider=True),
                            dbc.DropdownMenuItem([
                                html.I(className="fa fa-sign-out-alt me-2 text-danger"),
                                "Logout"
                            ], href="/logout")
                        ], label=html.I(className="fa fa-user-circle fa-lg"),
                           color="link",
                           className="profile-dropdown ms-2",
                           style={"color": "white"},
                           toggle_style={"padding": "0.5rem 0.75rem"})
                    ], className="d-flex align-items-center ms-auto")
                ], width=6, className="d-flex align-items-center justify-content-end")
            ])
        ], className="p-4")
    ], className="mb-4 glass-card border-0 shadow-lg"),

    # Header Tooltips
    dbc.Tooltip(
        "Notifications - View security alerts and system notifications. "
        "Badge shows unread count. Click to open notification drawer.",
        target="notification-bell-button",
        placement="bottom"
    ),
    dbc.Tooltip(
        "Toast History - View all recent toast notifications. "
        "Filter by category and type. Access complete notification history.",
        target="toast-history-toggle-btn",
        placement="bottom"
    ),
    dbc.Tooltip(
        "AI Assistant - Open the intelligent chat assistant. "
        "Ask questions about your network security, get recommendations, and troubleshoot issues.",
        target="open-chat-button",
        placement="bottom"
    ),
    dbc.Tooltip(
        "Pause/Resume - Pause or resume real-time dashboard updates. "
        "Useful when analyzing specific data without auto-refresh.",
        target="pause-button",
        placement="bottom"
    ),
    dbc.Tooltip(
        "Voice Alerts - Toggle text-to-speech announcements for critical security alerts. "
        "Get audio notifications even when not watching the dashboard.",
        target="voice-alert-toggle",
        placement="bottom"
    ),
    dbc.Tooltip(
        "Theme Switcher - Cycle through Light → Dark → Auto modes. "
        "Auto mode follows your system preference. Click to switch themes instantly.",
        target="dark-mode-toggle",
        placement="bottom"
    ),
    dbc.Tooltip(
        "Widget & Layout Customization - Control which widgets are visible, adjust display density, "
        "configure refresh rates, manage notifications, and personalize your monitoring experience.",
        target="customize-layout-button",
        placement="bottom"
    ),
    dbc.Tooltip(
        "Quick Actions - Access 17 powerful tools to manage your dashboard, security, network, data, and system. "
        "Instantly refresh data, scan network, export reports, block devices, backup data, and more!",
        target="quick-actions-button",
        placement="bottom"
    ),

    # ============================================================================
    # TABBED NAVIGATION - Wraps all visible content sections
    # ============================================================================
    dcc.Tabs(id='main-dashboard-tabs', value='tab-overview', className='dashboard-main-tabs', children=[

    # ====================== TAB 1: OVERVIEW ======================
    dcc.Tab(label='Overview', value='tab-overview', className='dashboard-tab',
            selected_className='dashboard-tab--selected', children=[

    # SECURITY SCORE DASHBOARD - Full Width Section
    html.Div(id='security-score-section', children=[
        dbc.Card([
            dbc.CardHeader([
                html.Div([
                    html.Div([
                        html.I(className="fa fa-shield-alt me-2", style={"color": "#10b981"}),
                        html.Span("Network Security Score", className="fw-bold"),
                    ], className="d-flex align-items-center"),
                    html.Div([
                        html.Small(id="security-score-last-updated", children="Last updated: Never",
                                 className="badge bg-light text-dark me-2", style={"padding": "0.4rem 0.6rem"}),
                        dbc.Button([
                            html.I(className="fa fa-sync-alt me-1"),
                            "Refresh"
                        ], id="security-score-refresh-btn", size="sm", color="light", outline=True)
                    ], className="d-flex align-items-center")
                ], className="d-flex justify-content-between align-items-center w-100")
            ], className="bg-gradient-success text-white"),
            dbc.CardBody([
                dbc.Row([
                    # Left: Large Gauge Chart
                    dbc.Col([
                        dcc.Loading(
                            dcc.Graph(
                                id='security-score-gauge',
                                config={'displayModeBar': False},
                                style={'height': '350px'}
                            ),
                            type="circle"
                        )
                    ], width=5),

                    # Right: 4 Dimensional Breakdown Cards
                    dbc.Col([
                        dbc.Row([
                            # Device Health
                            dbc.Col([
                                dbc.Card([
                                    dbc.CardBody([
                                        html.Div([
                                            html.I(className="fa fa-heartbeat text-success fa-2x mb-2"),
                                            html.H4(id="security-score-health", children="--",
                                                  className="mb-1 fw-bold"),
                                            html.P("Device Health", className="text-muted mb-0 small"),
                                            html.Small(id="security-score-health-detail", children="",
                                                     className="text-muted d-block", style={"fontSize": "0.7rem"})
                                        ], className="text-center")
                                    ], className="p-3")
                                ], className="glass-card border-0 shadow-sm h-100")
                            ], width=6, className="mb-3"),

                            # Vulnerabilities
                            dbc.Col([
                                dbc.Card([
                                    dbc.CardBody([
                                        html.Div([
                                            html.I(className="fa fa-bug text-danger fa-2x mb-2"),
                                            html.H4(id="security-score-vulns", children="--",
                                                  className="mb-1 fw-bold"),
                                            html.P("Vulnerabilities", className="text-muted mb-0 small"),
                                            html.Small(id="security-score-vulns-detail", children="",
                                                     className="text-muted d-block", style={"fontSize": "0.7rem"})
                                        ], className="text-center")
                                    ], className="p-3")
                                ], className="glass-card border-0 shadow-sm h-100")
                            ], width=6, className="mb-3"),

                            # Encryption
                            dbc.Col([
                                dbc.Card([
                                    dbc.CardBody([
                                        html.Div([
                                            html.I(className="fa fa-lock text-primary fa-2x mb-2"),
                                            html.H4(id="security-score-encryption", children="--",
                                                  className="mb-1 fw-bold"),
                                            html.P("Encryption", className="text-muted mb-0 small"),
                                            html.Small(id="security-score-encryption-detail", children="",
                                                     className="text-muted d-block", style={"fontSize": "0.7rem"})
                                        ], className="text-center")
                                    ], className="p-3")
                                ], className="glass-card border-0 shadow-sm h-100")
                            ], width=6),

                            # Segmentation
                            dbc.Col([
                                dbc.Card([
                                    dbc.CardBody([
                                        html.Div([
                                            html.I(className="fa fa-network-wired text-warning fa-2x mb-2"),
                                            html.H4(id="security-score-segmentation", children="--",
                                                  className="mb-1 fw-bold"),
                                            html.P("Segmentation", className="text-muted mb-0 small"),
                                            html.Small(id="security-score-segmentation-detail", children="",
                                                     className="text-muted d-block", style={"fontSize": "0.7rem"})
                                        ], className="text-center")
                                    ], className="p-3")
                                ], className="glass-card border-0 shadow-sm h-100")
                            ], width=6)
                        ])
                    ], width=7)
                ], className="mb-3"),

                # Bottom: Historical Trend Chart
                dbc.Row([
                    dbc.Col([
                        html.H6("Security Score Trend (Last 7 Days)", className="text-muted mb-2"),
                        dcc.Loading(
                            dcc.Graph(
                                id='security-score-history-chart',
                                config={'displayModeBar': False},
                                style={'height': '200px'}
                            ),
                            type="circle"
                        )
                    ], width=12)
                ])
            ], className="p-4")
        ], className="glass-card border-0 shadow-lg mb-4")
    ]),

    # Auto-refresh interval for security score (every 30 seconds)
    dcc.Interval(id='security-score-interval', interval=30*1000, n_intervals=0),

    # ============================================================================
    # PRIVACY DASHBOARD - Moved to Privacy Monitor Modal (Device Privacy tab)
    # Privacy dashboard content is now in the Privacy Monitor modal as the "Device Privacy" tab
    # Keeping this placeholder for backward compatibility
    html.Div(id='privacy-dashboard-section', children=[], style={'display': 'none'}),

    # Privacy device detail modal
    dbc.Modal([
        dbc.ModalHeader(dbc.ModalTitle(id="privacy-detail-modal-title")),
        dbc.ModalBody(id="privacy-detail-modal-body"),
        dbc.ModalFooter(
            dbc.Button("Close", id="privacy-detail-modal-close", className="ms-auto")
        )
    ], id="privacy-detail-modal", size="xl", scrollable=True),

    # Auto-refresh interval for privacy dashboard (every 60 seconds)
    dcc.Interval(id='privacy-interval', interval=60*1000, n_intervals=0),

    # THREE COLUMN LAYOUT - Asymmetric 2-7-3 Layout
    dbc.Row([
        # LEFT COLUMN - Metrics, Network Activity, Devices, Quick Actions (2 cols)
        dbc.Col([
            html.Div(id='metrics-section', children=[

            # Emergency Button (only visible for Home User template)
            html.Div(id='emergency-button-container', children=[
                dbc.Alert([
                    html.Div([
                        html.I(className="fa fa-exclamation-triangle fa-2x mb-2", style={"color": "#ff4444"}),
                        html.H5("Emergency Protection", className="mb-2", style={"color": "#ff4444", "fontWeight": "700"}),
                        html.P("Activate if you suspect a security threat", className="text-muted small mb-3"),
                        dbc.Button([
                            html.I(className="fa fa-shield-alt me-2"),
                            "ACTIVATE EMERGENCY MODE",
                            html.Span(" 🔐", className="ms-1", style={"fontSize": "1.2rem"})
                        ], id="emergency-activate-btn", color="danger", size="lg", className="w-100 pulse-danger",
                           title="Emergency mode blocks all untrusted devices (Parent/Admin only)"),
                    ], className="text-center")
                ], color="light", className="border border-danger mb-3", style={"display": "none"})
            ], style={"display": "none"}),

            # Emergency Mode Active Banner
            html.Div(id='emergency-active-banner', children=[
                dbc.Alert([
                    html.Div([
                        html.I(className="fa fa-shield-alt fa-2x mb-2 text-warning"),
                        html.H5("🚨 EMERGENCY MODE ACTIVE", className="mb-2 text-warning fw-bold"),
                        html.P(id="emergency-status-text", className="mb-3"),
                        dbc.Button([
                            html.I(className="fa fa-unlock me-2"),
                            "DEACTIVATE EMERGENCY MODE",
                            html.Span(" 🔐", className="ms-1", style={"fontSize": "1.2rem"})
                        ], id="emergency-deactivate-btn", color="success", size="lg", className="w-100",
                           title="Deactivate emergency protection (Parent/Admin only)"),
                    ], className="text-center")
                ], color="warning", className="border border-warning mb-3")
            ], style={"display": "none"}),

            # Metrics Boxes (2 columns for squarish layout)
            dbc.Row([
                # CPU Usage Box
                dbc.Col([
                    dbc.Card([
                        dbc.CardBody([
                            html.I(className="fa fa-microchip fa-2x mb-2 text-primary"),
                            html.H4(id="cpu-usage", className="mb-1 fw-bold text-gradient", style={"fontSize": "1rem"}),
                            html.P("CPU", className="text-muted mb-0 small")
                        ], className="p-3 text-center")
                    ], className="metric-card glass-card border-0 shadow hover-lift h-100")
                ], width=6, className="mb-2"),

                # RAM Usage Box
                dbc.Col([
                    dbc.Card([
                        dbc.CardBody([
                            html.I(className="fa fa-memory fa-2x mb-2 text-success"),
                            html.H4(id="ram-usage", className="mb-1 fw-bold", style={"fontSize": "1rem"}),
                            html.P("RAM", className="text-muted mb-0 small")
                        ], className="p-3 text-center")
                    ], className="metric-card glass-card border-0 shadow hover-lift h-100")
                ], width=6, className="mb-2"),

                # Bandwidth Usage Box
                dbc.Col([
                    dbc.Card([
                        dbc.CardBody([
                            html.I(className="fa fa-exchange-alt fa-2x mb-2 text-info"),
                            html.H4(id="bandwidth-usage", className="mb-1 fw-bold", style={"fontSize": "1rem"}),
                            html.P("Bandwidth", className="text-muted mb-0 small")
                        ], className="p-3 text-center")
                    ], className="metric-card glass-card border-0 shadow hover-lift h-100")
                ], width=6, className="mb-2"),

                # Threats Blocked Box
                dbc.Col([
                    dbc.Card([
                        dbc.CardBody([
                            html.I(className="fa fa-shield-alt fa-2x mb-2 text-success"),
                            html.H4(id="threats-blocked", className="mb-1 fw-bold", style={"fontSize": "1rem"}),
                            html.P("Blocked", className="text-muted mb-0 small")
                        ], className="p-3 text-center")
                    ], className="metric-card glass-card border-0 shadow hover-lift h-100")
                ], width=6, className="mb-2"),

                # Privacy Score Box
                dbc.Col([
                    dbc.Card([
                        dbc.CardBody([
                            html.I(className="fa fa-lock fa-2x mb-2 text-success", id="privacy-score-icon"),
                            html.H4(id="privacy-score-metric", className="mb-1 fw-bold", style={"fontSize": "1rem"}),
                            html.P([
                                "Privacy",
                                html.I(className="fa fa-question-circle ms-1 text-muted",
                                       id="privacy-score-tooltip-trigger",
                                       style={"cursor": "pointer", "fontSize": "0.6rem"})
                            ], className="text-muted mb-0 small")
                        ], className="p-3 text-center")
                    ], className="metric-card glass-card border-0 shadow hover-lift h-100", id="privacy-score-card", style={"cursor": "pointer"})
                ], width=6, className="mb-2"),

                # Network Health Box
                dbc.Col([
                    dbc.Card([
                        dbc.CardBody([
                            html.I(className="fa fa-wifi fa-2x mb-2", id="network-icon"),
                            html.H6(id="network-health", className="mb-1 fw-bold", style={"fontSize": "0.85rem"}),
                            html.P("Health", className="text-muted mb-0 small")
                        ], className="p-3 text-center")
                    ], className="metric-card glass-card border-0 shadow hover-lift h-100")
                ], width=6, className="mb-2"),
            ], className="g-2 mb-3"),

            # Network Activity Card (moved above devices)
            dbc.Card([
                dbc.CardHeader([
                    html.I(className="fa fa-chart-network me-2", style={"color": "#6366f1"}),
                    html.Span("Network Activity", className="fw-bold")
                ], className="bg-gradient-primary text-white", style={"padding": "0.5rem 0.75rem", "fontSize": "0.9rem"}),
                dbc.CardBody([
                    dbc.Row([
                        dbc.Col([
                            html.Div([
                                html.I(className="fa fa-laptop text-primary mb-1", style={"fontSize": "1.2rem"}),
                                html.H6(id='device-count-stat', className="mb-0 fw-bold", style={"fontSize": "1.1rem"}),
                                html.Small("Active (1h)", className="text-muted", style={"fontSize": "0.7rem"})
                            ], className="text-center")
                        ], width=6, className="mb-2"),
                        dbc.Col([
                            html.Div([
                                html.I(className="fa fa-exchange-alt text-info mb-1", style={"fontSize": "1.2rem"}),
                                html.H6(id='bandwidth-stat', className="mb-0 fw-bold", style={"fontSize": "1.1rem"}),
                                html.Small("Connections", className="text-muted", style={"fontSize": "0.7rem"})
                            ], className="text-center")
                        ], width=6, className="mb-2")
                    ], className="g-2")
                ], className="p-2")
            ], className="glass-card border-0 shadow hover-card mb-3"),

            # Devices Card
            dbc.Card([
                dbc.CardHeader([
                    html.Div([
                        html.I(className="fa fa-network-wired me-2", style={"color": "#3b82f6"}),
                        html.Span("Connected Devices", className="fw-bold"),
                    ], className="d-flex align-items-center")
                ], className="bg-gradient-primary text-white", style={"padding": "0.75rem 1rem"}),
                dbc.CardBody([
                    # Quick Status Grid
                    html.Div([
                        html.H6([
                            html.I(className="fa fa-th me-2"),
                            "Quick Status"
                        ], className="text-muted mb-2", style={"fontSize": "0.85rem"}),
                        html.Div(id='devices-status-compact', className="device-grid-modern")
                    ], className="mb-3"),

                    html.Hr(className="my-2", style={"borderTop": "1px solid #e5e7eb"}),

                    # Device List
                    html.Div([
                        html.H6([
                            html.I(className="fa fa-list-ul me-2"),
                            "Device List"
                        ], className="text-muted mb-2", style={"fontSize": "0.85rem"}),
                        html.Div(id='active-devices-list',
                                style={'height': '225px', 'overflowY': 'auto'},
                                className="custom-scrollbar-modern")
                    ])
                ], className="p-3")
            ], className="glass-card border-0 shadow-lg hover-card mb-3")
            ])
        ], width=2, className="mb-4"),

        # CENTER COLUMN - Network Visualization and Charts (7 cols)
        dbc.Col([
            # Network Topology Card
            dbc.Card([
                dbc.CardHeader([
                    html.Div([
                        html.Div([
                            html.I(className="fa fa-project-diagram me-2", style={"color": "#10b981"}),
                            html.Span("Network Topology", className="fw-bold"),
                        ], className="d-flex align-items-center"),
                        html.Div([
                            html.Small("Zeek Analysis", className="badge bg-success me-2", style={"padding": "0.4rem 0.6rem"}),
                            dbc.Switch(id="graph-view-toggle", label="3D View", value=False,
                                     className="d-inline-flex align-items-center",
                                     style={"fontSize": "0.85rem"}),
                            html.I(className="fa fa-question-circle ms-2 text-white",
                                  id="network-graph-help", style={"cursor": "pointer"})
                        ], className="d-flex align-items-center")
                    ], className="d-flex justify-content-between align-items-center w-100")
                ], className="bg-gradient-success text-white"),
                dbc.Tooltip(
                    "Network topology shows device connections. Each node is a device, edges show communication. "
                    "Watch for unusual connections between devices!",
                    target="network-graph-help", placement="bottom"
                ),
                dbc.CardBody([
                    # Graph Container (LARGER)
                    html.Div([
                        html.Div(id='2d-graph-container', children=[
                            cyto.Cytoscape(
                                id='network-graph',
                                layout={'name': 'cose', 'animate': True},
                                style={'width': '100%', 'height': '500px', 'borderRadius': '12px'},
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
                                tapNodeData={'id': None}
                            )
                        ]),
                        html.Div(id='3d-graph-container', children=[
                            dcc.Loading(
                                dcc.Graph(id='network-graph-3d', style={'height': '500px'}),
                                type="circle"
                            )
                        ], style={'display': 'none'})
                    ], className="graph-wrapper mb-3"),

                    # Traffic Stats Row
                    dbc.Card([
                        dbc.CardBody([
                            dbc.Row([
                                dbc.Col([
                                    html.Div([
                                        html.I(className="fa fa-arrow-up fa-lg text-info mb-2"),
                                        html.H5(id='total-outbound', className="mb-0 fw-bold"),
                                        html.Small("Outbound", className="text-muted")
                                    ], className="text-center")
                                ], width=4),
                                dbc.Col([
                                    html.Div([
                                        html.I(className="fa fa-arrow-down fa-lg text-success mb-2"),
                                        html.H5(id='total-inbound', className="mb-0 fw-bold"),
                                        html.Small("Inbound", className="text-muted")
                                    ], className="text-center")
                                ], width=4),
                                dbc.Col([
                                    html.Div([
                                        html.I(className="fa fa-exchange-alt fa-lg text-warning mb-2"),
                                        html.H5(id='connection-count', className="mb-0 fw-bold"),
                                        html.Small("Conn/Hour", className="text-muted")
                                    ], className="text-center")
                                ], width=4)
                            ])
                        ], className="p-3")
                    ], className="bg-light border-0")
                ], className="p-4")
            ], className="glass-card border-0 shadow-lg mb-3 hover-card"),

            # Analytics Cards - Stacked Layout
            dbc.Row([
                # Protocol Distribution
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader([
                            html.I(className="fa fa-chart-pie me-2"),
                            "Protocol Distribution",
                            html.I(className="fa fa-question-circle ms-2 text-muted",
                                  id="protocol-help", style={"cursor": "pointer", "fontSize": "0.8rem"})
                        ], className="bg-light border-bottom", style={"fontSize": "0.9rem", "padding": "0.75rem 1rem"}),
                        dbc.Tooltip("Shows network protocol usage (TCP/UDP/ICMP). Unusual patterns may indicate attacks.",
                                   target="protocol-help", placement="top"),
                        dbc.CardBody(
                            dcc.Loading(
                                dcc.Graph(id='protocol-pie', style={'height': '280px'},
                                    config={'displayModeBar': False}),
                                type="circle"
                            ),
                            className="p-2"
                        )
                    ], className="glass-card border-0 shadow hover-card mb-3")
                ], width=12),
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader([
                            html.I(className="fa fa-chart-line me-2"),
                            "Traffic Timeline (24h)",
                            html.I(className="fa fa-question-circle ms-2 text-muted",
                                  id="timeline-help", style={"cursor": "pointer", "fontSize": "0.8rem"})
                        ], className="bg-light border-bottom", style={"fontSize": "0.9rem", "padding": "0.75rem 1rem"}),
                        dbc.Tooltip("24-hour traffic patterns. Spikes at odd hours may indicate malware or unauthorized access.",
                                   target="timeline-help", placement="top"),
                        dbc.CardBody(
                            dcc.Loading(
                                dcc.Graph(id='traffic-timeline', style={'height': '280px'},
                                    config={'displayModeBar': False}),
                                type="circle"
                            ),
                            className="p-2"
                        )
                    ], className="glass-card border-0 shadow hover-card")
                ], width=12)
            ], className="g-3")
        ], width=7, className="mb-4"),

        # RIGHT COLUMN - Security Status and Alerts (3 cols)
        dbc.Col([
            html.Div(id='right-panel-section', children=[
            # Security Status Card
            dbc.Card([
                dbc.CardHeader([
                    html.I(className="fa fa-shield-alt me-2", style={"color": "#10b981"}),
                    html.Span("Security Status", className="fw-bold")
                ], className="bg-gradient-info text-white", style={"padding": "0.5rem 0.75rem", "fontSize": "0.9rem"}),
                dbc.CardBody([
                    # Security Score
                    html.Div([
                        html.Div([
                            html.H3(id='security-score', className="mb-0 fw-bold text-success", style={"fontSize": "2rem"}),
                            html.Small("Security Score", className="text-muted d-block", style={"fontSize": "0.75rem"})
                        ], className="text-center mb-3")
                    ]),
                    # Quick Stats
                    dbc.Row([
                        dbc.Col([
                            html.Div([
                                html.I(className="fa fa-clock text-secondary mb-1", style={"fontSize": "1rem"}),
                                html.P(id='last-scan-time', className="mb-0 small fw-bold", style={"fontSize": "0.7rem"}),
                                html.Small("Last Scan", className="text-muted", style={"fontSize": "0.65rem"})
                            ], className="text-center")
                        ], width=12, className="mb-2")
                    ], className="g-1")
                ], className="p-2")
            ], className="glass-card border-0 shadow hover-card mb-3"),

            # Recent Activity Card
            dbc.Card([
                dbc.CardHeader([
                    html.I(className="fa fa-history me-2", style={"color": "#8b5cf6"}),
                    html.Span("Recent Activity", className="fw-bold")
                ], className="bg-gradient-purple text-white", style={"padding": "0.5rem 0.75rem", "fontSize": "0.9rem"}),
                dbc.CardBody([
                    html.Div(id='recent-activity-list', className="", style={"fontSize": "0.75rem"})
                ], className="p-2", style={"minHeight": "150px"})
            ], className="glass-card border-0 shadow hover-card mb-3"),

            # Recommended Actions Card
            dbc.Card([
                dbc.CardHeader([
                    html.I(className="fa fa-lightbulb me-2", style={"color": "#fbbf24"}),
                    html.Span("Recommendations", className="fw-bold")
                ], className="bg-gradient-warning text-white", style={"padding": "0.5rem 0.75rem", "fontSize": "0.9rem"}),
                dbc.CardBody([
                    html.Div(id='recommendations-list', className="", style={"fontSize": "0.75rem"})
                ], className="p-2", style={"minHeight": "120px"})
            ], className="glass-card border-0 shadow hover-card mb-3"),

            # Live Threat Feed Card
            dbc.Card([
                dbc.CardHeader([
                    html.Div([
                        html.Div([
                            html.I(className="fa fa-bullseye me-2", style={"color": "#ef4444"}),
                            html.Span("Live Threat Feed", className="fw-bold")
                        ], className="d-flex align-items-center"),
                        dbc.Badge("LIVE", color="danger", pill=True, className="pulse-badge")
                    ], className="d-flex justify-content-between align-items-center w-100")
                ], className="bg-gradient-danger text-white", style={"padding": "0.5rem 0.75rem", "fontSize": "0.9rem"}),
                dbc.CardBody([
                    html.Div(id='live-threat-feed', className="threat-feed-container", style={
                        "maxHeight": "250px",
                        "overflowY": "auto",
                        "fontSize": "0.75rem"
                    })
                ], className="p-2")
            ], className="glass-card border-0 shadow hover-card mb-3"),

            # Predictive Threat Intelligence Card
            dbc.Card([
                dbc.CardHeader([
                    html.I(className="fa fa-brain me-2", style={"color": "#8b5cf6"}),
                    html.Span("Threat Forecast (AI)", className="fw-bold")
                ], className="bg-gradient-secondary text-white", style={"padding": "0.5rem 0.75rem", "fontSize": "0.9rem"}),
                dbc.CardBody([
                    html.Div(id='threat-forecast-content', style={"fontSize": "0.75rem"})
                ], className="p-2", style={"minHeight": "100px"})
            ], className="glass-card border-0 shadow hover-card mb-3"),

            # Security Alerts Card (moved to last)
            dbc.Card([
                dbc.CardHeader([
                    html.Div([
                        html.Div([
                            html.I(className="fa fa-exclamation-triangle me-2", style={"color": "#f59e0b"}),
                            html.Span("Security Alerts", className="fw-bold"),
                        ], className="d-flex align-items-center"),
                        dbc.Badge(id='alert-count', color="danger", pill=True,
                                className="pulse-badge", style={"fontSize": "1rem", "padding": "0.5rem 0.8rem"})
                    ], className="d-flex justify-content-between align-items-center w-100")
                ], className="bg-gradient-warning text-white", style={"padding": "0.75rem 1rem"}),
                dbc.CardBody([
                    # Alert Filters
                    html.Div([
                        html.Small("Severity:", className="text-muted d-block mb-2", style={"fontSize": "0.85rem", "fontWeight": "600"}),
                        dbc.ButtonGroup([
                            dbc.Button("All", id="filter-all", size="sm",
                                     color="primary", className="filter-btn-modern active"),
                            dbc.Button([html.I(className="fa fa-skull-crossbones")], id="filter-critical",
                                     size="sm", color="danger", outline=True, className="filter-btn-modern"),
                            dbc.Button([html.I(className="fa fa-exclamation-triangle")], id="filter-high",
                                     size="sm", color="warning", outline=True, className="filter-btn-modern"),
                            dbc.Button([html.I(className="fa fa-exclamation-circle")], id="filter-medium",
                                     size="sm", color="info", outline=True, className="filter-btn-modern"),
                            dbc.Button([html.I(className="fa fa-info-circle")], id="filter-low",
                                     size="sm", color="secondary", outline=True, className="filter-btn-modern")
                        ], className="w-100 mb-2", style={"gap": "0.25rem"}),
                        # Show reviewed alerts checkbox
                        dbc.Checklist(
                            options=[{"label": "Show Reviewed", "value": 1}],
                            value=[],
                            id="show-reviewed-alerts",
                            inline=True,
                            className="mt-2",
                            style={"fontSize": "0.8rem"}
                        )
                    ], className="mb-3"),

                    # Alerts Container (FIXED HEIGHT)
                    html.Div(id='alerts-container-compact',
                            style={'height': '375px', 'overflowY': 'auto'},
                            className="custom-scrollbar-modern alerts-modern")
                ], className="p-3", style={"paddingTop": "1rem !important"})
            ], className="glass-card border-0 shadow-lg hover-card")
            ])
        ], width=3, className="mb-4")
    ], className="g-3"),

    ]),  # End of Tab 1: Overview

    # ====================== TAB 2: ALERTS & THREATS ======================
    dcc.Tab(label='🚨 Alerts & Threats', value='tab-alerts', className='dashboard-tab',
            selected_className='dashboard-tab--selected', children=[
    html.Div([
    html.Div([
        # Threat Intelligence
        html.Div([
            html.Div([
                dbc.Card([
                    dbc.CardBody([
                        html.Div([
                            html.I(className="fa fa-shield-virus fa-2x mb-2", style={"color": "#ef4444"}),
                            html.H6("Threat Intelligence", className="fw-bold mb-1"),
                            html.P("Mirai, DDoS & botnet", className="small text-muted mb-0", style={"fontSize": "0.75rem"})
                        ], className="text-center")
                    ], className="p-3")
                ], className="glass-card border-0 shadow hover-lift", style={"cursor": "pointer"})
            ], id="threat-card-btn", n_clicks=0)
        ], className="masonry-item small", **{"data-category": "Security"}),

        # Geographic Threat Map (MEDIUM)
        html.Div([
            html.Div([
                dbc.Card([
                    dbc.CardBody([
                        html.Div([
                            html.I(className="fa fa-globe-americas fa-3x mb-3", style={"color": "#ef4444"}),
                            html.H5("Global Threat Map", className="fw-bold mb-2", style={"fontSize": "1.1rem"}),
                            html.P("Real-time global attack visualization", className="small text-muted mb-0")
                        ], className="text-center")
                    ], className="p-3")
                ], className="glass-card border-0 shadow hover-lift", style={"cursor": "pointer"})
            ], id="threat-map-card-btn", n_clicks=0)
        ], className="masonry-item medium", **{"data-category": "Security"}),

        # Device Risk Heat Map
        html.Div([
            html.Div([
                dbc.Card([
                    dbc.CardBody([
                        html.Div([
                            html.I(className="fa fa-fire-flame-curved fa-2x mb-2", style={"color": "#f59e0b"}),
                            html.H6("Risk Heat Map", className="fw-bold mb-1"),
                            html.P("Device vulnerabilities", className="small text-muted mb-0", style={"fontSize": "0.75rem"})
                        ], className="text-center")
                    ], className="p-3")
                ], className="glass-card border-0 shadow hover-lift", style={"cursor": "pointer"})
            ], id="risk-heatmap-card-btn", n_clicks=0)
        ], className="masonry-item small", **{"data-category": "Security"}),

        # Forensic Timeline
        html.Div([
            html.Div([
                dbc.Card([
                    dbc.CardBody([
                        html.Div([
                            html.I(className="fa fa-microscope fa-2x mb-2", style={"color": "#8b5cf6"}),
                            html.H6("Forensic Timeline", className="fw-bold mb-1"),
                            html.P("Attack reconstruction", className="small text-muted mb-0", style={"fontSize": "0.75rem"})
                        ], className="text-center")
                    ], className="p-3")
                ], className="glass-card border-0 shadow hover-lift", style={"cursor": "pointer"})
            ], id="forensic-timeline-card-btn", n_clicks=0)
        ], className="masonry-item small", **{"data-category": "Security"}),

        # Automated Response
        html.Div([
            html.Div([
                dbc.Card([
                    dbc.CardBody([
                        html.Div([
                            html.I(className="fa fa-wand-magic-sparkles fa-2x mb-2", style={"color": "#6366f1"}),
                            html.H6("Auto Response", className="fw-bold mb-1"),
                            html.P("Automated actions", className="small text-muted mb-0", style={"fontSize": "0.75rem"})
                        ], className="text-center")
                    ], className="p-3")
                ], className="glass-card border-0 shadow hover-lift", style={"cursor": "pointer"})
            ], id="auto-response-card-btn", n_clicks=0)
        ], className="masonry-item small", **{"data-category": "Security"}),
    ], className="masonry-grid")
    ], id="alerts-features-section"),
    ]),  # End of Tab 2: Alerts & Threats

    # ====================== TAB 3: DEVICES & IoT ======================
    dcc.Tab(label='📱 Devices & IoT', value='tab-devices', className='dashboard-tab',
            selected_className='dashboard-tab--selected', children=[
    html.Div([
    html.Div([
        # Device Management (LARGE)
        html.Div([
            html.Div([
                dbc.Card([
                    dbc.CardBody([
                        html.Div([
                            html.I(className="fa fa-diagram-project fa-4x mb-3", style={"color": "#f59e0b"}),
                            html.H4("Device Management", className="fw-bold mb-2"),
                            html.P("Manage all IoT devices with bulk operations and trust levels", className="text-muted mb-0 card-short-desc"),
                            html.Div([
                                html.P("Comprehensive IoT device management with bulk operations, trust level configuration, and device monitoring.",
                                       className="text-muted small mb-2 mt-2")
                            ], className="hover-preview-content", style={"display": "none"})
                        ], className="text-center")
                    ], className="p-4")
                ], className="glass-card border-0 shadow-lg hover-lift", style={"cursor": "pointer"})
            ], id="device-mgmt-card-btn", n_clicks=0)
        ], className="masonry-item large", **{"data-category": "Management"}),

        # IoT Protocol Analysis (MEDIUM)
        html.Div([
            html.Div([
                dbc.Card([
                    dbc.CardBody([
                        html.Div([
                            html.I(className="fa fa-network-wired fa-3x mb-3", style={"color": "#06b6d4"}),
                            html.H5("IoT Protocol Analysis", className="fw-bold mb-2", style={"fontSize": "1.1rem"}),
                            html.P("MQTT, CoAP, Zigbee protocol monitoring", className="small text-muted mb-0")
                        ], className="text-center")
                    ], className="p-3")
                ], className="glass-card border-0 shadow hover-lift", style={"cursor": "pointer"})
            ], id="protocol-card-btn", n_clicks=0)
        ], className="masonry-item medium", **{"data-category": "Management"}),

        # Smart Home Context (MEDIUM)
        html.Div([
            html.Div([
                dbc.Card([
                    dbc.CardBody([
                        html.Div([
                            html.I(className="fa fa-house-signal fa-3x mb-3", style={"color": "#8b5cf6"}),
                            html.H5("Smart Home Context", className="fw-bold mb-2", style={"fontSize": "1.1rem"}),
                            html.P("Hub management & ecosystem", className="small text-muted mb-0")
                        ], className="text-center")
                    ], className="p-3")
                ], className="glass-card border-0 shadow hover-lift", style={"cursor": "pointer"})
            ], id="smarthome-card-btn", n_clicks=0)
        ], className="masonry-item medium", **{"data-category": "Management"}),

        # Privacy Monitoring (COMPACT)
        html.Div([
            html.Div([
                dbc.Card([
                    dbc.CardBody([
                        html.Div([
                            html.I(className="fa fa-user-shield fa-2x mb-2", style={"color": "#f59e0b"}),
                            html.H6("Privacy Monitor", className="fw-bold mb-1"),
                            html.P("Cloud tracking", className="small text-muted mb-0", style={"fontSize": "0.75rem"})
                        ], className="text-center")
                    ], className="p-3")
                ], className="glass-card border-0 shadow hover-lift", style={"cursor": "pointer"})
            ], id="privacy-card-btn", n_clicks=0)
        ], className="masonry-item compact", **{"data-category": "Management"}),

        # Network Segmentation
        html.Div([
            html.Div([
                dbc.Card([
                    dbc.CardBody([
                        html.Div([
                            html.I(className="fa fa-layer-group fa-2x mb-2", style={"color": "#10b981"}),
                            html.H6("Segmentation", className="fw-bold mb-1"),
                            html.P("VLAN & isolation", className="small text-muted mb-0", style={"fontSize": "0.75rem"})
                        ], className="text-center")
                    ], className="p-3")
                ], className="glass-card border-0 shadow hover-lift", style={"cursor": "pointer"})
            ], id="segmentation-card-btn", n_clicks=0)
        ], className="masonry-item small", **{"data-category": "Management"}),

        # Firmware Management (LARGE)
        html.Div([
            html.Div([
                dbc.Card([
                    dbc.CardBody([
                        html.Div([
                            html.I(className="fa fa-microchip fa-4x mb-3", style={"color": "#6366f1"}),
                            html.H4("Firmware Management", className="fw-bold mb-2"),
                            html.P("Track firmware updates and end-of-life devices", className="text-muted mb-0")
                        ], className="text-center")
                    ], className="p-4")
                ], className="glass-card border-0 shadow hover-lift", style={"cursor": "pointer"})
            ], id="firmware-card-btn", n_clicks=0)
        ], className="masonry-item large", **{"data-category": "Management"}),

        # Security Education
        html.Div([
            html.Div([
                dbc.Card([
                    dbc.CardBody([
                        html.Div([
                            html.I(className="fa fa-user-graduate fa-2x mb-2", style={"color": "#06b6d4"}),
                            html.H6("Education", className="fw-bold mb-1"),
                            html.P("Security tips", className="small text-muted mb-0", style={"fontSize": "0.75rem"})
                        ], className="text-center")
                    ], className="p-3")
                ], className="glass-card border-0 shadow hover-lift", style={"cursor": "pointer"})
            ], id="education-card-btn", n_clicks=0)
        ], className="masonry-item small", **{"data-category": "Management"}),
    ], className="masonry-grid")
    ], id="devices-features-section"),
    ]),  # End of Tab 3: Devices & IoT

    # ====================== TAB 4: ANALYTICS & REPORTS ======================
    dcc.Tab(label='📊 Analytics', value='tab-analytics', className='dashboard-tab',
            selected_className='dashboard-tab--selected', children=[
    html.Div([
    html.Div([
        # Analytics Card Tile (XL)
        html.Div([
            html.Div([
                dbc.Card([
                    dbc.CardBody([
                        html.Div([
                            html.I(className="fa fa-chart-pie fa-4x mb-3", style={"color": "#8b5cf6"}),
                            html.H4("Analytics & Deep Insights", className="fw-bold mb-2"),
                            html.P("AI-powered analytics, alerts timeline, anomaly detection, and bandwidth monitoring", className="text-muted mb-0 card-short-desc"),
                            html.Div([
                                html.P("Advanced AI-powered security analytics with real-time threat detection. Monitor alerts timeline, anomaly distribution, and bandwidth usage patterns.",
                                       className="text-muted small mb-2 mt-2")
                            ], className="hover-preview-content", style={"display": "none"})
                        ], className="text-center")
                    ], className="p-4")
                ], className="glass-card border-0 shadow-lg hover-lift", style={"cursor": "pointer"})
            ], id="analytics-card-btn", n_clicks=0)
        ], className="masonry-item xl-card", **{"data-category": "Analytics"}),

        # Timeline Visualization
        html.Div([
            html.Div([
                dbc.Card([
                    dbc.CardBody([
                        html.Div([
                            html.I(className="fa fa-timeline fa-2x mb-2", style={"color": "#8b5cf6"}),
                            html.H6("Timeline Viz", className="fw-bold mb-1"),
                            html.P("Activity history", className="small text-muted mb-0", style={"fontSize": "0.75rem"})
                        ], className="text-center")
                    ], className="p-3")
                ], className="glass-card border-0 shadow hover-lift", style={"cursor": "pointer"})
            ], id="timeline-card-btn", n_clicks=0)
        ], className="masonry-item small", **{"data-category": "Analytics"}),

        # Comparison & Benchmarking
        html.Div([
            html.Div([
                dbc.Card([
                    dbc.CardBody([
                        html.Div([
                            html.I(className="fa fa-chart-column fa-2x mb-2", style={"color": "#10b981"}),
                            html.H6("Benchmarking", className="fw-bold mb-1"),
                            html.P("Industry comparison", className="small text-muted mb-0", style={"fontSize": "0.75rem"})
                        ], className="text-center")
                    ], className="p-3")
                ], className="glass-card border-0 shadow hover-lift", style={"cursor": "pointer"})
            ], id="benchmark-card-btn", n_clicks=0)
        ], className="masonry-item small", **{"data-category": "Analytics"}),

        # Network Performance Analytics
        html.Div([
            html.Div([
                dbc.Card([
                    dbc.CardBody([
                        html.Div([
                            html.I(className="fa fa-gauge-high fa-2x mb-2", style={"color": "#06b6d4"}),
                            html.H6("Performance", className="fw-bold mb-1"),
                            html.P("Latency & throughput", className="small text-muted mb-0", style={"fontSize": "0.75rem"})
                        ], className="text-center")
                    ], className="p-3")
                ], className="glass-card border-0 shadow hover-lift", style={"cursor": "pointer"})
            ], id="performance-card-btn", n_clicks=0)
        ], className="masonry-item small", **{"data-category": "Analytics"}),
    ], className="masonry-grid")
    ], id="analytics-features-section"),
    ]),  # End of Tab 4: Analytics & Reports

    # ====================== TAB 5: INTEGRATIONS & API ======================
    dcc.Tab(label='🔗 Integrations', value='tab-integrations', className='dashboard-tab',
            selected_className='dashboard-tab--selected', children=[
    html.Div([
    html.Div([
        # API Integration Hub
        html.Div([
            html.Div([
                dbc.Card([
                    dbc.CardBody([
                        html.Div([
                            html.I(className="fa fa-code fa-2x mb-2", style={"color": "#8b5cf6"}),
                            html.H6("API Hub", className="fw-bold mb-1"),
                            html.P("Threat intel APIs", className="small text-muted mb-0", style={"fontSize": "0.75rem"})
                        ], className="text-center")
                    ], className="p-3")
                ], className="glass-card border-0 shadow hover-lift", style={"cursor": "pointer"})
            ], id="api-hub-card-btn", n_clicks=0)
        ], className="masonry-item small", **{"data-category": "Integrations"}),

        # Email Notifications (COMPACT)
        html.Div([
            html.Div([
                dbc.Card([
                    dbc.CardBody([
                        html.Div([
                            html.I(className="fa fa-envelope fa-2x mb-2", style={"color": "#06b6d4"}),
                            html.H6("Email Notifications", className="fw-bold mb-1"),
                            html.P("SMTP settings & alerts", className="small text-muted mb-0", style={"fontSize": "0.75rem"})
                        ], className="text-center")
                    ], className="p-3")
                ], className="glass-card border-0 shadow-lg hover-lift", style={"cursor": "pointer"})
            ], id="email-card-btn", n_clicks=0)
        ], className="masonry-item compact", **{"data-category": "Integrations"}),
    ], className="masonry-grid")
    ], id="integrations-features-section"),
    ]),  # End of Tab 5: Integrations & API

    # ====================== TAB 6: COMPLIANCE & SECURITY ======================
    dcc.Tab(label='🛡️ Compliance', value='tab-compliance', className='dashboard-tab',
            selected_className='dashboard-tab--selected', children=[
    html.Div([
    html.Div([
        # Compliance Dashboard (MEDIUM)
        html.Div([
            html.Div([
                dbc.Card([
                    dbc.CardBody([
                        html.Div([
                            html.I(className="fa fa-list-check fa-3x mb-3", style={"color": "#10b981"}),
                            html.H5("Compliance Dashboard", className="fw-bold mb-2", style={"fontSize": "1.1rem"}),
                            html.P("GDPR, NIST, IoT Cybersecurity Act", className="small text-muted mb-0")
                        ], className="text-center")
                    ], className="p-3")
                ], className="glass-card border-0 shadow hover-lift", style={"cursor": "pointer"})
            ], id="compliance-card-btn", n_clicks=0)
        ], className="masonry-item medium", **{"data-category": "Compliance"}),

        # Vulnerability Scanner
        html.Div([
            html.Div([
                dbc.Card([
                    dbc.CardBody([
                        html.Div([
                            html.I(className="fa fa-magnifying-glass-chart fa-2x mb-2", style={"color": "#dc2626"}),
                            html.H6("Vuln Scanner", className="fw-bold mb-1"),
                            html.P("CVE & firmware check", className="small text-muted mb-0", style={"fontSize": "0.75rem"})
                        ], className="text-center")
                    ], className="p-3")
                ], className="glass-card border-0 shadow hover-lift", style={"cursor": "pointer"})
            ], id="vuln-scanner-card-btn", n_clicks=0)
        ], className="masonry-item small", **{"data-category": "Compliance"}),

        # Attack Surface Analyzer
        html.Div([
            html.Div([
                dbc.Card([
                    dbc.CardBody([
                        html.Div([
                            html.I(className="fa fa-bullseye fa-2x mb-2", style={"color": "#dc2626"}),
                            html.H6("Attack Surface", className="fw-bold mb-1"),
                            html.P("Entry points", className="small text-muted mb-0", style={"fontSize": "0.75rem"})
                        ], className="text-center")
                    ], className="p-3")
                ], className="glass-card border-0 shadow hover-lift", style={"cursor": "pointer"})
            ], id="attack-surface-card-btn", n_clicks=0)
        ], className="masonry-item small", **{"data-category": "Compliance"}),

        # Firewall Control (COMPACT)
        html.Div([
            html.Div([
                dbc.Card([
                    dbc.CardBody([
                        html.Div([
                            html.I(className="fa fa-shield-halved fa-2x mb-2", style={"color": "#ef4444"}),
                            html.H6("Firewall Control", className="fw-bold mb-1"),
                            html.P("Lockdown mode & security", className="small text-muted mb-0 card-short-desc", style={"fontSize": "0.75rem"}),
                            html.Div([
                                html.P("Configure lockdown mode and manage firewall rules for network security.",
                                       className="text-muted small mb-1 mt-1")
                            ], className="hover-preview-content", style={"display": "none"})
                        ], className="text-center")
                    ], className="p-3")
                ], className="glass-card border-0 shadow-lg hover-lift", style={"cursor": "pointer"})
            ], id="firewall-card-btn", n_clicks=0)
        ], className="masonry-item compact", **{"data-category": "Compliance"}),

        # Green Security Dashboard
        html.Div([
            html.Div([
                dbc.Card([
                    dbc.CardBody([
                        html.Div([
                            html.I(className="fa fa-leaf fa-2x mb-2", style={"color": "#10b981"}),
                            html.H6("Sustainability", className="fw-bold mb-1"),
                            html.P("Carbon footprint & energy", className="small text-muted mb-0", style={"fontSize": "0.75rem"})
                        ], className="text-center")
                    ], className="p-3")
                ], className="glass-card border-0 shadow hover-lift", style={"cursor": "pointer"})
            ], id="sustainability-card-btn", n_clicks=0)
        ], className="masonry-item medium", **{"data-category": "Compliance"}),
    ], className="masonry-grid")
    ], id="compliance-features-section"),
    ]),  # End of Tab 6: Compliance & Security

    # ====================== TAB 7: ADMINISTRATION ======================
    dcc.Tab(label='⚙️ Settings', value='tab-admin', className='dashboard-tab',
            selected_className='dashboard-tab--selected', children=[

    # Store component for category state (kept for backward compat with category filter callback)
    dcc.Store(id='features-category-filter', data='All'),

    html.Div([
    html.Div([
        # User Management
        html.Div([
            html.Div([
                dbc.Card([
                    dbc.CardBody([
                        html.Div([
                            html.I(className="fa fa-users-gear fa-2x mb-2", style={"color": "#8b5cf6"}),
                            html.H6("User Management", className="fw-bold mb-1"),
                            html.P("Accounts & passwords", className="small text-muted mb-0", style={"fontSize": "0.75rem"})
                        ], className="text-center")
                    ], className="p-3")
                ], className="glass-card border-0 shadow hover-lift", style={"cursor": "pointer"})
            ], id="user-card-btn", n_clicks=0)
        ], className="masonry-item small", **{"data-category": "Admin"}),

        # System & ML Models Card Tile (MEDIUM)
        html.Div([
            html.Div([
                dbc.Card([
                    dbc.CardBody([
                        html.Div([
                            html.I(className="fa fa-cogs fa-3x mb-3", style={"color": "#10b981"}),
                            html.H5("System & ML Models", className="fw-bold mb-2", style={"fontSize": "1.1rem"}),
                            html.P("System status, ML model information, comparison and performance metrics", className="text-muted mb-0 card-short-desc"),
                            html.Div([
                                html.P("Monitor ML model performance, compare different algorithms, and track system health metrics.",
                                       className="text-muted small mb-2 mt-2")
                            ], className="hover-preview-content", style={"display": "none"})
                        ], className="text-center")
                    ], className="p-3")
                ], className="glass-card border-0 shadow-lg hover-lift", style={"cursor": "pointer"})
            ], id="system-card-btn", n_clicks=0)
        ], className="masonry-item medium", **{"data-category": "Admin"}),

        # Dashboard Preferences
        html.Div([
            html.Div([
                dbc.Card([
                    dbc.CardBody([
                        html.Div([
                            html.I(className="fa fa-sliders-h fa-2x mb-2", style={"color": "#6366f1"}),
                            html.H6("Preferences", className="fw-bold mb-1"),
                            html.P("Themes & settings", className="small text-muted mb-0", style={"fontSize": "0.75rem"})
                        ], className="text-center")
                    ], className="p-3")
                ], className="glass-card border-0 shadow hover-lift", style={"cursor": "pointer"})
            ], id="preferences-card-btn", n_clicks=0)
        ], className="masonry-item small", **{"data-category": "Admin"}),

        # Quick Settings
        html.Div([
            html.Div([
                dbc.Card([
                    dbc.CardBody([
                        html.Div([
                            html.I(className="fa fa-cog fa-2x mb-2", style={"color": "#f59e0b"}),
                            html.H6("Quick Settings", className="fw-bold mb-1"),
                            html.P("Configure preferences", className="small text-muted mb-0", style={"fontSize": "0.75rem"})
                        ], className="text-center")
                    ], className="p-3")
                ], className="glass-card border-0 shadow hover-lift", style={"cursor": "pointer"})
            ], id="quick-settings-btn", n_clicks=0)
        ], className="masonry-item small", **{"data-category": "Admin"}),
    ], className="masonry-grid")
    ], id="admin-features-section"),
    ]),  # End of Tab 7: Administration

    ]),  # End of dcc.Tabs main-dashboard-tabs

    # ============================================================================
    # GLOBAL MODALS, STORES, INTERVALS, DOWNLOADS
    # (These must remain outside tabs so callbacks can access them from any tab)
    # ============================================================================

    # Modals for each feature
    # Analytics Modal - Enhanced with Tabs
    dbc.Modal([
        dbc.ModalHeader(dbc.ModalTitle([
            html.I(className="fa fa-chart-pie me-2 text-primary"),
            "Analytics & Deep Insights"
        ]), close_button=True),
        dbc.ModalBody([
            dbc.Tabs([
                # Security Status Tab
                dbc.Tab([
                    html.Div([
                        dbc.Card([
                            dbc.CardBody([
                                html.H6([html.I(className="fa fa-shield-halved me-2 text-success"), "IoT Security Status"], className="mb-3"),
                                html.Div(id='iot-security-widget')
                            ])
                        ], className="glass-card border-0 shadow-sm")
                    ], className="p-3")
                ], label="Security Status", tab_id="security-status-tab"),

                # Alert Timeline Tab
                dbc.Tab([
                    html.Div([
                        dbc.Row([
                            # Alert Timeline
                            dbc.Col([
                                dbc.Card([
                                    dbc.CardHeader([
                                        html.Div([
                                            html.Span([
                                                html.I(className="fa fa-chart-bar me-2"),
                                                "Alert Timeline (7 Days)"
                                            ]),
                                            html.I(className="fa fa-question-circle text-muted ms-2",
                                                  id="alert-timeline-help",
                                                  style={"cursor": "pointer", "fontSize": "0.85rem"})
                                        ])
                                    ], className="bg-light border-bottom", style={"fontSize": "0.95rem"}),
                                    dbc.Tooltip(
                                        "Alert patterns over 7 days. Recurring alerts at similar times may indicate automated attacks.",
                                        target="alert-timeline-help", placement="top"
                                    ),
                                    dbc.CardBody(
                                        dcc.Graph(id='alert-timeline', style={'height': '300px'},
                                                config={'displayModeBar': False}),
                                        className="p-3"
                                    )
                                ], className="glass-card border-0 shadow-sm hover-card h-100")
                            ], width=12, className="mb-4"),

                            # Anomaly Score Distribution
                            dbc.Col([
                                dbc.Card([
                                    dbc.CardHeader([
                                        html.Div([
                                            html.Span([
                                                html.I(className="fa fa-chart-area me-2"),
                                                "Anomaly Distribution"
                                            ]),
                                            html.I(className="fa fa-question-circle text-muted ms-2",
                                                  id="anomaly-help",
                                                  style={"cursor": "pointer", "fontSize": "0.85rem"})
                                        ])
                                    ], className="bg-light border-bottom", style={"fontSize": "0.95rem"}),
                                    dbc.Tooltip(
                                        "AI-calculated anomaly scores. Higher scores indicate unusual behavior worth investigating.",
                                        target="anomaly-help", placement="top"
                                    ),
                                    dbc.CardBody(
                                        dcc.Graph(id='anomaly-distribution', style={'height': '300px'},
                                                config={'displayModeBar': False}),
                                        className="p-3"
                                    )
                                ], className="glass-card border-0 shadow-sm hover-card h-100")
                            ], width=12, className="mb-4")
                        ])
                    ], className="p-3")
                ], label="Alert Timeline", tab_id="alert-timeline-tab"),

                # Anomaly Analysis Tab
                dbc.Tab([
                    html.Div([
                        dbc.Row([
                            # Bandwidth Chart
                            dbc.Col([
                                dbc.Card([
                                    dbc.CardHeader([
                                        html.Div([
                                            html.Span([
                                                html.I(className="fa fa-server me-2"),
                                                "Top Devices by Bandwidth"
                                            ]),
                                            html.I(className="fa fa-question-circle text-muted ms-2",
                                                  id="bandwidth-help",
                                                  style={"cursor": "pointer", "fontSize": "0.85rem"})
                                        ])
                                    ], className="bg-light border-bottom", style={"fontSize": "0.95rem"}),
                                    dbc.Tooltip(
                                        "Devices ranked by data usage. Unusual high usage from IoT devices may indicate compromise.",
                                        target="bandwidth-help", placement="top"
                                    ),
                                    dbc.CardBody(
                                        dcc.Graph(id='bandwidth-chart', style={'height': '300px'},
                                                config={'displayModeBar': False}),
                                        className="p-3"
                                    )
                                ], className="glass-card border-0 shadow-sm hover-card h-100")
                            ], width=6, className="mb-4"),

                            # Device Activity Heatmap
                            dbc.Col([
                                dbc.Card([
                                    dbc.CardHeader([
                                        html.Div([
                                            html.Span([
                                                html.I(className="fa fa-th me-2"),
                                                "Device Activity Heatmap"
                                            ]),
                                            html.I(className="fa fa-question-circle text-muted ms-2",
                                                  id="heatmap-help",
                                                  style={"cursor": "pointer", "fontSize": "0.85rem"})
                                        ])
                                    ], className="bg-light border-bottom", style={"fontSize": "0.95rem"}),
                                    dbc.Tooltip(
                                        "Hourly activity patterns. Dark colors = high activity. Look for unusual timing patterns.",
                                        target="heatmap-help", placement="top"
                                    ),
                                    dbc.CardBody(
                                        dcc.Graph(id='device-heatmap', style={'height': '300px'},
                                                config={'displayModeBar': False}),
                                        className="p-3"
                                    )
                                ], className="glass-card border-0 shadow-sm hover-card h-100")
                            ], width=6, className="mb-4")
                        ]),

                        # Network Traffic Flow Sankey Diagram
                        dbc.Row([
                            dbc.Col([
                                dbc.Card([
                                    dbc.CardHeader([
                                        html.Div([
                                            html.Span([
                                                html.I(className="fa fa-project-diagram me-2"),
                                                "Network Traffic Flow"
                                            ]),
                                            html.I(className="fa fa-question-circle text-muted ms-2",
                                                  id="sankey-help",
                                                  style={"cursor": "pointer", "fontSize": "0.85rem"})
                                        ])
                                    ], className="bg-light border-bottom", style={"fontSize": "0.95rem"}),
                                    dbc.Tooltip(
                                        "Visualizes data flow between devices, protocols, and destinations. Width = data volume.",
                                        target="sankey-help", placement="top"
                                    ),
                                    dbc.CardBody(
                                        dcc.Loading(
                                            dcc.Graph(id='traffic-flow-sankey', style={'height': '500px'},
                                                    config={'displayModeBar': False}),
                                            type='circle'
                                        ),
                                        className="p-3"
                                    )
                                ], className="glass-card border-0 shadow-sm hover-card")
                            ], width=12, className="mb-4")
                        ])
                    ], className="p-3")
                ], label="Anomaly Analysis", tab_id="anomaly-analysis-tab"),

                # Reports Tab - Security Summary Report
                dbc.Tab([
                    html.Div([
                        dbc.Card([
                            dbc.CardHeader([
                                html.I(className="fa fa-file-alt me-2"),
                                html.Strong("Security Summary Report")
                            ], className="bg-primary text-white"),
                            dbc.CardBody([
                                html.Div(id='security-summary-report', children=[
                                    # Report will be populated by callback
                                    dbc.Alert([
                                        html.I(className="fa fa-info-circle me-2"),
                                        "Loading security summary report..."
                                    ], color="info")
                                ])
                            ])
                        ], className="glass-card border-0 shadow-sm")
                    ], className="p-3")
                ], label="Reports", tab_id="reports-tab"),

                # Trend Analysis Tab - Advanced Reporting & Analytics
                dbc.Tab([
                    html.Div([
                        dbc.Row([
                            # Alert Trends Card
                            dbc.Col([
                                dbc.Card([
                                    dbc.CardHeader([
                                        html.Div([
                                            html.Span([
                                                html.I(className="fa fa-chart-line me-2"),
                                                "Alert Trends (7 Days)"
                                            ]),
                                            html.Span([
                                                dbc.Button([
                                                    html.I(className="fa fa-download me-1"),
                                                    "Custom Reports"
                                                ], id="open-reports-modal", color="primary", size="sm", className="float-end")
                                            ], className="float-end"),
                                            html.I(className="fa fa-question-circle text-muted ms-2",
                                                  id="alert-trends-help",
                                                  style={"cursor": "pointer", "fontSize": "0.85rem"})
                                        ])
                                    ], className="bg-light border-bottom", style={"fontSize": "0.95rem"}),
                                    dbc.Tooltip(
                                        "Time-series analysis of security alerts with moving average trend line. Identifies patterns and anomalies.",
                                        target="alert-trends-help", placement="top"
                                    ),
                                    dbc.CardBody(
                                        dcc.Loading(
                                            dcc.Graph(id='alert-trend-chart', style={'height': '350px'},
                                                    config={'displayModeBar': False}),
                                            type="circle"
                                        ),
                                        className="p-3"
                                    )
                                ], className="glass-card border-0 shadow-sm hover-card h-100")
                            ], width=12, className="mb-4"),

                            # Network Activity Heatmap Card
                            dbc.Col([
                                dbc.Card([
                                    dbc.CardHeader([
                                        html.Div([
                                            html.Span([
                                                html.I(className="fa fa-th me-2"),
                                                "Network Activity Heatmap (24h Pattern)"
                                            ]),
                                            html.I(className="fa fa-question-circle text-muted ms-2",
                                                  id="network-heatmap-help",
                                                  style={"cursor": "pointer", "fontSize": "0.85rem"})
                                        ])
                                    ], className="bg-light border-bottom", style={"fontSize": "0.95rem"}),
                                    dbc.Tooltip(
                                        "Visualizes network activity patterns by hour. Helps identify unusual timing or off-hours activity.",
                                        target="network-heatmap-help", placement="top"
                                    ),
                                    dbc.CardBody(
                                        dcc.Loading(
                                            dcc.Graph(id='activity-heatmap-chart', style={'height': '250px'},
                                                    config={'displayModeBar': False}),
                                            type="circle"
                                        ),
                                        className="p-3"
                                    )
                                ], className="glass-card border-0 shadow-sm hover-card h-100")
                            ], width=12, className="mb-4"),

                            # Trend Statistics Summary Card
                            dbc.Col([
                                dbc.Card([
                                    dbc.CardHeader([
                                        html.I(className="fa fa-chart-bar me-2"),
                                        "Trend Statistics"
                                    ], className="bg-light border-bottom", style={"fontSize": "0.95rem"}),
                                    dbc.CardBody(
                                        html.Div(id='trend-statistics-display', children=[
                                            dbc.Alert([
                                                html.I(className="fa fa-info-circle me-2"),
                                                "Open this tab to load trend statistics..."
                                            ], color="info")
                                        ]),
                                        className="p-3"
                                    )
                                ], className="glass-card border-0 shadow-sm hover-card")
                            ], width=12)
                        ])
                    ], className="p-3")
                ], label="Trend Analysis", tab_id="trend-analysis-tab")

            ], id="analytics-modal-tabs", active_tab="security-status-tab")
        ]),
        dbc.ModalFooter([
            html.Div(id='analytics-timestamp-display', className="me-auto"),
            dbc.Button([
                html.I(className="fa fa-sync-alt me-2"),
                "Refresh"
            ], id="refresh-analytics-btn", color="info", outline=True, size="sm", className="me-2"),
            dbc.Button([
                html.I(className="fa fa-times me-2"),
                "Close"
            ], id='close-analytics-modal-btn', color="secondary", size="sm")
        ]),
        dcc.Store(id='analytics-timestamp-store')
    ], id="analytics-modal", size="xl", is_open=False, scrollable=True),

    # System & ML Models Modal - Enhanced with Tabs
    dbc.Modal([
        dbc.ModalHeader(dbc.ModalTitle([
            html.I(className="fa fa-cogs me-2 text-primary"),
            "System & ML Models"
        ]), close_button=True),
        dbc.ModalBody([
            dbc.Tabs([
                # System Info Tab
                dbc.Tab([
                    html.Div([
                        dbc.Card([
                            dbc.CardBody([
                                html.H6([html.I(className="fa fa-server me-2 text-info"), "System Information"], className="mb-3"),
                                html.Div(id='system-info')
                            ])
                        ], className="glass-card border-0 shadow-sm mb-3"),

                        dbc.Card([
                            dbc.CardBody([
                                html.H6([html.I(className="fa fa-microchip me-2 text-success"), "Resource Usage"], className="mb-3"),
                                dbc.Row([
                                    dbc.Col([
                                        html.Label("CPU Usage", className="small text-muted"),
                                        dbc.Progress(id='cpu-usage-bar', value=0, color="info", className="mb-2", style={"height": "8px"}),
                                        html.Small(id='cpu-usage-text', className="text-muted")
                                    ], md=6),
                                    dbc.Col([
                                        html.Label("Memory Usage", className="small text-muted"),
                                        dbc.Progress(id='memory-usage-bar', value=0, color="warning", className="mb-2", style={"height": "8px"}),
                                        html.Small(id='memory-usage-text', className="text-muted")
                                    ], md=6)
                                ], className="mb-3"),
                                dbc.Row([
                                    dbc.Col([
                                        html.Label("Disk Usage", className="small text-muted"),
                                        dbc.Progress(id='disk-usage-bar', value=0, color="success", className="mb-2", style={"height": "8px"}),
                                        html.Small(id='disk-usage-text', className="text-muted")
                                    ], md=6),
                                    dbc.Col([
                                        html.Label("Network I/O", className="small text-muted"),
                                        dbc.Progress(id='network-usage-bar', value=0, color="primary", className="mb-2", style={"height": "8px"}),
                                        html.Small(id='network-usage-text', className="text-muted")
                                    ], md=6)
                                ])
                            ])
                        ], className="glass-card border-0 shadow-sm")
                    ], className="p-3")
                ], label="System", tab_id="system-info-tab"),

                # ML Models Tab
                dbc.Tab([
                    html.Div([
                        dbc.Card([
                            dbc.CardBody([
                                html.H6([html.I(className="fa fa-brain me-2 text-purple"), "Machine Learning Models"], className="mb-3"),
                                html.Div(id='model-info')
                            ])
                        ], className="glass-card border-0 shadow-sm mb-3"),

                        dbc.Card([
                            dbc.CardBody([
                                html.H6([html.I(className="fa fa-cog me-2 text-warning"), "Model Actions"], className="mb-3"),
                                html.P("River models learn incrementally - no retraining needed!", className="text-muted small mb-3"),
                                dbc.Row([
                                    dbc.Col([
                                        dbc.Button([
                                            html.I(className="fa fa-download me-2"),
                                            "Export Models"
                                        ], id='export-models-btn', color="info", outline=True, className="w-100 mb-2")
                                    ], md=6),
                                    dbc.Col([
                                        html.Label("Import Models", className="fw-bold mb-2 text-cyber"),
                                        dcc.Upload(
                                            id='import-models-upload',
                                            children=html.Div([
                                                html.I(className="fa fa-cloud-upload-alt fa-3x mb-2 text-success"),
                                                html.Br(),
                                                html.Span("Drag & Drop or ", className="text-muted"),
                                                html.Span("Click", className="text-success fw-bold"),
                                                html.Br(),
                                                html.Small(".pkl or .zip files", className="text-muted")
                                            ], className="text-center py-3"),
                                            className="border border-success border-dashed rounded p-3",
                                            style={
                                                'cursor': 'pointer',
                                                'background': 'rgba(0, 255, 0, 0.05)',
                                                'transition': 'all 0.3s ease'
                                            },
                                            multiple=True
                                        )
                                    ], md=6)
                                ]),
                                html.Div(id='model-action-status', className="mt-2"),
                                html.Div(id='import-models-status', className="mt-2")
                            ])
                        ], className="glass-card border-0 shadow-sm")
                    ], className="p-3")
                ], label="ML Models", tab_id="ml-models-tab"),

                # Model Comparison Tab
                dbc.Tab([
                    html.Div([
                        dbc.Card([
                            dbc.CardBody([
                                html.H6([html.I(className="fa fa-balance-scale me-2 text-success"), "Active River Models"], className="mb-3"),
                                html.P("View current River ML models and their learning status.", className="text-muted small mb-3"),
                                html.Div(id='model-comparison')
                            ])
                        ], className="glass-card border-0 shadow-sm mb-3"),

                        dbc.Card([
                            dbc.CardBody([
                                html.H6([html.I(className="fa fa-chart-bar me-2 text-info"), "Detection Accuracy"], className="mb-3"),
                                html.Div(id='model-accuracy-display')
                            ])
                        ], className="glass-card border-0 shadow-sm")
                    ], className="p-3")
                ], label="Comparison", tab_id="model-comparison-tab"),

                # Diagnostics Tab
                dbc.Tab([
                    html.Div([
                        dbc.Card([
                            dbc.CardBody([
                                html.H6([html.I(className="fa fa-stethoscope me-2 text-danger"), "System Diagnostics"], className="mb-3"),

                                dbc.Row([
                                    dbc.Col([
                                        dbc.Card([
                                            dbc.CardBody([
                                                html.Div([
                                                    html.I(className="fa fa-database fa-2x text-primary mb-2"),
                                                    html.H6("Database", className="mb-1"),
                                                    dbc.Badge("Connected", color="success", id='db-status-badge')
                                                ], className="text-center")
                                            ], className="py-3")
                                        ], className="border-0 bg-light")
                                    ], md=3),
                                    dbc.Col([
                                        dbc.Card([
                                            dbc.CardBody([
                                                html.Div([
                                                    html.I(className="fa fa-brain fa-2x text-purple mb-2"),
                                                    html.H6("ML Engine", className="mb-1"),
                                                    dbc.Badge("Running", color="success", id='ml-status-badge')
                                                ], className="text-center")
                                            ], className="py-3")
                                        ], className="border-0 bg-light")
                                    ], md=3),
                                    dbc.Col([
                                        dbc.Card([
                                            dbc.CardBody([
                                                html.Div([
                                                    html.I(className="fa fa-network-wired fa-2x text-info mb-2"),
                                                    html.H6("Capture", className="mb-1"),
                                                    dbc.Badge("Active", color="success", id='capture-status-badge')
                                                ], className="text-center")
                                            ], className="py-3")
                                        ], className="border-0 bg-light")
                                    ], md=3),
                                    dbc.Col([
                                        dbc.Card([
                                            dbc.CardBody([
                                                html.Div([
                                                    html.I(className="fa fa-bell fa-2x text-warning mb-2"),
                                                    html.H6("Alerts", className="mb-1"),
                                                    dbc.Badge("Enabled", color="success", id='alerts-status-badge')
                                                ], className="text-center")
                                            ], className="py-3")
                                        ], className="border-0 bg-light")
                                    ], md=3)
                                ], className="mb-4"),

                                html.H6([html.I(className="fa fa-terminal me-2"), "Recent Logs"], className="mb-3"),
                                html.Div([
                                    html.Pre(id='system-logs-display',
                                            style={"maxHeight": "200px", "overflow": "auto", "fontSize": "0.8rem"},
                                            className="border p-3 rounded")
                                ]),

                                dbc.Button([
                                    html.I(className="fa fa-download me-2"),
                                    "Download Full Logs"
                                ], id='download-logs-btn', color="secondary", outline=True, size="sm", className="mt-2")
                            ])
                        ], className="glass-card border-0 shadow-sm")
                    ], className="p-3")
                ], label="Diagnostics", tab_id="diagnostics-tab")

            ], id="system-modal-tabs", active_tab="system-info-tab")
        ]),
        dbc.ModalFooter([
            html.Div(id='system-timestamp-display', className="me-auto"),
            dbc.Button([
                html.I(className="fa fa-sync-alt me-2"),
                "Refresh"
            ], id='refresh-system-btn', color="primary", outline=True, className="me-2"),
            dbc.Button([
                html.I(className="fa fa-times me-2"),
                "Close"
            ], id='close-system-modal-btn', color="secondary", outline=True)
        ]),
        dcc.Store(id='system-timestamp-store')
    ], id="system-modal", size="xl", is_open=False, scrollable=True),

    # Email Notifications Modal - Enhanced with Tabs
    dbc.Modal([
        dbc.ModalHeader(dbc.ModalTitle([
            html.I(className="fa fa-envelope me-2 text-primary"),
            "Email Notifications"
        ]), close_button=True),
        dbc.ModalBody([
            dbc.Tabs([
                # SMTP Settings Tab
                dbc.Tab([
                    html.Div([
                        dbc.Card([
                            dbc.CardBody([
                                html.H6([html.I(className="fa fa-server me-2 text-info"), "SMTP Configuration"], className="mb-3"),

                                dbc.Alert([
                                    html.I(className="fa fa-info-circle me-2"),
                                    "SMTP settings are configured in the .env file for security."
                                ], color="info", className="mb-3"),

                                # Current SMTP Settings Display
                                dbc.Row([
                                    dbc.Col([
                                        html.Label("SMTP Server", className="small text-muted"),
                                        dbc.InputGroup([
                                            dbc.InputGroupText(html.I(className="fa fa-server")),
                                            dbc.Input(value=os.getenv('EMAIL_SMTP_HOST', 'Not configured'), disabled=True)
                                        ], className="mb-2")
                                    ], md=6),
                                    dbc.Col([
                                        html.Label("SMTP Port", className="small text-muted"),
                                        dbc.InputGroup([
                                            dbc.InputGroupText(html.I(className="fa fa-plug")),
                                            dbc.Input(value=os.getenv('EMAIL_SMTP_PORT', 'Not configured'), disabled=True)
                                        ], className="mb-2")
                                    ], md=6)
                                ]),
                                dbc.Row([
                                    dbc.Col([
                                        html.Label("From Email", className="small text-muted"),
                                        dbc.InputGroup([
                                            dbc.InputGroupText(html.I(className="fa fa-envelope")),
                                            dbc.Input(value=os.getenv('EMAIL_FROM', 'Not configured'), disabled=True)
                                        ], className="mb-2")
                                    ], md=6),
                                    dbc.Col([
                                        html.Label("Encryption", className="small text-muted"),
                                        dbc.InputGroup([
                                            dbc.InputGroupText(html.I(className="fa fa-lock")),
                                            dbc.Input(value="TLS/SSL", disabled=True)
                                        ], className="mb-2")
                                    ], md=6)
                                ]),

                                html.Hr(),

                                html.H6([html.I(className="fa fa-toggle-on me-2 text-success"), "Enable Notifications"], className="mb-3"),

                                dbc.Switch(id='email-enable-switch', label="Enable Email Alerts", value=False, className="mb-3"),
                                html.Small("When enabled, you'll receive email notifications for critical alerts.", className="text-muted d-block mb-3"),

                                html.Div(id='email-settings-status', className="mt-3")
                            ])
                        ], className="glass-card border-0 shadow-sm")
                    ], className="p-3")
                ], label="Settings", tab_id="smtp-settings-tab"),

                # Recipients Tab
                dbc.Tab([
                    html.Div([
                        dbc.Card([
                            dbc.CardBody([
                                html.H6([html.I(className="fa fa-users me-2 text-primary"), "Email Recipients"], className="mb-3"),

                                html.Label("Primary Recipient", className="fw-bold mb-2"),
                                dbc.InputGroup([
                                    dbc.InputGroupText(html.I(className="fa fa-user")),
                                    dbc.Input(id='email-to', type='email', placeholder='Enter primary email address')
                                ], className="mb-3"),
                                html.Small("This is the main email address for all alerts.", className="text-muted d-block mb-4"),

                                html.Label("Additional Recipients (Optional)", className="fw-bold mb-2"),
                                dbc.InputGroup([
                                    dbc.InputGroupText(html.I(className="fa fa-users")),
                                    dbc.Input(id='email-cc', type='text', placeholder='email1@example.com, email2@example.com')
                                ], className="mb-2"),
                                html.Small("Separate multiple emails with commas.", className="text-muted d-block mb-4"),

                                html.Hr(),

                                html.H6([html.I(className="fa fa-filter me-2 text-warning"), "Notification Preferences"], className="mb-3"),

                                dbc.Checklist(
                                    id='email-alert-types',
                                    options=[
                                        {'label': html.Span([html.I(className="fa fa-exclamation-circle me-2 text-danger"), "Critical Alerts"]), 'value': 'critical'},
                                        {'label': html.Span([html.I(className="fa fa-exclamation-triangle me-2 text-warning"), "Warning Alerts"]), 'value': 'warning'},
                                        {'label': html.Span([html.I(className="fa fa-info-circle me-2 text-info"), "Info Notifications"]), 'value': 'info'},
                                        {'label': html.Span([html.I(className="fa fa-file-alt me-2 text-primary"), "Daily Summary Report"]), 'value': 'daily_summary'},
                                        {'label': html.Span([html.I(className="fa fa-calendar-week me-2 text-success"), "Weekly Digest"]), 'value': 'weekly_digest'}
                                    ],
                                    value=['critical', 'warning'],
                                    switch=True,
                                    className="mb-3"
                                )
                            ])
                        ], className="glass-card border-0 shadow-sm")
                    ], className="p-3")
                ], label="Recipients", tab_id="recipients-tab"),

                # Templates Tab
                dbc.Tab([
                    html.Div([
                        dbc.Card([
                            dbc.CardBody([
                                html.H6([html.I(className="fa fa-file-code me-2 text-success"), "Email Templates"], className="mb-3"),

                                html.Label("Select Template to Edit", className="fw-bold mb-2"),
                                dbc.Select(
                                    id='template-select',
                                    options=[
                                        {'label': '🚨 Critical Alert Template', 'value': 'critical'},
                                        {'label': '⚠️ Warning Alert Template', 'value': 'warning'},
                                        {'label': '📊 Daily Summary Template', 'value': 'daily'},
                                        {'label': '📅 Weekly Digest Template', 'value': 'weekly'}
                                    ],
                                    value='critical',
                                    className="mb-3"
                                ),

                                html.Label("Email Subject", className="fw-bold mb-2"),
                                dbc.Input(id='template-subject', value="[IoTSentinel] Critical Security Alert: {{alert_type}}", className="mb-3"),

                                html.Label("Email Body Preview", className="fw-bold mb-2"),
                                dbc.Textarea(
                                    id='template-body',
                                    value="A critical security alert has been detected on your network.\n\nAlert Type: {{alert_type}}\nDevice: {{device_name}}\nIP Address: {{device_ip}}\nTime: {{timestamp}}\n\nPlease review this alert immediately.",
                                    style={"height": "150px", "fontFamily": "monospace", "fontSize": "0.85rem"},
                                    className="mb-3"
                                ),

                                html.Label("Available Variables", className="small text-muted mb-2"),
                                html.Div([
                                    dbc.Badge("{{alert_type}}", color="secondary", className="me-1 mb-1"),
                                    dbc.Badge("{{device_name}}", color="secondary", className="me-1 mb-1"),
                                    dbc.Badge("{{device_ip}}", color="secondary", className="me-1 mb-1"),
                                    dbc.Badge("{{timestamp}}", color="secondary", className="me-1 mb-1"),
                                    dbc.Badge("{{severity}}", color="secondary", className="me-1 mb-1"),
                                    dbc.Badge("{{description}}", color="secondary", className="me-1 mb-1")
                                ], className="mb-3"),

                                dbc.Button([
                                    html.I(className="fa fa-save me-2"),
                                    "Save Template"
                                ], id='save-template-btn', color="success", className="me-2"),
                                dbc.Button([
                                    html.I(className="fa fa-undo me-2"),
                                    "Reset to Default"
                                ], id='reset-template-btn', color="secondary", outline=True)
                            ])
                        ], className="glass-card border-0 shadow-sm")
                    ], className="p-3")
                ], label="Templates", tab_id="templates-tab"),

                # Test & History Tab
                dbc.Tab([
                    html.Div([
                        dbc.Card([
                            dbc.CardBody([
                                html.H6([html.I(className="fa fa-paper-plane me-2 text-info"), "Send Test Email"], className="mb-3"),

                                html.P("Send a test email to verify your configuration.", className="text-muted small mb-3"),

                                dbc.Row([
                                    dbc.Col([
                                        dbc.InputGroup([
                                            dbc.InputGroupText(html.I(className="fa fa-envelope")),
                                            dbc.Input(id='test-email-address', type='email', placeholder='Test recipient email')
                                        ])
                                    ], md=8),
                                    dbc.Col([
                                        dbc.Button([
                                            html.I(className="fa fa-paper-plane me-2"),
                                            "Send Test"
                                        ], id='test-email-btn', color="info", className="w-100")
                                    ], md=4)
                                ], className="mb-3"),

                                html.Div(id='test-email-status', className="mb-3")
                            ])
                        ], className="glass-card border-0 shadow-sm mb-3"),

                        dbc.Card([
                            dbc.CardBody([
                                html.H6([html.I(className="fa fa-history me-2 text-warning"), "Email History"], className="mb-3"),

                                html.Div(id='email-history-list', children=[
                                    dbc.Alert([
                                        html.I(className="fa fa-info-circle me-2"),
                                        "Email history will be populated from email notification logs"
                                    ], color="info", className="mb-0")
                                ])
                            ])
                        ], className="glass-card border-0 shadow-sm")
                    ], className="p-3")
                ], label="Test & History", tab_id="test-history-tab"),

                # Active Schedules Tab
                dbc.Tab([
                    html.Div([
                        dbc.Row([
                            dbc.Col([
                                html.H6([
                                    html.I(className="fa fa-list me-2 text-primary"),
                                    "Active Schedules"
                                ], className="mb-3"),
                                dbc.Button([
                                    html.I(className="fa fa-sync me-2"),
                                    "Refresh"
                                ], id="refresh-schedules-btn", color="primary", size="sm", outline=True, className="mb-3")
                            ])
                        ]),
                        html.Div(id='schedules-list-container')
                    ], className="p-3")
                ], label="Active Schedules", tab_id="schedules-list-tab"),

                # Add New Schedule Tab
                dbc.Tab([
                    html.Div([
                        html.H6([
                            html.I(className="fa fa-plus-circle me-2 text-success"),
                            "Create New Schedule"
                        ], className="mb-3"),

                        dbc.Row([
                            # Schedule ID
                            dbc.Col([
                                html.Label("Schedule Name/ID", className="fw-bold mb-2"),
                                dbc.Input(
                                    id='schedule-id-input',
                                    type='text',
                                    placeholder='e.g., daily_executive_summary',
                                    value=''
                                )
                            ], width=12, className="mb-3"),
                        ]),

                        dbc.Row([
                            # Template Selection
                            dbc.Col([
                                html.Label("Report Template", className="fw-bold mb-2"),
                                dbc.Select(
                                    id='schedule-template-select',
                                    options=[
                                        {'label': 'Executive Summary', 'value': 'executive_summary'},
                                        {'label': 'Security Audit Report', 'value': 'security_audit'},
                                        {'label': 'Network Activity Report', 'value': 'network_activity'},
                                        {'label': 'Device Inventory Report', 'value': 'device_inventory'},
                                        {'label': 'Threat Analysis Report', 'value': 'threat_analysis'}
                                    ],
                                    value='executive_summary'
                                )
                            ], width=6),

                            # Format Selection
                            dbc.Col([
                                html.Label("Export Format", className="fw-bold mb-2"),
                                dbc.Select(
                                    id='schedule-format-select',
                                    options=[
                                        {'label': 'PDF Report', 'value': 'pdf'},
                                        {'label': 'Excel Workbook', 'value': 'excel'}
                                    ],
                                    value='pdf'
                                )
                            ], width=6)
                        ], className="mb-3"),

                        dbc.Row([
                            # Schedule Type
                            dbc.Col([
                                html.Label("Schedule Type", className="fw-bold mb-2"),
                                dbc.RadioItems(
                                    id='schedule-type-radio',
                                    options=[
                                        {'label': 'Cron Expression', 'value': 'cron'},
                                        {'label': 'Interval (Hours)', 'value': 'interval'}
                                    ],
                                    value='cron',
                                    inline=True
                                )
                            ], width=12, className="mb-3"),
                        ]),

                        # Cron Expression Input (shown when cron is selected)
                        html.Div([
                            dbc.Row([
                                dbc.Col([
                                    html.Label("Cron Expression", className="fw-bold mb-2"),
                                    dbc.Input(
                                        id='schedule-cron-input',
                                        type='text',
                                        placeholder='0 8 * * * (Daily at 8 AM)',
                                        value='0 8 * * *'
                                    ),
                                    html.Small("Format: minute hour day month day_of_week", className="text-muted"),
                                    html.Br(),
                                    html.Small([
                                        "Examples: ",
                                        html.Code("0 8 * * *", className="text-primary"), " (Daily 8 AM), ",
                                        html.Code("0 9 * * 1", className="text-primary"), " (Monday 9 AM)"
                                    ], className="text-muted")
                                ], width=12)
                            ], className="mb-3")
                        ], id='cron-expression-div', style={'display': 'block'}),

                        # Interval Input (shown when interval is selected)
                        html.Div([
                            dbc.Row([
                                dbc.Col([
                                    html.Label("Interval (Hours)", className="fw-bold mb-2"),
                                    dbc.Input(
                                        id='schedule-interval-input',
                                        type='number',
                                        min=1,
                                        max=168,
                                        value=24,
                                        step=1
                                    ),
                                    html.Small("Run every N hours (1-168)", className="text-muted")
                                ], width=12)
                            ], className="mb-3")
                        ], id='interval-hours-div', style={'display': 'none'}),

                        dbc.Row([
                            # Time Range
                            dbc.Col([
                                html.Label("Report Time Range (Days)", className="fw-bold mb-2"),
                                dbc.Input(
                                    id='schedule-days-input',
                                    type='number',
                                    value=7,
                                    min=1,
                                    max=365,
                                    step=1
                                )
                            ], width=6),

                            # Email Recipient (optional)
                            dbc.Col([
                                html.Label("Email Recipient (Optional)", className="fw-bold mb-2"),
                                dbc.Input(
                                    id='schedule-email-input',
                                    type='email',
                                    placeholder='Leave empty for default'
                                )
                            ], width=6)
                        ], className="mb-3"),

                        dbc.Row([
                            dbc.Col([
                                dbc.Button([
                                    html.I(className="fa fa-plus me-2"),
                                    "Add Schedule"
                                ], id="add-schedule-btn", color="success", className="w-100")
                            ])
                        ]),

                        html.Div(id='add-schedule-status', className="mt-3")
                    ], className="p-3")
                ], label="Add Schedule", tab_id="add-schedule-tab"),

                # Daily Digest Tab
                dbc.Tab([
                    html.Div([
                        html.H6([
                            html.I(className="fa fa-envelope me-2 text-info"),
                            "Daily Security Digest"
                        ], className="mb-3"),
                        html.P("Automatically send a daily summary email with security metrics and trends.", className="text-muted mb-3"),

                        dbc.Row([
                            dbc.Col([
                                html.Label("Time to Send", className="fw-bold mb-2"),
                                dbc.Row([
                                    dbc.Col([
                                        dbc.Input(
                                            id='digest-hour-input',
                                            type='number',
                                            min=0,
                                            max=23,
                                            value=8,
                                            step=1
                                        ),
                                        html.Small("Hour (0-23)", className="text-muted")
                                    ], width=6),
                                    dbc.Col([
                                        dbc.Input(
                                            id='digest-minute-input',
                                            type='number',
                                            min=0,
                                            max=59,
                                            value=0,
                                            step=1
                                        ),
                                        html.Small("Minute (0-59)", className="text-muted")
                                    ], width=6)
                                ])
                            ], width=6),

                            dbc.Col([
                                html.Label("Email Recipient (Optional)", className="fw-bold mb-2"),
                                dbc.Input(
                                    id='digest-email-input',
                                    type='email',
                                    placeholder='Leave empty for default'
                                )
                            ], width=6)
                        ], className="mb-3"),

                        dbc.Row([
                            dbc.Col([
                                dbc.Button([
                                    html.I(className="fa fa-calendar-check me-2"),
                                    "Enable Daily Digest"
                                ], id="enable-digest-btn", color="info", className="w-100 mb-2")
                            ], width=6),
                            dbc.Col([
                                dbc.Button([
                                    html.I(className="fa fa-paper-plane me-2"),
                                    "Send Test Digest Now"
                                ], id="test-digest-btn", color="warning", outline=True, className="w-100 mb-2")
                            ], width=6)
                        ]),

                        html.Div(id='digest-status', className="mt-3")
                    ], className="p-3")
                ], label="Daily Digest", tab_id="daily-digest-tab")

            ], id="email-modal-tabs", active_tab="smtp-settings-tab")
        ]),
        dbc.ModalFooter([
            dbc.Button([
                html.I(className="fa fa-save me-2"),
                "Save Settings"
            ], id='save-email-settings-btn', color="primary", className="me-2"),
            dbc.Button([
                html.I(className="fa fa-times me-2"),
                "Close"
            ], id='close-email-modal-btn', color="secondary", outline=True)
        ])
    ], id="email-modal", size="xl", is_open=False, scrollable=True),

    # Firewall Control Modal
    dbc.Modal([
        dbc.ModalHeader(dbc.ModalTitle([
            html.I(className="fa fa-shield-halved me-2"),
            "Firewall Control"
        ]), close_button=True),
        dbc.ModalBody([
            dbc.Tabs([
                # Lockdown Control Tab
                dbc.Tab([
                    html.Div([
                        dbc.Card([
                            dbc.CardBody([
                                html.H6([html.I(className="fa fa-lock me-2 text-danger"), "Lockdown Mode"], className="mb-3"),
                                dbc.Alert([
                                    html.H5("⚠️ Lockdown Mode", className="alert-heading"),
                                    html.P("Enable lockdown mode to block all untrusted devices from your network. Only trusted devices will be allowed.")
                                ], color="warning", className="mb-3"),
                                dbc.Switch(id='lockdown-switch', label="Enable Lockdown Mode", value=False, className="mb-3"),
                                html.Div(id='lockdown-status')
                            ])
                        ], className="glass-card border-0 shadow-sm")
                    ], className="p-3")
                ], label="Lockdown Control", tab_id="firewall-lockdown-tab"),

                # Blocked Devices Tab
                dbc.Tab([
                    html.Div([
                        dbc.Card([
                            dbc.CardBody([
                                html.H6([html.I(className="fa fa-ban me-2 text-danger"), "Blocked Devices"], className="mb-3"),
                                dbc.Alert([
                                    html.I(className="fa fa-info-circle me-2"),
                                    "View and manage devices currently blocked by firewall rules."
                                ], color="info", className="mb-3"),
                                html.Div(id='firewall-blocked-devices', children=[
                                    html.P("No blocked devices", className="text-muted text-center py-4")
                                ])
                            ])
                        ], className="glass-card border-0 shadow-sm")
                    ], className="p-3")
                ], label="Blocked Devices", tab_id="firewall-blocked-tab"),

                # Firewall Rules Tab
                dbc.Tab([
                    html.Div([
                        dbc.Card([
                            dbc.CardBody([
                                html.H6([html.I(className="fa fa-list me-2 text-primary"), "Active Firewall Rules"], className="mb-3"),
                                dbc.Alert([
                                    html.I(className="fa fa-shield-alt me-2"),
                                    "Configure and monitor active firewall rules for your network."
                                ], color="success", className="mb-3"),
                                html.Div(id='firewall-rules-list', children=[
                                    html.P("No active rules", className="text-muted text-center py-4")
                                ])
                            ])
                        ], className="glass-card border-0 shadow-sm")
                    ], className="p-3")
                ], label="Firewall Rules", tab_id="firewall-rules-tab")
            ], id="firewall-tabs", active_tab="firewall-lockdown-tab")
        ], style={"maxHeight": "60vh", "overflowY": "auto"}),
        dbc.ModalFooter([
            dbc.Button([
                html.I(className="fa fa-save me-2"),
                "Save Changes"
            ], id="save-firewall-btn", color="primary", size="sm", className="me-2"),
            dbc.Button([
                html.I(className="fa fa-times me-2"),
                "Cancel"
            ], id="cancel-firewall-btn", color="secondary", size="sm")
        ])
    ], id="firewall-modal", size="lg", is_open=False),

    # Profile Edit Modal - Enhanced Design
    dbc.Modal([
        dbc.ModalHeader(dbc.ModalTitle([
            html.I(className="fa fa-user-edit me-2 text-primary"),
            "Edit Profile"
        ]), close_button=True),
        dbc.ModalBody([
            dbc.Tabs([
                # Profile Information Tab
                dbc.Tab([
                    html.Div([
                        dbc.Card([
                            dbc.CardBody([
                                html.H6([html.I(className="fa fa-user me-2 text-primary"), "Account Information"], className="mb-3"),

                                dbc.Row([
                                    dbc.Col([
                                        dbc.Label("Username", className="fw-bold"),
                                        dbc.InputGroup([
                                            dbc.InputGroupText(html.I(className="fa fa-at")),
                                            dbc.Input(id='edit-username', type='text', placeholder="Enter new username")
                                        ], className="mb-3"),
                                        html.Small("Choose a unique username (3-20 characters)", className="text-muted d-block mb-2")
                                    ], md=6),
                                    dbc.Col([
                                        dbc.Label("Email Address", className="fw-bold"),
                                        dbc.InputGroup([
                                            dbc.InputGroupText(html.I(className="fa fa-envelope")),
                                            dbc.Input(id='edit-email', type='email', placeholder="Enter email address")
                                        ], className="mb-3"),
                                        html.Small("Used for notifications and password recovery", className="text-muted d-block mb-2")
                                    ], md=6)
                                ]),

                                html.Hr(),

                                html.H6([html.I(className="fa fa-info-circle me-2 text-info"), "Profile Details"], className="mb-3"),

                                dbc.Row([
                                    dbc.Col([
                                        dbc.Label("Display Name", className="fw-bold"),
                                        dbc.InputGroup([
                                            dbc.InputGroupText(html.I(className="fa fa-id-card")),
                                            dbc.Input(id='edit-display-name', type='text', placeholder="How should we call you?")
                                        ], className="mb-3")
                                    ], md=6),
                                    dbc.Col([
                                        dbc.Label("Phone Number (Optional)", className="fw-bold"),
                                        dbc.InputGroup([
                                            dbc.InputGroupText(html.I(className="fa fa-phone")),
                                            dbc.Input(id='edit-phone', type='tel', placeholder="+1 (555) 000-0000")
                                        ], className="mb-3")
                                    ], md=6)
                                ]),

                                html.Div(id='profile-update-status', className="mb-3"),

                                dbc.Button([
                                    html.I(className="fa fa-save me-2"),
                                    "Save Changes"
                                ], id='update-profile-btn', color="primary", className="w-100")
                            ])
                        ], className="glass-card border-0 shadow-sm mb-3"),
                    ], className="p-3")
                ], label="Profile", tab_id="profile-info-tab"),

                # Security Tab
                dbc.Tab([
                    html.Div([
                        # Change Password Section
                        dbc.Card([
                            dbc.CardBody([
                                html.H6([html.I(className="fa fa-key me-2 text-warning"), "Change Password"], className="mb-3"),

                                dbc.Label("Current Password", className="fw-bold"),
                                dbc.InputGroup([
                                    dbc.InputGroupText(html.I(className="fa fa-lock")),
                                    dbc.Input(id='profile-current-password', type='password', placeholder="Enter current password"),
                                    dbc.Button(html.I(className="fa fa-eye", id='profile-current-password-toggle-icon'),
                                               id="profile-current-password-toggle-btn", color="light", n_clicks=0)
                                ], className="mb-3"),

                                dbc.Row([
                                    dbc.Col([
                                        dbc.Label("New Password", className="fw-bold"),
                                        dbc.InputGroup([
                                            dbc.InputGroupText(html.I(className="fa fa-lock")),
                                            dbc.Input(id='profile-new-password', type='password', placeholder="Enter new password"),
                                            dbc.Button(html.I(className="fa fa-eye", id='profile-new-password-toggle-icon'),
                                                       id="profile-new-password-toggle-btn", color="light", n_clicks=0)
                                        ], className="mb-2"),
                                        html.Small("Minimum 8 characters with letters and numbers", className="text-muted d-block mb-3")
                                    ], md=6),
                                    dbc.Col([
                                        dbc.Label("Confirm New Password", className="fw-bold"),
                                        dbc.InputGroup([
                                            dbc.InputGroupText(html.I(className="fa fa-check-circle")),
                                            dbc.Input(id='profile-new-password-confirm', type='password', placeholder="Confirm new password"),
                                            dbc.Button(html.I(className="fa fa-eye", id={'type': 'profile-password-toggle-icon', 'index': 'new-confirm'}),
                                                       id={"type": "profile-password-toggle-btn", "index": "new-confirm"}, color="light", n_clicks=0)
                                        ], className="mb-2"),
                                        html.Small("Re-enter your new password", className="text-muted d-block mb-3")
                                    ], md=6)
                                ]),

                                # Password Strength Indicator
                                html.Div([
                                    dbc.Label("Password Strength", className="fw-bold small"),
                                    dbc.Progress(id='password-strength-bar', value=0, className="mb-2", style={"height": "6px"}),
                                ], className="mb-3"),

                                html.Div(id='profile-change-password-status', className="mb-3"),

                                dbc.Button([
                                    html.I(className="fa fa-shield-alt me-2"),
                                    "Update Password"
                                ], id='profile-change-password-btn', color="success", className="w-100")
                            ])
                        ], className="glass-card border-0 shadow-sm mb-3"),

                        # Biometric Security Section
                        dbc.Card([
                            dbc.CardBody([
                                html.H6([html.I(className="fa fa-fingerprint me-2 text-success"), "Biometric Security"], className="mb-3"),

                                html.Div([
                                    html.I(className="fa fa-info-circle me-2 text-info"),
                                    "Use Touch ID, Face ID, or Windows Hello for quick and secure login. Your biometric data never leaves your device."
                                ], className="alert alert-info d-flex align-items-center mb-3", style={"fontSize": "0.85rem"}),

                                # Registered Devices List
                                html.Div(id='biometric-devices-list', className="mb-3"),

                                # Hidden div to store username for WebAuthn
                                html.Div(id='biometric-username-store', **{'data-username': ''}, style={'display': 'none'}),

                                # Register New Biometric Button
                                dbc.Button([
                                    html.I(className="fa fa-plus-circle me-2"),
                                    "Register New Biometric Device"
                                ], id='register-biometric-btn', color="primary", outline=True, className="w-100 mb-2"),

                                # Status messages
                                html.Div(id='biometric-status-message')
                            ])
                        ], className="glass-card border-0 shadow-sm", id="biometric-security-section", style={"display": "none"}),

                        # Two-Factor Authentication (2FA) Section
                        dbc.Card([
                            dbc.CardBody([
                                html.H6([html.I(className="fa fa-mobile-alt me-2 text-danger"), "Two-Factor Authentication (2FA)"], className="mb-3"),

                                html.Div([
                                    html.I(className="fa fa-shield-alt me-2 text-info"),
                                    "Add an extra layer of security to your account. Use any authenticator app (Google Authenticator, Authy, Microsoft Authenticator, etc.) to generate time-based codes."
                                ], className="alert alert-info d-flex align-items-center mb-3", style={"fontSize": "0.85rem"}),

                                # 2FA Status Display
                                html.Div(id='totp-status-display', className="mb-3"),

                                # Setup Section (hidden by default, shown when enabling)
                                html.Div([
                                    html.Hr(),
                                    html.H6([html.I(className="fa fa-qrcode me-2"), "Setup Authenticator"], className="mb-3"),

                                    dbc.Row([
                                        dbc.Col([
                                            html.P("Scan this QR code with your authenticator app:", className="mb-2 fw-bold"),
                                            html.Div(id='totp-qr-code', className="text-center mb-3"),

                                            html.P("Or enter this secret key manually:", className="mb-1 small text-muted"),
                                            dbc.InputGroup([
                                                dbc.Input(id='totp-secret-display', type='text', readonly=True, className="font-monospace"),
                                                dbc.Button([html.I(className="fa fa-copy")], id='copy-totp-secret-btn', color="secondary", outline=True)
                                            ], className="mb-3", size="sm"),
                                        ], md=6),

                                        dbc.Col([
                                            html.P("Backup Codes (save these securely):", className="mb-2 fw-bold"),
                                            html.Div([
                                                html.Small("Use these codes if you lose access to your authenticator app. Each code can only be used once.", className="text-muted d-block mb-2")
                                            ]),
                                            html.Div(id='totp-backup-codes-display', className="mb-3"),
                                            dbc.Button([
                                                html.I(className="fa fa-download me-2"),
                                                "Download Backup Codes"
                                            ], id='download-backup-codes-btn', color="warning", outline=True, size="sm", className="w-100")
                                        ], md=6)
                                    ]),

                                    html.Hr(),
                                    html.H6([html.I(className="fa fa-check-circle me-2"), "Verify Setup"], className="mb-3"),
                                    html.P("Enter the 6-digit code from your authenticator app to enable 2FA:", className="mb-2"),

                                    dbc.InputGroup([
                                        dbc.InputGroupText(html.I(className="fa fa-keyboard")),
                                        dbc.Input(
                                            id='totp-verification-code',
                                            type='text',
                                            placeholder="000000",
                                            maxLength=6,
                                            className="text-center font-monospace",
                                            style={"fontSize": "1.5rem", "letterSpacing": "0.5rem"}
                                        )
                                    ], className="mb-3"),

                                    html.Div(id='totp-verification-status', className="mb-3"),

                                    dbc.ButtonGroup([
                                        dbc.Button([
                                            html.I(className="fa fa-check me-2"),
                                            "Verify & Enable 2FA"
                                        ], id='verify-totp-btn', color="success", className="flex-fill"),
                                        dbc.Button([
                                            html.I(className="fa fa-times me-2"),
                                            "Cancel"
                                        ], id='cancel-totp-setup-btn', color="secondary", outline=True)
                                    ], className="w-100")
                                ], id='totp-setup-section', style={'display': 'none'}),

                                # Action Buttons (shown based on 2FA status)
                                html.Div([
                                    dbc.Button([
                                        html.I(className="fa fa-power-off me-2"),
                                        "Enable 2FA"
                                    ], id='enable-totp-btn', color="success", className="w-100 mb-2"),

                                    dbc.Button([
                                        html.I(className="fa fa-ban me-2"),
                                        "Disable 2FA"
                                    ], id='disable-totp-btn', color="danger", outline=True, className="w-100", style={'display': 'none'})
                                ], id='totp-action-buttons')
                            ])
                        ], className="glass-card border-0 shadow-sm mb-3")
                    ], className="p-3")
                ], label="Security", tab_id="security-tab"),

                # Preferences Tab
                dbc.Tab([
                    html.Div([
                        dbc.Card([
                            dbc.CardBody([
                                html.H6([html.I(className="fa fa-bell me-2 text-warning"), "Notification Preferences"], className="mb-3"),

                                dbc.Checklist(
                                    id='profile-notification-prefs',
                                    options=[
                                        {'label': html.Span([html.I(className="fa fa-envelope text-primary me-2"), "Email Notifications - Receive alerts via email"], className="d-flex align-items-center"), 'value': 'email'},
                                        {'label': html.Span([html.I(className="fa fa-bell text-warning me-2"), "Browser Notifications - Desktop push alerts"], className="d-flex align-items-center"), 'value': 'browser'},
                                        {'label': html.Span([html.I(className="fa fa-volume-up text-success me-2"), "Sound Alerts - Audio notifications"], className="d-flex align-items-center"), 'value': 'sound'},
                                        {'label': html.Span([html.I(className="fa fa-file-alt text-info me-2"), "Weekly Reports - Summary emails"], className="d-flex align-items-center"), 'value': 'reports'}
                                    ],
                                    value=['email', 'browser'],
                                    switch=True,
                                    className="mb-3"
                                ),

                                html.Hr(),

                                html.H6([html.I(className="fa fa-clock me-2 text-info"), "Session Settings"], className="mb-3"),

                                dbc.Label("Session Timeout", className="fw-bold"),
                                dbc.Select(
                                    id='session-timeout-dropdown',
                                    options=[
                                        {'label': '⏱️ 15 minutes - High security', 'value': 15},
                                        {'label': '⏱️ 30 minutes - Recommended', 'value': 30},
                                        {'label': '⏱️ 1 hour - Standard', 'value': 60},
                                        {'label': '⏱️ 4 hours - Extended session', 'value': 240}
                                    ],
                                    value=30,
                                    className="mb-2"
                                ),
                                html.Small("Automatically log out after this period of inactivity", className="text-muted d-block mb-3"),

                                html.Hr(),

                                html.H6([html.I(className="fa fa-layout me-2 text-primary"), "Dashboard Template"], className="mb-3"),
                                html.P("Choose a pre-configured dashboard layout optimized for your role.", className="text-muted small mb-3"),

                                dbc.RadioItems(
                                    id='dashboard-template-select',
                                    options=[
                                        {
                                            'label': html.Div([
                                                html.I(className="fa fa-home text-success me-2"),
                                                html.Span("Home User", className="fw-bold"),
                                                html.Br(),
                                                html.Small("Focus: Device Status, Privacy Score, Basic Security Health", className="text-muted")
                                            ]),
                                            'value': 'home_user'
                                        },
                                        {
                                            'label': html.Div([
                                                html.I(className="fa fa-code text-info me-2"),
                                                html.Span("Developer/Auditor", className="fw-bold"),
                                                html.Br(),
                                                html.Small("Focus: All Features, API Hub, Analytics, Performance", className="text-muted")
                                            ]),
                                            'value': 'developer'
                                        },
                                        {
                                            'label': html.Div([
                                                html.I(className="fa fa-sliders text-warning me-2"),
                                                html.Span("Custom", className="fw-bold"),
                                                html.Br(),
                                                html.Small("Use your own customized widget layout", className="text-muted")
                                            ]),
                                            'value': 'custom'
                                        }
                                    ],
                                    value=None,  # Value loaded from database via callback
                                    className="mb-3"
                                ),
                            ])
                        ], className="glass-card border-0 shadow-sm mb-3"),
                    ], className="p-3")
                ], label="Preferences", tab_id="preferences-tab"),

            ], id="profile-edit-tabs", active_tab="profile-info-tab"),
        ]),
        dbc.ModalFooter([
            dbc.Button([
                html.I(className="fa fa-times me-2"),
                "Close"
            ], id='close-profile-modal-btn', color="secondary", outline=True)
        ])
    ], id="profile-edit-modal", size="lg", is_open=False, scrollable=True),

    # User Management Modal (Admin Only) - Enhanced Design
    dbc.Modal([
        dbc.ModalHeader(dbc.ModalTitle([
            html.I(className="fa fa-users-gear me-2 text-primary"),
            "User Management"
        ])),
        dbc.ModalBody([
            # Admin-only notice
            html.Div(id='admin-only-notice', className="mb-3"),

            dbc.Tabs([
                # Add New User Tab
                dbc.Tab([
                    html.Div([
                        dbc.Card([
                            dbc.CardBody([
                                html.H6([html.I(className="fa fa-user-plus me-2 text-success"), "Create New User Account"], className="mb-3"),

                                dbc.Row([
                                    dbc.Col([
                                        dbc.Label("Username", className="fw-bold"),
                                        dbc.InputGroup([
                                            dbc.InputGroupText(html.I(className="fa fa-at")),
                                            dbc.Input(id='new-user-username', type='text', placeholder="Enter username")
                                        ], className="mb-2"),
                                        html.Small("Unique identifier for login", className="text-muted d-block mb-3")
                                    ], md=6),
                                    dbc.Col([
                                        dbc.Label("Email Address", className="fw-bold"),
                                        dbc.InputGroup([
                                            dbc.InputGroupText(html.I(className="fa fa-envelope")),
                                            dbc.Input(id='new-user-email', type='email', placeholder="Enter email")
                                        ], className="mb-2"),
                                        html.Small("For notifications and recovery", className="text-muted d-block mb-3")
                                    ], md=6)
                                ]),

                                dbc.Row([
                                    dbc.Col([
                                        dbc.Label("Password", className="fw-bold"),
                                        dbc.InputGroup([
                                            dbc.InputGroupText(html.I(className="fa fa-lock")),
                                            dbc.Input(id='new-user-password', type='password', placeholder="Enter password")
                                        ], className="mb-2"),
                                        html.Small("Minimum 8 characters", className="text-muted d-block mb-3")
                                    ], md=6),
                                    dbc.Col([
                                        dbc.Label("User Role", className="fw-bold"),
                                        dbc.Select(
                                            id='new-user-role',
                                            options=[
                                                {'label': '👑 Admin - Full system access', 'value': 'admin'},
                                                {'label': '👁️ Viewer - Read-only access', 'value': 'viewer'}
                                            ],
                                            value='viewer',
                                            className="mb-2"
                                        ),
                                        html.Small("Determines user permissions. Users can choose their own dashboard template in Preferences.", className="text-muted d-block mb-3")
                                    ], md=6)
                                ]),

                                # Role permissions explanation
                                dbc.Card([
                                    dbc.CardBody([
                                        html.H6([html.I(className="fa fa-info-circle me-2"), "Role Permissions & Templates"], className="mb-2"),
                                        html.Div([
                                            html.Div([
                                                html.Span("👑 Admin:", className="fw-bold text-warning me-2"),
                                                "Can manage users, configure settings, view all data, and perform all actions"
                                            ], className="mb-2", style={"fontSize": "0.85rem"}),
                                            html.Div([
                                                html.Span("👁️ Viewer:", className="fw-bold text-info me-2"),
                                                "Can view dashboard, alerts, and reports. Cannot modify settings or manage users"
                                            ], className="mb-2", style={"fontSize": "0.85rem"}),
                                            html.Div([
                                                html.Span("💡 Note:", className="fw-bold text-success me-2"),
                                                "All users can select their preferred dashboard template (Security Admin, Home User, Developer, or Custom) in Preferences"
                                            ], style={"fontSize": "0.85rem"})
                                        ])
                                    ], className="py-2")
                                ], className="bg-light border-0 mb-3"),

                                html.Div(id='add-user-status', className="mb-3"),

                                dbc.Button([
                                    html.I(className="fa fa-user-plus me-2"),
                                    "Create User Account"
                                ], id='create-user-btn', color="success", className="w-100")
                            ])
                        ], className="glass-card border-0 shadow-sm mb-3"),
                    ], className="p-3")
                ], label="Add User", tab_id="add-user-tab"),

                # User List Tab
                dbc.Tab([
                    html.Div([
                        dbc.Card([
                            dbc.CardBody([
                                html.H6([html.I(className="fa fa-users me-2 text-primary"), "Registered Users"], className="mb-3"),

                                # Search and Filter
                                dbc.Row([
                                    dbc.Col([
                                        dbc.InputGroup([
                                            dbc.InputGroupText(html.I(className="fa fa-search")),
                                            dbc.Input(id='user-search-input', type='text', placeholder="Search users...")
                                        ])
                                    ], md=8),
                                    dbc.Col([
                                        dbc.Select(
                                            id='user-role-filter',
                                            options=[
                                                {'label': 'All Roles', 'value': 'all'},
                                                {'label': '👑 Admins Only', 'value': 'admin'},
                                                {'label': '👁️ Viewers Only', 'value': 'viewer'}
                                            ],
                                            value='all'
                                        )
                                    ], md=4)
                                ], className="mb-3"),

                                # User List Container
                                html.Div(id='user-list-container')
                            ])
                        ], className="glass-card border-0 shadow-sm mb-3"),
                    ], className="p-3")
                ], label="User List", tab_id="user-list-tab"),

                # Activity Log Tab
                dbc.Tab([
                    html.Div([
                        dbc.Card([
                            dbc.CardBody([
                                html.H6([html.I(className="fa fa-history me-2 text-info"), "Recent User Activity"], className="mb-3"),

                                html.Div([
                                    html.I(className="fa fa-info-circle me-2 text-muted"),
                                    "Shows login attempts, profile changes, and administrative actions"
                                ], className="text-muted small mb-3"),

                                # Activity Log Container
                                html.Div(id='user-activity-log', children=[
                                    html.Div([
                                        html.I(className="fa fa-spinner fa-spin me-2"),
                                        "Loading activity log..."
                                    ], className="text-center text-muted py-4")
                                ])
                            ])
                        ], className="glass-card border-0 shadow-sm mb-3"),
                    ], className="p-3")
                ], label="Activity Log", tab_id="activity-log-tab"),

            ], id="user-management-tabs", active_tab="add-user-tab"),
        ]),
        dbc.ModalFooter([
            dbc.Button([
                html.I(className="fa fa-sync-alt me-2"),
                "Refresh"
            ], id='refresh-users-btn', color="primary", outline=True, className="me-2"),
            dbc.Button([
                html.I(className="fa fa-times me-2"),
                "Close"
            ], id='close-user-modal-btn', color="secondary", outline=True)
        ])
    ], id="user-modal", size="xl", is_open=False, scrollable=True),

    # Device Management Modal - Enhanced with Tabs
    dbc.Modal([
        dbc.ModalHeader(dbc.ModalTitle([
            html.I(className="fa fa-diagram-project me-2 text-primary"),
            "Device Management"
        ]), close_button=True),
        dbc.ModalBody([
            dbc.Tabs([
                # Devices List Tab
                dbc.Tab([
                    html.Div([
                        dbc.Card([
                            dbc.CardBody([
                                html.H6([html.I(className="fa fa-list me-2 text-primary"), "All Devices"], className="mb-3"),

                                # Search and Filter Row
                                dbc.Row([
                                    dbc.Col([
                                        dbc.InputGroup([
                                            dbc.InputGroupText(html.I(className="fa fa-search")),
                                            dbc.Input(id='device-search-input', type='text', placeholder="Search devices...")
                                        ])
                                    ], md=6),
                                    dbc.Col([
                                        dbc.Select(
                                            id='device-status-filter',
                                            options=[
                                                {'label': '🔍 All Devices', 'value': 'all'},
                                                {'label': '✅ Trusted', 'value': 'trusted'},
                                                {'label': '🚫 Blocked', 'value': 'blocked'},
                                                {'label': '⚠️ Unknown', 'value': 'unknown'}
                                            ],
                                            value='all'
                                        )
                                    ], md=3),
                                    dbc.Col([
                                        dbc.Button([
                                            html.I(className="fa fa-sync-alt me-2"),
                                            "Refresh Devices"
                                        ], id='load-devices-btn', color="primary", className="w-100 refresh-devices-btn")
                                    ], md=3)
                                ], className="mb-3"),

                                # Device Stats Row
                                dbc.Row([
                                    dbc.Col([
                                        html.Div([
                                            html.Span("0", id='total-devices-count', className="h4 text-primary mb-0"),
                                            html.Small(" Total", className="text-muted")
                                        ], className="text-center")
                                    ], width=3),
                                    dbc.Col([
                                        html.Div([
                                            html.Span("0", id='trusted-devices-count', className="h4 text-success mb-0"),
                                            html.Small(" Trusted", className="text-muted")
                                        ], className="text-center")
                                    ], width=3),
                                    dbc.Col([
                                        html.Span("0", id='blocked-devices-count', className="h4 text-danger mb-0"),
                                        html.Small(" Blocked", className="text-muted")
                                    ], width=3),
                                    dbc.Col([
                                        html.Div([
                                            html.Span("0", id='unknown-devices-count', className="h4 text-warning mb-0"),
                                            html.Small(" Unknown", className="text-muted")
                                        ], className="text-center")
                                    ], width=3)
                                ], className="mb-3 py-2 bg-light rounded"),

                                # Device Table
                                html.Div(id='device-management-table'),

                                dcc.Store(id='selected-devices-store', data=[]),
                                dcc.Store(id='device-table-page', data=1)
                            ])
                        ], className="glass-card border-0 shadow-sm")
                    ], className="p-3")
                ], label="Devices", tab_id="devices-list-tab"),

                # Bulk Actions Tab
                dbc.Tab([
                    html.Div([
                        dbc.Card([
                            dbc.CardBody([
                                html.H6([html.I(className="fa fa-tasks me-2 text-info"), "Bulk Device Actions"], className="mb-3"),

                                html.P("Select multiple devices from the Devices tab, then perform bulk actions here.", className="text-muted mb-4"),

                                # Selected devices indicator
                                dbc.Alert([
                                    html.I(className="fa fa-check-circle me-2"),
                                    html.Span("0", id='selected-count-display'),
                                    " devices selected"
                                ], color="info", className="mb-3"),

                                # Selected devices list
                                html.Div(id='selected-devices-list', className="mb-4"),

                                # Bulk Action Buttons
                                html.Div([
                                    html.Label("Trust Actions", className="fw-bold mb-2 d-block"),
                                    dbc.ButtonGroup([
                                        dbc.Button([
                                            html.I(className="fa fa-check-circle me-2"),
                                            "Trust Selected"
                                        ], id='bulk-trust-btn', color="success", className="me-2"),
                                        dbc.Button([
                                            html.I(className="fa fa-shield-alt me-2"),
                                            "Trust All Unknown",
                                            html.Span(" 🔐", className="ms-1", title="Admin Only")
                                        ], id='bulk-trust-all-btn', color="success", outline=True,
                                           title="Trust all unknown devices at once (Admin only)")
                                    ], className="mb-3 d-block")
                                ], className="mb-4"),

                                html.Div([
                                    html.Label("Block Actions", className="fw-bold mb-2 d-block"),
                                    dbc.ButtonGroup([
                                        dbc.Button([
                                            html.I(className="fa fa-ban me-2"),
                                            "Block Selected"
                                        ], id='bulk-block-btn', color="danger", className="me-2"),
                                        dbc.Button([
                                            html.I(className="fa fa-exclamation-triangle me-2"),
                                            "Block All Suspicious",
                                            html.Span(" 🔐", className="ms-1", title="Parent/Admin")
                                        ], id='bulk-block-suspicious-btn', color="danger", outline=True,
                                           title="Block all devices with critical/high alerts (Parent/Admin only)")
                                    ], className="mb-3 d-block")
                                ], className="mb-4"),

                                html.Div([
                                    html.Label("Danger Zone", className="fw-bold mb-2 d-block text-danger"),
                                    dbc.Button([
                                        html.I(className="fa fa-trash me-2"),
                                        "Delete Selected Devices",
                                        html.Span(" 🔐", className="ms-1", title="Admin Only")
                                    ], id='bulk-delete-btn', color="warning", outline=True,
                                       title="Delete selected devices from database (Admin only)")
                                ], className="mb-3"),

                                html.Div(id='bulk-action-status', className="mt-3")
                            ])
                        ], className="glass-card border-0 shadow-sm")
                    ], className="p-3")
                ], label="Bulk Actions", tab_id="bulk-actions-tab"),

                # Device Details Tab
                dbc.Tab([
                    html.Div([
                        dbc.Card([
                            dbc.CardBody([
                                html.H6([html.I(className="fa fa-info-circle me-2 text-success"), "Device Details"], className="mb-3"),

                                html.P("Click on a device in the Devices tab to view detailed information.", className="text-muted mb-3"),

                                html.Div(id='device-detail-view', children=[
                                    html.Div([
                                        html.I(className="fa fa-mouse-pointer fa-3x text-muted mb-3"),
                                        html.P("Select a device to view details", className="text-muted")
                                    ], className="text-center py-5")
                                ]),

                                # Hidden back button placeholder (shown when device details are displayed)
                                dbc.Button("Back", id='back-to-devices-list-btn', style={'display': 'none'})
                            ])
                        ], className="glass-card border-0 shadow-sm")
                    ], className="p-3")
                ], label="Details", tab_id="device-details-tab"),

                # Analytics Tab - NEW
                dbc.Tab([
                    html.Div([
                        dbc.Card([
                            dbc.CardHeader([
                                html.I(className="fa fa-chart-pie me-2"),
                                "Device Hierarchy & Analytics"
                            ], className="glass-card-header"),
                            dbc.CardBody([
                                dcc.Loading(
                                    dcc.Graph(
                                        id='device-hierarchy-sunburst',
                                        config={
                                            'displayModeBar': True,
                                            'modeBarButtonsToRemove': ['pan2d', 'lasso2d'],
                                            'displaylogo': False
                                        },
                                        style={'height': '600px'}
                                    ),
                                    type='circle'
                                ),
                                html.P([
                                    html.I(className="fa fa-info-circle me-2"),
                                    "Interactive sunburst chart showing 3-level device hierarchy. "
                                    "Size represents connection count (last 24h). Click segments to drill down."
                                ], className="text-muted small mt-2")
                            ])
                        ], className="glass-card border-0 shadow-sm")
                    ], className="p-3")
                ], label="Analytics", tab_id="device-analytics-tab"),

                # Import/Export Tab
                dbc.Tab([
                    html.Div([
                        dbc.Card([
                            dbc.CardBody([
                                html.H6([html.I(className="fa fa-file-export me-2 text-warning"), "Import & Export Devices"], className="mb-3"),

                                dbc.Row([
                                    dbc.Col([
                                        html.Label("Export Devices", className="fw-bold mb-2"),
                                        html.P("Download your device list for backup or migration.", className="text-muted small mb-3"),
                                        dbc.Select(
                                            id='export-format-select',
                                            options=[
                                                {'label': '📄 CSV Format', 'value': 'csv'},
                                                {'label': '📋 JSON Format', 'value': 'json'},
                                                {'label': '📕 PDF Report', 'value': 'pdf'},
                                                {'label': '📊 Excel Workbook', 'value': 'xlsx'}
                                            ],
                                            value='csv',
                                            className="mb-3"
                                        ),
                                        dbc.Button([
                                            html.I(className="fa fa-download me-2"),
                                            "Export Devices"
                                        ], id='export-devices-btn', color="primary", className="w-100")
                                    ], md=6),
                                    dbc.Col([
                                        html.Label("Import Devices", className="fw-bold mb-2 text-cyber"),
                                        html.P("Upload a device list from CSV or JSON file.", className="text-muted small mb-2"),
                                        dcc.Upload(
                                            id='import-devices-upload',
                                            children=html.Div([
                                                html.I(className="fa fa-cloud-upload-alt fa-3x mb-2 text-info"),
                                                html.Br(),
                                                html.Span("Drag & Drop or ", className="text-muted"),
                                                html.Span("Click to Upload", className="text-info fw-bold"),
                                                html.Br(),
                                                html.Small("Supports CSV & JSON files", className="text-muted")
                                            ], className="text-center py-4"),
                                            className="border border-info border-dashed rounded p-3",
                                            style={
                                                'cursor': 'pointer',
                                                'background': 'rgba(0, 255, 255, 0.05)',
                                                'transition': 'all 0.3s ease'
                                            }
                                        ),
                                        html.Div(id='import-status', className="mt-2")
                                    ], md=6)
                                ])
                            ])
                        ], className="glass-card border-0 shadow-sm")
                    ], className="p-3")
                ], label="Import/Export", tab_id="import-export-tab")

            ], id="device-mgmt-tabs", active_tab="devices-list-tab")
        ]),
        dbc.ModalFooter([
            html.Div(id='device-mgmt-timestamp-display', className="me-auto text-muted small"),
            dbc.Button([
                html.I(className="fa fa-sync-alt me-2"),
                "Refresh All"
            ], id="refresh-device-mgmt-btn", color="info", outline=True, size="sm", className="me-2 modal-refresh-btn"),
            dbc.Button([
                html.I(className="fa fa-times me-2"),
                "Close"
            ], id='close-device-modal-btn', color="secondary", size="sm", className="modal-close-btn")
        ], className="border-top pt-3"),
        dcc.Store(id='device-mgmt-timestamp-store')
    ], id="device-mgmt-modal", size="xl", is_open=False, scrollable=True),

    # Dashboard Preferences Modal - Enhanced
    dbc.Modal([
        dbc.ModalHeader(dbc.ModalTitle([
            html.I(className="fa fa-sliders-h me-2 text-primary"),
            "Dashboard Preferences"
        ])),
        dbc.ModalBody([
            dbc.Tabs([
                # Appearance Tab
                dbc.Tab([
                    html.Div([
                        dbc.Card([
                            dbc.CardBody([
                                html.H6([html.I(className="fa fa-palette me-2"), "Theme & Appearance"], className="mb-3"),

                                dbc.Label("Color Theme", className="fw-bold"),
                                dbc.RadioItems(
                                    id='theme-dropdown',
                                    options=[
                                        {'label': html.Span([html.I(className="fa fa-sun me-2 text-warning"), "Light Mode - Bright & clean"], className="d-flex align-items-center"), 'value': 'light'},
                                        {'label': html.Span([html.I(className="fa fa-moon me-2 text-primary"), "Dark Mode - Easy on eyes"], className="d-flex align-items-center"), 'value': 'dark'},
                                        {'label': html.Span([html.I(className="fa fa-adjust me-2 text-info"), "Auto - Follows system"], className="d-flex align-items-center"), 'value': 'auto'}
                                    ],
                                    value='light',
                                    className="mb-3"
                                ),

                                html.Hr(),

                                html.H6([html.I(className="fa fa-th me-2"), "Layout Settings"], className="mb-3"),

                                dbc.Label("Display Density", className="fw-bold"),
                                dbc.Select(
                                    id='display-density-dropdown',
                                    options=[
                                        {'label': '🎯 Compact - More data per screen', 'value': 'compact'},
                                        {'label': '✨ Comfortable - Balanced view (Default)', 'value': 'comfortable'},
                                        {'label': '🌟 Spacious - Easier reading, more whitespace', 'value': 'spacious'}
                                    ],
                                    value='comfortable',
                                    className="mb-3"
                                ),

                                dbc.Label("Dashboard Layout Style", className="fw-bold"),
                                dbc.Select(
                                    id='layout-dropdown',
                                    options=[
                                        {'label': '📊 Grid View - Cards arranged in grid (Default)', 'value': 'grid'},
                                        {'label': '📋 List View - Vertical list layout', 'value': 'list'},
                                        {'label': '🎨 Custom - Drag & drop positioning', 'value': 'custom'}
                                    ],
                                    value='grid',
                                    className="mb-3"
                                ),
                            ])
                        ], className="glass-card border-0 shadow-sm mb-3"),
                    ], className="p-3")
                ], label="Appearance", tab_id="appearance-tab"),

                # Performance Tab
                dbc.Tab([
                    html.Div([
                        dbc.Card([
                            dbc.CardBody([
                                html.H6([html.I(className="fa fa-tachometer-alt me-2"), "Performance & Data"], className="mb-3"),

                                dbc.Label("Auto-Refresh", className="fw-bold"),
                                dbc.Select(
                                    id='refresh-interval-dropdown',
                                    options=[
                                        {'label': '⚡ 5 seconds - Real-time (Higher CPU usage)', 'value': 5000},
                                        {'label': '✅ 10 seconds - Recommended balance', 'value': 10000},
                                        {'label': '💤 30 seconds - Light (Lower CPU usage)', 'value': 30000},
                                        {'label': '🐌 1 minute - Minimal (Manual refresh preferred)', 'value': 60000}
                                    ],
                                    value=10000,
                                    className="mb-3"
                                ),
                                html.Small("Lower intervals provide real-time updates but use more CPU and bandwidth.", className="text-muted d-block mb-3"),

                                dbc.Label("Data Retention Period", className="fw-bold"),
                                dbc.Select(
                                    id='retention-dropdown',
                                    options=[
                                        {'label': '7 days - Recent data only, minimal storage', 'value': 7},
                                        {'label': '30 days - Recommended for most users', 'value': 30},
                                        {'label': '90 days - Extended history & trends', 'value': 90},
                                        {'label': '180 days - Long-term forensic analysis', 'value': 180}
                                    ],
                                    value=30,
                                    className="mb-3"
                                ),
                                html.Small("Longer retention requires more storage but enables better trend analysis.", className="text-muted d-block mb-3"),

                                html.Hr(),

                                html.H6([html.I(className="fa fa-brain me-2"), "AI & Detection"], className="mb-3"),

                                dbc.Label("Anomaly Detection Sensitivity", className="fw-bold"),
                                dcc.Slider(
                                    id='anomaly-threshold-slider',
                                    min=0.5, max=0.99, step=0.01, value=0.85,
                                    marks={
                                        0.5: {'label': 'High', 'style': {'fontSize': '0.75rem'}},
                                        0.7: {'label': 'Balanced', 'style': {'fontSize': '0.75rem'}},
                                        0.85: {'label': 'Default', 'style': {'fontSize': '0.75rem', 'fontWeight': 'bold'}},
                                        0.99: {'label': 'Low', 'style': {'fontSize': '0.75rem'}}
                                    },
                                    tooltip={"placement": "bottom", "always_visible": True},
                                    className="mb-2"
                                ),
                                html.Small("Higher values = fewer but more confident alerts. Lower values = more sensitive detection.", className="text-muted d-block mb-3"),
                            ])
                        ], className="glass-card border-0 shadow-sm mb-3"),
                    ], className="p-3")
                ], label="Performance", tab_id="performance-tab"),

                # Localization Tab
                dbc.Tab([
                    html.Div([
                        dbc.Card([
                            dbc.CardBody([
                                html.H6([html.I(className="fa fa-globe-americas me-2"), "Regional Settings"], className="mb-3"),

                                dbc.Label("Interface Language", className="fw-bold"),
                                dbc.Select(
                                    id='language-dropdown',
                                    options=[
                                        {'label': '🇺🇸 English', 'value': 'en'},
                                        {'label': '🇪🇸 Español (Spanish)', 'value': 'es'},
                                        {'label': '🇫🇷 Français (French)', 'value': 'fr'},
                                        {'label': '🇩🇪 Deutsch (German)', 'value': 'de'},
                                        {'label': '🇮🇳 हिंदी (Hindi)', 'value': 'hi'},
                                        {'label': '🇨🇳 中文 (Chinese)', 'value': 'zh'},
                                        {'label': '🇯🇵 日本語 (Japanese)', 'value': 'ja'},
                                        {'label': '🇰🇷 한국어 (Korean)', 'value': 'ko'},
                                        {'label': '🇷🇺 Русский (Russian)', 'value': 'ru'},
                                        {'label': '🇵🇹 Português (Portuguese)', 'value': 'pt'}
                                    ],
                                    value='en',
                                    className="mb-3"
                                ),

                                dbc.Label("Timezone", className="fw-bold"),
                                dbc.Select(
                                    id='timezone-dropdown',
                                    options=[
                                        {'label': 'UTC - Coordinated Universal Time', 'value': 'UTC'},
                                        {'label': '🇺🇸 America/New_York (EST/EDT)', 'value': 'America/New_York'},
                                        {'label': '🇺🇸 America/Chicago (CST/CDT)', 'value': 'America/Chicago'},
                                        {'label': '🇺🇸 America/Denver (MST/MDT)', 'value': 'America/Denver'},
                                        {'label': '🇺🇸 America/Los_Angeles (PST/PDT)', 'value': 'America/Los_Angeles'},
                                        {'label': '🇬🇧 Europe/London (GMT/BST)', 'value': 'Europe/London'},
                                        {'label': '🇫🇷 Europe/Paris (CET/CEST)', 'value': 'Europe/Paris'},
                                        {'label': '🇩🇪 Europe/Berlin (CET/CEST)', 'value': 'Europe/Berlin'},
                                        {'label': '🇯🇵 Asia/Tokyo (JST)', 'value': 'Asia/Tokyo'},
                                        {'label': '🇮🇳 Asia/Kolkata (IST)', 'value': 'Asia/Kolkata'},
                                        {'label': '🇨🇳 Asia/Shanghai (CST)', 'value': 'Asia/Shanghai'},
                                        {'label': '🇦🇺 Australia/Sydney (AEST/AEDT)', 'value': 'Australia/Sydney'}
                                    ],
                                    value='UTC',
                                    className="mb-3"
                                ),
                                html.Small("All timestamps will be displayed in the selected timezone.", className="text-muted d-block"),
                            ])
                        ], className="glass-card border-0 shadow-sm mb-3"),
                    ], className="p-3")
                ], label="Localization", tab_id="localization-tab"),

                # Alerts & Notifications Tab
                dbc.Tab([
                    html.Div([
                        dbc.Card([
                            dbc.CardBody([
                                html.H6([html.I(className="fa fa-bell me-2"), "Notification Preferences"], className="mb-3"),

                                dbc.Label("Enable Notifications For:", className="fw-bold mb-2"),
                                dbc.Checklist(
                                    id='alert-notification-prefs',
                                    options=[
                                        {'label': html.Span([html.I(className="fa fa-exclamation-triangle text-danger me-2"), "Critical Threats - Immediate action required"], className="d-flex align-items-center"), 'value': 'critical'},
                                        {'label': html.Span([html.I(className="fa fa-exclamation-circle text-warning me-2"), "High Priority Alerts - Important security events"], className="d-flex align-items-center"), 'value': 'high'},
                                        {'label': html.Span([html.I(className="fa fa-info-circle text-info me-2"), "Medium Priority Alerts - Notable events"], className="d-flex align-items-center"), 'value': 'medium'},
                                        {'label': html.Span([html.I(className="fa fa-cog text-secondary me-2"), "System Events - Status changes"], className="d-flex align-items-center"), 'value': 'system'},
                                        {'label': html.Span([html.I(className="fa fa-network-wired text-primary me-2"), "Device Status Changes - New/disconnected devices"], className="d-flex align-items-center"), 'value': 'device'}
                                    ],
                                    value=['critical', 'high'],
                                    switch=True,
                                    className="mb-3"
                                ),
                            ])
                        ], className="glass-card border-0 shadow-sm mb-3"),
                    ], className="p-3")
                ], label="Alerts", tab_id="alerts-tab"),

                # Backup & Export Tab
                dbc.Tab([
                    html.Div([
                        dbc.Card([
                            dbc.CardBody([
                                html.H6([html.I(className="fa fa-cloud-download-alt me-2"), "Automated Export"], className="mb-3"),

                                dbc.Label("Export Schedule", className="fw-bold"),
                                dbc.Select(
                                    id='auto-export-dropdown',
                                    options=[
                                        {'label': '🚫 Disabled - Manual export only', 'value': 'disabled'},
                                        {'label': '📅 Daily Reports - Export every day', 'value': 'daily'},
                                        {'label': '📆 Weekly Summary - Export every week', 'value': 'weekly'},
                                        {'label': '🗓️ Monthly Analysis - Export monthly', 'value': 'monthly'}
                                    ],
                                    value='disabled',
                                    className="mb-4"
                                ),

                                html.Hr(),

                                html.H6([html.I(className="fa fa-database me-2"), "Backup Settings"], className="mb-3"),

                                dbc.Label("Backup Schedule", className="fw-bold"),
                                dbc.Select(
                                    id='backup-schedule-dropdown',
                                    options=[
                                        {'label': '🔵 Daily - Recommended for production', 'value': 'daily'},
                                        {'label': '🟢 Weekly - Balanced approach', 'value': 'weekly'},
                                        {'label': '🟡 Monthly - Minimal backups', 'value': 'monthly'},
                                        {'label': '🔴 Manual Only - No automatic backups', 'value': 'manual'}
                                    ],
                                    value='daily',
                                    className="mb-3"
                                ),

                                dbc.Label("Backup Retention Period", className="fw-bold"),
                                dbc.Input(
                                    id='backup-retention-input',
                                    type='number',
                                    min=7,
                                    max=365,
                                    value=30,
                                    className="mb-2"
                                ),
                                html.Small("Number of days to keep backup files before automatic deletion. Minimum 7 days, maximum 365 days.", className="text-muted d-block"),
                            ])
                        ], className="glass-card border-0 shadow-sm mb-3"),
                    ], className="p-3")
                ], label="Backup & Export", tab_id="backup-tab"),

            ], id="preferences-tabs", active_tab="appearance-tab"),

            html.Div(id='preferences-status', className="mt-3"),

            html.Hr(),

            # Action Buttons
            dbc.Row([
                dbc.Col([
                    dbc.Button(
                        [html.I(className="fa fa-times me-2"), "Cancel"],
                        id='cancel-preferences-btn',
                        color="secondary",
                        outline=True,
                        className="w-100"
                    )
                ], width=6),
                dbc.Col([
                    dbc.Button(
                        [html.I(className="fa fa-save me-2"), "Save All Preferences"],
                        id='save-preferences-btn',
                        color="primary",
                        className="w-100"
                    )
                ], width=6)
            ])
        ], style={"maxHeight": "70vh", "overflowY": "auto"})
    ], id="preferences-modal", size="lg", is_open=False),

    # IoT Protocol Analysis Modal
    dbc.Modal([
        dbc.ModalHeader(dbc.ModalTitle([
            html.I(className="fa fa-network-wired me-2 text-info"),
            "IoT Protocol Analysis - MQTT, CoAP & Zigbee Traffic"
        ]), close_button=True),
        dbc.ModalBody([
            dbc.Tabs([
                # Overview Tab
                dbc.Tab([
                    dbc.Row([
                        dbc.Col([
                            dbc.Card([
                                dbc.CardBody([
                                    html.Div([
                                        html.I(className="fa fa-comment-dots fa-2x text-success mb-2")
                                    ]),
                                    html.H3(id="protocol-mqtt-count", className="mb-1"),
                                    html.P("MQTT Messages", className="text-muted mb-0", style={"fontSize": "0.85rem"})
                                ], className="text-center p-2")
                            ], className="glass-card border-0 shadow-sm mb-3")
                        ], md=3),
                        dbc.Col([
                            dbc.Card([
                                dbc.CardBody([
                                    html.Div([
                                        html.I(className="fa fa-exchange-alt fa-2x text-info mb-2")
                                    ]),
                                    html.H3(id="protocol-coap-count", className="mb-1"),
                                    html.P("CoAP Requests", className="text-muted mb-0", style={"fontSize": "0.85rem"})
                                ], className="text-center p-2")
                            ], className="glass-card border-0 shadow-sm mb-3")
                        ], md=3),
                        dbc.Col([
                            dbc.Card([
                                dbc.CardBody([
                                    html.Div([
                                        html.I(className="fa fa-wave-square fa-2x text-warning mb-2")
                                    ]),
                                    html.H3(id="protocol-zigbee-count", className="mb-1"),
                                    html.P("Zigbee Packets", className="text-muted mb-0", style={"fontSize": "0.85rem"})
                                ], className="text-center p-2")
                            ], className="glass-card border-0 shadow-sm mb-3")
                        ], md=3),
                        dbc.Col([
                            dbc.Card([
                                dbc.CardBody([
                                    html.Div([
                                        html.I(className="fa fa-server fa-2x text-primary mb-2")
                                    ]),
                                    html.H3(id="protocol-devices-count", className="mb-1"),
                                    html.P("Active Devices", className="text-muted mb-0", style={"fontSize": "0.85rem"})
                                ], className="text-center p-2")
                            ], className="glass-card border-0 shadow-sm mb-3")
                        ], md=3)
                    ], className="mb-3"),

                    html.Div(id="mqtt-coap-stats", className="mb-3"),

                    dbc.Row([
                        dbc.Col([
                            dbc.Card([
                                dbc.CardHeader([
                                    html.I(className="fa fa-chart-pie me-2"),
                                    "Protocol Distribution"
                                ], className="glass-card-header"),
                                dbc.CardBody([
                                    dcc.Graph(id='protocol-distribution-chart', config={'displayModeBar': False}, style={'height': '300px'})
                                ])
                            ], className="glass-card border-0 shadow-sm")
                        ], md=6),
                        dbc.Col([
                            dbc.Card([
                                dbc.CardHeader([
                                    html.I(className="fa fa-chart-line me-2"),
                                    "Protocol Activity Timeline (7 Days)"
                                ], className="glass-card-header"),
                                dbc.CardBody([
                                    dcc.Graph(id='protocol-timeline-chart', config={'displayModeBar': False}, style={'height': '300px'})
                                ])
                            ], className="glass-card border-0 shadow-sm")
                        ], md=6)
                    ])
                ], label="Overview", tab_id="protocol-overview-tab", className="p-3"),

                # MQTT Tab
                dbc.Tab([
                    dbc.Card([
                        dbc.CardHeader([
                            html.I(className="fa fa-comment-dots me-2"),
                            "MQTT Traffic Analysis"
                        ], className="glass-card-header"),

                        dbc.CardBody([
                            dbc.Row([
                                dbc.Col([
                                    dbc.Label("Time Range:", className="fw-bold mb-2"),
                                    dbc.Select(
                                        id='protocol-mqtt-time-range',
                                        options=[
                                            {"label": "Last Hour", "value": 1},
                                            {"label": "Last 24 Hours", "value": 24},
                                            {"label": "Last 7 Days", "value": 168}
                                        ],
                                        value=24,
                                        className="mb-3"
                                    )
                                ], md=4)
                            ]),
                            html.Div(id='protocol-mqtt-traffic')
                        ])
                    ], className="glass-card border-0 shadow-sm")
                ], label="MQTT", tab_id="protocol-mqtt-tab", className="p-3"),

                # CoAP Tab
                dbc.Tab([
                    dbc.Card([
                        dbc.CardHeader([
                            html.I(className="fa fa-exchange-alt me-2"),
                            "CoAP Traffic Analysis"
                        ], className="glass-card-header"),

                        dbc.CardBody([
                            dbc.Row([
                                dbc.Col([
                                    dbc.Label("Time Range:", className="fw-bold mb-2"),
                                    dbc.Select(
                                        id='protocol-coap-time-range',
                                        options=[
                                            {"label": "Last Hour", "value": 1},
                                            {"label": "Last 24 Hours", "value": 24},
                                            {"label": "Last 7 Days", "value": 168}
                                        ],
                                        value=24,
                                        className="mb-3"
                                    )
                                ], md=4)
                            ]),
                            html.Div(id='protocol-coap-traffic')
                        ])
                    ], className="glass-card border-0 shadow-sm")
                ], label="CoAP", tab_id="protocol-coap-tab", className="p-3"),

                # Device Protocol Summary Tab
                dbc.Tab([
                    dbc.Card([
                        dbc.CardHeader([
                            html.I(className="fa fa-list me-2"),
                            "Device Protocol Usage Summary"
                        ], className="glass-card-header"),
                        dbc.CardBody([
                            html.Div(id='protocol-device-summary'),
                            html.Hr(className="my-3"),
                            dbc.Row([
                                dbc.Col([
                                    html.Label("Export Data", className="fw-bold mb-2 text-cyber"),
                                    html.P("Download protocol analysis data in your preferred format.", className="text-muted small mb-2"),
                                    dbc.Select(
                                        id='export-format-protocol',
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
                                        "Export Protocol Data"
                                    ], id='export-protocol-csv-btn', color="primary", className="w-100")
                                ], md=6)
                            ])
                        ])
                    ], className="glass-card border-0 shadow-sm")
                ], label="Device Summary", tab_id="protocol-summary-tab", className="p-3")
            ], id="protocol-analysis-tabs", active_tab="protocol-overview-tab")
        ], style={"maxHeight": "70vh", "overflowY": "auto"}),
        dbc.ModalFooter([
            html.Div(id='protocol-timestamp-display', className="me-auto"),
            dbc.Button([
                html.I(className="fa fa-sync-alt me-2"),
                "Refresh"
            ], id="refresh-protocol-btn", color="info", outline=True, size="sm", className="me-2"),
            dbc.Button([
                html.I(className="fa fa-times me-2"),
                "Close"
            ], id="close-protocol-modal-btn", color="secondary", size="sm")
        ]),
        dcc.Store(id='protocol-timestamp-store'),
        dcc.Download(id='download-protocol-csv')
    ], id="protocol-modal", size="xl", is_open=False, scrollable=True),

    # Threat Intelligence Modal - Enhanced
    dbc.Modal([
        dbc.ModalHeader(dbc.ModalTitle([
            html.I(className="fa fa-shield-virus me-2 text-danger"),
            "IoT Threat Intelligence & Analysis"
        ]), close_button=True),
        dbc.ModalBody([
            dbc.Tabs([
                # Overview Tab
                dbc.Tab([
                    dbc.Row([
                        dbc.Col([
                            dbc.Card([
                                dbc.CardBody([
                                    html.Div([
                                        html.I(className="fa fa-exclamation-triangle fa-2x text-danger mb-2")
                                    ]),
                                    html.H3(id="threat-intel-active-threats", className="mb-1"),
                                    html.P("Active Threats", className="text-muted mb-0", style={"fontSize": "0.85rem"})
                                ], className="text-center p-2")
                            ], className="glass-card border-0 shadow-sm mb-3")
                        ], md=3),
                        dbc.Col([
                            dbc.Card([
                                dbc.CardBody([
                                    html.Div([
                                        html.I(className="fa fa-bug fa-2x text-warning mb-2")
                                    ]),
                                    html.H3(id="threat-intel-vulnerabilities", className="mb-1"),
                                    html.P("Vulnerabilities", className="text-muted mb-0", style={"fontSize": "0.85rem"})
                                ], className="text-center p-2")
                            ], className="glass-card border-0 shadow-sm mb-3")
                        ], md=3),
                        dbc.Col([
                            dbc.Card([
                                dbc.CardBody([
                                    html.Div([
                                        html.I(className="fa fa-ban fa-2x text-danger mb-2")
                                    ]),
                                    html.H3(id="threat-intel-blocked-devices", className="mb-1"),
                                    html.P("Blocked Devices", className="text-muted mb-0", style={"fontSize": "0.85rem"})
                                ], className="text-center p-2")
                            ], className="glass-card border-0 shadow-sm mb-3")
                        ], md=3),
                        dbc.Col([
                            dbc.Card([
                                dbc.CardBody([
                                    html.Div([
                                        html.I(className="fa fa-shield-alt fa-2x text-success mb-2")
                                    ]),
                                    html.H3(id="threat-intel-threat-level", className="mb-1"),
                                    html.P("Threat Level", className="text-muted mb-0", style={"fontSize": "0.85rem"})
                                ], className="text-center p-2")
                            ], className="glass-card border-0 shadow-sm mb-3")
                        ], md=3)
                    ], className="mb-3"),

                    html.Div(id="threat-detection-stats", className="mb-3"),

                    dbc.Row([
                        dbc.Col([
                            dbc.Card([
                                dbc.CardHeader([
                                    html.I(className="fa fa-chart-pie me-2"),
                                    "Threat Distribution"
                                ], className="glass-card-header"),
                                dbc.CardBody([
                                    dcc.Graph(id='threat-intel-distribution-chart', config={'displayModeBar': False}, style={'height': '300px'})
                                ])
                            ], className="glass-card border-0 shadow-sm")
                        ], md=6),
                        dbc.Col([
                            dbc.Card([
                                dbc.CardHeader([
                                    html.I(className="fa fa-clock me-2"),
                                    "Recent Threats"
                                ], className="glass-card-header"),
                                dbc.CardBody([
                                    html.Div(id='threat-intel-recent-threats', style={'maxHeight': '300px', 'overflowY': 'auto'})
                                ])
                            ], className="glass-card border-0 shadow-sm")
                        ], md=6)
                    ])
                ], label="Overview", tab_id="threat-intel-overview-tab", className="p-3"),

                # Threat Feed Tab
                dbc.Tab([
                    # Search and Filter Controls
                    dbc.Row([
                        dbc.Col([
                            dbc.InputGroup([
                                dbc.InputGroupText(html.I(className="fa fa-search")),
                                dbc.Input(
                                    id='threat-feed-search-input',
                                    type='text',
                                    placeholder="Search by IP address, botnet name, or malicious domain..."
                                )
                            ])
                        ], md=12)
                    ], className="mb-2"),
                    dbc.Row([
                        dbc.Col([
                            dbc.Select(
                                id='threat-feed-severity-filter',
                                options=[
                                    {'label': '🔍 All Severities', 'value': 'all'},
                                    {'label': '🔴 Critical', 'value': 'critical'},
                                    {'label': '🟠 High', 'value': 'high'},
                                    {'label': '🟡 Medium', 'value': 'medium'},
                                    {'label': '🟢 Low', 'value': 'low'}
                                ],
                                value='all'
                            )
                        ], md=4),
                        dbc.Col([
                            dbc.Select(
                                id='threat-feed-status-filter',
                                options=[
                                    {'label': '📊 All Status', 'value': 'all'},
                                    {'label': '🔴 Active', 'value': 'active'},
                                    {'label': '✅ Resolved', 'value': 'resolved'}
                                ],
                                value='all'
                            )
                        ], md=4),
                        dbc.Col([
                            dbc.Button([
                                html.I(className="fa fa-sync-alt me-2"),
                                "Refresh"
                            ], id='refresh-threat-feed-btn', color="primary", size="sm", className="w-100")
                        ], md=4)
                    ], className="mb-3"),

                    dbc.Card([
                        dbc.CardHeader([
                            html.I(className="fa fa-rss me-2"),
                            "Live Threat Intelligence Feed"
                        ], className="glass-card-header"),
                        dbc.CardBody([
                            html.Div(id='threat-intel-feed-list')
                        ])
                    ], className="glass-card border-0 shadow-sm")
                ], label="Threat Feed", tab_id="threat-intel-feed-tab", className="p-3"),

                # Attack Patterns Tab
                dbc.Tab([
                    dbc.Card([
                        dbc.CardHeader([
                            html.I(className="fa fa-chart-line me-2"),
                            "Attack Pattern Analysis"
                        ], className="glass-card-header"),
                        dbc.CardBody([
                            html.Div(id='threat-intel-attack-patterns')
                        ])
                    ], className="glass-card border-0 shadow-sm"),

                    # Attack Path Visualization (Kill Chain)
                    dbc.Card([
                        dbc.CardHeader([
                            html.I(className="fa fa-project-diagram me-2"),
                            "Attack Path & Kill Chain Visualization"
                        ], className="glass-card-header mt-3"),
                        dbc.CardBody([
                            dcc.Loading(
                                dcc.Graph(
                                    id='attack-path-sankey',
                                    config={
                                        'displayModeBar': True,
                                        'modeBarButtonsToRemove': ['pan2d', 'lasso2d', 'select2d'],
                                        'displaylogo': False
                                    },
                                    style={'height': '500px'}
                                ),
                                type='circle'
                            ),
                            html.P([
                                html.I(className="fa fa-info-circle me-2"),
                                "Interactive Sankey diagram showing attack progression through MITRE ATT&CK kill chain stages. "
                                "Link thickness represents alert frequency."
                            ], className="text-muted small mt-2")
                        ])
                    ], className="glass-card border-0 shadow-sm")
                ], label="Attack Patterns", tab_id="threat-intel-patterns-tab", className="p-3"),

                # Response Tab
                dbc.Tab([
                    dbc.Card([
                        dbc.CardHeader([
                            html.I(className="fa fa-tasks me-2"),
                            "Threat Response & Mitigation"
                        ], className="glass-card-header"),
                        dbc.CardBody([
                            html.Div(id='threat-intel-response-list')
                        ])
                    ], className="glass-card border-0 shadow-sm")
                ], label="Response", tab_id="threat-intel-response-tab", className="p-3")
            ], id="threat-intel-tabs", active_tab="threat-intel-overview-tab")
        ], style={"maxHeight": "70vh", "overflowY": "auto"}),
        dbc.ModalFooter([
            dbc.Button([
                html.I(className="fa fa-sync-alt me-2"),
                "Refresh"
            ], id="refresh-threat-intel-btn", color="info", outline=True, size="sm", className="me-2"),
            dbc.Button([
                html.I(className="fa fa-times me-2"),
                "Close"
            ], id="close-threat-intel-modal-btn", color="secondary", size="sm")
        ])
    ], id="threat-modal", size="xl", is_open=False, scrollable=True),

    # Device Timeline Visualization Modal
    dbc.Modal([
        dbc.ModalHeader(dbc.ModalTitle([
            html.I(className="fa fa-chart-network me-2"),
            "Device Activity Timeline"
        ])),
        dbc.ModalBody([
            dbc.Row([
                dbc.Col([
                    dbc.Label("Select Device"),
                    dcc.Dropdown(
                        id='timeline-device-dropdown',
                        placeholder="Choose a device...",
                        className="mb-3"
                    )
                ], md=6),
                dbc.Col([
                    dbc.Label("Time Range"),
                    dcc.Dropdown(
                        id='timeline-range-dropdown',
                        options=[
                            {'label': '📅 Last 24 Hours', 'value': 24},
                            {'label': '📆 Last 7 Days', 'value': 168},
                            {'label': '🗓️ Last 30 Days', 'value': 720}
                        ],
                        value=24,
                        className="mb-3"
                    )
                ], md=6)
            ]),

            html.Hr(),

            # Activity Timeline Graph
            dcc.Loading(
                dcc.Graph(id='device-activity-timeline'),
                type='circle'
            ),

            html.Hr(),

            # Connection Heatmap
            html.H5([html.I(className="fa fa-fire me-2"), "Activity Heatmap"], className="mt-3 mb-3"),
            dcc.Loading(
                dcc.Graph(id='device-activity-heatmap'),
                type='circle'
            ),

            html.Hr(),

            # Event Log Table
            html.H5([html.I(className="fa fa-list me-2"), "Activity Events"], className="mt-3 mb-3"),
            html.Div(id='timeline-events-table')
        ])
    ], id="timeline-modal", size="xl", is_open=False, scrollable=True),

    # Privacy Monitoring Modal - Enhanced with Tabs
    dbc.Modal([
        dbc.ModalHeader(dbc.ModalTitle([
            html.I(className="fa fa-user-shield me-2 text-primary"),
            "Privacy Monitoring"
        ]), close_button=True),
        dbc.ModalBody([
            dbc.Tabs([
                # Privacy Score Tab
                dbc.Tab([
                    html.Div([
                        dbc.Card([
                            dbc.CardBody([
                                html.H6([html.I(className="fa fa-user-shield me-2 text-success"), "Privacy Score Overview"], className="mb-3"),

                                # Privacy Score Gauge - Dynamic
                                dbc.Row([
                                    dbc.Col([
                                        html.Div([
                                            html.Div([
                                                html.Span(id='privacy-modal-score-value', className="display-3 fw-bold"),
                                                html.Span("/100", className="h4 text-muted")
                                            ], className="text-center mb-2"),
                                            dbc.Progress(id='privacy-modal-score-bar', value=0, className="mb-2", style={"height": "12px"}),
                                            html.P(id='privacy-modal-score-status', className="text-center fw-bold")
                                        ])
                                    ], md=6, className="border-end"),
                                    dbc.Col([
                                        html.Div([
                                            html.H6("Score Breakdown", className="mb-3"),
                                            html.Div(id='privacy-modal-breakdown')
                                        ])
                                    ], md=6)
                                ], className="mb-4"),

                                html.Hr(),

                                html.H6([html.I(className="fa fa-lightbulb me-2 text-warning"), "Recommendations"], className="mb-3"),
                                html.Div(id='privacy-modal-recommendations')
                            ])
                        ], className="glass-card border-0 shadow-sm"),

                        html.Div(id='privacy-score-section', className="mt-3")
                    ], className="p-3")
                ], label="Privacy Score", tab_id="privacy-score-tab"),

                # Cloud Uploads Tab
                dbc.Tab([
                    html.Div([
                        dbc.Card([
                            dbc.CardBody([
                                html.H6([html.I(className="fa fa-cloud-upload-alt me-2 text-info"), "Cloud Data Uploads"], className="mb-3"),

                                html.P("Monitor data being sent to cloud services by your IoT devices.", className="text-muted small mb-3"),

                                # Stats Row - Dynamic
                                dbc.Row([
                                    dbc.Col([
                                        dbc.Card([
                                            dbc.CardBody([
                                                html.I(className="fa fa-upload fa-2x text-primary mb-2"),
                                                html.H4(id='cloud-upload-total', className="mb-0"),
                                                html.Small("Total Uploaded Today", className="text-muted")
                                            ], className="text-center py-2")
                                        ], className="border-0 bg-light")
                                    ], md=4),
                                    dbc.Col([
                                        dbc.Card([
                                            dbc.CardBody([
                                                html.I(className="fa fa-server fa-2x text-success mb-2"),
                                                html.H4(id='cloud-services-count', className="mb-0"),
                                                html.Small("Cloud Services Used", className="text-muted")
                                            ], className="text-center py-2")
                                        ], className="border-0 bg-light")
                                    ], md=4),
                                    dbc.Col([
                                        dbc.Card([
                                            dbc.CardBody([
                                                html.I(className="fa fa-exclamation-triangle fa-2x text-warning mb-2"),
                                                html.H4(id='suspicious-uploads-count', className="mb-0"),
                                                html.Small("Suspicious Uploads", className="text-muted")
                                            ], className="text-center py-2")
                                        ], className="border-0 bg-light")
                                    ], md=4)
                                ], className="mb-4"),

                                html.H6("Recent Cloud Connections", className="mb-3"),
                                html.Div(id='cloud-uploads-section')
                            ])
                        ], className="glass-card border-0 shadow-sm")
                    ], className="p-3")
                ], label="Cloud Uploads", tab_id="cloud-uploads-tab"),

                # Tracker Detection Tab
                dbc.Tab([
                    html.Div([
                        # Search and Filter Controls
                        dbc.Row([
                            dbc.Col([
                                dbc.InputGroup([
                                    dbc.InputGroupText(html.I(className="fa fa-search")),
                                    dbc.Input(
                                        id='tracker-search-input',
                                        type='text',
                                        placeholder="Search by cloud domain, tracker company, or device IP..."
                                    )
                                ])
                            ], md=12)
                        ], className="mb-2"),
                        dbc.Row([
                            dbc.Col([
                                dbc.Select(
                                    id='privacy-concern-filter',
                                    options=[
                                        {'label': '🔍 All Privacy Levels', 'value': 'all'},
                                        {'label': '🔴 Critical', 'value': 'critical'},
                                        {'label': '🟠 High', 'value': 'high'},
                                        {'label': '🟡 Medium', 'value': 'medium'},
                                        {'label': '🟢 Low', 'value': 'low'}
                                    ],
                                    value='all'
                                )
                            ], md=8),
                            dbc.Col([
                                dbc.Button([
                                    html.I(className="fa fa-sync-alt me-2"),
                                    "Refresh"
                                ], id='refresh-tracker-btn', color="primary", size="sm", className="w-100")
                            ], md=4)
                        ], className="mb-3"),

                        dbc.Card([
                            dbc.CardBody([
                                html.H6([html.I(className="fa fa-eye-slash me-2 text-danger"), "Tracker Detection"], className="mb-3"),

                                html.P("Identify and block tracking services attempting to collect your data.", className="text-muted small mb-3"),

                                # Tracker Stats - Dynamic
                                dbc.Row([
                                    dbc.Col([
                                        html.Div([
                                            html.Span(id='trackers-detected-count', className="display-4 fw-bold text-danger"),
                                            html.P("Trackers Detected", className="text-muted mb-0")
                                        ], className="text-center")
                                    ], md=4),
                                    dbc.Col([
                                        html.Div([
                                            html.Span(id='trackers-blocked-count', className="display-4 fw-bold text-success"),
                                            html.P("Trackers Blocked", className="text-muted mb-0")
                                        ], className="text-center")
                                    ], md=4),
                                    dbc.Col([
                                        html.Div([
                                            html.Span(id='trackers-pending-count', className="display-4 fw-bold text-warning"),
                                            html.P("Pending Review", className="text-muted mb-0")
                                        ], className="text-center")
                                    ], md=4)
                                ], className="mb-4 py-3 bg-light rounded"),

                                html.H6("Tracker Categories", className="mb-3"),
                                html.Div(id='tracker-categories-list'),

                                dbc.Button([
                                    html.I(className="fa fa-ban me-2"),
                                    "Block All Pending Trackers"
                                ], id='block-all-trackers-btn', color="danger", className="me-2"),
                                dbc.Button([
                                    html.I(className="fa fa-list me-2"),
                                    "View Detailed Log"
                                ], id='view-tracker-log-btn', color="secondary", outline=True)
                            ])
                        ], className="glass-card border-0 shadow-sm"),

                        html.Div(id='tracker-detection-section', className="mt-3")
                    ], className="p-3")
                ], label="Trackers", tab_id="tracker-detection-tab"),

                # Data Flow Tab
                dbc.Tab([
                    html.Div([
                        dbc.Card([
                            dbc.CardBody([
                                html.H6([html.I(className="fa fa-exchange-alt me-2 text-purple"), "Data Flow Analysis"], className="mb-3"),

                                html.P("Visualize how data flows from your devices to external services.", className="text-muted small mb-3"),

                                # Data Flow Summary - Dynamic
                                dbc.Row([
                                    dbc.Col([
                                        html.Label("Inbound Data", className="small text-muted"),
                                        html.H5(id='dataflow-inbound-total', className="text-primary mb-0"),
                                        dbc.Progress(id='dataflow-inbound-bar', value=0, color="primary", className="mt-2", style={"height": "6px"})
                                    ], md=6),
                                    dbc.Col([
                                        html.Label("Outbound Data", className="small text-muted"),
                                        html.H5(id='dataflow-outbound-total', className="text-danger mb-0"),
                                        dbc.Progress(id='dataflow-outbound-bar', value=0, color="danger", className="mt-2", style={"height": "6px"})
                                    ], md=6)
                                ], className="mb-4"),

                                html.H6("Top Data Destinations", className="mb-3"),
                                html.Div(id='dataflow-destinations-list')
                            ])
                        ], className="glass-card border-0 shadow-sm")
                    ], className="p-3")
                ], label="Data Flow", tab_id="data-flow-tab"),

                # Device Privacy Tab
                dbc.Tab([
                    html.Div([
                        dbc.Card([
                            dbc.CardBody([
                                html.H6([html.I(className="fa fa-user-shield me-2 text-purple"), "Device Privacy Analysis"], className="mb-3"),

                                html.P("Analyze what data your devices collect and where it goes.", className="text-muted small mb-3"),

                                # Summary Cards
                                html.Div(id="privacy-summary-cards", className="mb-4"),

                                # Device Privacy Table
                                html.H6("Device Privacy Analysis", className="mb-3"),
                                html.Div(id="privacy-devices-table"),

                                html.Hr(className="my-4"),

                                # Export Section
                                dbc.Row([
                                    dbc.Col([
                                        html.Label("Export Privacy Report:", className="fw-bold mb-2"),
                                        dbc.Select(
                                            id='export-format-privacy',
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
                                            "Export Privacy Report"
                                        ], id='export-privacy-report-btn', color="primary", className="w-100")
                                    ], md=6)
                                ], className="mb-3")
                            ])
                        ], className="glass-card border-0 shadow-sm")
                    ], className="p-3")
                ], label="Device Privacy", tab_id="device-privacy-tab")

            ], id="privacy-modal-tabs", active_tab="privacy-score-tab")
        ]),
        dbc.ModalFooter([
            html.Small(id="privacy-last-updated", children="Last updated: Never", className="text-muted me-auto"),
            dbc.Button([
                html.I(className="fa fa-sync-alt me-2"),
                "Refresh"
            ], id="privacy-refresh-btn", size="sm", color="primary", outline=True, className="me-2"),
            dbc.Button("Close", id='close-privacy-modal-btn', color="secondary")
        ])
    ], id="privacy-modal", size="xl", is_open=False, scrollable=True),

    # Smart Home Context Modal - Enhanced with Tabs
    dbc.Modal([
        dbc.ModalHeader(dbc.ModalTitle([
            html.I(className="fa fa-house-signal me-2 text-primary"),
            "Smart Home Context"
        ]), close_button=True),
        dbc.ModalBody([
            dbc.Tabs([
                # Hub Detection Tab
                dbc.Tab([
                    html.Div([
                        dbc.Card([
                            dbc.CardBody([
                                html.H6([html.I(className="fa fa-broadcast-tower me-2 text-success"), "Detected Smart Home Hubs"], className="mb-3"),

                                html.P("Central hubs that control your smart home devices.", className="text-muted small mb-3"),

                                # Detected Hubs - Dynamic
                                html.Div(id='smarthome-hubs-list')
                            ])
                        ], className="glass-card border-0 shadow-sm"),

                        html.Div(id='hub-detection-section', className="mt-3"),

                        html.Hr(className="my-3"),
                        dbc.Card([
                            dbc.CardBody([
                                dbc.Row([
                                    dbc.Col([
                                        html.Label("Export Data", className="fw-bold mb-2 text-cyber"),
                                        html.P("Download smart home device data in your preferred format.", className="text-muted small mb-2"),
                                        dbc.Select(
                                            id='export-format-smarthome',
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
                                            "Export Smart Home Data"
                                        ], id='export-smarthome-csv-btn', color="primary", className="w-100")
                                    ], md=6)
                                ])
                            ])
                        ], className="glass-card border-0 shadow-sm")
                    ], className="p-3")
                ], label="Hubs", tab_id="hub-detection-tab"),

                # Ecosystems Tab
                dbc.Tab([
                    html.Div([
                        dbc.Card([
                            dbc.CardBody([
                                html.H6([html.I(className="fa fa-sitemap me-2 text-info"), "Device Ecosystems"], className="mb-3"),

                                html.P("Group your devices by manufacturer ecosystem.", className="text-muted small mb-3"),

                                # Ecosystem Cards - Dynamic
                                html.Div(id='smarthome-ecosystems-list')
                            ])
                        ], className="glass-card border-0 shadow-sm"),

                        html.Div(id='ecosystem-section', className="mt-3")
                    ], className="p-3")
                ], label="Ecosystems", tab_id="ecosystem-tab"),

                # Room Mapping Tab
                dbc.Tab([
                    html.Div([
                        dbc.Card([
                            dbc.CardBody([
                                html.H6([html.I(className="fa fa-map-marker-alt me-2 text-success"), "Room Mapping"], className="mb-3"),

                                html.P("Organize devices by their physical location in your home.", className="text-muted small mb-3"),

                                # Room Cards - Dynamic
                                html.Div(id='smarthome-rooms-list')
                            ])
                        ], className="glass-card border-0 shadow-sm"),

                        html.Div(id='room-section', className="mt-3")
                    ], className="p-3")
                ], label="Rooms", tab_id="room-mapping-tab"),

                # Automations Tab
                dbc.Tab([
                    html.Div([
                        dbc.Card([
                            dbc.CardBody([
                                html.H6([html.I(className="fa fa-magic me-2 text-purple"), "Smart Automations"], className="mb-3"),

                                html.P("View and manage automated routines detected in your smart home.", className="text-muted small mb-3"),

                                # Automation List - Dynamic
                                html.Div(id='smarthome-automations-list'),

                                dbc.Button([
                                    html.I(className="fa fa-plus me-2"),
                                    "Create Automation"
                                ], id='create-automation-btn', color="primary", outline=True, className="mt-3")
                            ])
                        ], className="glass-card border-0 shadow-sm")
                    ], className="p-3")
                ], label="Automations", tab_id="automations-tab")

            ], id="smarthome-modal-tabs", active_tab="hub-detection-tab")
        ]),
        dbc.ModalFooter([
            html.Div(id='smarthome-timestamp-display', className="me-auto"),
            dbc.Button([
                html.I(className="fa fa-sync-alt me-2"),
                "Refresh"
            ], id='refresh-smarthome-btn', color="info", outline=True, size="sm", className="me-2"),
            dbc.Button([
                html.I(className="fa fa-times me-2"),
                "Close"
            ], id='close-smarthome-modal-btn', color="secondary", outline=True, size="sm")
        ]),
        dcc.Store(id='smarthome-timestamp-store'),
        dcc.Download(id='download-smarthome-csv')
    ], id="smarthome-modal", size="xl", is_open=False, scrollable=True),

    # Network Segmentation Modal - Enhanced with Tabs
    dbc.Modal([
        dbc.ModalHeader(dbc.ModalTitle([
            html.I(className="fa fa-layer-group me-2 text-primary"),
            "Network Segmentation - VLAN & Isolation Management"
        ]), close_button=True),
        dbc.ModalBody([
            dbc.Tabs([
                # Overview Tab
                dbc.Tab([
                    html.Div([
                        dbc.Card([
                            dbc.CardBody([
                                html.H6([html.I(className="fa fa-chart-pie me-2 text-success"), "Segmentation Overview"], className="mb-3"),

                                # Segmentation Stats
                                dbc.Row([
                                    dbc.Col([
                                        dbc.Card([
                                            dbc.CardBody([
                                                html.I(className="fa fa-check-circle fa-2x text-success mb-2"),
                                                html.H3(id='seg-total-segments', className="mb-0"),
                                                html.Small("Total Segments", className="text-muted")
                                            ], className="text-center py-3")
                                        ], className="border-0 bg-light")
                                    ], md=3),
                                    dbc.Col([
                                        dbc.Card([
                                            dbc.CardBody([
                                                html.I(className="fa fa-shield-alt fa-2x text-info mb-2"),
                                                html.H3(id='seg-segmented-devices', className="mb-0"),
                                                html.Small("Segmented Devices", className="text-muted")
                                            ], className="text-center py-3")
                                        ], className="border-0 bg-light")
                                    ], md=3),
                                    dbc.Col([
                                        dbc.Card([
                                            dbc.CardBody([
                                                html.I(className="fa fa-exclamation-triangle fa-2x text-warning mb-2"),
                                                html.H3(id='seg-unsegmented-devices', className="mb-0"),
                                                html.Small("Unsegmented", className="text-muted")
                                            ], className="text-center py-3")
                                        ], className="border-0 bg-light")
                                    ], md=3),
                                    dbc.Col([
                                        dbc.Card([
                                            dbc.CardBody([
                                                html.I(className="fa fa-ban fa-2x text-danger mb-2"),
                                                html.H3(id='seg-violations-24h', className="mb-0"),
                                                html.Small("Violations (24h)", className="text-muted")
                                            ], className="text-center py-3")
                                        ], className="border-0 bg-light")
                                    ], md=3)
                                ], className="mb-4"),

                                # Segmentation Coverage Chart
                                html.H6("Segmentation Coverage", className="mb-3"),
                                dcc.Graph(id='segmentation-coverage-chart', config={'displayModeBar': False})
                            ])
                        ], className="glass-card border-0 shadow-sm")
                    ], className="p-3")
                ], label="Overview", tab_id="seg-overview-tab"),

                # Segments Tab
                dbc.Tab([
                    html.Div([
                        dbc.Card([
                            dbc.CardBody([
                                html.H6([html.I(className="fa fa-sitemap me-2 text-info"), "Network Segments"], className="mb-3"),

                                dbc.Alert([
                                    html.I(className="fa fa-info-circle me-2"),
                                    "Network segments isolate different types of devices to contain potential threats and limit lateral movement."
                                ], color="info", className="mb-3"),

                                html.Div(id='segments-list-table')
                            ])
                        ], className="glass-card border-0 shadow-sm")
                    ], className="p-3")
                ], label="Segments", tab_id="seg-segments-tab"),

                # Device Mapping Tab
                dbc.Tab([
                    html.Div([
                        dbc.Card([
                            dbc.CardBody([
                                html.H6([html.I(className="fa fa-map-marked-alt me-2 text-warning"), "Device-to-Segment Mapping"], className="mb-3"),

                                dbc.Row([
                                    dbc.Col([
                                        dbc.Label("Filter by Segment:", className="fw-bold"),
                                        dbc.Select(
                                            id='seg-filter-dropdown',
                                            placeholder="All Segments",
                                            className="mb-3"
                                        )
                                    ], md=6)
                                ]),

                                html.Div(id='device-segment-mapping-table')
                            ])
                        ], className="glass-card border-0 shadow-sm")
                    ], className="p-3")
                ], label="Device Mapping", tab_id="seg-mapping-tab"),

                # Violations Tab
                dbc.Tab([
                    html.Div([
                        dbc.Card([
                            dbc.CardBody([
                                html.H6([html.I(className="fa fa-ban me-2 text-danger"), "Segmentation Violations"], className="mb-3"),

                                dbc.Alert([
                                    html.I(className="fa fa-exclamation-triangle me-2"),
                                    "Violations occur when devices attempt to communicate across segment boundaries without authorization."
                                ], color="warning", className="mb-3"),

                                dbc.Row([
                                    dbc.Col([
                                        dbc.Label("Time Range:", className="fw-bold"),
                                        dbc.Select(
                                            id='seg-violations-timerange',
                                            options=[
                                                {'label': 'Last 24 Hours', 'value': 24},
                                                {'label': 'Last 7 Days', 'value': 168},
                                                {'label': 'Last 30 Days', 'value': 720}
                                            ],
                                            value=24,
                                            className="mb-3"
                                        )
                                    ], md=4)
                                ]),

                                html.Div(id='violations-timeline-chart'),
                                html.Div(id='violations-list-table', className="mt-3")
                            ])
                        ], className="glass-card border-0 shadow-sm")
                    ], className="p-3")
                ], label="Violations", tab_id="seg-violations-tab"),

                # Recommendations Tab
                dbc.Tab([
                    html.Div([
                        dbc.Card([
                            dbc.CardBody([
                                html.H6([html.I(className="fa fa-lightbulb me-2 text-success"), "VLAN Recommendations"], className="mb-3"),

                                dbc.Alert([
                                    html.I(className="fa fa-magic me-2"),
                                    "AI-powered recommendations for optimal network segmentation based on device types, risk profiles, and communication patterns."
                                ], color="success", className="mb-3"),

                                html.Div(id='vlan-recommendations')
                            ])
                        ], className="glass-card border-0 shadow-sm")
                    ], className="p-3")
                ], label="Recommendations", tab_id="seg-recommendations-tab")
            ], id="segmentation-tabs", active_tab="seg-overview-tab")
        ], style={"maxHeight": "70vh", "overflowY": "auto"}),
        dbc.ModalFooter([
            html.Div(id='segmentation-timestamp-display', className="me-auto"),
            dbc.Button([
                html.I(className="fa fa-sync-alt me-2"),
                "Refresh Data"
            ], id="refresh-segmentation-btn", color="info", outline=True, size="sm", className="me-2"),
            dbc.Button([
                html.I(className="fa fa-times me-2"),
                "Close"
            ], id="close-segmentation-modal-btn", color="secondary", size="sm")
        ]),
        dcc.Store(id='segmentation-timestamp-store')
    ], id="segmentation-modal", size="xl", is_open=False, scrollable=True),

    # Firmware Management Modal - Enhanced with Tabs
    dbc.Modal([
        dbc.ModalHeader(dbc.ModalTitle([
            html.I(className="fa fa-microchip me-2 text-primary"),
            "Firmware Management"
        ]), close_button=True),
        dbc.ModalBody([
            dbc.Tabs([
                # Firmware Status Tab
                dbc.Tab([
                    html.Div([
                        dbc.Card([
                            dbc.CardBody([
                                html.H6([html.I(className="fa fa-check-circle me-2 text-success"), "Firmware Status Overview"], className="mb-3"),

                                # Status Summary - Dynamic
                                dbc.Row([
                                    dbc.Col([
                                        dbc.Card([
                                            dbc.CardBody([
                                                html.I(className="fa fa-check fa-2x text-success mb-2"),
                                                html.H3(id='firmware-uptodate-count', className="mb-0"),
                                                html.Small("Up to Date", className="text-muted")
                                            ], className="text-center py-3")
                                        ], className="border-0 bg-light")
                                    ], md=3),
                                    dbc.Col([
                                        dbc.Card([
                                            dbc.CardBody([
                                                html.I(className="fa fa-arrow-up fa-2x text-warning mb-2"),
                                                html.H3(id='firmware-updates-count', className="mb-0"),
                                                html.Small("Updates Available", className="text-muted")
                                            ], className="text-center py-3")
                                        ], className="border-0 bg-light")
                                    ], md=3),
                                    dbc.Col([
                                        dbc.Card([
                                            dbc.CardBody([
                                                html.I(className="fa fa-exclamation-triangle fa-2x text-danger mb-2"),
                                                html.H3(id='firmware-critical-count', className="mb-0"),
                                                html.Small("Critical Updates", className="text-muted")
                                            ], className="text-center py-3")
                                        ], className="border-0 bg-light")
                                    ], md=3),
                                    dbc.Col([
                                        dbc.Card([
                                            dbc.CardBody([
                                                html.I(className="fa fa-question fa-2x text-secondary mb-2"),
                                                html.H3(id='firmware-unknown-count', className="mb-0"),
                                                html.Small("Unknown Version", className="text-muted")
                                            ], className="text-center py-3")
                                        ], className="border-0 bg-light")
                                    ], md=3)
                                ], className="mb-4"),

                                html.H6("Devices Needing Updates", className="mb-3"),
                                html.Div(id='firmware-status-section'),

                                html.Hr(className="my-3"),
                                dbc.Row([
                                    dbc.Col([
                                        html.Label("Export Data", className="fw-bold mb-2 text-cyber"),
                                        html.P("Download firmware status data in your preferred format.", className="text-muted small mb-2"),
                                        dbc.Select(
                                            id='export-format-firmware',
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
                                            "Export Firmware Data"
                                        ], id='export-firmware-csv-btn', color="primary", className="w-100")
                                    ], md=6)
                                ])
                            ])
                        ], className="glass-card border-0 shadow-sm")
                    ], className="p-3")
                ], label="Status", tab_id="firmware-status-tab"),

                # EOL Devices Tab
                dbc.Tab([
                    html.Div([
                        dbc.Card([
                            dbc.CardBody([
                                html.H6([html.I(className="fa fa-skull-crossbones me-2 text-danger"), "End-of-Life Devices"], className="mb-3"),

                                dbc.Alert([
                                    html.I(className="fa fa-exclamation-triangle me-2"),
                                    "These devices no longer receive security updates and pose a risk to your network."
                                ], color="danger", className="mb-4"),

                                # EOL Device Cards - Dynamic
                                html.Div(id='eol-devices-list'),

                                html.Div(id='eol-devices-section', className="mt-3")
                            ])
                        ], className="glass-card border-0 shadow-sm")
                    ], className="p-3")
                ], label="EOL Devices", tab_id="eol-devices-tab"),

                # Update Center Tab
                dbc.Tab([
                    html.Div([
                        dbc.Card([
                            dbc.CardBody([
                                html.H6([html.I(className="fa fa-download me-2 text-info"), "Update Center"], className="mb-3"),

                                html.P("Manage firmware updates for all your devices.", className="text-muted small mb-3"),

                                # Update Actions
                                dbc.Row([
                                    dbc.Col([
                                        dbc.Button([
                                            html.I(className="fa fa-sync-alt me-2"),
                                            "Check for Updates"
                                        ], id='check-firmware-updates-btn', color="primary", className="w-100 mb-2")
                                    ], md=6),
                                    dbc.Col([
                                        dbc.Button([
                                            html.I(className="fa fa-download me-2"),
                                            "Update All Devices"
                                        ], id='update-all-firmware-btn', color="success", className="w-100 mb-2")
                                    ], md=6)
                                ], className="mb-4"),

                                html.H6("Available Updates", className="mb-3"),
                                html.Div(id='firmware-updates-list'),

                                html.Div(id='provisioning-section', className="mt-3")
                            ])
                        ], className="glass-card border-0 shadow-sm")
                    ], className="p-3")
                ], label="Updates", tab_id="update-center-tab"),

                # Settings Tab
                dbc.Tab([
                    html.Div([
                        dbc.Card([
                            dbc.CardBody([
                                html.H6([html.I(className="fa fa-cog me-2 text-secondary"), "Update Settings"], className="mb-3"),

                                html.Div([
                                    html.Label("Auto-Update Policy", className="fw-bold mb-2"),
                                    dbc.RadioItems(
                                        id='auto-update-policy',
                                        options=[
                                            {'label': html.Span([html.I(className="fa fa-shield-alt me-2 text-danger"), "Security updates only - Install critical security patches automatically"]), 'value': 'security'},
                                            {'label': html.Span([html.I(className="fa fa-check-circle me-2 text-success"), "All updates - Install all available updates automatically"]), 'value': 'all'},
                                            {'label': html.Span([html.I(className="fa fa-hand-paper me-2 text-warning"), "Manual only - Never auto-update, notify me instead"]), 'value': 'manual'}
                                        ],
                                        value='security',
                                        className="mb-4"
                                    )
                                ]),

                                html.Hr(),

                                html.Div([
                                    html.Label("Update Schedule", className="fw-bold mb-2"),
                                    dbc.Select(
                                        id='update-schedule-select',
                                        options=[
                                            {'label': '🌙 Night (2:00 AM - 5:00 AM)', 'value': 'night'},
                                            {'label': '☀️ Morning (6:00 AM - 9:00 AM)', 'value': 'morning'},
                                            {'label': '🌆 Evening (8:00 PM - 11:00 PM)', 'value': 'evening'},
                                            {'label': '⚡ Immediate (As soon as available)', 'value': 'immediate'}
                                        ],
                                        value='night',
                                        className="mb-3"
                                    ),
                                    html.Small("Updates will be installed during this time window to minimize disruption.", className="text-muted d-block mb-4")
                                ]),

                                html.Hr(),

                                html.Div([
                                    html.Label("Notifications", className="fw-bold mb-2"),
                                    dbc.Checklist(
                                        id='firmware-notification-settings',
                                        options=[
                                            {'label': ' Email me when updates are available', 'value': 'email_available'},
                                            {'label': ' Email me when updates are installed', 'value': 'email_installed'},
                                            {'label': ' Alert for EOL device warnings', 'value': 'eol_warning'},
                                            {'label': ' Weekly firmware status report', 'value': 'weekly_report'}
                                        ],
                                        value=['email_available', 'eol_warning'],
                                        switch=True,
                                        className="mb-3"
                                    )
                                ]),

                                dbc.Button([
                                    html.I(className="fa fa-save me-2"),
                                    "Save Settings"
                                ], id='save-firmware-settings-btn', color="primary")
                            ])
                        ], className="glass-card border-0 shadow-sm")
                    ], className="p-3")
                ], label="Settings", tab_id="firmware-settings-tab")

            ], id="firmware-modal-tabs", active_tab="firmware-status-tab")
        ]),
        dbc.ModalFooter([
            html.Div(id='firmware-timestamp-display', className="me-auto"),
            dbc.Button([
                html.I(className="fa fa-sync-alt me-2"),
                "Refresh"
            ], id='refresh-firmware-btn', color="info", outline=True, size="sm", className="me-2"),
            dbc.Button([
                html.I(className="fa fa-times me-2"),
                "Close"
            ], id='close-firmware-modal-btn', color="secondary", outline=True, size="sm")
        ]),
        dcc.Store(id='firmware-timestamp-store'),
        dcc.Download(id='download-firmware-csv')
    ], id="firmware-modal", size="xl", is_open=False, scrollable=True),

    # EOL Device Replacement Modal
    dbc.Modal([
        dbc.ModalHeader(
            dbc.ModalTitle("Replace End-of-Life Device")
        ),

        dbc.ModalBody([
            html.P("Select a new device to replace the EOL device."),
            dbc.Select(
                id='replacement-device-dropdown',
                options=[],  # populate dynamically via callback
                placeholder="Select replacement device...",
                className="mb-2"
            ),
        ]),

        dbc.ModalFooter([
            dbc.Button("Cancel", id="cancel-replacement-btn", color="secondary"),
            dbc.Button(
                "Confirm",
                id="confirm-replacement-btn",
                color="primary",
                disabled=True
            ),
        ]),
    ], id="eol-replacement-modal", is_open=False),

    dcc.Store(id='eol-device-ip-store'),

    # Security Education Modal - Enhanced with Tabs
    dbc.Modal([
        dbc.ModalHeader(dbc.ModalTitle([
            html.I(className="fa fa-user-graduate me-2 text-success"),
            "Security Education & Resources"
        ]), close_button=True),
        dbc.ModalBody([
            dbc.Tabs([
                # Threat Scenarios Tab
                dbc.Tab([
                    html.Div([
                        dbc.Card([
                            dbc.CardBody([
                                html.H6([
                                    html.I(className="fa fa-shield-alt me-2 text-warning"),
                                    "Common IoT Threat Scenarios"
                                ], className="mb-3"),
                                html.Div(id='threat-scenarios-section')
                            ])
                        ], className="glass-card border-0 shadow-sm")
                    ], className="p-3")
                ], label="Threat Scenarios", tab_id="threat-scenarios-tab"),

                # Security Tips Tab
                dbc.Tab([
                    html.Div([
                        dbc.Card([
                            dbc.CardBody([
                                html.H6([
                                    html.I(className="fa fa-lightbulb me-2 text-info"),
                                    "IoT Security Best Practices"
                                ], className="mb-3"),
                                html.Div(id='security-tips-section')
                            ])
                        ], className="glass-card border-0 shadow-sm")
                    ], className="p-3")
                ], label="Security Tips", tab_id="security-tips-tab"),

                # Competitive Analysis Tab
                dbc.Tab([
                    html.Div([
                        dbc.Card([
                            dbc.CardHeader([
                                html.I(className="fa fa-chart-bar me-2"),
                                html.Strong("IoTSentinel vs Commercial Solutions")
                            ], className="glass-card-header"),
                            dbc.CardBody([
                                html.P([
                                    "IoTSentinel is an open-source, Raspberry Pi-based IoT security solution. ",
                                    "Here's how it compares to commercial alternatives:"
                                ], className="mb-4"),
                                dbc.Table([
                                    html.Thead([
                                        html.Tr([
                                            html.Th("Feature"),
                                            html.Th("IoTSentinel", className="text-success"),
                                            html.Th("Commercial Solutions", className="text-info")
                                        ])
                                    ]),
                                    html.Tbody([
                                        html.Tr([
                                            html.Td([html.I(className="fa fa-dollar-sign me-2"), html.Strong("Cost")]),
                                            html.Td([
                                                dbc.Badge("Free & Open Source", color="success", className="me-2"),
                                                html.Br(),
                                                html.Small("~$100 hardware (Raspberry Pi)", className="text-muted")
                                            ]),
                                            html.Td([
                                                dbc.Badge("$500-$5000+/year", color="warning"),
                                                html.Br(),
                                                html.Small("Subscription fees + hardware", className="text-muted")
                                            ])
                                        ]),
                                        html.Tr([
                                            html.Td([html.I(className="fa fa-cogs me-2"), html.Strong("Customization")]),
                                            html.Td([
                                                dbc.Badge("Fully Customizable", color="success"),
                                                html.Br(),
                                                html.Small("Modify source code, add features", className="text-muted")
                                            ]),
                                            html.Td([
                                                dbc.Badge("Limited", color="secondary"),
                                                html.Br(),
                                                html.Small("Vendor-controlled features only", className="text-muted")
                                            ])
                                        ]),
                                        html.Tr([
                                            html.Td([html.I(className="fa fa-database me-2"), html.Strong("Data Privacy")]),
                                            html.Td([
                                                dbc.Badge("100% Local", color="success"),
                                                html.Br(),
                                                html.Small("All data stays on your network", className="text-muted")
                                            ]),
                                            html.Td([
                                                dbc.Badge("Cloud-Based", color="warning"),
                                                html.Br(),
                                                html.Small("Data sent to vendor servers", className="text-muted")
                                            ])
                                        ]),
                                        html.Tr([
                                            html.Td([html.I(className="fa fa-robot me-2"), html.Strong("AI/ML Detection")]),
                                            html.Td([
                                                dbc.Badge("Advanced", color="success"),
                                                html.Br(),
                                                html.Small("River ML: HalfSpaceTrees, HoeffdingAdaptive, SNARIMAX", className="text-muted")
                                            ]),
                                            html.Td([
                                                dbc.Badge("Advanced", color="success"),
                                                html.Br(),
                                                html.Small("Proprietary algorithms", className="text-muted")
                                            ])
                                        ]),
                                        html.Tr([
                                            html.Td([html.I(className="fa fa-network-wired me-2"), html.Strong("Network Analysis")]),
                                            html.Td([
                                                dbc.Badge("Professional", color="success"),
                                                html.Br(),
                                                html.Small("Zeek (formerly Bro IDS) integration", className="text-muted")
                                            ]),
                                            html.Td([
                                                dbc.Badge("Professional", color="success"),
                                                html.Br(),
                                                html.Small("Commercial IDS/IPS", className="text-muted")
                                            ])
                                        ]),
                                        html.Tr([
                                            html.Td([html.I(className="fa fa-plug me-2"), html.Strong("Device Support")]),
                                            html.Td([
                                                dbc.Badge("Universal", color="success"),
                                                html.Br(),
                                                html.Small("Any IP-connected device", className="text-muted")
                                            ]),
                                            html.Td([
                                                dbc.Badge("Universal", color="success"),
                                                html.Br(),
                                                html.Small("Any IP-connected device", className="text-muted")
                                            ])
                                        ]),
                                        html.Tr([
                                            html.Td([html.I(className="fa fa-tachometer-alt me-2"), html.Strong("Real-Time Monitoring")]),
                                            html.Td([
                                                dbc.Badge("Yes", color="success"),
                                                html.Br(),
                                                html.Small("WebSocket updates", className="text-muted")
                                            ]),
                                            html.Td([
                                                dbc.Badge("Yes", color="success"),
                                                html.Br(),
                                                html.Small("Real-time dashboards", className="text-muted")
                                            ])
                                        ]),
                                        html.Tr([
                                            html.Td([html.I(className="fa fa-leaf me-2"), html.Strong("Sustainability")]),
                                            html.Td([
                                                dbc.Badge("Eco-Friendly", color="success"),
                                                html.Br(),
                                                html.Small("3W power consumption (Raspberry Pi)", className="text-muted")
                                            ]),
                                            html.Td([
                                                dbc.Badge("Variable", color="secondary"),
                                                html.Br(),
                                                html.Small("150W+ (dedicated hardware)", className="text-muted")
                                            ])
                                        ]),
                                        html.Tr([
                                            html.Td([html.I(className="fa fa-user-shield me-2"), html.Strong("Vendor Lock-In")]),
                                            html.Td([
                                                dbc.Badge("None", color="success"),
                                                html.Br(),
                                                html.Small("You own and control everything", className="text-muted")
                                            ]),
                                            html.Td([
                                                dbc.Badge("High", color="danger"),
                                                html.Br(),
                                                html.Small("Dependent on vendor support", className="text-muted")
                                            ])
                                        ]),
                                        html.Tr([
                                            html.Td([html.I(className="fa fa-graduation-cap me-2"), html.Strong("Learning Value")]),
                                            html.Td([
                                                dbc.Badge("High", color="success"),
                                                html.Br(),
                                                html.Small("Learn cybersecurity hands-on", className="text-muted")
                                            ]),
                                            html.Td([
                                                dbc.Badge("Low", color="secondary"),
                                                html.Br(),
                                                html.Small("Black-box solution", className="text-muted")
                                            ])
                                        ])
                                    ])
                                ], bordered=True, hover=True, responsive=True, dark=False, className="mb-3 table-adaptive"),
                                dbc.Alert([
                                    html.I(className="fa fa-info-circle me-2"),
                                    html.Strong("Best For: "),
                                    "IoTSentinel is ideal for home users, students, researchers, and small businesses who want ",
                                    "full control over their IoT security without recurring costs or vendor lock-in."
                                ], color="info", className="mt-4")
                            ])
                        ], className="glass-card border-0 shadow-sm")
                    ], className="p-3")
                ], label="Competitive Analysis", tab_id="competitive-analysis-tab")

            ], id="education-modal-tabs", active_tab="threat-scenarios-tab")
        ]),
        dbc.ModalFooter([
            dbc.Button([
                html.I(className="fa fa-times me-2"),
                "Close"
            ], id='close-education-modal-btn', color="secondary", outline=True)
        ])
    ], id="education-modal", size="xl", is_open=False, scrollable=True),

    # Geographic Threat Map Modal
    dbc.Modal([
        dbc.ModalHeader(dbc.ModalTitle([
            html.I(className="fa fa-earth-americas me-2 text-danger"),
            "Geographic Threat Map - Attack Origins"
        ]), close_button=True),
        dbc.ModalBody([
            dbc.Tabs([
                # Global Map Tab
                dbc.Tab([
                    html.Div([
                        dbc.Card([
                            dbc.CardBody([
                                html.H6([html.I(className="fa fa-map me-2 text-danger"), "Global Threat Distribution"], className="mb-3"),
                                dbc.Row([
                                    dbc.Col([
                                        dbc.Card([
                                            dbc.CardBody([
                                                html.Div([
                                                    html.I(className="fa fa-skull-crossbones me-2 text-danger"),
                                                    html.Span(id='threat-map-total', className="h4 mb-0")
                                                ], className="d-flex align-items-center justify-content-center")
                                            ])
                                        ], className="glass-card mb-3")
                                    ], md=4),
                                    dbc.Col([
                                        dbc.Card([
                                            dbc.CardBody([
                                                html.Div([
                                                    html.I(className="fa fa-globe me-2 text-info"),
                                                    html.Span(id='threat-map-countries', className="h4 mb-0")
                                                ], className="d-flex align-items-center justify-content-center")
                                            ])
                                        ], className="glass-card mb-3")
                                    ], md=4),
                                    dbc.Col([
                                        dbc.Card([
                                            dbc.CardBody([
                                                html.Div([
                                                    html.I(className="fa fa-clock me-2 text-warning"),
                                                    html.Span("Last Hour", className="h6 mb-0")
                                                ], className="d-flex align-items-center justify-content-center")
                                            ])
                                        ], className="glass-card mb-3")
                                    ], md=4)
                                ]),
                                dcc.Loading(
                                    dcc.Graph(id='geographic-threat-map', config={'displayModeBar': False},
                                             style={'height': '500px'}),
                                    type='circle'
                                )
                            ])
                        ], className="glass-card border-0 shadow-sm")
                    ], className="p-3")
                ], label="Global Map", tab_id="threat-map-global-tab"),

                # Top Countries Tab
                dbc.Tab([
                    html.Div([
                        dbc.Card([
                            dbc.CardBody([
                                html.H6([html.I(className="fa fa-flag me-2 text-danger"), "Top Attack Source Countries"], className="mb-3"),
                                dbc.Alert([
                                    html.I(className="fa fa-info-circle me-2"),
                                    "Countries with the highest number of attack attempts detected."
                                ], color="info", className="mb-3"),
                                html.Div(id='threat-map-top-countries', children=[
                                    html.P("Loading country statistics...", className="text-muted text-center py-4")
                                ])
                            ])
                        ], className="glass-card border-0 shadow-sm")
                    ], className="p-3")
                ], label="Top Countries", tab_id="threat-map-countries-tab"),

                # Attack Timeline Tab
                dbc.Tab([
                    html.Div([
                        dbc.Card([
                            dbc.CardBody([
                                html.H6([html.I(className="fa fa-chart-network me-2 text-warning"), "Attack Timeline"], className="mb-3"),
                                html.Div(id='threat-map-details', children=[
                                    html.P("Attack timeline and detailed statistics", className="text-muted text-center py-4")
                                ])
                            ])
                        ], className="glass-card border-0 shadow-sm")
                    ], className="p-3")
                ], label="Attack Timeline", tab_id="threat-map-timeline-tab")
            ], id="threat-map-tabs", active_tab="threat-map-global-tab")
        ], style={"maxHeight": "70vh", "overflowY": "auto"}),
        dbc.ModalFooter([
            html.Div(id='threat-map-timestamp-display', className="me-auto"),
            dbc.Button([
                html.I(className="fa fa-sync-alt me-2"),
                "Refresh Map"
            ], id="refresh-threat-map-btn", color="primary", outline=True, size="sm", className="me-2"),
            dbc.Button([
                html.I(className="fa fa-times me-2"),
                "Close"
            ], id="close-threat-map-modal-btn", color="secondary", size="sm")
        ]),
        dcc.Store(id='threat-map-timestamp-store')
    ], id="threat-map-modal", size="xl", is_open=False, scrollable=True),

    # Device Risk Heat Map Modal
    dbc.Modal([
        dbc.ModalHeader(dbc.ModalTitle([
            html.I(className="fa fa-fire-flame-curved me-2 text-warning"),
            "Device Risk Assessment Heat Map & Analysis"
        ]), close_button=True),
        dbc.ModalBody([
            dbc.Tabs([
                # Overview Tab
                dbc.Tab([
                    dbc.Row([
                        dbc.Col([
                            dbc.Card([
                                dbc.CardBody([
                                    html.Div([
                                        html.I(className="fa fa-exclamation-triangle fa-2x text-danger mb-2")
                                    ]),
                                    html.H3(id='high-risk-count', className="mb-1"),
                                    html.P("High Risk", className="text-muted mb-0", style={"fontSize": "0.85rem"})
                                ], className="text-center p-2")
                            ], className="glass-card border-0 shadow-sm mb-3")
                        ], md=3),
                        dbc.Col([
                            dbc.Card([
                                dbc.CardBody([
                                    html.Div([
                                        html.I(className="fa fa-exclamation-circle fa-2x text-warning mb-2")
                                    ]),
                                    html.H3(id='medium-risk-count', className="mb-1"),
                                    html.P("Medium Risk", className="text-muted mb-0", style={"fontSize": "0.85rem"})
                                ], className="text-center p-2")
                            ], className="glass-card border-0 shadow-sm mb-3")
                        ], md=3),
                        dbc.Col([
                            dbc.Card([
                                dbc.CardBody([
                                    html.Div([
                                        html.I(className="fa fa-check-circle fa-2x text-success mb-2")
                                    ]),
                                    html.H3(id='low-risk-count', className="mb-1"),
                                    html.P("Low Risk", className="text-muted mb-0", style={"fontSize": "0.85rem"})
                                ], className="text-center p-2")
                            ], className="glass-card border-0 shadow-sm mb-3")
                        ], md=3),
                        dbc.Col([
                            dbc.Card([
                                dbc.CardBody([
                                    html.Div([
                                        html.I(className="fa fa-tachometer-alt fa-2x text-info mb-2")
                                    ]),
                                    html.H3(id='avg-risk-score', className="mb-1"),
                                    html.P("Avg Risk Score", className="text-muted mb-0", style={"fontSize": "0.85rem"})
                                ], className="text-center p-2")
                            ], className="glass-card border-0 shadow-sm mb-3")
                        ], md=3)
                    ], className="mb-3"),

                    dbc.Card([
                        dbc.CardHeader([
                            html.I(className="fa fa-fire me-2"),
                            "Device Risk Heat Map"
                        ], className="glass-card-header"),
                        dbc.CardBody([
                            dcc.Loading(
                                dcc.Graph(id='device-risk-heatmap', config={'displayModeBar': False}, style={'height': '400px'}),
                                type='circle'
                            )
                        ])
                    ], className="glass-card border-0 shadow-sm")
                ], label="Overview", tab_id="risk-overview-tab", className="p-3"),

                # Device Details Tab
                dbc.Tab([
                    dbc.Card([
                        dbc.CardHeader([
                            html.I(className="fa fa-list me-2"),
                            "Device Risk Details"
                        ], className="glass-card-header"),

                        dbc.CardBody([
                            dbc.Row([
                                dbc.Col([
                                    dbc.Label("Risk Level Filter:", className="fw-bold mb-2"),
                                    dbc.Select(
                                        id='risk-level-filter',
                                        options=[
                                            {"label": "All Devices", "value": "all"},
                                            {"label": "High Risk Only", "value": "high"},
                                            {"label": "Medium Risk Only", "value": "medium"},
                                            {"label": "Low Risk Only", "value": "low"}
                                        ],
                                        value="all",
                                        className="mb-3"
                                    )
                                ], md=4)
                            ]),
                            html.Div(id='risk-device-details')
                        ])
                    ], className="glass-card border-0 shadow-sm")
                ], label="Device Details", tab_id="risk-details-tab", className="p-3"),

                # Risk Factors Tab
                dbc.Tab([
                    dbc.Card([
                        dbc.CardHeader([
                            html.I(className="fa fa-chart-bar me-2"),
                            "Risk Factor Analysis"
                        ], className="glass-card-header"),
                        dbc.CardBody([
                            dbc.Row([
                                dbc.Col([
                                    dcc.Graph(id='risk-factors-chart', config={'displayModeBar': False}, style={'height': '300px'})
                                ], md=6),
                                dbc.Col([
                                    dcc.Graph(id='risk-distribution-chart', config={'displayModeBar': False}, style={'height': '300px'})
                                ], md=6)
                            ]),
                            html.Div(id='risk-factors-summary', className="mt-3")
                        ])
                    ], className="glass-card border-0 shadow-sm")
                ], label="Risk Factors", tab_id="risk-factors-tab", className="p-3"),

                # Remediation Tab
                dbc.Tab([
                    dbc.Card([
                        dbc.CardHeader([
                            html.I(className="fa fa-tools me-2"),
                            "Risk Mitigation Recommendations"
                        ], className="glass-card-header"),
                        dbc.CardBody([
                            html.Div(id='risk-remediation-recommendations')
                        ])
                    ], className="glass-card border-0 shadow-sm")
                ], label="Remediation", tab_id="risk-remediation-tab", className="p-3")
            ], id="risk-heatmap-tabs", active_tab="risk-overview-tab")
        ], style={"maxHeight": "70vh", "overflowY": "auto"}),
        dbc.ModalFooter([
            html.Div(id='risk-heatmap-timestamp-display', className="me-auto"),
            dbc.Button([
                html.I(className="fa fa-sync-alt me-2"),
                "Refresh"
            ], id="refresh-risk-heatmap-btn", color="primary", outline=True, size="sm", className="me-2"),
            dbc.Button([
                html.I(className="fa fa-times me-2"),
                "Close"
            ], id="close-risk-heatmap-modal-btn", color="secondary", size="sm")
        ]),
        dcc.Store(id='risk-heatmap-timestamp-store')
    ], id="risk-heatmap-modal", size="xl", is_open=False, scrollable=True),

    # Attack Surface Modal - Enhanced
    dbc.Modal([
        dbc.ModalHeader(dbc.ModalTitle([
            html.I(className="fa fa-bullseye me-2 text-danger"),
            "Attack Surface Analysis & Hardening"
        ]), close_button=True),
        dbc.ModalBody([
            dbc.Tabs([
                # Overview Tab
                dbc.Tab([
                    dbc.Row([
                        dbc.Col([
                            dbc.Card([
                                dbc.CardBody([
                                    html.Div([
                                        html.I(className="fa fa-door-open fa-2x text-danger mb-2")
                                    ]),
                                    html.H3(id="attack-surface-open-ports", className="mb-1"),
                                    html.P("Exposed Ports", className="text-muted mb-0", style={"fontSize": "0.85rem"})
                                ], className="text-center p-2")
                            ], className="glass-card border-0 shadow-sm mb-3")
                        ], md=3),
                        dbc.Col([
                            dbc.Card([
                                dbc.CardBody([
                                    html.Div([
                                        html.I(className="fa fa-server fa-2x text-warning mb-2")
                                    ]),
                                    html.H3(id="attack-surface-services", className="mb-1"),
                                    html.P("Running Services", className="text-muted mb-0", style={"fontSize": "0.85rem"})
                                ], className="text-center p-2")
                            ], className="glass-card border-0 shadow-sm mb-3")
                        ], md=3),
                        dbc.Col([
                            dbc.Card([
                                dbc.CardBody([
                                    html.Div([
                                        html.I(className="fa fa-exclamation-triangle fa-2x text-danger mb-2")
                                    ]),
                                    html.H3(id="attack-surface-high-risk", className="mb-1"),
                                    html.P("High-Risk Devices", className="text-muted mb-0", style={"fontSize": "0.85rem"})
                                ], className="text-center p-2")
                            ], className="glass-card border-0 shadow-sm mb-3")
                        ], md=3),
                        dbc.Col([
                            dbc.Card([
                                dbc.CardBody([
                                    html.Div([
                                        html.I(className="fa fa-shield-alt fa-2x text-info mb-2")
                                    ]),
                                    html.H3(id="attack-surface-exposure-score", className="mb-1"),
                                    html.P("Exposure Score", className="text-muted mb-0", style={"fontSize": "0.85rem"})
                                ], className="text-center p-2")
                            ], className="glass-card border-0 shadow-sm mb-3")
                        ], md=3)
                    ], className="mb-3"),

                    html.Div(id="attack-surface-list", className="mb-3"),

                    dbc.Card([
                        dbc.CardHeader([
                            html.I(className="fa fa-chart-bar me-2"),
                            "Attack Vector Distribution"
                        ], className="glass-card-header"),
                        dbc.CardBody([
                            dcc.Graph(id='attack-surface-vector-chart', config={'displayModeBar': False}, style={'height': '300px'})
                        ])
                    ], className="glass-card border-0 shadow-sm mb-3"),
                    dbc.Card([
                        dbc.CardHeader([
                            html.I(className="fa fa-list me-2"),
                            "Top Attack Vectors"
                        ], className="glass-card-header"),
                        dbc.CardBody([
                            html.Div(id='attack-surface-top-vectors')
                        ])
                    ], className="glass-card border-0 shadow-sm")
                ], label="Overview", tab_id="attack-surface-overview-tab", className="p-3"),

                # Exposed Services Tab
                dbc.Tab([
                    # Search and Filter Controls
                    dbc.Row([
                        dbc.Col([
                            dbc.InputGroup([
                                dbc.InputGroupText(html.I(className="fa fa-search")),
                                dbc.Input(
                                    id='attack-surface-services-search',
                                    type='text',
                                    placeholder="Search by port number, service name, or device IP..."
                                )
                            ])
                        ], md=12)
                    ], className="mb-2"),
                    dbc.Row([
                        dbc.Col([
                            dbc.Select(
                                id='attack-surface-risk-filter',
                                options=[
                                    {'label': '🔍 All Risk Levels', 'value': 'all'},
                                    {'label': '🔴 High Risk', 'value': 'high'},
                                    {'label': '🟡 Medium Risk', 'value': 'medium'},
                                    {'label': '🟢 Low Risk', 'value': 'low'}
                                ],
                                value='all'
                            )
                        ], md=4),
                        dbc.Col([
                            dbc.Select(
                                id='attack-surface-port-status-filter',
                                options=[
                                    {'label': '📊 All Port Status', 'value': 'all'},
                                    {'label': '🔓 Open Ports', 'value': 'open'},
                                    {'label': '🔒 Closed Ports', 'value': 'closed'}
                                ],
                                value='all'
                            )
                        ], md=4),
                        dbc.Col([
                            dbc.Button([
                                html.I(className="fa fa-sync-alt me-2"),
                                "Refresh"
                            ], id='refresh-attack-services-btn', color="primary", size="sm", className="w-100")
                        ], md=4)
                    ], className="mb-3"),

                    dbc.Card([
                        dbc.CardHeader([
                            html.I(className="fa fa-server me-2"),
                            "Exposed Services & Risk Assessment"
                        ], className="glass-card-header"),
                        dbc.CardBody([
                            html.Div(id='attack-surface-services-list')
                        ])
                    ], className="glass-card border-0 shadow-sm")
                ], label="Exposed Services", tab_id="attack-surface-services-tab", className="p-3"),

                # Open Ports Tab
                dbc.Tab([
                    dbc.Card([
                        dbc.CardHeader([
                            html.I(className="fa fa-door-open me-2"),
                            "Open Ports by Device"
                        ], className="glass-card-header"),
                        dbc.CardBody([
                            html.Div(id='attack-surface-ports-list')
                        ])
                    ], className="glass-card border-0 shadow-sm")
                ], label="Open Ports", tab_id="attack-surface-ports-tab", className="p-3"),

                # Mitigation Tab
                dbc.Tab([
                    dbc.Card([
                        dbc.CardHeader([
                            html.I(className="fa fa-shield-alt me-2"),
                            "Attack Surface Reduction Recommendations"
                        ], className="glass-card-header"),
                        dbc.CardBody([
                            html.Div(id='attack-surface-mitigation-list')
                        ])
                    ], className="glass-card border-0 shadow-sm")
                ], label="Mitigation", tab_id="attack-surface-mitigation-tab", className="p-3")
            ], id="attack-surface-tabs", active_tab="attack-surface-overview-tab")
        ], style={"maxHeight": "70vh", "overflowY": "auto"}),
        dbc.ModalFooter([
            dbc.Button([
                html.I(className="fa fa-sync-alt me-2"),
                "Refresh"
            ], id="refresh-attack-surface-btn", color="info", outline=True, size="sm", className="me-2"),
            dbc.Button([
                html.I(className="fa fa-times me-2"),
                "Close"
            ], id="close-attack-surface-modal-btn", color="secondary", size="sm")
        ])
    ], id="attack-surface-modal", size="xl", is_open=False, scrollable=True),

    # Forensic Timeline Modal - Enhanced
    dbc.Modal([
        dbc.ModalHeader(dbc.ModalTitle([
            html.I(className="fa fa-microscope me-2 text-purple"),
            "Forensic Timeline - Attack Reconstruction"
        ]), close_button=True),
        dbc.ModalBody([
            # Device selector at top
            dbc.Row([
                dbc.Col([
                    html.Label("Select Device to Analyze:", className="fw-bold mb-2"),
                    dbc.Select(
                        id="forensic-device-select",
                        placeholder="Choose a device...",
                    )
                ], md=8),
                dbc.Col([
                    html.Label("Time Range:", className="fw-bold mb-2"),
                    dbc.Select(
                        id="forensic-time-range",
                        options=[
                            {"label": "Last 24 Hours", "value": "24"},
                            {"label": "Last 7 Days", "value": "168"},
                            {"label": "Last 30 Days", "value": "720"}
                        ],
                        value="168"
                    )
                ], md=4)
            ], className="mb-4"),

            dbc.Tabs([
                # Events Timeline Tab
                dbc.Tab([
                    html.Div([
                        dbc.Card([
                            dbc.CardBody([
                                html.H6([html.I(className="fa fa-stream me-2 text-info"), "Event Timeline"], className="mb-3"),

                                # Timeline stats
                                dbc.Row([
                                    dbc.Col([
                                        html.Div([
                                            html.H4(id="forensic-total-events", className="mb-0 text-primary"),
                                            html.Small("Total Events", className="text-muted")
                                        ], className="text-center p-2 rounded", style={"background": "rgba(0, 212, 255, 0.1)"})
                                    ], md=3),
                                    dbc.Col([
                                        html.Div([
                                            html.H4(id="forensic-critical-count", className="mb-0 text-danger"),
                                            html.Small("Critical", className="text-muted")
                                        ], className="text-center p-2 rounded", style={"background": "rgba(255, 68, 68, 0.1)"})
                                    ], md=3),
                                    dbc.Col([
                                        html.Div([
                                            html.H4(id="forensic-suspicious-count", className="mb-0 text-warning"),
                                            html.Small("Suspicious", className="text-muted")
                                        ], className="text-center p-2 rounded", style={"background": "rgba(255, 170, 0, 0.1)"})
                                    ], md=3),
                                    dbc.Col([
                                        html.Div([
                                            html.H4(id="forensic-timespan", className="mb-0 text-info"),
                                            html.Small("Time Span", className="text-muted")
                                        ], className="text-center p-2 rounded", style={"background": "rgba(0, 255, 136, 0.1)"})
                                    ], md=3)
                                ], className="mb-4"),

                                # Timeline graph
                                dcc.Graph(id='forensic-timeline-graph', style={'height': '400px'},
                                         config={'displayModeBar': True, 'displaylogo': False})
                            ])
                        ], className="glass-card border-0 shadow-sm")
                    ], className="p-3")
                ], label="Events", tab_id="forensic-events-tab"),

                # Attack Patterns Tab
                dbc.Tab([
                    html.Div([
                        dbc.Card([
                            dbc.CardBody([
                                html.H6([html.I(className="fa fa-crosshairs me-2 text-danger"), "Attack Pattern Analysis"], className="mb-3"),
                                html.P("Identified attack patterns and behaviors", className="text-muted small mb-3"),

                                html.Div(id='forensic-attack-patterns')
                            ])
                        ], className="glass-card border-0 shadow-sm")
                    ], className="p-3")
                ], label="Attack Patterns", tab_id="forensic-patterns-tab"),

                # Detailed Events Tab
                dbc.Tab([
                    html.Div([
                        # Search and Filter Controls
                        dbc.Row([
                            dbc.Col([
                                dbc.InputGroup([
                                    dbc.InputGroupText(html.I(className="fa fa-search")),
                                    dbc.Input(
                                        id='forensic-event-search-input',
                                        type='text',
                                        placeholder="Search by device IP, destination IP, protocol, or service..."
                                    )
                                ])
                            ], md=12)
                        ], className="mb-2"),
                        dbc.Row([
                            dbc.Col([
                                dbc.Select(
                                    id='forensic-severity-filter',
                                    options=[
                                        {'label': '🔍 All Severities', 'value': 'all'},
                                        {'label': '🔴 Critical', 'value': 'critical'},
                                        {'label': '🟠 High', 'value': 'high'},
                                        {'label': '🟡 Medium', 'value': 'medium'},
                                        {'label': '🟢 Low', 'value': 'low'}
                                    ],
                                    value='all'
                                )
                            ], md=4),
                            dbc.Col([
                                dbc.Select(
                                    id='forensic-event-type-filter',
                                    options=[
                                        {'label': '📊 All Event Types', 'value': 'all'},
                                        {'label': '🔌 Connections', 'value': 'connection'},
                                        {'label': '🚨 Alerts', 'value': 'alert'},
                                        {'label': '📤 Data Exfiltration', 'value': 'exfiltration'}
                                    ],
                                    value='all'
                                )
                            ], md=4),
                            dbc.Col([
                                dbc.Button([
                                    html.I(className="fa fa-sync-alt me-2"),
                                    "Refresh"
                                ], id='refresh-forensic-log-btn', color="primary", size="sm", className="w-100")
                            ], md=4)
                        ], className="mb-3"),

                        dbc.Card([
                            dbc.CardBody([
                                html.H6([html.I(className="fa fa-list me-2 text-success"), "Detailed Event Log"], className="mb-3"),
                                html.P("Chronological event details for forensic analysis", className="text-muted small mb-3"),

                                html.Div(id='forensic-event-log')
                            ])
                        ], className="glass-card border-0 shadow-sm")
                    ], className="p-3")
                ], label="Event Log", tab_id="forensic-log-tab"),

                # Export Tab
                dbc.Tab([
                    html.Div([
                        dbc.Card([
                            dbc.CardBody([
                                html.H6([html.I(className="fa fa-file-export me-2 text-warning"), "Export Forensic Report"], className="mb-3"),
                                html.P("Generate and download detailed forensic reports", className="text-muted small mb-3"),

                                dbc.Row([
                                    dbc.Col([
                                        html.Label("Report Format:", className="fw-bold mb-2"),
                                        dbc.Select(
                                            id="forensic-report-format",
                                            options=[
                                                {'label': '📄 CSV Format', 'value': 'csv'},
                                                {'label': '📋 JSON Format', 'value': 'json'},
                                                {'label': '📕 PDF Report', 'value': 'pdf'},
                                                {'label': '📊 Excel Workbook', 'value': 'xlsx'}
                                            ],
                                            value="pdf",
                                            className="mb-3"
                                        )
                                    ], md=6),
                                    dbc.Col([
                                        html.Label("Include:", className="fw-bold mb-2"),
                                        dbc.Checklist(
                                            id="forensic-report-sections",
                                            options=[
                                                {"label": " Timeline Graph", "value": "timeline"},
                                                {"label": " Attack Patterns", "value": "patterns"},
                                                {"label": " Event Details", "value": "events"},
                                                {"label": " Recommendations", "value": "recommendations"}
                                            ],
                                            value=["timeline", "patterns", "events"],
                                            className="mb-3"
                                        )
                                    ], md=6)
                                ]),

                                dbc.Button([
                                    html.I(className="fa fa-download me-2"),
                                    "Generate & Download Report"
                                ], id="forensic-export-btn", color="success", size="lg", className="w-100")
                            ])
                        ], className="glass-card border-0 shadow-sm")
                    ], className="p-3")
                ], label="Export", tab_id="forensic-export-tab")

            ], id="forensic-timeline-tabs", active_tab="forensic-events-tab")
        ]),
        dbc.ModalFooter([
            dbc.Button([
                html.I(className="fa fa-sync-alt me-2"),
                "Refresh"
            ], id='refresh-forensic-btn', color="primary", outline=True, className="me-2"),
            dbc.Button([
                html.I(className="fa fa-times me-2"),
                "Close"
            ], id='close-forensic-modal-btn', color="secondary", outline=True)
        ])
    ], id="forensic-timeline-modal", size="xl", is_open=False, scrollable=True),

    # Timeline Visualization Modal
    dbc.Modal([
        dbc.ModalHeader(dbc.ModalTitle([
            html.I(className="fa fa-timeline me-2 text-primary"),
            "Timeline Visualization - Activity History"
        ]), close_button=True),
        dbc.ModalBody([
            dbc.Tabs([
                # Activity Timeline Tab
                dbc.Tab([
                    html.Div([
                        dbc.Card([
                            dbc.CardBody([
                                html.H6([html.I(className="fa fa-clock me-2 text-info"), "Network Activity Timeline"], className="mb-3"),
                                html.P("Visualize network traffic patterns over time", className="text-muted small mb-3"),

                                # Time range selector
                                dbc.Row([
                                    dbc.Col([
                                        html.Label("Time Range:", className="fw-bold mb-2"),
                                        dbc.Select(
                                            id='timeline-range-select',
                                            options=[
                                                {"label": "Last Hour", "value": "1"},
                                                {"label": "Last 6 Hours", "value": "6"},
                                                {"label": "Last 24 Hours", "value": "24"},
                                                {"label": "Last 7 Days", "value": "168"}
                                            ],
                                            value="24"
                                        )
                                    ], md=4)
                                ], className="mb-4"),

                                # Activity timeline graph
                                dcc.Graph(id='activity-timeline-graph', style={'height': '400px'},
                                         config={'displayModeBar': True, 'displaylogo': False}),

                                html.Hr(className="my-3"),
                                dbc.Row([
                                    dbc.Col([
                                        html.Label("Export Data", className="fw-bold mb-2 text-cyber"),
                                        html.P("Download timeline activity data in your preferred format.", className="text-muted small mb-2"),
                                        dbc.Select(
                                            id='export-format-timeline',
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
                                            "Export Timeline Data"
                                        ], id='export-timeline-viz-csv-btn', color="primary", className="w-100")
                                    ], md=6)
                                ])
                            ])
                        ], className="glass-card border-0 shadow-sm")
                    ], className="p-3")
                ], label="Activity", tab_id="activity-timeline-tab"),

                # Device Activity Tab
                dbc.Tab([
                    html.Div([
                        dbc.Card([
                            dbc.CardBody([
                                html.H6([html.I(className="fa fa-hdd me-2 text-success"), "Device Activity Breakdown"], className="mb-3"),
                                html.P("Activity timeline per device", className="text-muted small mb-3"),

                                # Device activity timeline
                                dcc.Graph(id='device-activity-timeline', style={'height': '450px'},
                                         config={'displayModeBar': True, 'displaylogo': False})
                            ])
                        ], className="glass-card border-0 shadow-sm")
                    ], className="p-3")
                ], label="Devices", tab_id="device-timeline-tab"),

                # Connection Patterns Tab
                dbc.Tab([
                    html.Div([
                        dbc.Card([
                            dbc.CardBody([
                                html.H6([html.I(className="fa fa-project-diagram me-2 text-warning"), "Connection Patterns"], className="mb-3"),
                                html.P("Timeline of connection patterns and protocols", className="text-muted small mb-3"),

                                # Connection patterns timeline
                                html.Div(id='connection-patterns-timeline')
                            ])
                        ], className="glass-card border-0 shadow-sm")
                    ], className="p-3")
                ], label="Connections", tab_id="connections-timeline-tab"),

                # Anomaly Timeline Tab
                dbc.Tab([
                    html.Div([
                        dbc.Card([
                            dbc.CardBody([
                                html.H6([html.I(className="fa fa-exclamation-triangle me-2 text-danger"), "Anomaly Detection Timeline"], className="mb-3"),
                                html.P("Timeline of detected anomalies and security events", className="text-muted small mb-3"),

                                # Anomaly timeline
                                html.Div(id='anomaly-timeline-section')
                            ])
                        ], className="glass-card border-0 shadow-sm")
                    ], className="p-3")
                ], label="Anomalies", tab_id="anomaly-timeline-tab")

            ], id="timeline-viz-tabs", active_tab="activity-timeline-tab")
        ]),
        dbc.ModalFooter([
            html.Div(id='timeline-viz-timestamp-display', className="me-auto"),
            dbc.Button([
                html.I(className="fa fa-sync-alt me-2"),
                "Refresh"
            ], id='refresh-timeline-viz-btn', color="info", outline=True, size="sm", className="me-2"),
            dbc.Button([
                html.I(className="fa fa-times me-2"),
                "Close"
            ], id='close-timeline-modal-btn', color="secondary", outline=True, size="sm")
        ]),
        dcc.Store(id='timeline-viz-timestamp-store'),
        dcc.Download(id='download-timeline-viz-csv')
    ], id="timeline-viz-modal", size="xl", is_open=False, scrollable=True),

    # Compliance Dashboard Modal
    dbc.Modal([
        dbc.ModalHeader(dbc.ModalTitle([
            html.I(className="fa fa-list-check me-2 text-success"),
            "Compliance Dashboard"
        ]), close_button=True),
        dbc.ModalBody([
            dbc.Tabs([
                # Overview Tab
                dbc.Tab([
                    html.Div([
                        # Search and Filter Controls
                        dbc.Row([
                            dbc.Col([
                                dbc.InputGroup([
                                    dbc.InputGroupText(html.I(className="fa fa-search")),
                                    dbc.Input(
                                        id='compliance-search-input',
                                        type='text',
                                        placeholder="Search by regulation name or requirement..."
                                    )
                                ])
                            ], md=12)
                        ], className="mb-2"),
                        dbc.Row([
                            dbc.Col([
                                dbc.Select(
                                    id='compliance-status-filter',
                                    options=[
                                        {'label': '📊 All Status', 'value': 'all'},
                                        {'label': '✅ Compliant', 'value': 'compliant'},
                                        {'label': '❌ Non-Compliant', 'value': 'non-compliant'},
                                        {'label': '⚠️ Partial', 'value': 'partial'}
                                    ],
                                    value='all'
                                )
                            ], md=8),
                            dbc.Col([
                                dbc.Button([
                                    html.I(className="fa fa-sync-alt me-2"),
                                    "Refresh"
                                ], id='refresh-compliance-overview-btn', color="primary", size="sm", className="w-100")
                            ], md=4)
                        ], className="mb-3"),

                        dbc.Card([
                            dbc.CardBody([
                                html.H6([html.I(className="fa fa-chart-bar me-2 text-success"), "Compliance Overview"], className="mb-3"),
                                dbc.Alert([
                                    html.I(className="fa fa-info-circle me-2"),
                                    "Monitor compliance with GDPR, NIST Cybersecurity Framework, and IoT Cybersecurity Act."
                                ], color="info", className="mb-4"),

                                # Compliance score summary
                                dbc.Row([
                                    dbc.Col([
                                        dbc.Card([
                                            dbc.CardBody([
                                                html.Div([
                                                    html.H2(id="compliance-overall-score", className="text-success mb-2"),
                                                    html.P("Overall Compliance Score", className="text-muted mb-0")
                                                ], className="text-center")
                                            ])
                                        ], className="border-0 shadow-sm mb-4")
                                    ], width=12)
                                ]),

                                # Compliance breakdown
                                dbc.Row([
                                    dbc.Col([
                                        dbc.Card([
                                            dbc.CardBody([
                                                html.I(className="fa fa-user-shield fa-2x text-primary mb-2"),
                                                html.H4(id="compliance-gdpr-score", className="mb-0"),
                                                html.Small("GDPR Compliance", className="text-muted")
                                            ], className="text-center py-3")
                                        ], className="border-0 bg-light")
                                    ], md=4),
                                    dbc.Col([
                                        dbc.Card([
                                            dbc.CardBody([
                                                html.I(className="fa fa-shield-alt fa-2x text-info mb-2"),
                                                html.H4(id="compliance-nist-score", className="mb-0"),
                                                html.Small("NIST Framework", className="text-muted")
                                            ], className="text-center py-3")
                                        ], className="border-0 bg-light")
                                    ], md=4),
                                    dbc.Col([
                                        dbc.Card([
                                            dbc.CardBody([
                                                html.I(className="fa fa-network-wired fa-2x text-success mb-2"),
                                                html.H4(id="compliance-iot-score", className="mb-0"),
                                                html.Small("IoT Act", className="text-muted")
                                            ], className="text-center py-3")
                                        ], className="border-0 bg-light")
                                    ], md=4)
                                ])
                            ])
                        ], className="glass-card border-0 shadow-sm"),

                        # Compliance Requirements List
                        dbc.Card([
                            dbc.CardHeader([
                                html.I(className="fa fa-list-check me-2"),
                                "Compliance Requirements"
                            ], className="glass-card-header"),
                            dbc.CardBody([
                                html.Div(id='compliance-requirements-list')
                            ])
                        ], className="glass-card border-0 shadow-sm mt-3")
                    ], className="p-3")
                ], label="Overview", tab_id="compliance-overview-tab"),

                # GDPR Compliance Tab
                dbc.Tab([
                    html.Div([
                        dbc.Card([
                            dbc.CardBody([
                                html.H6([html.I(className="fa fa-user-shield me-2 text-primary"), "GDPR Compliance"], className="mb-3"),
                                dbc.Alert([
                                    html.I(className="fa fa-info-circle me-2"),
                                    "General Data Protection Regulation compliance monitoring for IoT devices."
                                ], color="primary", className="mb-3"),
                                html.Div(id='gdpr-compliance-content')
                            ])
                        ], className="glass-card border-0 shadow-sm")
                    ], className="p-3")
                ], label="GDPR", tab_id="compliance-gdpr-tab"),

                # NIST Framework Tab
                dbc.Tab([
                    html.Div([
                        dbc.Card([
                            dbc.CardBody([
                                html.H6([html.I(className="fa fa-shield-halved me-2 text-info"), "NIST Cybersecurity Framework"], className="mb-3"),
                                dbc.Alert([
                                    html.I(className="fa fa-info-circle me-2"),
                                    "NIST Cybersecurity Framework implementation and compliance status."
                                ], color="info", className="mb-3"),
                                html.Div(id='nist-compliance-content')
                            ])
                        ], className="glass-card border-0 shadow-sm")
                    ], className="p-3")
                ], label="NIST Framework", tab_id="compliance-nist-tab"),

                # IoT Cybersecurity Act Tab
                dbc.Tab([
                    html.Div([
                        dbc.Card([
                            dbc.CardBody([
                                html.H6([html.I(className="fa fa-network-wired me-2 text-success"), "IoT Cybersecurity Act"], className="mb-3"),
                                dbc.Alert([
                                    html.I(className="fa fa-info-circle me-2"),
                                    "IoT Cybersecurity Improvement Act compliance requirements."
                                ], color="success", className="mb-3"),
                                html.Div(id='iot-act-compliance-content')
                            ])
                        ], className="glass-card border-0 shadow-sm")
                    ], className="p-3")
                ], label="IoT Act", tab_id="compliance-iot-tab")
            ], id="compliance-tabs", active_tab="compliance-overview-tab")
        ], style={"maxHeight": "70vh", "overflowY": "auto"}),
        dbc.ModalFooter([
            dbc.Button([
                html.I(className="fa fa-sync-alt me-2"),
                "Refresh Compliance"
            ], id="refresh-compliance-btn", color="primary", outline=True, size="sm", className="me-2"),
            dbc.Button([
                html.I(className="fa fa-times me-2"),
                "Close"
            ], id="close-compliance-modal-btn", color="secondary", size="sm")
        ])
    ], id="compliance-modal", size="xl", is_open=False, scrollable=True),

    # Automated Response Dashboard Modal - Enhanced with Tabs
    dbc.Modal([
        dbc.ModalHeader(dbc.ModalTitle([
            html.I(className="fa fa-wand-magic-sparkles me-2 text-primary"),
            "Automated Response Dashboard - Rule Management & Analytics"
        ]), close_button=True),
        dbc.ModalBody([
            dbc.Tabs([
                # Overview Tab
                dbc.Tab([
                    html.Div([
                        dbc.Card([
                            dbc.CardBody([
                                html.H6([html.I(className="fa fa-chart-bar me-2 text-success"), "Response Overview"], className="mb-3"),

                                # Response statistics
                                dbc.Row([
                                    dbc.Col([
                                        dbc.Card([
                                            dbc.CardBody([
                                                html.I(className="fa fa-ban fa-2x text-danger mb-2"),
                                                html.H3(id="auto-blocked-count", className="mb-0"),
                                                html.Small("Blocked Devices", className="text-muted")
                                            ], className="text-center py-3")
                                        ], className="border-0 bg-light")
                                    ], md=3),
                                    dbc.Col([
                                        dbc.Card([
                                            dbc.CardBody([
                                                html.I(className="fa fa-exclamation-triangle fa-2x text-warning mb-2"),
                                                html.H3(id="auto-alerts-count", className="mb-0"),
                                                html.Small("Alerts (24h)", className="text-muted")
                                            ], className="text-center py-3")
                                        ], className="border-0 bg-light")
                                    ], md=3),
                                    dbc.Col([
                                        dbc.Card([
                                            dbc.CardBody([
                                                html.I(className="fa fa-shield-alt fa-2x text-info mb-2"),
                                                html.H3(id="auto-active-rules", className="mb-0"),
                                                html.Small("Active Rules", className="text-muted")
                                            ], className="text-center py-3")
                                        ], className="border-0 bg-light")
                                    ], md=3),
                                    dbc.Col([
                                        dbc.Card([
                                            dbc.CardBody([
                                                html.I(className="fa fa-clock fa-2x text-success mb-2"),
                                                html.H3(id="auto-last-action", className="mb-0"),
                                                html.Small("Last Trigger", className="text-muted")
                                            ], className="text-center py-3")
                                        ], className="border-0 bg-light")
                                    ], md=3)
                                ], className="mb-4"),

                                # Alert Timeline Chart
                                html.H6("Alert Activity (Last 7 Days)", className="mb-3"),
                                dcc.Graph(id='auto-response-timeline-chart', config={'displayModeBar': False})
                            ])
                        ], className="glass-card border-0 shadow-sm")
                    ], className="p-3")
                ], label="Overview", tab_id="auto-overview-tab"),

                # Alert Rules Tab
                dbc.Tab([
                    html.Div([
                        dbc.Card([
                            dbc.CardBody([
                                html.H6([html.I(className="fa fa-cogs me-2 text-info"), "Configured Alert Rules"], className="mb-3"),

                                dbc.Alert([
                                    html.I(className="fa fa-lightbulb me-2"),
                                    "Alert rules automatically monitor your network and trigger actions when conditions are met. Toggle rules on/off as needed."
                                ], color="info", className="mb-3"),

                                html.Div(id='alert-rules-table')
                            ])
                        ], className="glass-card border-0 shadow-sm")
                    ], className="p-3")
                ], label="Alert Rules", tab_id="auto-rules-tab"),

                # Action History Tab
                dbc.Tab([
                    html.Div([
                        dbc.Card([
                            dbc.CardBody([
                                html.H6([html.I(className="fa fa-history me-2 text-warning"), "Automated Action History"], className="mb-3"),

                                dbc.Row([
                                    dbc.Col([
                                        dbc.Label("Time Range:", className="fw-bold"),
                                        dbc.Select(
                                            id='auto-history-timerange',
                                            options=[
                                                {'label': 'Last 24 Hours', 'value': 24},
                                                {'label': 'Last 7 Days', 'value': 168},
                                                {'label': 'Last 30 Days', 'value': 720}
                                            ],
                                            value=24,
                                            className="mb-3"
                                        )
                                    ], md=4)
                                ]),

                                html.Div(id='auto-response-log')
                            ])
                        ], className="glass-card border-0 shadow-sm")
                    ], className="p-3")
                ], label="Action History", tab_id="auto-history-tab"),

                # Rule Analytics Tab
                dbc.Tab([
                    html.Div([
                        dbc.Card([
                            dbc.CardBody([
                                html.H6([html.I(className="fa fa-chart-network me-2 text-purple"), "Rule Performance Analytics"], className="mb-3"),

                                dbc.Alert([
                                    html.I(className="fa fa-info-circle me-2"),
                                    "Track how often each rule is triggered and which rules are most effective."
                                ], color="success", className="mb-3"),

                                html.Div(id='rule-analytics-content')
                            ])
                        ], className="glass-card border-0 shadow-sm")
                    ], className="p-3")
                ], label="Analytics", tab_id="auto-analytics-tab")
            ], id="auto-response-tabs", active_tab="auto-overview-tab")
        ], style={"maxHeight": "70vh", "overflowY": "auto"}),
        dbc.ModalFooter([
            html.Div(id='auto-response-timestamp-display', className="me-auto"),
            dbc.Button([
                html.I(className="fa fa-sync-alt me-2"),
                "Refresh Data"
            ], id="refresh-auto-response-btn", color="primary", outline=True, size="sm", className="me-2"),
            dbc.Button([
                html.I(className="fa fa-times me-2"),
                "Close"
            ], id="close-auto-response-modal-btn", color="secondary", size="sm")
        ]),
        dcc.Store(id='auto-response-timestamp-store')
    ], id="auto-response-modal", size="xl", is_open=False, scrollable=True),

    # Vulnerability Scanner Modal
    dbc.Modal([
        dbc.ModalHeader(dbc.ModalTitle([
            html.I(className="fa fa-magnifying-glass-chart me-2 text-danger"),
            "Vulnerability Scanner - CVE Detection & Security Analysis"
        ]), close_button=True),
        dbc.ModalBody([
            dbc.Tabs([
                # Overview Tab
                dbc.Tab([
                    dbc.Row([
                        dbc.Col([
                            dbc.Card([
                                dbc.CardBody([
                                    html.Div([
                                        html.I(className="fa fa-exclamation-triangle fa-2x text-danger mb-2")
                                    ]),
                                    html.H3(id="vuln-critical-count", className="mb-1"),
                                    html.P("Critical", className="text-muted mb-0", style={"fontSize": "0.85rem"})
                                ], className="text-center p-2")
                            ], className="glass-card border-0 shadow-sm mb-3")
                        ], md=3),
                        dbc.Col([
                            dbc.Card([
                                dbc.CardBody([
                                    html.Div([
                                        html.I(className="fa fa-exclamation-circle fa-2x text-warning mb-2")
                                    ]),
                                    html.H3(id="vuln-high-count", className="mb-1"),
                                    html.P("High", className="text-muted mb-0", style={"fontSize": "0.85rem"})
                                ], className="text-center p-2")
                            ], className="glass-card border-0 shadow-sm mb-3")
                        ], md=3),
                        dbc.Col([
                            dbc.Card([
                                dbc.CardBody([
                                    html.Div([
                                        html.I(className="fa fa-shield-alt fa-2x text-info mb-2")
                                    ]),
                                    html.H3(id="vuln-total-devices", className="mb-1"),
                                    html.P("Affected Devices", className="text-muted mb-0", style={"fontSize": "0.85rem"})
                                ], className="text-center p-2")
                            ], className="glass-card border-0 shadow-sm mb-3")
                        ], md=3),
                        dbc.Col([
                            dbc.Card([
                                dbc.CardBody([
                                    html.Div([
                                        html.I(className="fa fa-database fa-2x text-success mb-2")
                                    ]),
                                    html.H3(id="vuln-total-cve", className="mb-1"),
                                    html.P("Total CVEs", className="text-muted mb-0", style={"fontSize": "0.85rem"})
                                ], className="text-center p-2")
                            ], className="glass-card border-0 shadow-sm mb-3")
                        ], md=3)
                    ], className="mb-3"),

                    dbc.Card([
                        dbc.CardHeader([
                            html.I(className="fa fa-chart-line me-2"),
                            "Vulnerability Discovery Timeline"
                        ], className="glass-card-header"),
                        dbc.CardBody([
                            dcc.Graph(id='vuln-timeline-chart', config={'displayModeBar': False}, style={'height': '300px'})
                        ])
                    ], className="glass-card border-0 shadow-sm")
                ], label="Overview", tab_id="vuln-overview-tab", className="p-3"),

                # CVE Database Tab
                dbc.Tab([
                    # Search and Filter Controls
                    dbc.Row([
                        dbc.Col([
                            dbc.InputGroup([
                                dbc.InputGroupText(html.I(className="fa fa-search")),
                                dbc.Input(
                                    id='cve-database-search-input',
                                    type='text',
                                    placeholder="Search by CVE ID, description, or vendor..."
                                )
                            ])
                        ], md=6),
                        dbc.Col([
                            dbc.Select(
                                id='cve-severity-filter',
                                options=[
                                    {'label': '🔍 All Severities', 'value': 'all'},
                                    {'label': '🔴 Critical', 'value': 'critical'},
                                    {'label': '🟠 High', 'value': 'high'},
                                    {'label': '🟡 Medium', 'value': 'medium'},
                                    {'label': '🟢 Low', 'value': 'low'}
                                ],
                                value='all'
                            )
                        ], md=4),
                        dbc.Col([
                            dbc.Button([
                                html.I(className="fa fa-sync-alt me-2"),
                                "Refresh"
                            ], id='refresh-cve-database-btn', color="primary", size="sm", className="w-100")
                        ], md=2)
                    ], className="mb-3"),

                    dbc.Card([
                        dbc.CardHeader([
                            html.I(className="fa fa-database me-2"),
                            "Known CVE Vulnerabilities Database"
                        ], className="glass-card-header"),
                        dbc.CardBody([
                            html.Div(id='vuln-cve-database-table')
                        ])
                    ], className="glass-card border-0 shadow-sm")
                ], label="CVE Database", tab_id="vuln-cve-tab", className="p-3"),

                # Device Scan Tab
                dbc.Tab([
                    # Search and Filter Controls
                    dbc.Row([
                        dbc.Col([
                            dbc.InputGroup([
                                dbc.InputGroupText(html.I(className="fa fa-search")),
                                dbc.Input(
                                    id='device-scan-search-input',
                                    type='text',
                                    placeholder="Search by CVE ID, title, vendor/model, or device..."
                                )
                            ])
                        ], md=12)
                    ], className="mb-2"),
                    dbc.Row([
                        dbc.Col([
                            dbc.Select(
                                id='vuln-status-filter',
                                options=[
                                    {'label': '🔍 All Status', 'value': 'all'},
                                    {'label': '🔴 Active', 'value': 'active'},
                                    {'label': '🟢 Patched', 'value': 'patched'},
                                    {'label': '🟡 Mitigated', 'value': 'mitigated'}
                                ],
                                value='all'
                            )
                        ], md=4),
                        dbc.Col([
                            dbc.Select(
                                id='vuln-severity-filter',
                                options=[
                                    {'label': '🔍 All Severities', 'value': 'all'},
                                    {'label': '🔴 Critical (9.0-10.0)', 'value': 'critical'},
                                    {'label': '🟠 High (7.0-8.9)', 'value': 'high'},
                                    {'label': '🟡 Medium (4.0-6.9)', 'value': 'medium'},
                                    {'label': '🟢 Low (0.1-3.9)', 'value': 'low'}
                                ],
                                value='all'
                            )
                        ], md=4),
                        dbc.Col([
                            dbc.Button([
                                html.I(className="fa fa-sync-alt me-2"),
                                "Refresh"
                            ], id='refresh-device-scan-btn', color="primary", size="sm", className="w-100")
                        ], md=4)
                    ], className="mb-3"),

                    dbc.Card([
                        dbc.CardHeader([
                            html.I(className="fa fa-search me-2"),
                            "Device Vulnerability Scan Results"
                        ], className="glass-card-header"),
                        dbc.CardBody([
                            html.Div(id='vuln-device-scan-results')
                        ])
                    ], className="glass-card border-0 shadow-sm")
                ], label="Device Scan", tab_id="vuln-scan-tab", className="p-3"),

                # Recommendations Tab
                dbc.Tab([
                    dbc.Card([
                        dbc.CardHeader([
                            html.I(className="fa fa-lightbulb me-2"),
                            "Security Recommendations & Mitigation Steps"
                        ], className="glass-card-header"),
                        dbc.CardBody([
                            html.Div(id='vuln-recommendations')
                        ])
                    ], className="glass-card border-0 shadow-sm")
                ], label="Recommendations", tab_id="vuln-recommendations-tab", className="p-3")
            ], id="vuln-scanner-tabs", active_tab="vuln-overview-tab")
        ], style={"maxHeight": "70vh", "overflowY": "auto"}),
        dbc.ModalFooter([
            dbc.Button([
                html.I(className="fa fa-sync-alt me-2"),
                "Refresh Scan"
            ], id="refresh-vuln-scanner-btn", color="primary", outline=True, size="sm", className="me-2"),
            dbc.Button([
                html.I(className="fa fa-times me-2"),
                "Close"
            ], id="close-vuln-scanner-modal-btn", color="secondary", size="sm")
        ])
    ], id="vuln-scanner-modal", size="xl", is_open=False, scrollable=True),

    # API Integration Hub Modal
    dbc.Modal([
        dbc.ModalHeader(dbc.ModalTitle([
            html.I(className="fa fa-plug me-2 text-primary"),
            "API Integration Hub - Free-Tier Integrations"
        ]), close_button=True),
        dbc.ModalBody([
            dbc.Alert([
                html.I(className="fa fa-info-circle me-2"),
                "Configure and manage external API integrations for threat intelligence, notifications, ticketing, and automation. All credentials are encrypted before storage."
            ], color="info", className="mb-4"),

            dbc.Tabs([
                # Overview Tab
                dbc.Tab([
                    dbc.Row([
                        dbc.Col([
                            dbc.Card([
                                dbc.CardBody([
                                    html.Div([
                                        html.I(className="fa fa-plug fa-2x text-success mb-2")
                                    ]),
                                    html.H3(id="api-hub-enabled-count", className="mb-1"),
                                    html.P("Enabled Integrations", className="text-muted mb-0", style={"fontSize": "0.85rem"})
                                ], className="text-center p-2")
                            ], className="glass-card border-0 shadow-sm mb-3")
                        ], md=3),
                        dbc.Col([
                            dbc.Card([
                                dbc.CardBody([
                                    html.Div([
                                        html.I(className="fa fa-heartbeat fa-2x text-info mb-2")
                                    ]),
                                    html.H3(id="api-hub-healthy-count", className="mb-1"),
                                    html.P("Healthy Services", className="text-muted mb-0", style={"fontSize": "0.85rem"})
                                ], className="text-center p-2")
                            ], className="glass-card border-0 shadow-sm mb-3")
                        ], md=3),
                        dbc.Col([
                            dbc.Card([
                                dbc.CardBody([
                                    html.Div([
                                        html.I(className="fa fa-check-circle fa-2x text-success mb-2")
                                    ]),
                                    html.H3(id="api-hub-total-requests", className="mb-1"),
                                    html.P("Total Requests", className="text-muted mb-0", style={"fontSize": "0.85rem"})
                                ], className="text-center p-2")
                            ], className="glass-card border-0 shadow-sm mb-3")
                        ], md=3),
                        dbc.Col([
                            dbc.Card([
                                dbc.CardBody([
                                    html.Div([
                                        html.I(className="fa fa-percentage fa-2x text-primary mb-2")
                                    ]),
                                    html.H3(id="api-hub-success-rate", className="mb-1"),
                                    html.P("Success Rate", className="text-muted mb-0", style={"fontSize": "0.85rem"})
                                ], className="text-center p-2")
                            ], className="glass-card border-0 shadow-sm mb-3")
                        ], md=3)
                    ]),
                    html.Div(id='api-hub-integration-cards', className="mt-3")
                ], label="Overview", tab_id="api-hub-overview"),

                # Threat Intelligence Tab
                dbc.Tab([
                    html.Div(id='api-hub-threat-intel-content')
                ], label="Threat Intel (8)", tab_id="api-hub-threat"),

                # Notifications Tab
                dbc.Tab([
                    html.Div(id='api-hub-notifications-content')
                ], label="Notifications (5)", tab_id="api-hub-notifications"),

                # Ticketing Tab
                dbc.Tab([
                    html.Div(id='api-hub-ticketing-content')
                ], label="Ticketing (4)", tab_id="api-hub-ticketing"),

                # Geolocation Tab
                dbc.Tab([
                    html.Div(id='api-hub-geolocation-content')
                ], label="Geolocation (3)", tab_id="api-hub-geo"),

                # Webhooks Tab
                dbc.Tab([
                    html.Div(id='api-hub-webhooks-content')
                ], label="Webhooks (4)", tab_id="api-hub-webhooks"),

                # Settings Tab
                dbc.Tab([
                    html.Div(id='api-hub-settings-content')
                ], label="Settings", tab_id="api-hub-settings")
            ], id="api-hub-tabs", active_tab="api-hub-overview")
        ], style={"maxHeight": "70vh", "overflowY": "auto"}),
        dbc.ModalFooter([
            dbc.Button([
                html.I(className="fa fa-sync-alt me-2"),
                "Refresh All"
            ], id="api-hub-refresh-btn", color="primary", outline=True, size="sm", className="me-2"),
            dbc.Button([
                html.I(className="fa fa-times me-2"),
                "Close"
            ], id="api-hub-close-btn", color="secondary", size="sm")
        ]),
        dcc.Store(id='api-hub-store'),
        # Download component for API Hub config export
        dcc.Download(id='download-api-hub-config')
    ], id="api-hub-modal", size="xl", is_open=False, scrollable=True),

    # API Integration Configuration Modal
    dbc.Modal([
        dbc.ModalHeader(dbc.ModalTitle(id="api-config-modal-title"), close_button=True),
        dbc.ModalBody([
            html.Div(id='api-config-form-content')
        ]),
        dbc.ModalFooter([
            dbc.Button("Save Configuration", id="api-config-save-btn", color="primary", className="me-2"),
            dbc.Button("Cancel", id="api-config-cancel-btn", color="secondary")
        ]),
        dcc.Store(id='api-config-store')
    ], id="api-config-modal", size="lg", is_open=False),

    # Benchmarking Modal
    dbc.Modal([
        dbc.ModalHeader(dbc.ModalTitle([
            html.I(className="fa fa-chart-column me-2 text-success"),
            "Network Security Benchmarking & Compliance"
        ]), close_button=True),
        dbc.ModalBody([
            dbc.Tabs([
                # Overview Tab
                dbc.Tab([
                    dbc.Row([
                        dbc.Col([
                            dbc.Card([
                                dbc.CardBody([
                                    html.Div([
                                        html.I(className="fa fa-trophy fa-2x text-warning mb-2")
                                    ]),
                                    html.H3(id="benchmark-overall-score", className="mb-1"),
                                    html.P("Overall Security Score", className="text-muted mb-0", style={"fontSize": "0.85rem"})
                                ], className="text-center p-2")
                            ], className="glass-card border-0 shadow-sm mb-3")
                        ], md=4),
                        dbc.Col([
                            dbc.Card([
                                dbc.CardBody([
                                    html.Div([
                                        html.I(className="fa fa-industry fa-2x text-info mb-2")
                                    ]),
                                    html.H3(id="benchmark-industry-avg", className="mb-1"),
                                    html.P("Industry Average", className="text-muted mb-0", style={"fontSize": "0.85rem"})
                                ], className="text-center p-2")
                            ], className="glass-card border-0 shadow-sm mb-3")
                        ], md=4),
                        dbc.Col([
                            dbc.Card([
                                dbc.CardBody([
                                    html.Div([
                                        html.I(className="fa fa-chart-line fa-2x text-success mb-2")
                                    ]),
                                    html.H3(id="benchmark-percentile", className="mb-1"),
                                    html.P("Percentile Rank", className="text-muted mb-0", style={"fontSize": "0.85rem"})
                                ], className="text-center p-2")
                            ], className="glass-card border-0 shadow-sm mb-3")
                        ], md=4)
                    ], className="mb-3"),

                    html.Div(id="benchmark-comparison", className="mb-3"),

                    dbc.Card([
                        dbc.CardHeader([
                            html.I(className="fa fa-chart-radar me-2"),
                            "Security Posture Comparison"
                        ], className="glass-card-header"),
                        dbc.CardBody([
                            dcc.Graph(id='benchmark-radar-chart', config={'displayModeBar': False}, style={'height': '400px'})
                        ])
                    ], className="glass-card border-0 shadow-sm")
                ], label="Overview", tab_id="benchmark-overview-tab", className="p-3"),

                # Metrics Tab
                dbc.Tab([
                    dbc.Card([
                        dbc.CardHeader([
                            html.I(className="fa fa-list-check me-2"),
                            "Security Metrics Comparison"
                        ], className="glass-card-header"),
                        dbc.CardBody([
                            html.Div(id='benchmark-metrics-comparison')
                        ])
                    ], className="glass-card border-0 shadow-sm")
                ], label="Metrics", tab_id="benchmark-metrics-tab", className="p-3"),

                # Best Practices Tab
                dbc.Tab([
                    dbc.Card([
                        dbc.CardHeader([
                            html.I(className="fa fa-check-double me-2"),
                            "Security Best Practices Checklist"
                        ], className="glass-card-header"),
                        dbc.CardBody([
                            html.Div(id='benchmark-best-practices')
                        ])
                    ], className="glass-card border-0 shadow-sm")
                ], label="Best Practices", tab_id="benchmark-practices-tab", className="p-3"),

                # Recommendations Tab
                dbc.Tab([
                    dbc.Card([
                        dbc.CardHeader([
                            html.I(className="fa fa-lightbulb me-2"),
                            "Improvement Recommendations"
                        ], className="glass-card-header"),
                        dbc.CardBody([
                            html.Div(id='benchmark-recommendations')
                        ])
                    ], className="glass-card border-0 shadow-sm")
                ], label="Recommendations", tab_id="benchmark-recommendations-tab", className="p-3")
            ], id="benchmark-tabs", active_tab="benchmark-overview-tab")
        ], style={"maxHeight": "70vh", "overflowY": "auto"}),
        dbc.ModalFooter([
            html.Div(id='benchmark-timestamp-display', className="me-auto"),
            dbc.Button([
                html.I(className="fa fa-sync-alt me-2"),
                "Refresh"
            ], id="refresh-benchmark-btn", color="primary", outline=True, size="sm", className="me-2"),
            dbc.Button([
                html.I(className="fa fa-times me-2"),
                "Close"
            ], id="close-benchmark-modal-btn", color="secondary", size="sm")
        ]),
        dcc.Store(id='benchmark-timestamp-store')
    ], id="benchmark-modal", size="xl", is_open=False, scrollable=True),

    # Network Performance Analytics Modal - Enhanced
    dbc.Modal([
        dbc.ModalHeader(dbc.ModalTitle([
            html.I(className="fa fa-gauge-high me-2 text-info"),
            "Network Performance Analytics & Optimization"
        ]), close_button=True),
        dbc.ModalBody([
            dbc.Tabs([
                # Overview Tab
                dbc.Tab([
                    dbc.Row([
                        dbc.Col([
                            dbc.Card([
                                dbc.CardBody([
                                    html.Div([
                                        html.I(className="fa fa-clock fa-2x text-info mb-2")
                                    ]),
                                    html.H3(id="perf-avg-latency", className="mb-1"),
                                    html.P("Avg Latency", className="text-muted mb-0", style={"fontSize": "0.85rem"})
                                ], className="text-center p-2")
                            ], className="glass-card border-0 shadow-sm mb-3")
                        ], md=3),
                        dbc.Col([
                            dbc.Card([
                                dbc.CardBody([
                                    html.Div([
                                        html.I(className="fa fa-exchange-alt fa-2x text-success mb-2")
                                    ]),
                                    html.H3(id="perf-throughput", className="mb-1"),
                                    html.P("Throughput", className="text-muted mb-0", style={"fontSize": "0.85rem"})
                                ], className="text-center p-2")
                            ], className="glass-card border-0 shadow-sm mb-3")
                        ], md=3),
                        dbc.Col([
                            dbc.Card([
                                dbc.CardBody([
                                    html.Div([
                                        html.I(className="fa fa-exclamation-triangle fa-2x text-warning mb-2")
                                    ]),
                                    html.H3(id="perf-packet-loss", className="mb-1"),
                                    html.P("Packet Loss", className="text-muted mb-0", style={"fontSize": "0.85rem"})
                                ], className="text-center p-2")
                            ], className="glass-card border-0 shadow-sm mb-3")
                        ], md=3),
                        dbc.Col([
                            dbc.Card([
                                dbc.CardBody([
                                    html.Div([
                                        html.I(className="fa fa-link fa-2x text-primary mb-2")
                                    ]),
                                    html.H3(id="perf-active-connections", className="mb-1"),
                                    html.P("Active Connections", className="text-muted mb-0", style={"fontSize": "0.85rem"})
                                ], className="text-center p-2")
                            ], className="glass-card border-0 shadow-sm mb-3")
                        ], md=3)
                    ], className="mb-3"),
                    dbc.Card([
                        dbc.CardHeader([
                            html.I(className="fa fa-chart-line me-2"),
                            "Connection Activity Over Time"
                        ], className="glass-card-header"),
                        dbc.CardBody([
                            dcc.Graph(id='performance-graph', config={'displayModeBar': False}, style={'height': '350px'})
                        ])
                    ], className="glass-card border-0 shadow-sm")
                ], label="Overview", tab_id="performance-overview-tab", className="p-3"),

                # Bandwidth Tab
                dbc.Tab([
                    dbc.Card([
                        dbc.CardHeader([
                            html.I(className="fa fa-chart-bar me-2"),
                            "Bandwidth Usage Analysis"
                        ], className="glass-card-header"),
                        dbc.CardBody([
                            html.Div(id='performance-bandwidth-analysis')
                        ])
                    ], className="glass-card border-0 shadow-sm")
                ], label="Bandwidth", tab_id="performance-bandwidth-tab", className="p-3"),

                # Connection Quality Tab
                dbc.Tab([
                    dbc.Card([
                        dbc.CardHeader([
                            html.I(className="fa fa-signal me-2"),
                            "Connection Quality Metrics"
                        ], className="glass-card-header"),
                        dbc.CardBody([
                            html.Div(id='performance-quality-metrics')
                        ])
                    ], className="glass-card border-0 shadow-sm")
                ], label="Quality", tab_id="performance-quality-tab", className="p-3"),

                # Optimization Tab
                dbc.Tab([
                    dbc.Card([
                        dbc.CardHeader([
                            html.I(className="fa fa-cogs me-2"),
                            "Performance Optimization Recommendations"
                        ], className="glass-card-header"),
                        dbc.CardBody([
                            html.Div(id='performance-optimization-list')
                        ])
                    ], className="glass-card border-0 shadow-sm")
                ], label="Optimization", tab_id="performance-optimization-tab", className="p-3")
            ], id="performance-tabs", active_tab="performance-overview-tab")
        ], style={"maxHeight": "70vh", "overflowY": "auto"}),
        dbc.ModalFooter([
            html.Div(id='performance-timestamp-display', className="me-auto"),
            dbc.Button([
                html.I(className="fa fa-sync-alt me-2"),
                "Refresh"
            ], id="refresh-performance-btn", color="info", outline=True, size="sm", className="me-2"),
            dbc.Button([
                html.I(className="fa fa-times me-2"),
                "Close"
            ], id="close-performance-modal-btn", color="secondary", size="sm")
        ]),
        dcc.Store(id='performance-timestamp-store')
    ], id="performance-modal", size="xl", is_open=False, scrollable=True),

    # Green Security Dashboard Modal - NEW
    dbc.Modal([
        dbc.ModalHeader(dbc.ModalTitle([
            html.I(className="fa fa-leaf me-2 text-success"),
            "Green Security Dashboard"
        ]), close_button=True),
        dbc.ModalBody([
            dbc.Tabs([
                # Tab 1: Carbon Footprint
                dbc.Tab([
                    html.Div([
                        dbc.Row([
                            # Carbon Footprint Gauge
                            dbc.Col([
                                dbc.Card([
                                    dbc.CardHeader([
                                        html.I(className="fa fa-smog me-2 text-success"),
                                        "Network Carbon Footprint"
                                    ], className="bg-success text-white"),
                                    dbc.CardBody([
                                        dcc.Graph(id='carbon-footprint-gauge', config={'displayModeBar': False}),
                                        html.Hr(),
                                        dbc.Row([
                                            dbc.Col([
                                                html.Div([
                                                    html.I(className="fa fa-tree me-2 text-success"),
                                                    html.Strong("Trees to offset:", className="me-2"),
                                                    html.Span(id='trees-needed', className="badge bg-success")
                                                ])
                                            ], width=6),
                                            dbc.Col([
                                                html.Div([
                                                    html.I(className="fa fa-car me-2 text-warning"),
                                                    html.Strong("Car miles equiv:", className="me-2"),
                                                    html.Span(id='car-miles-equiv', className="badge bg-warning")
                                                ])
                                            ], width=6)
                                        ])
                                    ])
                                ], className="glass-card border-0 shadow-sm")
                            ], md=12, className="mb-3"),

                            # Monthly Trend
                            dbc.Col([
                                dbc.Card([
                                    dbc.CardHeader([
                                        html.I(className="fa fa-chart-line me-2 text-primary"),
                                        "Carbon Footprint Trend (30 Days)"
                                    ], className="bg-primary text-white"),
                                    dbc.CardBody([
                                        dcc.Graph(id='carbon-trend-chart', config={'displayModeBar': False}),
                                        html.Hr(className="my-3"),
                                        dbc.Row([
                                            dbc.Col([
                                                html.Label("Export Sustainability Report", className="fw-bold mb-2 text-success"),
                                                html.P("Download complete sustainability metrics in your preferred format.", className="text-muted small mb-2"),
                                                dbc.Select(
                                                    id='export-format-sustainability',
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
                                                    "Export Sustainability Data"
                                                ], id='export-sustainability-btn', color="success", className="w-100")
                                            ], md=6)
                                        ])
                                    ])
                                ], className="glass-card border-0 shadow-sm")
                            ], md=12)
                        ])
                    ], className="p-3")
                ], label="Carbon Footprint", tab_id="carbon-tab"),

                # Tab 2: Energy Consumption
                dbc.Tab([
                    html.Div([
                        dbc.Row([
                            # Energy Summary Cards
                            dbc.Col([
                                dbc.Card([
                                    dbc.CardBody([
                                        html.Div([
                                            html.I(className="fa fa-bolt fa-2x text-warning mb-2"),
                                            html.H6("Today's Energy", className="text-muted mb-1"),
                                            html.H3(id='today-energy-kwh', className="mb-0 text-primary"),
                                            html.Small("kWh", className="text-muted")
                                        ], className="text-center")
                                    ])
                                ], className="glass-card border-0 shadow-sm hover-lift")
                            ], md=3),

                            dbc.Col([
                                dbc.Card([
                                    dbc.CardBody([
                                        html.Div([
                                            html.I(className="fa fa-pound-sign fa-2x text-success mb-2"),
                                            html.H6("Daily Cost", className="text-muted mb-1"),
                                            html.H3(id='today-energy-cost', className="mb-0 text-primary"),
                                            html.Small("GBP", className="text-muted")
                                        ], className="text-center")
                                    ])
                                ], className="glass-card border-0 shadow-sm hover-lift")
                            ], md=3),

                            dbc.Col([
                                dbc.Card([
                                    dbc.CardBody([
                                        html.Div([
                                            html.I(className="fa fa-calendar-days fa-2x text-info mb-2"),
                                            html.H6("Monthly Estimate", className="text-muted mb-1"),
                                            html.H3(id='monthly-energy-cost', className="mb-0 text-primary"),
                                            html.Small("GBP/month", className="text-muted")
                                        ], className="text-center")
                                    ])
                                ], className="glass-card border-0 shadow-sm hover-lift")
                            ], md=3),

                            dbc.Col([
                                dbc.Card([
                                    dbc.CardBody([
                                        html.Div([
                                            html.I(className="fa fa-chart-pie fa-2x text-danger mb-2"),
                                            html.H6("Yearly Estimate", className="text-muted mb-1"),
                                            html.H3(id='yearly-energy-cost', className="mb-0 text-primary"),
                                            html.Small("GBP/year", className="text-muted")
                                        ], className="text-center")
                                    ])
                                ], className="glass-card border-0 shadow-sm hover-lift")
                            ], md=3)
                        ], className="mb-3"),

                        # Top Energy Consumers
                        dbc.Row([
                            dbc.Col([
                                dbc.Card([
                                    dbc.CardHeader([
                                        html.I(className="fa fa-ranking-star me-2 text-danger"),
                                        "Top 10 Energy Consumers"
                                    ], className="bg-danger text-white"),
                                    dbc.CardBody([
                                        dcc.Graph(id='top-energy-consumers-chart', config={'displayModeBar': False})
                                    ])
                                ], className="glass-card border-0 shadow-sm")
                            ], md=12)
                        ])
                    ], className="p-3")
                ], label="Energy Consumption", tab_id="energy-tab"),

                # Tab 3: Green Best Practices
                dbc.Tab([
                    html.Div([
                        dbc.Alert([
                            html.I(className="fa fa-lightbulb me-2"),
                            html.Strong("Green Security Best Practices"),
                            html.P("Follow these recommendations to reduce your network's environmental impact while maintaining security.", className="mb-0 mt-2")
                        ], color="success", className="mb-3"),

                        html.Div(id='green-best-practices-content')
                    ], className="p-3")
                ], label="Best Practices", tab_id="practices-tab")
            ], id="sustainability-tabs", active_tab="carbon-tab")
        ]),
        dbc.ModalFooter([
            html.Div(id='sustainability-timestamp-display', className="me-auto"),
            dbc.Button([
                html.I(className="fa fa-sync-alt me-2"),
                "Refresh"
            ], id="refresh-sustainability-btn", color="success", outline=True, size="sm", className="me-2"),
            dbc.Button([
                html.I(className="fa fa-times me-2"),
                "Close"
            ], id="close-sustainability-modal-btn", color="secondary", size="sm")
        ]),
        dcc.Store(id='sustainability-data-store'),
        dcc.Download(id='download-sustainability-report')
    ], id="sustainability-modal", size="xl", is_open=False, scrollable=True),

    # Quick Settings Modal - Enhanced
    dbc.Modal([
        dbc.ModalHeader(dbc.ModalTitle([
            html.I(className="fa fa-cog me-2 text-primary"),
            "Quick Settings"
        ])),
        dbc.ModalBody([
            dbc.Tabs([
                # Tab 1: General Settings
                dbc.Tab([
                    dbc.Card([
                        dbc.CardBody([
                            # Refresh Interval
                            html.Div([
                                html.Label([
                                    html.I(className="fa fa-sync-alt me-2"),
                                    "Refresh Interval"
                                ], className="fw-bold mb-2"),
                                html.Small("How often to update dashboard data", className="text-muted d-block mb-2"),
                                dbc.Select(
                                    id="refresh-interval-select",
                                    options=[
                                        {"label": "5 seconds", "value": 5000},
                                        {"label": "10 seconds (Default)", "value": 10000},
                                        {"label": "30 seconds", "value": 30000},
                                        {"label": "1 minute", "value": 60000}
                                    ],
                                    value=10000,
                                    className="mb-4"
                                )
                            ]),

                            # Auto-update Widgets
                            html.Div([
                                html.Label([
                                    html.I(className="fa fa-magic me-2"),
                                    "Auto-Update Features"
                                ], className="fw-bold mb-2"),
                                dbc.Checklist(
                                    options=[
                                        {"label": "Auto-refresh widgets", "value": "auto-refresh"},
                                        {"label": "Auto-save preferences", "value": "auto-save"},
                                        {"label": "Load last view on startup", "value": "last-view"}
                                    ],
                                    value=["auto-refresh", "auto-save"],
                                    id="general-auto-settings",
                                    switch=True,
                                    className="mb-4"
                                )
                            ]),

                            # Default View
                            html.Div([
                                html.Label([
                                    html.I(className="fa fa-home me-2"),
                                    "Default View on Startup"
                                ], className="fw-bold mb-2"),
                                html.Small("Select which page to show when opening the dashboard", className="text-muted d-block mb-2"),
                                dbc.RadioItems(
                                    options=[
                                        {"label": "Dashboard Overview", "value": "dashboard"},
                                        {"label": "Analytics", "value": "analytics"},
                                        {"label": "Devices", "value": "devices"},
                                        {"label": "Alerts", "value": "alerts"}
                                    ],
                                    value="dashboard",
                                    id="default-view-setting",
                                    className="mb-3"
                                )
                            ])
                        ])
                    ], className="glass-card border-0 shadow-sm")
                ], label="General", tab_id="general-tab"),

                # Tab 2: Notifications
                dbc.Tab([
                    dbc.Card([
                        dbc.CardBody([
                            # Alert Types
                            html.Div([
                                html.Label([
                                    html.I(className="fa fa-bell me-2"),
                                    "Alert Notifications"
                                ], className="fw-bold mb-2"),
                                html.Small("Choose how you want to be notified about security alerts", className="text-muted d-block mb-2"),
                                dbc.Checklist(
                                    options=[
                                        {"label": "Enable voice alerts", "value": "voice"},
                                        {"label": "Enable browser notifications", "value": "browser"},
                                        {"label": "Show critical alerts only", "value": "critical"}
                                    ],
                                    value=["voice"],
                                    id="alert-settings",
                                    switch=True,
                                    className="mb-4"
                                )
                            ]),

                            # Notification Sound
                            html.Div([
                                html.Label([
                                    html.I(className="fa fa-volume-up me-2"),
                                    "Notification Sound"
                                ], className="fw-bold mb-2"),
                                dbc.Select(
                                    id="notification-sound-select",
                                    options=[
                                        {"label": "Default Beep", "value": "default"},
                                        {"label": "Chime", "value": "chime"},
                                        {"label": "Alert Tone", "value": "alert"},
                                        {"label": "Silent", "value": "silent"}
                                    ],
                                    value="default",
                                    className="mb-4"
                                )
                            ]),

                            # Alert Display Duration
                            html.Div([
                                html.Label([
                                    html.I(className="fa fa-clock me-2"),
                                    "Alert Popup Duration"
                                ], className="fw-bold mb-2"),
                                html.Small("How long to show alert popups (in seconds)", className="text-muted d-block mb-2"),
                                dbc.Select(
                                    id="alert-duration-select",
                                    options=[
                                        {"label": "3 seconds", "value": 3000},
                                        {"label": "5 seconds (Default)", "value": 5000},
                                        {"label": "10 seconds", "value": 10000},
                                        {"label": "Until dismissed", "value": 0}
                                    ],
                                    value=5000,
                                    className="mb-4"
                                )
                            ]),

                            # Desktop Notification Position
                            html.Div([
                                html.Label([
                                    html.I(className="fa fa-arrows-alt me-2"),
                                    "Desktop Notification Position"
                                ], className="fw-bold mb-2"),
                                dbc.RadioItems(
                                    options=[
                                        {"label": "Top Right", "value": "top-right"},
                                        {"label": "Top Left", "value": "top-left"},
                                        {"label": "Bottom Right", "value": "bottom-right"},
                                        {"label": "Bottom Left", "value": "bottom-left"}
                                    ],
                                    value="top-right",
                                    id="notification-position-setting",
                                    className="mb-3"
                                )
                            ])
                        ])
                    ], className="glass-card border-0 shadow-sm")
                ], label="Notifications", tab_id="notifications-tab"),

                # Tab 3: Network
                dbc.Tab([
                    dbc.Card([
                        dbc.CardBody([
                            # Network Interface
                            html.Div([
                                html.Label([
                                    html.I(className="fa fa-network-wired me-2"),
                                    "Network Interface"
                                ], className="fw-bold mb-2"),
                                html.Small("Specify the network interface to monitor (e.g., en0, eth0, wlan0)", className="text-muted d-block mb-2"),
                                dbc.Input(
                                    id="network-interface-input",
                                    placeholder="e.g., en0, eth0, wlan0",
                                    value=config.get('network.interface', 'en0'),
                                    className="mb-4"
                                )
                            ]),

                            # Network Options
                            html.Div([
                                html.Label([
                                    html.I(className="fa fa-cogs me-2"),
                                    "Network Monitoring Options"
                                ], className="fw-bold mb-2"),
                                dbc.Checklist(
                                    options=[
                                        {"label": "Auto-detect network interface", "value": "auto-detect"},
                                        {"label": "Show offline devices", "value": "show-offline"},
                                        {"label": "Monitor all interfaces", "value": "all-interfaces"}
                                    ],
                                    value=["show-offline"],
                                    id="network-options-settings",
                                    switch=True,
                                    className="mb-4"
                                )
                            ]),

                            # Network Scan Interval
                            html.Div([
                                html.Label([
                                    html.I(className="fa fa-search me-2"),
                                    "Network Scan Interval"
                                ], className="fw-bold mb-2"),
                                html.Small("How often to scan for new devices", className="text-muted d-block mb-2"),
                                dbc.Select(
                                    id="network-scan-interval-select",
                                    options=[
                                        {"label": "1 minute", "value": 60},
                                        {"label": "5 minutes (Default)", "value": 300},
                                        {"label": "15 minutes", "value": 900},
                                        {"label": "30 minutes", "value": 1800}
                                    ],
                                    value=300,
                                    className="mb-4"
                                )
                            ]),

                            # Connection Timeout
                            html.Div([
                                html.Label([
                                    html.I(className="fa fa-hourglass-half me-2"),
                                    "Connection Timeout"
                                ], className="fw-bold mb-2"),
                                html.Small("Timeout for device connection checks (in seconds)", className="text-muted d-block mb-2"),
                                dbc.Select(
                                    id="connection-timeout-select",
                                    options=[
                                        {"label": "5 seconds", "value": 5},
                                        {"label": "10 seconds (Default)", "value": 10},
                                        {"label": "30 seconds", "value": 30},
                                        {"label": "60 seconds", "value": 60}
                                    ],
                                    value=10,
                                    className="mb-3"
                                )
                            ])
                        ])
                    ], className="glass-card border-0 shadow-sm")
                ], label="Network", tab_id="network-tab"),

                # Tab 4: Display
                dbc.Tab([
                    dbc.Card([
                        dbc.CardBody([
                            # Chart Animations
                            html.Div([
                                html.Label([
                                    html.I(className="fa fa-chart-line me-2"),
                                    "Chart Animation Speed"
                                ], className="fw-bold mb-2"),
                                html.Small("Adjust animation speed for charts and graphs", className="text-muted d-block mb-2"),
                                dbc.Select(
                                    id="chart-animation-select",
                                    options=[
                                        {"label": "Fast", "value": "fast"},
                                        {"label": "Normal (Default)", "value": "normal"},
                                        {"label": "Slow", "value": "slow"},
                                        {"label": "Disabled", "value": "none"}
                                    ],
                                    value="normal",
                                    className="mb-4"
                                )
                            ]),

                            # UI Options
                            html.Div([
                                html.Label([
                                    html.I(className="fa fa-eye me-2"),
                                    "Display Options"
                                ], className="fw-bold mb-2"),
                                dbc.Checklist(
                                    options=[
                                        {"label": "Enable smooth scrolling", "value": "smooth-scroll"},
                                        {"label": "Show tooltips", "value": "tooltips"},
                                        {"label": "Compact mode", "value": "compact"},
                                        {"label": "Show timestamps", "value": "timestamps"},
                                        {"label": "Highlight new alerts", "value": "highlight-new"}
                                    ],
                                    value=["smooth-scroll", "tooltips", "timestamps"],
                                    id="display-options-settings",
                                    switch=True,
                                    className="mb-4"
                                )
                            ]),

                            # Font Size
                            html.Div([
                                html.Label([
                                    html.I(className="fa fa-text-height me-2"),
                                    "Interface Font Size"
                                ], className="fw-bold mb-2"),
                                dbc.RadioItems(
                                    options=[
                                        {"label": "Small", "value": "small"},
                                        {"label": "Medium (Default)", "value": "medium"},
                                        {"label": "Large", "value": "large"}
                                    ],
                                    value="medium",
                                    id="font-size-setting",
                                    className="mb-3"
                                )
                            ])
                        ])
                    ], className="glass-card border-0 shadow-sm")
                ], label="Display", tab_id="display-tab"),

                # Tab 5: Advanced
                dbc.Tab([
                    dbc.Card([
                        dbc.CardBody([
                            # Debug Options
                            html.Div([
                                html.Label([
                                    html.I(className="fa fa-bug me-2"),
                                    "Developer Options"
                                ], className="fw-bold mb-2"),
                                html.Small("Enable debugging and logging features", className="text-muted d-block mb-2"),
                                dbc.Checklist(
                                    options=[
                                        {"label": "Enable debug mode", "value": "debug"},
                                        {"label": "Console logging", "value": "logging"},
                                        {"label": "Show performance metrics", "value": "metrics"}
                                    ],
                                    value=[],
                                    id="debug-options-settings",
                                    switch=True,
                                    className="mb-4"
                                )
                            ]),

                            # Performance Mode
                            html.Div([
                                html.Label([
                                    html.I(className="fa fa-tachometer-alt me-2"),
                                    "Performance Mode"
                                ], className="fw-bold mb-2"),
                                html.Small("Optimize dashboard for different use cases", className="text-muted d-block mb-2"),
                                dbc.RadioItems(
                                    options=[
                                        {"label": "Balanced (Default) - Standard performance", "value": "balanced"},
                                        {"label": "High Performance - Faster updates, more resources", "value": "high"},
                                        {"label": "Power Saver - Slower updates, less resources", "value": "saver"}
                                    ],
                                    value="balanced",
                                    id="performance-mode-setting",
                                    className="mb-4"
                                )
                            ]),

                            # Actions
                            html.Div([
                                html.Label([
                                    html.I(className="fa fa-tools me-2"),
                                    "Maintenance Actions"
                                ], className="fw-bold mb-3"),
                                dbc.Row([
                                    dbc.Col([
                                        dbc.Button([
                                            html.I(className="fa fa-trash me-2"),
                                            "Clear Browser Cache"
                                        ], id="clear-cache-btn", color="warning", outline=True, className="w-100 mb-2")
                                    ], md=6),
                                    dbc.Col([
                                        dbc.Button([
                                            html.I(className="fa fa-undo me-2"),
                                            "Reset to Defaults"
                                        ], id="reset-settings-btn", color="danger", outline=True, className="w-100 mb-2")
                                    ], md=6)
                                ]),
                                dbc.Button([
                                    html.I(className="fa fa-download me-2"),
                                    "Export Settings"
                                ], id="export-settings-btn", color="info", outline=True, className="w-100 mt-2")
                            ])
                        ])
                    ], className="glass-card border-0 shadow-sm")
                ], label="Advanced", tab_id="advanced-tab"),

                # Tab 6: Discovery Settings
                dbc.Tab([
                    dbc.Card([
                        dbc.CardBody([
                            # Discovery Mode
                            html.Div([
                                html.Label([
                                    html.I(className="fa fa-radar me-2"),
                                    "Discovery Mode"
                                ], className="fw-bold mb-2"),
                                html.Small("Choose how devices are discovered on your network", className="text-muted d-block mb-2"),
                                dbc.RadioItems(
                                    options=[
                                        {"label": "Passive - Listen only (no active scanning, most secure)", "value": "passive"},
                                        {"label": "Hybrid - Passive + optional active (recommended)", "value": "hybrid"},
                                        {"label": "Active - Full network scanning (requires root)", "value": "active"}
                                    ],
                                    value="passive",
                                    id="discovery-mode-setting",
                                    className="mb-4"
                                )
                            ]),

                            # Active Scanning Features
                            html.Div([
                                html.Label([
                                    html.I(className="fa fa-search me-2"),
                                    "Active Scanning Features"
                                ], className="fw-bold mb-2"),
                                html.Small("Enable specific discovery protocols (requires Hybrid or Active mode)", className="text-muted d-block mb-2"),
                                dbc.Checklist(
                                    options=[
                                        {"label": "nmap Host Discovery - Scan network for devices", "value": "nmap"},
                                        {"label": "UPnP M-SEARCH - Query for UPnP devices", "value": "upnp"},
                                        {"label": "mDNS Queries - Discover Bonjour/Zeroconf services", "value": "mdns"}
                                    ],
                                    value=[],
                                    id="discovery-features-setting",
                                    switch=True,
                                    className="mb-4"
                                )
                            ]),

                            # Scan Interval
                            html.Div([
                                html.Label([
                                    html.I(className="fa fa-clock me-2"),
                                    "Active Scan Interval"
                                ], className="fw-bold mb-2"),
                                html.Small("How often to run active scans (applies to nmap)", className="text-muted d-block mb-2"),
                                dbc.Select(
                                    id="scan-interval-setting",
                                    options=[
                                        {"label": "Every 30 minutes", "value": 1800},
                                        {"label": "Every hour (Default)", "value": 3600},
                                        {"label": "Every 3 hours", "value": 10800},
                                        {"label": "Every 6 hours", "value": 21600},
                                        {"label": "Once per day", "value": 86400}
                                    ],
                                    value=3600,
                                    className="mb-4"
                                )
                            ]),

                            # Warning Alert
                            dbc.Alert([
                                html.I(className="fa fa-exclamation-triangle me-2"),
                                html.Strong("Important: "),
                                "Active scanning (especially nmap) requires root/sudo privileges. Passive discovery methods (mDNS listener, UPnP listener) work without elevated permissions."
                            ], color="warning", className="mb-3"),

                            # Current Status
                            html.Div([
                                html.Label([
                                    html.I(className="fa fa-info-circle me-2"),
                                    "Current Discovery Status"
                                ], className="fw-bold mb-2"),
                                html.Div(id="discovery-status-display", children=[
                                    dbc.Badge("Passive Listeners: Active", color="success", className="me-2 mb-1"),
                                    dbc.Badge("Active Scanning: Disabled", color="secondary", className="mb-1")
                                ])
                            ])
                        ])
                    ], className="glass-card border-0 shadow-sm")
                ], label="Discovery", tab_id="discovery-tab")

            ], id="quick-settings-tabs", active_tab="general-tab", className="mb-3"),

            dbc.Alert([
                html.I(className="fa fa-info-circle me-2"),
                "Settings are saved locally and will persist across sessions."
            ], color="info", className="mb-0")
        ], style={"maxHeight": "70vh", "overflowY": "auto"}),
        dbc.ModalFooter([
            dbc.Button("Save Changes", id="settings-save-btn", color="primary", size="sm", className="me-2"),
            dbc.Button("Close", id="settings-close-btn", color="secondary", size="sm")
        ])
    ], id="quick-settings-modal", size="lg", is_open=False),

    # Hidden Components & Modals
    html.Div(id='dummy-output-card-clicks', style={'display': 'none'}),
    WebSocket(id="ws", url="ws://127.0.0.1:8050/ws"),
    dcc.Interval(id='refresh-interval', interval=30*1000, n_intervals=0),  # 30 second refresh (optimized for performance)
    dcc.Store(id='alert-filter', data='all'),
    dcc.Store(id='alerts-data-store', data=[]),  # Store recent alerts data
    dcc.Store(id='selected-device-ip', data=None),
    dcc.Store(id='widget-preferences', data={'metrics': True, 'features': True, 'rightPanel': True}, storage_type='local'),
    dcc.Store(id='page-visibility-store', data={'visible': True}),  # Track page visibility for auto-pause
    dcc.Store(id='emergency-mode-store', data={'active': False, 'log_id': None}, storage_type='session'),  # Emergency mode state

    # Cross-chart filtering stores
    dcc.Store(id='global-device-filter', data=None),  # Filter by device IP across all charts
    dcc.Store(id='global-time-filter', data=None),    # Filter by time range across all charts
    dcc.Store(id='global-severity-filter', data=None), # Filter by severity across all charts

    # Emergency Mode Confirmation Modal
    dbc.Modal([
        dbc.ModalHeader(dbc.ModalTitle([
            html.I(className="fa fa-exclamation-triangle me-2 text-danger"),
            "Activate Emergency Protection"
        ])),
        dbc.ModalBody([
            html.P("This will immediately:", className="fw-bold mb-2"),
            html.Ul([
                html.Li("Block all unknown/untrusted devices from your network"),
                html.Li("Enable maximum firewall protection"),
                html.Li("Notify administrators"),
                html.Li("Log this security event")
            ]),
            html.Hr(),
            html.P("Optional: Describe what you observed (this helps us protect you better)", className="text-muted small mb-2"),
            dbc.Textarea(id="emergency-reason-input", placeholder="E.g., 'Strange pop-ups on my phone', 'Unknown device appeared', etc.", rows=3, className="mb-3"),
            dbc.Alert([
                html.I(className="fa fa-info-circle me-2"),
                "You can deactivate emergency mode at any time."
            ], color="info")
        ]),
        dbc.ModalFooter([
            dbc.Button("Cancel", id="emergency-cancel-btn", color="secondary", outline=True),
            dbc.Button([
                html.I(className="fa fa-shield-alt me-2"),
                "Activate Now"
            ], id="emergency-confirm-btn", color="danger")
        ])
    ], id="emergency-confirm-modal", is_open=False),

    # Customize Layout Modal - Enhanced
    dbc.Modal([
        dbc.ModalHeader(dbc.ModalTitle([
            html.I(className="fa fa-gears me-2"),
            "Widget & Layout Customization"
        ]), close_button=True),
        dbc.ModalBody([
            dbc.Tabs([
                # Dashboard Layout Tab
                dbc.Tab([
                    html.Div([
                        html.H6([html.I(className="fa fa-th me-2"), "Dashboard Sections"], className="mt-3 mb-3"),
                        dbc.Checklist(
                            id="widget-toggles",
                            options=[
                                {"label": html.Span([html.I(className="fa fa-chart-network me-2"), "Metrics Cards"], className="d-flex align-items-center"), "value": "metrics"},
                                {"label": html.Span([html.I(className="fa fa-th-large me-2"), "Feature Cards"], className="d-flex align-items-center"), "value": "features"},
                                {"label": html.Span([html.I(className="fa fa-sidebar me-2"), "Right Panel (Alerts & Feed)"], className="d-flex align-items-center"), "value": "rightPanel"}
                            ],
                            value=["metrics", "features", "rightPanel"],
                            switch=True,
                            className="mb-3"
                        ),

                        html.Hr(),

                        html.H6([html.I(className="fa fa-eye me-2"), "Individual Widgets"], className="mb-3"),
                        dbc.Checklist(
                            id="individual-widget-toggles",
                            options=[
                                {"label": html.Span([html.I(className="fa fa-project-diagram me-2"), "Network Topology Graph"], className="d-flex align-items-center"), "value": "network-graph"},
                                {"label": html.Span([html.I(className="fa fa-chart-pie me-2"), "Protocol Distribution"], className="d-flex align-items-center"), "value": "protocol-chart"},
                                {"label": html.Span([html.I(className="fa fa-chart-area me-2"), "Traffic Timeline"], className="d-flex align-items-center"), "value": "traffic-timeline"},
                                {"label": html.Span([html.I(className="fa fa-network-wired me-2"), "Device List"], className="d-flex align-items-center"), "value": "device-list"},
                                {"label": html.Span([html.I(className="fa fa-exclamation-triangle me-2"), "Alert Feed"], className="d-flex align-items-center"), "value": "alert-feed"}
                            ],
                            value=["network-graph", "protocol-chart", "traffic-timeline", "device-list", "alert-feed"],
                            switch=True,
                            className="mb-3"
                        ),
                    ], className="p-3")
                ], label="Layout", tab_id="layout-tab"),

                # Display Preferences Tab
                dbc.Tab([
                    html.Div([
                        html.H6([html.I(className="fa fa-desktop me-2"), "View Density"], className="mt-3 mb-3"),
                        dbc.RadioItems(
                            id="view-density",
                            options=[
                                {"label": html.Span([html.I(className="fa fa-compress me-2"), "Compact - More data, less spacing"], className="d-flex align-items-center"), "value": "compact"},
                                {"label": html.Span([html.I(className="fa fa-grip-horizontal me-2"), "Comfortable - Balanced view (Default)"], className="d-flex align-items-center"), "value": "comfortable"},
                                {"label": html.Span([html.I(className="fa fa-expand me-2"), "Spacious - Easier to read"], className="d-flex align-items-center"), "value": "spacious"}
                            ],
                            value="comfortable",
                            className="mb-3"
                        ),

                        html.Hr(),

                        html.H6([html.I(className="fa fa-text-height me-2"), "Font Size"], className="mb-3"),
                        dbc.RadioItems(
                            id="font-size-pref",
                            options=[
                                {"label": "Small", "value": "small"},
                                {"label": "Medium (Default)", "value": "medium"},
                                {"label": "Large", "value": "large"}
                            ],
                            value="medium",
                            inline=True,
                            className="mb-3"
                        ),

                        html.Hr(),

                        html.H6([html.I(className="fa fa-film me-2"), "Animations"], className="mb-3"),
                        dbc.RadioItems(
                            id="animation-speed",
                            options=[
                                {"label": "Off - Best performance", "value": "off"},
                                {"label": "Fast", "value": "fast"},
                                {"label": "Normal (Default)", "value": "normal"},
                                {"label": "Slow - More fluid", "value": "slow"}
                            ],
                            value="normal",
                            className="mb-3"
                        ),
                    ], className="p-3")
                ], label="Display", tab_id="display-tab"),

                # Data & Refresh Tab
                dbc.Tab([
                    html.Div([
                        html.H6([html.I(className="fa fa-sync me-2"), "Auto-Refresh"], className="mt-3 mb-3"),
                        dbc.Switch(
                            id="auto-refresh-toggle",
                            label="Enable auto-refresh",
                            value=True,
                            className="mb-3"
                        ),

                        html.H6([html.I(className="fa fa-clock me-2"), "Refresh Interval"], className="mb-3"),
                        dbc.Select(
                            id="customize-refresh-interval-select",
                            options=[
                                {"label": "5 seconds - Real-time (Higher CPU usage)", "value": "5"},
                                {"label": "10 seconds - Default", "value": "10"},
                                {"label": "30 seconds - Balanced", "value": "30"},
                                {"label": "1 minute - Light", "value": "60"},
                                {"label": "5 minutes - Minimal", "value": "300"}
                            ],
                            value="10",
                            className="mb-3"
                        ),

                        html.Hr(),

                        html.H6([html.I(className="fa fa-database me-2"), "Data Retention"], className="mb-3"),
                        dbc.Select(
                            id="data-retention-select",
                            options=[
                                {"label": "24 hours", "value": "24"},
                                {"label": "7 days (Default)", "value": "168"},
                                {"label": "30 days", "value": "720"},
                                {"label": "90 days", "value": "2160"}
                            ],
                            value="168",
                            className="mb-3"
                        ),

                        html.Hr(),

                        html.H6([html.I(className="fa fa-chart-network me-2"), "Chart Preferences"], className="mb-3"),
                        dbc.Checklist(
                            id="chart-preferences",
                            options=[
                                {"label": "Show data points on charts", "value": "show-points"},
                                {"label": "Show grid lines", "value": "show-grid"},
                                {"label": "Smooth chart animations", "value": "smooth-charts"},
                                {"label": "Show tooltips on hover", "value": "chart-tooltips"}
                            ],
                            value=["show-grid", "smooth-charts", "chart-tooltips"],
                            switch=True
                        ),
                    ], className="p-3")
                ], label="Data", tab_id="data-tab"),

                # Notifications Tab
                dbc.Tab([
                    html.Div([
                        html.H6([html.I(className="fa fa-bell me-2"), "Alert Notifications"], className="mt-3 mb-3"),
                        dbc.Checklist(
                            id="notification-prefs",
                            options=[
                                {"label": html.Span([html.I(className="fa fa-volume-up me-2"), "Sound alerts"], className="d-flex align-items-center"), "value": "sound"},
                                {"label": html.Span([html.I(className="fa fa-comment me-2"), "Voice announcements (critical only)"], className="d-flex align-items-center"), "value": "voice"},
                                {"label": html.Span([html.I(className="fa fa-desktop me-2"), "Desktop notifications"], className="d-flex align-items-center"), "value": "desktop"},
                                {"label": html.Span([html.I(className="fa fa-envelope me-2"), "Email digest (daily)"], className="d-flex align-items-center"), "value": "email"}
                            ],
                            value=["sound"],
                            switch=True,
                            className="mb-3"
                        ),

                        html.Hr(),

                        html.H6([html.I(className="fa fa-filter me-2"), "Show Alert Severity"], className="mb-3"),
                        dbc.Checklist(
                            id="alert-severity-filter",
                            options=[
                                {"label": html.Span([html.I(className="fa fa-exclamation-circle text-danger me-2"), "Critical"], className="d-flex align-items-center"), "value": "critical"},
                                {"label": html.Span([html.I(className="fa fa-exclamation-triangle text-warning me-2"), "High"], className="d-flex align-items-center"), "value": "high"},
                                {"label": html.Span([html.I(className="fa fa-info-circle text-info me-2"), "Medium"], className="d-flex align-items-center"), "value": "medium"},
                                {"label": html.Span([html.I(className="fa fa-check-circle text-muted me-2"), "Low"], className="d-flex align-items-center"), "value": "low"}
                            ],
                            value=["critical", "high", "medium", "low"],
                            switch=True
                        ),
                    ], className="p-3")
                ], label="Notifications", tab_id="notifications-tab"),

                # Advanced Tab
                dbc.Tab([
                    html.Div([
                        html.H6([html.I(className="fa fa-cog me-2"), "Advanced Settings"], className="mt-3 mb-3"),

                        dbc.Button([
                            html.I(className="fa fa-download me-2"),
                            "Export Configuration"
                        ], id="export-config-btn", color="info", outline=True, className="w-100 mb-2"),

                        dbc.Button([
                            html.I(className="fa fa-upload me-2"),
                            "Import Configuration"
                        ], id="import-config-btn", color="info", outline=True, className="w-100 mb-2"),

                        html.Hr(),

                        dbc.Button([
                            html.I(className="fa fa-undo me-2"),
                            "Reset to Defaults"
                        ], id="reset-prefs-btn", color="warning", outline=True, className="w-100 mb-3"),

                        html.Hr(),

                        html.H6([html.I(className="fa fa-keyboard me-2"), "Keyboard Shortcuts"], className="mb-2"),
                        html.Small([
                            html.Strong("Enabled shortcuts:"), html.Br(),
                            "• N - Toggle notifications", html.Br(),
                            "• D - Jump to devices", html.Br(),
                            "• A - Jump to alerts", html.Br(),
                            "• P - Open preferences", html.Br(),
                            "• C - Open AI chat", html.Br(),
                            "• S - System info", html.Br(),
                            "• F - Firewall settings"
                        ], className="text-muted"),
                    ], className="p-3")
                ], label="Advanced", tab_id="advanced-tab"),
            ], id="customize-tabs", active_tab="layout-tab"),

            html.Hr(),

            dbc.Row([
                dbc.Col([
                    dbc.Button([
                        html.I(className="fa fa-times me-2"),
                        "Cancel"
                    ], id="cancel-prefs-btn", color="secondary", outline=True, className="w-100")
                ], width=6),
                dbc.Col([
                    dbc.Button([
                        html.I(className="fa fa-save me-2"),
                        "Save All Preferences"
                    ], id="save-widget-prefs", color="primary", className="w-100")
                ], width=6)
            ], className="mt-3")
        ], style={"maxHeight": "70vh", "overflowY": "auto"})
    ], id="customize-layout-modal", size="lg", is_open=False),

    # Quick Actions Components
    dcc.Download(id="download-export"),


    # Quick Actions Modal
    dbc.Modal([
        dbc.ModalHeader(dbc.ModalTitle([
            html.I(className="fa fa-bolt-lightning me-2 text-primary"),
            "Quick Actions"
        ])),
        dbc.ModalBody([
            html.P("Execute quick actions to manage your dashboard and network security.", className="text-muted mb-3"),
            html.Div(id="quick-actions-content"),  # Dynamic content based on user role
        ], style={"maxHeight": "70vh", "overflowY": "auto"}),
        dbc.ModalFooter([
            dbc.Button("Close", id="close-quick-actions-modal", color="secondary")
        ])
    ], id="quick-actions-modal", size="lg", is_open=False),

    dcc.Store(id='theme-store', storage_type='local', data={'theme': 'light'}),
    dcc.Store(id='voice-alert-store', storage_type='local', data={'enabled': False}),
    dcc.Store(id='user-role-store', storage_type='session', data={'role': 'viewer'}),  # Store user role for permission checks
    dcc.Store(id='quick-settings-store', storage_type='local', data={
        'general': {'auto_settings': ['auto-refresh', 'auto-save'], 'default_view': 'dashboard'},
        'notifications': {'browser': False, 'critical_only': False, 'sound': 'default', 'duration': 5000, 'position': 'top-right'},
        'network': {'interface': 'en0', 'options': ['show-offline'], 'scan_interval': 300, 'timeout': 10},
        'display': {'animation': 'normal', 'options': ['smooth-scroll', 'tooltips', 'timestamps'], 'font_size': 'medium'},
        'advanced': {'debug': [], 'performance': 'balanced'}
    }),
    dcc.Store(id='announced-alerts-store', storage_type='session', data={}),
    dcc.Store(id='onboarding-store', storage_type='local'),
    dcc.Store(id='onboarding-step-store', data=0),
    dcc.Store(id='keyboard-shortcut-store', data=None),

    # Dummy output for clientside callback
    html.Div(id='widget-visibility-dummy', style={'display': 'none'}),

    # Onboarding Modal
    dbc.Modal([
        dbc.ModalHeader(dbc.ModalTitle(id='onboarding-title')),
        dbc.ModalBody(id='onboarding-body'),
        dbc.ModalFooter([
            dbc.Button("Previous", id="onboarding-prev", color="secondary", className="me-auto cyber-button", disabled=True),
            dbc.Button("Next", id="onboarding-next", color="primary", className="cyber-button")
        ]),
    ], id="onboarding-modal", is_open=False, backdrop="static", size="lg"),

    # Alert Details Modal
    dbc.Modal([
        dbc.ModalHeader(dbc.ModalTitle(id="alert-details-title")),
        dbc.ModalBody(id="alert-details-body"),
        dbc.ModalFooter([
            dbc.Button([html.I(className="fa fa-robot me-2"), "Ask AI About This Alert"],
                      id="ask-ai-alert-btn", color="info", className="cyber-button me-2"),
            dbc.Button("Mark as Reviewed", id="alert-acknowledge-btn", color="success", className="cyber-button"),
            dbc.Button("Close", id="alert-close-btn", color="secondary", className="cyber-button")
        ]),
        # Collapsible AI Analysis Section
        dbc.Collapse(
            dbc.Card([
                dbc.CardHeader([
                    html.I(className="fa fa-robot me-2"),
                    html.Strong("AI Deep Analysis"),
                    dbc.Badge("POWERED BY HYBRID AI", color="success", className="ms-2")
                ], className="bg-info text-white"),
                dbc.CardBody(id="ai-alert-analysis-body", children=[
                    dbc.Spinner(html.Div("Analyzing alert with AI..."), color="info")
                ])
            ], className="mt-3"),
            id="ai-alert-analysis-collapse",
            is_open=False
        )
    ], id="alert-details-modal", is_open=False, size="xl"),

    # Store for current alert ID
    dcc.Store(id='current-alert-id', data=None),

    # Lockdown Confirmation Modal
    dbc.Modal([
        dbc.ModalHeader(
            dbc.ModalTitle("⚠️ Confirm Lockdown Mode"),
            close_button=True
        ),
        dbc.ModalBody([
            html.Div([
                # Icon card
                dbc.Card([
                    dbc.CardBody([
                        html.I(className="fa fa-exclamation-triangle fa-4x text-warning mb-2"),
                    ], className="text-center py-3 bg-light")
                ], className="mb-3 border-0"),

                # Question card
                dbc.Card([
                    dbc.CardBody([
                        html.H5("Are you sure you want to enable Lockdown Mode?", className="text-center mb-3"),
                        html.P("This will block all untrusted devices from accessing your network.", className="text-center text-muted mb-3"),
                        dbc.Row([
                            dbc.Col([
                                dbc.Card([
                                    dbc.CardBody([
                                        html.I(className="fa fa-shield-alt text-success me-2"),
                                        html.Strong("Trusted: "),
                                        html.Span(id='lockdown-trusted-count', children="0", className="text-success fw-bold")
                                    ], className="text-center py-2")
                                ], className="border-0 bg-light")
                            ], width=6),
                            dbc.Col([
                                dbc.Card([
                                    dbc.CardBody([
                                        html.I(className="fa fa-ban text-danger me-2"),
                                        html.Strong("Will Block: "),
                                        html.Span(id='lockdown-blocked-count', children="0", className="text-danger fw-bold")
                                    ], className="text-center py-2")
                                ], className="border-0 bg-light")
                            ], width=6)
                        ])
                    ])
                ], className="mb-3 border-warning"),
            ])
        ]),
        dbc.ModalFooter([
            dbc.Button([
                html.I(className="fa fa-times me-2"),
                "Cancel"
            ], id="lockdown-cancel", color="secondary", outline=True, className="cyber-button"),
            dbc.Button([
                html.I(className="fa fa-lock me-2"),
                "Enable Lockdown"
            ], id="lockdown-confirm", color="danger", className="cyber-button"),
        ]),
    ], id="lockdown-modal", is_open=False, centered=True, backdrop="static"),

    # Bulk Delete Confirmation Modal
    dbc.Modal([
        dbc.ModalHeader(
            dbc.ModalTitle("⚠️ Confirm Delete"),
            close_button=True
        ),
        dbc.ModalBody([
            html.Div([
                # Icon card
                dbc.Card([
                    dbc.CardBody([
                        html.I(className="fa fa-trash fa-4x text-danger mb-2"),
                    ], className="text-center py-3 bg-light")
                ], className="mb-3 border-0"),

                # Question card
                dbc.Card([
                    dbc.CardBody([
                        html.H5("Are you sure you want to delete selected devices?", className="text-center mb-3"),
                        html.Div([
                            html.I(className="fa fa-info-circle me-2 text-muted"),
                            html.Span(id="bulk-delete-confirm-message", className="text-muted")
                        ], className="text-center mb-2"),
                    ])
                ], className="mb-3 border-danger"),

                # Warning alert
                dbc.Alert([
                    html.I(className="fa fa-exclamation-triangle me-2"),
                    "This action cannot be undone!"
                ], color="warning", className="mb-0")
            ])
        ]),
        dbc.ModalFooter([
            dbc.Button([
                html.I(className="fa fa-times me-2"),
                "Cancel"
            ], id="bulk-delete-cancel", color="secondary", outline=True),
            dbc.Button([
                html.I(className="fa fa-trash me-2"),
                "Delete"
            ], id="bulk-delete-confirm", color="danger"),
        ]),
    ], id="bulk-delete-modal", is_open=False, centered=True, backdrop="static"),

    # User Delete Confirmation Modal
    dbc.Modal([
        dbc.ModalHeader(
            dbc.ModalTitle("⚠️ Confirm Delete User"),
            close_button=True
        ),
        dbc.ModalBody([
            html.Div([
                # Icon card
                dbc.Card([
                    dbc.CardBody([
                        html.I(className="fa fa-user-times fa-4x text-danger mb-2"),
                    ], className="text-center py-3 bg-light")
                ], className="mb-3 border-0"),

                # Question card
                dbc.Card([
                    dbc.CardBody([
                        html.H5("Are you sure you want to delete this user?", className="text-center mb-3"),
                        html.Div([
                            html.I(className="fa fa-user me-2 text-primary"),
                            html.Strong("Username: "),
                            html.Span(id="user-delete-confirm-username", className="text-primary")
                        ], className="text-center mb-2"),
                    ])
                ], className="mb-3 border-danger"),

                # Warning alerts
                dbc.Alert([
                    html.I(className="fa fa-exclamation-circle me-2"),
                    "This will permanently delete the user account and all associated data!"
                ], color="warning", className="mb-2"),
                dbc.Alert([
                    html.I(className="fa fa-exclamation-triangle me-2"),
                    "This action cannot be undone!"
                ], color="danger", className="mb-0")
            ])
        ]),
        dbc.ModalFooter([
            dbc.Button([
                html.I(className="fa fa-times me-2"),
                "Cancel"
            ], id="user-delete-cancel", color="secondary", outline=True),
            dbc.Button([
                html.I(className="fa fa-user-times me-2"),
                "Delete User"
            ], id="user-delete-confirm", color="danger"),
        ]),
    ], id="user-delete-modal", is_open=False, centered=True, backdrop="static"),
    dcc.Store(id='user-delete-id-store', data=None),

    # User Delete Confirmation Modal
    dbc.Modal([
        dbc.ModalHeader(dbc.ModalTitle("⚠️ Confirm Delete User")),
        dbc.ModalBody([
            html.Div([
                html.I(className="fa fa-user-times fa-3x text-danger mb-3"),
                html.H5("Are you sure you want to delete this user?"),
                html.P(id="user-delete-confirm-username", className="fw-bold text-muted"),
                html.Hr(),
                html.P("This will permanently delete the user account and all associated data!", className="text-warning fw-bold"),
                html.P("This action cannot be undone!", className="text-danger")
            ], className="text-center")
        ]),
        dbc.ModalFooter([
            dbc.Button("Cancel", id="user-delete-cancel", color="secondary"),
            dbc.Button("Delete User", id="user-delete-confirm", color="danger"),
        ]),
    ], id="user-delete-modal", is_open=False),
    dcc.Store(id='user-delete-id-store', data=None),

    # Block/Unblock Device Confirmation Modal
    dbc.Modal([
        dbc.ModalHeader(
            dbc.ModalTitle(id="block-device-modal-title"),
            close_button=True
        ),
        dbc.ModalBody([
            html.Div([
                # Icon card
                dbc.Card([
                    dbc.CardBody([
                        html.I(id="block-device-modal-icon", className="fa fa-ban fa-4x text-warning mb-2"),
                    ], className="text-center py-3 bg-light")
                ], className="mb-3 border-0"),

                # Question card
                dbc.Card([
                    dbc.CardBody([
                        html.H5(id="block-device-modal-question", className="text-center mb-3"),
                        html.Div([
                            html.I(className="fa fa-network-wired me-2 text-muted"),
                            html.Strong("Device IP: "),
                            html.Span(id="block-device-modal-ip", className="text-primary")
                        ], className="text-center mb-2"),
                    ])
                ], className="mb-3 border-primary"),

                # Warning card
                dbc.Alert(
                    id="block-device-modal-warning",
                    color="warning",
                    className="mb-0"
                )
            ])
        ]),
        dbc.ModalFooter([
            dbc.Button([
                html.I(className="fa fa-times me-2"),
                "Cancel"
            ], id="block-device-cancel", color="secondary", outline=True),
            dbc.Button(id="block-device-confirm-btn", color="danger"),
        ]),
    ], id="block-device-modal", is_open=False, centered=True, backdrop="static"),
    dcc.Store(id='block-device-ip-store', data=None),
    dcc.Store(id='block-device-action-store', data=None),

    # Toast Detail Modal - For viewing detailed toast messages
    dbc.Modal([
        dbc.ModalHeader(
            dbc.ModalTitle(id="toast-detail-modal-title"),
            close_button=True
        ),
        dbc.ModalBody([
            html.Div(id="toast-detail-modal-summary", className="mb-3 fw-bold"),
            html.Hr(),
            html.Div(id="toast-detail-modal-content", className="toast-detail-content")
        ]),
        dbc.ModalFooter([
            dbc.Button(
                "Close",
                id="toast-detail-modal-close",
                color="secondary",
                size="sm",
                className="cyber-button"
            )
        ])
    ], id="toast-detail-modal", size="lg", is_open=False, backdrop=True, keyboard=True, centered=True),

    # Toast History Modal - Popup modal for toast history (triggered from navbar)
    dbc.Modal([
        dbc.ModalHeader(dbc.ModalTitle([
            html.I(className="fa fa-history me-2"),
            "Toast History"
        ])),
        dbc.ModalBody([
            # Filters
            html.Div([
                dbc.Row([
                    dbc.Col([
                        dbc.Label("Category", size="sm"),
                        dbc.Select(
                            id="toast-history-category-filter",
                            options=[
                                {"label": "All Categories", "value": "all"},
                                {"label": "General", "value": "general"},
                                {"label": "Security", "value": "security"},
                                {"label": "Network", "value": "network"},
                                {"label": "Device", "value": "device"},
                                {"label": "User", "value": "user"},
                                {"label": "System", "value": "system"},
                                {"label": "Export", "value": "export"},
                                {"label": "Scan", "value": "scan"}
                            ],
                            value="all",
                            size="sm"
                        )
                    ], width=6),
                    dbc.Col([
                        dbc.Label("Type", size="sm"),
                        dbc.Select(
                            id="toast-history-type-filter",
                            options=[
                                {"label": "All Types", "value": "all"},
                                {"label": "Success", "value": "success"},
                                {"label": "Error", "value": "danger"},
                                {"label": "Warning", "value": "warning"},
                                {"label": "Info", "value": "info"}
                            ],
                            value="all",
                            size="sm"
                        )
                    ], width=6)
                ], className="mb-3"),
                dbc.Button(
                    [html.I(className="fas fa-trash me-2"), "Clear All"],
                    id="toast-history-clear-btn",
                    color="danger",
                    size="sm",
                    outline=True,
                    className="w-100 mb-3"
                )
            ]),

            # History list with loading
            dcc.Loading(
                id="toast-history-loader",
                type="default",
                children=html.Div(id="toast-history-list")
            )
        ])
    ], id="toast-history-modal", size="lg", is_open=False, scrollable=True, centered=True),

    # Notifications Modal (changed from Offcanvas to Modal)
    dbc.Modal([
        dbc.ModalHeader(dbc.ModalTitle([
            html.I(className="fa fa-bell me-2"),
            "Notifications ",
            html.Span(id="notification-count-display", className="badge bg-danger ms-2")
        ])),
        dbc.ModalBody([
            dcc.Loading(id="notification-loader", type="default", children=html.Div(id="notification-drawer-body"))
        ])
    ], id="notification-drawer", size="lg", is_open=False, scrollable=True, centered=True),

    html.Div(id='backdrop-overlay', style={'position': 'fixed', 'top': 0, 'left': 0, 'width': '100%', 'height': '100%', 'backgroundColor': 'rgba(0,0,0,0.5)', 'display': 'none', 'zIndex': 1040}),


    dbc.Modal([
        dbc.ModalHeader([
            dbc.ModalTitle("🤖 AI Assistant", className="flex-grow-1"),
            dbc.Button(
                [html.I(className="fa fa-trash me-1"), "Clear"],
                id="clear-chat-button",
                color="danger",
                size="sm",
                outline=True
            )
        ], className="d-flex align-items-center w-100"),
        dbc.ModalBody([
            # Loading indicator
            dcc.Loading(
                id="chat-loading",
                type="default",
                children=[
                    html.Div(
                        id='chat-history',
                        style={
                            'height': '450px',
                            'overflowY': 'auto',
                            'scrollBehavior': 'smooth',
                            'padding': '10px'
                        }
                    )
                ]
            ),
        ], id='chat-history-container', style={'padding': '0'}),
        dbc.ModalFooter([
            html.Div([
                dbc.InputGroup([
                    dbc.Input(
                        id='chat-input',
                        placeholder="Ask about your network security, baseline collection, alerts...",
                        className="cyber-input",
                        type="text",
                        debounce=False,
                        style={'fontSize': '14px'}
                    ),
                    dbc.Button(
                        [html.I(className="fa fa-paper-plane me-1"), "Send"],
                        id='chat-send-button',
                        color="primary",
                        className="cyber-button"
                    ),
                ]),
                html.Small(
                    "Press Enter to send • Shift+Enter for new line",
                    className="text-muted mt-2 d-block",
                    style={'fontSize': '11px'}
                )
            ], className="w-100")
        ], style={'padding': '15px'}),
    ], id="chat-modal", is_open=False, size="lg", scrollable=True),

    dcc.Store(id='chat-history-store', storage_type='session', data={'history': []}),

    # PHASE 6: Global Educational Tooltips
    html.Div([
        dbc.Tooltip(
            "Privacy Score (0-100): Measures how well your IoT devices protect your data. "
            "Based on cloud connections, encryption usage, and third-party trackers detected. "
            "Scores above 70 are good, above 85 are excellent. Click for detailed breakdown.",
            target="privacy-score-tooltip-trigger",
            placement="top"
        ),
        dbc.Tooltip(
            "Your current Privacy Score based on device cloud connections and encryption usage.",
            target="privacy-score-icon",
            placement="bottom"
        )
    ], style={"display": "none"}),

    # ============================================================================
    # SPOTLIGHT SEARCH - COMPONENTS
    # ============================================================================

    # Floating Search Button (Bottom Right)
    html.Div([
        dbc.Button([
            html.I(className="fa fa-search me-2"),
            html.Span("Search", className="d-none d-md-inline"),
            html.Kbd("⌘K", className="ms-2 d-none d-lg-inline",
                     style={"fontSize": "0.75rem", "padding": "2px 6px"})
        ],
        id="spotlight-search-button",
        color="primary",
        className="spotlight-floating-button shadow-lg",
        title="Search features (Cmd+K / Ctrl+K)"
        )
    ], className="spotlight-button-container"),

    # Spotlight Search Modal
    dbc.Modal([
        dbc.ModalBody([
            # Search Input (No Header - Clean Design)
            html.Div([
                html.I(className="fa fa-search spotlight-search-icon"),
                dbc.Input(
                    id="spotlight-search-input",
                    type="text",
                    placeholder="Search for features, modals, settings...",
                    className="spotlight-search-input",
                    autoComplete="off",
                    debounce=False,  # Real-time search without debounce
                    n_submit=0  # Track Enter key
                ),
                dbc.Button(
                    html.I(className="fa fa-times"),
                    id="spotlight-search-clear",
                    className="spotlight-clear-button",
                    color="link",
                    size="sm",
                    n_clicks=0
                )
            ], className="spotlight-search-bar"),

            # Results Container
            html.Div(id="spotlight-results-container", className="spotlight-results")
        ], className="p-0"),
    ],
    id="spotlight-search-modal",
    size="lg",
    is_open=False,
    backdrop=True,
    keyboard=True,
    centered=True,
    className="spotlight-modal"
    ),

    # Enhanced Custom Reports Modal with Tabs
    dbc.Modal([
        dbc.ModalHeader(
            dbc.ModalTitle([
                html.I(className="fa fa-file-alt me-2", style={"color": "#6366f1"}),
                "Advanced Report Builder"
            ]),
            close_button=True
        ),
        dbc.ModalBody([
            dbc.Tabs([
                # Report Builder Tab
                dbc.Tab([
                    html.Div([
                        # Template Selection with Visual Cards
                        html.H6([html.I(className="fa fa-file-alt me-2"), "Select Report Template"], className="mb-3"),
                        dbc.Row([
                            dbc.Col([
                                dbc.Card([
                                    dbc.CardBody([
                                        html.I(className="fa fa-chart-pie fa-2x mb-2 text-primary"),
                                        html.H6("Executive Summary", className="card-title"),
                                        html.P("High-level overview with KPIs", className="card-text small"),
                                        dbc.Button("Select", id="select-exec-template", color="primary", size="sm", outline=True, className="w-100")
                                    ], className="text-center")
                                ], className="shadow-sm mb-2 cursor-pointer hover-shadow", id="exec-template-card")
                            ], md=4),
                            dbc.Col([
                                dbc.Card([
                                    dbc.CardBody([
                                        html.I(className="fa fa-shield-alt fa-2x mb-2 text-danger"),
                                        html.H6("Security Audit", className="card-title"),
                                        html.P("Comprehensive security analysis", className="card-text small"),
                                        dbc.Button("Select", id="select-security-template", color="danger", size="sm", outline=True, className="w-100")
                                    ], className="text-center")
                                ], className="shadow-sm mb-2 cursor-pointer hover-shadow", id="security-template-card")
                            ], md=4),
                            dbc.Col([
                                dbc.Card([
                                    dbc.CardBody([
                                        html.I(className="fa fa-network-wired fa-2x mb-2 text-success"),
                                        html.H6("Network Activity", className="card-title"),
                                        html.P("Traffic and connection analysis", className="card-text small"),
                                        dbc.Button("Select", id="select-network-template", color="success", size="sm", outline=True, className="w-100")
                                    ], className="text-center")
                                ], className="shadow-sm mb-2 cursor-pointer hover-shadow", id="network-template-card")
                            ], md=4)
                        ], className="mb-3"),
                        dbc.Row([
                            dbc.Col([
                                dbc.Card([
                                    dbc.CardBody([
                                        html.I(className="fa fa-tablet-alt fa-2x mb-2 text-info"),
                                        html.H6("Device Inventory", className="card-title"),
                                        html.P("Complete device catalog", className="card-text small"),
                                        dbc.Button("Select", id="select-device-template", color="info", size="sm", outline=True, className="w-100")
                                    ], className="text-center")
                                ], className="shadow-sm mb-2 cursor-pointer hover-shadow", id="device-template-card")
                            ], md=4),
                            dbc.Col([
                                dbc.Card([
                                    dbc.CardBody([
                                        html.I(className="fa fa-bug fa-2x mb-2 text-warning"),
                                        html.H6("Threat Analysis", className="card-title"),
                                        html.P("Advanced threat detection", className="card-text small"),
                                        dbc.Button("Select", id="select-threat-template", color="warning", size="sm", outline=True, className="w-100")
                                    ], className="text-center")
                                ], className="shadow-sm mb-2 cursor-pointer hover-shadow", id="threat-template-card")
                            ], md=4)
                        ], className="mb-4"),

                        html.Hr(),

                        # Configuration Section
                        html.H6([html.I(className="fa fa-cog me-2"), "Report Configuration"], className="mb-3"),
                        dbc.Row([
                            dbc.Col([
                                html.Label("Selected Template", className="fw-bold mb-2"),
                                dbc.Input(id='report-template-select', value='executive_summary', disabled=True)
                            ], md=4),
                            dbc.Col([
                                html.Label("Export Format", className="fw-bold mb-2"),
                                dbc.Select(
                                    id='report-format-select',
                                    options=[
                                        {'label': '📄 PDF Report', 'value': 'pdf'},
                                        {'label': '📊 Excel Workbook', 'value': 'excel'},
                                        {'label': '📋 JSON Data', 'value': 'json'}
                                    ],
                                    value='pdf'
                                )
                            ], md=4),
                            dbc.Col([
                                html.Label("Time Range (Days)", className="fw-bold mb-2"),
                                dbc.Input(
                                    id='report-days-input',
                                    type='number',
                                    value=7,
                                    min=1,
                                    max=365,
                                    step=1
                                )
                            ], md=4)
                        ], className="mb-3"),

                        # Template Preview
                        dbc.Alert([
                            html.I(className="fa fa-info-circle me-2"),
                            html.Span(id='template-preview')
                        ], color="light", className="mb-3"),

                        # Progress and Status
                        html.Div([
                            # Status message
                            html.Div(id='report-status'),

                            # Progress bar (hidden by default)
                            html.Div([
                                html.Label("Report Generation Progress", className="fw-bold mb-2"),
                                dbc.Progress(
                                    id="report-progress-bar",
                                    value=0,
                                    striped=True,
                                    animated=True,
                                    color="success",
                                    className="mb-2"
                                ),
                                html.Small(id="report-progress-text", className="text-muted")
                            ], id="report-progress-container", style={"display": "none"})
                        ], className="mb-3"),

                        # Interval for polling job status
                        dcc.Interval(
                            id='report-job-poll',
                            interval=1000,  # Poll every second
                            disabled=True,
                            n_intervals=0
                        ),

                        # Store for current job ID
                        dcc.Store(id='current-report-job-id', data=None),

                        # Download Component
                        dcc.Download(id='download-custom-report')
                    ], className="p-3")
                ], label="Build Report", tab_id="build-tab"),

                # Recent Reports Tab
                dbc.Tab([
                    html.Div([
                        html.H6([html.I(className="fa fa-history me-2"), "Recent Reports"], className="mb-3"),
                        html.Div(id='recent-reports-list', children=[
                            dbc.Alert("No recent reports. Generate your first report!", color="info", className="text-center")
                        ])
                    ], className="p-3")
                ], label="Recent Reports", tab_id="recent-tab")
            ], id="report-builder-tabs", active_tab="build-tab")
        ]),
        dbc.ModalFooter([
            dbc.Button("Close", id="close-reports-modal", color="secondary", outline=True),
            dbc.Button([
                html.I(className="fa fa-download me-2"),
                "Generate Report"
            ], id="generate-report-btn", color="primary", className="ms-2")
        ])
    ], id="custom-reports-modal", size="xl", is_open=False),

    # Store for feature catalog (client-side)
    dcc.Store(id='spotlight-catalog-store', data=SEARCH_FEATURE_CATALOG),

    # Store for filtered search results (client-side fuzzy matching)
    dcc.Store(id='spotlight-filtered-results', data=SEARCH_FEATURE_CATALOG[:10]),

    # Store for selected result index (for keyboard navigation)
    dcc.Store(id='spotlight-selected-index', data=0),

    # Store to track which modal to open from spotlight
    dcc.Store(id='spotlight-modal-trigger', data={}),

    # Store for category filter
    dcc.Store(id='spotlight-category-filter', data=None)

], fluid=True, className="dashboard-container p-3")

# ============================================================================
# MAIN APP LAYOUT - WITH AUTHENTICATION
# ============================================================================
# ============================================================================
# MAIN APP LAYOUT - WITH AUTHENTICATION
# ============================================================================

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
    'primary': ['analytics-card-btn', 'device-mgmt-card-btn', 'firmware-card-btn'],  # xl-card, large
    'secondary': ['system-card-btn', 'threat-map-card-btn', 'protocol-card-btn',
                  'smarthome-card-btn', 'compliance-card-btn'],  # medium
    'tertiary': []  # small, compact - all others
}

app.layout = html.Div([
    dcc.Location(id='url', refresh=False),
    dcc.Store(id='user-session', storage_type='session'),
    # Use 'memory' storage to prevent login toast from persisting across page refreshes
    dcc.Store(id='auth-notification-store', storage_type='memory'),
    # Store for 2FA setup data (secret, QR code, backup codes)
    dcc.Store(id='totp-setup-data', storage_type='memory'),
    # Dashboard template store - global to prevent callback errors
    dcc.Store(id='dashboard-template-store', storage_type='session'),
    # Store for biometric credential to remove
    dcc.Store(id='biometric-remove-credential-id', storage_type='memory'),

    # Confirmation Modal for Biometric Removal
    dbc.Modal([
        dbc.ModalHeader(dbc.ModalTitle([
            html.I(className="fa fa-exclamation-triangle me-2 text-warning"),
            "Remove Biometric Device?"
        ])),
        dbc.ModalBody([
            html.P([
                "Are you sure you want to remove this biometric credential? ",
                "You will need to register again if you want to use this device for biometric login."
            ]),
            html.Div([
                html.I(className="fa fa-info-circle me-2 text-info"),
                html.Small("This action cannot be undone.", className="text-muted")
            ], className="alert alert-warning py-2")
        ]),
        dbc.ModalFooter([
            dbc.Button("Cancel", id="cancel-remove-biometric", color="secondary", outline=True, className="me-2"),
            dbc.Button([
                html.I(className="fa fa-trash me-2"),
                "Remove Device"
            ], id="confirm-remove-biometric", color="danger")
        ])
    ], id="confirm-remove-biometric-modal", is_open=False, centered=True),

    html.Div(id='page-content'),

    # Global toast container - appears on all pages (login & dashboard)
    # Positioning handled by individual toasts via ToastManager
    # Start with empty children to prevent flash of old toasts on refresh
    html.Div(id="toast-container", children=[])
])


# ============================================================================
# HELPER FUNCTIONS (Database Queries)
# ============================================================================


# Simple helper functions (cached queries disabled due to performance issues)
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
        # Use connections table instead of network_traffic
        cursor.execute("SELECT SUM(bytes_sent + bytes_received) as total FROM connections WHERE timestamp > datetime('now', '-1 hour')")
        row = cursor.fetchone()
        total = row['total'] or 0
        # Format bytes
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


# ============================================================================
# WEBSOCKET BACKGROUND THREAD
# ============================================================================

thread = None
thread_lock = threading.Lock()

def background_thread():
    while True:
        socketio.sleep(3)
        data_payload = {}

        # Collect system metrics using psutil
        try:
            data_payload['cpu_percent'] = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            data_payload['ram_percent'] = memory.percent
        except Exception as e:
            logger.error(f"Error collecting system metrics: {e}")
            data_payload['cpu_percent'] = 0
            data_payload['ram_percent'] = 0

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
                pass

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
                pass

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
# EMAIL VERIFICATION HELPERS
# ============================================================================

# Email verification storage (in production, use Redis or database)
verification_codes = {}

def send_verification_email(email, code):
    """Send verification code via email"""
    try:
        # Get SMTP settings from environment variables
        smtp_server = os.getenv('EMAIL_SMTP_HOST', 'smtp.gmail.com')
        smtp_port = int(os.getenv('EMAIL_SMTP_PORT', '587'))
        smtp_user = os.getenv('EMAIL_SMTP_USER', '')
        smtp_password = os.getenv('EMAIL_SMTP_PASSWORD', '')
        sender_email = os.getenv('EMAIL_SENDER_EMAIL', smtp_user)

        if not smtp_user or not smtp_password:
            logger.warning("SMTP credentials not configured. Verification code: " + code)
            return False

        # Create message
        msg = MIMEMultipart()
        msg['From'] = f"IoTSentinel Security <{sender_email}>"
        msg['To'] = email
        msg['Subject'] = 'IoTSentinel - Email Verification Code'

        body = f"""
        <html>
            <body>
                <h2>IoTSentinel Email Verification</h2>
                <p>Your verification code is:</p>
                <h1 style="color: #60a5fa; letter-spacing: 5px;">{code}</h1>
                <p>This code will expire in 10 minutes.</p>
                <p>If you didn't request this code, please ignore this email.</p>
            </body>
        </html>
        """

        msg.attach(MIMEText(body, 'html'))

        # Send email
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_password)
            server.send_message(msg)

        return True
    except Exception as e:
        logger.error(f"Failed to send verification email: {e}")
        return False


# ============================================================================
# FLASK ROUTES
# ============================================================================

@server.route('/verify/<code>')
def verify_email(code):
    """Redirect to registration page with verification code for user to enter"""
    # Validate that the code exists and is not expired
    import sqlite3
    from datetime import datetime

    db_path = config.get('database', 'path', fallback='data/database/iot_monitor.db')

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        cursor.execute("""
            SELECT email, expires_at, verified
            FROM email_verification_codes
            WHERE code = ?
        """, (code,))

        result = cursor.fetchone()
        conn.close()

        if not result:
            # Invalid code
            return """
            <!DOCTYPE html>
            <html>
            <head>
                <title>Invalid Code - IoTSentinel</title>
                <style>
                    body {
                        font-family: Arial, sans-serif;
                        display: flex;
                        justify-content: center;
                        align-items: center;
                        height: 100vh;
                        margin: 0;
                        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    }
                    .container {
                        background: white;
                        padding: 40px;
                        border-radius: 10px;
                        box-shadow: 0 10px 25px rgba(0,0,0,0.2);
                        text-align: center;
                        max-width: 450px;
                    }
                    .error-icon {
                        font-size: 64px;
                        color: #ef4444;
                        margin-bottom: 20px;
                    }
                    h1 {
                        color: #333;
                        margin-bottom: 10px;
                    }
                    p {
                        color: #666;
                        line-height: 1.6;
                    }
                    .login-btn {
                        display: inline-block;
                        margin-top: 20px;
                        padding: 12px 30px;
                        background: #667eea;
                        color: white;
                        text-decoration: none;
                        border-radius: 5px;
                        transition: background 0.3s;
                    }
                    .login-btn:hover {
                        background: #5568d3;
                    }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="error-icon">✗</div>
                    <h1>Invalid Verification Code</h1>
                    <p>The verification code is invalid or does not exist.</p>
                    <p>Please check the link in your email or request a new verification code.</p>
                    <a href="/" class="login-btn">Go to Registration</a>
                </div>
            </body>
            </html>
            """

        email, expires_at, verified = result

        if verified:
            # Already verified
            return """
            <!DOCTYPE html>
            <html>
            <head>
                <title>Already Verified - IoTSentinel</title>
                <style>
                    body {
                        font-family: Arial, sans-serif;
                        display: flex;
                        justify-content: center;
                        align-items: center;
                        height: 100vh;
                        margin: 0;
                        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    }
                    .container {
                        background: white;
                        padding: 40px;
                        border-radius: 10px;
                        box-shadow: 0 10px 25px rgba(0,0,0,0.2);
                        text-align: center;
                        max-width: 400px;
                    }
                    .info-icon {
                        font-size: 64px;
                        color: #3b82f6;
                        margin-bottom: 20px;
                    }
                    h1 {
                        color: #333;
                        margin-bottom: 10px;
                    }
                    p {
                        color: #666;
                        line-height: 1.6;
                    }
                    .login-btn {
                        display: inline-block;
                        margin-top: 20px;
                        padding: 12px 30px;
                        background: #667eea;
                        color: white;
                        text-decoration: none;
                        border-radius: 5px;
                        transition: background 0.3s;
                    }
                    .login-btn:hover {
                        background: #5568d3;
                    }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="info-icon">ℹ</div>
                    <h1>Already Verified</h1>
                    <p>This email has already been verified.</p>
                    <p>You can now login to your IoTSentinel account.</p>
                    <a href="/" class="login-btn">Go to Login</a>
                </div>
            </body>
            </html>
            """

        # Check if expired
        if datetime.fromisoformat(expires_at) < datetime.now():
            return """
            <!DOCTYPE html>
            <html>
            <head>
                <title>Code Expired - IoTSentinel</title>
                <style>
                    body {
                        font-family: Arial, sans-serif;
                        display: flex;
                        justify-content: center;
                        align-items: center;
                        height: 100vh;
                        margin: 0;
                        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    }
                    .container {
                        background: white;
                        padding: 40px;
                        border-radius: 10px;
                        box-shadow: 0 10px 25px rgba(0,0,0,0.2);
                        text-align: center;
                        max-width: 450px;
                    }
                    .warning-icon {
                        font-size: 64px;
                        color: #f59e0b;
                        margin-bottom: 20px;
                    }
                    h1 {
                        color: #333;
                        margin-bottom: 10px;
                    }
                    p {
                        color: #666;
                        line-height: 1.6;
                    }
                    .login-btn {
                        display: inline-block;
                        margin-top: 20px;
                        padding: 12px 30px;
                        background: #667eea;
                        color: white;
                        text-decoration: none;
                        border-radius: 5px;
                        transition: background 0.3s;
                    }
                    .login-btn:hover {
                        background: #5568d3;
                    }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="warning-icon">⏱</div>
                    <h1>Verification Code Expired</h1>
                    <p>This verification code has expired.</p>
                    <p>Please request a new verification code from the registration page.</p>
                    <a href="/" class="login-btn">Go to Registration</a>
                </div>
            </body>
            </html>
            """

        # Valid code - redirect to registration page to enter the code
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Enter Verification Code - IoTSentinel</title>
            <meta http-equiv="refresh" content="3;url=/?verify={code}">
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    height: 100vh;
                    margin: 0;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                }}
                .container {{
                    background: white;
                    padding: 40px;
                    border-radius: 10px;
                    box-shadow: 0 10px 25px rgba(0,0,0,0.2);
                    text-align: center;
                    max-width: 500px;
                }}
                .info-icon {{
                    font-size: 64px;
                    color: #667eea;
                    margin-bottom: 20px;
                }}
                h1 {{
                    color: #333;
                    margin-bottom: 10px;
                }}
                p {{
                    color: #666;
                    line-height: 1.6;
                    margin: 10px 0;
                }}
                .code-display {{
                    background: #f3f4f6;
                    padding: 15px 25px;
                    border-radius: 8px;
                    font-size: 24px;
                    font-weight: bold;
                    letter-spacing: 3px;
                    color: #667eea;
                    margin: 20px 0;
                    font-family: 'Courier New', monospace;
                }}
                .redirect-text {{
                    color: #999;
                    font-size: 14px;
                    margin-top: 20px;
                }}
                .spinner {{
                    border: 3px solid #f3f4f6;
                    border-top: 3px solid #667eea;
                    border-radius: 50%;
                    width: 30px;
                    height: 30px;
                    animation: spin 1s linear infinite;
                    margin: 20px auto 10px;
                }}
                @keyframes spin {{
                    0% {{ transform: rotate(0deg); }}
                    100% {{ transform: rotate(360deg); }}
                }}
                .login-btn {{
                    display: inline-block;
                    margin-top: 15px;
                    padding: 12px 30px;
                    background: #667eea;
                    color: white;
                    text-decoration: none;
                    border-radius: 5px;
                    transition: background 0.3s;
                }}
                .login-btn:hover {{
                    background: #5568d3;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="info-icon">📧</div>
                <h1>Enter Your Verification Code</h1>
                <p>Please enter this code in the registration form:</p>
                <div class="code-display">{code}</div>
                <p style="font-size: 14px; color: #888;">Copy this code and paste it in the verification field.</p>
                <div class="spinner"></div>
                <p class="redirect-text">Redirecting to registration page in 3 seconds...</p>
                <a href="/?verify={code}" class="login-btn">Go Now</a>
            </div>
        </body>
        </html>
        """

    except Exception as e:
        logger.error(f"Error in verify_email route: {e}")
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Error - IoTSentinel</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    height: 100vh;
                    margin: 0;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                }
                .container {
                    background: white;
                    padding: 40px;
                    border-radius: 10px;
                    box-shadow: 0 10px 25px rgba(0,0,0,0.2);
                    text-align: center;
                    max-width: 400px;
                }
                .error-icon {
                    font-size: 64px;
                    color: #ef4444;
                    margin-bottom: 20px;
                }
                h1 {
                    color: #333;
                    margin-bottom: 10px;
                }
                p {
                    color: #666;
                    line-height: 1.6;
                }
                .retry-btn {
                    display: inline-block;
                    margin-top: 20px;
                    padding: 12px 30px;
                    background: #667eea;
                    color: white;
                    text-decoration: none;
                    border-radius: 5px;
                    transition: background 0.3s;
                }
                .retry-btn:hover {
                    background: #5568d3;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="error-icon">✗</div>
                <h1>Verification Error</h1>
                <p>An error occurred while processing your verification.</p>
                <p>Please try again or contact support.</p>
                <a href="/" class="retry-btn">Back to Login</a>
            </div>
        </body>
        </html>
        """

# ============================================================================
# REGISTER ALL CALLBACKS FROM MODULES
# ============================================================================
from dashboard.callbacks import register_all_callbacks
register_all_callbacks(app, login_layout, dashboard_layout)

# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

def main():
    host = '127.0.0.1'
    port = config.get('dashboard', 'port', default=8050)
    debug = True

    # Suppress Flask/Werkzeug HTTP access logs (keeps error logs)
    import logging as log
    log.getLogger('werkzeug').setLevel(log.ERROR)
    log.getLogger('socketio').setLevel(log.WARNING)
    log.getLogger('engineio').setLevel(log.WARNING)

    logger.info("=" * 70)
    logger.info("IoTSentinel Dashboard - Enhanced Educational Edition")
    logger.info("=" * 70)
    logger.info(f"Dashboard URL: http://{host}:{port}")
    logger.info("")

    # Check AI Assistant status
    ai_status = ai_assistant.get_status_message()
    logger.info(f"🤖 AI Chat: {ai_status}")

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

    # Check Report Scheduler status
    scheduler_status = "📅 Report Scheduler: "
    if report_scheduler:
        scheduler_status += "✅ ACTIVE (Automated reports enabled)"
    else:
        scheduler_status += "❌ DISABLED (Check email configuration)"
    logger.info(scheduler_status)
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

    logger.info("✨ ADVANCED REPORTING & ANALYTICS:")
    logger.info("  ✓ 📊 Trend Analysis (Time-series, Anomaly detection)")
    logger.info("  ✓ 📈 Executive Summaries (Security posture, KPIs)")
    logger.info("  ✓ 📄 Professional Reports (PDF, Excel, JSON, HTML)")
    logger.info("  ✓ 📅 Automated Scheduling (Cron & Interval-based)")
    logger.info("  ✓ 📧 Email Attachments (PDF/Excel reports)")
    logger.info("  ✓ 📮 Daily Security Digest (Automated summaries)")
    logger.info("")

    logger.info("✨ CORE FEATURES:")
    logger.info("  ✓ Interactive onboarding wizard (6 steps)")
    logger.info("  ✓ Device details modal with trust management")
    logger.info("  ✓ Lockdown mode with confirmation")
    logger.info("  ✓ Keyboard shortcuts (N/D/A/P/C/S/F/U/T/H/?/Esc)")
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
        # Note: use_reloader=False prevents double initialization in debug mode
        socketio.run(app.server, host=host, port=port, debug=debug,
                    allow_unsafe_werkzeug=True, log_output=False, use_reloader=False)
    except Exception as e:
        logger.error(f"SocketIO failed to start: {e}")
        logger.info("Falling back to standard Dash server (WebSockets disabled)...")

        # Suppress werkzeug logs for fallback server too
        import logging as log
        werkzeug_log = log.getLogger('werkzeug')
        werkzeug_log.setLevel(log.ERROR)

        # Note: use_reloader=False prevents double initialization in debug mode
        app.run(host=host, port=port, debug=debug, use_reloader=False)


# WEBAUTHN / PASSKEY API ENDPOINTS
# ============================================================================

@app.server.route('/api/webauthn/generate-authentication-options', methods=['POST'])
def generate_webauthn_auth_options():
    """Generate WebAuthn authentication options for passkey login"""
    try:
        if not webauthn_handler:
            return jsonify({'error': 'WebAuthn not configured'}), 500

        # Generate authentication options (no username required - discoverable credentials)
        options = webauthn_handler.generate_authentication_options()

        return jsonify(options), 200

    except Exception as e:
        logger.error(f"Error generating WebAuthn auth options: {e}")
        return jsonify({'error': str(e)}), 500


@app.server.route('/api/webauthn/verify-authentication', methods=['POST'])
def verify_webauthn_authentication():
    """Verify WebAuthn authentication response and log user in"""
    try:
        if not webauthn_handler:
            return jsonify({'success': False, 'error': 'WebAuthn not configured'}), 500

        data = request.get_json()
        credential_data = data.get('credential')
        challenge_key = data.get('challenge_key')

        if not credential_data or not challenge_key:
            return jsonify({'success': False, 'error': 'Missing required data'}), 400

        # Verify authentication
        user_id = webauthn_handler.verify_authentication(credential_data, challenge_key)

        if user_id:
            # Get user and log them in
            user = auth_manager.get_user_by_id(user_id)
            if user:
                login_user(user, remember=True)

                # Log audit
                log_user_action(
                    audit_logger,
                    action='passkey_login',
                    target_username=user.username,
                    success=True
                )

                logger.info(f"User '{user.username}' logged in via passkey/biometric")
                return jsonify({'success': True, 'username': user.username}), 200

        return jsonify({'success': False, 'error': 'Authentication failed'}), 401

    except Exception as e:
        logger.error(f"Error verifying WebAuthn authentication: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500



# ============================================================================
# APP LAUNCHER
# ============================================================================

if __name__ == "__main__":
    main()
