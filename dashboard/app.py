#!/usr/bin/env python3
"""
IoTSentinel Dashboard - Enhanced Educational Transparency Edition
=================================================================
Main application entry point. Creates the Dash app, configures Flask,
sets up authentication, defines layouts, registers callbacks, and runs the server.

All services, constants, and helper functions are imported from dashboard.shared
(single source of truth) to avoid duplicate initialization.
"""
# Eventlet monkey-patching MUST be done before any other imports
import eventlet
eventlet.monkey_patch()

import json
import logging
import math
import os
import secrets
import smtplib
import sqlite3
import threading
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path
from typing import List

import dash
import dash_bootstrap_components as dbc
import pandas as pd
import psutil
from dash import (dcc, html, Input, ALL)
from flask import (request, redirect, jsonify, send_file)
from flask_login import (LoginManager, login_user, login_required, current_user)
from flask_socketio import SocketIO

# Setup path so 'dashboard.shared' can be resolved when running directly
import sys
_project_root = Path(__file__).parent.parent
sys.path.insert(0, str(_project_root))

# ---------------------------------------------------------------------------
# Import EVERYTHING from shared.py (single source of truth for services)
# ---------------------------------------------------------------------------
from dashboard.shared import (
    # Core infrastructure
    config, project_root,
    logger, DB_PATH, db_manager,
    # Authentication & security
    auth_manager, audit_logger, rate_limiter, login_rate_limiter,
    security_audit_logger, totp_manager,
    # RBAC
    PermissionManager, can_export_data, can_manage_devices,
    can_block_devices, can_delete_data, ROLES,
    # Audit helpers
    log_device_action, log_bulk_action, log_emergency_mode,
    log_user_action, log_settings_change,
    # User model
    User,
    # Reporting & analytics
    trend_analyzer, report_builder, template_manager, report_queue,
    # Alerts & notifications
    notification_dispatcher, alert_service, email_notifier, report_scheduler,
    # IoT modules
    iot_intelligence, iot_protocol_analyzer, iot_threat_detector,
    smart_home_manager, privacy_monitor, network_segmentation, firmware_manager,
    # Innovation features
    network_security_scorer, privacy_analyzer,
    # Device management
    group_manager, chart_factory, export_helper,
    # Threat intelligence
    threat_intel, THREAT_INTEL_ENABLED, ABUSEIPDB_API_KEY, THREAT_INTEL_CACHE_HOURS,
    # AI & ML
    ai_assistant, inference_engine, smart_recommender,
    traffic_forecaster, attack_tracker, nl_to_sql,
    # OAuth & WebAuthn (placeholders — real init below after Flask app created)
    GoogleOAuthHandler, is_oauth_configured,
    WebAuthnHandler, is_webauthn_available,
    # Toast & chart utilities
    ToastManager, TOAST_DURATIONS,
    ChartFactory, SEVERITY_COLORS, RISK_COLORS, SEVERITY_BADGE_COLORS,
    DashExportHelper,
    # Constants
    MITRE_ATTACK_MAPPING, SEVERITY_CONFIG, DEVICE_STATUS_COLORS, DEVICE_TYPE_ICONS,
    DASHBOARD_TEMPLATES, FEATURE_CATEGORIES, CARD_PRIORITIES,
    # Database helper functions
    get_db_connection, format_timestamp_relative,
    create_timestamp_display, get_device_today_stats, get_alert_with_context,
    get_device_details, get_devices_with_status,
    # Query helpers
    get_latest_alerts, get_bandwidth_stats, get_threats_blocked,
    get_device_status, get_device_baseline, get_latest_alerts_content,
    # UI helper functions
    format_bytes, create_status_indicator, get_device_icon_data,
    create_device_icon, create_threat_intel_badge,
    create_device_skeleton, create_device_list_skeleton,
    create_baseline_comparison_chart, create_educational_explanation,
    # Mobile UI
    create_mobile_tabbar,
    # Shell chrome
    create_sidebar, create_header,
    VERSION,
)

# Also need these for WebSocket/layout (re-export from shared)
from dash_extensions import WebSocket
import dash_cytoscape as cyto
from utils.topology_icons import device_icon_uri, router_icon_uri
from utils.capture_mode import capture_mode_name

# App-level logger (shows as __main__ when run directly)
app_logger = logging.getLogger(__name__)

# ============================================================================
# DASH APP CREATION
# ============================================================================

# Minify first-party CSS at boot (custom/mobile-responsive/skeleton) and tell
# Dash to inject only the .min.css copies; falls back to sources on failure.
from dashboard.asset_build import ensure_minified_css, ensure_pwa_icons
_assets_dir = str(Path(__file__).parent / 'assets')
_assets_ignore = ensure_minified_css(_assets_dir) or ""
ensure_pwa_icons(_assets_dir)  # square home-screen / install icons from logo.png

app = dash.Dash(
    __name__,
    # bootstrap.min.css and fontawesome.min.css live in dashboard/assets/ and are
    # auto-served by Dash — listing them here too caused each to load twice.
    external_stylesheets=[],
    external_scripts=[],
    title="IoTSentinel - AI-Powered Edge Network Guardian",
    suppress_callback_exceptions=True,
    compress=True,
    update_title=None,
    assets_ignore=_assets_ignore,
)

# FOUC prevention: inject critical background + dark-mode detection into <head>
# before any external CSS loads. Eliminates white flash on Pi's slow GPU.
app.index_string = """<!DOCTYPE html>
<html>
<head>
{%metas%}
<title>{%title%}</title>
{%favicon%}
<style>
html,body{margin:0;background-color:#f0f4f8}
html.iot-dark,html.iot-dark body{background-color:#0f172a}
</style>
<script>
(function(){try{if(localStorage.getItem('iotsentinel-theme')==='dark'){document.documentElement.classList.add('iot-dark');}}catch(e){}}());
</script>
<link rel="manifest" href="/manifest.webmanifest">
<meta name="theme-color" content="#f0f4f8" id="iot-theme-color">
<meta name="mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<meta name="apple-mobile-web-app-title" content="IoTSentinel">
<link rel="apple-touch-icon" href="/assets/apple-touch-icon.png">
{%css%}
</head>
<body>
{%app_entry%}
<footer>
{%config%}
{%scripts%}
{%renderer%}
</footer>
<script>
// Register the PWA service worker only on origins with browser-trusted TLS:
// - localhost / 127.0.0.1: always trusted
// - *.ts.net: Tailscale-issued cert, trusted by all browsers
// NOT on iotsentinel.local or LAN IPs: those use a self-signed cert. Even when
// the user clicks "proceed" through the cert warning on the main frame, the
// service worker's own fetch() calls run in a background context that does NOT
// inherit that decision -- the browser blocks them with "SSL certificate error
// when fetching the script", preventing Dash component bundles from loading and
// causing TypeError: Cannot read properties of undefined (reading 'apply') in
// the Dash renderer. On untrusted domains we actively unregister any stale
// worker that may have been installed on a previous visit.
if ('serviceWorker' in navigator) {
  var host = location.hostname;
  var trustedOrigin = (host === 'localhost' || host === '127.0.0.1' ||
                       host.endsWith('.ts.net'));
  if (trustedOrigin && location.protocol === 'https:') {
    window.addEventListener('load', function () {
      navigator.serviceWorker.register('/sw.js', { scope: '/' }).catch(function () {});
    });
  } else {
    // Unregister any stale service worker so it cannot intercept script fetches
    // and cause SSL cert errors on self-signed HTTPS or plain HTTP.
    navigator.serviceWorker.getRegistrations().then(function (regs) {
      regs.forEach(function (r) { r.unregister(); });
    }).catch(function () {});
  }
}
</script>
</body>
</html>"""

# SocketIO verbose logging only when debug is explicitly enabled
_debug_sio = os.getenv('IOTSENTINEL_DEBUG', 'false').lower() in ('true', '1', 'yes')
# '*' is intentional: Tailscale Funnel proxies requests from a *.ts.net origin,
# so a locked-down allowlist would break remote access.
# To restrict on a LAN-only install: IOTSENTINEL_CORS_ORIGINS=http://localhost:8050
_cors_origins = os.getenv('IOTSENTINEL_CORS_ORIGINS', '*')

socketio = SocketIO(
    app.server,
    cors_allowed_origins=_cors_origins,
    async_mode='eventlet',
    logger=_debug_sio,
    engineio_logger=_debug_sio,
    websocket_ping_interval=25,
    websocket_ping_timeout=60
)

# Plain WebSocket endpoint for dash-extensions WebSocket component.
# flask-socketio speaks Socket.IO protocol; dash-extensions.WebSocket expects
# plain WS at /ws — these two live side-by-side without conflict.
from flask_sock import Sock as _FlaskSock
_plain_sock = _FlaskSock(app.server)
_plain_ws_clients = set()

@_plain_sock.route('/ws')
def _plain_ws_handler(ws):
    _plain_ws_clients.add(ws)
    # The dashboard delivers all live data over THIS plain socket (the page loads
    # no Socket.IO client), so the producer thread must be started here too — not
    # only from the Socket.IO 'connect' handler. Without this, a browser reaching
    # the Pi over plain LAN/hotspot http gets an empty dashboard (no devices,
    # graphs or metrics) because the background thread is never spun up.
    _ensure_background_thread()
    try:
        while True:
            ws.receive(timeout=60)  # yield to scheduler; detect dead connections
    except Exception:
        pass
    finally:
        _plain_ws_clients.discard(ws)

# Inject into shared module so callback modules can access them
import dashboard.shared as _shared
_shared.app = app
_shared.socketio_instance = socketio

server = app.server

# ============================================================================
# FLASK SERVER CONFIGURATION
# ============================================================================

secret_key = os.getenv('FLASK_SECRET_KEY')
if not secret_key or secret_key == 'your-secret-key-change-this-in-production-please-use-at-least-32-characters':  # pragma: allowlist secret
    logger.warning("Using auto-generated SECRET_KEY. Set FLASK_SECRET_KEY in .env for production!")
    secret_key = secrets.token_hex(32)
server.config['SECRET_KEY'] = secret_key

login_manager = LoginManager()
login_manager.init_app(server)
login_manager.login_view = '/login'

# Remember Me cookie configuration. 30 days by default (was 7) so users on the
# LAN-over-HTTP path, where biometrics can't run (WebAuthn needs HTTPS/localhost),
# are not forced to re-enter their password every week. Tunable via config.
#
# HTTPS-on-LAN: when enabled (config security.https_enabled or env IOTSENTINEL_HTTPS),
# the dashboard serves a self-signed cert so biometrics + the PWA service worker
# work and passwords are encrypted on the LAN. The launch block generates the cert
# and downgrades these Secure flags if cert generation fails (so HTTP login still
# works). Default OFF until verified on hardware.
try:
    _https_cfg = bool(config.get('security', 'https_enabled', default=False))
except Exception:
    _https_cfg = False
_use_https = _https_cfg or os.getenv('IOTSENTINEL_HTTPS', 'false').lower() in ('true', '1', 'yes')
try:
    _remember_days = int(config.get('security', 'remember_cookie_days', default=30))
except Exception:
    _remember_days = 30
server.config['REMEMBER_COOKIE_DURATION'] = timedelta(days=_remember_days)
server.config['REMEMBER_COOKIE_SECURE'] = _use_https  # Only True when served over HTTPS
server.config['REMEMBER_COOKIE_HTTPONLY'] = True
server.config['REMEMBER_COOKIE_SAMESITE'] = 'Strict'
server.config['SESSION_COOKIE_SECURE'] = _use_https
server.config['SESSION_COOKIE_HTTPONLY'] = True
server.config['SESSION_COOKIE_SAMESITE'] = 'Strict'

# ============================================================================
# REVERSE PROXY SUPPORT (set IOTSENTINEL_BEHIND_PROXY=true when behind nginx)
# ============================================================================
if os.getenv('IOTSENTINEL_BEHIND_PROXY', 'false').lower() in ('true', '1', 'yes'):
    from werkzeug.middleware.proxy_fix import ProxyFix
    server.wsgi_app = ProxyFix(server.wsgi_app, x_for=1, x_proto=1, x_host=1)
    logger.info("ProxyFix middleware enabled (trusted proxy headers: X-Forwarded-For/Proto/Host)")

# ============================================================================
# HTTP SECURITY HEADERS
# ============================================================================
_CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data: blob:; "
    "connect-src 'self' wss: ws:; "
    "font-src 'self' data: blob:; "
    "frame-ancestors 'self';"
)


@server.after_request
def set_security_headers(response):
    """Inject security headers into every response."""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = (
        'camera=(), microphone=(), geolocation=(), payment=()'
    )
    response.headers['Content-Security-Policy'] = _CSP
    # HSTS — only meaningful over HTTPS (browsers ignore it on plain http). Gate on the
    # actual request scheme so it's correct behind the Tailscale Funnel (ProxyFix makes
    # request.is_secure reflect X-Forwarded-Proto) and never advertised on a LAN http hit.
    if request.is_secure or request.headers.get('X-Forwarded-Proto', '').lower() == 'https':
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    # Cache-Control for static assets (JS/CSS/fonts)
    if response.content_type and any(
        ct in response.content_type
        for ct in ('javascript', 'text/css', 'font/', 'image/')
    ):
        response.headers['Cache-Control'] = 'public, max-age=604800, immutable'
    return response


def _verify_same_origin():
    """Return a 403 JSON response if the request Origin doesn't match our Host, else None."""
    origin = request.headers.get('Origin')
    if not origin:
        return None
    try:
        from urllib.parse import urlparse
        if urlparse(origin).netloc != request.host:
            return jsonify({'error': 'CSRF check failed'}), 403
    except Exception:
        pass
    return None

# ============================================================================
# REQUEST LOGGING MIDDLEWARE
# ============================================================================
_APP_START_TIME = datetime.now()

@server.before_request
def _start_timer():
    """Record request start time for duration logging."""
    from flask import g
    g._request_start = datetime.now()

@server.after_request
def _log_request(response):
    """Log non-trivial HTTP requests (skip Dash internal & health pings)."""
    from flask import g
    path = request.path
    # Skip noisy internal Dash callbacks and static assets
    if path.startswith('/_dash') or path.startswith('/assets/') or path == '/health':
        return response
    elapsed_ms = 0
    start = getattr(g, '_request_start', None)
    if start:
        elapsed_ms = int((datetime.now() - start).total_seconds() * 1000)
    logger.info(f"{request.method} {path} → {response.status_code} ({elapsed_ms}ms)")
    return response

@login_manager.user_loader
def load_user(user_id):
    """Load user by ID for Flask-Login"""
    return auth_manager.get_user_by_id(int(user_id))


# ============================================================================
# GLOBAL ERROR HANDLERS — prevent raw stack traces from leaking to clients
# ============================================================================

@server.errorhandler(404)
def not_found(_e):
    return jsonify({'error': 'Not found'}), 404

@server.errorhandler(500)
def internal_error(_e):
    # Log the FULL traceback (not just str(e)) so a first-boot 500 is diagnosable from
    # the journal / firstboot report — the generic message still goes to the client.
    logger.error("Unhandled 500 error on %s %s", request.method, request.path, exc_info=True)
    return jsonify({'error': 'Internal server error'}), 500

# ============================================================================
# GOOGLE OAUTH INITIALIZATION
# ============================================================================

oauth_handler = None
try:
    oauth_handler = GoogleOAuthHandler(server, db_manager=db_manager)
    if oauth_handler.enabled:
        logger.info("Google OAuth initialized successfully")
    else:
        logger.warning("Google OAuth credentials not configured")
except Exception as e:
    logger.error(f"Failed to initialize OAuth: {e}")
    oauth_handler = None

# Update shared module reference so callbacks can use it
_shared.oauth_handler = oauth_handler

# ============================================================================
# WEBAUTHN INITIALIZATION
# ============================================================================

webauthn_handler = None
try:
    webauthn_handler = WebAuthnHandler(db_manager=db_manager)
    if is_webauthn_available():
        logger.info("WebAuthn initialized successfully")
    else:
        logger.warning("WebAuthn requires HTTPS (except localhost)")
except Exception as e:
    logger.error(f"Failed to initialize WebAuthn: {e}")
    webauthn_handler = None

# Update shared module reference so callbacks can use it
_shared.webauthn_handler = webauthn_handler

# ---------------------------------------------------------------------------
# PWA: manifest + service worker served at the site ROOT.
# A service worker can only control pages at or below its own URL, so it must be
# served from / (not /assets/) to control navigations. Both are unauthenticated:
# the browser fetches them before login and they contain no secrets.
# ---------------------------------------------------------------------------
_PWA_ASSETS_DIR = Path(__file__).parent / 'assets'

@server.route('/sw.js')
def service_worker():
    resp = send_file(_PWA_ASSETS_DIR / 'sw.js', mimetype='application/javascript')
    resp.headers['Service-Worker-Allowed'] = '/'
    resp.headers['Cache-Control'] = 'no-cache'  # always revalidate the worker itself
    return resp


@server.route('/manifest.webmanifest')
def web_manifest():
    resp = send_file(_PWA_ASSETS_DIR / 'manifest.webmanifest',
                     mimetype='application/manifest+json')
    resp.headers['Cache-Control'] = 'public, max-age=3600'
    return resp


# Health check endpoint for monitoring
@server.route('/health')
def health_check():
    """
    Health check endpoint for monitoring and deployment verification.
    Returns JSON with status of various system components.
    """
    from flask import jsonify
    import shutil

    health_status = {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "uptime_seconds": int((datetime.now() - _APP_START_TIME).total_seconds()),
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

    # Check ML / inference engine
    try:
        ml_status = "healthy" if inference_engine else "unavailable"
        health_status["components"]["ml_engine"] = {"status": ml_status}
    except Exception:
        health_status["components"]["ml_engine"] = {"status": "unavailable"}

    # Check report scheduler
    health_status["components"]["report_scheduler"] = {
        "status": "healthy" if report_scheduler else "disabled"
    }

    # Check AI assistant
    health_status["components"]["ai_assistant"] = {
        "status": "healthy" if (ai_assistant and getattr(ai_assistant, 'enabled', False)) else "disabled"
    }

    # System resources
    try:
        disk = shutil.disk_usage(str(project_root))
        mem = psutil.virtual_memory()
        health_status["system"] = {
            "disk_free_gb": round(disk.free / (1024 ** 3), 2),
            "disk_percent_used": round((disk.used / disk.total) * 100, 1),
            "memory_percent_used": round(mem.percent, 1),
            "cpu_percent": psutil.cpu_percent(interval=0),
        }
        # Warn if disk is > 90 % full
        if health_status["system"]["disk_percent_used"] > 90:
            health_status["components"]["disk_space"] = {
                "status": "warning",
                "message": "Disk usage above 90%"
            }
    except Exception:
        pass  # non-fatal

    # Check if .env file exists
    env_path = Path(__file__).parent.parent / '.env'
    health_status["components"]["configuration"] = {
        "status": "healthy" if env_path.exists() else "warning",
        "env_file_exists": env_path.exists()
    }

    # Capture pipeline freshness — surfaces a dead Zeek/parser pipeline that would
    # otherwise look "healthy". Reported as info ("idle") rather than a warning so a
    # genuinely quiet network never flips the endpoint to degraded.
    try:
        cur = db_manager.conn.cursor()
        last = cur.execute("SELECT MAX(timestamp) FROM connections").fetchone()[0]
        if last:
            try:
                age = (datetime.now() - datetime.fromisoformat(str(last))).total_seconds()
            except ValueError:
                age = None
            health_status["components"]["capture"] = {
                "status": "healthy" if (age is not None and age < 3600) else "idle",
                "last_connection": str(last),
                "seconds_since_last": round(age) if age is not None else None,
            }
        else:
            health_status["components"]["capture"] = {
                "status": "idle", "last_connection": None,
                "note": "No network traffic captured yet.",
            }
    except Exception as e:
        health_status["components"]["capture"] = {"status": "unknown", "error": str(e)}

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
# API RATE LIMITING HELPER
# ============================================================================

def _check_api_rate_limit(action_type='api_call'):
    """Return a 429 JSON response if the caller is rate-limited, else None."""
    client_ip = request.remote_addr or 'unknown'
    try:
        allowed, remaining, reset_secs = rate_limiter.check_rate_limit(client_ip, action_type)
        if not allowed:
            return jsonify({
                'error': 'Too many requests',
                'retry_after': reset_secs,
            }), 429
        rate_limiter.record_attempt(client_ip, action_type)
    except Exception:
        pass  # fail open — don't block requests if rate-limiter DB is down
    return None

# ============================================================================
# WEBAUTHN BIOMETRIC AUTHENTICATION ROUTES
# ============================================================================

@server.route('/api/webauthn/register/start', methods=['POST'])
@login_required
def webauthn_register_start():
    """Start WebAuthn registration"""
    csrf_err = _verify_same_origin()
    if csrf_err:
        return csrf_err
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
        return jsonify({'error': 'Internal server error'}), 500


@server.route('/api/webauthn/register/verify', methods=['POST'])
@login_required
def webauthn_register_verify():
    """Verify WebAuthn registration"""
    csrf_err = _verify_same_origin()
    if csrf_err:
        return csrf_err
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
        return jsonify({'error': 'Internal server error'}), 500


@server.route('/api/webauthn/login/start', methods=['POST'])
def webauthn_login_start():
    """Start WebAuthn authentication"""
    csrf_err = _verify_same_origin()
    if csrf_err:
        return csrf_err
    rl = _check_api_rate_limit('api_call')
    if rl:
        return rl
    if not webauthn_handler:
        return jsonify({'error': 'WebAuthn not available'}), 503

    try:
        data = request.get_json()
        username = data.get('username')

        options = webauthn_handler.generate_authentication_options(username)
        return jsonify(options), 200

    except Exception as e:
        logger.error(f"WebAuthn login start error: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@server.route('/api/webauthn/login/verify', methods=['POST'])
def webauthn_login_verify():
    """Verify WebAuthn authentication"""
    csrf_err = _verify_same_origin()
    if csrf_err:
        return csrf_err
    rl = _check_api_rate_limit('api_call')
    if rl:
        return rl
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
        return jsonify({'error': 'Internal server error'}), 500



from dashboard.layouts.login import login_layout
from dashboard.components.feature_padlock import padlock_overlay


# ============================================================================
# DASHBOARD LAYOUT
# ============================================================================

# ============================================================================
# SPOTLIGHT SEARCH - FEATURE CATALOG & HELPER FUNCTIONS
# ============================================================================

# Universal Search Feature Catalog for Spotlight-like navigation
SEARCH_FEATURE_CATALOG = [
    # Analytics (2 features)
    {"id": "analytics-modal", "name": "Analytics Dashboard", "description": "View security status, alert timelines, anomaly distribution, and device analytics", "icon": "fa-chart-pie", "color": "text-info", "category": "Analytics", "keywords": ["analytics", "charts", "statistics", "security status", "alerts", "anomaly", "insights", "visualization", "viz"], "action_type": "modal"},
    {"id": "risk-heatmap-modal", "name": "Risk Heatmap", "description": "Visual heatmap showing network risk distribution and vulnerable areas", "icon": "fa-fire-flame-curved", "color": "text-warning", "category": "Analytics", "keywords": ["risk", "heatmap", "visualization", "viz", "vulnerable", "areas", "security"], "action_type": "modal"},
    # Device Management (2 features)
    {"id": "device-mgmt-modal", "name": "Device Management", "description": "Manage network devices, trust levels, groups, and device information", "icon": "fa-diagram-project", "color": "text-info", "category": "Device Management", "keywords": ["devices", "manage", "trust", "network", "groups", "mac", "ip"], "action_type": "modal"},
    {"id": "user-modal", "name": "User Management", "description": "Manage user accounts, roles, permissions, and access control (Admin only)", "icon": "fa-users-gear", "color": "text-info", "category": "Device Management", "keywords": ["users", "accounts", "roles", "admin", "permissions", "access"], "action_type": "modal"},
    # Security (5 features)
    {"id": "firewall-modal", "name": "Firewall Rules", "description": "Configure and manage firewall rules for network protection", "icon": "fa-shield-halved", "color": "text-success", "category": "Security", "keywords": ["firewall", "rules", "protection", "block", "allow", "security"], "action_type": "modal"},
    {"id": "threat-modal", "name": "Threat Intelligence", "description": "View threat analysis, malicious IPs, and security intelligence data", "icon": "fa-shield-virus", "color": "text-danger", "category": "Security", "keywords": ["threat", "intelligence", "malicious", "ips", "security", "analysis"], "action_type": "modal"},
    {"id": "vuln-scanner-modal", "name": "Vulnerability Scanner", "description": "Scan network for vulnerabilities and security weaknesses", "icon": "fa-magnifying-glass-chart", "color": "text-danger", "category": "Security", "keywords": ["vulnerability", "scanner", "scan", "weaknesses", "security", "cve"], "action_type": "modal"},
    {"id": "privacy-modal", "name": "Privacy Monitor", "description": "Monitor privacy risks, data exposure, and privacy score", "icon": "fa-user-shield", "color": "text-warning", "category": "Security", "keywords": ["privacy", "monitor", "data", "exposure", "score", "risks"], "action_type": "modal"},
    {"id": "compliance-modal", "name": "Compliance Dashboard", "description": "Track compliance with security standards and regulations", "icon": "fa-list-check", "color": "text-success", "category": "Security", "keywords": ["compliance", "standards", "regulations", "gdpr", "hipaa", "audit"], "action_type": "modal"},
    # System & Configuration (5 features)
    {"id": "system-modal", "name": "System Information", "description": "View system resources, performance metrics, and hardware details", "icon": "fa-server", "color": "text-info", "category": "System", "keywords": ["system", "resources", "performance", "cpu", "memory", "hardware"], "action_type": "modal"},
    {"id": "email-modal", "name": "Email Notifications", "description": "Configure SMTP settings and email alert preferences", "icon": "fa-envelope", "color": "text-success", "category": "System", "keywords": ["email", "smtp", "notifications", "alerts", "mail", "settings"], "action_type": "modal"},
    {"id": "preferences-modal", "name": "Dashboard Preferences", "description": "Customize dashboard layout, widgets, and display preferences", "icon": "fa-sliders-h", "color": "text-info", "category": "System", "keywords": ["preferences", "settings", "customize", "layout", "widgets", "display"], "action_type": "modal"},
    {"id": "quick-settings-modal", "name": "Quick Settings", "description": "Fast access to common settings: network, notifications, display, and performance", "icon": "fa-cog", "color": "text-info", "category": "System", "keywords": ["quick", "settings", "config", "preferences", "network", "notifications"], "action_type": "modal"},
    {"id": "profile-edit-modal", "name": "Edit Profile", "description": "Update your user profile, password, and account settings", "icon": "fa-user-edit", "color": "text-info", "category": "System", "keywords": ["profile", "edit", "account", "password", "settings", "user"], "action_type": "modal"},
    # IoT Features (4 features)
    {"id": "smarthome-modal", "name": "Smart Home Hub Detection", "description": "Detect and manage smart home hubs and IoT devices", "icon": "fa-house-signal", "color": "text-warning", "category": "IoT", "keywords": ["smart home", "hub", "iot", "devices", "detection", "alexa", "google home"], "action_type": "modal"},
    {"id": "segmentation-modal", "name": "Network Segmentation", "description": "Configure network segmentation and VLAN isolation for IoT devices", "icon": "fa-layer-group", "color": "text-info", "category": "IoT", "keywords": ["segmentation", "vlan", "isolation", "network", "iot", "zones"], "action_type": "modal"},
    {"id": "firmware-modal", "name": "Firmware Management", "description": "Track device firmware versions and security updates", "icon": "fa-microchip", "color": "text-warning", "category": "IoT", "keywords": ["firmware", "updates", "versions", "security", "patches", "iot"], "action_type": "modal"},
    {"id": "protocol-modal", "name": "Protocol Analyzer", "description": "Analyze network protocols and IoT communication patterns", "icon": "fa-network-wired", "color": "text-info", "category": "IoT", "keywords": ["protocol", "analyzer", "mqtt", "http", "coap", "communication", "iot"], "action_type": "modal"},
    # Intelligence & Analysis (4 features)
    {"id": "threat-map-modal", "name": "3D Threat Map", "description": "Interactive 3D visualization of global threat origins and attack patterns", "icon": "fa-earth-americas", "color": "text-danger", "category": "Intelligence", "keywords": ["threat", "map", "3d", "visualization", "viz", "global", "attacks", "origins"], "action_type": "modal"},
    {"id": "attack-surface-modal", "name": "Attack Surface Analysis", "description": "Analyze exposed services, open ports, and potential attack vectors", "icon": "fa-bullseye", "color": "text-danger", "category": "Intelligence", "keywords": ["attack", "surface", "analysis", "ports", "services", "exposure", "vectors"], "action_type": "modal"},
    {"id": "forensic-timeline-modal", "name": "Forensic Timeline", "description": "Detailed forensic timeline for incident investigation and analysis", "icon": "fa-microscope", "color": "text-purple", "category": "Intelligence", "keywords": ["forensic", "timeline", "investigation", "incident", "analysis", "events", "visualization", "viz"], "action_type": "modal"},
    {"id": "auto-response-modal", "name": "Automated Response", "description": "Configure automated responses to security threats and incidents", "icon": "fa-wand-magic-sparkles", "color": "text-purple", "category": "Intelligence", "keywords": ["automated", "response", "automation", "threats", "incident", "action"], "action_type": "modal"},
    # Notifications & Alerts (3 features)
    {"id": "alert-details-modal", "name": "Alert Details", "description": "View detailed information about security alerts and incidents", "icon": "fa-triangle-exclamation", "color": "text-warning", "category": "Notifications", "keywords": ["alert", "details", "incident", "security", "notification", "warning"], "action_type": "modal"},
    {"id": "toast-history-modal", "name": "Toast History", "description": "View complete history of toast notifications with filtering", "icon": "fa-clock-rotate-left", "color": "text-info", "category": "Notifications", "keywords": ["toast", "history", "notifications", "messages", "log"], "action_type": "modal"},
    {"id": "toast-detail-modal", "name": "Toast Details", "description": "View detailed information about a specific toast notification", "icon": "fa-circle-info", "color": "text-info", "category": "Notifications", "keywords": ["toast", "details", "notification", "info", "message"], "action_type": "modal"},
    # Performance & Monitoring (2 features)
    {"id": "performance-modal", "name": "Performance Analytics", "description": "Monitor network performance, latency, and throughput metrics", "icon": "fa-gauge-high", "color": "text-info", "category": "Performance", "keywords": ["performance", "analytics", "latency", "throughput", "metrics", "monitoring"], "action_type": "modal"},
    {"id": "benchmark-modal", "name": "Security Benchmark", "description": "Compare your security posture against industry benchmarks", "icon": "fa-chart-column", "color": "text-info", "category": "Performance", "keywords": ["benchmark", "security", "comparison", "standards", "posture", "metrics"], "action_type": "modal"},
    # Other Features (7 features)
    {"id": "education-modal", "name": "Security Education", "description": "Learn about threat scenarios, security best practices, and educational content", "icon": "fa-user-graduate", "color": "text-success", "category": "Education", "keywords": ["education", "learning", "security", "threats", "best practices", "training"], "action_type": "modal"},
    {"id": "api-hub-modal", "name": "API Hub", "description": "Access API documentation and integration endpoints", "icon": "fa-puzzle-piece", "color": "text-info", "category": "Developer", "keywords": ["api", "hub", "documentation", "integration", "endpoints", "developer"], "action_type": "modal"},
    {"id": "quick-actions-modal", "name": "Quick Actions", "description": "Fast access to common actions: scan, export, backup, and system controls", "icon": "fa-bolt-lightning", "color": "text-warning", "category": "Actions", "keywords": ["quick", "actions", "scan", "export", "backup", "controls"], "action_type": "modal"},
    {"id": "customize-layout-modal", "name": "Customize Layout", "description": "Customize dashboard layout, widgets visibility, and display density", "icon": "fa-gears", "color": "text-info", "category": "Customization", "keywords": ["customize", "layout", "widgets", "visibility", "density", "display"], "action_type": "modal"},
    {"id": "chat-modal", "name": "AI Assistant", "description": "Chat with AI assistant for network security guidance and troubleshooting", "icon": "fa-comments", "color": "text-purple", "category": "Assistance", "keywords": ["ai", "assistant", "chat", "help", "guidance", "troubleshooting"], "action_type": "modal"},
    {"id": "onboarding-modal", "name": "Interactive Tour", "description": "Element-highlighting tour of every AI feature: briefing, insights, weekly story, ask-why chat, agent, and more", "icon": "fa-circle-play", "color": "text-success", "category": "Help", "keywords": ["onboarding", "tour", "tutorial", "guide", "help", "introduction", "ai", "features", "walkthrough"], "action_type": "modal"},
    {"id": "lockdown-modal", "name": "Lockdown Mode", "description": "Emergency lockdown mode to block all untrusted devices", "icon": "fa-shield-heart", "color": "text-danger", "category": "Emergency", "keywords": ["lockdown", "emergency", "block", "security", "protection", "untrusted"], "action_type": "modal"},
    # AI Agent (added Phase 6B)
    {"id": "agent-modal", "name": "AI Security Agent", "description": "Review and approve autonomous remediation actions recommended by the security agent", "icon": "fa-robot", "color": "text-purple", "category": "Security", "keywords": ["agent", "ai", "autonomous", "remediation", "approve", "firewall", "block", "pending", "actions"], "action_type": "modal"},
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
                            html.I(className=f"fa {feature['icon']} {'fa-3x' if is_top_hit else 'fa-2x'} {feature.get('color', 'text-secondary')}")
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

    create_sidebar(),
    *create_header(),
    # ============================================================================
    # TABBED NAVIGATION - Wraps all visible content sections
    # ============================================================================
    dcc.Tabs(id='main-dashboard-tabs', value='tab-overview', className='dashboard-main-tabs',
             content_style={'padding': 0, 'margin': 0},
             children=[

    # ====================== TAB 1: OVERVIEW ======================
    dcc.Tab(label='Overview', value='tab-overview', className='dashboard-tab',
            selected_className='dashboard-tab--selected', children=[

    # Mode banner — shows current Simple/Advanced mode prominently
    html.Div(id='mode-banner', className='mode-banner mode-banner-simple', children=[
        html.I(className="fa fa-house me-2"),
        html.Span("Simple Mode", className="fw-bold"),
        html.Span(" — focused on what matters", className="text-muted small ms-2"),
    ]),

    # SECURITY SCORE DASHBOARD - Full Width Section
    html.Div(id='security-score-section', children=[
        dbc.Card([
            dbc.CardHeader([
                html.Div([
                    html.Div([
                        html.I(className="fa fa-shield-alt me-2 u-text-success"),
                        html.Span("Network Security Score", className="fw-bold"),
                        html.Span(id='traffic-light-badge', className='badge ms-2 d-none'),
                    ], className="d-flex align-items-center"),
                    html.Div([
                        html.Small(id="security-score-last-updated", children="Last updated: Never",
                                 className="badge badge-outline-light me-2 badge-pad"),
                        dbc.Button([
                            html.I(className="fa fa-sync-alt me-1"),
                            "Refresh"
                        ], id="security-score-refresh-btn", size="sm", color="light", outline=True,
                           className="btn-header-light")
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
                                className="chart-h-350"
                            ),
                            type="circle"
                        )
                    ], xs=12, md=5),

                    # Right: 4 Dimensional Breakdown Cards (hidden in home_user mode)
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
                                                     className="text-muted d-block u-text-xxs")
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
                                                     className="text-muted d-block u-text-xxs")
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
                                                     className="text-muted d-block u-text-xxs")
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
                                                     className="text-muted d-block u-text-xxs")
                                        ], className="text-center")
                                    ], className="p-3")
                                ], className="glass-card border-0 shadow-sm h-100")
                            ], width=6)
                        ])
                    ], xs=12, md=7, id='score-dims-col')
                ], className="mb-3"),

                # Bottom: Historical Trend Chart (hidden in home_user mode)
                dbc.Row([
                    dbc.Col([
                        html.H6("Security Score Trend (Last 7 Days)", className="text-muted mb-2"),
                        dcc.Loading(
                            dcc.Graph(
                                id='security-score-history-chart',
                                config={'displayModeBar': False},
                                className="chart-h-200"
                            ),
                            type="circle"
                        )
                    ], width=12)
                ], id='security-score-history-row')
            ], className="p-4")
        ], className="glass-card border-0 shadow-lg mb-3")
    ]),

    # Auto-refresh interval for security score (every 30 seconds)
    dcc.Interval(id='security-score-interval', interval=30*1000, n_intervals=0),

    # ── AI Network Briefing + Proactive Insights row ─────────────────────────
    dbc.Row([
        # Left: AI-generated plain-English network briefing
        dbc.Col([
            dbc.Card([
                dbc.CardHeader([
                    html.Div([
                        html.I(className="fa fa-satellite-dish me-2"),
                        html.Span("Network Briefing", className="fw-bold"),
                        dbc.Badge(id="ai-briefing-source-badge", children="", className="ms-2 badge-sm d-none"),
                    ], className="d-flex align-items-center"),
                    html.Div([
                        html.Small(id="ai-briefing-timestamp", children="", className="me-2"),
                        dbc.Button([html.I(className="fa fa-sync-alt me-1"), "Refresh"],
                                   id="ai-briefing-refresh-btn", size="sm", color="light", outline=True,
                                   className="btn-header-light"),
                    ], className="d-flex align-items-center"),
                ], className="bg-gradient-info text-white card-header-sm d-flex justify-content-between align-items-center"),
                dbc.CardBody([
                    dcc.Loading(html.Div(id="ai-briefing-content",
                                        children=html.Span("Generating network briefing…",
                                                           className="text-muted fst-italic small")),
                                type="dot"),
                ], className="p-3"),
            ], id="tour-ai-briefing-card", className="glass-card border-0 shadow-sm h-100"),
        ], xs=12, md=7),

        # Right: 2-3 proactive AI-generated insights
        dbc.Col([
            dbc.Card([
                dbc.CardHeader([
                    html.I(className="fa fa-lightbulb me-2"),
                    html.Span("AI Insights", className="fw-bold"),
                ], className="bg-gradient-warning text-white card-header-sm d-flex align-items-center"),
                dbc.CardBody([
                    dcc.Loading(html.Div(id="ai-insights-content",
                                        children=html.Span("Analysing your network…",
                                                           className="text-muted fst-italic small")),
                                type="dot"),
                ], className="p-2"),
            ], id="tour-ai-insights-card", className="glass-card border-0 shadow-sm h-100"),
        ], xs=12, md=5),
    ], className="mb-3 g-3"),
    dcc.Store(id='ai-briefing-cache', data={}),

    # ── This Week on Your Network — AI-narrated weekly security story ─────────
    # Absolute differentiator
    # generates a personalised, AI-narrated weekly story from your own data.
    dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardHeader([
                    html.Div([
                        html.I(className="fa fa-book-open me-2"),
                        html.Span("This Week on Your Network", className="fw-bold"),
                        dbc.Badge(id="weekly-story-source-badge", children="",
                                  className="ms-2 badge-sm d-none"),
                    ], className="d-flex align-items-center"),
                    html.Div([
                        html.Small(id="weekly-story-timestamp", children="",
                                   className="me-2 text-white-50"),
                        dbc.Button([html.I(className="fa fa-sync-alt me-1"), "Refresh"],
                                   id="weekly-story-refresh-btn", size="sm",
                                   color="light", outline=True, className="btn-header-light"),
                    ], className="d-flex align-items-center"),
                ], className="bg-gradient-success text-white card-header-sm d-flex justify-content-between align-items-center"),
                dbc.CardBody([
                    dcc.Loading(
                        html.Div(id="weekly-story-content",
                                 children=html.Span(
                                     "Generating your weekly security story…",
                                     className="text-muted fst-italic small"
                                 )),
                        type="dot",
                    ),
                ], className="p-3"),
            ], id="tour-ai-weekly-card", className="glass-card border-0 shadow-sm"),
        ], xs=12),
    ], className="mb-3"),
    dcc.Store(id='weekly-story-cache', data={}),
    dcc.Store(id='device-personality-cache', data={}),

    # Home-user email toggle (shown only in simple mode)
    html.Div(id='home-email-row', style={'display': 'none'}, children=[
        dbc.Card([
            dbc.CardBody([
                html.Div([
                    html.Div([
                        html.I(className="fa fa-envelope me-2 text-success"),
                        html.Span("Email Alerts", className="fw-semibold"),
                        html.Span(" - Get notified about critical events",
                                  className="text-muted small ms-2"),
                    ], className="d-flex align-items-center"),
                    dbc.Switch(id='home-email-switch', value=False, className="mb-0"),
                ], className="d-flex align-items-center justify-content-between"),
            ], className="py-2 px-3")
        ], className="glass-card border-0 shadow-sm mb-3")
    ]),

    # ============================================================================
    # PRIVACY DASHBOARD - Moved to Privacy Monitor Modal (Device Privacy tab)
    # Privacy dashboard content is now in the Privacy Monitor modal as the "Device Privacy" tab
    # Keeping this placeholder for backward compatibility
    html.Div(id='privacy-dashboard-section', children=[], style={'display': 'none'}),

    # Privacy device detail modal
    dbc.Modal([
        dbc.ModalHeader(dbc.ModalTitle(id="privacy-detail-modal-title")),
        dbc.ModalBody(id="privacy-detail-modal-body"),
    ], id="privacy-detail-modal", size="xl", scrollable=True),

    # Auto-refresh interval for privacy dashboard (every 60 seconds)
    dcc.Interval(id='privacy-interval', interval=60*1000, n_intervals=0),

    # THREE COLUMN LAYOUT - Asymmetric 2-7-3 Layout
    dbc.Row([
        # LEFT COLUMN - Metrics, Network Activity, Devices, Quick Actions (2 cols)
        dbc.Col([
            html.Div(id='metrics-section', children=[

            # Metrics Boxes (2 columns for squarish layout)
            dbc.Row([
                # CPU Usage Box
                dbc.Col([
                    dbc.Card([
                        dbc.CardBody([
                            html.I(className="fa fa-microchip fa-2x mb-2 text-primary"),
                            html.H4(id="cpu-usage", className="mb-1 fw-bold text-gradient u-text-body"),
                            html.P("CPU", className="text-muted mb-0 small")
                        ], className="p-3 text-center")
                    ], className="metric-card glass-card border-0 shadow hover-lift h-100")
                ], width=6, className="mb-2"),

                # RAM Usage Box
                dbc.Col([
                    dbc.Card([
                        dbc.CardBody([
                            html.I(className="fa fa-memory fa-2x mb-2 text-success"),
                            html.H4(id="ram-usage", className="mb-1 fw-bold u-text-body"),
                            html.P("RAM", className="text-muted mb-0 small")
                        ], className="p-3 text-center")
                    ], className="metric-card glass-card border-0 shadow hover-lift h-100")
                ], width=6, className="mb-2"),

                # Bandwidth Usage Box
                dbc.Col([
                    dbc.Card([
                        dbc.CardBody([
                            html.I(className="fa fa-exchange-alt fa-2x mb-2 text-info"),
                            html.H4(id="bandwidth-usage", className="mb-1 fw-bold u-text-body"),
                            html.P("Bandwidth", className="text-muted mb-0 small text-nowrap")
                        ], className="p-3 text-center")
                    ], className="metric-card glass-card border-0 shadow hover-lift h-100")
                ], width=6, className="mb-2"),

                # Threats Blocked Box
                dbc.Col([
                    dbc.Card([
                        dbc.CardBody([
                            html.I(className="fa fa-shield-alt fa-2x mb-2 text-success"),
                            html.H4(id="threats-blocked", className="mb-1 fw-bold u-text-body"),
                            html.P("Blocked", className="text-muted mb-0 small")
                        ], className="p-3 text-center")
                    ], className="metric-card glass-card border-0 shadow hover-lift h-100")
                ], width=6, className="mb-2"),

                # Privacy Score Box
                dbc.Col([
                    dbc.Card([
                        dbc.CardBody([
                            html.I(className="fa fa-lock fa-2x mb-2 text-success", id="privacy-score-icon"),
                            html.H4(id="privacy-score-metric", className="mb-1 fw-bold u-text-body"),
                            html.P([
                                "Privacy",
                                html.I(className="fa fa-question-circle ms-1 text-muted u-pointer",
                                       id="privacy-score-tooltip-trigger")
                            ], className="text-muted mb-0 small"),
                            dbc.Tooltip(
                                "Your network privacy score (0-100). It reflects how much your "
                                "devices leak to trackers, ad networks and cloud servers. Higher "
                                "is better - tap the card for the per-device breakdown.",
                                target="privacy-score-tooltip-trigger", placement="top"),
                        ], className="p-3 text-center")
                    ], className="metric-card glass-card border-0 shadow hover-lift h-100 u-pointer")
                ], width=6, className="mb-2"),

                # Network Health Box
                dbc.Col([
                    dbc.Card([
                        dbc.CardBody([
                            html.I(className="fa fa-wifi fa-2x mb-2 text-info", id="network-icon"),
                            html.H6(id="network-health", className="mb-1 fw-bold u-text-sm"),
                            html.P("Health", className="text-muted mb-0 small")
                        ], className="p-3 text-center")
                    ], className="metric-card glass-card border-0 shadow hover-lift h-100")
                ], width=6, className="mb-2"),
            ], className="g-2 mb-3"),

            # Network Activity Card (moved above devices)
            dbc.Card([
                dbc.CardHeader([
                    html.I(className="fa fa-chart-network me-2 text-secondary"),
                    html.Span("Network Activity", className="fw-bold")
                ], className="bg-gradient-primary text-white card-header-sm"),
                dbc.CardBody([
                    dbc.Row([
                        dbc.Col([
                            html.Div([
                                html.I(className="fa fa-laptop text-primary mb-1 u-text-lg"),
                                html.H6(id='device-count-stat', className="mb-0 fw-bold u-text-md-lg"),
                                html.Small("Active (1h)", className="text-muted u-text-xxs")
                            ], className="text-center")
                        ], width=6, className="mb-2"),
                        dbc.Col([
                            html.Div([
                                html.I(className="fa fa-exchange-alt text-info mb-1 u-text-lg"),
                                html.H6(id='bandwidth-stat', className="mb-0 fw-bold u-text-md-lg"),
                                html.Small("Connections", className="text-muted u-text-xxs")
                            ], className="text-center")
                        ], width=6, className="mb-2")
                    ], className="g-2")
                ], className="p-2")
            ], className="glass-card border-0 shadow hover-card mb-3"),

            # Devices Card
            dbc.Card([
                dbc.CardHeader([
                    html.Div([
                        html.I(className="fa fa-network-wired me-2 text-secondary"),
                        html.Span("Connected Devices", className="fw-bold"),
                    ], className="d-flex align-items-center")
                ], className="bg-gradient-primary text-white card-header-md"),
                dbc.CardBody([
                    # Quick Status Grid
                    html.Div([
                        html.H6([
                            html.I(className="fa fa-th me-2 text-info"),
                            "Quick Status"
                        ], className="text-muted mb-2 u-text-sm"),
                        html.Div(id='devices-status-compact', className="device-grid-modern")
                    ], className="mb-3"),

                    html.Hr(className="my-2 border-top border-light"),

                    # Device List
                    html.Div([
                        html.H6([
                            html.I(className="fa fa-list-ul me-2 text-info"),
                            "Device List"
                        ], className="text-muted mb-2 u-text-sm"),
                        html.Div(id='active-devices-list',
                                className="custom-scrollbar-modern scroll-panel-225")
                    ])
                ], className="p-3")
            ], className="glass-card border-0 shadow-lg hover-card mb-3")
            ])
        ], xs=12, lg=2, className="mb-4"),

        # CENTER COLUMN - Network Visualization and Charts (7 cols)
        dbc.Col([
            # Network Topology Card
            dbc.Card([
                dbc.CardHeader([
                    html.Div([
                        html.Div([
                            html.I(className="fa fa-project-diagram me-2 u-text-success"),
                            html.Span("Network Topology", className="fw-bold"),
                        ], className="d-flex align-items-center"),
                        html.Div([
                            # Honest mode badge: Gateway sees all traffic; Passive shows the
                            # device map only (traffic cards say so until Gateway is enabled).
                            (html.Small("Gateway · full traffic", className="badge bg-success me-2 badge-pad")
                             if capture_mode_name() == 'gateway' else
                             html.Small("Passive · device map", className="badge bg-light text-dark me-2 badge-pad",
                                        title="Passive mode maps your devices. Enable Gateway mode "
                                              "(Settings → Network) for live per-device traffic flows.")),
                            dbc.Switch(id="graph-view-toggle", label="3D View", value=False,
                                     className="d-inline-flex align-items-center u-text-sm"),
                            html.I(className="fa fa-question-circle ms-2 text-white u-pointer",
                                  id="network-graph-help")
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
                                className="cytoscape-panel",
                                # Keep the graph well-framed: clamp how far it can zoom
                                # so a small home network can't auto-fit to an extreme
                                # zoom where the node icons look oversized or tiny.
                                minZoom=0.5,
                                maxZoom=2.0,
                                stylesheet=[
                                    # Each node renders a real device-type glyph on a light
                                    # face, ringed by its status colour (green/amber/red).
                                    # Label sits BELOW as a soft rounded pill — readable on
                                    # both the light and dark graph surfaces.
                                    {'selector': 'node', 'style': {
                                        'content': 'data(label)',
                                        'text-valign': 'bottom', 'text-halign': 'center', 'text-margin-y': 7,
                                        'background-color': '#f8fafc',
                                        'background-image': 'data(icon)',
                                        'background-fit': 'none',
                                        'background-clip': 'none',
                                        'background-width': '58%', 'background-height': '58%',
                                        'background-position-x': '50%', 'background-position-y': '50%',
                                        'border-width': 3, 'border-color': 'data(borderColor)',
                                        'border-opacity': 0.95,
                                        'font-size': '11px', 'font-weight': 600,
                                        'color': '#ffffff',
                                        'text-outline-width': 0,
                                        'text-background-color': '#27272a',
                                        'text-background-opacity': 0.82,
                                        'text-background-shape': 'roundrectangle',
                                        'text-background-padding': 3,
                                        'min-zoomed-font-size': 6,
                                    }},
                                    # Central router/gateway hub: indigo face, white icon, larger.
                                    {'selector': 'node[type="router"]', 'style': {
                                        'shape': 'round-rectangle', 'width': 66, 'height': 66,
                                        'background-color': '#6366f1', 'border-color': '#4f46e5',
                                        'background-width': '52%', 'background-height': '52%',
                                        'font-size': '12px',
                                    }},
                                    {'selector': 'node[type="device"]', 'style': {'width': 48, 'height': 48}},
                                    {'selector': 'edge', 'style': {
                                        'width': 2, 'line-color': '#94a3b8', 'opacity': 0.55,
                                        'target-arrow-shape': 'triangle', 'target-arrow-color': '#94a3b8',
                                        'arrow-scale': 0.9, 'curve-style': 'bezier'
                                    }},
                                    {'selector': '.animated-edge', 'style': {
                                        'line-color': '#6366f1', 'target-arrow-color': '#6366f1',
                                        'width': 3, 'opacity': 0.9
                                    }}
                                ],
                                tapNodeData={'id': None}
                            )
                        ]),
                        html.Div(id='3d-graph-container', children=[
                            dcc.Loading(
                                dcc.Graph(id='network-graph-3d', className="chart-h-500"),
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
                    ], className="card-header-neutral border-0")
                ], className="p-4")
            ], className="glass-card border-0 shadow-lg mb-3 hover-card"),

            # Analytics Cards - Stacked Layout
            dbc.Row([
                # Protocol Distribution
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader([
                            html.I(className="fa fa-chart-pie me-2 text-info"),
                            "Protocol Distribution",
                            html.I(className="fa fa-question-circle ms-2 text-muted u-pointer",
                                  id="protocol-help")
                        ], className="glass-card-header card-header-md u-text-base"),
                        dbc.Tooltip("Shows network protocol usage (TCP/UDP/ICMP). Unusual patterns may indicate attacks.",
                                   target="protocol-help", placement="top"),
                        dbc.CardBody(
                            dcc.Loading(
                                dcc.Graph(id='protocol-pie', className="chart-h-280",
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
                            html.I(className="fa fa-chart-line me-2 text-info"),
                            "Traffic Timeline (24h)",
                            html.I(className="fa fa-question-circle ms-2 text-muted u-pointer",
                                  id="timeline-help")
                        ], className="glass-card-header card-header-md u-text-base"),
                        dbc.Tooltip("24-hour traffic patterns. Spikes at odd hours may indicate malware or unauthorized access.",
                                   target="timeline-help", placement="top"),
                        dbc.CardBody(
                            dcc.Loading(
                                dcc.Graph(id='traffic-timeline', className="chart-h-280",
                                    config={'displayModeBar': False}),
                                type="circle"
                            ),
                            className="p-2"
                        )
                    ], className="glass-card border-0 shadow hover-card")
                ], width=12)
            ], className="g-3")
        ], xs=12, lg=7, className="mb-4"),

        # RIGHT COLUMN - Security Status and Alerts (3 cols)
        dbc.Col([
            html.Div(id='right-panel-section', children=[
            # Live Threat Feed Card
            dbc.Card([
                dbc.CardHeader([
                    html.Div([
                        html.Div([
                            html.I(className="fa fa-bullseye me-2 text-danger"),
                            html.Span("Live Threat Feed", className="fw-bold")
                        ], className="d-flex align-items-center"),
                        dbc.Badge("LIVE", color="danger", pill=True, className="pulse-badge")
                    ], className="d-flex justify-content-between align-items-center w-100")
                ], className="bg-gradient-danger text-white card-header-sm"),
                dbc.CardBody([
                    html.Div(id='live-threat-feed', className="threat-feed-container threat-feed-scroll")
                ], className="p-2")
            ], className="glass-card border-0 shadow hover-card mb-3"),

            # Security Status Card
            dbc.Card([
                dbc.CardHeader([
                    html.I(className="fa fa-shield-alt me-2 u-text-success"),
                    html.Span("Security Status", className="fw-bold")
                ], className="bg-gradient-info text-white card-header-sm"),
                dbc.CardBody([
                    # Security Score
                    html.Div([
                        html.Div([
                            html.H3(id='security-score', className="mb-0 fw-bold text-success u-text-hero-sm"),
                            html.Small("Security Score", className="text-muted d-block u-text-xs")
                        ], className="text-center mb-3")
                    ]),
                    # Quick Stats
                    dbc.Row([
                        dbc.Col([
                            html.Div([
                                html.I(className="fa fa-clock text-secondary mb-1 u-text-body"),
                                html.P(id='last-scan-time', className="mb-0 small fw-bold u-text-xxs"),
                                html.Small("Last Scan", className="text-muted u-text-badge")
                            ], className="text-center")
                        ], width=12, className="mb-2")
                    ], className="g-1")
                ], className="p-2")
            ], className="glass-card border-0 shadow hover-card mb-3"),

            # Recent Activity Card
            dbc.Card([
                dbc.CardHeader([
                    html.I(className="fa fa-history me-2 text-secondary"),
                    html.Span("Recent Activity", className="fw-bold")
                ], className="bg-gradient-purple text-white card-header-sm"),
                dbc.CardBody([
                    html.Div(id='recent-activity-list', className=" u-text-xs")
                ], className="p-2")
            ], className="glass-card border-0 shadow hover-card mb-3"),

            # Recommended Actions Card
            dbc.Card([
                dbc.CardHeader([
                    html.I(className="fa fa-lightbulb me-2 text-warning"),
                    html.Span("Recommendations", className="fw-bold")
                ], className="bg-gradient-warning text-white card-header-sm"),
                dbc.CardBody([
                    html.Div(id='recommendations-list', className=" u-text-xs")
                ], className="p-2")
            ], className="glass-card border-0 shadow hover-card mb-3"),

            # Predictive Threat Intelligence Card
            dbc.Card([
                dbc.CardHeader([
                    html.I(className="fa fa-brain me-2 text-secondary"),
                    html.Span("Threat Forecast", className="fw-bold")
                ], className="bg-gradient-secondary text-white card-header-sm"),
                dbc.CardBody([
                    html.Div(id='threat-forecast-content', className="u-text-xs")
                ], className="p-2")
            ], className="glass-card border-0 shadow hover-card mb-3"),

            # Security Alerts Card (moved to last)
            dbc.Card(id="tour-alerts-card", children=[
                dbc.CardHeader([
                    html.Div([
                        html.Div([
                            html.I(className="fa fa-exclamation-triangle me-2 text-warning"),
                            html.Span("Security Alerts", className="fw-bold"),
                            # AI activity pulse — appears when background worker is actively
                            # rewriting alerts. Hidden by default; callback shows it.
                            dbc.Badge(
                                [html.I(className="fa fa-microchip me-1"), "AI active"],
                                id="ai-activity-badge",
                                color="info",
                                className="ms-2 badge-sm pulse-badge d-none",
                                title="AI is actively explaining new alerts in plain English",
                            ),
                        ], className="d-flex align-items-center"),
                        dbc.Badge(id='alert-count', color="danger", pill=True,
                                className="pulse-badge u-text-body badge-pad")
                    ], className="d-flex justify-content-between align-items-center w-100")
                ], className="bg-gradient-warning text-white card-header-md"),
                dbc.CardBody([
                    # Alert Filters
                    html.Div([
                        html.Small("Severity:", className="text-muted d-block mb-2 u-text-sm fw-semibold"),
                        dbc.ButtonGroup([
                            dbc.Button("All", id="filter-all", size="sm",
                                       className="filter-btn-sev filter-btn-all filter-btn-active",
                                       title="Show all severities"),
                            dbc.Button(html.I(className="fa fa-skull-crossbones"),
                                       id="filter-critical", size="sm",
                                       className="filter-btn-sev filter-btn-critical",
                                       title="Critical alerts only"),
                            dbc.Button(html.I(className="fa fa-fire"),
                                       id="filter-high", size="sm",
                                       className="filter-btn-sev filter-btn-high",
                                       title="High severity alerts"),
                            dbc.Button(html.I(className="fa fa-bolt"),
                                       id="filter-medium", size="sm",
                                       className="filter-btn-sev filter-btn-medium",
                                       title="Medium severity alerts"),
                            dbc.Button(html.I(className="fa fa-info-circle"),
                                       id="filter-low", size="sm",
                                       className="filter-btn-sev filter-btn-low",
                                       title="Low severity alerts"),
                        ], className="w-100 mb-2"),
                        html.Div(
                            dbc.Checklist(
                                options=[{"label": "Show Reviewed", "value": 1}],
                                value=[],
                                id="show-reviewed-alerts",
                                switch=True,
                                className="mt-1 u-text-sm"
                            ),
                            className="modal-compact-switches mt-2"
                        )
                    ], className="mb-3"),

                    # Incident correlation panel — groups of related alerts
                    html.Div(id='incidents-panel', className="mb-2"),

                    # Alerts Container (FIXED HEIGHT)
                    html.Div(id='alerts-container-compact',
                            className="custom-scrollbar-modern alerts-modern scroll-panel-375")
                ], className="p-3")
            ], className="glass-card border-0 shadow-lg hover-card"),

            # Emergency Protection (compact strip — shown only in Advanced mode)
            html.Div(id='emergency-button-container', children=[
                dbc.Card([
                    dbc.CardBody([
                        html.Div([
                            html.I(className="fa fa-shield-alt text-danger me-2"),
                            html.Span("Emergency Protection", className="fw-semibold u-text-sm"),
                        ], className="d-flex align-items-center mb-2"),
                        html.P("Instantly blocks all untrusted devices from the network.", className="u-text-xs text-muted mb-2"),
                        dbc.Button([
                            html.I(className="fa fa-exclamation-triangle me-2"),
                            "Activate Emergency Mode"
                        ], id="emergency-activate-btn", color="danger", size="sm",
                           className="w-100 pulse-danger",
                           title="Emergency mode blocks all untrusted devices (Parent/Admin only)"),
                    ], className="p-2")
                ], className="glass-card border border-danger border-opacity-50 shadow-sm")
            ], style={"display": "none"}, className="mt-3"),

            # Emergency Mode Active Banner (compact)
            html.Div(id='emergency-active-banner', children=[
                dbc.Card([
                    dbc.CardBody([
                        html.Div([
                            html.I(className="fa fa-shield-alt text-warning me-2"),
                            html.Span("🚨 Emergency Mode Active", className="fw-semibold u-text-sm text-warning"),
                        ], className="d-flex align-items-center mb-2"),
                        html.P(id="emergency-status-text", className="u-text-xs text-muted mb-2"),
                        dbc.Button([
                            html.I(className="fa fa-unlock me-2"),
                            "Deactivate"
                        ], id="emergency-deactivate-btn", color="success", size="sm",
                           className="w-100",
                           title="Deactivate emergency protection (Parent/Admin only)"),
                    ], className="p-2")
                ], className="glass-card border border-warning border-opacity-50 shadow-sm")
            ], style={"display": "none"}, className="mt-3"),
            ])
        ], xs=12, lg=3, className="mb-4")
    ], className="g-3"),

    ]),  # End of Tab 1: Overview

    # ====================== TAB 2: ALERTS & THREATS ======================
    dcc.Tab(label='🚨 Alerts & Threats', value='tab-alerts', className='dashboard-tab',
            selected_className='dashboard-tab--selected', children=[
    html.Div([
    html.Div([
        # Threat Intelligence (locked until threat-intel API key is configured)
        html.Div([
            padlock_overlay(
                html.Div([
                    dbc.Card([
                        dbc.CardBody([
                            html.Div([
                                html.I(className="fa fa-shield-virus fa-3x mb-3 text-danger"),
                                html.H5("Threat Intelligence", className="fw-bold mb-2"),
                                html.P("Mirai, DDoS & botnet", className="small text-muted mb-0 card-short-desc"),
                                html.Div([
                                    html.P("Detect Mirai botnets, DDoS patterns and active threat campaigns targeting your IoT devices in real time.",
                                           className="text-muted small mb-2 mt-2")
                                ], className="hover-preview-content", style={"display": "none"})
                            ], className="text-center")
                        ], className="p-3")
                    ], className="glass-card border-0 shadow hover-lift")
                ], id="threat-card-btn", n_clicks=0),
                "threat",
                "Requires a threat intelligence API key. Add one in the Integrations → API Hub.",
            )
        ], className="feature-card-cell masonry-item", **{"data-category": "Security"}),

        # Geographic Threat Map (locked until threat-intel API key is configured)
        html.Div([
            padlock_overlay(
                html.Div([
                    dbc.Card([
                        dbc.CardBody([
                            html.Div([
                                html.I(className="fa fa-earth-americas fa-3x mb-3 text-danger"),
                                html.H5("Global Threat Map", className="fw-bold mb-2"),
                                html.P("Real-time global attack visualization", className="small text-muted mb-0 card-short-desc"),
                                html.Div([
                                    html.P("See live cyberattacks worldwide and track which threats are actively targeting IoT infrastructure near you.",
                                           className="text-muted small mb-2 mt-2")
                                ], className="hover-preview-content", style={"display": "none"})
                            ], className="text-center")
                        ], className="p-3")
                    ], className="glass-card border-0 shadow hover-lift")
                ], id="threat-map-card-btn", n_clicks=0),
                "threat-map",
                "Requires a threat intelligence API key. Add one in the Integrations → API Hub.",
            )
        ], className="feature-card-cell masonry-item", **{"data-category": "Security"}),

        # Device Risk Heat Map
        html.Div([
            html.Div([
                dbc.Card([
                    dbc.CardBody([
                        html.Div([
                            html.I(className="fa fa-fire-flame-curved fa-3x mb-3 text-warning"),
                            html.H5("Risk Heat Map", className="fw-bold mb-2"),
                            html.P("Device vulnerabilities", className="small text-muted mb-0 card-short-desc"),
                            html.Div([
                                html.P("Color-coded view of all devices ranked by vulnerability severity, CVE count, and unpatched firmware age.",
                                       className="text-muted small mb-2 mt-2")
                            ], className="hover-preview-content", style={"display": "none"})
                        ], className="text-center")
                    ], className="p-3")
                ], className="glass-card border-0 shadow hover-lift")
            ], id="risk-heatmap-card-btn", n_clicks=0)
        ], className="feature-card-cell masonry-item", **{"data-category": "Security"}),

        # Forensic Timeline
        html.Div([
            html.Div([
                dbc.Card([
                    dbc.CardBody([
                        html.Div([
                            html.I(className="fa fa-microscope fa-3x mb-3 text-purple"),
                            html.H5("Forensic Timeline", className="fw-bold mb-2"),
                            html.P("Attack reconstruction", className="small text-muted mb-0 card-short-desc"),
                            html.Div([
                                html.P("Replay security incidents step-by-step to trace exactly how an attacker moved through your network.",
                                       className="text-muted small mb-2 mt-2")
                            ], className="hover-preview-content", style={"display": "none"})
                        ], className="text-center")
                    ], className="p-3")
                ], className="glass-card border-0 shadow hover-lift")
            ], id="forensic-timeline-card-btn", n_clicks=0)
        ], className="feature-card-cell masonry-item", **{"data-category": "Security"}),

        # Automated Response
        html.Div([
            html.Div([
                dbc.Card([
                    dbc.CardBody([
                        html.Div([
                            html.I(className="fa fa-wand-magic-sparkles fa-3x mb-3 text-purple"),
                            html.H5("Auto Response", className="fw-bold mb-2"),
                            html.P("Automated actions", className="small text-muted mb-0 card-short-desc"),
                            html.Div([
                                html.P("Automatically quarantine suspicious devices, block bad IPs, or send alerts the moment a threat is detected.",
                                       className="text-muted small mb-2 mt-2")
                            ], className="hover-preview-content", style={"display": "none"})
                        ], className="text-center")
                    ], className="p-3")
                ], className="glass-card border-0 shadow hover-lift")
            ], id="auto-response-card-btn", n_clicks=0)
        ], className="feature-card-cell masonry-item", **{"data-category": "Security"}),
    ], className="feature-cards")
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
                            html.I(className="fa fa-diagram-project fa-3x mb-3 text-info"),
                            html.H5("Device Management", className="fw-bold mb-2"),
                            html.P("Manage all IoT devices with bulk operations and trust levels", className="text-muted mb-0 card-short-desc"),
                            html.Div([
                                html.P("Comprehensive IoT device management with bulk operations, trust level configuration, and device monitoring.",
                                       className="text-muted small mb-2 mt-2")
                            ], className="hover-preview-content", style={"display": "none"})
                        ], className="text-center")
                    ], className="p-3")
                ], className="glass-card border-0 shadow hover-lift")
            ], id="device-mgmt-card-btn", n_clicks=0)
        ], className="feature-card-cell masonry-item", **{"data-category": "Management"}),

        # IoT Protocol Analysis (MEDIUM)
        html.Div([
            html.Div([
                dbc.Card([
                    dbc.CardBody([
                        html.Div([
                            html.I(className="fa fa-network-wired fa-3x mb-3 text-info"),
                            html.H5("IoT Protocol Analysis", className="fw-bold mb-2"),
                            html.P("MQTT, CoAP, Zigbee protocol monitoring", className="small text-muted mb-0 card-short-desc"),
                            html.Div([
                                html.P("Inspect IoT protocol traffic for anomalies, misconfigured brokers, and unencrypted data streams.",
                                       className="text-muted small mb-2 mt-2")
                            ], className="hover-preview-content", style={"display": "none"})
                        ], className="text-center")
                    ], className="p-3")
                ], className="glass-card border-0 shadow hover-lift")
            ], id="protocol-card-btn", n_clicks=0)
        ], className="feature-card-cell masonry-item", **{"data-category": "Management"}),

        # Smart Home Context (MEDIUM)
        html.Div([
            html.Div([
                dbc.Card([
                    dbc.CardBody([
                        html.Div([
                            html.I(className="fa fa-house-signal fa-3x mb-3 text-warning"),
                            html.H5("Smart Home Context", className="fw-bold mb-2"),
                            html.P("Hub management & ecosystem", className="small text-muted mb-0 card-short-desc"),
                            html.Div([
                                html.P("Map and manage smart home hubs, group devices by room, and track ecosystem-level security posture.",
                                       className="text-muted small mb-2 mt-2")
                            ], className="hover-preview-content", style={"display": "none"})
                        ], className="text-center")
                    ], className="p-3")
                ], className="glass-card border-0 shadow hover-lift")
            ], id="smarthome-card-btn", n_clicks=0)
        ], className="feature-card-cell masonry-item", **{"data-category": "Management"}),

        # Privacy Monitoring (COMPACT)
        html.Div([
            html.Div([
                dbc.Card([
                    dbc.CardBody([
                        html.Div([
                            html.I(className="fa fa-user-shield fa-3x mb-3 text-warning"),
                            html.H5("Privacy Monitor", className="fw-bold mb-2"),
                            html.P("Cloud tracking", className="small text-muted mb-0 card-short-desc"),
                            html.Div([
                                html.P("Detect which devices are phoning home, identify unexpected cloud endpoints, and block privacy-leaking traffic.",
                                       className="text-muted small mb-2 mt-2")
                            ], className="hover-preview-content", style={"display": "none"})
                        ], className="text-center")
                    ], className="p-3")
                ], className="glass-card border-0 shadow hover-lift")
            ], id="privacy-card-btn", n_clicks=0)
        ], className="feature-card-cell masonry-item", **{"data-category": "Management"}),

        # Network Segmentation
        html.Div([
            html.Div([
                dbc.Card([
                    dbc.CardBody([
                        html.Div([
                            html.I(className="fa fa-layer-group fa-3x mb-3 text-info"),
                            html.H5("Segmentation", className="fw-bold mb-2"),
                            html.P("VLAN & isolation", className="small text-muted mb-0 card-short-desc"),
                            html.Div([
                                html.P("Isolate IoT devices into separate VLANs so a compromised device can't reach the rest of your network.",
                                       className="text-muted small mb-2 mt-2")
                            ], className="hover-preview-content", style={"display": "none"})
                        ], className="text-center")
                    ], className="p-3")
                ], className="glass-card border-0 shadow hover-lift")
            ], id="segmentation-card-btn", n_clicks=0)
        ], className="feature-card-cell masonry-item", **{"data-category": "Management"}),

        # Firmware Management (LARGE)
        html.Div([
            html.Div([
                dbc.Card([
                    dbc.CardBody([
                        html.Div([
                            html.I(className="fa fa-microchip fa-3x mb-3 text-warning"),
                            html.H5("Firmware Management", className="fw-bold mb-2"),
                            html.P("Track firmware updates and end-of-life devices", className="text-muted mb-0 card-short-desc"),
                            html.Div([
                                html.P("Get alerted when devices run outdated firmware, find end-of-life models, and track your full update history.",
                                       className="text-muted small mb-2 mt-2")
                            ], className="hover-preview-content", style={"display": "none"})
                        ], className="text-center")
                    ], className="p-3")
                ], className="glass-card border-0 shadow hover-lift")
            ], id="firmware-card-btn", n_clicks=0)
        ], className="feature-card-cell masonry-item", **{"data-category": "Management"}),

    ], className="feature-cards")
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
                            html.I(className="fa fa-chart-pie fa-3x mb-3 text-info"),
                            html.H5("Analytics & Deep Insights", className="fw-bold mb-2"),
                            html.P("AI-powered analytics, alerts timeline, anomaly detection, and bandwidth monitoring", className="text-muted mb-0 card-short-desc"),
                            html.Div([
                                html.P("Advanced AI-powered security analytics with real-time threat detection. Monitor alerts timeline, anomaly distribution, and bandwidth usage patterns.",
                                       className="text-muted small mb-2 mt-2")
                            ], className="hover-preview-content", style={"display": "none"})
                        ], className="text-center")
                    ], className="p-3")
                ], className="glass-card border-0 shadow hover-lift")
            ], id="analytics-card-btn", n_clicks=0)
        ], className="feature-card-cell masonry-item", **{"data-category": "Analytics"}),

        # Timeline Visualization
        html.Div([
            html.Div([
                dbc.Card([
                    dbc.CardBody([
                        html.Div([
                            html.I(className="fa fa-timeline fa-3x mb-3 text-info"),
                            html.H5("Timeline Viz", className="fw-bold mb-2"),
                            html.P("Activity history", className="small text-muted mb-0 card-short-desc"),
                            html.Div([
                                html.P("Scroll through a chronological log of all network events, alerts, and device status changes over time.",
                                       className="text-muted small mb-2 mt-2")
                            ], className="hover-preview-content", style={"display": "none"})
                        ], className="text-center")
                    ], className="p-3")
                ], className="glass-card border-0 shadow hover-lift")
            ], id="timeline-card-btn", n_clicks=0)
        ], className="feature-card-cell masonry-item", **{"data-category": "Analytics"}),

        # Comparison & Benchmarking
        html.Div([
            html.Div([
                dbc.Card([
                    dbc.CardBody([
                        html.Div([
                            html.I(className="fa fa-chart-column fa-3x mb-3 text-info"),
                            html.H5("Benchmarking", className="fw-bold mb-2"),
                            html.P("Industry comparison", className="small text-muted mb-0 card-short-desc"),
                            html.Div([
                                html.P("Compare your security score against industry baselines and see where your setup exceeds or falls short.",
                                       className="text-muted small mb-2 mt-2")
                            ], className="hover-preview-content", style={"display": "none"})
                        ], className="text-center")
                    ], className="p-3")
                ], className="glass-card border-0 shadow hover-lift")
            ], id="benchmark-card-btn", n_clicks=0)
        ], className="feature-card-cell masonry-item", **{"data-category": "Analytics"}),

        # Network Performance Analytics
        html.Div([
            html.Div([
                dbc.Card([
                    dbc.CardBody([
                        html.Div([
                            html.I(className="fa fa-gauge-high fa-3x mb-3 text-info"),
                            html.H5("Performance", className="fw-bold mb-2"),
                            html.P("Latency & throughput", className="small text-muted mb-0 card-short-desc"),
                            html.Div([
                                html.P("Track per-device bandwidth, detect traffic spikes, and spot latency issues before they affect your network.",
                                       className="text-muted small mb-2 mt-2")
                            ], className="hover-preview-content", style={"display": "none"})
                        ], className="text-center")
                    ], className="p-3")
                ], className="glass-card border-0 shadow hover-lift")
            ], id="performance-card-btn", n_clicks=0)
        ], className="feature-card-cell masonry-item", **{"data-category": "Analytics"}),
    ], className="feature-cards")
    ], id="analytics-features-section"),
    ]),  # End of Tab 4: Analytics & Reports

    # ====================== TAB 5: INTEGRATIONS & API ======================
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
                            html.I(className="fa fa-list-check fa-3x mb-3 u-text-success"),
                            html.H5("Compliance Dashboard", className="fw-bold mb-2"),
                            html.P("GDPR, NIST, IoT Cybersecurity Act", className="small text-muted mb-0 card-short-desc"),
                            html.Div([
                                html.P("Track your compliance posture across GDPR, NIST, and IoT-specific regulations with automated scoring.",
                                       className="text-muted small mb-2 mt-2")
                            ], className="hover-preview-content", style={"display": "none"})
                        ], className="text-center")
                    ], className="p-3")
                ], className="glass-card border-0 shadow hover-lift")
            ], id="compliance-card-btn", n_clicks=0)
        ], className="feature-card-cell masonry-item", **{"data-category": "Compliance"}),

        # Vulnerability Scanner
        html.Div([
            html.Div([
                dbc.Card([
                    dbc.CardBody([
                        html.Div([
                            html.I(className="fa fa-magnifying-glass-chart fa-3x mb-3 text-danger"),
                            html.H5("Vuln Scanner", className="fw-bold mb-2"),
                            html.P("CVE & firmware check", className="small text-muted mb-0 card-short-desc"),
                            html.Div([
                                html.P("Scan all devices for known CVEs, weak credentials, and outdated firmware against the NVD database.",
                                       className="text-muted small mb-2 mt-2")
                            ], className="hover-preview-content", style={"display": "none"})
                        ], className="text-center")
                    ], className="p-3")
                ], className="glass-card border-0 shadow hover-lift")
            ], id="vuln-scanner-card-btn", n_clicks=0)
        ], className="feature-card-cell masonry-item", **{"data-category": "Compliance"}),

        # Attack Surface Analyzer
        html.Div([
            html.Div([
                dbc.Card([
                    dbc.CardBody([
                        html.Div([
                            html.I(className="fa fa-bullseye fa-3x mb-3 text-danger"),
                            html.H5("Attack Surface", className="fw-bold mb-2"),
                            html.P("Entry points", className="small text-muted mb-0 card-short-desc"),
                            html.Div([
                                html.P("Enumerate all open ports, exposed services, and weak authentication points across your IoT fleet.",
                                       className="text-muted small mb-2 mt-2")
                            ], className="hover-preview-content", style={"display": "none"})
                        ], className="text-center")
                    ], className="p-3")
                ], className="glass-card border-0 shadow hover-lift")
            ], id="attack-surface-card-btn", n_clicks=0)
        ], className="feature-card-cell masonry-item", **{"data-category": "Compliance"}),

        # Firewall Control (COMPACT)
        html.Div([
            html.Div([
                dbc.Card([
                    dbc.CardBody([
                        html.Div([
                            html.I(className="fa fa-shield-halved fa-3x mb-3 text-success"),
                            html.H5("Firewall Control", className="fw-bold mb-2"),
                            html.P("Lockdown mode & security", className="small text-muted mb-0 card-short-desc u-text-xs"),
                            html.Div([
                                html.P("Configure lockdown mode and manage firewall rules for network security.",
                                       className="text-muted small mb-1 mt-1")
                            ], className="hover-preview-content", style={"display": "none"})
                        ], className="text-center")
                    ], className="p-3")
                ], className="glass-card border-0 shadow hover-lift")
            ], id="firewall-card-btn", n_clicks=0)
        ], className="feature-card-cell masonry-item", **{"data-category": "Compliance"}),

    ], className="feature-cards")
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
                            html.I(className="fa fa-users-gear fa-3x mb-3 text-info"),
                            html.H5("User Management", className="fw-bold mb-2"),
                            html.P("Accounts & passwords", className="small text-muted mb-0 card-short-desc"),
                            html.Div([
                                html.P("Create accounts, assign roles, reset passwords, and manage two-factor authentication for all users.",
                                       className="text-muted small mb-2 mt-2")
                            ], className="hover-preview-content", style={"display": "none"})
                        ], className="text-center")
                    ], className="p-3")
                ], className="glass-card border-0 shadow hover-lift")
            ], id="user-card-btn", n_clicks=0)
        ], className="feature-card-cell masonry-item", **{"data-category": "Admin"}),

        # System & ML Models Card Tile (MEDIUM)
        html.Div([
            html.Div([
                dbc.Card([
                    dbc.CardBody([
                        html.Div([
                            html.I(className="fa fa-server fa-3x mb-3 text-info"),
                            html.H5("System & ML Models", className="fw-bold mb-2"),
                            html.P("System status, ML model information, comparison and performance metrics", className="text-muted mb-0 card-short-desc"),
                            html.Div([
                                html.P("Monitor ML model performance, compare different algorithms, and track system health metrics.",
                                       className="text-muted small mb-2 mt-2")
                            ], className="hover-preview-content", style={"display": "none"})
                        ], className="text-center")
                    ], className="p-3")
                ], className="glass-card border-0 shadow hover-lift")
            ], id="system-card-btn", n_clicks=0)
        ], className="feature-card-cell masonry-item", **{"data-category": "Admin"}),

        # Dashboard Preferences
        html.Div([
            html.Div([
                dbc.Card([
                    dbc.CardBody([
                        html.Div([
                            html.I(className="fa fa-sliders-h fa-3x mb-3 text-info"),
                            html.H5("Preferences", className="fw-bold mb-2"),
                            html.P("Themes & settings", className="small text-muted mb-0 card-short-desc"),
                            html.Div([
                                html.P("Choose your dashboard theme, configure notification preferences, and set your default view mode.",
                                       className="text-muted small mb-2 mt-2")
                            ], className="hover-preview-content", style={"display": "none"})
                        ], className="text-center")
                    ], className="p-3")
                ], className="glass-card border-0 shadow hover-lift")
            ], id="preferences-card-btn", n_clicks=0)
        ], className="feature-card-cell masonry-item", **{"data-category": "Admin"}),

        # Quick Settings
        html.Div([
            html.Div([
                dbc.Card([
                    dbc.CardBody([
                        html.Div([
                            html.I(className="fa fa-cog fa-3x mb-3 text-warning"),
                            html.H5("Quick Settings", className="fw-bold mb-2"),
                            html.P("Configure preferences", className="small text-muted mb-0 card-short-desc"),
                            html.Div([
                                html.P("Toggle the most-used settings in one place — dark mode, alerts, monitoring, and email notifications.",
                                       className="text-muted small mb-2 mt-2")
                            ], className="hover-preview-content", style={"display": "none"})
                        ], className="text-center")
                    ], className="p-3")
                ], className="glass-card border-0 shadow hover-lift")
            ], id="quick-settings-btn", n_clicks=0)
        ], className="feature-card-cell masonry-item", **{"data-category": "Admin"}),

        # API Integration Hub
        html.Div([
            padlock_overlay(
                html.Div([
                    dbc.Card([
                        dbc.CardBody([
                            html.Div([
                                html.I(className="fa fa-puzzle-piece fa-3x mb-3 text-info"),
                                html.H5("API Hub", className="fw-bold mb-2"),
                                html.P("Threat intel APIs", className="small text-muted mb-0 card-short-desc"),
                                html.Div([
                                    html.P("Cross-check suspicious IPs and domains against global threat databases. Add an API key to activate.",
                                           className="text-muted small mb-2 mt-2")
                                ], className="hover-preview-content", style={"display": "none"})
                            ], className="text-center")
                        ], className="p-3")
                    ], className="glass-card border-0 shadow hover-lift")
                ], id="api-hub-card-btn", n_clicks=0),
                "api-hub",
                "Cross-check suspicious IPs against global databases that track hackers and malware. Add a free API key to enable.",
            )
        ], className="feature-card-cell masonry-item", **{"data-category": "Admin"}),

        # Email Notifications
        html.Div([
            padlock_overlay(
                html.Div([
                    dbc.Card([
                        dbc.CardBody([
                            html.Div([
                                html.I(className="fa fa-bell fa-3x mb-3 text-success"),
                                html.H5("Notifications", className="fw-bold mb-2"),
                                html.P("Push, email & webhook alerts", className="small text-muted mb-0 card-short-desc"),
                                html.Div([
                                    html.P("Send instant alerts via ntfy, Telegram, Discord, webhook, or email when your devices behave suspiciously.",
                                           className="text-muted small mb-2 mt-2")
                                ], className="hover-preview-content", style={"display": "none"})
                            ], className="text-center")
                        ], className="p-3")
                    ], className="glass-card border-0 shadow hover-lift")
                ], id="email-card-btn", n_clicks=0),
                "email",
                "Get instant email alerts when your devices behave suspiciously. Needs SMTP configuration.",
            )
        ], className="feature-card-cell masonry-item", **{"data-category": "Admin"}),

        # Sustainability
        html.Div([
            html.Div([
                dbc.Card([
                    dbc.CardBody([
                        html.Div([
                            html.I(className="fa fa-leaf fa-3x mb-3 u-text-success"),
                            html.H5("Sustainability", className="fw-bold mb-2"),
                            html.P("Carbon footprint & energy", className="small text-muted mb-0 card-short-desc"),
                            html.Div([
                                html.P("Estimate your IoT fleet's energy consumption, track idle devices, and reduce your carbon footprint.",
                                       className="text-muted small mb-2 mt-2")
                            ], className="hover-preview-content", style={"display": "none"})
                        ], className="text-center")
                    ], className="p-3")
                ], className="glass-card border-0 shadow hover-lift")
            ], id="sustainability-card-btn", n_clicks=0)
        ], className="feature-card-cell masonry-item", **{"data-category": "Admin"}),

        # Security Education
        html.Div([
            html.Div([
                dbc.Card([
                    dbc.CardBody([
                        html.Div([
                            html.I(className="fa fa-user-graduate fa-3x mb-3 text-success"),
                            html.H5("Education", className="fw-bold mb-2"),
                            html.P("Security tips", className="small text-muted mb-0 card-short-desc"),
                            html.Div([
                                html.P("Role-aware security guidance, best-practice checklists, and plain-English explanations of active threats.",
                                       className="text-muted small mb-2 mt-2")
                            ], className="hover-preview-content", style={"display": "none"})
                        ], className="text-center")
                    ], className="p-3")
                ], className="glass-card border-0 shadow hover-lift")
            ], id="education-card-btn", n_clicks=0)
        ], className="feature-card-cell masonry-item", **{"data-category": "Admin"}),

    ], className="feature-cards")
    ], id="admin-features-section"),
    ]),  # End of Tab 6 (was 7): Administration

    ]),  # End of dcc.Tabs main-dashboard-tabs

    # ============================================================================
    # GLOBAL MODALS, STORES, INTERVALS, DOWNLOADS
    # (These must remain outside tabs so callbacks can access them from any tab)
    # ============================================================================

    # Modals for each feature
    # Analytics Modal - Enhanced with Tabs
    dbc.Modal([
        dbc.ModalHeader(dbc.ModalTitle([
            html.I(className="fa fa-chart-pie me-2 text-info"),
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
                                                html.I(className="fa fa-chart-bar me-2 text-info"),
                                                "Alert Timeline (7 Days)"
                                            ]),
                                            html.I(className="fa fa-question-circle text-muted ms-2 u-pointer",
                                                  id="alert-timeline-help")
                                        ])
                                    ], className="glass-card-header u-text-md"),
                                    dbc.Tooltip(
                                        "Alert patterns over 7 days. Recurring alerts at similar times may indicate automated attacks.",
                                        target="alert-timeline-help", placement="top"
                                    ),
                                    dbc.CardBody(
                                        dcc.Graph(id='alert-timeline', className="chart-h-300",
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
                                                html.I(className="fa fa-chart-area me-2 text-info"),
                                                "Anomaly Distribution"
                                            ]),
                                            html.I(className="fa fa-question-circle text-muted ms-2 u-pointer",
                                                  id="anomaly-help")
                                        ])
                                    ], className="glass-card-header u-text-md"),
                                    dbc.Tooltip(
                                        "AI-calculated anomaly scores. Higher scores indicate unusual behavior worth investigating.",
                                        target="anomaly-help", placement="top"
                                    ),
                                    dbc.CardBody(
                                        dcc.Graph(id='anomaly-distribution', className="chart-h-300",
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
                                                html.I(className="fa fa-server me-2 text-info"),
                                                "Top Devices by Bandwidth"
                                            ]),
                                            html.I(className="fa fa-question-circle text-muted ms-2 u-pointer",
                                                  id="bandwidth-help")
                                        ])
                                    ], className="glass-card-header u-text-md"),
                                    dbc.Tooltip(
                                        "Devices ranked by data usage. Unusual high usage from IoT devices may indicate compromise.",
                                        target="bandwidth-help", placement="top"
                                    ),
                                    dbc.CardBody(
                                        dcc.Graph(id='bandwidth-chart', className="chart-h-300",
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
                                                html.I(className="fa fa-th me-2 text-info"),
                                                "Device Activity Heatmap"
                                            ]),
                                            html.I(className="fa fa-question-circle text-muted ms-2 u-pointer",
                                                  id="heatmap-help")
                                        ])
                                    ], className="glass-card-header u-text-md"),
                                    dbc.Tooltip(
                                        "Hourly activity patterns. Dark colors = high activity. Look for unusual timing patterns.",
                                        target="heatmap-help", placement="top"
                                    ),
                                    dbc.CardBody(
                                        dcc.Graph(id='device-heatmap', className="chart-h-300",
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
                                                html.I(className="fa fa-project-diagram me-2 text-info"),
                                                "Network Traffic Flow"
                                            ]),
                                            html.I(className="fa fa-question-circle text-muted ms-2 u-pointer",
                                                  id="sankey-help")
                                        ])
                                    ], className="glass-card-header u-text-md"),
                                    dbc.Tooltip(
                                        "Visualizes data flow between devices, protocols, and destinations. Width = data volume.",
                                        target="sankey-help", placement="top"
                                    ),
                                    dbc.CardBody(
                                        dcc.Loading(
                                            dcc.Graph(id='traffic-flow-sankey', className="chart-h-500",
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
                                html.I(className="fa fa-file-alt me-2 text-info"),
                                html.Strong("Security Summary Report")
                            ], className="glass-card-header"),
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
                                                html.I(className="fa fa-chart-line me-2 text-info"),
                                                "Alert Trends (7 Days)"
                                            ]),
                                            html.Span([
                                                dbc.Button([
                                                    html.I(className="fa fa-download me-1"),
                                                    "Custom Reports"
                                                ], id="open-reports-modal", color="primary", size="sm", className="float-end")
                                            ], className="float-end"),
                                            html.I(className="fa fa-question-circle text-muted ms-2 u-pointer",
                                                  id="alert-trends-help")
                                        ])
                                    ], className="glass-card-header u-text-md"),
                                    dbc.Tooltip(
                                        "Time-series analysis of security alerts with moving average trend line. Identifies patterns and anomalies.",
                                        target="alert-trends-help", placement="top"
                                    ),
                                    dbc.CardBody(
                                        dcc.Loading(
                                            dcc.Graph(id='alert-trend-chart', className="chart-h-350",
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
                                                html.I(className="fa fa-th me-2 text-info"),
                                                "Network Activity Heatmap (24h Pattern)"
                                            ]),
                                            html.I(className="fa fa-question-circle text-muted ms-2 u-pointer",
                                                  id="network-heatmap-help")
                                        ])
                                    ], className="glass-card-header u-text-md"),
                                    dbc.Tooltip(
                                        "Visualizes network activity patterns by hour. Helps identify unusual timing or off-hours activity.",
                                        target="network-heatmap-help", placement="top"
                                    ),
                                    dbc.CardBody(
                                        dcc.Loading(
                                            dcc.Graph(id='activity-heatmap-chart', className="chart-h-250",
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
                                        html.I(className="fa fa-chart-bar me-2 text-info"),
                                        "Trend Statistics"
                                    ], className="glass-card-header u-text-md"),
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
        ]),
        dcc.Store(id='analytics-timestamp-store')
    ], id="analytics-modal", size="xl", is_open=False, scrollable=True),

    # System & ML Models Modal - Enhanced with Tabs
    dbc.Modal([
        dbc.ModalHeader(dbc.ModalTitle([
            html.I(className="fa fa-server me-2 text-info"),
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
                                        dbc.Progress(id='cpu-usage-bar', value=0, color="info", className="mb-2 progress-sm"),
                                        html.Small(id='cpu-usage-text', className="text-muted")
                                    ], md=6),
                                    dbc.Col([
                                        html.Label("Memory Usage", className="small text-muted"),
                                        dbc.Progress(id='memory-usage-bar', value=0, color="warning", className="mb-2 progress-sm"),
                                        html.Small(id='memory-usage-text', className="text-muted")
                                    ], md=6)
                                ], className="mb-3"),
                                dbc.Row([
                                    dbc.Col([
                                        html.Label("Disk Usage", className="small text-muted"),
                                        dbc.Progress(id='disk-usage-bar', value=0, color="success", className="mb-2 progress-sm"),
                                        html.Small(id='disk-usage-text', className="text-muted")
                                    ], md=6),
                                    dbc.Col([
                                        html.Label("Network I/O", className="small text-muted"),
                                        dbc.Progress(id='network-usage-bar', value=0, color="primary", className="mb-2 progress-sm"),
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

                        # Model Performance — Precision / Recall / F1 from the offline
                        # holdout evaluation (River HalfSpaceTrees vs Isolation Forest comparator).
                        dbc.Card([
                            dbc.CardBody([
                                html.Div([
                                    html.H6([html.I(className="fa fa-chart-line me-2 text-info"),
                                             "Model Performance (Precision / Recall / F1)"], className="mb-0"),
                                    dbc.Button(html.I(className="fa fa-rotate"),
                                               id='ml-metrics-refresh-btn', color="link", size="sm",
                                               className="p-0 text-muted", title="Refresh"),
                                ], className="d-flex justify-content-between align-items-center mb-2"),
                                html.Div(id='ml-metrics-card-body'),
                            ])
                        ], className="glass-card border-0 shadow-sm mb-3"),

                        dbc.Card([
                            dbc.CardBody([
                                html.H6([html.I(className="fa fa-cog me-2 text-warning"), "Model Actions"], className="mb-3"),
                                html.P("River models learn continuously from live traffic — no batch retraining or importing needed.", className="text-muted small mb-3"),
                                dbc.Button([
                                    html.I(className="fa fa-download me-2"),
                                    "Export Model Config"
                                ], id='export-models-btn', color="info", outline=True, className="w-100 mb-2"),
                                html.Div(id='model-action-status', className="mt-2")
                            ])
                        ], className="glass-card border-0 shadow-sm")
                    ], className="p-3")
                ], label="ML Models", tab_id="ml-models-tab"),


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

                                html.H6([html.I(className="fa fa-terminal me-2 text-info"), "Recent Logs"], className="mb-3"),
                                html.Div([
                                    html.Pre(id='system-logs-display',
                                            className="modal-scroll-200 u-text-sm border p-3 rounded")
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
        ]),
        dcc.Store(id='system-timestamp-store')
    ], id="system-modal", size="xl", is_open=False, scrollable=True),

    # Notifications Modal - Email + Push channels
    dbc.Modal([
        dbc.ModalHeader(dbc.ModalTitle([
            html.I(className="fa fa-bell me-2 text-success"),
            "Notifications"
        ]), close_button=True),
        dbc.ModalBody([
            dbc.Tabs([

                # ── Push Notifications Tab (ntfy / Telegram / Discord / Webhook) ──
                dbc.Tab([
                    html.Div([
                        html.P(
                            "Configure one or more push channels. Each channel fires "
                            "independently on critical and high-severity alerts.",
                            className="text-muted small mb-3"
                        ),
                        dbc.Accordion([

                            # ntfy.sh
                            dbc.AccordionItem([
                                html.P([
                                    "Zero-account phone push via ",
                                    html.A("ntfy.sh", href="https://ntfy.sh", target="_blank",
                                           className="text-info"),
                                    ". Subscribe at ntfy.sh/<topic> or scan the QR from the setup wizard.",
                                ], className="small text-muted mb-3"),
                                dbc.Row([
                                    dbc.Col([
                                        html.Label("Topic", className="small fw-bold mb-1"),
                                        dbc.Input(
                                            id="notif-ntfy-topic",
                                            placeholder=os.getenv("NOTIFICATIONS_NTFY_TOPIC", "e.g. iotsentinel-a7f3"),
                                            value=os.getenv("NOTIFICATIONS_NTFY_TOPIC", ""),
                                            autocomplete="off", className="mb-2",
                                        ),
                                    ], md=8),
                                    dbc.Col([
                                        html.Label("Server", className="small fw-bold mb-1"),
                                        dbc.Input(
                                            id="notif-ntfy-server",
                                            placeholder="https://ntfy.sh",
                                            value=os.getenv("NOTIFICATIONS_NTFY_SERVER", "https://ntfy.sh"),
                                            autocomplete="off", className="mb-2",
                                        ),
                                    ], md=4),
                                ]),
                                dbc.Row([
                                    dbc.Col(dbc.Button([html.I(className="fa fa-save me-1"), "Save"],
                                        id="notif-ntfy-save-btn", color="success", outline=True,
                                        size="sm", className="me-2"), width="auto"),
                                    dbc.Col(dbc.Button([html.I(className="fa fa-paper-plane me-1"), "Send test"],
                                        id="notif-ntfy-test-btn", color="info", outline=True,
                                        size="sm"), width="auto"),
                                ], className="mb-2"),
                                html.Div(id="notif-ntfy-result", className="small mt-1"),
                            ], title="Phone Push (ntfy.sh) - No account needed"),

                            # Telegram
                            dbc.AccordionItem([
                                html.P([
                                    "Create a bot with ",
                                    html.A("@BotFather", href="https://t.me/botfather",
                                           target="_blank", className="text-info"),
                                    " and get your chat ID from ",
                                    html.A("@userinfobot", href="https://t.me/userinfobot",
                                           target="_blank", className="text-info"),
                                    ".",
                                ], className="small text-muted mb-3"),
                                html.Label("Bot token", className="small fw-bold mb-1"),
                                dbc.Input(
                                    id="notif-telegram-token",
                                    type="password", autocomplete="off",
                                    placeholder="(set)" if os.getenv("NOTIFICATIONS_TELEGRAM_BOT_TOKEN") else "123456:ABC-DEF...",
                                    className="mb-2",
                                ),
                                html.Label("Chat ID", className="small fw-bold mb-1"),
                                dbc.Input(
                                    id="notif-telegram-chat",
                                    autocomplete="off",
                                    placeholder=os.getenv("NOTIFICATIONS_TELEGRAM_CHAT_ID", "e.g. -1001234567890"),
                                    value=os.getenv("NOTIFICATIONS_TELEGRAM_CHAT_ID", ""),
                                    className="mb-2",
                                ),
                                dbc.Row([
                                    dbc.Col(dbc.Button([html.I(className="fa fa-save me-1"), "Save"],
                                        id="notif-telegram-save-btn", color="success", outline=True,
                                        size="sm", className="me-2"), width="auto"),
                                    dbc.Col(dbc.Button([html.I(className="fa fa-paper-plane me-1"), "Send test"],
                                        id="notif-telegram-test-btn", color="info", outline=True,
                                        size="sm"), width="auto"),
                                ], className="mb-2"),
                                html.Div(id="notif-telegram-result", className="small mt-1"),
                            ], title="Telegram Bot"),

                            # Discord
                            dbc.AccordionItem([
                                html.P(
                                    "Server Settings > Integrations > Webhooks > New Webhook. "
                                    "Copy the URL and paste below.",
                                    className="small text-muted mb-3"
                                ),
                                html.Label("Webhook URL", className="small fw-bold mb-1"),
                                dbc.Input(
                                    id="notif-discord-webhook",
                                    type="password", autocomplete="off",
                                    placeholder="(set)" if os.getenv("NOTIFICATIONS_DISCORD_WEBHOOK_URL") else "https://discord.com/api/webhooks/...",
                                    className="mb-2",
                                ),
                                dbc.Row([
                                    dbc.Col(dbc.Button([html.I(className="fa fa-save me-1"), "Save"],
                                        id="notif-discord-save-btn", color="success", outline=True,
                                        size="sm", className="me-2"), width="auto"),
                                    dbc.Col(dbc.Button([html.I(className="fa fa-paper-plane me-1"), "Send test"],
                                        id="notif-discord-test-btn", color="info", outline=True,
                                        size="sm"), width="auto"),
                                ], className="mb-2"),
                                html.Div(id="notif-discord-result", className="small mt-1"),
                            ], title="Discord Webhook"),

                            # Generic webhook
                            dbc.AccordionItem([
                                html.P(
                                    "POST a structured JSON payload to any HTTP endpoint. "
                                    "Compatible with Home Assistant, automation platforms, "
                                    "and any custom consumer.",
                                    className="small text-muted mb-3"
                                ),
                                html.Label("Endpoint URL", className="small fw-bold mb-1"),
                                dbc.Input(
                                    id="notif-webhook-url",
                                    type="url",
                                    placeholder=os.getenv("NOTIFICATIONS_WEBHOOK_URL", "https://your-endpoint.example.com/hook"),
                                    value=os.getenv("NOTIFICATIONS_WEBHOOK_URL", ""),
                                    className="mb-2",
                                ),
                                dbc.Row([
                                    dbc.Col(dbc.Button([html.I(className="fa fa-save me-1"), "Save"],
                                        id="notif-webhook-save-btn", color="success", outline=True,
                                        size="sm", className="me-2"), width="auto"),
                                    dbc.Col(dbc.Button([html.I(className="fa fa-paper-plane me-1"), "Send test"],
                                        id="notif-webhook-test-btn", color="info", outline=True,
                                        size="sm"), width="auto"),
                                ], className="mb-2"),
                                html.Div(id="notif-webhook-result", className="small mt-1"),
                            ], title="Generic Webhook"),

                        ], start_collapsed=True, always_open=True),
                    ], className="p-3")
                ], label="Push Alerts", tab_id="push-notifications-tab"),

                # Email tab (SMTP setup + recipients merged)
                dbc.Tab([
                    html.Div([
                        # Email account credentials (admin only, hidden for non-admins by callback)
                        html.Div(id='smtp-credentials-section', children=[dbc.Card([
                            dbc.CardBody([
                                html.H6([html.I(className="fa fa-envelope me-2 text-info"), "Email Account"], className="mb-1"),
                                html.P("Saved to your local config. Use Gmail with an App Password.", className="text-muted small mb-3"),
                                dbc.Row([
                                    dbc.Col([
                                        html.Label("Mail Server", className="small fw-bold"),
                                        dbc.Input(id='smtp-host-input',
                                                  placeholder=os.getenv('EMAIL_SMTP_HOST', 'smtp.gmail.com'),
                                                  autocomplete="off", className="mb-2"),
                                    ], md=8),
                                    dbc.Col([
                                        html.Label("Port", className="small fw-bold"),
                                        dbc.Input(id='smtp-port-input', type="number",
                                                  placeholder=os.getenv('EMAIL_SMTP_PORT', '587'),
                                                  autocomplete="off", className="mb-2"),
                                    ], md=4),
                                ]),
                                html.Label("Your email address", className="small fw-bold"),
                                dbc.Input(id='smtp-user-input', type='email',
                                          placeholder=os.getenv('EMAIL_SMTP_USER', 'you@gmail.com'),
                                          autocomplete="off", className="mb-2"),
                                html.Label("App Password", className="small fw-bold"),
                                dbc.Input(id='smtp-password-input', type='password',
                                          placeholder="xxxx xxxx xxxx xxxx" if not os.getenv('EMAIL_SMTP_PASSWORD') else "(already set)",
                                          autocomplete="off", className="mb-3"),
                                dbc.Button([
                                    html.I(className="fa fa-save me-2"), "Save"
                                ], id='smtp-settings-save-btn', color="success", outline=True, className="w-100 mb-2"),
                                html.Div(id='smtp-save-result'),
                            ])
                        ], className="glass-card border-0 shadow-sm mb-3")]),

                        # Who gets the emails
                        dbc.Card([
                            dbc.CardBody([
                                html.H6([html.I(className="fa fa-users me-2 text-primary"), "Who Gets Alerts"], className="mb-3"),

                                html.Label("Primary address", className="fw-bold mb-2"),
                                dbc.InputGroup([
                                    dbc.InputGroupText(html.I(className="fa fa-user text-info")),
                                    dbc.Input(id='email-to', type='email', placeholder='you@example.com')
                                ], className="mb-2"),
                                html.Small("All alerts go here.", className="text-muted d-block mb-3"),

                                html.Label("Extra recipients (optional)", className="fw-bold mb-2"),
                                dbc.InputGroup([
                                    dbc.InputGroupText(html.I(className="fa fa-users")),
                                    dbc.Input(id='email-cc', type='text', placeholder='person1@example.com, person2@example.com')
                                ], className="mb-2"),
                                html.Small("Separate with commas.", className="text-muted d-block mb-3"),

                                html.Hr(),

                                html.H6([html.I(className="fa fa-filter me-2 text-warning"), "Which alerts to send"], className="mb-3"),

                                dbc.Checklist(
                                    id='email-alert-types',
                                    options=[
                                        {'label': 'Critical alerts', 'value': 'critical'},
                                        {'label': 'Warning alerts', 'value': 'warning'},
                                        {'label': 'Info notifications', 'value': 'info'},
                                        {'label': 'Daily summary', 'value': 'daily_summary'},
                                        {'label': 'Weekly digest', 'value': 'weekly_digest'}
                                    ],
                                    value=['critical', 'warning'],
                                    switch=True,
                                    className="mb-3"
                                )
                            ])
                        ], className="glass-card border-0 shadow-sm mb-3"),

                        # Enable toggle
                        dbc.Card([
                            dbc.CardBody([
                                html.H6([html.I(className="fa fa-toggle-on me-2 text-success"), "Email Alerts"], className="mb-2"),
                                dbc.Switch(id='email-enable-switch', label="Enable email alerts", value=False, className="mb-2"),
                                html.Small("Fires on critical alerts only.", className="text-muted d-block"),
                                html.Div(id='email-settings-status', className="mt-2"),
                            ])
                        ], className="glass-card border-0 shadow-sm"),
                    ], className="p-3")
                ], label="Email", tab_id="smtp-settings-tab"),

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
                                        html.I(className="fa fa-info-circle me-2 text-info"),
                                        "Email history will be populated from email notification logs"
                                    ], color="info", className="mb-0")
                                ])
                            ])
                        ], className="glass-card border-0 shadow-sm")
                    ], className="p-3")
                ], label="Test", tab_id="test-history-tab"),

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
                ], label="Schedules", tab_id="schedules-list-tab"),

                # Add New Report Schedule Tab
                dbc.Tab([
                    html.Div([
                        html.H6([
                            html.I(className="fa fa-plus-circle me-2 text-success"),
                            "Schedule a Report"
                        ], className="mb-3"),

                        dbc.Row([
                            dbc.Col([
                                html.Label("Report Name", className="fw-bold mb-2"),
                                dbc.Input(
                                    id='schedule-id-input',
                                    type='text',
                                    placeholder='e.g. daily-report',
                                    value=''
                                )
                            ], width=12, className="mb-3"),
                        ]),

                        dbc.Row([
                            dbc.Col([
                                html.Label("Report Type", className="fw-bold mb-2"),
                                dbc.Select(
                                    id='schedule-template-select',
                                    options=[
                                        {'label': 'Executive Summary', 'value': 'executive_summary'},
                                        {'label': 'Security Audit', 'value': 'security_audit'},
                                        {'label': 'Network Activity', 'value': 'network_activity'},
                                        {'label': 'Device Inventory', 'value': 'device_inventory'},
                                        {'label': 'Threat Analysis', 'value': 'threat_analysis'}
                                    ],
                                    value='executive_summary'
                                )
                            ], width=6),

                            dbc.Col([
                                html.Label("File Format", className="fw-bold mb-2"),
                                dbc.Select(
                                    id='schedule-format-select',
                                    options=[
                                        {'label': 'PDF', 'value': 'pdf'},
                                        {'label': 'Excel', 'value': 'excel'}
                                    ],
                                    value='pdf'
                                )
                            ], width=6)
                        ], className="mb-3"),

                        dbc.Row([
                            dbc.Col([
                                html.Label("Frequency", className="fw-bold mb-2"),
                                dbc.RadioItems(
                                    id='schedule-type-radio',
                                    options=[
                                        {'label': 'Every N hours', 'value': 'interval'},
                                        {'label': 'Custom (advanced)', 'value': 'cron'}
                                    ],
                                    value='interval',
                                    inline=True
                                )
                            ], width=12, className="mb-3"),
                        ]),

                        html.Div([
                            dbc.Row([
                                dbc.Col([
                                    html.Label("Schedule", className="fw-bold mb-2"),
                                    dbc.Input(
                                        id='schedule-cron-input',
                                        type='text',
                                        placeholder='0 8 * * *',
                                        value='0 8 * * *'
                                    ),
                                    html.Small([
                                        "Examples: ",
                                        html.Code("0 8 * * *", className="text-primary"), " (daily at 8 AM), ",
                                        html.Code("0 9 * * 1", className="text-primary"), " (Monday at 9 AM)"
                                    ], className="text-muted")
                                ], width=12)
                            ], className="mb-3")
                        ], id='cron-expression-div', style={'display': 'none'}),

                        html.Div([
                            dbc.Row([
                                dbc.Col([
                                    html.Label("Repeat every (hours)", className="fw-bold mb-2"),
                                    dbc.Input(
                                        id='schedule-interval-input',
                                        type='number',
                                        min=1,
                                        max=168,
                                        value=24,
                                        step=1
                                    ),
                                    html.Small("Between 1 and 168 hours.", className="text-muted")
                                ], width=12)
                            ], className="mb-3")
                        ], id='interval-hours-div', style={'display': 'block'}),

                        dbc.Row([
                            dbc.Col([
                                html.Label("Cover the last (days)", className="fw-bold mb-2"),
                                dbc.Input(
                                    id='schedule-days-input',
                                    type='number',
                                    value=7,
                                    min=1,
                                    max=365,
                                    step=1
                                )
                            ], width=6),

                            dbc.Col([
                                html.Label("Send to (optional)", className="fw-bold mb-2"),
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
                                    "Add Report"
                                ], id="add-schedule-btn", color="success", className="w-100")
                            ])
                        ]),

                        html.Div(id='add-schedule-status', className="mt-3")
                    ], className="p-3")
                ], label="Add Report", tab_id="add-schedule-tab"),

                # Daily Digest Tab
                dbc.Tab([
                    html.Div([
                        html.H6([
                            html.I(className="fa fa-envelope me-2 text-info"),
                            "Daily Summary Email"
                        ], className="mb-3"),
                        html.P("Get a daily email with your network's security highlights and trends.", className="text-muted mb-3"),

                        dbc.Row([
                            dbc.Col([
                                html.Label("Send at", className="fw-bold mb-2"),
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
                                        html.Small("Hour (24h)", className="text-muted")
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
                                        html.Small("Minute", className="text-muted")
                                    ], width=6)
                                ])
                            ], width=6),

                            dbc.Col([
                                html.Label("Send to (optional)", className="fw-bold mb-2"),
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
                                    "Turn On"
                                ], id="enable-digest-btn", color="info", className="w-100 mb-2")
                            ], width=6),
                            dbc.Col([
                                dbc.Button([
                                    html.I(className="fa fa-paper-plane me-2"),
                                    "Send Now"
                                ], id="test-digest-btn", color="warning", outline=True, className="w-100 mb-2")
                            ], width=6)
                        ]),

                        html.Div(id='digest-status', className="mt-3")
                    ], className="p-3")
                ], label="Daily Digest", tab_id="daily-digest-tab")

            ], id="email-modal-tabs", active_tab="push-notifications-tab"),
            # Hidden: template components kept in DOM so their callbacks don't error
            html.Div([
                dbc.Select(id='template-select', options=[
                    {'label': 'Critical', 'value': 'critical'},
                    {'label': 'Warning', 'value': 'warning'},
                    {'label': 'Daily', 'value': 'daily'},
                    {'label': 'Weekly', 'value': 'weekly'}
                ], value='critical'),
                dbc.Input(id='template-subject', value="[IoTSentinel] Critical Security Alert: {{alert_type}}"),
                dbc.Textarea(id='template-body',
                             value="A critical security alert has been detected.\n\nAlert Type: {{alert_type}}\nDevice: {{device_name}}"),
                dbc.Button("Save Template", id='save-template-btn'),
                dbc.Button("Reset to Default", id='reset-template-btn'),
            ], style={"display": "none"}),
        ], className="modal-scroll modal-compact-switches"),
        dbc.ModalFooter([
            dbc.Button([
                html.I(className="fa fa-save me-2"),
                "Save Settings"
            ], id='save-email-settings-btn', color="primary", className="me-2"),
        ])
    ], id="email-modal", size="xl", is_open=False, scrollable=True),

    # Phase 3: Lightweight unlock modal for threat-intel API key entry
    dbc.Modal([
        dbc.ModalHeader(dbc.ModalTitle([
            html.I(className="fa fa-unlock-alt me-2 text-success"),
            "Unlock Threat Intelligence",
        ])),
        dbc.ModalBody([
            html.P(
                "Cross-check suspicious device IPs against global databases that track "
                "hackers and malware. A free AbuseIPDB account takes 2 minutes to set up.",
                className="text-muted mb-3",
            ),
            dbc.Label("AbuseIPDB API Key", html_for="unlock-api-key-input"),
            dbc.Input(
                id="unlock-api-key-input",
                type="password",
                placeholder="Paste your API key here…",
                className="mb-1",
            ),
            html.Small(
                "Get your free key at abuseipdb.com → Account → API",
                className="text-muted d-block mb-3",
            ),
            html.Div(id="unlock-api-key-feedback", className="text-danger small"),
        ]),
        dbc.ModalFooter([
            dbc.Button("Save & Unlock", id="unlock-save-btn", color="success", className="me-2"),
            dbc.Button("Cancel", id="unlock-cancel-btn", color="secondary", outline=True),
        ]),
    ], id="unlock-padlock-modal", is_open=False, centered=True),

    # Firewall Control Modal
    dbc.Modal([
        dbc.ModalHeader(dbc.ModalTitle([
            html.I(className="fa fa-shield-halved me-2 text-success"),
            "Firewall Control"
        ]), close_button=True),
        dbc.ModalBody([
            # Action feedback toast area
            html.Div(id='fw-action-toast', className="mb-2"),
            dbc.Tabs([
                # Lockdown Control Tab
                dbc.Tab([
                    html.Div([
                        dbc.Card([
                            dbc.CardBody([
                                html.H6([html.I(className="fa fa-lock me-2 text-danger"), "Lockdown Mode"], className="mb-3"),
                                dbc.Alert([
                                    html.H5("Lockdown Mode", className="alert-heading"),
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
                                dbc.Row([
                                    dbc.Col(html.H6([html.I(className="fa fa-ban me-2 text-danger"), "Blocked Devices"], className="mb-0")),
                                    dbc.Col(dbc.Button([html.I(className="fa fa-rotate-right me-1 text-info"), "Refresh"],
                                            id="fw-refresh-blocked-btn", color="outline-secondary", size="sm"),
                                            width="auto"),
                                ], align="center", className="mb-3"),
                                html.Div(id='firewall-blocked-devices', children=[
                                    html.P("No blocked devices", className="text-muted text-center py-4")
                                ])
                            ])
                        ], className="glass-card border-0 shadow-sm")
                    ], className="p-3")
                ], label="Blocked Devices", tab_id="firewall-blocked-tab"),

                # Active Rules Tab
                dbc.Tab([
                    html.Div([
                        dbc.Card([
                            dbc.CardBody([
                                dbc.Row([
                                    dbc.Col(html.H6([html.I(className="fa fa-list me-2 text-primary"), "Active Firewall Rules"], className="mb-0")),
                                    dbc.Col([
                                        dbc.Button([html.I(className="fa fa-rotate-right me-1 text-info"), "Refresh"],
                                                   id="fw-refresh-rules-btn", color="outline-secondary", size="sm", className="me-2"),
                                        dbc.Button([html.I(className="fa fa-rotate-left me-1 text-info"), "Rollback"],
                                                   id="fw-rollback-btn", color="outline-warning", size="sm",
                                                   title="Restore rules from last backup"),
                                    ], width="auto", className="d-flex align-items-center"),
                                ], align="center", className="mb-3"),
                                html.Small(id='fw-backend-badge', className="text-muted d-block mb-2"),
                                html.Div(id='firewall-rules-list', children=[
                                    html.P("No active rules", className="text-muted text-center py-4")
                                ])
                            ])
                        ], className="glass-card border-0 shadow-sm")
                    ], className="p-3")
                ], label="Active Rules", tab_id="firewall-rules-tab"),

                # Add Rule Tab
                dbc.Tab([
                    html.Div([
                        dbc.Card([
                            dbc.CardBody([
                                html.H6([html.I(className="fa fa-plus me-2 text-success"), "Add Firewall Rule"], className="mb-3"),
                                dbc.Row([
                                    dbc.Col([
                                        dbc.Label("Target IP Address", html_for="fw-target-ip"),
                                        dbc.Input(id="fw-target-ip", type="text", placeholder="192.168.1.42",
                                                  className="mb-2"),
                                    ], md=6),
                                    dbc.Col([
                                        dbc.Label("Target Port (optional)", html_for="fw-target-port"),
                                        dbc.Input(id="fw-target-port", type="text", placeholder="e.g. 22, 80-443",
                                                  className="mb-2"),
                                    ], md=6),
                                ]),
                                dbc.Row([
                                    dbc.Col([
                                        dbc.Label("Action", html_for="fw-action-select"),
                                        dbc.Select(id="fw-action-select", options=[
                                            {"label": "Block (DROP)", "value": "block"},
                                            {"label": "Allow (ACCEPT)", "value": "allow"},
                                        ], value="block", className="mb-2"),
                                    ], md=6),
                                    dbc.Col([
                                        dbc.Label("Direction", html_for="fw-direction-select"),
                                        dbc.Select(id="fw-direction-select", options=[
                                            {"label": "Inbound + Outbound", "value": "both"},
                                            {"label": "Inbound only", "value": "in"},
                                            {"label": "Outbound only", "value": "out"},
                                        ], value="both", className="mb-2"),
                                    ], md=6),
                                ]),
                                dbc.Checklist(
                                    options=[{"label": "Dry-run preview (no real changes)", "value": "dry_run"}],
                                    value=["dry_run"],
                                    id="fw-dry-run-toggle",
                                    switch=True,
                                    className="mb-3",
                                ),
                                dbc.Row([
                                    dbc.Col(dbc.Button([html.I(className="fa fa-eye me-1"), "Preview"],
                                            id="fw-preview-btn", color="outline-info", size="sm"), width="auto"),
                                    dbc.Col(dbc.Button([html.I(className="fa fa-check me-1"), "Apply Rule"],
                                            id="fw-apply-rule-btn", color="danger", size="sm"), width="auto"),
                                ], className="g-2 mb-3"),
                                html.Div(id='fw-rule-preview'),
                            ])
                        ], className="glass-card border-0 shadow-sm")
                    ], className="p-3")
                ], label="Add Rule", tab_id="firewall-add-rule-tab"),

                # Audit Log Tab
                dbc.Tab([
                    html.Div([
                        dbc.Card([
                            dbc.CardBody([
                                dbc.Row([
                                    dbc.Col(html.H6([html.I(className="fa fa-history me-2 text-muted"), "Audit Log"], className="mb-0")),
                                    dbc.Col(dbc.Button([html.I(className="fa fa-rotate-right me-1 text-info"), "Refresh"],
                                            id="fw-refresh-audit-btn", color="outline-secondary", size="sm"),
                                            width="auto"),
                                ], align="center", className="mb-3"),
                                html.Div(id='firewall-audit-log', className="scroll-panel-340",
                                         children=[html.P("No audit entries.", className="text-muted text-center py-4")])
                            ])
                        ], className="glass-card border-0 shadow-sm")
                    ], className="p-3")
                ], label="Audit Log", tab_id="firewall-audit-tab"),

            ], id="firewall-tabs", active_tab="firewall-lockdown-tab"),
            dcc.Interval(id='firewall-refresh-interval', interval=30_000, n_intervals=0),
            dcc.Store(id='fw-release-signal', data=0),
        ], className="modal-scroll-65 modal-compact-switches"),
    ], id="firewall-modal", size="xl", is_open=False),

    # Profile Edit Modal - Enhanced Design
    dbc.Modal([
        dbc.ModalHeader(dbc.ModalTitle([
            html.I(className="fa fa-user-edit me-2 text-info"),
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
                                    dbc.InputGroupText(html.I(className="fa fa-lock text-info")),
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
                                    dbc.Progress(id='password-strength-bar', value=0, className="mb-2 progress-xs"),
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
                                ], className="alert alert-info d-flex align-items-center mb-3 u-text-sm"),

                                # Registered Devices List
                                html.Div(id='biometric-devices-list', className="mb-3"),

                                # In-memory store for username passed to the WebAuthn clientside callback
                                dcc.Store(id='biometric-username-store', storage_type='memory'),

                                # Register New Biometric Button
                                dbc.Button([
                                    html.I(className="fa fa-plus-circle me-2"),
                                    "Register New Biometric Device"
                                ], id='register-biometric-btn', color="primary", outline=True, className="w-100 mb-2"),

                                # Secure-context note: WebAuthn only works over HTTPS/localhost.
                                # Filled + the button disabled by a clientside callback when the
                                # browser is on a plain-http origin (e.g. http://iotsentinel.local).
                                html.Div(id='biometric-secure-note', className="small text-warning mb-1"),

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
                                ], className="alert alert-info d-flex align-items-center mb-3 u-text-sm"),

                                # 2FA Status Display
                                html.Div(id='totp-status-display', className="mb-3"),

                                # Setup Section (hidden by default, shown when enabling)
                                html.Div([
                                    html.Hr(),
                                    html.H6([html.I(className="fa fa-qrcode me-2 text-info"), "Setup Authenticator"], className="mb-3"),

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
                                            ], id='download-backup-codes-btn', color="warning", outline=True, size="sm", className="w-100"),
                                            dcc.Download(id='download-backup-codes')
                                        ], md=6)
                                    ]),

                                    html.Hr(),
                                    html.H6([html.I(className="fa fa-check-circle me-2 text-success"), "Verify Setup"], className="mb-3"),
                                    html.P("Enter the 6-digit code from your authenticator app to enable 2FA:", className="mb-2"),

                                    dbc.InputGroup([
                                        dbc.InputGroupText(html.I(className="fa fa-keyboard text-info")),
                                        dbc.Input(
                                            id='totp-verification-code',
                                            type='text',
                                            placeholder="000000",
                                            maxLength=6,
                                            className="text-center font-monospace u-text-xl u-otp-display"
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
                                        {'label': 'Email Notifications - receive alerts via email', 'value': 'email'},
                                        {'label': 'Browser Notifications - desktop push alerts', 'value': 'browser'},
                                        {'label': 'Sound Alerts - audio notifications', 'value': 'sound'},
                                        {'label': 'Weekly Reports - summary emails', 'value': 'reports'},
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
                                                html.I(className="fa fa-house text-success me-2"),
                                                html.Span("Simple", className="fw-bold"),
                                                html.Br(),
                                                html.Small("Focused on what matters — device status, privacy, home security", className="text-muted")
                                            ]),
                                            'value': 'simple'
                                        },
                                        {
                                            'label': html.Div([
                                                html.I(className="fa fa-sliders text-info me-2"),
                                                html.Span("Advanced", className="fw-bold"),
                                                html.Br(),
                                                html.Small("Full security console — threat intelligence, forensics, all tools", className="text-muted")
                                            ]),
                                            'value': 'advanced'
                                        },
                                        {
                                            'label': html.Div([
                                                html.I(className="fa fa-grid-2 text-warning me-2"),
                                                html.Span("Custom", className="fw-bold"),
                                                html.Br(),
                                                html.Small("Your own customized layout", className="text-muted")
                                            ]),
                                            'value': 'custom'
                                        }
                                    ],
                                    value=None,  # Value loaded from database via callback
                                    className="mb-3"
                                ),
                            ])
                        ], className="glass-card border-0 shadow-sm mb-3"),
                    ], className="p-3 modal-compact-switches")
                ], label="Preferences", tab_id="preferences-tab"),

                # AI Settings Tab (admin only)
                dbc.Tab([
                    html.Div([
                        dbc.Card([
                            dbc.CardBody([
                                html.H6([
                                    html.I(className="fa fa-robot me-2 text-info"),
                                    "AI Provider API Keys"
                                ], className="mb-1"),
                                html.P(
                                    "Enter your cloud AI provider keys. Keys are stored in .env and never logged. "
                                    "Groq and Gemini have free tiers. OpenAI and Claude are paid.",
                                    className="text-muted small mb-3"
                                ),

                                dbc.Label("Groq API Key (free tier - recommended)", className="fw-bold"),
                                dbc.InputGroup([
                                    dbc.InputGroupText(html.I(className="fa fa-key")),
                                    dbc.Input(
                                        id='ai-groq-key-input',
                                        type='password',
                                        placeholder="gsk_...",
                                        autocomplete="off"
                                    ),
                                ], className="mb-3"),

                                dbc.Label("OpenAI API Key (paid - Business tier)", className="fw-bold"),
                                dbc.InputGroup([
                                    dbc.InputGroupText(html.I(className="fa fa-key")),
                                    dbc.Input(
                                        id='ai-openai-key-input',
                                        type='password',
                                        placeholder="sk-...",
                                        autocomplete="off"
                                    ),
                                ], className="mb-3"),

                                dbc.Label("Anthropic API Key (paid - Claude)", className="fw-bold"),
                                dbc.InputGroup([
                                    dbc.InputGroupText(html.I(className="fa fa-key")),
                                    dbc.Input(
                                        id='ai-anthropic-key-input',
                                        type='password',
                                        placeholder="sk-ant-...",
                                        autocomplete="off"
                                    ),
                                ], className="mb-3"),

                                dbc.Label("Gemini API Key (free tier - backup)", className="fw-bold"),
                                dbc.InputGroup([
                                    dbc.InputGroupText(html.I(className="fa fa-key")),
                                    dbc.Input(
                                        id='ai-gemini-key-input',
                                        type='password',
                                        placeholder="AIza...",
                                        autocomplete="off"
                                    ),
                                ], className="mb-3"),

                                dbc.Button([
                                    html.I(className="fa fa-save me-2"),
                                    "Save API Keys"
                                ], id='ai-key-save-btn', color="info", className="w-100 mb-2"),

                                html.Div(id='ai-key-save-result'),

                                html.Hr(),
                                html.P([
                                    "Get a free Groq key at ",
                                    html.A("console.groq.com", href="https://console.groq.com",
                                           target="_blank", className="text-info"),
                                    ", a free Gemini key at ",
                                    html.A("aistudio.google.com", href="https://aistudio.google.com/apikey",
                                           target="_blank", className="text-info"),
                                    ". OpenAI keys at ",
                                    html.A("platform.openai.com", href="https://platform.openai.com",
                                           target="_blank", className="text-info"),
                                    ", Claude keys at ",
                                    html.A("console.anthropic.com", href="https://console.anthropic.com",
                                           target="_blank", className="text-info"),
                                    "."
                                ], className="text-muted small mb-0"),
                            ])
                        ], className="glass-card border-0 shadow-sm mb-3"),

                        # AI Engine health — provider status, usage, cache
                        dbc.Card([
                            dbc.CardBody([
                                html.Div([
                                    html.H6([
                                        html.I(className="fa fa-heart-pulse me-2 text-info"),
                                        "AI Engine Health"
                                    ], className="mb-0"),
                                    dbc.Button(
                                        html.I(className="fa fa-rotate"),
                                        id='ai-health-refresh-btn',
                                        color="link", size="sm",
                                        className="p-0 text-muted",
                                        title="Refresh",
                                    ),
                                ], className="d-flex justify-content-between align-items-center mb-2"),
                                html.Div(id='ai-health-card-body'),
                            ])
                        ], className="glass-card border-0 shadow-sm mb-3"),

                        # Privacy Mode — local AI first (compact inline toggle)
                        dbc.Card([
                            dbc.CardBody([
                                html.Div([
                                    html.Div([
                                        html.I(className="fa fa-shield-halved me-2 text-success"),
                                        html.Span("AI Privacy Mode", className="fw-semibold"),
                                        html.Span(" - Keep network data on device, Ollama first",
                                                  className="text-muted small ms-2"),
                                    ], className="d-flex align-items-center"),
                                    dbc.Switch(
                                        id='ai-privacy-mode-toggle',
                                        label="",
                                        value=False,
                                        className="mb-0",
                                    ),
                                ], className="d-flex align-items-center justify-content-between"),
                                html.Div(id='ai-privacy-mode-result', className="small mt-1"),
                            ], className="py-2 px-3")
                        ], className="glass-card border-0 shadow-sm mb-3"),
                    ], className="p-3")
                ], label="AI Settings", tab_id="ai-settings-tab", id="ai-settings-tab-nav"),

                # Credentials Tab (admin only) — Google OAuth, SMTP, Threat Intel
                dbc.Tab([
                    html.Div([

                        # Google Sign-In
                        dbc.Card([
                            dbc.CardBody([
                                html.H6([
                                    html.I(className="fa-brands fa-google me-2 text-danger"),
                                    "Google Sign-In (OAuth)"
                                ], className="mb-1"),
                                html.P(
                                    "Allow users to log in with their Google account. "
                                    "Requires a project in Google Cloud Console.",
                                    className="text-muted small mb-3"
                                ),
                                dbc.Label("Client ID", className="fw-bold"),
                                dbc.InputGroup([
                                    dbc.InputGroupText(html.I(className="fa fa-id-card")),
                                    dbc.Input(id='creds-google-client-id', type='password',
                                              placeholder="xxxxxxxxx.apps.googleusercontent.com",
                                              autocomplete="off"),
                                ], className="mb-2"),
                                dbc.Label("Client Secret", className="fw-bold"),
                                dbc.InputGroup([
                                    dbc.InputGroupText(html.I(className="fa fa-key")),
                                    dbc.Input(id='creds-google-client-secret', type='password',
                                              placeholder="GOCSPX-...", autocomplete="off"),
                                ], className="mb-3"),
                                dbc.Button([
                                    html.I(className="fa fa-save me-2"), "Save OAuth Credentials"
                                ], id='creds-google-save-btn', color="danger", outline=True,
                                    className="w-100 mb-2"),
                                html.Div(id='creds-google-save-result'),
                                html.Hr(),
                                html.P([
                                    "1. Create credentials at ",
                                    html.A("console.cloud.google.com",
                                           href="https://console.cloud.google.com",
                                           target="_blank", className="text-info"),
                                    ".", html.Br(),
                                    "2. Add this redirect URI: ",
                                    html.Code(id='creds-google-redirect-uri', className="small"),
                                    html.Br(),
                                    "3. Save — Google Sign-in activates immediately.",
                                ], className="text-muted small mb-0"),
                            ])
                        ], className="glass-card border-0 shadow-sm mb-3"),

                    ], className="p-3")
                ], label="Credentials", tab_id="credentials-tab", id="credentials-tab-nav"),

            ], id="profile-edit-tabs", active_tab="profile-info-tab"),
        ]),
    ], id="profile-edit-modal", size="lg", is_open=False, scrollable=True),

    # User Management Modal (Admin Only) - Enhanced Design
    dbc.Modal([
        dbc.ModalHeader(dbc.ModalTitle([
            html.I(className="fa fa-users-gear me-2 text-info"),
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
                                        html.H6([html.I(className="fa fa-info-circle me-2 text-info"), "Role Permissions & Templates"], className="mb-2"),
                                        html.Div([
                                            html.Div([
                                                html.Span("👑 Admin:", className="fw-bold text-warning me-2"),
                                                "Can manage users, configure settings, view all data, and perform all actions"
                                            ], className="mb-2 u-text-sm"),
                                            html.Div([
                                                html.Span("👁️ Viewer:", className="fw-bold text-info me-2"),
                                                "Can view dashboard, alerts, and reports. Cannot modify settings or manage users"
                                            ], className="mb-2 u-text-sm"),
                                            html.Div([
                                                html.Span("💡 Note:", className="fw-bold text-success me-2"),
                                                "All users can select their preferred dashboard template (Security Admin, Home User, Developer, or Custom) in Preferences"
                                            ], className="u-text-sm")
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
                                html.H6([html.I(className="fa fa-users me-2 text-primary"), "Email Recipients"], className="mb-3"),

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
        ])
    ], id="user-modal", size="xl", is_open=False, scrollable=True),

    # Device Management Modal - Enhanced with Tabs
    dbc.Modal([
        dbc.ModalHeader(dbc.ModalTitle([
            html.I(className="fa fa-diagram-project me-2 text-info"),
            "Device Management"
        ]), close_button=True),
        dbc.ModalBody([
            dbc.Tabs([
                # Devices List Tab
                dbc.Tab([
                    html.Div([
                        dbc.Card([
                            dbc.CardBody([
                                dbc.Col(html.H6([html.I(className="fa fa-list me-2 text-info"), "Devices"], className="mb-0")),

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

                # Analytics Tab - NEW
                dbc.Tab([
                    html.Div([
                        dbc.Card([
                            dbc.CardHeader([
                                html.I(className="fa fa-chart-pie me-2 text-info"),
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
                                        className="chart-h-600"
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
                                            className="border border-info border-dashed rounded p-3 dropzone-area dropzone-area--info"
                                        ),
                                        html.Div(id='import-status', className="mt-2")
                                    ], md=6)
                                ])
                            ])
                        ], className="glass-card border-0 shadow-sm")
                    ], className="p-3")
                ], label="Import/Export", tab_id="import-export-tab")

            ], id="device-mgmt-tabs", active_tab="devices-list-tab")
        ], className="modal-compact-switches"),
        dbc.ModalFooter([
            html.Div(id='device-mgmt-timestamp-display', className="me-auto text-muted small"),
            dbc.Button([
                html.I(className="fa fa-sync-alt me-2"),
                "Refresh All"
            ], id="refresh-device-mgmt-btn", color="info", outline=True, size="sm", className="me-2 modal-refresh-btn"),
        ], className="border-top pt-3"),
        dcc.Store(id='device-mgmt-timestamp-store')
    ], id="device-mgmt-modal", size="xl", is_open=False, scrollable=True),

    # Device Details Modal - centered popup (opens stacked on top of device-mgmt-modal)
    dbc.Modal([
        dbc.ModalHeader(
            dbc.ModalTitle(html.Span(id='device-detail-modal-title')),
            close_button=True
        ),
        dbc.ModalBody([
            html.Div(id='device-detail-view')
        ], className="modal-compact-switches"),
        dbc.ModalFooter([
            dbc.Button([html.I(className="fa fa-save me-2"), "Save Changes"],
                       id='save-device-details-btn', color="primary",
                       className="cyber-button"),
        ]),
    ], id="device-detail-modal", size="lg", is_open=False,
       centered=True, scrollable=True),

    # Dashboard Preferences Modal - Enhanced
    dbc.Modal([
        dbc.ModalHeader(dbc.ModalTitle([
            html.I(className="fa fa-sliders-h me-2 text-info"),
            "Dashboard Preferences"
        ])),
        dbc.ModalBody([
            dbc.Tabs([
                # Appearance Tab
                dbc.Tab([
                    html.Div([
                        dbc.Card([
                            dbc.CardBody([
                                html.H6([html.I(className="fa fa-palette me-2 text-purple"), "Theme & Appearance"], className="mb-3"),

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

                                html.H6([html.I(className="fa fa-th me-2 text-info"), "Layout Settings"], className="mb-3"),

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

                                html.Hr(),

                                html.H6([html.I(className="fa fa-user-gear me-2 text-info"), "Personalization"], className="mb-3"),

                                dbc.Label("Dashboard Template", className="fw-bold"),
                                dbc.Select(
                                    id='pref-dashboard-template',
                                    options=[
                                        {'label': 'Simple — focused on what matters', 'value': 'simple'},
                                        {'label': 'Advanced — full security console', 'value': 'advanced'},
                                        {'label': 'Custom — I\'ll customize it myself', 'value': 'custom'}
                                    ],
                                    value='simple',
                                    className="mb-3"
                                ),

                                dbc.Label("Household Role", className="fw-bold"),
                                html.Small("Affects available features and default security thresholds.", className="text-muted d-block mb-2"),
                                dbc.Select(
                                    id='pref-family-role',
                                    options=[
                                        {'label': 'Parent / Guardian — full access', 'value': 'parent'},
                                        {'label': 'Child — restricted access for safety', 'value': 'kid'}
                                    ],
                                    value='parent',
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
                                html.H6([html.I(className="fa fa-tachometer-alt me-2 text-info"), "Performance & Data"], className="mb-3"),

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

                                html.H6([html.I(className="fa fa-brain me-2 text-purple"), "AI & Detection"], className="mb-3"),

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
                                html.H6([html.I(className="fa fa-globe-americas me-2 text-info"), "Regional Settings"], className="mb-3"),

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
                                html.H6([html.I(className="fa fa-bell me-2 text-warning"), "Notification Preferences"], className="mb-3"),

                                dbc.Label("Enable Notifications For:", className="fw-bold mb-2"),
                                dbc.Checklist(
                                    id='alert-notification-prefs',
                                    options=[
                                        {'label': 'Critical Threats - Immediate action required', 'value': 'critical'},
                                        {'label': 'High Priority Alerts - Important security events', 'value': 'high'},
                                        {'label': 'Medium Priority Alerts - Notable events', 'value': 'medium'},
                                        {'label': 'System Events - Status changes', 'value': 'system'},
                                        {'label': 'Device Status Changes - New/disconnected devices', 'value': 'device'}
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
                                html.H6([html.I(className="fa fa-cloud-download-alt me-2 text-info"), "Automated Export"], className="mb-3"),

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

                                html.H6([html.I(className="fa fa-database me-2 text-info"), "Backup Settings"], className="mb-3"),

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
        ], className="modal-scroll modal-compact-switches")
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
                                    html.P("MQTT Messages", className="text-muted mb-0 u-text-sm")
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
                                    html.P("CoAP Requests", className="text-muted mb-0 u-text-sm")
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
                                    html.P("Zigbee Packets", className="text-muted mb-0 u-text-sm")
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
                                    html.P("Active Devices", className="text-muted mb-0 u-text-sm")
                                ], className="text-center p-2")
                            ], className="glass-card border-0 shadow-sm mb-3")
                        ], md=3)
                    ], className="mb-3"),

                    html.Div(id="mqtt-coap-stats", className="mb-3"),

                    dbc.Row([
                        dbc.Col([
                            dbc.Card([
                                dbc.CardHeader([
                                    html.I(className="fa fa-chart-pie me-2 text-info"),
                                    "Protocol Distribution"
                                ], className="glass-card-header"),
                                dbc.CardBody([
                                    dcc.Graph(id='protocol-distribution-chart', config={'displayModeBar': False}, className="chart-h-300")
                                ])
                            ], className="glass-card border-0 shadow-sm")
                        ], md=6),
                        dbc.Col([
                            dbc.Card([
                                dbc.CardHeader([
                                    html.I(className="fa fa-chart-line me-2 text-info"),
                                    "Protocol Activity Timeline (7 Days)"
                                ], className="glass-card-header"),
                                dbc.CardBody([
                                    dcc.Graph(id='protocol-timeline-chart', config={'displayModeBar': False}, className="chart-h-300")
                                ])
                            ], className="glass-card border-0 shadow-sm")
                        ], md=6)
                    ])
                ], label="Overview", tab_id="protocol-overview-tab", className="p-3"),

                # MQTT Tab
                dbc.Tab([
                    dbc.Card([
                        dbc.CardHeader([
                            html.I(className="fa fa-comment-dots me-2 text-purple"),
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
                            html.I(className="fa fa-exchange-alt me-2 text-info"),
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
                            html.I(className="fa fa-list me-2 text-info"),
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
        ], className="modal-scroll"),
        dbc.ModalFooter([
            html.Div(id='protocol-timestamp-display', className="me-auto"),
            dbc.Button([
                html.I(className="fa fa-sync-alt me-2"),
                "Refresh"
            ], id="refresh-protocol-btn", color="info", outline=True, size="sm", className="me-2"),
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
                                    html.P("Active Threats", className="text-muted mb-0 u-text-sm")
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
                                    html.P("Vulnerabilities", className="text-muted mb-0 u-text-sm")
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
                                    html.P("Blocked Devices", className="text-muted mb-0 u-text-sm")
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
                                    html.P("Threat Level", className="text-muted mb-0 u-text-sm")
                                ], className="text-center p-2")
                            ], className="glass-card border-0 shadow-sm mb-3")
                        ], md=3)
                    ], className="mb-3"),

                    html.Div(id="threat-detection-stats", className="mb-3"),

                    dbc.Row([
                        dbc.Col([
                            dbc.Card([
                                dbc.CardHeader([
                                    html.I(className="fa fa-chart-pie me-2 text-info"),
                                    "Threat Distribution"
                                ], className="glass-card-header"),
                                dbc.CardBody([
                                    dcc.Graph(id='threat-intel-distribution-chart', config={'displayModeBar': False}, className="chart-h-300")
                                ])
                            ], className="glass-card border-0 shadow-sm")
                        ], md=6),
                        dbc.Col([
                            dbc.Card([
                                dbc.CardHeader([
                                    html.I(className="fa fa-clock me-2 text-info"),
                                    "Recent Threats"
                                ], className="glass-card-header"),
                                dbc.CardBody([
                                    html.Div(id='threat-intel-recent-threats', className="scroll-panel-300")
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
                            html.I(className="fa fa-rss me-2 text-info"),
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
                            html.I(className="fa fa-chart-line me-2 text-info"),
                            "Attack Pattern Analysis"
                        ], className="glass-card-header"),
                        dbc.CardBody([
                            html.Div(id='threat-intel-attack-patterns')
                        ])
                    ], className="glass-card border-0 shadow-sm"),

                    # Attack Path Visualization (Kill Chain)
                    dbc.Card([
                        dbc.CardHeader([
                            html.I(className="fa fa-project-diagram me-2 text-info"),
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
                                    className="chart-h-500"
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
                            html.I(className="fa fa-tasks me-2 text-info"),
                            "Threat Response & Mitigation"
                        ], className="glass-card-header"),
                        dbc.CardBody([
                            html.Div(id='threat-intel-response-list')
                        ])
                    ], className="glass-card border-0 shadow-sm")
                ], label="Response", tab_id="threat-intel-response-tab", className="p-3")
            ], id="threat-intel-tabs", active_tab="threat-intel-overview-tab")
        ], className="modal-scroll"),
        dbc.ModalFooter([
            dbc.Button([
                html.I(className="fa fa-sync-alt me-2"),
                "Refresh"
            ], id="refresh-threat-intel-btn", color="info", outline=True, size="sm", className="me-2"),
        ])
    ], id="threat-modal", size="xl", is_open=False, scrollable=True),



    # Privacy Monitoring Modal - Enhanced with Tabs
    dbc.Modal([
        dbc.ModalHeader(dbc.ModalTitle([
            html.I(className="fa fa-user-shield me-2 text-warning"),
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
                                            dbc.Progress(id='privacy-modal-score-bar', value=0, className="mb-2 progress-12"),
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
                                    html.I(className="fa fa-ban me-2 text-info"),
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
                                        dbc.Progress(id='dataflow-inbound-bar', value=0, color="primary", className="mt-2 progress-xs")
                                    ], md=6),
                                    dbc.Col([
                                        html.Label("Outbound Data", className="small text-muted"),
                                        html.H5(id='dataflow-outbound-total', className="text-danger mb-0"),
                                        dbc.Progress(id='dataflow-outbound-bar', value=0, color="danger", className="mt-2 progress-xs")
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
            ], id="privacy-refresh-btn", size="sm", color="primary", outline=True, className="me-2")
        ])
    ], id="privacy-modal", size="xl", is_open=False, scrollable=True),

    # Smart Home Context Modal - Enhanced with Tabs
    dbc.Modal([
        dbc.ModalHeader(dbc.ModalTitle([
            html.I(className="fa fa-house-signal me-2 text-warning"),
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
        ]),
        dcc.Store(id='smarthome-timestamp-store'),
        dcc.Download(id='download-smarthome-csv')
    ], id="smarthome-modal", size="xl", is_open=False, scrollable=True),

    # Network Segmentation Modal - Enhanced with Tabs
    dbc.Modal([
        dbc.ModalHeader(dbc.ModalTitle([
            html.I(className="fa fa-layer-group me-2 text-info"),
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
                                html.H6([html.I(className="fa fa-sitemap me-2 text-info"), "Device Ecosystems"], className="mb-3"),

                                dbc.Alert([
                                    html.I(className="fa fa-info-circle me-2 text-info"),
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
                                dbc.Col(html.H6([html.I(className="fa fa-ban me-2 text-danger"), "Blocked Devices"], className="mb-0")),

                                dbc.Alert([
                                    html.I(className="fa fa-exclamation-triangle me-2 text-warning"),
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
                                    html.I(className="fa fa-magic me-2 text-purple"),
                                    "AI-powered recommendations for optimal network segmentation based on device types, risk profiles, and communication patterns."
                                ], color="success", className="mb-3"),

                                html.Div(id='vlan-recommendations')
                            ])
                        ], className="glass-card border-0 shadow-sm")
                    ], className="p-3")
                ], label="Recommendations", tab_id="seg-recommendations-tab")
            ], id="segmentation-tabs", active_tab="seg-overview-tab")
        ], className="modal-scroll"),
        dbc.ModalFooter([
            html.Div(id='segmentation-timestamp-display', className="me-auto"),
            dbc.Button([
                html.I(className="fa fa-sync-alt me-2"),
                "Refresh Data"
            ], id="refresh-segmentation-btn", color="info", outline=True, size="sm", className="me-2"),
        ]),
        dcc.Store(id='segmentation-timestamp-store')
    ], id="segmentation-modal", size="xl", is_open=False, scrollable=True),

    # Firmware Management Modal - Enhanced with Tabs
    dbc.Modal([
        dbc.ModalHeader(dbc.ModalTitle([
            html.I(className="fa fa-microchip me-2 text-warning"),
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
                                    html.I(className="fa fa-exclamation-triangle me-2 text-warning"),
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
        ], className="modal-scroll modal-compact-switches"),
        dbc.ModalFooter([
            html.Div(id='firmware-timestamp-display', className="me-auto"),
            dbc.Button([
                html.I(className="fa fa-sync-alt me-2"),
                "Refresh"
            ], id='refresh-firmware-btn', color="info", outline=True, size="sm", className="me-2"),
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
            html.Div([
                dbc.Button([
                    html.I(className="fa fa-sync-alt me-1"),
                    "Regenerate"
                ], id="education-regenerate-btn", color="secondary", outline=True, size="sm",
                   className="float-end", style={"fontSize": "0.75rem", "padding": "0.25rem 0.65rem"})
            ], className="clearfix mb-2"),
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
                                dcc.Loading(html.Div(id='threat-scenarios-section'), type="circle")
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
                                dcc.Loading(html.Div(id='security-tips-section'), type="circle")
                            ])
                        ], className="glass-card border-0 shadow-sm")
                    ], className="p-3")
                ], label="Security Tips", tab_id="security-tips-tab"),

            ], id="education-modal-tabs", active_tab="threat-scenarios-tab")
        ]),
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
                                html.H6([html.I(className="fa fa-map me-2 text-danger"), "Global Threat Distribution"], className="mb-1"),
                                html.P("Where your devices connect on the internet over the last 24 hours. "
                                       "Each marker is an external destination IP - larger and redder means more "
                                       "connections. Local (private) addresses are excluded.",
                                       className="text-muted small mb-3"),
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
                                                    html.Span("Last 24 Hours", className="h6 mb-0")
                                                ], className="d-flex align-items-center justify-content-center")
                                            ])
                                        ], className="glass-card mb-3")
                                    ], md=4)
                                ]),
                                dcc.Loading(
                                    dcc.Graph(id='geographic-threat-map',
                                             config={'displayModeBar': False, 'responsive': True,
                                                     # Serve the geo basemap from our own
                                                     # /assets so Plotly never fetches
                                                     # cdn.plot.ly (CSP-blocked + works offline).
                                                     'topojsonURL': '/assets/topojson/'},
                                             className="chart-h-500"),
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
                                    html.I(className="fa fa-info-circle me-2 text-info"),
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
        ], className="modal-scroll"),
        dbc.ModalFooter([
            html.Div(id='threat-map-timestamp-display', className="me-auto"),
            dbc.Button([
                html.I(className="fa fa-sync-alt me-2"),
                "Refresh Map"
            ], id="refresh-threat-map-btn", color="primary", outline=True, size="sm", className="me-2"),
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
                                    html.P("High Risk", className="text-muted mb-0 u-text-sm")
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
                                    html.P("Medium Risk", className="text-muted mb-0 u-text-sm")
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
                                    html.P("Low Risk", className="text-muted mb-0 u-text-sm")
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
                                    html.P("Avg Risk Score", className="text-muted mb-0 u-text-sm")
                                ], className="text-center p-2")
                            ], className="glass-card border-0 shadow-sm mb-3")
                        ], md=3)
                    ], className="mb-3"),

                    dbc.Card([
                        dbc.CardHeader([
                            html.I(className="fa fa-fire me-2 text-warning"),
                            "Device Risk Heat Map"
                        ], className="glass-card-header"),
                        dbc.CardBody([
                            dcc.Loading(
                                dcc.Graph(id='device-risk-heatmap', config={'displayModeBar': False}, className="chart-h-400"),
                                type='circle'
                            )
                        ])
                    ], className="glass-card border-0 shadow-sm")
                ], label="Overview", tab_id="risk-overview-tab", className="p-3"),

                # Device Details Tab
                dbc.Tab([
                    dbc.Card([
                        dbc.CardHeader([
                            html.I(className="fa fa-list me-2 text-info"),
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
                            html.I(className="fa fa-chart-bar me-2 text-info"),
                            "Risk Factor Analysis"
                        ], className="glass-card-header"),
                        dbc.CardBody([
                            dbc.Row([
                                dbc.Col([
                                    dcc.Graph(id='risk-factors-chart', config={'displayModeBar': False}, className="chart-h-300")
                                ], md=6),
                                dbc.Col([
                                    dcc.Graph(id='risk-distribution-chart', config={'displayModeBar': False}, className="chart-h-300")
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
                            html.I(className="fa fa-tools me-2 text-info"),
                            "Risk Mitigation Recommendations"
                        ], className="glass-card-header"),
                        dbc.CardBody([
                            html.Div(id='risk-remediation-recommendations')
                        ])
                    ], className="glass-card border-0 shadow-sm")
                ], label="Remediation", tab_id="risk-remediation-tab", className="p-3")
            ], id="risk-heatmap-tabs", active_tab="risk-overview-tab")
        ], className="modal-scroll"),
        dbc.ModalFooter([
            html.Div(id='risk-heatmap-timestamp-display', className="me-auto"),
            dbc.Button([
                html.I(className="fa fa-sync-alt me-2"),
                "Refresh"
            ], id="refresh-risk-heatmap-btn", color="primary", outline=True, size="sm", className="me-2"),
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
                                    html.P("Exposed Ports", className="text-muted mb-0 u-text-sm")
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
                                    html.P("Running Services", className="text-muted mb-0 u-text-sm")
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
                                    html.P("High-Risk Devices", className="text-muted mb-0 u-text-sm")
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
                                    html.P("Exposure Score", className="text-muted mb-0 u-text-sm")
                                ], className="text-center p-2")
                            ], className="glass-card border-0 shadow-sm mb-3")
                        ], md=3)
                    ], className="mb-3"),

                    html.Div(id="attack-surface-list", className="mb-3"),

                    dbc.Card([
                        dbc.CardHeader([
                            html.I(className="fa fa-chart-bar me-2 text-info"),
                            "Attack Vector Distribution"
                        ], className="glass-card-header"),
                        dbc.CardBody([
                            dcc.Graph(id='attack-surface-vector-chart', config={'displayModeBar': False}, className="chart-h-300")
                        ])
                    ], className="glass-card border-0 shadow-sm mb-3"),
                    dbc.Card([
                        dbc.CardHeader([
                            html.I(className="fa fa-list me-2 text-info"),
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
                            html.I(className="fa fa-server me-2 text-info"),
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
                            html.I(className="fa fa-door-open me-2 text-warning"),
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
                            html.I(className="fa fa-shield-alt me-2 text-success"),
                            "Attack Surface Reduction Recommendations"
                        ], className="glass-card-header"),
                        dbc.CardBody([
                            html.Div(id='attack-surface-mitigation-list')
                        ])
                    ], className="glass-card border-0 shadow-sm")
                ], label="Mitigation", tab_id="attack-surface-mitigation-tab", className="p-3")
            ], id="attack-surface-tabs", active_tab="attack-surface-overview-tab")
        ], className="modal-scroll"),
        dbc.ModalFooter([
            dbc.Button([
                html.I(className="fa fa-sync-alt me-2"),
                "Refresh"
            ], id="refresh-attack-surface-btn", color="info", outline=True, size="sm", className="me-2"),
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
                                        ], className="text-center p-2 rounded stat-tile-info")
                                    ], md=3),
                                    dbc.Col([
                                        html.Div([
                                            html.H4(id="forensic-critical-count", className="mb-0 text-danger"),
                                            html.Small("Critical", className="text-muted")
                                        ], className="text-center p-2 rounded stat-tile-danger")
                                    ], md=3),
                                    dbc.Col([
                                        html.Div([
                                            html.H4(id="forensic-suspicious-count", className="mb-0 text-warning"),
                                            html.Small("Suspicious", className="text-muted")
                                        ], className="text-center p-2 rounded stat-tile-warning")
                                    ], md=3),
                                    dbc.Col([
                                        html.Div([
                                            html.H4(id="forensic-timespan", className="mb-0 text-info"),
                                            html.Small("Time Span", className="text-muted")
                                        ], className="text-center p-2 rounded stat-tile-success")
                                    ], md=3)
                                ], className="mb-4"),

                                # Timeline graph
                                dcc.Graph(id='forensic-timeline-graph', className="chart-h-400",
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
                                html.H6([html.I(className="fa fa-file-export me-2 text-warning"), "Import & Export Devices"], className="mb-3"),
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
                                html.H6([html.I(className="fa fa-clock me-2 text-info"), "Session Settings"], className="mb-3"),
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
                                dcc.Graph(id='activity-timeline-graph', className="chart-h-400",
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
                                dcc.Graph(id='device-activity-timeline', className="chart-h-450",
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
                                    html.I(className="fa fa-info-circle me-2 text-info"),
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
                                html.I(className="fa fa-list-check me-2 text-info"),
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
                                    html.I(className="fa fa-info-circle me-2 text-info"),
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
                                    html.I(className="fa fa-info-circle me-2 text-info"),
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
                                    html.I(className="fa fa-info-circle me-2 text-info"),
                                    "IoT Cybersecurity Improvement Act compliance requirements."
                                ], color="success", className="mb-3"),
                                html.Div(id='iot-act-compliance-content')
                            ])
                        ], className="glass-card border-0 shadow-sm")
                    ], className="p-3")
                ], label="IoT Act", tab_id="compliance-iot-tab")
            ], id="compliance-tabs", active_tab="compliance-overview-tab")
        ], className="modal-scroll"),
        dbc.ModalFooter([
            dbc.Button([
                html.I(className="fa fa-sync-alt me-2"),
                "Refresh Compliance"
            ], id="refresh-compliance-btn", color="primary", outline=True, size="sm", className="me-2"),
        ])
    ], id="compliance-modal", size="xl", is_open=False, scrollable=True),

    # Automated Response Dashboard Modal - Enhanced with Tabs
    dbc.Modal([
        dbc.ModalHeader(dbc.ModalTitle([
            html.I(className="fa fa-wand-magic-sparkles me-2 text-purple"),
            "Automated Response Dashboard - Rule Management & Analytics"
        ]), close_button=True),
        dbc.ModalBody([
            dbc.Tabs([
                # Overview Tab
                dbc.Tab([
                    html.Div([
                        dbc.Card([
                            dbc.CardBody([
                                html.H6([html.I(className="fa fa-chart-bar me-2 text-success"), "Compliance Overview"], className="mb-3"),

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
                                    html.I(className="fa fa-lightbulb me-2 text-info"),
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
                                html.H6([html.I(className="fa fa-history me-2 text-warning"), "Email History"], className="mb-3"),

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
                                    html.I(className="fa fa-info-circle me-2 text-info"),
                                    "Track how often each rule is triggered and which rules are most effective."
                                ], color="success", className="mb-3"),

                                html.Div(id='rule-analytics-content')
                            ])
                        ], className="glass-card border-0 shadow-sm")
                    ], className="p-3")
                ], label="Analytics", tab_id="auto-analytics-tab")
            ], id="auto-response-tabs", active_tab="auto-overview-tab")
        ], className="modal-scroll"),
        dbc.ModalFooter([
            html.Div(id='auto-response-timestamp-display', className="me-auto"),
            dbc.Button([
                html.I(className="fa fa-sync-alt me-2"),
                "Refresh Data"
            ], id="refresh-auto-response-btn", color="primary", outline=True, size="sm", className="me-2"),
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
                                    html.P("Critical", className="text-muted mb-0 u-text-sm")
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
                                    html.P("High", className="text-muted mb-0 u-text-sm")
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
                                    html.P("Affected Devices", className="text-muted mb-0 u-text-sm")
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
                                    html.P("Total CVEs", className="text-muted mb-0 u-text-sm")
                                ], className="text-center p-2")
                            ], className="glass-card border-0 shadow-sm mb-3")
                        ], md=3)
                    ], className="mb-3"),

                    dbc.Card([
                        dbc.CardHeader([
                            html.I(className="fa fa-chart-line me-2 text-info"),
                            "Vulnerability Discovery Timeline"
                        ], className="glass-card-header"),
                        dbc.CardBody([
                            dcc.Graph(id='vuln-timeline-chart', config={'displayModeBar': False}, className="chart-h-300")
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
                            html.I(className="fa fa-database me-2 text-info"),
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
                            html.I(className="fa fa-search me-2 text-info"),
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
                            html.I(className="fa fa-lightbulb me-2 text-info"),
                            "Security Recommendations & Mitigation Steps"
                        ], className="glass-card-header"),
                        dbc.CardBody([
                            html.Div(id='vuln-recommendations')
                        ])
                    ], className="glass-card border-0 shadow-sm")
                ], label="Recommendations", tab_id="vuln-recommendations-tab", className="p-3")
            ], id="vuln-scanner-tabs", active_tab="vuln-overview-tab")
        ], className="modal-scroll"),
        dbc.ModalFooter([
            dbc.Button([
                html.I(className="fa fa-sync-alt me-2"),
                "Refresh Scan"
            ], id="refresh-vuln-scanner-btn", color="primary", outline=True, size="sm", className="me-2"),
        ])
    ], id="vuln-scanner-modal", size="xl", is_open=False, scrollable=True),

    # API Integration Hub Modal
    dbc.Modal([
        dbc.ModalHeader(dbc.ModalTitle([
            html.I(className="fa fa-puzzle-piece me-2 text-info"),
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
                                    html.P("Enabled Integrations", className="text-muted mb-0 u-text-sm")
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
                                    html.P("Healthy Services", className="text-muted mb-0 u-text-sm")
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
                                    html.P("Total Requests", className="text-muted mb-0 u-text-sm")
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
                                    html.P("Success Rate", className="text-muted mb-0 u-text-sm")
                                ], className="text-center p-2")
                            ], className="glass-card border-0 shadow-sm mb-3")
                        ], md=3)
                    ]),
                    html.Div(id='api-hub-integration-cards', className="mt-3")
                ], label="Overview", tab_id="api-hub-overview"),

                # Threat Intelligence Tab
                dbc.Tab([
                    html.Div(id='api-hub-threat-intel-content')
                ], label="Threat Intel", tab_id="api-hub-threat"),

                # Notifications Tab
                dbc.Tab([
                    html.Div(id='api-hub-notifications-content')
                ], label="Notifications", tab_id="api-hub-notifications"),

                # Ticketing Tab
                dbc.Tab([
                    html.Div(id='api-hub-ticketing-content')
                ], label="Ticketing", tab_id="api-hub-ticketing"),

                # Geolocation Tab
                dbc.Tab([
                    html.Div(id='api-hub-geolocation-content')
                ], label="Geolocation", tab_id="api-hub-geo"),

                # Webhooks Tab
                dbc.Tab([
                    html.Div(id='api-hub-webhooks-content')
                ], label="Webhooks", tab_id="api-hub-webhooks"),

                # Settings Tab
                dbc.Tab([
                    html.Div(id='api-hub-settings-content')
                ], label="Settings", tab_id="api-hub-settings")
            ], id="api-hub-tabs", active_tab="api-hub-overview")
        ], className="modal-scroll"),
        dbc.ModalFooter([
            dbc.Button([
                html.I(className="fa fa-sync-alt me-2"),
                "Refresh All"
            ], id="api-hub-refresh-btn", color="primary", outline=True, size="sm", className="me-2"),
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
            html.I(className="fa fa-chart-column me-2 text-info"),
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
                                    html.P("Overall Security Score", className="text-muted mb-0 u-text-sm")
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
                                    html.P("Recommended Target", className="text-muted mb-0 u-text-sm")
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
                                    html.P("Score vs Target", className="text-muted mb-0 u-text-sm")
                                ], className="text-center p-2")
                            ], className="glass-card border-0 shadow-sm mb-3")
                        ], md=4)
                    ], className="mb-3"),

                    html.Div(id="benchmark-comparison", className="mb-3"),

                    dbc.Card([
                        dbc.CardHeader([
                            html.I(className="fa fa-chart-radar me-2 text-info"),
                            "Security Posture Comparison"
                        ], className="glass-card-header"),
                        dbc.CardBody([
                            dcc.Graph(id='benchmark-radar-chart', config={'displayModeBar': False}, className="chart-h-400")
                        ])
                    ], className="glass-card border-0 shadow-sm")
                ], label="Overview", tab_id="benchmark-overview-tab", className="p-3"),

                # Metrics Tab
                dbc.Tab([
                    dbc.Card([
                        dbc.CardHeader([
                            html.I(className="fa fa-list-check me-2 text-info"),
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
                            html.I(className="fa fa-check-double me-2 text-info"),
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
                            html.I(className="fa fa-lightbulb me-2 text-info"),
                            "Improvement Recommendations"
                        ], className="glass-card-header"),
                        dbc.CardBody([
                            html.Div(id='benchmark-recommendations')
                        ])
                    ], className="glass-card border-0 shadow-sm")
                ], label="Recommendations", tab_id="benchmark-recommendations-tab", className="p-3")
            ], id="benchmark-tabs", active_tab="benchmark-overview-tab")
        ], className="modal-scroll"),
        dbc.ModalFooter([
            html.Div(id='benchmark-timestamp-display', className="me-auto"),
            dbc.Button([
                html.I(className="fa fa-sync-alt me-2"),
                "Refresh"
            ], id="refresh-benchmark-btn", color="primary", outline=True, size="sm", className="me-2"),
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
                                    html.P("Avg Latency", className="text-muted mb-0 u-text-sm")
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
                                    html.P("Throughput", className="text-muted mb-0 u-text-sm")
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
                                    html.P("Packet Loss", className="text-muted mb-0 u-text-sm")
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
                                    html.P("Active Connections", className="text-muted mb-0 u-text-sm")
                                ], className="text-center p-2")
                            ], className="glass-card border-0 shadow-sm mb-3")
                        ], md=3)
                    ], className="mb-3"),
                    dbc.Card([
                        dbc.CardHeader([
                            html.I(className="fa fa-chart-line me-2 text-info"),
                            "Connection Activity Over Time"
                        ], className="glass-card-header"),
                        dbc.CardBody([
                            dcc.Graph(id='performance-graph', config={'displayModeBar': False}, className="chart-h-350")
                        ])
                    ], className="glass-card border-0 shadow-sm")
                ], label="Overview", tab_id="performance-overview-tab", className="p-3"),

                # Bandwidth Tab
                dbc.Tab([
                    dbc.Card([
                        dbc.CardHeader([
                            html.I(className="fa fa-chart-bar me-2 text-info"),
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
                            html.I(className="fa fa-signal me-2 text-info"),
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
                            html.I(className="fa fa-cogs me-2 text-info"),
                            "Performance Optimization Recommendations"
                        ], className="glass-card-header"),
                        dbc.CardBody([
                            html.Div(id='performance-optimization-list')
                        ])
                    ], className="glass-card border-0 shadow-sm")
                ], label="Optimization", tab_id="performance-optimization-tab", className="p-3")
            ], id="performance-tabs", active_tab="performance-overview-tab")
        ], className="modal-scroll"),
        dbc.ModalFooter([
            html.Div(id='performance-timestamp-display', className="me-auto"),
            dbc.Button([
                html.I(className="fa fa-sync-alt me-2"),
                "Refresh"
            ], id="refresh-performance-btn", color="info", outline=True, size="sm", className="me-2"),
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
                                    ], className="glass-card-header"),
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
                                    ], className="glass-card-header"),
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
                                    ], className="glass-card-header"),
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
        ]),
        dcc.Store(id='sustainability-data-store'),
        dcc.Download(id='download-sustainability-report')
    ], id="sustainability-modal", size="xl", is_open=False, scrollable=True),

    # Quick Settings Modal - Enhanced
    dbc.Modal([
        dbc.ModalHeader(dbc.ModalTitle([
            html.I(className="fa fa-cog me-2 text-info"),
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
                            # Change WiFi — lets a headless Pi move to a new network
                            # after setup without re-flashing. Reuses the same nmcli
                            # helpers as the first-run wizard (utils.wifi_manager).
                            html.Div([
                                html.Label([
                                    html.I(className="fa fa-wifi me-2"),
                                    "WiFi Network"
                                ], className="fw-bold mb-2"),
                                html.Div(id="settings-wifi-current",
                                         className="small text-muted mb-2"),
                                dbc.InputGroup([
                                    # Typeable (not a dropdown): if the Pi lost home Wi-Fi and
                                    # re-armed the setup AP, the radio can't scan, so the user
                                    # must be able to type the SSID to recover. Scan results
                                    # populate the datalist as suggestions when available.
                                    dbc.Input(id="settings-wifi-ssid", type="text",
                                              list="settings-wifi-ssid-list",
                                              placeholder="WiFi network name",
                                              autocomplete="off"),
                                    dbc.Button("Scan", id="settings-wifi-scan-btn",
                                               color="secondary", outline=True, size="sm",
                                               className="ms-1"),
                                ], className="mb-2"),
                                html.Datalist(id="settings-wifi-ssid-list"),
                                dbc.Input(id="settings-wifi-password", type="password",
                                          placeholder="WiFi password (blank for open networks)",
                                          autocomplete="off", className="mb-2"),
                                dbc.Button([html.I(className="fa fa-right-left me-2"),
                                            "Switch to this WiFi"],
                                           id="settings-wifi-connect-btn",
                                           color="primary", outline=True, size="sm"),
                                html.Div(id="settings-wifi-feedback", className="small mt-2"),
                                dbc.Alert(
                                    "Switching networks will briefly disconnect this device "
                                    "from the Pi. After it switches, rejoin the same WiFi and "
                                    "reopen the dashboard.",
                                    color=None, className="glass-alert-info small mt-2 mb-0"),
                            ], className="wizard-section-box mb-4"),

                            # How to reach this device (find-the-Pi helper)
                            html.Div(id="settings-reachable",
                                     className="small text-muted mb-4"),

                            # Remote access (Tailscale Funnel) — set up POST-wizard, when the
                            # Pi is online. The offline setup hotspot can't authenticate, so
                            # this lives here (Settings) rather than in the wizard.
                            html.Div([
                                html.Label([
                                    html.I(className="fa fa-globe me-2"),
                                    "Remote Access"
                                ], className="fw-bold mb-2"),
                                html.Small(
                                    "Reach this dashboard securely from anywhere via Tailscale. "
                                    "Your Pi must be online (on home WiFi) to sign in.",
                                    className="text-muted d-block mb-2"),
                                dbc.Button([html.I(className="fa fa-globe me-2"),
                                            "Enable Remote Access"],
                                           id="settings-remote-enable-btn",
                                           color="primary", outline=True, size="sm"),
                                dbc.Button([html.I(className="fa fa-rotate me-2"),
                                            "Re-link this device"],
                                           id="settings-remote-relink-btn",
                                           color="secondary", outline=True, size="sm",
                                           className="ms-2"),
                                html.Small(
                                    "Deleted this Pi from your Tailscale admin? Use Re-link to "
                                    "sign in again as a fresh device.",
                                    className="text-muted d-block mt-2"),
                                html.Div(id="settings-remote-status", className="small mt-2"),
                                dcc.Interval(id="settings-remote-interval", interval=3000,
                                             disabled=True),
                            ], className="wizard-section-box mb-4"),

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
        ], className="modal-scroll modal-compact-switches"),
        dbc.ModalFooter([
            dbc.Button("Save Changes", id="settings-save-btn", color="primary", size="sm", className="me-2")
        ])
    ], id="quick-settings-modal", size="lg", is_open=False),

    # Hidden Components & Modals
    html.Div(id='dummy-output-card-clicks', style={'display': 'none'}),
    # No hardcoded url: dash-extensions defaults the socket to the page's OWN host
    # (ws://<location.host>/ws), and the clientside callback in callbacks_global.py
    # immediately rewrites it to ws://|wss://<window.location.host>/ws. A hardcoded
    # 127.0.0.1 made every remote browser (iotsentinel.local / Tailscale) dial its own
    # localhost and fail, so the dashboard never received live data over the LAN.
    WebSocket(id="ws"),
    # dash-extensions delivers ws.message as {data: "<raw json>"}, but every
    # consumer wants the parsed payload. A clientside callback JSON-parses each
    # message into this Store, and all callbacks read ws-data.data instead of the
    # raw ws.message. (Without this, ws_message.get(...) always missed and the
    # live cards/devices/graphs stayed empty.)
    dcc.Store(id="ws-data"),
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
            html.I(className="fa fa-shield-heart me-2 text-danger"),
            "Activate Emergency Protection"
        ])),
        dbc.ModalBody([
            dbc.Card([
                dbc.CardBody([
                    html.I(className="fa fa-shield-alt fa-3x text-danger mb-2"),
                    html.H5("Activate Emergency Protection?", className="mb-1"),
                    html.P("This immediately blocks all untrusted devices and enables maximum firewall protection.", className="text-muted small mb-0"),
                ], className="text-center py-3")
            ], className="glass-card border-0 shadow-sm mb-3"),
            dbc.Card([
                dbc.CardBody([
                    html.P("What this does:", className="fw-semibold small mb-2"),
                    html.Ul([
                        html.Li("Block all unknown and untrusted devices", className="small"),
                        html.Li("Enable maximum firewall protection", className="small"),
                        html.Li("Log this security event", className="small"),
                    ], className="mb-0 ps-3"),
                ])
            ], className="glass-card border-0 shadow-sm mb-3"),
            dbc.Label("What did you notice? (optional)", className="small fw-semibold"),
            dbc.Textarea(
                id="emergency-reason-input",
                placeholder="e.g. Strange pop-ups, unknown device appeared...",
                rows=2, className="mb-3"
            ),
            dbc.Alert([
                html.I(className="fa fa-info-circle me-2"),
                "You can deactivate emergency mode at any time from the dashboard.",
            ], color="info", className="mb-0"),
        ]),
        dbc.ModalFooter([
            dbc.Button("Cancel", id="emergency-cancel-btn", color="secondary", outline=True, className="cyber-button"),
            dbc.Button([html.I(className="fa fa-shield-alt me-2"), "Activate Now"],
                       id="emergency-confirm-btn", color="danger", className="cyber-button"),
        ])
    ], id="emergency-confirm-modal", is_open=False, centered=True, backdrop="static"),

    # Customize Layout Modal - Enhanced
    dbc.Modal([
        dbc.ModalHeader(dbc.ModalTitle([
            html.I(className="fa fa-gears me-2 text-info"),
            "Widget & Layout Customization"
        ]), close_button=True),
        dbc.ModalBody([
            dbc.Tabs([
                # Dashboard Layout Tab
                dbc.Tab([
                    html.Div([
                        html.H6([html.I(className="fa fa-th me-2 text-info"), "Dashboard Sections"], className="mt-3 mb-3"),
                        dbc.Checklist(
                            id="widget-toggles",
                            options=[
                                {"label": "Metrics Cards", "value": "metrics"},
                                {"label": "Feature Cards", "value": "features"},
                                {"label": "Right Panel (Alerts & Feed)", "value": "rightPanel"},
                            ],
                            value=["metrics", "features", "rightPanel"],
                            switch=True,
                            className="mb-3"
                        ),

                        html.Hr(),

                        html.H6([html.I(className="fa fa-eye me-2 text-info"), "Individual Widgets"], className="mb-3"),
                        dbc.Checklist(
                            id="individual-widget-toggles",
                            options=[
                                {"label": "Network Topology Graph", "value": "network-graph"},
                                {"label": "Protocol Distribution", "value": "protocol-chart"},
                                {"label": "Traffic Timeline", "value": "traffic-timeline"},
                                {"label": "Device List", "value": "device-list"},
                                {"label": "Alert Feed", "value": "alert-feed"},
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
                        html.H6([html.I(className="fa fa-desktop me-2 text-info"), "View Density"], className="mt-3 mb-3"),
                        dbc.RadioItems(
                            id="view-density",
                            options=[
                                {"label": html.Span([html.I(className="fa fa-compress me-2 text-info"), "Compact - More data, less spacing"], className="d-flex align-items-center"), "value": "compact"},
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

                        html.H6([html.I(className="fa fa-film me-2 text-info"), "Animations"], className="mb-3"),
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
                        html.H6([html.I(className="fa fa-sync me-2 text-info"), "Auto-Refresh"], className="mt-3 mb-3"),
                        dbc.Switch(
                            id="auto-refresh-toggle",
                            label="Enable auto-refresh",
                            value=True,
                            className="mb-3"
                        ),

                        html.H6([html.I(className="fa fa-clock me-2 text-info"), "Refresh Interval"], className="mb-3"),
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

                        html.H6([html.I(className="fa fa-database me-2 text-info"), "Backup Settings"], className="mb-3"),
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

                        html.H6([html.I(className="fa fa-chart-network me-2 text-info"), "Chart Preferences"], className="mb-3"),
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
                        html.H6([html.I(className="fa fa-bell me-2 text-warning"), "Alert Notifications"], className="mt-3 mb-3"),
                        dbc.Checklist(
                            id="notification-prefs",
                            options=[
                                {"label": "Sound alerts", "value": "sound"},
                                {"label": "Voice announcements (critical only)", "value": "voice"},
                                {"label": "Desktop notifications", "value": "desktop"},
                                {"label": "Email digest (daily)", "value": "email"},
                            ],
                            value=["sound"],
                            switch=True,
                            className="mb-3"
                        ),

                        html.Hr(),

                        html.H6([html.I(className="fa fa-filter me-2 text-info"), "Show Alert Severity"], className="mb-3"),
                        dbc.Checklist(
                            id="alert-severity-filter",
                            options=[
                                {"label": "Critical", "value": "critical"},
                                {"label": "High", "value": "high"},
                                {"label": "Medium", "value": "medium"},
                                {"label": "Low", "value": "low"},
                            ],
                            value=["critical", "high", "medium", "low"],
                            switch=True
                        ),
                    ], className="p-3")
                ], label="Notifications", tab_id="notifications-tab"),

                # Advanced Tab
                dbc.Tab([
                    html.Div([
                        html.H6([html.I(className="fa fa-cog me-2 text-info"), "Advanced Settings"], className="mt-3 mb-3"),

                        dbc.Button([
                            html.I(className="fa fa-download me-2 text-info"),
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

                        html.H6([html.I(className="fa fa-keyboard me-2 text-info"), "Keyboard Shortcuts"], className="mb-2"),
                        html.Small([
                            html.Span("⌘K / Ctrl+K", className="shortcut-key me-2"), "Open Spotlight search", html.Br(),
                            html.Span("⌘⇧C / Ctrl+Shift+C", className="shortcut-key me-2"), "Open AI Chat", html.Br(),
                            html.Span("⌘\\ / Ctrl+\\", className="shortcut-key me-2"), "Toggle dark / light mode", html.Br(),
                            html.Span("⌘⇧L / Ctrl+Shift+L", className="shortcut-key me-2"), "Emergency Lockdown", html.Br(),
                            html.Span("Esc", className="shortcut-key me-2"), "Close dialog", html.Br(),
                            html.Span("/", className="shortcut-key me-2"), "Show shortcuts overlay",
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
        ], className="modal-scroll modal-compact-switches")
    ], id="customize-layout-modal", size="lg", is_open=False),

    # Quick Actions Components
    dcc.Download(id="download-export"),


    # Quick Actions Modal
    dbc.Modal([
        dbc.ModalHeader(dbc.ModalTitle([
            html.I(className="fa fa-bolt-lightning me-2 text-warning"),
            "Quick Actions"
        ])),
        dbc.ModalBody([
            html.P("Execute quick actions to manage your dashboard and network security.", className="text-muted mb-3"),
            html.Div(id="quick-actions-content"),  # Dynamic content based on user role
        ], className="modal-scroll"),
    ], id="quick-actions-modal", size="lg", is_open=False),

    dcc.Store(id='theme-store', storage_type='local', data={'theme': 'auto'}),
    # resolved-theme-store: written by the theme-applicator clientside callback so
    # server-side chart callbacks can read the actual dark/light state (incl. Auto mode).
    dcc.Store(id='resolved-theme-store', storage_type='memory', data={'theme': 'light'}),
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
    dcc.Store(id='onboarding-step-store', data=0),  # Kept as dummy output for clientside callbacks
    dcc.Store(id='keyboard-shortcut-store', data=None),

    # Dummy output for clientside callback
    html.Div(id='widget-visibility-dummy', style={'display': 'none'}),

    # Hidden sentinel: clicked by tour.js onDestroyed to persist completion via Dash callback
    html.Button(id='tour-complete-sentinel', n_clicks=0, style={'display': 'none'}),

    # Ghost modal kept for Dash/spotlight type-compatibility; tour.js intercepts is_open=True
    # and starts the driver.js tour instead — no visible content needed here.
    dbc.Modal(
        id="onboarding-modal",
        is_open=False,
        backdrop=False,
        children=[],
    ),

    # Alert Details Modal
    dbc.Modal([
        dbc.ModalHeader(dbc.ModalTitle(id="alert-details-title")),
        dbc.ModalBody(id="alert-details-body"),
        dbc.ModalFooter([
            dbc.Button([html.I(className="fa fa-robot me-2"), "Ask AI About This Alert"],
                      id="ask-ai-alert-btn", color="info", className="cyber-button me-2"),
            dbc.InputGroup([
                dbc.Select(
                    id="alert-suppress-duration",
                    options=[
                        {"label": "1 hour", "value": "1"},
                        {"label": "24 hours", "value": "24"},
                        {"label": "7 days", "value": "168"},
                        {"label": "Forever", "value": "0"},
                    ],
                    value="24",
                    style={"maxWidth": "120px"},
                ),
                dbc.Button(
                    [html.I(className="fa fa-bell-slash me-1"), "Suppress"],
                    id="alert-suppress-btn", color="warning", outline=True,
                    className="cyber-button",
                    title="Mute future alerts for this device for the selected duration",
                ),
            ], size="sm", className="me-auto"),
            dbc.Button("Mark as Reviewed", id="alert-acknowledge-btn", color="success", className="cyber-button")
        ]),
        # Collapsible AI Analysis Section
        dbc.Collapse(
            dbc.Card([
                dbc.CardHeader([
                    html.I(className="fa fa-robot me-2 text-info"),
                    html.Strong("AI Deep Analysis"),
                    dbc.Badge("POWERED BY HYBRID AI", color="success", className="ms-2")
                ], className="glass-card-header"),
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
            dbc.ModalTitle([html.I(className="fa fa-lock me-2 text-danger"), "Confirm Lockdown Mode"]),
            close_button=True
        ),
        dbc.ModalBody([
            dbc.Card([
                dbc.CardBody([
                    html.I(className="fa fa-exclamation-triangle fa-3x text-warning mb-2"),
                    html.H5("Enable Network Lockdown?", className="mb-1"),
                    html.P("All untrusted devices will be blocked from your network.", className="text-muted small mb-0"),
                ], className="text-center py-3")
            ], className="glass-card border-0 shadow-sm mb-3"),

            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardBody([
                            html.I(className="fa fa-shield-alt text-success me-2"),
                            html.Strong("Trusted: "),
                            html.Span(id='lockdown-trusted-count', children="0", className="text-success fw-bold"),
                        ], className="text-center py-2")
                    ], className="glass-card border-0 shadow-sm")
                ], width=6),
                dbc.Col([
                    dbc.Card([
                        dbc.CardBody([
                            html.I(className="fa fa-ban text-danger me-2"),
                            html.Strong("Will Block: "),
                            html.Span(id='lockdown-blocked-count', children="0", className="text-danger fw-bold"),
                        ], className="text-center py-2")
                    ], className="glass-card border-0 shadow-sm")
                ], width=6),
            ], className="mb-3"),

            # Admin device protection status — populated by callback
            html.Div(id='lockdown-admin-device-status'),
        ]),
        dbc.ModalFooter([
            dbc.Button([html.I(className="fa fa-times me-2"), "Cancel"],
                       id="lockdown-cancel", color="secondary", outline=True, className="cyber-button"),
            dbc.Button([html.I(className="fa fa-lock me-2"), "Enable Lockdown"],
                       id="lockdown-confirm", color="danger", className="cyber-button"),
        ]),
    ], id="lockdown-modal", is_open=False, centered=True, backdrop="static"),

    # Bulk Delete Confirmation Modal
    dbc.Modal([
        dbc.ModalHeader(
            dbc.ModalTitle([html.I(className="fa fa-trash me-2 text-danger"), "Confirm Delete"]),
            close_button=True
        ),
        dbc.ModalBody([
            dbc.Card([
                dbc.CardBody([
                    html.I(className="fa fa-trash fa-3x text-danger mb-2"),
                    html.H5("Delete selected devices?", className="mb-1"),
                    html.Div([
                        html.I(className="fa fa-info-circle me-1 text-muted"),
                        html.Span(id="bulk-delete-confirm-message", className="text-muted small"),
                    ], className="mb-0"),
                ], className="text-center py-3")
            ], className="glass-card border-0 shadow-sm mb-3"),
            dbc.Alert([
                html.I(className="fa fa-exclamation-triangle me-2"),
                "This action cannot be undone. All device history will be permanently removed.",
            ], color="danger", className="mb-0"),
        ]),
        dbc.ModalFooter([
            dbc.Button([html.I(className="fa fa-times me-2"), "Cancel"],
                       id="bulk-delete-cancel", color="secondary", outline=True, className="cyber-button"),
            dbc.Button([html.I(className="fa fa-trash me-2"), "Delete"],
                       id="bulk-delete-confirm", color="danger", className="cyber-button"),
        ]),
    ], id="bulk-delete-modal", is_open=False, centered=True, backdrop="static"),

    # Bulk Trust / Block Confirmation Modal
    dbc.Modal([
        dbc.ModalHeader(
            dbc.ModalTitle(id="bulk-action-modal-title"),
            close_button=True
        ),
        dbc.ModalBody([
            dbc.Card([
                dbc.CardBody([
                    html.I(id="bulk-action-modal-icon", className="fa fa-3x mb-2"),
                    html.H5(id="bulk-action-modal-question", className="mb-1"),
                    html.P(id="bulk-action-modal-detail", className="text-muted small mb-0"),
                ], className="text-center py-3")
            ], className="glass-card border-0 shadow-sm mb-3"),
            dbc.Alert(id="bulk-action-modal-warning", color="warning", className="mb-0"),
        ]),
        dbc.ModalFooter([
            dbc.Button([html.I(className="fa fa-times me-2"), "Cancel"],
                       id="bulk-action-cancel", color="secondary", outline=True, className="cyber-button"),
            dbc.Button(id="bulk-action-confirm-btn", color="success", className="cyber-button"),
        ]),
    ], id="bulk-action-confirm-modal", is_open=False, centered=True, backdrop="static"),
    dcc.Store(id='bulk-action-pending-store', data=None),

    # ── AI Alert Analysis Modal ───────────────────────────────────────────────
    dbc.Modal([
        dbc.ModalHeader([
            html.I(className="fa fa-wand-magic-sparkles me-2 text-info"),
            html.Span(id="alert-analysis-modal-title", children="AI Alert Analysis"),
        ], close_button=True, className="border-0"),
        dbc.ModalBody([
            dcc.Loading(html.Div(id="alert-analysis-modal-body"), type="circle"),

            # ── Ask Why: per-alert conversational AI analyst ──────────────
            html.Hr(className="my-3"),
            html.Div([
                html.Div([
                    html.I(className="fa fa-comments me-2 text-info"),
                    html.Strong("Ask about this alert", className="me-2"),
                    html.Small("AI answers from your actual network data",
                               className="text-muted"),
                ], className="d-flex align-items-center mb-2"),

                # Suggested-question quick chips
                html.Div([
                    dbc.Button("Why is this bad?", id="alert-q-why", size="sm",
                               color="outline-secondary", className="me-1 mb-1 cyber-button",
                               n_clicks=0),
                    dbc.Button("What should I do?", id="alert-q-action", size="sm",
                               color="outline-secondary", className="me-1 mb-1 cyber-button",
                               n_clicks=0),
                    dbc.Button("Is my data safe?", id="alert-q-data", size="sm",
                               color="outline-secondary", className="me-1 mb-1 cyber-button",
                               n_clicks=0),
                ], className="mb-2"),

                # Chat history (reuses dashboard chat-bubble CSS)
                html.Div(id="alert-chat-messages",
                         className="custom-scrollbar-modern",
                         style={"maxHeight": "260px", "overflowY": "auto"}),

                # Input row
                dbc.InputGroup([
                    dbc.Input(id="alert-chat-input", placeholder="Ask a follow-up question…",
                              type="text", className="border-secondary"),
                    dbc.Button([html.I(className="fa fa-paper-plane me-1"), "Send"],
                               id="alert-chat-send", color="info", outline=True, n_clicks=0),
                ], className="mt-2"),
            ], id="alert-ask-why-panel"),

            # Hidden stores for the ask-why conversation
            dcc.Store(id='alert-chat-history', data={'history': [], 'alert_id': None}),
        ], className="p-3"),
    ], id="alert-ai-analysis-modal", is_open=False, size="lg",
       centered=True, backdrop="static", scrollable=True),

    # User Delete Confirmation Modal
    dbc.Modal([
        dbc.ModalHeader(
            dbc.ModalTitle([html.I(className="fa fa-user-times me-2 text-danger"), "Confirm Delete User"]),
            close_button=True
        ),
        dbc.ModalBody([
            dbc.Card([
                dbc.CardBody([
                    html.I(className="fa fa-user-times fa-3x text-danger mb-2"),
                    html.H5("Delete this user account?", className="mb-1"),
                    html.Div([
                        html.I(className="fa fa-user me-1 text-primary"),
                        html.Strong("Username: "),
                        html.Span(id="user-delete-confirm-username", className="text-primary"),
                    ]),
                ], className="text-center py-3")
            ], className="glass-card border-0 shadow-sm mb-3"),
            dbc.Alert([
                html.I(className="fa fa-exclamation-triangle me-2"),
                "Permanently deletes the account and all associated data. Cannot be undone.",
            ], color="danger", className="mb-0"),
        ]),
        dbc.ModalFooter([
            dbc.Button([html.I(className="fa fa-times me-2"), "Cancel"],
                       id="user-delete-cancel", color="secondary", outline=True, className="cyber-button"),
            dbc.Button([html.I(className="fa fa-user-times me-2"), "Delete User"],
                       id="user-delete-confirm", color="danger", className="cyber-button"),
        ]),
    ], id="user-delete-modal", is_open=False, centered=True, backdrop="static"),
    dcc.Store(id='user-delete-id-store', data=None),



    # Block/Unblock Device Confirmation Modal
    dbc.Modal([
        dbc.ModalHeader(
            dbc.ModalTitle(id="block-device-modal-title"),
            close_button=True
        ),
        dbc.ModalBody([
            dbc.Card([
                dbc.CardBody([
                    html.I(id="block-device-modal-icon", className="fa fa-ban fa-3x text-warning mb-2"),
                    html.H5(id="block-device-modal-question", className="mb-1"),
                    html.Div([
                        html.I(className="fa fa-network-wired me-1 text-muted"),
                        html.Strong("Device: "),
                        html.Span(id="block-device-modal-ip", className="text-primary"),
                    ]),
                ], className="text-center py-3")
            ], className="glass-card border-0 shadow-sm mb-3"),
            dbc.Alert(id="block-device-modal-warning", color="warning", className="mb-0"),
        ]),
        dbc.ModalFooter([
            dbc.Button([html.I(className="fa fa-times me-2"), "Cancel"],
                       id="block-device-cancel", color="secondary", outline=True, className="cyber-button"),
            dbc.Button(id="block-device-confirm-btn", color="danger", className="cyber-button"),
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
    ], id="toast-detail-modal", size="lg", is_open=False, backdrop=True, keyboard=True, centered=True),

    # Toast History Modal - Popup modal for toast history (triggered from navbar)
    dbc.Modal([
        dbc.ModalHeader(dbc.ModalTitle([
            html.I(className="fa fa-clock-rotate-left me-2 text-info"),
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
            html.I(className="fa fa-bell me-2 text-warning"),
            "Notifications ",
            html.Span(id="notification-count-display", className="badge bg-danger ms-2")
        ])),
        dbc.ModalBody([
            dcc.Loading(id="notification-loader", type="default", children=html.Div(id="notification-drawer-body"))
        ])
    ], id="notification-drawer", size="lg", is_open=False, scrollable=True, centered=True),

    html.Div(id='backdrop-overlay', style={'position': 'fixed', 'top': 0, 'left': 0, 'width': '100%', 'height': '100%', 'backgroundColor': 'rgba(0,0,0,0.5)', 'display': 'none', 'zIndex': 1040}),


    dbc.Modal([
        dbc.ModalBody([
            # ── Top bar: title + clear button ─────────────────────────────
            html.Div([
                html.Div([
                    html.I(className="fa fa-robot chat-topbar-icon"),
                    html.Span("AI Assistant", className="chat-topbar-title"),
                ], className="d-flex align-items-center gap-2"),
                dbc.Button(
                    html.I(className="fa fa-trash"),
                    id="clear-chat-button",
                    color="link",
                    size="sm",
                    className="chat-topbar-clear",
                    title="Clear conversation",
                ),
            ], className="chat-topbar"),

            # ── Message area ───────────────────────────────────────────────
            dcc.Loading(
                id="chat-loading",
                type="default",
                children=[
                    html.Div(id='chat-history', className='chat-scroll')
                ],
            ),

            # ── Input bar (Spotlight-style) ────────────────────────────────
            html.Div([
                html.I(className="fa fa-comment-dots chat-input-icon"),
                dbc.Input(
                    id='chat-input',
                    placeholder="Ask about your network, devices, or alerts…",
                    className="chat-input",
                    type="text",
                    debounce=False,
                ),
                dbc.Button(
                    html.I(className="fa fa-paper-plane"),
                    id='chat-send-button',
                    color="link",
                    className="chat-send-btn",
                    title="Send",
                ),
            ], className="chat-input-bar"),

            # ── Footer hints ──────────────────────────────────────────────
            html.Div([
                html.Span([
                    html.Kbd("Enter"), " to send  •  ",
                    html.Code("/query"), " for DB",
                ], className="chat-footer-hint"),
                html.Span(id='chat-quota-badge', className="chat-footer-quota"),
            ], className="chat-footer"),
        ], className="p-0", id='chat-history-container'),
    ], id="chat-modal", is_open=False, size="lg", scrollable=False),

    dcc.Store(id='chat-history-store', storage_type='session', data={'history': []}),

    # AI Security Agent modal
    dbc.Modal([
        dbc.ModalHeader([
            dbc.ModalTitle([
                html.I(className="fa fa-robot me-2 text-purple"),
                "AI Security Agent"
            ]),
            html.Button(type="button", id="close-agent-modal-btn",
                        className="btn-close", **{"aria-label": "Close"}),
        ], close_button=False),
        dbc.ModalBody([
            html.Div(id='agent-action-result', className="mb-2"),
            html.Div(id='agent-panel-content', className="modal-scroll-60"),
        ]),
        dbc.ModalFooter(
            html.Div([
                html.Span(id="agent-status-pill"),
                dbc.Button(
                    id="agent-toggle-btn",
                    size="sm",
                    outline=True,
                    className="cyber-button ms-auto py-1 px-3",
                    style={"fontSize": "0.75rem", "minWidth": "100px", "maxWidth": "120px"},
                ),
            ], className="d-flex align-items-center w-100"),
            style={"padding": "0.4rem 1rem"},
        ),
    ], id="agent-modal", is_open=False, size="lg", scrollable=True),

    dcc.Interval(id='agent-refresh-interval', interval=30_000, n_intervals=0),

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
            html.Kbd("⌘K", className="ms-2 d-none d-lg-inline badge-tiny")
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
            # Search Input Bar
            html.Div([
                html.I(className="fa fa-search spotlight-search-icon"),
                dbc.Input(
                    id="spotlight-search-input",
                    type="text",
                    placeholder="Search for features, modals, settings...",
                    className="spotlight-search-input",
                    autoComplete="off",
                    debounce=False,
                    n_submit=0
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

            # Two-column results area
            html.Div([
                # Left 60%: results list
                html.Div(
                    id="spotlight-results-container",
                    className="sl-results-list"
                ),
                # Right 40%: preview pane
                html.Div(
                    id="sl-preview-pane",
                    className="sl-preview-pane",
                    children=[
                        html.Div(
                            id="sl-preview-content",
                            className="sl-preview-inner sl-preview-empty"
                        )
                    ]
                ),
            ], className="sl-two-col"),

            html.Div([
                html.Span([html.Kbd("⌘K"), " anywhere"], className="sl-footer-hint"),
            ], className="sl-footer"),
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
                html.I(className="fa fa-file-alt me-2 text-secondary"),
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
                        html.H6([html.I(className="fa fa-file-alt me-2 text-info"), "Select Report Template"], className="mb-3"),
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
                        html.H6([html.I(className="fa fa-cog me-2 text-info"), "Advanced Settings"], className="mt-3 mb-3"),
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
                        html.H6([html.I(className="fa fa-history me-2 text-info"), "Recent Reports"], className="mb-3"),
                        html.Div(id='recent-reports-list', children=[
                            dbc.Alert([html.I(className="fa fa-file-alt me-2"), "No recent reports. Generate your first report!"], color="info", className="text-center")
                        ])
                    ], className="p-3")
                ], label="Recent Reports", tab_id="recent-tab")
            ], id="report-builder-tabs", active_tab="build-tab")
        ]),
        dbc.ModalFooter([
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
    dcc.Store(id='spotlight-category-filter', data=None),

    # Store for context-aware boost data (active alerts, CPU → search rank boosts)
    dcc.Store(id='spotlight-context-data', data={'active_alerts': 0, 'cpu_pct': 0.0, 'boosts': {}}),

    # Store for cross-domain search results (live devices + alerts from DB)
    dcc.Store(id='spotlight-cross-domain-results', data={'devices': [], 'alerts': [], 'query': ''}),

    # Debounce intermediary — only written to after 300ms of no typing (prevents per-keystroke DB queries)
    dcc.Store(id='spotlight-cross-domain-debounced', data=''),

    # Hidden button — Cmd+Shift+L fires this, callback opens lockdown modal
    html.Button(id='spotlight-emergency-lockdown-btn', n_clicks=0,
                style={'display': 'none'}),

    # Keyboard shortcuts overlay — toggled by ? key (keyboard-shortcuts.js)
    html.Div([
        html.Div([
            html.H6([html.I(className="fa fa-keyboard me-2 text-info"), "Keyboard Shortcuts"],
                    className="mb-3 fw-semibold"),
            html.Table([
                html.Tbody([
                    html.Tr([
                        html.Td(html.Span("⌘K / Ctrl+K", className="shortcut-key"), className="pe-4 text-end"),
                        html.Td("Open Spotlight search"),
                    ]),
                    html.Tr([
                        html.Td(html.Span("⌘⇧C / Ctrl+Shift+C", className="shortcut-key"), className="pe-4 text-end"),
                        html.Td("Open AI Chat"),
                    ]),
                    html.Tr([
                        html.Td(html.Span("⌘\\ / Ctrl+\\", className="shortcut-key"), className="pe-4 text-end"),
                        html.Td("Toggle dark / light mode"),
                    ]),
                    html.Tr([
                        html.Td(html.Span("⌘⇧L / Ctrl+Shift+L", className="shortcut-key"), className="pe-4 text-end"),
                        html.Td("Emergency Lockdown"),
                    ]),
                    html.Tr([
                        html.Td(html.Span("Esc", className="shortcut-key"), className="pe-4 text-end"),
                        html.Td("Close dialog"),
                    ]),
                    html.Tr([
                        html.Td(html.Span("/", className="shortcut-key"), className="pe-4 text-end"),
                        html.Td("Show / hide this overlay"),
                    ]),
                ])
            ], className="shortcuts-table w-100 mb-2"),
            html.Small("Press ? or Esc to dismiss", className="text-muted d-block text-center mt-2"),
        ], className="shortcuts-overlay-card"),
    ], id="shortcuts-overlay", style={"display": "none"}, className="shortcuts-overlay"),

    # =========================================================================
    # MOBILE BOTTOM TAB BAR (hidden on desktop via CSS)
    # =========================================================================
    create_mobile_tabbar(),

], fluid=True, className="dashboard-container p-3")

# ============================================================================
# MAIN APP LAYOUT - WITH AUTHENTICATION
# ============================================================================
# ============================================================================
# MAIN APP LAYOUT - WITH AUTHENTICATION
# ============================================================================

# Feature Card Categorization for Enhanced Masonry Layout
FEATURE_CATEGORIES = {
    # Alerts & Threats tab
    'Security': [
        'threat-card-btn', 'threat-map-card-btn', 'risk-heatmap-card-btn',
        'forensic-timeline-card-btn', 'auto-response-card-btn',
    ],
    # Devices & IoT tab
    'Management': [
        'device-mgmt-card-btn', 'protocol-card-btn', 'smarthome-card-btn',
        'privacy-card-btn', 'segmentation-card-btn', 'firmware-card-btn',
    ],
    # Analytics tab
    'Analytics': [
        'analytics-card-btn', 'timeline-card-btn', 'benchmark-card-btn',
        'performance-card-btn',
    ],
    # Compliance tab
    'Compliance': [
        'compliance-card-btn', 'vuln-scanner-card-btn', 'attack-surface-card-btn',
        'firewall-card-btn',
    ],
    # Settings/Admin tab
    'Admin': [
        'user-card-btn', 'system-card-btn', 'preferences-card-btn',
        'quick-settings-btn', 'api-hub-card-btn', 'email-card-btn',
        'sustainability-card-btn', 'education-card-btn',
    ],
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
    # Canonical template rules fed from shared.py DASHBOARD_TEMPLATES (single source of truth)
    dcc.Store(id='dashboard-template-rules', data=DASHBOARD_TEMPLATES, storage_type='memory'),
    # Phase 3: padlock refresh trigger — bumped by save_api_key to re-evaluate lock states
    dcc.Store(id='padlock-refresh-trigger', data=0),
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
# WEBSOCKET BACKGROUND THREAD
# ============================================================================

thread = None
thread_lock = threading.Lock()

# Cache for slow-moving WS aggregates (recomputed every ~15 s, i.e. every 5 cycles)
_WS_SLOW_INTERVAL = 5  # recompute slow items every N cycles
_ws_slow_cache: dict = {}  # last computed slow payload values


def background_thread():
    # Prime psutil so the first non-blocking call returns a valid delta.
    psutil.cpu_percent(interval=None)

    _cycle = 0
    while True:
        socketio.sleep(3)
        _cycle += 1
        _recompute_slow = (_cycle == 1) or (_cycle % _WS_SLOW_INTERVAL == 0)
        data_payload = {}

        # Collect system metrics — non-blocking (delta since previous call)
        try:
            data_payload['cpu_percent'] = psutil.cpu_percent(interval=None)
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
                # "Connected" window. 5 min was too twitchy on a home LAN: a passive ARP
                # sweep only runs every few minutes and sleeping devices don't answer every
                # cycle, so the headline read far below the real device list. Use a more
                # forgiving, configurable window (default 30 min) and also expose the total
                # known-device count so the full inventory is never hidden by the window.
                try:
                    _win = int(config.get('network', 'online_window_minutes', default=30))
                except Exception:
                    _win = 30
                cursor.execute(
                    "SELECT COUNT(*) FROM devices WHERE last_seen > datetime('now', ?)",
                    (f'-{_win} minutes',))
                data_payload['device_count'] = cursor.fetchone()[0]
                cursor.execute("SELECT COUNT(*) FROM devices")
                data_payload['device_count_total'] = cursor.fetchone()[0]
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
        elements.append({'data': {'id': 'router', 'label': 'Router', 'type': 'router',
                                  'color': '#6366f1', 'borderColor': '#4f46e5',
                                  'icon': router_icon_uri('#ffffff')}})
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
                    'status': status,
                    # Real device-type glyph (laptop/phone/camera/...) so the topology
                    # reads like a network diagram, not coloured blobs.
                    'icon': device_icon_uri(device.get('device_type'), device.get('category')),
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
        data_payload['all_devices_with_status'] = devices_with_status

        # ------------------------------------------------------------------
        # Slow-moving aggregates: recompute every ~15 s (every 5 cycles).
        # On cycle 1 we always compute so the first payload is complete.
        # Between recomputes we reuse the cached value — payload shape stays
        # identical so no client callback ever receives a missing key.
        # ------------------------------------------------------------------
        if _recompute_slow:
            _ws_slow_cache['traffic_timeline'] = db_manager.get_traffic_timeline(hours=24)
            _ws_slow_cache['protocol_distribution'] = db_manager.get_protocol_distribution(hours=24)
            _ws_slow_cache['device_activity_heatmap'] = db_manager.get_device_activity_heatmap(hours=24)

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
                    _ws_slow_cache['recent_alerts'] = df_alerts.to_dict('records')
                except (sqlite3.Error, pd.io.sql.DatabaseError) as e:
                    logger.error(f"Error fetching alerts for WebSocket: {e}")

            _ws_slow_cache['alert_timeline'] = db_manager.get_alert_timeline(days=7)
            _ws_slow_cache['anomaly_distribution'] = db_manager.get_anomaly_distribution(hours=24)
            _ws_slow_cache['bandwidth_chart'] = db_manager.get_bandwidth_stats(hours=24)

            conn = get_db_connection()
            if conn:
                try:
                    cursor = conn.cursor()
                    cursor.execute("SELECT COUNT(*) FROM devices")
                    _ws_slow_cache['total_devices_db'] = cursor.fetchone()[0]
                    cursor.execute("SELECT COUNT(*) FROM connections")
                    _ws_slow_cache['total_connections_db'] = cursor.fetchone()[0]
                    cursor.execute("SELECT COUNT(*) FROM alerts")
                    _ws_slow_cache['total_alerts_db'] = cursor.fetchone()[0]
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
            _ws_slow_cache['model_info'] = models_list

        # Merge cached slow values into the live payload
        data_payload.update(_ws_slow_cache)

        socketio.emit('update_data', data_payload)

        # Broadcast to plain WebSocket clients (dash-extensions WebSocket component)
        if _plain_ws_clients:
            _payload_str = json.dumps(data_payload)
            for _ws in _plain_ws_clients.copy():
                try:
                    _ws.send(_payload_str)
                except Exception:
                    _plain_ws_clients.discard(_ws)

def _ensure_background_thread():
    """Start the single live-data producer thread if it isn't running yet.

    Idempotent and safe to call from both the plain-WS handler and the Socket.IO
    connect handler — whichever client arrives first spins it up.
    """
    global thread
    with thread_lock:
        if thread is None:
            thread = socketio.start_background_task(background_thread)
            logger.info("Live-data background thread started.")


@socketio.on('connect')
def test_connect(auth):
    _ensure_background_thread()
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

    db_path = config.get('database', 'path', fallback='data/database/iotsentinel.db')

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

# One-shot migration: rename legacy tier values stored in user_preferences
try:
    _mc = db_manager.conn.cursor()
    _mc.execute("UPDATE user_preferences SET preference_value='simple' "
                "WHERE preference_key='dashboard_template' AND preference_value='home_user'")
    _mc.execute("UPDATE user_preferences SET preference_value='advanced' "
                "WHERE preference_key='dashboard_template' AND preference_value IN ('security_admin','developer')")
    db_manager.conn.commit()
except Exception:
    pass

# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

def _quiet_eventlet_tls_noise():
    """Stop eventlet from dumping a traceback for every benign per-connection TLS or
    socket error. A self-signed cert makes browsers and OS probes routinely abort the
    handshake (SSLV3_ALERT_CERTIFICATE_UNKNOWN, HTTP_REQUEST when plain http hits the
    TLS port, connection resets). eventlet's hub prints these unconditionally via
    squelch_exception ('Removing descriptor: N'), flooding the journal even though the
    server is fine. We wrap squelch_exception to silently drop ssl/connection errors
    and delegate anything unexpected to the original handler, and turn off the
    timer-path debug tracebacks too. Real request errors are handled by Flask/Dash."""
    try:
        import ssl as _ssl
        import eventlet.debug as _ev_debug
        import eventlet.hubs as _ev_hubs

        _benign = (_ssl.SSLError, ConnectionError, BrokenPipeError, ConnectionResetError, OSError)
        hub = _ev_hubs.get_hub()
        if hasattr(hub, 'squelch_exception'):
            _orig = hub.squelch_exception

            def _filtered(fileno, exc_info):
                if exc_info and exc_info[0] is not None and issubclass(exc_info[0], _benign):
                    try:
                        hub.remove_descriptor(fileno)
                    except Exception:
                        pass
                    return
                return _orig(fileno, exc_info)

            hub.squelch_exception = _filtered
        _ev_debug.hub_exceptions(False)  # also quiet the timer-path tracebacks
    except Exception as e:
        logger.debug(f"Could not install eventlet TLS-noise filter: {e}")


def _spawn_https_redirector(target_port):
    """Best-effort HTTP->HTTPS redirect on port 80, so a user who types the bare
    hostname (e.g. iotsentinel.local -> http on port 80) is bounced to the HTTPS
    dashboard instead of hitting a dead/cert-error page. Runs as an eventlet green
    thread. If port 80 can't be bound (no CAP_NET_BIND_SERVICE, not root, or it is
    already taken) it is skipped -- never fatal; the HTTPS dashboard is unaffected.
    The dashboard systemd unit grants AmbientCapabilities=CAP_NET_BIND_SERVICE so
    the unprivileged service user can bind 80 on the Pi."""
    try:
        import eventlet
        import eventlet.wsgi

        def _redirect_app(environ, start_response):
            host = (environ.get('HTTP_HOST', '') or 'localhost').split(':')[0]
            path = environ.get('PATH_INFO', '/') or '/'
            qs = environ.get('QUERY_STRING', '')
            target = f"https://{host}:{target_port}{path}" + (f"?{qs}" if qs else "")
            # 307 (temporary) so browsers don't cache it -- avoids a stale redirect
            # if HTTPS is ever turned back off.
            start_response('307 Temporary Redirect',
                           [('Location', target), ('Content-Length', '0')])
            return [b'']

        sock = eventlet.listen(('0.0.0.0', 80))
        eventlet.spawn_n(eventlet.wsgi.server, sock, _redirect_app, log_output=False)
        logger.info(f"HTTP->HTTPS redirector active on :80 -> https://<host>:{target_port}")
    except PermissionError:
        logger.info("HTTP->HTTPS redirector skipped (port 80 needs CAP_NET_BIND_SERVICE); not fatal")
    except Exception as e:
        logger.info(f"HTTP->HTTPS redirector skipped ({e}); not fatal")


def main():
    host = os.getenv('IOTSENTINEL_HOST', '127.0.0.1')
    port = int(os.getenv('IOTSENTINEL_PORT', config.get('dashboard', 'port', default=8050)))
    debug = os.getenv('IOTSENTINEL_DEBUG', 'false').lower() in ('true', '1', 'yes')

    # Suppress Flask/Werkzeug HTTP access logs (keeps error logs)
    import logging as log
    log.getLogger('werkzeug').setLevel(log.ERROR)
    log.getLogger('socketio').setLevel(log.WARNING)
    log.getLogger('engineio').setLevel(log.WARNING)

    logger.info("=" * 70)
    logger.info("IoTSentinel Dashboard - Enhanced Educational Edition")
    logger.info("=" * 70)
    logger.info(f"Dashboard URL: {'https' if _use_https else 'http'}://{host}:{port}")
    logger.info(f"Debug Mode: {'ON' if debug else 'OFF'}")
    logger.info("")

    # Check AI Assistant status
    ai_status = ai_assistant.get_status_message()
    ai_level = ai_assistant.get_status_level()
    logger.info(f"🤖 AI Chat: {ai_status}" + (f" ({ai_level})" if ai_level != "ok" else ""))

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

    # ── Startup Self-Test ─────────────────────────────────────────────────
    # Verify that critical DB tables exist before accepting traffic. On a FRESH first
    # boot the backend (orchestrator) creates the schema, and it may still be doing so
    # when the dashboard starts (it is only ordered After= the backend's *start*, not
    # its readiness). Rather than exit(1) immediately — which crash-loops the service
    # and previously left the Pi serving errors until a manual reboot — WAIT for the
    # tables to appear, re-opening the connection each try, then continue.
    import time as _time
    _required_tables = ['devices', 'alerts', 'users', 'connections']
    _deadline = _time.time() + 90
    _missing = list(_required_tables)
    _cur = None
    while _time.time() < _deadline:
        try:
            _conn = get_db_connection()
            _cur = _conn.cursor()
            _cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            _existing = {row[0] for row in _cur.fetchall()}
            _missing = [t for t in _required_tables if t not in _existing]
            if not _missing:
                break
        except Exception as e:
            logger.warning(f"DB not ready yet ({e}) — waiting for the backend…")
        logger.info(f"Waiting for backend to create DB tables (missing: {_missing})…")
        _time.sleep(3)
    if _missing:
        logger.error(f"❌ Required DB tables still missing after wait: {_missing}. "
                     "Is the backend (orchestrator) service running?")
        sys.exit(1)

    # Admin user check (warning only — admin is created during the setup wizard)
    try:
        _cur.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'")
        if _cur.fetchone()[0] == 0:
            logger.warning("⚠️  No admin user found yet (created during the setup wizard).")
    except Exception:
        pass

    # ── Graceful Shutdown ──────────────────────────────────────────────────
    import signal

    _shutdown_state = {"done": False}

    def _graceful_shutdown(signum, frame):
        # Ignore a second signal (e.g. an impatient double Ctrl+C) — re-running the
        # teardown raced the first pass and produced a spurious scheduler error.
        if _shutdown_state["done"]:
            return
        _shutdown_state["done"] = True
        sig_name = signal.Signals(signum).name
        logger.info(f"Received {sig_name} — shutting down gracefully …")
        try:
            if report_scheduler and hasattr(report_scheduler, 'stop'):
                report_scheduler.stop()
                logger.info("  ✓ Report scheduler stopped")
        except Exception:
            pass
        try:
            if db_manager and hasattr(db_manager, 'close'):
                db_manager.close()
                logger.info("  ✓ Database connection closed")
        except Exception:
            pass
        logger.info("Goodbye 👋")
        # os._exit (not sys.exit) — eventlet's greenlet WSGI server swallows the
        # SystemExit that sys.exit raises, so a single Ctrl+C never terminated the
        # process on macOS. A hard exit after the graceful cleanup above guarantees
        # the first Ctrl+C/SIGTERM actually stops the server.
        os._exit(0)

    signal.signal(signal.SIGTERM, _graceful_shutdown)
    signal.signal(signal.SIGINT, _graceful_shutdown)

    # HTTPS-on-LAN: generate a self-signed cert so WebAuthn/biometrics + the PWA
    # service worker work and passwords are encrypted on the LAN. Best-effort: if
    # anything fails we serve plain HTTP and downgrade the Secure cookie flags so
    # login still works (the dashboard must ALWAYS come up).
    certfile = keyfile = None
    if _use_https:
        try:
            from utils.self_signed_cert import ensure_self_signed_cert
            from utils.net_detect import get_local_ip
            lan_ip = get_local_ip()
            cert_ips = ['127.0.0.1', '10.42.0.1'] + ([lan_ip] if lan_ip else [])
            pair = ensure_self_signed_cert(
                Path(project_root) / 'data' / 'certs',
                hostnames=['localhost', 'iotsentinel.local'],
                ips=cert_ips,
            )
            if pair:
                certfile, keyfile = pair
                logger.info(f"HTTPS enabled — serving self-signed cert on {host}:{port}")
            else:
                raise RuntimeError("cert generation returned None")
        except Exception as e:
            logger.error(f"HTTPS requested but unavailable ({e}); serving plain HTTP")
            certfile = keyfile = None
            # Secure cookies would never be sent over HTTP -> downgrade so login works.
            server.config['SESSION_COOKIE_SECURE'] = False
            server.config['REMEMBER_COOKIE_SECURE'] = False

    if certfile and keyfile:
        # Serving a self-signed cert means browsers/probes constantly abort TLS
        # handshakes -- SSLV3_ALERT_CERTIFICATE_UNKNOWN (client rejects the cert),
        # HTTP_REQUEST (plain http hits the TLS port), connection resets. eventlet's
        # hub prints a full traceback for EACH of these dropped connections ("Removing
        # descriptor: N"), which is harmless (HTTPS keeps serving) but floods the log.
        # squelch_exception prints unconditionally, so hub_exceptions(False) alone is
        # not enough -- wrap it to drop these benign per-connection errors quietly.
        # Real application errors are handled by Flask/Dash and are untouched.
        _quiet_eventlet_tls_noise()

        # Bounce plain-HTTP visitors (bare hostname / port 80) to the HTTPS dashboard.
        _spawn_https_redirector(port)

    # Try running with SocketIO, fall back if needed
    try:
        # Note: use_reloader=False prevents double initialization in debug mode
        run_kwargs = dict(host=host, port=port, debug=debug,
                          allow_unsafe_werkzeug=debug, log_output=False, use_reloader=False)
        if certfile and keyfile:
            run_kwargs['certfile'] = certfile
            run_kwargs['keyfile'] = keyfile
        socketio.run(app.server, **run_kwargs)
    except Exception as e:
        logger.error(f"SocketIO failed to start: {e}")
        logger.info("Falling back to standard Dash server (WebSockets disabled)...")

        # Suppress werkzeug logs for fallback server too
        import logging as log
        werkzeug_log = log.getLogger('werkzeug')
        werkzeug_log.setLevel(log.ERROR)

        # Note: use_reloader=False prevents double initialization in debug mode
        fallback_kwargs = dict(host=host, port=port, debug=debug, use_reloader=False)
        if certfile and keyfile:
            fallback_kwargs['ssl_context'] = (certfile, keyfile)
        app.run(**fallback_kwargs)


# WEBAUTHN / PASSKEY API ENDPOINTS
# ============================================================================

@app.server.route('/api/webauthn/generate-authentication-options', methods=['POST'])
def generate_webauthn_auth_options():
    """Generate WebAuthn authentication options for passkey login"""
    csrf_err = _verify_same_origin()
    if csrf_err:
        return csrf_err
    rl = _check_api_rate_limit('api_call')
    if rl:
        return rl
    try:
        if not webauthn_handler:
            return jsonify({'error': 'WebAuthn not configured'}), 500

        # Generate authentication options (no username required - discoverable credentials)
        options = webauthn_handler.generate_authentication_options()

        return jsonify(options), 200

    except Exception as e:
        logger.error(f"Error generating WebAuthn auth options: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@app.server.route('/api/webauthn/verify-authentication', methods=['POST'])
def verify_webauthn_authentication():
    """Verify WebAuthn authentication response and log user in"""
    csrf_err = _verify_same_origin()
    if csrf_err:
        return csrf_err
    rl = _check_api_rate_limit('api_call')
    if rl:
        return rl
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
        return jsonify({'success': False, 'error': 'Internal server error'}), 500



# ============================================================================
# APP LAUNCHER
# ============================================================================

if __name__ == "__main__":
    main()
