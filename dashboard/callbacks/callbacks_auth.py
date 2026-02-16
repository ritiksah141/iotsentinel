"""
Authentication callbacks — Login, Registration, Password, 2FA/TOTP, WebAuthn/Passkey, URL routing.

Extracted from app.py. All callbacks are registered via ``register(app, login_layout, dashboard_layout)``.
"""

import json
import logging
import os
import random
import re
import smtplib
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import dash
import dash_bootstrap_components as dbc
from dash import Input, Output, State, callback_context, html, ALL

from flask import request
from flask_login import login_required, login_user, logout_user, current_user

from dashboard.shared import (
    db_manager,
    auth_manager,
    totp_manager,
    audit_logger,
    security_audit_logger,
    login_rate_limiter,
    webauthn_handler,
    config,
    ToastManager,
    DASHBOARD_TEMPLATES,
    log_user_action,
    is_webauthn_available,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module-level helpers (moved together with their callbacks)
# ---------------------------------------------------------------------------

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


def send_password_reset_email(email: str, reset_link: str, token: str):
    """Send password reset email with glassmorphic styling"""
    smtp_server = os.getenv('EMAIL_SMTP_HOST', 'smtp.gmail.com')
    smtp_port = int(os.getenv('EMAIL_SMTP_PORT', '587'))
    smtp_user = os.getenv('EMAIL_SMTP_USER', '')
    smtp_password = os.getenv('EMAIL_SMTP_PASSWORD', '')
    sender_email = os.getenv('EMAIL_SENDER_EMAIL', smtp_user)

    if not smtp_user or not smtp_password:
        # If SMTP not configured, log the reset link for development
        logger.warning(f"SMTP not configured. Reset link: {reset_link}")
        logger.warning(f"Reset token for {email}: {token}")
        return

    msg = MIMEMultipart('alternative')
    msg['Subject'] = 'Reset Your IoTSentinel Password'
    msg['From'] = sender_email
    msg['To'] = email

    # Create HTML email body
    html_body = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                padding: 40px 20px;
                margin: 0;
            }}
            .container {{
                max-width: 600px;
                margin: 0 auto;
                background: rgba(255, 255, 255, 0.95);
                backdrop-filter: blur(10px);
                border-radius: 20px;
                padding: 40px;
                box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            }}
            .header {{
                text-align: center;
                margin-bottom: 30px;
            }}
            .logo {{
                font-size: 36px;
                font-weight: bold;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
            }}
            .content {{
                color: #333;
                line-height: 1.6;
            }}
            .button {{
                display: inline-block;
                padding: 16px 32px;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white !important;
                text-decoration: none;
                border-radius: 12px;
                font-weight: 600;
                margin: 20px 0;
                box-shadow: 0 8px 24px rgba(102, 126, 234, 0.4);
            }}
            .footer {{
                margin-top: 30px;
                padding-top: 20px;
                border-top: 1px solid #e0e0e0;
                color: #666;
                font-size: 14px;
                text-align: center;
            }}
            .warning {{
                background: #fff3cd;
                border-left: 4px solid #ffc107;
                padding: 12px;
                margin: 20px 0;
                border-radius: 4px;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <div class="logo">🛡️ IoTSentinel</div>
                <p style="color: #666; margin-top: 10px;">AI-Powered Network Security</p>
            </div>

            <div class="content">
                <h2 style="color: #333;">Password Reset Request</h2>
                <p>Hello,</p>
                <p>We received a request to reset your IoTSentinel password. Click the button below to create a new password:</p>

                <div style="text-align: center;">
                    <a href="{reset_link}" class="button">Reset My Password</a>
                </div>

                <div class="warning">
                    <strong>⚠️ Security Notice:</strong> This link will expire in 1 hour for your security.
                </div>

                <p>If you didn't request this password reset, please ignore this email. Your password will remain unchanged.</p>

                <p>For security reasons, we recommend:</p>
                <ul>
                    <li>Use a strong, unique password</li>
                    <li>Enable two-factor authentication</li>
                    <li>Never share your password with anyone</li>
                </ul>
            </div>

            <div class="footer">
                <p>This is an automated message from IoTSentinel.</p>
                <p>If you have any questions, please contact your system administrator.</p>
                <p style="margin-top: 20px; color: #999; font-size: 12px;">
                    If the button doesn't work, copy and paste this link into your browser:<br>
                    <a href="{reset_link}" style="color: #667eea;">{reset_link}</a>
                </p>
            </div>
        </div>
    </body>
    </html>
    """

    # Plain text version
    text_body = f"""
    IoTSentinel - Password Reset Request

    Hello,

    We received a request to reset your IoTSentinel password.

    Click the link below to create a new password:
    {reset_link}

    This link will expire in 1 hour for your security.

    If you didn't request this password reset, please ignore this email.

    Best regards,
    IoTSentinel Security Team
    """

    part1 = MIMEText(text_body, 'plain')
    part2 = MIMEText(html_body, 'html')

    msg.attach(part1)
    msg.attach(part2)

    # Send email
    server = smtplib.SMTP(smtp_server, smtp_port, timeout=30)
    server.ehlo()
    server.starttls()
    server.ehlo()
    server.login(smtp_user, smtp_password)
    server.sendmail(sender_email, email, msg.as_string())
    server.quit()


# ---------------------------------------------------------------------------
# Callback registration
# ---------------------------------------------------------------------------

def register(app, login_layout, dashboard_layout):
    """Register all authentication-related callbacks on *app*.

    Parameters
    ----------
    app : dash.Dash
        The Dash application instance.
    login_layout : dash component
        The login page layout (defined in app.py).
    dashboard_layout : dash component
        The main dashboard layout (defined in app.py).
    """

    # ------------------------------------------------------------------
    # Show/hide passkey login button based on WebAuthn support
    # ------------------------------------------------------------------
    app.clientside_callback(
        """
        function() {
            // Check if WebAuthn is supported
            if (window.PublicKeyCredential) {
                return {'display': 'block'};
            }
            return {'display': 'none'};
        }
        """,
        Output('biometric-login-btn', 'style'),
        Input('url', 'pathname')
    )

    # ------------------------------------------------------------------
    # URL routing / page display
    # ------------------------------------------------------------------
    @app.callback(
        [Output('page-content', 'children'),
         Output('auth-notification-store', 'data', allow_duplicate=True)],
        [Input('url', 'pathname')],
        prevent_initial_call='initial_duplicate'
    )
    def display_page(pathname):
        """Route to login or dashboard based on authentication"""
        # Check if user is authenticated
        if current_user.is_authenticated:
            # User is logged in
            if pathname == '/logout':
                # Log logout to security audit
                from flask import request
                user_ip = request.remote_addr or 'Unknown'
                security_audit_logger.log(
                    event_type='logout',
                    user_id=current_user.id,
                    username=current_user.username,
                    details={'session_ended': True},
                    severity='info',
                    ip_address=user_ip,
                    result='success'
                )
                # Only set notification store, do not immediately redirect or clear
                logout_user()
                return login_layout, {"type": "logout_success"}
            # Show dashboard for any other path when authenticated
            # IMPORTANT: Always return dash.no_update for auth-notification-store on dashboard navigation
            # to prevent triggering login toasts on page refresh
            return dashboard_layout, dash.no_update
        else:
            # User not logged in, show login page
            return login_layout, dash.no_update

    # ------------------------------------------------------------------
    # Redirect after auth toast
    # ------------------------------------------------------------------
    @app.callback(
        Output('url', 'pathname', allow_duplicate=True),
        Input('auth-notification-store', 'data'),
        prevent_initial_call=True
    )
    def redirect_after_auth_toast(notification_data):
        if notification_data:
            ntype = notification_data.get('type')
            if ntype == 'login_success':
                return "/"
            elif ntype == 'logout_success':
                return "/login"
        raise dash.exceptions.PreventUpdate

    # ------------------------------------------------------------------
    # Clear forms on logout
    # ------------------------------------------------------------------
    @app.callback(
        [Output('login-username', 'value'),
         Output('login-password', 'value'),
         Output('register-email', 'value'),
         Output('register-username', 'value'),
         Output('register-password', 'value'),
         Output('register-password-confirm', 'value'),
         Output('verification-code', 'value', allow_duplicate=True),
         Output('forgot-password-email', 'value')],
        [Input('url', 'pathname'),
         Input('auth-notification-store', 'data')],
        prevent_initial_call=True
    )
    def clear_form_inputs(pathname, notification_data):
        """Clear all form inputs when showing login page or after logout"""
        # Clear on logout or when not authenticated
        if notification_data and notification_data.get('type') == 'logout_success':
            return '', '', '', '', '', '', '', ''
        elif not current_user.is_authenticated:
            return '', '', '', '', '', '', '', ''
        # User is authenticated - don't update
        return dash.no_update, dash.no_update, dash.no_update, dash.no_update, dash.no_update, dash.no_update, dash.no_update, dash.no_update

    # ------------------------------------------------------------------
    # Auth toast notifications
    # ------------------------------------------------------------------
    @app.callback(
        [Output('toast-container', 'children', allow_duplicate=True),
         Output('auth-notification-store', 'data', allow_duplicate=True)],
        Input('auth-notification-store', 'data'),
        prevent_initial_call=True
    )
    def show_auth_notification(notification_data):
        """
        Display toast notifications for login/logout events

        IMPORTANT: This callback only triggers when auth-notification-store changes.
        The store uses 'memory' storage type, so it doesn't persist across refreshes.
        This prevents duplicate toasts on page refresh.
        """
        if not notification_data:
            raise dash.exceptions.PreventUpdate

        notification_type = notification_data.get('type')

        if notification_type == 'login_success':
            username = notification_data.get('username', 'User')
            first_login = notification_data.get('first_login', False)

            if first_login:
                # First time login
                welcome_body = f"Welcome, {username}! This is your first login."
                detail_info = f"First Login:\n• Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n• Status: Active\n\nWelcome to IoTSentinel! This is your first time logging in."
            else:
                # Returning user with last login info
                welcome_body = f"Welcome back, {username}!"
                last_login_time = notification_data.get('last_login_time', 'recently')
                last_login_ip = notification_data.get('last_login_ip', 'Unknown')
                detail_info = f"Last Login Details:\n• Time: {last_login_time}\n• IP Address: {last_login_ip}\n• Login Method: Password\n\nYou now have full access to the IoTSentinel dashboard."

            toast = ToastManager.success(
                welcome_body,
                header="Login Successful",
                duration="long",
                detail_message=detail_info
            )
            # Clear the notification store immediately to prevent any duplicate triggers
            return toast, None

        elif notification_type == 'logout_success':
            logout_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            toast = ToastManager.info(
                "You have been logged out successfully.",
                header="Logged Out",
                duration="medium",
                detail_message=f"Logout Time: {logout_time}\nSession Status: Terminated\n\nYour session has been securely closed. Please log in again to access the dashboard."
            )
            # Clear the notification store immediately to prevent any duplicate triggers
            return toast, None

        raise dash.exceptions.PreventUpdate

    # ------------------------------------------------------------------
    # Login handler with 2FA
    # ------------------------------------------------------------------
    @app.callback(
        [Output('toast-container', 'children', allow_duplicate=True),
         Output('url', 'pathname', allow_duplicate=True),
         Output('auth-notification-store', 'data', allow_duplicate=True),
         Output('login-totp-section', 'style'),
         Output('totp-login-state', 'data')],
        [Input('login-button', 'n_clicks'),
         Input('login-password', 'n_submit')],
        [State('login-username', 'value'),
         State('login-password', 'value'),
         State('remember-me-checkbox', 'value'),
         State('login-totp-code', 'value'),
         State('use-backup-code-checkbox', 'value'),
         State('totp-login-state', 'data')],
        prevent_initial_call=True
    )
    def handle_login(n_clicks, n_submit, username, password, remember_me, totp_code, use_backup, login_state):
        if n_clicks is None and n_submit is None:
            raise dash.exceptions.PreventUpdate

        # Validate inputs
        if not username or not password:
            missing_fields = []
            if not username:
                missing_fields.append("Username")
            if not password:
                missing_fields.append("Password")

            detail_msg = f"Missing required fields:\n"
            detail_msg += "\n".join(f"  • {field}" for field in missing_fields)
            detail_msg += "\n\nPlease fill in all required fields to continue."

            toast = ToastManager.warning(
                "Please enter both username and password",
                header="Validation Error",
                duration="short",
                detail_message=detail_msg
            )
            return toast, dash.no_update, dash.no_update, {'display': 'none'}, None

        # Check if username is locked out due to too many failed attempts
        is_locked, remaining_time = login_rate_limiter.is_locked_out(username)
        if is_locked:
            minutes = remaining_time // 60
            seconds = remaining_time % 60
            logger.warning(f"Login attempt for locked account '{username}' (locked for {minutes}m {seconds}s)")

            detail_msg = f"Security Lockout Information:\n\n"
            detail_msg += f"Account: {username}\n"
            detail_msg += f"Lockout Duration: {minutes} minute(s) and {seconds} second(s)\n"
            detail_msg += f"Reason: Too many failed login attempts\n\n"
            detail_msg += f"What you can do:\n"
            detail_msg += f"  • Wait for the lockout period to expire\n"
            detail_msg += f"  • Contact system administrator if you need immediate access\n"
            detail_msg += f"  • Ensure you're using the correct credentials\n\n"
            detail_msg += f"This is a security measure to protect your account from unauthorized access."

            toast = ToastManager.error(
                f"Too many failed attempts. Account locked for {minutes} minute(s) and {seconds} second(s).",
                header="Account Locked",
                duration="long",
                detail_message=detail_msg
            )
            return toast, dash.no_update, dash.no_update, {'display': 'none'}, None

        # Verify credentials
        user = auth_manager.verify_user(username, password)

        if user:
            # Check if 2FA is enabled for this user
            totp_enabled = totp_manager.is_totp_enabled(user.id)

            if totp_enabled:
                # User has 2FA enabled - check if they provided the code
                if not totp_code:
                    # Password correct, but need 2FA code - show 2FA section
                    toast = ToastManager.info(
                        "Password verified. Please enter your 2FA code.",
                        header="2FA Required",
                        duration="medium"
                    )
                    return toast, dash.no_update, dash.no_update, {'display': 'block'}, {'username': username, 'verified': True}

                # Verify 2FA code
                conn = db_manager.conn
                cursor = conn.cursor()
                cursor.execute('SELECT secret FROM totp_secrets WHERE user_id = ? AND enabled = 1', (user.id,))
                result = cursor.fetchone()

                if result:
                    secret = result['secret']

                    # Check if using backup code
                    if use_backup:
                        totp_valid = totp_manager.verify_backup_code(user.id, totp_code)
                        if totp_valid:
                            logger.info(f"User '{username}' authenticated with backup code")
                    else:
                        totp_valid = totp_manager.verify_token(secret, totp_code)

                    if not totp_valid:
                        # Invalid 2FA code
                        logger.warning(f"Invalid 2FA code for user '{username}'")
                        toast = ToastManager.error(
                            "Invalid 2FA code. Please try again.",
                            header="2FA Verification Failed",
                            duration="medium"
                        )
                        return toast, dash.no_update, dash.no_update, {'display': 'block'}, login_state

                    # 2FA successful - log audit
                    log_user_action(
                        audit_logger,
                        action='2fa_login',
                        target_username=username,
                        success=True
                    )
                else:
                    logger.error(f"2FA secret not found for user {user.id}")
                    toast = ToastManager.error(
                        "2FA configuration error. Please contact administrator.",
                        header="2FA Error",
                        duration="long"
                    )
                    return toast, dash.no_update, dash.no_update, {'display': 'none'}, None

            # Login successful (either no 2FA or 2FA verified) - reset rate limiter
            login_rate_limiter.record_successful_login(username)
            login_user(user, remember=remember_me)
            logger.info(f"User '{username}' logged in successfully (2FA: {totp_enabled}, remember_me={remember_me})")

            # Enhanced Welcome Experience: Get login history and record current login
            from flask import request
            from datetime import datetime

            # Get user's IP and user agent
            user_ip = request.remote_addr or 'Unknown'
            user_agent = request.headers.get('User-Agent', 'Unknown')

            # Log successful login to security audit
            security_audit_logger.log(
                event_type='login_success',
                user_id=user.id,
                username=user.username,
                details={'method': 'password' + ('+2fa' if totp_enabled else ''), 'remember_me': remember_me},
                severity='info',
                ip_address=user_ip,
                result='success'
            )

            # Query last login from history (before recording current one)
            conn = db_manager.conn
            cursor = conn.cursor()
            cursor.execute("""
                SELECT login_timestamp, ip_address, login_method
                FROM user_login_history
                WHERE user_id = ? AND success = 1
                ORDER BY login_timestamp DESC
                LIMIT 1
            """, (user.id,))
            last_login = cursor.fetchone()

            # Record current login in history
            cursor.execute("""
                INSERT INTO user_login_history
                (user_id, login_timestamp, ip_address, user_agent, login_method, success)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (user.id, datetime.now(), user_ip, user_agent, 'password' + ('+2fa' if totp_enabled else ''), 1))
            conn.commit()

            # Create personalized welcome message
            if last_login:
                last_login_time = last_login[0]
                last_login_ip = last_login[1]
                last_login_method = last_login[2]

                # Parse datetime - handle SQLite datetime format
                try:
                    # Try different datetime parsing methods
                    try:
                        # Try ISO format first
                        last_dt = datetime.fromisoformat(last_login_time)
                    except:
                        # Try SQLite datetime format: "2025-12-21 10:30:45.123456"
                        last_dt = datetime.strptime(last_login_time.split('.')[0], "%Y-%m-%d %H:%M:%S")

                    now = datetime.now()
                    time_diff = now - last_dt

                    # Format time difference
                    if time_diff.total_seconds() < 60:
                        time_ago = "moments ago"
                    elif time_diff.total_seconds() < 3600:
                        minutes = int(time_diff.total_seconds() / 60)
                        time_ago = f"{minutes} minute{'s' if minutes != 1 else ''} ago"
                    elif time_diff.total_seconds() < 86400:
                        hours = int(time_diff.total_seconds() / 3600)
                        time_ago = f"{hours} hour{'s' if hours != 1 else ''} ago"
                    else:
                        days = int(time_diff.days)
                        time_ago = f"{days} day{'s' if days != 1 else ''} ago"

                    # Simple text format like other toasts
                    welcome_body = f"Welcome back, {username}! Last login: {time_ago} from {last_login_ip}"

                    # Create detailed session information
                    detail_msg = f"Session Information:\n\n"
                    detail_msg += f"Username: {username}\n"
                    detail_msg += f"Current IP: {user_ip}\n"
                    detail_msg += f"User Agent: {user_agent[:100]}{'...' if len(user_agent) > 100 else ''}\n\n"
                    detail_msg += f"Last Login Details:\n"
                    detail_msg += f"  • Time: {last_login_time}\n"
                    detail_msg += f"  • IP Address: {last_login_ip}\n"
                    detail_msg += f"  • Method: {last_login_method}\n\n"
                    detail_msg += f"If this login was not you, please contact your administrator immediately."

                except Exception as e:
                    logger.error(f"Failed to parse last login time '{last_login_time}': {e}")
                    welcome_body = f"Welcome back, {username}!"

                    # Create basic session information even if parsing failed
                    detail_msg = f"Session Information:\n\n"
                    detail_msg += f"Username: {username}\n"
                    detail_msg += f"Current IP: {user_ip}\n"
                    detail_msg += f"User Agent: {user_agent[:100]}{'...' if len(user_agent) > 100 else ''}\n\n"
                    detail_msg += f"Successfully authenticated and logged in."
            else:
                # First time login
                welcome_body = f"Welcome, {username}! This is your first login."

                # Create first-time login detail message
                detail_msg = f"First Login Information:\n\n"
                detail_msg += f"Username: {username}\n"
                detail_msg += f"IP Address: {user_ip}\n"
                detail_msg += f"User Agent: {user_agent[:100]}{'...' if len(user_agent) > 100 else ''}\n\n"
                detail_msg += f"Welcome to IoTSentinel! This is your first successful login.\n\n"
                detail_msg += f"Security Tips:\n"
                detail_msg += f"  • Use a strong, unique password\n"
                detail_msg += f"  • Enable 2FA if available\n"
                detail_msg += f"  • Review login history regularly"

            toast = ToastManager.success(
                welcome_body,
                header="Login Successful",
                duration="long",
                detail_message=detail_msg
            )
            # Return toast directly - don't use auth-notification-store to avoid duplicate toasts
            return toast, "/", None, {'display': 'none'}, None
        else:
            # Check if login failed due to unverified email (except for admin user)
            user_data = auth_manager.get_user_by_username(username)
            if user_data and not user_data.get('email_verified') and username.lower() != 'admin':
                # User exists but email is not verified
                logger.warning(f"Login attempt with unverified email: {username}")

                detail_msg = f"Email Verification Required:\n\n"
                detail_msg += f"Your account has been created but your email address has not been verified.\n\n"
                detail_msg += f"To complete registration:\n"
                detail_msg += f"  1. Check your email inbox for the verification code\n"
                detail_msg += f"  2. Enter the code in the registration form\n"
                detail_msg += f"  3. Or click the verification link in the email\n\n"
                detail_msg += f"If you didn't receive the email:\n"
                detail_msg += f"  • Check your spam/junk folder\n"
                detail_msg += f"  • Request a new verification code\n"
                detail_msg += f"  • Contact administrator for assistance\n\n"
                detail_msg += f"Account: {username}\n"
                detail_msg += f"Email: {user_data.get('email', 'Not set')}"

                toast = ToastManager.warning(
                    "Please verify your email address before logging in.",
                    header="Email Verification Required",
                    duration="long",
                    detail_message=detail_msg
                )
                return toast, dash.no_update, dash.no_update, {'display': 'none'}, None

            # Login failed - record failed attempt
            is_now_locked, remaining_attempts = login_rate_limiter.record_failed_attempt(username)

            # Log failed login attempt to security audit
            from flask import request
            user_ip = request.remote_addr or 'Unknown'
            security_audit_logger.log(
                event_type='login_failure',
                username=username,
                details={'reason': 'invalid_credentials', 'remaining_attempts': remaining_attempts},
                severity='medium' if is_now_locked else 'low',
                ip_address=user_ip,
                result='failure',
                failure_reason='Invalid username or password'
            )

            if is_now_locked:
                logger.warning(f"Account '{username}' locked due to too many failed attempts")

                detail_msg = f"Account Security Lockout:\n\n"
                detail_msg += f"Your account has been temporarily locked due to multiple failed login attempts.\n\n"
                detail_msg += f"Details:\n"
                detail_msg += f"  • Account: {username}\n"
                detail_msg += f"  • Lockout Duration: 5 minutes\n"
                detail_msg += f"  • Reason: Security protection against brute force attacks\n\n"
                detail_msg += f"What to do:\n"
                detail_msg += f"  • Wait 5 minutes before trying again\n"
                detail_msg += f"  • Verify you are using the correct password\n"
                detail_msg += f"  • Use 'Forgot Password' if you cannot remember your credentials\n"
                detail_msg += f"  • Contact administrator if you suspect unauthorized access\n\n"
                detail_msg += f"This lockout protects your account from unauthorized access attempts."

                toast = ToastManager.error(
                    "Too many failed attempts. Account locked for 5 minutes.",
                    header="Account Locked",
                    duration="long",
                    detail_message=detail_msg
                )
                return toast, dash.no_update, dash.no_update, {'display': 'none'}, None
            else:
                logger.warning(f"Failed login attempt for username '{username}' ({remaining_attempts} attempts remaining)")

                detail_msg = f"Login Failed:\n\n"
                detail_msg += f"The username or password you entered is incorrect.\n\n"
                detail_msg += f"Security Information:\n"
                detail_msg += f"  • Account: {username}\n"
                detail_msg += f"  • Attempts Remaining: {remaining_attempts}\n"
                detail_msg += f"  • Lockout Threshold: 5 failed attempts\n\n"
                detail_msg += f"Troubleshooting:\n"
                detail_msg += f"  • Verify your username is spelled correctly\n"
                detail_msg += f"  • Check that Caps Lock is off\n"
                detail_msg += f"  • Ensure you're using the correct password\n"
                detail_msg += f"  • Use 'Forgot Password' if you cannot remember\n\n"
                detail_msg += f"After {remaining_attempts} more failed attempt(s), your account will be locked for 5 minutes."

                toast = ToastManager.error(
                    f"Invalid username or password. {remaining_attempts} attempt(s) remaining before lockout.",
                    header="Login Failed",
                    duration="long",
                    detail_message=detail_msg
                )
                return toast, dash.no_update, dash.no_update, {'display': 'none'}, None

    # ==================================================================
    # 2FA / TOTP CALLBACKS
    # ==================================================================

    # ------------------------------------------------------------------
    # 2FA status display
    # ------------------------------------------------------------------
    @app.callback(
        [Output('totp-status-display', 'children'),
         Output('enable-totp-btn', 'style'),
         Output('disable-totp-btn', 'style')],
        [Input('profile-edit-tabs', 'active_tab'),
         Input('profile-edit-modal', 'is_open')],
        prevent_initial_call=True
    )
    @login_required
    def load_totp_status(active_tab, is_open):
        if not is_open or active_tab != 'security-tab':
            raise dash.exceptions.PreventUpdate

        try:
            totp_status = totp_manager.get_totp_status(current_user.id)

            if totp_status['enabled']:
                # 2FA is enabled
                status_card = dbc.Alert([
                    html.Div([
                        html.I(className="fa fa-check-circle me-2 text-success"),
                        html.Strong("Two-Factor Authentication: Enabled", className="text-success")
                    ], className="d-flex align-items-center mb-2"),
                    html.Div([
                        html.Small(f"✓ Activated: {totp_status.get('verified_at', 'Unknown')}", className="d-block"),
                        html.Small(f"✓ Backup Codes Remaining: {totp_status.get('backup_codes_remaining', 0)}", className="d-block"),
                    ], className="ms-4")
                ], color="success", className="mb-0")

                return status_card, {'display': 'none'}, {'display': 'block'}
            else:
                # 2FA is disabled
                status_card = dbc.Alert([
                    html.Div([
                        html.I(className="fa fa-exclamation-triangle me-2 text-warning"),
                        html.Strong("Two-Factor Authentication: Disabled")
                    ], className="d-flex align-items-center mb-2"),
                    html.P("Enable 2FA to add an extra layer of security to your account.", className="mb-0 small text-muted")
                ], color="warning", className="mb-0")

                return status_card, {'display': 'block'}, {'display': 'none'}

        except Exception as e:
            logger.error(f"Error loading 2FA status: {e}")
            return dbc.Alert("Error loading 2FA status", color="danger"), {'display': 'none'}, {'display': 'none'}

    # ------------------------------------------------------------------
    # Generate TOTP QR + backup codes
    # ------------------------------------------------------------------
    @app.callback(
        [Output('totp-setup-section', 'style'),
         Output('totp-qr-code', 'children'),
         Output('totp-secret-display', 'value'),
         Output('totp-backup-codes-display', 'children'),
         Output('totp-setup-data', 'data'),
         Output('toast-container', 'children', allow_duplicate=True)],
        [Input('enable-totp-btn', 'n_clicks')],
        prevent_initial_call=True
    )
    @login_required
    def enable_totp_setup(n_clicks):
        if not n_clicks:
            raise dash.exceptions.PreventUpdate

        try:
            # Generate TOTP secret, QR code, and backup codes
            secret, qr_code, backup_codes = totp_manager.setup_totp(current_user.id, current_user.username)

            # Display QR code
            qr_img = html.Img(src=qr_code, style={'maxWidth': '250px', 'height': 'auto'})

            # Display backup codes
            codes_display = html.Div([
                dbc.ListGroup([
                    dbc.ListGroupItem(
                        html.Code(code, className="font-monospace"),
                        className="d-flex justify-content-center py-1"
                    )
                    for code in backup_codes
                ], flush=True)
            ])

            # Store data for verification
            setup_data = {
                'secret': secret,
                'backup_codes': backup_codes,
                'user_id': current_user.id
            }

            toast = ToastManager.info(
                "2FA setup initiated. Scan the QR code and enter a verification code.",
                header="2FA Setup",
                duration="medium"
            )

            return {'display': 'block'}, qr_img, secret, codes_display, setup_data, toast

        except Exception as e:
            logger.error(f"Error setting up 2FA: {e}")
            toast = ToastManager.error(
                f"Failed to set up 2FA: {str(e)}",
                header="2FA Setup Error",
                duration="long"
            )
            return {'display': 'none'}, None, "", None, None, toast

    # ------------------------------------------------------------------
    # Verify 2FA code
    # ------------------------------------------------------------------
    @app.callback(
        [Output('totp-verification-status', 'children'),
         Output('totp-status-display', 'children', allow_duplicate=True),
         Output('enable-totp-btn', 'style', allow_duplicate=True),
         Output('disable-totp-btn', 'style', allow_duplicate=True),
         Output('totp-setup-section', 'style', allow_duplicate=True),
         Output('totp-verification-code', 'value'),
         Output('toast-container', 'children', allow_duplicate=True)],
        [Input('verify-totp-btn', 'n_clicks')],
        [State('totp-verification-code', 'value')],
        prevent_initial_call=True
    )
    @login_required
    def verify_and_enable_totp(n_clicks, code):
        if not n_clicks:
            raise dash.exceptions.PreventUpdate

        if not code or len(code) != 6:
            status = dbc.Alert("Please enter a 6-digit code", color="warning", className="mb-0")
            return status, dash.no_update, dash.no_update, dash.no_update, dash.no_update, dash.no_update, dash.no_update

        try:
            # Verify and enable TOTP
            success = totp_manager.enable_totp(current_user.id, code)

            if success:
                # Log audit
                log_user_action(
                    audit_logger,
                    action='2fa_enable',
                    target_username=current_user.username,
                    success=True
                )

                # Update status display
                status_card = dbc.Alert([
                    html.Div([
                        html.I(className="fa fa-check-circle me-2 text-success"),
                        html.Strong("Two-Factor Authentication: Enabled", className="text-success")
                    ], className="d-flex align-items-center mb-2"),
                    html.Small("2FA has been successfully enabled for your account.", className="d-block ms-4")
                ], color="success", className="mb-0")

                toast = ToastManager.success(
                    "2FA enabled successfully! Your account is now more secure.",
                    header="2FA Enabled",
                    duration="long"
                )

                return (
                    dbc.Alert("2FA enabled successfully!", color="success"),
                    status_card,
                    {'display': 'none'},
                    {'display': 'block'},
                    {'display': 'none'},
                    "",
                    toast
                )
            else:
                status = dbc.Alert("Invalid code. Please try again.", color="danger", className="mb-0")
                return status, dash.no_update, dash.no_update, dash.no_update, dash.no_update, dash.no_update, dash.no_update

        except Exception as e:
            logger.error(f"Error verifying 2FA: {e}")
            status = dbc.Alert(f"Error: {str(e)}", color="danger", className="mb-0")
            return status, dash.no_update, dash.no_update, dash.no_update, dash.no_update, dash.no_update, dash.no_update

    # ------------------------------------------------------------------
    # Cancel 2FA setup
    # ------------------------------------------------------------------
    @app.callback(
        [Output('totp-setup-section', 'style', allow_duplicate=True),
         Output('totp-verification-code', 'value', allow_duplicate=True)],
        [Input('cancel-totp-setup-btn', 'n_clicks')],
        prevent_initial_call=True
    )
    @login_required
    def cancel_totp_setup(n_clicks):
        if not n_clicks:
            raise dash.exceptions.PreventUpdate

        return {'display': 'none'}, ""

    # ------------------------------------------------------------------
    # Disable 2FA
    # ------------------------------------------------------------------
    @app.callback(
        [Output('totp-status-display', 'children', allow_duplicate=True),
         Output('enable-totp-btn', 'style', allow_duplicate=True),
         Output('disable-totp-btn', 'style', allow_duplicate=True),
         Output('toast-container', 'children', allow_duplicate=True)],
        [Input('disable-totp-btn', 'n_clicks')],
        prevent_initial_call=True
    )
    @login_required
    def disable_totp(n_clicks):
        if not n_clicks:
            raise dash.exceptions.PreventUpdate

        try:
            success = totp_manager.disable_totp(current_user.id)

            if success:
                # Log audit
                log_user_action(
                    audit_logger,
                    action='2fa_disable',
                    target_username=current_user.username,
                    success=True
                )

                status_card = dbc.Alert([
                    html.Div([
                        html.I(className="fa fa-exclamation-triangle me-2 text-warning"),
                        html.Strong("Two-Factor Authentication: Disabled")
                    ], className="d-flex align-items-center mb-2"),
                    html.P("Enable 2FA to add an extra layer of security to your account.", className="mb-0 small text-muted")
                ], color="warning", className="mb-0")

                toast = ToastManager.info(
                    "2FA has been disabled for your account.",
                    header="2FA Disabled",
                    duration="medium"
                )

                return status_card, {'display': 'block'}, {'display': 'none'}, toast
            else:
                toast = ToastManager.error(
                    "Failed to disable 2FA.",
                    header="Error",
                    duration="medium"
                )
                return dash.no_update, dash.no_update, dash.no_update, toast

        except Exception as e:
            logger.error(f"Error disabling 2FA: {e}")
            toast = ToastManager.error(
                f"Error: {str(e)}",
                header="2FA Disable Error",
                duration="long"
            )
            return dash.no_update, dash.no_update, dash.no_update, toast

    # ------------------------------------------------------------------
    # Copy TOTP secret
    # ------------------------------------------------------------------
    @app.callback(
        Output('toast-container', 'children', allow_duplicate=True),
        [Input('copy-totp-secret-btn', 'n_clicks')],
        [State('totp-secret-display', 'value')],
        prevent_initial_call=True
    )
    def copy_totp_secret(n_clicks, secret):
        if not n_clicks:
            raise dash.exceptions.PreventUpdate

        toast = ToastManager.info(
            f"Secret copied: {secret}",
            header="Copied to Clipboard",
            duration="short"
        )
        return toast

    # ------------------------------------------------------------------
    # Download backup codes
    # ------------------------------------------------------------------
    @app.callback(
        Output('download-backup-codes-btn', 'n_clicks'),
        [Input('download-backup-codes-btn', 'n_clicks')],
        [State('totp-setup-data', 'data')],
        prevent_initial_call=True
    )
    @login_required
    def download_backup_codes(n_clicks, setup_data):
        if not n_clicks or not setup_data:
            raise dash.exceptions.PreventUpdate

        try:
            backup_codes = setup_data.get('backup_codes', [])

            # Create backup codes file content
            content = f"IoTSentinel 2FA Backup Codes\n"
            content += f"Username: {current_user.username}\n"
            content += f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            content += f"\n{'='*50}\n\n"
            content += "BACKUP CODES (use these if you lose access to your authenticator):\n\n"

            for i, code in enumerate(backup_codes, 1):
                content += f"{i}. {code}\n"

            content += f"\n{'='*50}\n"
            content += "IMPORTANT: Store these codes in a safe place!\n"
            content += "Each code can only be used once.\n"

            # Create download
            filename = f"iotsentinel_backup_codes_{current_user.username}_{datetime.now().strftime('%Y%m%d')}.txt"

            # Note: In a real implementation, you would use dcc.Download component
            # For now, just log it
            logger.info(f"Backup codes download requested for user {current_user.username}")

        except Exception as e:
            logger.error(f"Error downloading backup codes: {e}")

        return 0  # Reset clicks

    # ------------------------------------------------------------------
    # Forgot password modal
    # ------------------------------------------------------------------
    @app.callback(
        Output('forgot-password-modal', 'is_open'),
        [Input('forgot-password-link', 'n_clicks'),
         Input('forgot-password-cancel', 'n_clicks'),
         Input('forgot-password-submit', 'n_clicks')],
        State('forgot-password-modal', 'is_open'),
        prevent_initial_call=True
    )
    def toggle_forgot_password_modal(link_clicks, cancel_clicks, submit_clicks, is_open):
        """Toggle forgot password modal"""
        ctx = callback_context
        if not ctx.triggered:
            return is_open

        button_id = ctx.triggered[0]['prop_id'].split('.')[0]

        # Open modal when link is clicked, close when cancel is clicked
        # Keep open when submit is clicked (will be handled by next callback)
        if button_id == 'forgot-password-link':
            return True
        elif button_id == 'forgot-password-cancel':
            return False

        return is_open

    # ------------------------------------------------------------------
    # Password reset email
    # ------------------------------------------------------------------
    @app.callback(
        [Output('forgot-password-step-1', 'style'),
         Output('forgot-password-step-2', 'style'),
         Output('reset-email-display', 'children'),
         Output('forgot-password-footer', 'style'),
         Output('forgot-password-message', 'children')],
        Input('forgot-password-submit', 'n_clicks'),
        State('forgot-password-email', 'value'),
        prevent_initial_call=True
    )
    def send_reset_email(n_clicks, email):
        """Send password reset email"""
        if not email or '@' not in email or '.' not in email:
            return (
                {"display": "block"},
                {"display": "none"},
                "",
                {"display": "flex"},
                dbc.Alert("Please enter a valid email address", color="warning", className="mb-0")
            )

        # Generate reset token
        reset_token = auth_manager.create_password_reset_token(email)

        if not reset_token:
            return (
                {"display": "block"},
                {"display": "none"},
                "",
                {"display": "flex"},
                dbc.Alert("No account found with that email address", color="danger", className="mb-0")
            )

        # Send email with reset link
        from flask import request
        reset_link = f"{request.host_url}reset-password?token={reset_token}"

        try:
            # Send email using existing SMTP configuration
            send_password_reset_email(email, reset_link, reset_token)
            logger.info(f"Password reset email sent to {email}")

            # Show success step
            return (
                {"display": "none"},
                {"display": "block"},
                email,
                {"display": "none"},
                ""
            )
        except Exception as e:
            logger.error(f"Failed to send reset email: {e}")
            return (
                {"display": "block"},
                {"display": "none"},
                "",
                {"display": "flex"},
                dbc.Alert(f"Failed to send email. Please try again later or contact support.", color="danger", className="mb-0")
            )

    # ==================================================================
    # PASSWORD TOGGLE VISIBILITY CALLBACKS
    # ==================================================================

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

    @app.callback(
        [Output('profile-current-password', 'type'),
         Output('profile-current-password-toggle-icon', 'className')],
        Input('profile-current-password-toggle-btn', 'n_clicks'),
        State('profile-current-password', 'type'),
        prevent_initial_call=True
    )
    def toggle_profile_current_password(n_clicks, current_type):
        """Toggle current password visibility on profile page"""
        if current_type == 'password':
            return 'text', 'fa fa-eye-slash'
        return 'password', 'fa fa-eye'

    @app.callback(
        [Output('profile-new-password', 'type'),
         Output('profile-new-password-toggle-icon', 'className')],
        Input('profile-new-password-toggle-btn', 'n_clicks'),
        State('profile-new-password', 'type'),
        prevent_initial_call=True
    )
    def toggle_profile_new_password(n_clicks, current_type):
        """Toggle new password visibility on profile page"""
        if current_type == 'password':
            return 'text', 'fa fa-eye-slash'
        return 'password', 'fa fa-eye'

    @app.callback(
        [Output('profile-new-password-confirm', 'type'),
         Output({'type': 'profile-password-toggle-icon', 'index': 'new-confirm'}, 'className')],
        Input({'type': 'profile-password-toggle-btn', 'index': 'new-confirm'}, 'n_clicks'),
        State('profile-new-password-confirm', 'type'),
        prevent_initial_call=True
    )
    def toggle_profile_confirm_password(n_clicks, current_type):
        """Toggle confirm new password visibility on profile page"""
        if current_type == 'password':
            return 'text', 'fa fa-eye-slash'
        return 'password', 'fa fa-eye'

    # ==================================================================
    # VALIDATION CALLBACKS
    # ==================================================================

    # ------------------------------------------------------------------
    # Email validation
    # ------------------------------------------------------------------
    @app.callback(
        [Output('email-validation-feedback', 'children'),
         Output('register-email', 'style')],
        Input('register-email', 'value'),
        prevent_initial_call=True
    )
    def validate_email_realtime(email):
        """Validate email in real-time"""
        base_style = {"border": "1px solid var(--border-color)", "borderLeft": "none"}

        if not email:
            return "", base_style

        # Import email validator
        try:
            from email_validator import validate_email, EmailNotValidError

            try:
                # Validate email format
                validate_email(email, check_deliverability=False)

                # Check if email already exists
                conn = db_manager.conn
                cursor = conn.cursor()
                cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
                existing = cursor.fetchone()

                if existing:
                    error_style = {**base_style, "borderColor": "var(--danger-color)", "boxShadow": "0 0 0 0.2rem rgba(239, 68, 68, 0.25)"}
                    return html.Div([
                        html.I(className="fa fa-times-circle validation-error me-1"),
                        html.Small("Email already registered", className="text-danger")
                    ]), error_style

                success_style = {**base_style, "borderColor": "var(--success-color)", "boxShadow": "0 0 0 0.2rem rgba(16, 185, 129, 0.25)"}
                return html.Div([
                    html.I(className="fa fa-check-circle validation-success me-1", style={"color": "var(--success-color)"}),
                    html.Small("Valid email", className="text-success")
                ]), success_style

            except EmailNotValidError:
                error_style = {**base_style, "borderColor": "var(--danger-color)", "boxShadow": "0 0 0 0.2rem rgba(239, 68, 68, 0.25)"}
                return html.Div([
                    html.I(className="fa fa-times-circle validation-error me-1"),
                    html.Small("Invalid email format", className="text-danger")
                ]), error_style

        except ImportError:
            # If email-validator not installed, do basic validation
            if '@' in email and '.' in email.split('@')[-1]:
                return html.Div([
                    html.I(className="fa fa-check-circle validation-success me-1", style={"color": "var(--success-color)"}),
                    html.Small("Valid email", className="text-success")
                ]), base_style
            else:
                return html.Div([
                    html.I(className="fa fa-times-circle validation-error me-1"),
                    html.Small("Invalid email format", className="text-danger")
                ]), base_style

    # ------------------------------------------------------------------
    # Username validation
    # ------------------------------------------------------------------
    @app.callback(
        [Output('username-validation-feedback', 'children'),
         Output('register-username', 'style')],
        Input('register-username', 'value'),
        prevent_initial_call=True
    )
    def validate_username_realtime(username):
        """Validate username in real-time"""
        base_style = {"border": "1px solid var(--border-color)", "borderLeft": "none"}

        if not username:
            return "", base_style

        # Check length
        if len(username) < 3:
            error_style = {**base_style, "borderColor": "var(--danger-color)", "boxShadow": "0 0 0 0.2rem rgba(239, 68, 68, 0.25)"}
            return html.Div([
                html.I(className="fa fa-times-circle validation-error me-1"),
                html.Small("Username must be at least 3 characters", className="text-danger")
            ]), error_style

        # Check valid characters
        if not username.replace('_', '').replace('-', '').isalnum():
            error_style = {**base_style, "borderColor": "var(--danger-color)", "boxShadow": "0 0 0 0.2rem rgba(239, 68, 68, 0.25)"}
            return html.Div([
                html.I(className="fa fa-times-circle validation-error me-1"),
                html.Small("Only letters, numbers, _ and - allowed", className="text-danger")
            ]), error_style

        # Check availability
        conn = db_manager.conn
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        existing = cursor.fetchone()

        if existing:
            error_style = {**base_style, "borderColor": "var(--danger-color)", "boxShadow": "0 0 0 0.2rem rgba(239, 68, 68, 0.25)"}
            return html.Div([
                html.I(className="fa fa-times-circle validation-error me-1"),
                html.Small("Username already taken", className="text-danger")
            ]), error_style

        success_style = {**base_style, "borderColor": "var(--success-color)", "boxShadow": "0 0 0 0.2rem rgba(16, 185, 129, 0.25)"}
        return html.Div([
            html.I(className="fa fa-check-circle validation-success me-1", style={"color": "var(--success-color)"}),
            html.Small(f"'{username}' is available", className="text-success")
        ]), success_style

    # ------------------------------------------------------------------
    # Password strength meter
    # ------------------------------------------------------------------
    @app.callback(
        [Output('password-strength-bar', 'style'),
         Output('password-strength-text', 'children'),
         Output('password-strength-container', 'style')],
        Input('register-password', 'value'),
        prevent_initial_call=True
    )
    def validate_password_strength(password):
        """Validate password strength in real-time"""
        if not password:
            return (
                {"height": "4px", "width": "0%", "borderRadius": "2px", "transition": "all 0.3s ease"},
                "",
                {"display": "none"}
            )

        # Try to use zxcvbn for advanced strength checking
        try:
            from zxcvbn import zxcvbn
            result = zxcvbn(password)
            score = result['score']  # 0-4

            colors = ["#ef4444", "#f59e0b", "#fbbf24", "#10b981", "#059669"]
            labels = ["Very Weak", "Weak", "Fair", "Good", "Strong"]
            widths = ["20%", "40%", "60%", "80%", "100%"]

            bar_style = {
                "height": "4px",
                "width": widths[score],
                "backgroundColor": colors[score],
                "borderRadius": "2px",
                "transition": "all 0.3s ease"
            }

            text = f"{labels[score]}"
            if score < 2 and result['feedback'].get('warning'):
                text += f" - {result['feedback']['warning']}"

            return bar_style, text, {"display": "block"}

        except ImportError:
            # Fallback to basic strength checking
            score = 0
            if len(password) >= 8: score += 1
            if any(c.isupper() for c in password): score += 1
            if any(c.islower() for c in password): score += 1
            if any(c.isdigit() for c in password): score += 1
            if any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password): score += 1

            score = min(score, 4)
            colors = ["#ef4444", "#f59e0b", "#fbbf24", "#10b981", "#059669"]
            labels = ["Very Weak", "Weak", "Fair", "Good", "Strong"]
            widths = ["20%", "40%", "60%", "80%", "100%"]

            bar_style = {
                "height": "4px",
                "width": widths[score],
                "backgroundColor": colors[score],
                "borderRadius": "2px",
                "transition": "all 0.3s ease"
            }

            return bar_style, labels[score], {"display": "block"}

    # ------------------------------------------------------------------
    # Email verification code
    # ------------------------------------------------------------------
    @app.callback(
        [Output('verification-code-container', 'style'),
         Output('verification-code-sent', 'data'),
         Output('send-verification-btn', 'disabled'),
         Output('toast-container', 'children', allow_duplicate=True)],
        Input('send-verification-btn', 'n_clicks'),
        State('register-email', 'value'),
        prevent_initial_call=True
    )
    def send_verification_code(n_clicks, email):
        """Send verification code to email"""
        if n_clicks is None:
            raise dash.exceptions.PreventUpdate

        # Validate email
        if not email or '@' not in email or '.' not in email:
            toast = ToastManager.warning(
                "Invalid Email",
                detail_message="Please enter a valid email address"
            )
            return {"display": "none"}, False, False, toast

        # Generate 6-digit code
        code = ''.join([str(random.randint(0, 9)) for _ in range(6)])

        # Store code with timestamp (expires in 10 minutes)
        verification_codes[email] = {
            'code': code,
            'timestamp': datetime.now(),
            'expires': datetime.now() + timedelta(minutes=10)
        }

        # Send email
        if send_verification_email(email, code):
            logger.info(f"Verification code sent to {email}")
            toast = ToastManager.success(
                "Code Sent",
                detail_message=f"Verification code sent to {email}"
            )
            return {"display": "block"}, True, True, toast
        else:
            # For development/testing - show code in toast if email fails
            logger.warning(f"Email sending failed. Verification code for {email}: {code}")
            toast = ToastManager.info(
                "Email Service Down",
                detail_message=f"Email service unavailable. Your verification code is: {code}"
            )
            return {"display": "block"}, True, True, toast

    # ------------------------------------------------------------------
    # Code verification
    # ------------------------------------------------------------------
    @app.callback(
        [Output('email-verified', 'data'),
         Output('register-button', 'disabled'),
         Output('toast-container', 'children', allow_duplicate=True)],
        Input('verification-code', 'value'),
        [State('register-email', 'value'),
         State('verification-code-sent', 'data')],
        prevent_initial_call=True
    )
    def verify_code(code, email, code_sent):
        """Verify the entered code"""
        if not code_sent or not code or len(code) != 6:
            raise dash.exceptions.PreventUpdate

        if email not in verification_codes:
            toast = ToastManager.error(
                "Code Expired",
                detail_message="Verification code expired. Please request a new code."
            )
            return False, True, toast

        stored_data = verification_codes[email]

        # Check if code expired
        if datetime.now() > stored_data['expires']:
            del verification_codes[email]
            toast = ToastManager.error(
                "Code Expired",
                detail_message="Verification code expired. Please request a new code."
            )
            return False, True, toast

        # Verify code
        if code == stored_data['code']:
            toast = ToastManager.success(
                "Email Verified",
                detail_message="Email verified successfully! You can now create your account."
            )
            return True, False, toast
        else:
            toast = ToastManager.error(
                "Verification Failed",
                detail_message="Invalid verification code"
            )
            return False, True, toast

    # ------------------------------------------------------------------
    # URL param autofill
    # ------------------------------------------------------------------
    @app.callback(
        [Output('verification-code', 'value'),
         Output('verification-code-container', 'style', allow_duplicate=True),
         Output('tabs', 'active_tab', allow_duplicate=True)],
        Input('url', 'search'),
        prevent_initial_call=True
    )
    def autofill_verification_code(search):
        """Auto-fill verification code if provided in URL parameter"""
        if not search:
            raise dash.exceptions.PreventUpdate

        # Parse query parameters
        from urllib.parse import parse_qs
        params = parse_qs(search.lstrip('?'))

        # Check if verify parameter exists
        if 'verify' in params and params['verify']:
            code = params['verify'][0]
            if code and len(code) == 6 and code.isdigit():
                # Show verification code container and switch to register tab
                return code, {"display": "block"}, "register-tab"

        raise dash.exceptions.PreventUpdate

    # ------------------------------------------------------------------
    # Password match feedback
    # ------------------------------------------------------------------
    @app.callback(
        [Output('password-strength-bar', 'style', allow_duplicate=True),
         Output('password-strength-text', 'children', allow_duplicate=True),
         Output('password-strength-container', 'style', allow_duplicate=True),
         Output('req-length', 'className'),
         Output('req-upper', 'className'),
         Output('req-lower', 'className'),
         Output('req-digit', 'className'),
         Output('req-special', 'className'),
         Output('password-match-feedback', 'children'),
         Output('password-match-feedback', 'className'),
         Output('register-button', 'disabled', allow_duplicate=True)],
        [Input('register-password', 'value'),
         Input('register-password-confirm', 'value')],
        [State('email-verified', 'data')],
        prevent_initial_call=True
    )
    def update_password_feedback_and_button_state(password, password_confirm, email_verified):
        # Initialize outputs
        bar_style = {"height": "8px", "width": "0%", "borderRadius": "4px", "transition": "all 0.3s ease", "backgroundColor": "var(--border-color)"}
        strength_text = ""
        strength_container_style = {"display": "block"}

        # Requirement icons (initially red X)
        req_class_red = "fa fa-times-circle me-2 text-danger"
        req_class_green = "fa fa-check-circle me-2 text-success"
        req_length = req_class_red
        req_upper = req_class_red
        req_lower = req_class_red
        req_digit = req_class_red
        req_special = req_class_red

        match_feedback_children = ""
        match_feedback_class = "validation-feedback mb-3"
        register_button_disabled = True

        # Password Matching
        if password and password_confirm:
            if password == password_confirm:
                match_feedback_children = html.Div([
                    html.I(className="fa fa-check-circle me-1"),
                    "Passwords match"
                ], className="text-success")
                match_feedback_class = "validation-feedback mb-3 text-success"
                register_button_disabled = False # Temporarily enable, will be re-evaluated by strength
            else:
                match_feedback_children = html.Div([
                    html.I(className="fa fa-times-circle me-1"),
                    "Passwords do not match"
                ], className="text-danger")
                match_feedback_class = "validation-feedback mb-3 text-danger"
                register_button_disabled = True
        elif not password_confirm and password:
            match_feedback_children = html.Div([
                html.I(className="fa fa-info-circle me-1"),
                "Please confirm password"
            ], className="text-muted")
            match_feedback_class = "validation-feedback mb-3 text-muted"
            register_button_disabled = True
        else:
            register_button_disabled = True # Disable if either password field is empty

        # Password Strength
        if password:
            score = 0
            if len(password) >= 8:
                score += 1
                req_length = req_class_green
            if re.search(r"[A-Z]", password):
                score += 1
                req_upper = req_class_green
            if re.search(r"[a-z]", password):
                score += 1
                req_lower = req_class_green
            if re.search(r"\d", password):
                score += 1
                req_digit = req_class_green
            if re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]", password):
                score += 1
                req_special = req_class_green

            # Max score is 5 for all criteria met + length
            colors = ["#ef4444", "#f59e0b", "#fbbf24", "#10b981", "#059669", "#059669"] # Adjusted colors for 6 levels
            labels = ["Very Weak", "Weak", "Fair", "Good", "Strong", "Very Strong"]
            widths = ["0%", "20%", "40%", "60%", "80%", "100%"]

            # If length requirement isn't met, cap score
            actual_score = score if len(password) >= 8 else min(score, 1)

            bar_style = {
                "height": "8px",
                "width": widths[actual_score],
                "backgroundColor": colors[actual_score],
                "borderRadius": "4px",
                "transition": "all 0.3s ease"
            }
            strength_text = labels[actual_score]

            # Determine if password is strong enough based on AuthManager logic (all 5 criteria)
            is_strong = (len(password) >= 8 and
                         re.search(r"[A-Z]", password) and
                         re.search(r"[a-z]", password) and
                         re.search(r"\d", password) and
                         re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]", password))

            # Final decision on button enablement
            if not is_strong or password != password_confirm or not email_verified:
                register_button_disabled = True
            else:
                register_button_disabled = False

        return (
            bar_style, strength_text, strength_container_style,
            req_length, req_upper, req_lower, req_digit, req_special,
            match_feedback_children, match_feedback_class, register_button_disabled
        )

    # ------------------------------------------------------------------
    # User registration
    # ------------------------------------------------------------------
    @app.callback(
        [Output('auth-tabs', 'active_tab', allow_duplicate=True),
         Output('toast-container', 'children', allow_duplicate=True),
         Output('dashboard-template-store', 'data', allow_duplicate=True)],
        Input('register-button', 'n_clicks'),
        [State('register-email', 'value'),
         State('register-username', 'value'),
         State('register-password', 'value'),
         State('register-password-confirm', 'value'),
         State('register-role', 'data'),
         State('register-template-select', 'value'),
         State('register-family-role-select', 'value')],
        prevent_initial_call=True
    )
    def handle_registration(n_clicks, email, username, password, password_confirm, role, template, family_role):
        """Handle user registration"""
        if n_clicks is None:
            raise dash.exceptions.PreventUpdate

        # Validation
        if not email or not username or not password or not password_confirm:
            toast = ToastManager.warning(
                "Validation Error",
                detail_message="Please fill in all fields"
            )
            return dash.no_update, toast, dash.no_update

        if len(username) < 3:
            toast = ToastManager.warning(
                "Validation Error",
                detail_message="Username must be at least 3 characters"
            )
            return dash.no_update, toast, dash.no_update

        if not auth_manager.is_password_strong_enough(password):
            toast = ToastManager.error(
                "Password Not Strong Enough",
                detail_message="Password must be at least 8 characters and contain at least one uppercase letter, one lowercase letter, one digit, and one special character.",
                show_detail_button=True
            )
            return dash.no_update, toast, dash.no_update

        if password != password_confirm:
            toast = ToastManager.error(
                "Validation Error",
                detail_message="Passwords do not match"
            )
            return dash.no_update, toast, dash.no_update

        # Attempt to create user
        success = auth_manager.create_user(username, password, role or 'viewer', email)

        if success:
            # Log successful user creation to security audit
            security_audit_logger.log(
                event_type='user_created',
                severity='info',
                user_id=current_user.id if current_user.is_authenticated else None,
                username=current_user.username if current_user.is_authenticated else 'system',
                resource_type='user',
                resource_id=username,
                details={'created_user': username, 'role': role or 'viewer', 'email': email},
                result='success'
            )

            # Initialize all user preferences and settings for security and privacy
            try:
                conn = db_manager.conn
                cursor = conn.cursor()

                # Get the newly created user ID
                cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
                user_result = cursor.fetchone()

                if user_result:
                    new_user_id = user_result[0]

                    # Determine user restrictions based on family role
                    is_kid_value = '1' if family_role == 'kid' else '0'

                    # Comprehensive default preferences for security, privacy, and usability
                    default_preferences = [
                        # Family & Access Control
                        ('is_kid', is_kid_value),
                        ('dashboard_template', template or 'custom'),

                        # Security Settings (stricter for kids)
                        ('require_2fa', '1' if is_kid_value == '0' else '0'),  # Parents should use 2FA
                        ('session_timeout', '15' if is_kid_value == '1' else '60'),  # Kids: 15 min, Adults: 60 min
                        ('allow_api_access', '0' if is_kid_value == '1' else '1'),  # Kids: no API access

                        # Privacy Settings
                        ('data_sharing', '0'),  # Disabled by default
                        ('analytics_tracking', '0'),  # No tracking by default
                        ('activity_logging', '1'),  # Enable activity logging for security

                        # Notification Preferences (stricter for kids to alert parents)
                        ('email_notifications', '1'),  # Enabled by default
                        ('alert_notifications', 'critical,high' if is_kid_value == '0' else 'critical,high,medium'),  # Kids get more alerts
                        ('email_recipient', email),

                        # UI/UX Preferences
                        ('refresh_interval', '10000'),  # 10 seconds
                        ('display_density', 'comfortable'),
                        ('theme', 'light'),
                        ('language', 'en'),
                        ('layout', 'grid'),
                        ('timezone', 'UTC'),

                        # Data Management
                        ('data_retention', '30'),  # 30 days
                        ('auto_export', 'disabled'),
                        ('backup_schedule', 'daily'),
                        ('backup_retention', '30'),

                        # ML & Detection Settings
                        ('anomaly_threshold', '0.85'),
                        ('enable_ml_predictions', '1'),
                        ('auto_block_threats', '0' if is_kid_value == '0' else '0'),  # Manual review by default

                        # Device Management (stricter for kids)
                        ('auto_trust_new_devices', '0'),  # Always require manual approval
                        ('allow_device_blocking', '0' if is_kid_value == '1' else '1'),  # Kids can't block devices
                        ('allow_device_deletion', '0' if is_kid_value == '1' else '1'),  # Kids can't delete devices

                        # Network Settings
                        ('enable_network_isolation', '1'),  # Enabled by default for security
                        ('upnp_enabled', '0'),  # Disabled by default (security risk)

                        # Toast Preferences
                        ('toast_history_enabled', '1'),
                        ('toast_retention_days', '30'),
                        ('toast_sound_enabled', '0'),
                        ('max_simultaneous_toasts', '3'),
                    ]

                    # Batch insert all preferences
                    cursor.executemany('''
                        INSERT INTO user_preferences (user_id, preference_key, preference_value)
                        VALUES (?, ?, ?)
                    ''', [(new_user_id, key, value) for key, value in default_preferences])

                    conn.commit()

                    logger.info(f"Initialized {len(default_preferences)} default preferences for {username} (family_role: {'kid' if is_kid_value == '1' else 'parent'}, template: {template})")

            except Exception as e:
                logger.error(f"Failed to save user preferences during registration: {e}")
                # Don't fail registration if preference save fails, but log it

            # Send verification email
            try:
                auth_manager.send_verification_email(email)
                logger.info(f"Verification email sent to {email} for user {username}")
            except Exception as e:
                logger.error(f"Failed to send verification email: {e}")
                # Don't fail registration if email fails, user can verify later

            logger.info(f"New user registered: {username} (role: {role or 'viewer'}, email: {email}, template: {template or 'custom'})")

            template_name = DASHBOARD_TEMPLATES.get(template or 'custom', {}).get('name', 'Custom')
            toast = ToastManager.success(
                "Account Created Successfully!",
                detail_message=f"Your account has been created with {template_name} dashboard template. Please check your email to verify your account. After login, you can change your dashboard template in Preferences.",
                show_detail_button=True
            )
            return "login-tab", toast, template or 'custom'
        else:
            toast = ToastManager.error(
                "Registration Failed",
                detail_message="Username or email already exists. Please try a different username or email address.",
                show_detail_button=True
            )
            return dash.no_update, toast, dash.no_update

    # ==================================================================
    # BIOMETRIC / WEBAUTHN CALLBACKS
    # ==================================================================

    # ------------------------------------------------------------------
    # Biometric/WebAuthn management
    # ------------------------------------------------------------------
    @app.callback(
        [Output('biometric-security-section', 'style'),
         Output('biometric-devices-list', 'children'),
         Output('biometric-username-store', 'data-username')],
        Input('profile-edit-modal', 'is_open'),
        prevent_initial_call=False
    )
    def manage_biometric_section(is_open):
        """Show biometric section if WebAuthn available and load registered devices"""
        if not is_open or not current_user.is_authenticated:
            return {"display": "none"}, [], ''

        # Check if WebAuthn is available
        if not webauthn_handler or not is_webauthn_available():
            return {"display": "none"}, [], ''

        # Get current username
        username = current_user.username

        # Load registered devices
        try:
            credentials = webauthn_handler.get_user_credentials_list(current_user.id)

            if not credentials:
                device_list = html.Div([
                    html.P([
                        html.I(className="fa fa-info-circle me-2", style={"color": "var(--info-color)"}),
                        "No biometric credentials registered yet."
                    ], className="text-secondary", style={"fontSize": "0.85rem"})
                ])
            else:
                device_items = []
                for cred in credentials:
                    device_name = cred.get('device_name', 'Unknown Device')
                    credential_id = cred.get('credential_id')

                    device_items.append(
                        dbc.Card([
                            dbc.CardBody([
                                dbc.Row([
                                    dbc.Col([
                                        html.I(className="fa fa-fingerprint me-2", style={"color": "var(--accent-color)"}),
                                        html.Strong(device_name)
                                    ], md=9),
                                    dbc.Col([
                                        dbc.Button([html.I(className="fa fa-trash")],
                                        id={"type": "remove-biometric-btn", "index": credential_id},
                                        color="danger", size="sm", outline=True, title="Remove device", n_clicks=0)
                                    ], md=3, className="d-flex justify-content-end")
                                ])
                            ])
                        ], className="mb-2", style={"background": "rgba(255, 255, 255, 0.05)", "border": "1px solid rgba(255, 255, 255, 0.1)"})
                    )
                device_list = html.Div(device_items)

            return {"display": "block"}, device_list, username

        except Exception as e:
            logger.error(f"Error loading biometric devices: {e}")
            return {"display": "block"}, html.P("Error loading devices", className="text-danger"), username

    # ------------------------------------------------------------------
    # WebAuthn register (clientside)
    # ------------------------------------------------------------------
    app.clientside_callback(
        """
        function(n_clicks, username) {
            if (!n_clicks) {
                return window.dash_clientside.no_update;
            }

            if (!username) {
                alert('Username not available. Please try again.');
                return window.dash_clientside.no_update;
            }

            // Call WebAuthn registration
            if (window.WebAuthnClient && window.WebAuthnClient.register) {
                window.WebAuthnClient.register(username)
                    .then(result => {
                        // Success - reload page to refresh device list
                        console.log('Biometric registration successful:', result);
                        alert('Biometric credential registered successfully! Please close and reopen the profile to see it.');
                        window.location.reload();
                    })
                    .catch(error => {
                        console.error('Biometric registration failed:', error);
                        alert('Biometric registration failed: ' + error.message);
                    });
            } else {
                alert('WebAuthn is not supported on this device/browser');
            }

            return window.dash_clientside.no_update;
        }
        """,
        Output('biometric-status-message', 'children'),
        [Input('register-biometric-btn', 'n_clicks'),
         Input('biometric-username-store', 'data-username')],
        prevent_initial_call=True
    )

    # ------------------------------------------------------------------
    # WebAuthn/passkey login (clientside)
    # ------------------------------------------------------------------
    app.clientside_callback(
        """
        async function(n_clicks) {
            if (!n_clicks) {
                return window.dash_clientside.no_update;
            }

            // Check if WebAuthn is supported
            if (!window.PublicKeyCredential) {
                return {
                    'props': {
                        'children': 'Passkey authentication is not supported in this browser. Please use Chrome, Edge, Safari, or Firefox.',
                        'color': 'warning',
                        'className': 'mb-2'
                    },
                    'type': 'Alert',
                    'namespace': 'dash_bootstrap_components'
                };
            }

            try {
                // Get authentication options from server
                const optionsResponse = await fetch('/api/webauthn/generate-authentication-options', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'}
                });

                if (!optionsResponse.ok) {
                    throw new Error('Failed to get authentication options');
                }

                const options = await optionsResponse.json();

                // Convert challenge from base64
                options.challenge = Uint8Array.from(atob(options.challenge.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));

                // Convert credential IDs if present
                if (options.allowCredentials) {
                    options.allowCredentials = options.allowCredentials.map(cred => ({
                        ...cred,
                        id: Uint8Array.from(atob(cred.id.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0))
                    }));
                }

                // Request authentication
                const credential = await navigator.credentials.get({
                    publicKey: options
                });

                // Prepare credential for server
                const credentialData = {
                    id: credential.id,
                    rawId: btoa(String.fromCharCode(...new Uint8Array(credential.rawId))),
                    response: {
                        clientDataJSON: btoa(String.fromCharCode(...new Uint8Array(credential.response.clientDataJSON))),
                        authenticatorData: btoa(String.fromCharCode(...new Uint8Array(credential.response.authenticatorData))),
                        signature: btoa(String.fromCharCode(...new Uint8Array(credential.response.signature))),
                        userHandle: credential.response.userHandle ? btoa(String.fromCharCode(...new Uint8Array(credential.response.userHandle))) : null
                    },
                    type: credential.type
                };

                // Verify with server
                const verifyResponse = await fetch('/api/webauthn/verify-authentication', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        credential: credentialData,
                        challenge_key: options.challenge_key
                    })
                });

                const result = await verifyResponse.json();

                if (result.success) {
                    // Redirect to dashboard
                    window.location.href = '/';
                    return window.dash_clientside.no_update;
                } else {
                    return {
                        'props': {
                            'children': result.error || 'Authentication failed. Please try again.',
                            'color': 'danger',
                            'className': 'mb-2'
                        },
                        'type': 'Alert',
                        'namespace': 'dash_bootstrap_components'
                    };
                }

            } catch (error) {
                console.error('Passkey authentication error:', error);
                return {
                    'props': {
                        'children': error.name === 'NotAllowedError' ? 'Authentication cancelled or timed out.' : 'Passkey authentication failed: ' + error.message,
                        'color': 'warning',
                        'className': 'mb-2'
                    },
                    'type': 'Alert',
                    'namespace': 'dash_bootstrap_components'
                };
            }
        }
        """,
        Output('totp-login-status', 'children'),  # Reuse this output for biometric status
        Input('biometric-login-btn', 'n_clicks'),
        prevent_initial_call=True
    )

    # ------------------------------------------------------------------
    # Biometric remove dialog
    # ------------------------------------------------------------------
    @app.callback(
        [Output('biometric-remove-credential-id', 'data'),
         Output('confirm-remove-biometric-modal', 'is_open', allow_duplicate=True)],
        Input({"type": "remove-biometric-btn", "index": ALL}, "n_clicks"),
        prevent_initial_call=True
    )
    def open_biometric_remove_confirmation(n_clicks_list):
        """Open confirmation modal before removing biometric credential"""
        if not current_user.is_authenticated or not webauthn_handler:
            raise dash.exceptions.PreventUpdate

        ctx = callback_context
        if not ctx.triggered:
            raise dash.exceptions.PreventUpdate

        # Check if any button was actually clicked (n_clicks > 0)
        if not n_clicks_list or not any(n_clicks_list):
            raise dash.exceptions.PreventUpdate

        # Get credential ID from button that was clicked
        triggered_id = ctx.triggered[0]['prop_id'].split('.')[0]
        import json
        try:
            button_data = json.loads(triggered_id)
            credential_id = button_data['index']
        except:
            raise dash.exceptions.PreventUpdate

        # Store credential ID and open modal
        return credential_id, True

    # ------------------------------------------------------------------
    # Cancel biometric removal
    # ------------------------------------------------------------------
    @app.callback(
        Output('confirm-remove-biometric-modal', 'is_open', allow_duplicate=True),
        Input('cancel-remove-biometric', 'n_clicks'),
        prevent_initial_call=True
    )
    def cancel_biometric_removal(n_clicks):
        """Close confirmation modal without removing"""
        if not n_clicks:
            raise dash.exceptions.PreventUpdate
        return False

    # ------------------------------------------------------------------
    # Confirm biometric removal
    # ------------------------------------------------------------------
    @app.callback(
        [Output('toast-container', 'children', allow_duplicate=True),
         Output('confirm-remove-biometric-modal', 'is_open', allow_duplicate=True),
         Output('profile-edit-modal', 'is_open', allow_duplicate=True)],
        Input('confirm-remove-biometric', 'n_clicks'),
        State('biometric-remove-credential-id', 'data'),
        prevent_initial_call=True
    )
    def confirm_remove_biometric_device(n_clicks, credential_id):
        """Remove biometric credential after confirmation"""
        if not n_clicks or not credential_id:
            raise dash.exceptions.PreventUpdate

        if not current_user.is_authenticated or not webauthn_handler:
            raise dash.exceptions.PreventUpdate

        # Remove credential
        success = webauthn_handler.remove_credential(current_user.id, credential_id)

        if success:
            # Log the action
            audit_logger.log_user_action(
                action="biometric_removed",
                username=current_user.username,
                success=True,
                details=f"Credential ID: {credential_id[:10]}..."
            )

            toast = ToastManager.success(
                "Device Removed",
                detail_message="Biometric credential has been removed successfully. You can register a new device anytime."
            )
            return toast, False, True  # Close confirmation modal, reopen profile to refresh list
        else:
            toast = ToastManager.error(
                "Removal Failed",
                detail_message="Failed to remove biometric credential. Please try again."
            )
            return toast, False, dash.no_update
