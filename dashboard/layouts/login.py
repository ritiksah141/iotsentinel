"""
IoTSentinel Dashboard - Login Layout
====================================
Single outer glass card (Spotlight-style) with left branding panel +
right form sub-card, mirroring the sl-two-col / sl-preview-pane pattern.
"""
from dash import dcc, html
import dash_bootstrap_components as dbc
from utils.oauth_handler import is_oauth_configured as _is_oauth_configured

_OAUTH_ENABLED = _is_oauth_configured()
_OAUTH_DISPLAY = {} if _OAUTH_ENABLED else {'display': 'none'}


# ============================================================================
# LOGIN PAGE LAYOUT
# ============================================================================

login_layout = dbc.Container([

    # ---- Full-screen centred wrapper ----------------------------------------
    html.Div([

        # ---- Outer glass card (like the Spotlight modal shell) ---------------
        html.Div([

            # ======================================================
            # LEFT PANEL — branding + features  (like sl-results-list)
            # ======================================================
            html.Div([

                # Logo
                html.Div([
                    html.Img(src="/assets/logo.png", className="login-logo"),
                ], className="text-center mb-3"),

                # Title + subtitle
                html.H1("IoTSentinel",
                        className="gradient-text text-center login-brand-title mb-1"),
                html.P("AI-Powered Edge Network Guardian",
                       className="text-center login-brand-subtitle mb-4"),

                # Feature badges — 2-col grid
                html.Div([
                    html.Div([
                        html.I(className="fa fa-diagram-project login-feat-icon"),
                        html.Div("Real-time Monitoring", className="login-feat-title"),
                        html.Div("Track connected devices", className="login-feat-desc"),
                    ], className="login-feat-badge"),
                    html.Div([
                        html.I(className="fa fa-brain login-feat-icon"),
                        html.Div("AI Threat Detection", className="login-feat-title"),
                        html.Div("ML-powered analysis", className="login-feat-desc"),
                    ], className="login-feat-badge"),
                    html.Div([
                        html.I(className="fa fa-network-wired login-feat-icon"),
                        html.Div("Network Analytics", className="login-feat-title"),
                        html.Div("Deep traffic insights", className="login-feat-desc"),
                    ], className="login-feat-badge"),
                    html.Div([
                        html.I(className="fa fa-gauge-high login-feat-icon"),
                        html.Div("Security Dashboard", className="login-feat-title"),
                        html.Div("Complete visibility", className="login-feat-desc"),
                    ], className="login-feat-badge"),
                ], className="login-feat-grid mb-4"),

                # Trust badges — 3-col grid
                html.Div([
                    html.Div([
                        html.I(className="fa fa-shield-halved login-feat-icon"),
                        html.Div("End-to-End Encrypted", className="login-feat-title"),
                        html.Div("256-bit AES", className="login-feat-desc"),
                    ], className="login-feat-badge"),
                    html.Div([
                        html.I(className="fa fa-lock login-feat-icon"),
                        html.Div("Data Stays Local", className="login-feat-title"),
                        html.Div("Never shared", className="login-feat-desc"),
                    ], className="login-feat-badge"),
                    html.Div([
                        html.I(className="fab fa-github login-feat-icon"),
                        html.Div("Open Source", className="login-feat-title"),
                        html.Div("Auditable code", className="login-feat-desc"),
                    ], className="login-feat-badge"),
                ], className="login-trust-grid"),

            ], className="login-brand-panel"),

            # ======================================================
            # RIGHT PANEL — form sub-card  (like sl-preview-pane)
            # ======================================================
            html.Div([

                # ---- Auth tabs (Login / Register) ----------------------------
                dbc.Tabs([

                    # ---- LOGIN TAB -------------------------------------------
                    dbc.Tab([

                        # Tab heading
                        html.Div([
                            html.Div([
                                html.I(className="fa fa-sign-in-alt login-header-icon"),
                                html.H2("Sign In", className="mb-0 login-header-title"),
                            ], className="d-flex align-items-center justify-content-center mb-1"),
                            html.P("Sign in to access your dashboard",
                                   className="mb-0 login-header-subtitle text-center"),
                        ], className="mt-1 mb-4"),

                        # Username
                        html.Div([
                            html.I(className="fa fa-user input-icon"),
                            dbc.Input(id="login-username", type="text", placeholder=" ",
                                      autocomplete="username",
                                      className="form-control login-form-input"),
                            html.Label("Username", htmlFor="login-username"),
                        ], className="floating-input-group mt-2"),

                        # Password
                        html.Div([
                            html.I(className="fa fa-lock input-icon"),
                            dbc.Input(id="login-password", type="password", placeholder=" ",
                                      autocomplete="current-password", n_submit=0,
                                      className="form-control login-form-input-pad"),
                            html.Label("Password", htmlFor="login-password"),
                            html.Button(
                                html.I(id="login-password-toggle", className="fa fa-eye"),
                                id="login-password-toggle-btn",
                                className="password-toggle-btn", type="button"),
                        ], className="floating-input-group"),

                        # 2FA section (hidden by default)
                        html.Div([
                            html.Div([
                                html.I(className="fa fa-shield-alt me-2 text-success"),
                                html.Strong("Two-Factor Authentication Required"),
                            ], className="d-flex align-items-center mb-2"),
                            html.P("Enter the 6-digit code from your authenticator app:",
                                   className="text-muted small mb-2"),
                            dbc.InputGroup([
                                dbc.InputGroupText(html.I(className="fa fa-mobile-alt")),
                                dbc.Input(id="login-totp-code", type="text",
                                          placeholder="000000", maxLength=6,
                                          className="text-center font-monospace u-otp-display u-text-xl"),
                            ], className="mb-2"),
                            html.Div([
                                dbc.Switch(id="use-backup-code-checkbox",
                                           label="Use backup code instead",
                                           value=False, className="small"),
                            ], className="mb-2"),
                            html.Div(id='totp-login-status'),
                        ], id='login-totp-section', style={'display': 'none'},
                           className="mb-3 p-3 border rounded login-totp-box"),

                        # Remember me + forgot password
                        html.Div([
                            dbc.Button([
                                html.I(className="fa fa-clock me-1"),
                                "Remember Me",
                            ], id="remember-me-btn", n_clicks=0,
                               className="login-pill-btn",
                               color="success", outline=True),
                            dbc.Switch(id="remember-me-checkbox", value=False,
                                       style={"display": "none"}),
                            html.A([
                                html.I(className="fa fa-key me-1"),
                                "Forgot Password?",
                            ], id="forgot-password-link", href="#",
                               className="login-pill-btn login-pill-forgot"),
                        ], className="auth-options-container"),

                        # Sign In button
                        dbc.Button([html.I(className="fa fa-sign-in-alt me-2"), "Sign In"],
                                   id="login-button",
                                   className="w-100 mt-2 cyber-button-modern", size="lg"),

                        # OAuth divider
                        html.Div([
                            html.Div(className="login-or-divider"),
                            html.Span("OR", className="login-or-label"),
                        ], style={"position": "relative", **_OAUTH_DISPLAY}),

                        # Google Sign-In
                        html.Div([
                            html.A([
                                html.Img(
                                    src="data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA0OCA0OCI+PHBhdGggZmlsbD0iI0ZGQzEwNyIgZD0iTTQzLjYgMjAuMUgyNHY3LjhoMTEuOEMzNC43IDMzIDMwIDM2LjkgMjQgMzYuOWMtNy4yIDAtMTMtNS44LTEzLTEzcy41LjgtMTMgMTNjMCAxMi4xIDkuOSAyMiAyMiAyMiA1LjkgMCAxMS4yLTIuMyAxNS4yLTYgNC4yLTMuOSA2LjgtOS42IDYuOC0xNiAwLTEtLjEtMi0uMi0zeiIvPjxwYXRoIGZpbGw9IiNGRjM5MzYiIGQ9Ik02LjMgMTQuNmwzIDYuNkM4LjggMTkuMyA4IDIxLjUgOCAyNHMuOCA0LjcgMS40IDYuOGwtNy02LjJDMSAzMSAxIDI3LjUgMSAyNHMwLTYuNy4zLTkuNHoiLz48cGF0aCBmaWxsPSIjM0U3MkI4IiBkPSJNMjQgMTFjMy4yIDAgNi4xIDEuMSA4LjQgMy4xTDM4IDguNkMzNC4yIDUuMiAyOS40IDMgMjQgM2MtNy45IDAtMTQuOCA0LjYtMTguMyAxMS4zTDEyLjMgMjBDMTQuMiAxNC43IDE4LjYgMTEgMjQgMTF6Ii8+PHBhdGggZmlsbD0iIzJFNzgzNSIgZD0iTTI0IDQ1Yy01LjUgMCAxMC40LTIuMS0xNC4xLTUuNmw2LjgtNS44QzE3LjcgMzUuNyAyMC43IDM3IDI0IDM3YzQuOCAwIDguOS0yLjYgMTEtNi41bDYuNCA1LjVDMzcuOCA0Mi43IDMxLjMgNDUgMjQgNDV6Ii8+PC9zdmc+",
                                    className="google-signin-img"),
                                html.Span("Continue with Google"),
                            ], href="/auth/google",
                               className="w-100 btn btn-outline-light google-signin-btn",
                               id="google-signin-btn"),
                        ], className="mb-2", id="oauth-section", style=_OAUTH_DISPLAY),

                        # Biometric
                        html.Div([
                            dbc.Button([
                                html.I(className="fa fa-fingerprint me-2"),
                                html.Span("Sign in with Biometrics"),
                            ], id="biometric-login-btn", className="w-100 biometric-btn",
                               color="primary", outline=True,
                               style={"display": "none"}),
                        ], className="mb-1", id="biometric-section"),

                    ], label="Login", tab_id="login-tab",
                       activeTabClassName="fw-bold"),

                    # ---- REGISTER TAB ----------------------------------------
                    dbc.Tab([

                        # Tab heading
                        html.Div([
                            html.Div([
                                html.I(className="fa fa-user-plus login-header-icon"),
                                html.H2("Create Account", className="mb-0 login-header-title"),
                            ], className="d-flex align-items-center justify-content-center mb-1"),
                            html.P("Set up your IoTSentinel account",
                                   className="mb-0 login-header-subtitle text-center"),
                        ], className="mt-1 mb-3"),

                        dbc.Alert(id="register-alert", is_open=False, duration=4000),

                        # Email
                        html.Div([
                            html.I(className="fa fa-envelope input-icon"),
                            dbc.Input(id="register-email", type="email", placeholder=" ",
                                      autocomplete="email",
                                      className="form-control login-form-input"),
                            html.Label("Email Address", htmlFor="register-email"),
                        ], className="floating-input-group mt-1"),
                        html.Div(id="email-validation-feedback",
                                 className="validation-feedback mb-1"),

                        # Username
                        html.Div([
                            html.I(className="fa fa-user input-icon"),
                            dbc.Input(id="register-username", type="text", placeholder=" ",
                                      autocomplete="off",
                                      className="form-control login-form-input"),
                            html.Label("Username", htmlFor="register-username"),
                        ], className="floating-input-group"),
                        html.Div(id="username-validation-feedback",
                                 className="validation-feedback mb-1"),

                        # Password
                        html.Div([
                            html.I(className="fa fa-lock input-icon"),
                            dbc.Input(id="register-password", type="password",
                                      placeholder=" ", autocomplete="new-password",
                                      className="form-control login-form-input-pad"),
                            html.Label("Password", htmlFor="register-password"),
                            html.Button(
                                html.I(id="register-password-toggle", className="fa fa-eye"),
                                id="register-password-toggle-btn",
                                className="password-toggle-btn", type="button"),
                        ], className="floating-input-group"),

                        # Compact strength bar + requirement chips
                        html.Div([
                            html.Div([
                                html.Div([
                                    html.Div(id="password-strength-bar",
                                             className="progress-xs rounded"),
                                ], className="progress-sm rounded flex-grow-1"),
                                html.Small(id="password-strength-text",
                                           className="login-strength-label"),
                            ], className="d-flex align-items-center gap-2 mb-2"),
                            html.Div([
                                html.Span([html.I(id="req-length",  className="fa fa-times-circle me-1 text-danger"), "8 chars"], className="login-req-chip"),
                                html.Span([html.I(id="req-upper",   className="fa fa-times-circle me-1 text-danger"), "A–Z"],     className="login-req-chip"),
                                html.Span([html.I(id="req-lower",   className="fa fa-times-circle me-1 text-danger"), "a–z"],     className="login-req-chip"),
                                html.Span([html.I(id="req-digit",   className="fa fa-times-circle me-1 text-danger"), "0–9"],     className="login-req-chip"),
                                html.Span([html.I(id="req-special", className="fa fa-times-circle me-1 text-danger"), "!@#"],     className="login-req-chip"),
                            ], className="login-req-chips"),
                        ], id="password-strength-container", className="mb-2"),

                        # Confirm password
                        html.Div([
                            html.I(className="fa fa-lock input-icon"),
                            dbc.Input(id="register-password-confirm", type="password",
                                      placeholder=" ", autocomplete="new-password",
                                      className="form-control login-form-input-pad"),
                            html.Label("Confirm Password",
                                       htmlFor="register-password-confirm"),
                            html.Button(
                                html.I(id="register-password-confirm-toggle",
                                       className="fa fa-eye"),
                                id="register-password-confirm-toggle-btn",
                                className="password-toggle-btn", type="button"),
                        ], className="floating-input-group mb-0"),
                        html.Div(id="password-match-feedback",
                                 className="validation-feedback mb-3"),

                        # Send verification code
                        dbc.Button(
                            [html.I(className="fa fa-paper-plane me-2"),
                             "Send Verification Code"],
                            id="send-verification-btn",
                            className="w-100 mb-3 fw-semibold",
                            color="info", outline=True),

                        # Verification code (hidden until sent)
                        html.Div([
                            # When email/SMTP isn't configured, the code can't be emailed —
                            # show it right here so registration still works on a LAN-only
                            # appliance (the admin controls who can reach the dashboard).
                            html.Div(id="verification-code-hint", className="small mb-2"),
                            html.Div([
                                html.I(className="fa fa-key input-icon"),
                                dbc.Input(id="verification-code", type="text",
                                          placeholder=" ", maxLength=6,
                                          className="form-control login-form-input"),
                                html.Label("Verification Code",
                                           htmlFor="verification-code"),
                            ], className="floating-input-group mb-3"),
                        ], id="verification-code-container", style={"display": "none"}),

                        # Hidden fields — configurable later in Settings
                        dbc.Select(id='register-template-select', value='simple',
                                   style={"display": "none"}),
                        dbc.Select(id='register-family-role-select', value='parent',
                                   style={"display": "none"}),
                        dcc.Store(id="register-role",          data="viewer"),
                        dcc.Store(id='verification-code-sent', storage_type='memory'),
                        dcc.Store(id='email-verified',         storage_type='memory'),
                        dcc.Store(id='totp-login-state',       storage_type='memory'),

                        # Create Account button
                        dbc.Button(
                            [html.I(className="fa fa-user-plus me-2"), "Create Account"],
                            id="register-button",
                            className="w-100 mt-2 cyber-button-modern",
                            size="lg", disabled=False),

                    ], label="Register", tab_id="register-tab",
                       activeTabClassName="fw-bold"),

                ], id="auth-tabs", active_tab="login-tab", className="mb-0"),

            ], className="login-form-panel"),

        ], className="login-outer-card"),

    ], className="login-page-center"),

    # ---- Forgot Password Modal -----------------------------------------------
    dbc.Modal([
        dbc.ModalHeader(
            dbc.ModalTitle([
                html.I(className="fa fa-key me-2 u-text-primary"),
                "Reset Your Password",
            ]),
            close_button=True,
        ),
        dbc.ModalBody([
            html.Div([
                html.P("Enter your email address and we'll send you a password reset link.",
                       className="text-secondary mb-3"),
                html.Div([
                    html.I(className="fa fa-envelope input-icon"),
                    dbc.Input(id="forgot-password-email", type="email",
                              placeholder=" ", autocomplete="email",
                              className="form-control login-form-input"),
                    html.Label("Email Address", htmlFor="forgot-password-email"),
                ], className="floating-input-group mb-3"),
                html.Div(id="forgot-password-message"),
            ], id="forgot-password-step-1"),
            html.Div([
                html.Div([
                    html.I(className="fa fa-check-circle fa-3x text-success mb-3"),
                    html.H5("Check Your Email", className="mb-2"),
                    html.P(["We've sent a password reset link to ",
                            html.Strong(id="reset-email-display",
                                        className="text-primary")],
                           className="text-secondary mb-2"),
                    html.P("The link will expire in 1 hour.",
                           className="text-muted small"),
                ], className="text-center"),
            ], id="forgot-password-step-2", style={"display": "none"}),
        ]),
        dbc.ModalFooter([
            dbc.Button("Cancel", id="forgot-password-cancel",
                       color="secondary", outline=True),
            dbc.Button([html.I(className="fa fa-paper-plane me-2"), "Send Reset Link"],
                       id="forgot-password-submit", color="primary",
                       className="cyber-button-modern"),
        ], id="forgot-password-footer"),
    ], id="forgot-password-modal", size="md", is_open=False, className="glass-modal"),

], fluid=True, className="login-page-bg")
