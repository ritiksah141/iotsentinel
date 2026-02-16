"""
IoTSentinel Dashboard - Login Layout
====================================
Contains the login/register page layout and forgot-password modal.
Extracted from the monolithic app.py without any logic changes.
"""
from dash import dcc, html
import dash_bootstrap_components as dbc


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
                                    ], id="password-strength-container", style={"display": "block"}),
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
                                ], className="floating-input-group mb-0"),
                                html.Div(id="password-match-feedback", className="validation-feedback mb-3"),


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
                                dcc.Store(id='totp-login-state', storage_type='memory'),

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
