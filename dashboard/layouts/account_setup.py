"""
IoTSentinel — First-run account setup screen (non-Linux / dev machines).

Shown when no admin user exists yet, on platforms where the full 6-step
setup wizard is skipped (macOS, Windows). Uses the same glass-card shell
as the login page so it looks intentional, not like an error state.
"""
from dash import dcc, html
import dash_bootstrap_components as dbc


account_setup_layout = dbc.Container([
    dcc.Location(id="account-setup-url", refresh=True),

    html.Div([
        html.Div([

            # Left brand panel
            html.Div([
                html.Div([
                    html.I(className="fa fa-shield-halved fa-3x text-info mb-3 d-block text-center"),
                    html.H2("IoTSentinel", className="gradient-text text-center login-brand-title mb-1"),
                    html.P("AI-Powered Edge Network Guardian",
                           className="text-center login-brand-subtitle mb-4"),
                ]),
                html.Div([
                    html.Div([
                        html.I(className="fa fa-circle-check text-success me-2"),
                        html.Span("No default password", className="small"),
                    ], className="mb-2"),
                    html.Div([
                        html.I(className="fa fa-circle-check text-success me-2"),
                        html.Span("You choose your credentials", className="small"),
                    ], className="mb-2"),
                    html.Div([
                        html.I(className="fa fa-circle-check text-success me-2"),
                        html.Span("Strong password enforced", className="small"),
                    ], className="mb-2"),
                ], className="mt-auto text-muted"),
            ], className="login-brand-panel"),

            # Right form panel
            html.Div([
                html.Div([
                    html.I(className="fa fa-user-shield login-header-icon"),
                    html.H4("Create Admin Account", className="mb-0 login-header-title"),
                ], className="d-flex align-items-center mb-1"),
                html.P(
                    "This is a one-time step. Your credentials will be used to log in "
                    "to IoTSentinel from now on.",
                    className="text-muted small mb-4"
                ),

                # Username
                html.Div([
                    html.I(className="fa fa-user input-icon"),
                    dbc.Input(
                        id="account-setup-username",
                        type="text",
                        placeholder=" ",
                        value="admin",
                        autocomplete="username",
                        className="form-control login-form-input",
                    ),
                    html.Label("Username", htmlFor="account-setup-username"),
                ], className="floating-input-group mb-3"),

                # Password
                html.Div([
                    html.I(className="fa fa-lock input-icon"),
                    dbc.Input(
                        id="account-setup-password",
                        type="password",
                        placeholder=" ",
                        autocomplete="new-password",
                        className="form-control login-form-input",
                    ),
                    html.Label("Password", htmlFor="account-setup-password"),
                ], className="floating-input-group mb-3"),

                # Confirm password
                html.Div([
                    html.I(className="fa fa-lock input-icon"),
                    dbc.Input(
                        id="account-setup-password-confirm",
                        type="password",
                        placeholder=" ",
                        autocomplete="new-password",
                        className="form-control login-form-input",
                    ),
                    html.Label("Confirm password", htmlFor="account-setup-password-confirm"),
                ], className="floating-input-group mb-1"),

                html.P(
                    "Min 8 chars, upper + lower + digit + special (e.g. @, !, #).",
                    className="small text-muted mb-3"
                ),

                # Autonomous protection — same consent the Pi wizard asks for.
                dbc.Switch(
                    id="account-setup-autoblock",
                    label="Let IoTSentinel block a device automatically when it behaves like a threat",
                    value=True,
                    className="mb-3",
                ),

                # Feedback area
                html.Div(id="account-setup-feedback", className="mb-3"),

                # Submit
                dbc.Button(
                    [html.I(className="fa fa-arrow-right me-2"), "Create account and log in"],
                    id="account-setup-submit-btn",
                    color="primary",
                    className="w-100 cyber-button-modern",
                    n_clicks=0,
                ),

            ], className="login-form-panel"),

        ], className="login-outer-card"),
    ], className="login-page-center"),

], fluid=True, className="login-page-bg")
