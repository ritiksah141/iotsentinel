"""
IoTSentinel First-Run Setup Wizard
===================================
Shown automatically when no .env file is found (fresh install).
Writes the .env, marks is_configured=true, then redirects to /login.
"""
from dash import dcc, html
import dash_bootstrap_components as dbc

# Vendor "Get my key" links
_VENDOR_LINKS = {
    "groq": "https://console.groq.com/keys",
    "abuseipdb": "https://www.abuseipdb.com/account/api",
    "gmail_apppassword": "https://myaccount.google.com/apppasswords",  # pragma: allowlist secret
}


def _key_row(label, field_id, placeholder, vendor_key=None, hint=None):
    """Helper: renders a labelled input row with optional 'Get my key' link."""
    children = [
        dbc.Label(label, html_for=field_id, className="fw-semibold"),
        dbc.InputGroup([
            dbc.Input(id=field_id, placeholder=placeholder, type="password",
                      autocomplete="off", className="setup-input"),
            dbc.InputGroupText(
                html.A("Get my key", href=_VENDOR_LINKS[vendor_key],
                       target="_blank", className="text-info text-decoration-none small")
            ) if vendor_key else None,
        ], className="mb-1"),
        html.Div(id=f"{field_id}-feedback", className="small text-muted mb-3"),
    ]
    if hint:
        children.insert(1, html.P(hint, className="small text-muted mb-1"))
    return html.Div([c for c in children if c is not None])


# --------------------------------------------------------------------------
# Step panels
# --------------------------------------------------------------------------

_step_1 = dbc.Card([
    dbc.CardHeader(html.H5("Step 1 of 3 — Base Setup", className="mb-0 text-cyber")),
    dbc.CardBody([
        html.P(
            "IoTSentinel works straight away with no API keys at all. "
            "These settings let it find your devices on the network.",
            className="text-muted mb-3"
        ),
        dbc.Label("Local network range (CIDR)", html_for="setup-network-cidr", className="fw-semibold"),
        dbc.Input(id="setup-network-cidr", placeholder="192.168.1.0/24",
                  value="192.168.1.0/24", className="mb-3"),

        dbc.Label("Network interface", html_for="setup-interface", className="fw-semibold"),
        dbc.Input(id="setup-interface", placeholder="wlan0 or eth0",
                  value="wlan0", className="mb-3"),

        dbc.Label("Admin password", html_for="setup-admin-password", className="fw-semibold"),
        html.P("Used only for the first admin account — change it after login.",
               className="small text-muted mb-1"),
        dbc.Input(id="setup-admin-password", type="password",
                  placeholder="Choose a strong password", className="mb-3"),
        dbc.Input(id="setup-admin-password-confirm", type="password",
                  placeholder="Confirm password", className="mb-3"),
        html.Div(id="setup-password-feedback", className="small text-danger mb-2"),
    ]),
], className="mb-3 setup-card")

_step_2 = dbc.Card([
    dbc.CardHeader(html.H5("Step 2 of 3 — Optional Features", className="mb-0 text-cyber")),
    dbc.CardBody([
        html.P(
            "All of these are optional. You can add them later from inside the dashboard.",
            className="text-muted mb-3"
        ),
        dbc.Accordion([
            dbc.AccordionItem([
                html.P(
                    "Lets IoTSentinel email you when an alert fires. "
                    "Gmail works best — use an App Password, not your main password.",
                    className="small text-muted mb-2"
                ),
                dbc.Label("Gmail address", html_for="setup-smtp-user", className="fw-semibold"),
                dbc.Input(id="setup-smtp-user", placeholder="you@gmail.com",
                          type="email", className="mb-2"),
                dbc.Label("App Password", html_for="setup-smtp-password", className="fw-semibold"),
                dbc.InputGroup([
                    dbc.Input(id="setup-smtp-password", type="password",
                              placeholder="16-character app password"),
                    dbc.InputGroupText(
                        html.A("Get App Password",
                               href=_VENDOR_LINKS["gmail_apppassword"],
                               target="_blank",
                               className="text-info text-decoration-none small")
                    ),
                ], className="mb-1"),
                dbc.Collapse(
                    html.Img(src="/assets/setup/gmail_apppassword.gif",
                             style={"maxWidth": "100%", "borderRadius": "8px"}),
                    id="setup-gmail-gif-collapse", is_open=False
                ),
                dbc.Button("Show me how", id="setup-gmail-gif-btn",
                           size="sm", color="link", className="p-0 mb-2"),
                html.Div(id="setup-smtp-feedback", className="small text-muted"),
            ], title="📧 Email Alerts"),

            dbc.AccordionItem([
                html.P(
                    "Powers the 'Explain in Plain English' button on each alert. "
                    "Free tier available — no credit card needed.",
                    className="small text-muted mb-2"
                ),
                _key_row("Groq API Key", "setup-groq-key",
                         "gsk_...", vendor_key="groq"),
                html.Div(id="setup-groq-feedback", className="small text-muted"),
            ], title="🤖 AI-Powered Explanations (Groq)"),

            dbc.AccordionItem([
                html.P(
                    "Checks IP addresses against the AbuseIPDB global blocklist "
                    "to give your alerts more context.",
                    className="small text-muted mb-2"
                ),
                _key_row("AbuseIPDB API Key", "setup-abuseipdb-key",
                         "Paste your key here", vendor_key="abuseipdb"),
                html.Div(id="setup-abuseipdb-feedback", className="small text-muted"),
            ], title="🌐 Threat Intelligence (AbuseIPDB)"),
        ], start_collapsed=True, always_open=True),
    ]),
], className="mb-3 setup-card")

_step_3 = dbc.Card([
    dbc.CardHeader(html.H5("Step 3 of 3 — Review & Launch", className="mb-0 text-cyber")),
    dbc.CardBody([
        html.P("Your configuration summary:", className="fw-semibold mb-2"),
        html.Div(id="setup-review-content"),
        html.Hr(),
        dbc.Alert(
            "IoTSentinel will start monitoring your network immediately after launch. "
            "Anomaly detection improves within the first 24 hours as it learns your "
            "normal traffic patterns.",
            color="info", className="small"
        ),
    ]),
], className="mb-3 setup-card")

# --------------------------------------------------------------------------
# Full wizard layout
# --------------------------------------------------------------------------

setup_wizard_layout = dbc.Container([
    dcc.Store(id="setup-step-store", data={"step": 1}),
    dcc.Store(id="setup-data-store", data={}),
    dcc.Location(id="setup-url", refresh=True),

    dbc.Row([
        dbc.Col([
            # Header
            html.Div([
                html.Img(src="/assets/logo.png",
                         style={"height": "60px",
                                "filter": "drop-shadow(0 0 20px rgba(102,126,234,0.7))"}),
                html.H3("IoTSentinel Setup", className="text-cyber mt-2 mb-0"),
                html.P("Let's get your network monitor running in under 2 minutes.",
                       className="text-muted small"),
            ], className="text-center mb-4"),

            # Progress bar
            dbc.Progress(id="setup-progress", value=33, color="info",
                         striped=True, animated=True,
                         className="mb-4", style={"height": "8px"}),

            # Step panels (visibility controlled by callbacks)
            html.Div(id="setup-step-1-container", children=_step_1),
            html.Div(id="setup-step-2-container", children=_step_2,
                     style={"display": "none"}),
            html.Div(id="setup-step-3-container", children=_step_3,
                     style={"display": "none"}),

            # Navigation buttons
            dbc.Row([
                dbc.Col(
                    dbc.Button("Back", id="setup-back-btn", color="secondary",
                               outline=True, className="w-100",
                               style={"display": "none"}),
                    width=4
                ),
                dbc.Col(
                    dbc.Button("Skip & Use Base Mode", id="setup-skip-btn",
                               color="link", size="sm", className="w-100 text-muted"),
                    width=4
                ),
                dbc.Col(
                    dbc.Button("Next →", id="setup-next-btn", color="primary",
                               className="w-100 cyber-button"),
                    width=4
                ),
            ], className="g-2 mt-2"),

            # Status output
            html.Div(id="setup-status", className="mt-3"),

        ], md=8, lg=6, className="mx-auto"),
    ], className="min-vh-100 align-items-center py-5"),
], fluid=True, className="setup-wizard-container")
