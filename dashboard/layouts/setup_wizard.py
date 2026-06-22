"""
IoTSentinel First-Run Setup Wizard
=====================================
Mirrors the login page shell: same login-outer-card glass card,
login-brand-panel (left) + login-form-panel (right).
"""
import secrets as _secrets

from dash import dcc, html
import dash_bootstrap_components as dbc

from utils.qr import make_qr_data_uri as _make_qr_data_uri
from utils import wifi_manager as _wifi


def _ntfy_default_topic():
    """Generate a random ntfy topic that is valid and easy to type."""
    return "iotsentinel-" + _secrets.token_hex(3)  # e.g. iotsentinel-a7f3c1

_VENDOR_LINKS = {
    "groq": "https://console.groq.com/keys",
    "abuseipdb": "https://www.abuseipdb.com/account/api",
    "gmail_apppassword": "https://myaccount.google.com/apppasswords",  # pragma: allowlist secret
}

_STEPS = [
    (1, "fa-wifi",            "WiFi & Admin"),
    (2, "fa-users",           "Usage Mode"),
    (3, "fa-puzzle-piece",    "Optional Features"),
    (4, "fa-globe",           "Remote Access"),
    (5, "fa-clipboard-check", "Review & Launch"),
    (6, "fa-circle-check",    "All Set"),
]

H = {"display": "none"}


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def _step_header(n):
    _, icon, name = _STEPS[n - 1]
    return html.Div([
        html.Small(f"Step {n} of 6", className="text-muted wizard-step-badge"),
        html.Div([
            html.I(className=f"fa {icon} login-header-icon"),
            html.H4(name, className="mb-0 login-header-title"),
        ], className="d-flex align-items-center"),
    ], className="mb-3")



def _key_row(label, field_id, vendor_key=None, hint=None):
    """API key input row with optional Get-my-key link."""
    children = [
        dbc.Label(label, html_for=field_id, className="small fw-semibold mb-1"),
        dbc.InputGroup([
            dbc.Input(id=field_id, placeholder="Paste your key here",
                      type="password", autocomplete="off",
                      className="login-form-input"),
            dbc.InputGroupText(
                html.A("Get key", href=_VENDOR_LINKS[vendor_key],
                       target="_blank", className="text-info text-decoration-none small")
            ) if vendor_key else None,
        ], className="mb-1"),
        html.P(hint, className="small text-muted mb-2") if hint else None,
    ]
    return html.Div([c for c in children if c is not None])


# --------------------------------------------------------------------------
# Step panels
# --------------------------------------------------------------------------

_step_1 = html.Div([
    _step_header(1),

    # WiFi section
    html.Div([
        html.Div([
            html.I(className="fa fa-wifi me-2 text-info"),
            html.Span("Connect to home WiFi", className="fw-semibold small"),
        ], className="d-flex align-items-center mb-2"),
        html.P(
            "If you're on the IoTSentinel-Setup hotspot, enter your home WiFi here. "
            "On a spare PC or virtual machine connected by Ethernet, skip these WiFi "
            "fields and just pick the interface to monitor below.",
            className="small text-muted mb-2"
        ),
        dbc.InputGroup([
            dbc.Select(id="setup-wifi-ssid", options=[], placeholder="Select network...",
                       className="mb-0"),
            dbc.Button("Scan", id="setup-wifi-scan-btn",
                       color="secondary", outline=True, size="sm", className="ms-1"),
        ], className="mb-2"),
        dbc.Input(id="setup-wifi-password", type="password",
                  placeholder="WiFi password (blank for open networks)",
                  autocomplete="off", className="mb-2 login-form-input"),
        dbc.Button("Connect to this WiFi", id="setup-wifi-connect-btn",
                   color="primary", outline=True, size="sm", className="mb-1"),
        html.Div(id="setup-wifi-feedback", className="small mt-1"),

        # Wi-Fi region — needed so the radio is legal/usable in the user's country
        # (governs channels and power). Defaults to the image's bootstrap country;
        # the user sets their own here so a single image works worldwide.
        dbc.Label("Your country (for Wi-Fi)", className="small fw-semibold mt-2 mb-1"),
        dbc.Select(
            id="setup-wifi-country",
            options=[{"label": name, "value": code} for code, name in _wifi.COUNTRY_OPTIONS],
            value=None,
            placeholder="Select your country…",
            className="mb-0",
        ),
        html.Small("Sets the correct Wi-Fi rules for where you live.",
                   className="text-muted"),
    ], className="wizard-section-box mb-3"),

    # Network details
    html.Div([
        html.I(className="fa fa-network-wired input-icon"),
        dbc.Input(id="setup-network-cidr", placeholder=" ", value="192.168.1.0/24",
                  className="form-control login-form-input"),
        html.Label("Local network range (CIDR)", htmlFor="setup-network-cidr"),
    ], className="floating-input-group mb-3"),

    dbc.Label("Network interface to monitor", className="small fw-semibold mb-1"),
    dbc.Select(id="setup-interface", options=[], value=None,
               placeholder="Detecting interfaces...", className="mb-3"),

    # Capture mode, passive (default, safe today) vs gateway/AP (full visibility).
    # Gateway is the recommended full-protection mode but needs a USB Wi-Fi adapter;
    # it is fully activated in a later step, so the default here stays passive.
    dbc.Label("Monitoring mode", className="small fw-semibold mb-1"),
    dbc.RadioItems(
        id="setup-capture-mode",
        options=[
            {"label": "Passive monitor, watches your existing Wi-Fi (no extra hardware)",
             "value": "passive"},
            {"label": "Gateway / Access Point, full per-device protection "
                      "(recommended; needs a USB Wi-Fi adapter)",
             "value": "gateway"},
        ],
        value="passive",
        className="mb-2",
    ),
    # Shown only when Gateway is selected (toggled by a callback). Starts hidden so
    # passive users, the plug-and-play majority, never see AP fields.
    html.Div([
        dbc.Alert([
            html.I(className="fa fa-usb me-2"),
            "Plug your USB Wi-Fi adapter into the Pi, then click Rescan. The built-in "
            "Wi-Fi stays your home connection.",
        ], color="info", className="py-2 small mb-2"),
        dbc.Label("USB Wi-Fi adapter (serves the IoT network)",
                  className="small fw-semibold mb-1"),
        dbc.InputGroup([
            dbc.Select(id="setup-ap-interface", options=[], value=None,
                       placeholder="Detecting adapters..."),
            dbc.Button("Rescan", id="setup-ap-rescan-btn", color="secondary",
                       outline=True, size="sm"),
        ], className="mb-2"),
        dbc.Input(id="setup-ap-ssid", placeholder="IoT network name (SSID)",
                  value="IoTSentinel", className="mb-2 login-form-input"),
        dbc.Input(id="setup-ap-password", type="password",
                  placeholder="IoT network password (min 8 characters)",
                  autocomplete="off", className="mb-2 login-form-input"),
        dbc.Label("IoT network band", className="small fw-semibold mb-1"),
        dbc.Select(
            id="setup-ap-band",
            options=[
                {"label": "2.4 GHz (best reach — most smart-home devices)", "value": "bg"},
                {"label": "5 GHz (faster — needs 5 GHz-capable devices + adapter)", "value": "a"},
            ],
            value="bg",
            className="mb-2",
        ),
        html.Small("Pick the USB Wi-Fi adapter (not your home Wi-Fi). Don't see it? Plug "
                   "it in and click Rescan. Your IoT devices join this network so "
                   "IoTSentinel sees and protects all their traffic. Your home Wi-Fi is "
                   "never changed.",
                   className="text-muted d-block"),
    ], id="setup-ap-fields", style={"display": "none"}),

    html.Hr(className="my-3"),

    # Admin account, username + password chosen by the user
    html.Div([
        html.I(className="fa fa-user input-icon"),
        dbc.Input(id="setup-admin-username", type="text", placeholder=" ",
                  value="admin", autocomplete="username",
                  className="form-control login-form-input"),
        html.Label("Admin username", htmlFor="setup-admin-username"),
    ], className="floating-input-group mb-3"),

    html.Div([
        html.I(className="fa fa-lock input-icon"),
        dbc.Input(id="setup-admin-password", type="password", placeholder=" ",
                  autocomplete="new-password",
                  className="form-control login-form-input"),
        html.Label("Admin password", htmlFor="setup-admin-password"),
    ], className="floating-input-group mb-3"),

    html.Div([
        html.I(className="fa fa-lock input-icon"),
        dbc.Input(id="setup-admin-password-confirm", type="password", placeholder=" ",
                  autocomplete="new-password",
                  className="form-control login-form-input"),
        html.Label("Confirm password", htmlFor="setup-admin-password-confirm"),
    ], className="floating-input-group mb-1"),

    html.P(
        "Min 8 chars, upper + lower + digit + special (e.g. @, !, #).",
        className="small text-muted mb-1"
    ),
    html.Div(id="setup-password-feedback", className="small text-danger mb-1"),
])


_step_2_tier = html.Div([
    _step_header(2),
    html.P("Choose the mode that fits. You can change it later in Settings.",
           className="text-muted small mb-3"),
    dbc.RadioItems(
        id="setup-tier-select",
        options=[
            {
                "label": html.Div([
                    html.Div([
                        html.I(className="fa fa-house me-2 text-info"),
                        html.Span("Household", className="fw-semibold"),
                    ], className="d-flex align-items-center"),
                    html.Small(
                        "Full home security: threat intelligence, AI alerts, email notifications. Free.",
                        className="text-muted d-block mt-1"
                    ),
                ], className="wizard-tier-option"),
                "value": "household",
            },
            {
                "label": html.Div([
                    html.Div([
                        html.I(className="fa fa-building me-2 text-info"),
                        html.Span("Small Business", className="fw-semibold"),
                    ], className="d-flex align-items-center"),
                    html.Small(
                        "Adds ticketing integrations, enterprise threat feeds, and compliance-ready logging.",
                        className="text-muted d-block mt-1"
                    ),
                ], className="wizard-tier-option"),
                "value": "business",
            },
        ],
        value="household",
        inputStyle={"marginRight": "10px"},
        labelStyle={"display": "flex", "alignItems": "flex-start", "marginBottom": "1rem"},
    ),

    html.Hr(className="my-3"),

    # Autonomous protection, disclosed up front (privacy/consent), not buried.
    html.Div([
        html.Div([
            html.I(className="fa fa-shield-halved me-2 text-info"),
            html.Span("Automatic threat blocking", className="fw-semibold small"),
        ], className="d-flex align-items-center mb-2"),
        dbc.Switch(
            id="setup-autoblock-toggle",
            label="Let IoTSentinel block a device automatically when it behaves like a threat",
            value=True,
            className="mb-1",
        ),
        html.P(
            "When on, the AI can cut off a device the moment it acts malicious, without "
            "waiting for you. When off, blocks wait for your approval. Enforcement also "
            "needs the optional router setup in the next step. Change this any time in Settings.",
            className="small text-muted mb-0",
        ),
    ], className="wizard-section-box mb-3"),

    # Alert sensitivity, how chatty notifications are.
    dbc.Label("Alert sensitivity", className="small fw-semibold mb-1"),
    dbc.RadioItems(
        id="setup-alert-sensitivity",
        options=[
            {"label": "Low - only the most important alerts", "value": "low"},
            {"label": "Medium - balanced (recommended)", "value": "medium"},
            {"label": "High - tell me about everything", "value": "high"},
        ],
        value="medium",
        className="small",
    ),
])


def _build_step_3():
    """Build the Step 3 panel. Called at import time so the ntfy topic QR is
    generated once per process start, each fresh first-run wizard session gets
    its own random topic."""
    _default_topic = _ntfy_default_topic()
    _ntfy_url      = f"https://ntfy.sh/{_default_topic}"
    _qr_src        = _make_qr_data_uri(_ntfy_url)

    return html.Div([
        _step_header(3),
        html.P("All optional. You can configure any of these later from the dashboard.",
               className="text-muted small mb-3"),

        dbc.Accordion([

            # ----------------------------------------------------------------
            # ntfy.sh, Phone push (zero-account, zero-config)
            # ----------------------------------------------------------------
            dbc.AccordionItem([
                html.P([
                    "Get instant phone alerts with no account needed. ",
                    html.Strong("ntfy.sh"),
                    " is open-source and free. Install the ",
                    html.A("ntfy app", href="https://ntfy.sh", target="_blank",
                           className="text-info"),
                    " and scan the QR code below, done.",
                ], className="small text-muted mb-3"),

                # Topic input + live QR code
                dbc.Row([
                    dbc.Col([
                        dbc.Label("Topic name", html_for="setup-ntfy-topic",
                                  className="small fw-semibold mb-1"),
                        dbc.Input(
                            id="setup-ntfy-topic",
                            value=_default_topic,
                            placeholder="e.g. iotsentinel-a7f3",
                            type="text",
                            className="mb-2 login-form-input",
                        ),
                        html.P([
                            "Subscribe at: ",
                            html.A(id="setup-ntfy-url-link",
                                   href=_ntfy_url,
                                   children=_ntfy_url,
                                   target="_blank",
                                   className="text-info small text-break"),
                        ], className="small mb-2"),
                        dbc.Alert([
                            html.I(className="fa fa-info-circle me-1"),
                            "The topic name is public, anyone who knows it can "
                            "subscribe. Keep it random (the default is fine).",
                        ], color="secondary", className="small py-2 px-3 mb-0"),
                    ], md=7),
                    dbc.Col([
                        html.Div([
                            html.Img(
                                id="setup-ntfy-qr",
                                src=_qr_src,
                                alt="Scan to subscribe",
                                style={"width": "160px", "height": "160px",
                                       "border": "1px solid var(--border-soft)",
                                       "borderRadius": "8px",
                                       "background": "#fff",
                                       "padding": "4px"},
                            ),
                            html.P("Scan to subscribe on your phone",
                                   className="small text-muted text-center mt-1 mb-0"),
                        ], className="text-center"),
                    ], md=5),
                ]),

                html.Div(id="setup-ntfy-feedback", className="small mt-2"),
            ], title="Phone Push (ntfy.sh) - No account needed"),

            # ----------------------------------------------------------------
            # Telegram Bot
            # ----------------------------------------------------------------
            dbc.AccordionItem([
                html.P([
                    "Send alerts to any Telegram chat or group. ",
                    "1. Create a bot with ",
                    html.A("@BotFather", href="https://t.me/botfather",
                           target="_blank", className="text-info"),
                    ", copy the token. 2. Start the bot and send /start. "
                    "3. Get your chat ID from ",
                    html.A("@userinfobot", href="https://t.me/userinfobot",
                           target="_blank", className="text-info"),
                    ".",
                ], className="small text-muted mb-3"),
                dbc.Label("Bot token", html_for="setup-telegram-token",
                          className="small fw-semibold mb-1"),
                dbc.Input(id="setup-telegram-token",
                          placeholder="123456:ABC-DEF...",
                          type="password", autocomplete="off",
                          className="mb-2 login-form-input"),
                dbc.Label("Chat ID", html_for="setup-telegram-chat",
                          className="small fw-semibold mb-1"),
                dbc.Input(id="setup-telegram-chat",
                          placeholder="e.g. -1001234567890",
                          type="text", autocomplete="off",
                          className="mb-2 login-form-input"),
                html.Div(id="setup-telegram-feedback", className="small text-muted"),
            ], title="Telegram Bot"),

            # ----------------------------------------------------------------
            # Discord Webhook
            # ----------------------------------------------------------------
            dbc.AccordionItem([
                html.P([
                    "Post alerts as rich embeds to a Discord channel. ",
                    "In your server: Settings > Integrations > Webhooks > New Webhook. "
                    "Copy the webhook URL and paste it below.",
                ], className="small text-muted mb-3"),
                dbc.Label("Webhook URL", html_for="setup-discord-webhook",
                          className="small fw-semibold mb-1"),
                dbc.Input(id="setup-discord-webhook",
                          placeholder="https://discord.com/api/webhooks/...",
                          type="password", autocomplete="off",
                          className="mb-2 login-form-input"),
                html.Div(id="setup-discord-feedback", className="small text-muted"),
            ], title="Discord Webhook"),

            # ----------------------------------------------------------------
            # Generic webhook
            # ----------------------------------------------------------------
            dbc.AccordionItem([
                html.P(
                    "POST a structured JSON payload to any HTTP endpoint. "
                    "Compatible with Home Assistant, automation platforms, "
                    "and any custom consumer.",
                    className="small text-muted mb-3"
                ),
                dbc.Label("Endpoint URL", html_for="setup-webhook-url",
                          className="small fw-semibold mb-1"),
                dbc.Input(id="setup-webhook-url",
                          placeholder="https://your-endpoint.example.com/hook",
                          type="url",
                          className="mb-2 login-form-input"),
                html.Div(id="setup-webhook-feedback", className="small text-muted"),
            ], title="Generic Webhook"),

            # ----------------------------------------------------------------
            # Email / SMTP (kept as-is, now the fourth option)
            # ----------------------------------------------------------------
            dbc.AccordionItem([
                html.P(
                    "Receive alert emails via Gmail. Use an App Password, "
                    "not your main account password.",
                    className="small text-muted mb-3"
                ),
                dbc.Label("Gmail address", html_for="setup-smtp-user",
                          className="small fw-semibold mb-1"),
                dbc.Input(id="setup-smtp-user", placeholder="you@gmail.com",
                          type="email", className="mb-3 login-form-input"),
                _key_row("App Password", "setup-smtp-password", vendor_key="gmail_apppassword"),
                html.Div(id="setup-smtp-feedback", className="small text-muted"),
            ], title="Email (Gmail / SMTP)"),

            # ----------------------------------------------------------------
            # AI Explanations (Groq), unchanged
            # ----------------------------------------------------------------
            dbc.AccordionItem([
                html.P(
                    "Powers the plain-English explanation on each alert. "
                    "Free tier available. No credit card needed.",
                    className="small text-muted mb-3"
                ),
                _key_row("Groq API Key", "setup-groq-key", vendor_key="groq"),
                html.Div(id="setup-groq-feedback", className="small text-muted"),
            ], title="AI Explanations (Groq)"),

            # ----------------------------------------------------------------
            # Local AI (Ollama) + privacy preference
            # ----------------------------------------------------------------
            dbc.AccordionItem([
                html.P(
                    "Run AI explanations fully on this device with Ollama. "
                    "Nothing leaves your network. Optional, install from ollama.com.",
                    className="small text-muted mb-3"
                ),
                dbc.Button(
                    [html.I(className="fa fa-magnifying-glass me-2"), "Detect local AI"],
                    id="setup-ollama-detect-btn", outline=True, color="secondary",
                    size="sm", className="mb-2", n_clicks=0,
                ),
                html.Div(id="setup-ollama-feedback", className="small text-muted mb-3"),
                dbc.Label("How should AI answers be generated?",
                          className="small fw-semibold mb-1"),
                dbc.RadioItems(
                    id="setup-ai-privacy-choice",
                    options=[
                        {"label": "Cloud first - best quality, free Groq tier", "value": "cloud"},
                        {"label": "Local only first - privacy mode, nothing leaves your network", "value": "local"},
                    ],
                    value="cloud",
                    className="small",
                ),
            ], title="Local AI (Ollama)"),

            # ----------------------------------------------------------------
            # Threat Intelligence (AbuseIPDB), unchanged
            # ----------------------------------------------------------------
            dbc.AccordionItem([
                html.P(
                    "Checks IP addresses against the AbuseIPDB global blocklist "
                    "to add context to your alerts.",
                    className="small text-muted mb-3"
                ),
                _key_row("AbuseIPDB API Key", "setup-abuseipdb-key", vendor_key="abuseipdb"),
                html.Div(id="setup-abuseipdb-feedback", className="small text-muted"),
            ], title="Threat Intelligence (AbuseIPDB)"),

            # ----------------------------------------------------------------
            # Firewall enforcement (advanced), lets auto-block actually act
            # ----------------------------------------------------------------
            dbc.AccordionItem([
                html.P([
                    "Advanced. IoTSentinel can enforce blocks by talking to your router "
                    "over SSH. Without this, automatic blocking only logs its decisions. ",
                    html.Strong("Leave this off unless you know your router's SSH details."),
                ], className="small text-muted mb-3"),
                dbc.Switch(
                    id="setup-firewall-enable",
                    label="Enable firewall enforcement via my router",
                    value=False,
                    className="mb-2",
                ),
                dbc.Label("Router IP", html_for="setup-firewall-router-ip",
                          className="small fw-semibold mb-1"),
                dbc.Input(id="setup-firewall-router-ip", value="192.168.1.1",
                          type="text", className="mb-2 login-form-input"),
                dbc.Label("Router SSH user", html_for="setup-firewall-router-user",
                          className="small fw-semibold mb-1"),
                dbc.Input(id="setup-firewall-router-user", value="root",
                          type="text", className="mb-2 login-form-input"),
                dbc.Label("SSH private key path", html_for="setup-firewall-key-path",
                          className="small fw-semibold mb-1"),
                dbc.Input(id="setup-firewall-key-path", value="~/.ssh/id_rsa",
                          type="text", className="mb-2 login-form-input"),
                dbc.Button(
                    [html.I(className="fa fa-plug me-2"), "Test connection"],
                    id="setup-firewall-test-btn", outline=True, color="secondary",
                    size="sm", className="mb-2", n_clicks=0,
                ),
                html.Div(id="setup-firewall-feedback", className="small text-muted mb-1"),
                html.P(
                    "The key must already be authorised on the router. You can set this up "
                    "later from Settings if you're not sure.",
                    className="small text-muted mb-0"),
            ], title="Firewall enforcement (advanced)"),

        ], start_collapsed=True, always_open=True),
    ])


_step_3_optional = _build_step_3()


_step_4_remote = html.Div([
    _step_header(4),
    html.P(
        "Enable this to get a secure link that lets you open the dashboard "
        "from any device, anywhere, even when you're not home.",
        className="text-muted small mb-3"
    ),
    dbc.Switch(
        id="setup-tailscale-toggle",
        label="Enable remote access (free, powered by Tailscale)",
        value=False,
        className="mb-3",
    ),
    html.Div(id="setup-tailscale-panel", children=[
        dbc.Alert([
            html.Strong("How it works: "),
            "Click the button, sign in with Google, GitHub, or email. "
            "Your dashboard gets a permanent private URL like ",
            html.Code("https://iotsentinel.yourtailnet.ts.net"),
            ", accessible from any network.",
        ], color=None, className="glass-alert-info small mb-3"),
        dbc.Button(
            [html.I(className="fa fa-link me-2"), "Start Tailscale setup"],
            id="setup-tailscale-start-btn",
            color="primary", outline=True, className="mb-3",
        ),
        html.Div(id="setup-tailscale-status", className="mt-2"),
        dcc.Interval(id="setup-tailscale-interval", interval=3000,
                     n_intervals=0, disabled=True),
        dcc.Store(id="setup-tailscale-url-store", data=None),
    ], style={"display": "none"}),
])


_step_5_review = html.Div([
    _step_header(5),
    html.P("Your configuration summary:", className="small fw-semibold mb-2"),
    html.Div(id="setup-review-content"),
    html.Hr(className="my-3"),
    dbc.Alert(
        "IoTSentinel will start monitoring your network immediately after launch. "
        "Anomaly detection improves within the first 24 hours as it learns your normal traffic.",
        color=None, className="glass-alert-info small"
    ),
])


_step_6_final = html.Div([
    _step_header(6),
    dbc.Alert([
        html.I(className="fa fa-circle-check me-2"),
        html.Strong("Login credentials: "),
        "Username: ", html.Code(id="setup-final-username", className="mx-1"),
        " and the password you just set.",
    ], color="success", className="mb-3 small"),
    html.Div(id="setup-public-url-display", className="mb-3"),
    html.Div(id="setup-reachable-display", className="mb-3"),
    html.P("What would you like to do next?", className="small text-muted mb-3"),
    dbc.Row([
        dbc.Col(html.Div([
            html.I(className="fa fa-home fa-2x text-success mb-2 d-block text-center"),
            html.Div("Go to Dashboard", className="fw-semibold small text-center mb-1"),
            html.P("Start monitoring your network now.", className="small text-muted text-center mb-3"),
            dbc.Button("Open Dashboard", id="setup-done-btn", color="success",
                       className="w-100 cyber-button-modern mt-auto"),
        ], className="wizard-finale-card p-3"), md=4, className="mb-3"),
        dbc.Col(html.Div([
            html.I(className="fa fa-user-shield fa-2x text-primary mb-2 d-block text-center"),
            html.Div("Secure your account", className="fw-semibold small text-center mb-1"),
            html.P("After you log in, add two-factor authentication or a passkey "
                   "from Settings → Security for a stronger login.",
                   className="small text-muted text-center mb-3"),
            html.A("Open Dashboard", href="/",
                   className="btn btn-outline-primary btn-sm w-100 d-block text-center mt-auto"),
        ], className="wizard-finale-card p-3"), md=4, className="mb-3"),
        dbc.Col(html.Div([
            html.I(className="fa fa-book-open fa-2x text-info mb-2 d-block text-center"),
            html.Div("Read the guide", className="fw-semibold small text-center mb-1"),
            html.P("Quick-start walkthroughs and tips.", className="small text-muted text-center mb-3"),
            html.A("Open guide", href="https://github.com/ritiksah141/iotsentinel#getting-started",
                   target="_blank",
                   className="btn btn-outline-info btn-sm w-100 d-block text-center mt-auto"),
        ], className="wizard-finale-card p-3"), md=4, className="mb-3"),
    ]),
])


# --------------------------------------------------------------------------
# Left panel, static step roadmap
# --------------------------------------------------------------------------

_left_panel = html.Div([

    html.Div([
        html.Img(src="/assets/logo.png", className="setup-logo"),
    ], className="text-center mb-3"),

    html.H2("IoTSentinel Setup", className="gradient-text text-center login-brand-title mb-1"),
    html.P("Network security in under 2 minutes.",
           className="text-center login-brand-subtitle mb-4"),

    html.Div([
        html.Div([
            html.Div([
                html.Div(str(n), className="wizard-step-num-circle"),
                html.Span(name, className="wizard-step-name"),
            ], className="wizard-step-row"),
            html.Div(className="wizard-step-connector") if n < 6 else None,
        ]) for n, _icon, name in _STEPS
    ], className="wizard-step-list"),

    html.P("All settings can be changed after login.",
           className="text-muted small mt-auto pt-4"),

], className="login-brand-panel")


# --------------------------------------------------------------------------
# Full wizard layout
# --------------------------------------------------------------------------

setup_wizard_layout = dbc.Container([
    dcc.Store(id="setup-step-store", data={"step": 1}),
    dcc.Store(id="setup-data-store", data={}),
    dcc.Location(id="setup-url", refresh=True),

    html.Div([
        html.Div([

            _left_panel,

            # Right panel
            html.Div([

                dbc.Progress(id="setup-progress", value=17,
                             className="wizard-progress mb-4"),

                html.Div(id="setup-step-1-container", children=_step_1),
                html.Div(id="setup-step-2-container", children=_step_2_tier, style=H),
                html.Div(id="setup-step-3-container", children=_step_3_optional, style=H),
                html.Div(id="setup-step-4-container", children=_step_4_remote, style=H),
                html.Div(id="setup-step-5-container", children=_step_5_review, style=H),
                html.Div(id="setup-step-6-container", children=_step_6_final, style=H),

                dbc.Row([
                    dbc.Col(
                        dbc.Button("Back", id="setup-back-btn", color="secondary",
                                   outline=True, className="w-100",
                                   style={"display": "none"}),
                        xs=12, sm=4
                    ),
                    dbc.Col(
                        dbc.Button("Skip Setup", id="setup-skip-btn",
                                   color="link", size="sm",
                                   className="w-100 text-muted text-decoration-none",
                                   style={"textDecoration": "none"}),
                        xs=12, sm=4
                    ),
                    dbc.Col(
                        dbc.Button("Next", id="setup-next-btn", color="primary",
                                   className="w-100 cyber-button-modern"),
                        xs=12, sm=4
                    ),
                ], className="g-2 mt-2"),

                html.Div(id="setup-status", className="mt-3"),

            ], className="login-form-panel"),

        ], className="login-outer-card wizard-outer-card"),
    ], className="login-page-center"),

], fluid=True, className="login-page-bg")
