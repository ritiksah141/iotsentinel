"""
Setup Wizard Callbacks
======================
Handles step navigation, optional API-key validation, and final .env write
for the first-run setup wizard (/setup route).
"""
import json as _json
import logging
import os
import re
import secrets
import shutil
import subprocess
import threading
from pathlib import Path

import dash
import psutil
import requests
from dash import (Input, Output, State, callback_context, html)
import dash_bootstrap_components as dbc

from dashboard.shared import config, db_manager, auth_manager

logger = logging.getLogger(__name__)

# Module-level state for Tailscale setup (shared across callbacks)
_ts_state = {'url': None, 'connected': False, 'public_url': None, 'running': False}
_ts_lock = threading.Lock()

# Guard so the deferred final-step Wi-Fi join (apply_wifi_on_finish) runs at most once
# per process — the join drops the hotspot the request came in on, so the reply is
# usually lost and a retry would only thrash a wlan0 that is already a client.
_wifi_join_done = False


def _tailscale_available() -> bool:
    return shutil.which("tailscale") is not None


def _tailscale_up_worker():
    """Run 'tailscale up' in background; capture the login URL from stdout."""
    with _ts_lock:
        _ts_state.update({'url': None, 'connected': False, 'public_url': None, 'running': True})
    try:
        proc = subprocess.Popen(
            ['tailscale', 'up', '--accept-routes'],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
        )
        for line in proc.stdout:
            m = re.search(r'https://login\.tailscale\.com/\S+', line)
            if m:
                with _ts_lock:
                    _ts_state['url'] = m.group(0)
                break
        proc.wait()
    except Exception as exc:
        logger.warning(f"Tailscale up worker error: {exc}")
    finally:
        with _ts_lock:
            _ts_state['running'] = False


def _check_tailscale_connected() -> tuple[bool, str | None]:
    """Return (is_connected, public_url_or_None) by parsing tailscale status --json."""
    try:
        result = subprocess.run(
            ['tailscale', 'status', '--json'],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode != 0:
            return False, None
        data = _json.loads(result.stdout)
        if data.get('BackendState') == 'Running':
            dns_name = data.get('Self', {}).get('DNSName', '').rstrip('.')
            if dns_name:
                return True, f"https://{dns_name}"
    except Exception:
        pass
    return False, None


def _enable_tailscale_funnel(port: int = 8050) -> bool:
    """Enable Tailscale Funnel for the given port. Returns True on success."""
    try:
        result = subprocess.run(
            ['tailscale', 'funnel', str(port)],
            capture_output=True, text=True, timeout=10
        )
        return result.returncode == 0
    except Exception:
        return False

_ENV_PATH = Path(__file__).parent.parent.parent / '.env'

_PROG = {1: 17, 2: 33, 3: 50, 4: 67, 5: 83, 6: 100}


def _navigate_steps_logic(
    triggered_id, step,
    admin_username, password, password_confirm,
    cidr, interface,
    smtp_user, smtp_password, groq_key, abuseipdb_key,
    tier, public_url,
    ntfy_topic=None, telegram_token=None, telegram_chat=None,
    discord_webhook=None, webhook_url=None,
    ai_privacy_choice=None,
    auto_block=None, alert_sensitivity=None,
    firewall_enable=None, firewall_router_ip=None,
    firewall_router_user=None, firewall_key_path=None,
    capture_mode=None, ap_ssid=None, ap_password=None, ap_interface=None, ap_band=None,
):
    """Pure navigation logic for the 6-step wizard; no Dash context dependency.

    Returns the same 14-element tuple the navigate_steps callback outputs.
    """
    S = {"display": "block"}
    H = {"display": "none"}

    def _show(*visible):
        return tuple(S if i in visible else H for i in range(1, 6))

    def _ret(new_step, visible, back_vis, next_lbl, next_col,
             review=dash.no_update, status=dash.no_update,
             skip_style=dash.no_update, final_username=dash.no_update):
        c1, c2, c3, c4, c5 = _show(*visible)
        # Hide Skip button on Step 1 — account creation is mandatory
        _skip = H if new_step == 1 else S
        return (
            {"step": new_step}, c1, c2, c3, c4, c5,
            S if back_vis else H,
            next_lbl, next_col, _PROG.get(new_step, 100),
            review, status,
            _skip, final_username,
        )

    _clean_username = (admin_username or "admin").strip() or "admin"

    if triggered_id == "setup-skip-btn":
        # Skip is only reachable from steps 2-5 (hidden on step 1).
        # The admin was already created when step 1 was completed.
        _save_config(cidr, interface, None, None, None, None, "household", None,
                     None, None, None, None, None,
                     capture_mode=capture_mode, ap_ssid=ap_ssid, ap_password=ap_password,
                     ap_interface=ap_interface, ap_band=ap_band)
        return _ret(
            6, (), False, "Next →", "primary",
            _build_review(cidr, interface, None, None, None, "household", None,
                          None, None, None, None, None),
            "", S, _clean_username,
        )

    if triggered_id == "setup-next-btn":
        if step == 1:
            _clean_username = (admin_username or "admin").strip() or "admin"
            if not password or not auth_manager.is_password_strong_enough(password):
                return _ret(1, (1,), False, "Next →", "primary", status=dbc.Alert(
                    "Password must be at least 8 characters and include upper, lower, "
                    "a digit, and a special character (e.g. @, !, #).",
                    color="danger", dismissable=True))
            if password != password_confirm:
                return _ret(1, (1,), False, "Next →", "primary", status=dbc.Alert(
                    "Passwords do not match.", color="danger", dismissable=True))
            # Create the admin now — before any other wizard step so Skip is safe
            ok = auth_manager.create_admin(_clean_username, password)
            if not ok:
                # Username already exists (re-run scenario) — update the hash
                import bcrypt as _bcrypt
                pw_hash = _bcrypt.hashpw(
                    password.encode("utf-8"), _bcrypt.gensalt()
                ).decode("utf-8")
                try:
                    cur = db_manager.conn.cursor()
                    cur.execute(
                        "UPDATE users SET password_hash=?, must_change_password=0, "
                        "email_verified=1 WHERE username=? AND role='admin'",
                        (pw_hash, _clean_username),
                    )
                    db_manager.conn.commit()
                except Exception as _e:
                    return _ret(1, (1,), False, "Next →", "primary", status=dbc.Alert(
                        f"Could not save admin account: {_e}", color="danger", dismissable=True))
            return _ret(2, (2,), True, "Next →", "primary", skip_style=S,
                        final_username=_clean_username)

        elif step == 2:
            return _ret(3, (3,), True, "Next →", "primary")

        elif step == 3:
            return _ret(4, (4,), True, "Next →", "primary")

        elif step == 4:
            return _ret(
                5, (5,), True, "Launch IoTSentinel →", "success",
                review=_build_review(
                    cidr, interface, smtp_user, groq_key, abuseipdb_key,
                    tier or "household", public_url,
                    ntfy_topic, telegram_token, telegram_chat,
                    discord_webhook, webhook_url,
                    ai_privacy_choice=ai_privacy_choice,
                    auto_block=auto_block, alert_sensitivity=alert_sensitivity,
                    firewall_enable=firewall_enable,
                ),
            )

        elif step == 5:
            success = _save_config(
                cidr, interface,
                smtp_user, smtp_password, groq_key, abuseipdb_key,
                tier or "household", public_url,
                ntfy_topic, telegram_token, telegram_chat,
                discord_webhook, webhook_url,
                ai_privacy_choice=ai_privacy_choice,
                auto_block=auto_block, alert_sensitivity=alert_sensitivity,
                firewall_enable=firewall_enable, firewall_router_ip=firewall_router_ip,
                firewall_router_user=firewall_router_user, firewall_key_path=firewall_key_path,
                capture_mode=capture_mode, ap_ssid=ap_ssid, ap_password=ap_password,
                ap_interface=ap_interface, ap_band=ap_band,
            )
            if success:
                return _ret(6, (), False, "Next →", "primary", status="",
                            final_username=_clean_username)
            return _ret(5, (5,), True, "Launch IoTSentinel →", "success",
                        status=dbc.Alert("Setup failed. Check the logs.", color="danger"))

    if triggered_id == "setup-back-btn":
        back_map = {2: (1, (1,), False), 3: (2, (2,), True),
                    4: (3, (3,), True), 5: (4, (4,), True)}
        if step in back_map:
            ns, vis, bv = back_map[step]
            lbl = "Launch IoTSentinel →" if ns == 5 else "Next →"
            col = "success" if ns == 5 else "primary"
            # Hide Skip on step 1, show on all others
            skip = H if ns == 1 else S
            return _ret(ns, vis, bv, lbl, col, skip_style=skip)

    raise dash.exceptions.PreventUpdate


def _validate_groq(api_key: str) -> tuple[bool, str]:
    """Ping Groq models endpoint to confirm key is valid."""
    if not api_key or len(api_key) < 20:
        return False, "Key looks too short. Check you copied all characters."
    try:
        r = requests.get(
            "https://api.groq.com/openai/v1/models",
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=5,
        )
        if r.status_code == 200:
            return True, "✓ Key verified!"
        return False, f"That key didn't work (status {r.status_code}). Check it and try again."
    except Exception:
        return False, "Could not reach Groq. Check your internet connection."


def _detect_ollama(url: str = "http://localhost:11434/api/tags",
                   expected_model: str = "gemma2:2b") -> tuple[bool, str]:
    """Probe the local Ollama server and report installed models."""
    try:
        r = requests.get(url, timeout=2)
        if r.status_code != 200:
            return False, f"Ollama responded with status {r.status_code}. Try restarting it."
        models = [m.get("name", "") for m in r.json().get("models", [])]
        if not models:
            return True, ("✓ Ollama is running but has no models yet. "
                          f"Run: ollama pull {expected_model}")
        names = ", ".join(models[:5])
        if any(m.startswith(expected_model.split(":")[0]) for m in models):
            return True, f"✓ Local AI ready! Models installed: {names}"
        return True, (f"✓ Ollama is running with: {names}. "
                      f"For best results on a Pi, run: ollama pull {expected_model}")
    except Exception:
        return False, ("Ollama not detected. Install it from ollama.com to enable "
                       "on-device AI. Optional - cloud AI works without it.")


# WiFi/reachability helpers live in utils.wifi_manager (shared with the post-setup
# "Change WiFi" control and the connectivity-recovery watchdog). Thin wrappers keep
# the existing wizard call sites and message wording stable.
from utils import wifi_manager


def _nmcli_available() -> bool:
    return wifi_manager.nmcli_available()


def _scan_wifi_networks() -> list[dict]:
    """Return a list of {label, value} dicts for visible SSIDs."""
    return wifi_manager.scan_wifi_networks()


def _connect_wifi(ssid: str, password: str) -> tuple[bool, str]:
    """Connect to a WiFi network using nmcli. Returns (success, message)."""
    ok, msg = wifi_manager.connect_wifi(ssid, password)
    if ok:
        # First-run wizard sends the user back to the /setup route to continue.
        msg = msg.replace(
            f"reopen http://{wifi_manager.DEFAULT_MDNS_HOST}:{wifi_manager.DASHBOARD_PORT}.",
            f"continue at http://{wifi_manager.DEFAULT_MDNS_HOST}:{wifi_manager.DASHBOARD_PORT}/setup.",
        ).replace(
            f"reopen http://{wifi_manager.DEFAULT_MDNS_HOST}:{wifi_manager.DASHBOARD_PORT} to continue.",
            f"open http://{wifi_manager.DEFAULT_MDNS_HOST}:{wifi_manager.DASHBOARD_PORT}/setup to continue.",
        )
    return ok, msg


def _do_wifi_join(ssid, password, country):
    """Perform the final-step (deferred) Wi-Fi join. Returns (ok, msg), or None when
    there is nothing to do (no SSID chosen, or nmcli unavailable, e.g. an Ethernet
    setup). Applies the Wi-Fi region first so the channels are legal. Kept module-level
    so it is unit-testable without driving the Dash callback context."""
    if not ssid or not wifi_manager.nmcli_available():
        return None
    if country:
        try:
            config.update("network", "wifi_country", country)
            wifi_manager.set_country(country)
        except Exception as e:
            logger.warning("Wi-Fi country apply failed: %s", e)
    ok, msg = _connect_wifi(ssid, password or "")
    if ok:
        # Now that wlan0 is on the home LAN (not the 10.42.0.1 hotspot), bounce the
        # backend so its one-shot subnet self-heal re-runs against the real network.
        # Without this, discovery keeps scanning the placeholder subnet until the next
        # periodic ARP cycle. Best-effort; `sudo -n` never blocks on a password prompt.
        try:
            _unit = "/etc/systemd/system/iotsentinel-backend.service"
            if os.path.exists(_unit):
                subprocess.run(["sudo", "-n", "systemctl", "restart", "iotsentinel-backend"],
                               check=False, capture_output=True, timeout=15)
        except Exception as e:
            logger.warning(f"Could not restart backend after Wi-Fi join: {e}")
    return ok, msg


def _test_router_ssh(router_ip: str, router_user: str, key_path: str) -> tuple[bool, str]:
    """Attempt an SSH connection to the router with the given credentials so the
    user can confirm firewall enforcement will work before relying on it."""
    if not router_ip or not router_user or not key_path:
        return False, "Fill in router IP, user, and key path first."
    try:
        import paramiko
    except ImportError:
        return False, "SSH library not available on this device."
    client = None
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        pkey = paramiko.RSAKey.from_private_key_file(os.path.expanduser(key_path))
        client.connect(router_ip, username=router_user, pkey=pkey, timeout=10)
        return True, f"✓ Connected to {router_ip}. Firewall enforcement will work."
    except FileNotFoundError:
        return False, f"Key file not found: {key_path}"
    except Exception as e:
        return False, f"Could not connect: {e}"
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass


def _validate_abuseipdb(api_key: str) -> tuple[bool, str]:
    """Ping AbuseIPDB check endpoint with a known safe IP."""
    if not api_key or len(api_key) < 20:
        return False, "Key looks too short. Check you copied all characters."
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": "1.1.1.1", "maxAgeInDays": 90},
            headers={"Key": api_key, "Accept": "application/json"},
            timeout=5,
        )
        if r.status_code == 200:
            return True, "✓ Key verified!"
        return False, f"That key didn't work (status {r.status_code}). Check it and try again."
    except Exception:
        return False, "Could not reach AbuseIPDB. Check your internet connection."


def register(app):
    """Register all setup wizard callbacks."""

    # ------------------------------------------------------------------
    # WiFi network scan
    # ------------------------------------------------------------------
    @app.callback(
        Output("setup-wifi-ssid", "options"),
        Input("setup-wifi-scan-btn", "n_clicks"),
        prevent_initial_call=True,
    )
    def scan_wifi_networks(_n):
        return _scan_wifi_networks()

    # ------------------------------------------------------------------
    # WiFi connect
    # ------------------------------------------------------------------
    @app.callback(
        Output("setup-wifi-feedback", "children"),
        Input("setup-wifi-connect-btn", "n_clicks"),
        State("setup-wifi-ssid", "value"),
        State("setup-wifi-password", "value"),
        State("setup-wifi-country", "value"),
        prevent_initial_call=True,
    )
    def connect_to_wifi(_n, ssid, password, country):
        # Deferred-connect model: a single-radio Pi cannot host the IoTSentinel-Setup
        # hotspot AND be a client on home Wi-Fi at once, so connecting *now* would drop
        # the very session the user is in (the dead "Next" button on the rc4/rc5 image).
        # Instead we only RECORD the choice here — applying the Wi-Fi region is safe and
        # makes the channels legal/usable — and the actual join + hotspot teardown happen
        # on the final step (see apply_wifi_on_finish), after the hand-off screen renders.
        if country:
            try:
                config.update("network", "wifi_country", country)
                wifi_manager.set_country(country)
            except Exception as e:
                logger.warning("Wi-Fi country apply failed: %s", e)
        if not ssid:
            return html.Span("Select a network first.", className="text-warning")
        return html.Span(
            f"Saved. Your Pi will join “{ssid}” when you finish setup, then the "
            "setup hotspot closes and the dashboard moves to your home network.",
            className="text-success",
        )

    # ------------------------------------------------------------------
    # Deferred Wi-Fi join — the final-step half of the record-now/join-later flow.
    # Arming the interval only on Step 6 lets the browser paint the hand-off screen
    # before wlan0 leaves the hotspot (otherwise the user never sees the "switch
    # networks" instructions because the connection drops first).
    # ------------------------------------------------------------------
    @app.callback(
        Output("setup-wifi-apply-interval", "disabled"),
        Input("setup-step-store", "data"),
        prevent_initial_call=True,
    )
    def arm_wifi_apply(step_data):
        return (step_data or {}).get("step") != 6

    @app.callback(
        Output("setup-wifi-handoff-status", "children"),
        Input("setup-wifi-apply-interval", "n_intervals"),
        State("setup-wifi-ssid", "value"),
        State("setup-wifi-password", "value"),
        State("setup-wifi-country", "value"),
        prevent_initial_call=True,
    )
    def apply_wifi_on_finish(_n, ssid, password, country):
        # Perform the Wi-Fi join deferred from Step 1. On a single-radio Pi this tears
        # down the setup hotspot, so the reply below is usually lost — that's expected;
        # the hand-off alert already told the user to switch networks. Runs once.
        global _wifi_join_done
        if _wifi_join_done:
            raise dash.exceptions.PreventUpdate
        result = _do_wifi_join(ssid, password, country)
        if result is None:
            raise dash.exceptions.PreventUpdate
        _wifi_join_done = True
        ok, msg = result
        return html.Span(msg, className="text-success" if ok else "text-danger")

    # ------------------------------------------------------------------
    # Post-setup "Change WiFi" (Settings → Network). Lets a headless Pi move to
    # a new network after the wizard, without re-flashing. Reuses wifi_manager.
    # ------------------------------------------------------------------
    @app.callback(
        Output("settings-wifi-current", "children"),
        Output("settings-wifi-ssid", "options"),
        Output("settings-reachable", "children"),
        Input("quick-settings-modal", "is_open"),
        Input("settings-wifi-scan-btn", "n_clicks"),
        prevent_initial_call=True,
    )
    def settings_wifi_refresh(is_open, _scan_clicks):
        triggered = callback_context.triggered_id
        # Ignore the modal-close event; only act on open or an explicit Scan.
        if triggered == "quick-settings-modal" and not is_open:
            raise dash.exceptions.PreventUpdate

        # "How to reach this device" — always useful, even without nmcli.
        addr = wifi_manager.get_reachable_addresses()
        reach = [html.I(className="fa fa-location-dot me-1"),
                 "Reach this dashboard at ",
                 html.Code(f"http://{addr['mdns']}:{addr['port']}")]
        if addr["ip"]:
            reach += [" or ", html.Code(f"http://{addr['ip']}:{addr['port']}")]
        if addr.get("remote"):
            reach += [html.Br(),
                      html.I(className="fa fa-globe me-1"),
                      "From anywhere (remote access): ",
                      html.A(addr["remote"], href=addr["remote"], target="_blank")]

        if not wifi_manager.nmcli_available():
            return (
                html.Span([html.I(className="fa fa-circle-info me-1"),
                           "WiFi switching isn't available on this host."]),
                [],
                reach,
            )
        current = wifi_manager.current_wifi()
        if current:
            current_txt = html.Span(
                [html.I(className="fa fa-circle-check text-success me-1"),
                 "Connected to ", html.Strong(current), "."])
        else:
            current_txt = html.Span(
                [html.I(className="fa fa-circle-exclamation text-warning me-1"),
                 "Not connected to any WiFi network."])
        # Rescanning is slow (~15s), so only do it on an explicit Scan click; on a
        # plain modal-open just refresh the current-network line.
        if triggered == "settings-wifi-scan-btn":
            options = wifi_manager.scan_wifi_networks()
            if not options:
                # Empty result looks like a broken button — tell the user why and
                # what to do (common while wlan0 is still hosting the setup AP).
                current_txt = html.Div([
                    current_txt,
                    html.Div([
                        html.I(className="fa fa-circle-info me-1"),
                        "No networks found. Wait a moment and tap Scan again.",
                    ], className="text-warning mt-1"),
                ])
        else:
            options = dash.no_update
        return current_txt, options, reach

    @app.callback(
        Output("settings-wifi-feedback", "children"),
        Input("settings-wifi-connect-btn", "n_clicks"),
        State("settings-wifi-ssid", "value"),
        State("settings-wifi-password", "value"),
        prevent_initial_call=True,
    )
    def settings_wifi_connect(_n, ssid, password):
        if not ssid:
            return html.Span("Select a network first.", className="text-warning")
        ok, msg = wifi_manager.connect_wifi(ssid, password or "")
        icon = "fa-circle-check text-success" if ok else "fa-circle-exclamation text-danger"
        color = "text-success" if ok else "text-danger"
        return html.Span([html.I(className=f"fa {icon} me-1"), msg], className=color)

    # ------------------------------------------------------------------
    # Show the access-point fields only when Gateway mode is selected, so the
    # passive (plug-and-play) majority never see USB-adapter settings.
    # ------------------------------------------------------------------
    @app.callback(
        Output("setup-ap-fields", "style"),
        Input("setup-capture-mode", "value"),
    )
    def _toggle_ap_fields(mode):
        return {"display": "block"} if mode == "gateway" else {"display": "none"}

    # ------------------------------------------------------------------
    # Populate network interface dropdown from psutil
    # ------------------------------------------------------------------
    @app.callback(
        Output("setup-interface", "options"),
        Output("setup-interface", "value"),
        Output("setup-network-cidr", "value"),
        Output("setup-ap-interface", "options"),
        Output("setup-ap-interface", "value"),
        Input("setup-step-store", "data"),
        Input("setup-ap-rescan-btn", "n_clicks"),
    )
    def populate_interface_options(_step_data, _rescan):
        import ipaddress
        import socket

        def _rank(name):
            n = name.lower()
            if any(x in n for x in ('wlan', 'wifi', 'wi-fi', 'wireless', 'en0', 'en1')):
                return 0
            if any(x in n for x in ('eth', 'en', 'lan')):
                return 1
            if any(x in n for x in ('lo', 'loop')):
                return 3
            return 2

        def _guess_cidr(iface):
            """Return CIDR string for the first real IPv4 address on the interface, or
            None. Skips loopback, link-local, and the 10.42.0.x setup-hotspot range —
            the wizard now runs entirely on that hotspot, so without these skips it
            would pre-fill (and the Step 5 review would show) the wrong subnet. The
            orchestrator self-heals the real LAN once on home Wi-Fi anyway."""
            try:
                for addr in psutil.net_if_addrs().get(iface, []):
                    if addr.family != socket.AF_INET:
                        continue
                    if addr.address.startswith(('127.', '169.254.', '10.42.')):
                        continue
                    net = ipaddress.IPv4Network(
                        f"{addr.address}/{addr.netmask}", strict=False
                    )
                    return str(net)
            except Exception:
                pass
            return None

        def _ap_default(ifaces, home):
            """Best guess for the USB Wi-Fi adapter that serves the IoT AP. Linux names
            USB Wi-Fi dongles wlx<mac> or wlan1/wlan2; otherwise pick any interface
            that isn't the home-Wi-Fi uplink."""
            for i in ifaces:
                n = i.lower()
                if n.startswith('wlx') or n in ('wlan1', 'wlan2'):
                    return i
            for i in ifaces:
                if i != home and not i.lower().startswith(('lo', 'loop')):
                    return i
            return 'wlan1'

        try:
            interfaces = list(psutil.net_if_addrs().keys())
            interfaces.sort(key=_rank)
            options = [{"label": iface, "value": iface} for iface in interfaces]
            default = interfaces[0] if interfaces else "wlan0"
            detected_cidr = _guess_cidr(default) or "192.168.1.0/24"
            ap_default = _ap_default(interfaces, default)
            return options, default, detected_cidr, options, ap_default
        except Exception:
            fallback = [{"label": "wlan0", "value": "wlan0"},
                        {"label": "wlan1", "value": "wlan1"}]
            return fallback, "wlan0", "192.168.1.0/24", fallback, "wlan1"

    # ------------------------------------------------------------------
    # Show / hide step 6 (finale) based on step-store
    # ------------------------------------------------------------------
    @app.callback(
        Output("setup-step-6-container", "style"),
        Input("setup-step-store", "data"),
    )
    def show_step_6(step_data):
        step = (step_data or {}).get("step", 1)
        return {"display": "block"} if step == 6 else {"display": "none"}

    # ------------------------------------------------------------------
    # Show public URL on step 6 if Tailscale was configured
    # ------------------------------------------------------------------
    @app.callback(
        Output("setup-public-url-display", "children"),
        Input("setup-step-store", "data"),
        State("setup-tailscale-url-store", "data"),
        prevent_initial_call=True,
    )
    def update_public_url_display(step_data, public_url):
        if (step_data or {}).get("step") != 6 or not public_url:
            return ""
        return dbc.Alert([
            html.Strong("Your remote access URL: "),
            html.A(public_url, href=public_url, target="_blank",
                   className="text-success fw-semibold"),
            html.Br(),
            html.Small("Bookmark this link. It's how you reach IoTSentinel from anywhere.",
                        className="text-muted"),
        ], color="success", className="small")

    # ------------------------------------------------------------------
    # On step 6, show how to reach the dashboard on the local network. Crucial for
    # a headless Pi: gives the user the .local name AND the live IP so they never
    # have to dig the address out of their router.
    # ------------------------------------------------------------------
    @app.callback(
        Output("setup-reachable-display", "children"),
        Input("setup-step-store", "data"),
        prevent_initial_call=True,
    )
    def update_reachable_display(step_data):
        if (step_data or {}).get("step") != 6:
            return ""
        from utils import wifi_manager
        addr = wifi_manager.get_reachable_addresses()
        port = addr["port"]
        mdns_url = f"http://{addr['mdns']}:{port}"
        rows = [
            html.Strong("On your home network, reach IoTSentinel at:"),
            html.Br(),
            html.A(mdns_url, href=mdns_url, className="text-info fw-semibold"),
            html.Span(" (works on most phones and computers)", className="text-muted"),
        ]
        if addr["ip"]:
            ip_url = f"http://{addr['ip']}:{port}"
            rows += [
                html.Br(),
                html.A(ip_url, href=ip_url, className="text-info fw-semibold"),
                html.Span("  (use this if the name above doesn't load)", className="text-muted"),
            ]
        rows.append(
            html.Div("Tip: bookmark one of these now so you can always find your Pi.",
                     className="text-muted mt-1"))
        return dbc.Alert(rows, color=None, className="glass-alert-info small")

    # ------------------------------------------------------------------
    # Step navigation + progress bar  (6-step wizard)
    # ------------------------------------------------------------------
    @app.callback(
        [
            Output("setup-step-store", "data"),
            Output("setup-step-1-container", "style"),
            Output("setup-step-2-container", "style"),
            Output("setup-step-3-container", "style"),
            Output("setup-step-4-container", "style"),
            Output("setup-step-5-container", "style"),
            Output("setup-back-btn", "style"),
            Output("setup-next-btn", "children"),
            Output("setup-next-btn", "color"),
            Output("setup-progress", "value"),
            Output("setup-review-content", "children"),
            Output("setup-status", "children"),
            Output("setup-skip-btn", "style"),
            Output("setup-final-username", "children"),
        ],
        [
            Input("setup-next-btn", "n_clicks"),
            Input("setup-back-btn", "n_clicks"),
            Input("setup-skip-btn", "n_clicks"),
        ],
        [
            State("setup-step-store", "data"),
            State("setup-network-cidr", "value"),
            State("setup-interface", "value"),
            State("setup-admin-username", "value"),
            State("setup-admin-password", "value"),
            State("setup-admin-password-confirm", "value"),
            State("setup-smtp-user", "value"),
            State("setup-smtp-password", "value"),
            State("setup-groq-key", "value"),
            State("setup-abuseipdb-key", "value"),
            State("setup-tier-select", "value"),
            State("setup-tailscale-toggle", "value"),
            State("setup-tailscale-url-store", "data"),
            # Push notification channels (Step 3)
            State("setup-ntfy-topic", "value"),
            State("setup-telegram-token", "value"),
            State("setup-telegram-chat", "value"),
            State("setup-discord-webhook", "value"),
            State("setup-webhook-url", "value"),
            State("setup-ai-privacy-choice", "value"),
            # Protection + advanced (Steps 2 & 3)
            State("setup-autoblock-toggle", "value"),
            State("setup-alert-sensitivity", "value"),
            State("setup-firewall-enable", "value"),
            State("setup-firewall-router-ip", "value"),
            State("setup-firewall-router-user", "value"),
            State("setup-firewall-key-path", "value"),
            # Capture mode (gateway/AP) — capture_mode + AP settings.
            State("setup-capture-mode", "value"),
            State("setup-ap-ssid", "value"),
            State("setup-ap-password", "value"),
            State("setup-ap-interface", "value"),
            State("setup-ap-band", "value"),
        ],
        prevent_initial_call=True,
    )
    def navigate_steps(
        next_clicks, back_clicks, skip_clicks,
        step_data,
        cidr, interface, admin_username, password, password_confirm,
        smtp_user, smtp_password, groq_key, abuseipdb_key,
        tier, tailscale_enabled, public_url,
        ntfy_topic, telegram_token, telegram_chat, discord_webhook, webhook_url,
        ai_privacy_choice,
        auto_block, alert_sensitivity,
        firewall_enable, firewall_router_ip, firewall_router_user, firewall_key_path,
        capture_mode=None, ap_ssid=None, ap_password=None, ap_interface=None, ap_band=None,
    ):
        triggered = callback_context.triggered_id
        step = (step_data or {}).get("step", 1)
        return _navigate_steps_logic(
            triggered, step,
            admin_username, password, password_confirm,
            cidr, interface,
            smtp_user, smtp_password, groq_key, abuseipdb_key,
            tier, public_url,
            ntfy_topic, telegram_token, telegram_chat, discord_webhook, webhook_url,
            ai_privacy_choice=ai_privacy_choice,
            auto_block=auto_block, alert_sensitivity=alert_sensitivity,
            firewall_enable=firewall_enable, firewall_router_ip=firewall_router_ip,
            firewall_router_user=firewall_router_user, firewall_key_path=firewall_key_path,
            capture_mode=capture_mode, ap_ssid=ap_ssid, ap_password=ap_password,
            ap_interface=ap_interface, ap_band=ap_band,
        )

    # ------------------------------------------------------------------
    # Tailscale: show/hide the setup panel based on toggle
    # ------------------------------------------------------------------
    @app.callback(
        Output("setup-tailscale-panel", "style"),
        Input("setup-tailscale-toggle", "value"),
        prevent_initial_call=True,
    )
    def toggle_tailscale_panel(enabled):
        return {"display": "block"} if enabled else {"display": "none"}

    # ------------------------------------------------------------------
    # Tailscale: start setup when button clicked
    # ------------------------------------------------------------------
    @app.callback(
        Output("setup-tailscale-status", "children"),
        Output("setup-tailscale-interval", "disabled"),
        Input("setup-tailscale-start-btn", "n_clicks"),
        prevent_initial_call=True,
    )
    def start_tailscale_setup(_n):
        if not _tailscale_available():
            return (
                dbc.Alert(
                    "Tailscale is not installed on this device. Run the installer "
                    "(install.sh) first, or skip this step.",
                    color="warning", className="small"
                ),
                True,
            )
        with _ts_lock:
            if _ts_state.get('running'):
                return dash.no_update, False
        threading.Thread(target=_tailscale_up_worker, daemon=True).start()
        return (
            html.Div([
                dbc.Spinner(size="sm", className="me-2"),
                html.Span("Starting Tailscale… waiting for the sign-in page…",
                           className="text-muted small"),
            ]),
            False,
        )

    # ------------------------------------------------------------------
    # Tailscale: poll status via interval
    # ------------------------------------------------------------------
    @app.callback(
        Output("setup-tailscale-status", "children", allow_duplicate=True),
        Output("setup-tailscale-interval", "disabled", allow_duplicate=True),
        Output("setup-tailscale-url-store", "data"),
        Input("setup-tailscale-interval", "n_intervals"),
        State("setup-tailscale-url-store", "data"),
        prevent_initial_call=True,
    )
    def poll_tailscale_status(_n, stored_url):
        with _ts_lock:
            login_url = _ts_state.get('url')

        connected, public_url = _check_tailscale_connected()

        if connected and public_url:
            _app_port = int(os.getenv('IOTSENTINEL_PORT', config.get('dashboard', 'port', default=8050)))
            funnel_ok = _enable_tailscale_funnel(port=_app_port)
            funnel_note = (
                html.Small("Funnel active. Accessible from anywhere.",
                           className="text-muted d-block")
                if funnel_ok else
                html.Small("Funnel not enabled. Check that Tailscale supports Funnel on your plan.",
                           className="text-warning d-block")
            )
            status = dbc.Alert([
                html.Strong("Connected! "),
                "Your remote access URL: ",
                html.A(public_url, href=public_url, target="_blank",
                       className="fw-semibold"),
                html.Br(),
                funnel_note,
            ], color="success" if funnel_ok else "warning", className="small")
            return status, True, public_url

        if login_url:
            status = html.Div([
                html.P("Open this link on any device to authenticate:", className="small mb-1"),
                html.A(login_url, href=login_url, target="_blank",
                       className="small fw-semibold text-info d-block text-break mb-2"),
                html.Div([
                    dbc.Spinner(size="sm", className="me-2"),
                    html.Span("Waiting for you to sign in…", className="text-muted small"),
                ]),
            ])
            return status, False, stored_url

        return dash.no_update, False, stored_url

    # ------------------------------------------------------------------
    # Live Groq key validation
    # ------------------------------------------------------------------
    @app.callback(
        Output("setup-groq-feedback", "children"),
        Input("setup-groq-key", "value"),
        prevent_initial_call=True,
    )
    def validate_groq_key(api_key):
        if not api_key:
            return ""
        ok, msg = _validate_groq(api_key)
        return html.Span(msg, className="text-success" if ok else "text-danger")

    # ------------------------------------------------------------------
    # Local AI (Ollama) detection
    # ------------------------------------------------------------------
    @app.callback(
        Output("setup-ollama-feedback", "children"),
        Input("setup-ollama-detect-btn", "n_clicks"),
        prevent_initial_call=True,
    )
    def detect_ollama(n_clicks):
        if not n_clicks:
            raise dash.exceptions.PreventUpdate
        ok, msg = _detect_ollama()
        return html.Span(msg, className="text-success" if ok else "text-muted")

    # ------------------------------------------------------------------
    # Firewall: test the router SSH connection
    # ------------------------------------------------------------------
    @app.callback(
        Output("setup-firewall-feedback", "children"),
        Input("setup-firewall-test-btn", "n_clicks"),
        State("setup-firewall-router-ip", "value"),
        State("setup-firewall-router-user", "value"),
        State("setup-firewall-key-path", "value"),
        prevent_initial_call=True,
    )
    def test_firewall_ssh(n_clicks, router_ip, router_user, key_path):
        if not n_clicks:
            raise dash.exceptions.PreventUpdate
        ok, msg = _test_router_ssh(router_ip, router_user, key_path)
        return html.Span(msg, className="text-success" if ok else "text-danger")

    # ------------------------------------------------------------------
    # Live AbuseIPDB key validation
    # ------------------------------------------------------------------
    @app.callback(
        Output("setup-abuseipdb-feedback", "children"),
        Input("setup-abuseipdb-key", "value"),
        prevent_initial_call=True,
    )
    def validate_abuseipdb_key(api_key):
        if not api_key:
            return ""
        ok, msg = _validate_abuseipdb(api_key)
        return html.Span(msg, className="text-success" if ok else "text-danger")

    # ------------------------------------------------------------------
    # ntfy QR code + URL live update (fires when the topic changes)
    # ------------------------------------------------------------------
    @app.callback(
        Output("setup-ntfy-qr", "src"),
        Output("setup-ntfy-url-link", "href"),
        Output("setup-ntfy-url-link", "children"),
        Input("setup-ntfy-topic", "value"),
        prevent_initial_call=True,
    )
    def update_ntfy_qr(topic):
        from utils.qr import make_qr_data_uri
        topic = (topic or "").strip()
        if not topic:
            raise dash.exceptions.PreventUpdate
        url = f"https://ntfy.sh/{topic}"
        return make_qr_data_uri(url), url, url

    # ------------------------------------------------------------------
    # "Watch your shield" button → navigate to dashboard
    # ------------------------------------------------------------------
    @app.callback(
        Output("setup-url", "href"),
        Input("setup-done-btn", "n_clicks"),
        prevent_initial_call=True,
    )
    def navigate_to_dashboard(n_clicks):
        if n_clicks:
            return "/"
        raise dash.exceptions.PreventUpdate


def _build_review(
    cidr, interface, smtp_user, groq_key, abuseipdb_key,
    tier="household", public_url=None,
    ntfy_topic=None, telegram_token=None, telegram_chat=None,
    discord_webhook=None, webhook_url=None,
    ai_privacy_choice=None,
    auto_block=None, alert_sensitivity=None, firewall_enable=None,
):
    """Build the review summary shown on step 5."""
    tier_label = "Household" if tier == "household" else "Small Business"
    remote_label = public_url if public_url else "LAN only (can enable later from Settings)"
    try:
        row = db_manager.conn.execute(
            "SELECT username FROM users WHERE role = 'admin' LIMIT 1"
        ).fetchone()
        admin_username = row[0] if row else "admin"
    except Exception:
        admin_username = "admin"

    # Build notification channel summary
    notif_parts = []
    if ntfy_topic:
        notif_parts.append(f"ntfy ({ntfy_topic})")
    if telegram_token and telegram_chat:
        notif_parts.append("Telegram")
    if discord_webhook:
        notif_parts.append("Discord")
    if webhook_url:
        notif_parts.append("Webhook")
    if smtp_user:
        notif_parts.append(f"Email ({smtp_user})")
    notif_label = ", ".join(notif_parts) if notif_parts else "Not configured (can add later)"

    rows = [
        ("Admin username", admin_username),
        ("Deployment tier", tier_label),
        ("Network CIDR", cidr or "192.168.1.0/24"),
        ("Interface", interface or "wlan0"),
        ("Notifications", notif_label),
        ("AI explanations", "Cloud (Groq) ✓" if groq_key else "Local only (Ollama) - no data leaves Pi"),
        ("AI mode", "Local first (privacy mode)" if ai_privacy_choice == "local"
                    else "Cloud first (best quality)"),
        ("Threat intel", "Enabled ✓" if abuseipdb_key else "Not configured (can add later)"),
        ("Auto-block", "On - blocks threats automatically" if auto_block is not False
                       else "Off - blocks wait for your approval"),
        ("Alert sensitivity", (alert_sensitivity or "medium").capitalize()),
        ("Firewall enforcement", "Enabled via router ✓" if firewall_enable else "LAN only (log decisions)"),
        ("Remote access", remote_label),
    ]
    return dbc.Table(
        [html.Tbody([
            html.Tr([html.Td(k, className="fw-semibold text-muted small", style={"width": "45%"}),
                     html.Td(v, className="small")])
            for k, v in rows
        ])],
        bordered=False, hover=True, size="sm", className="mb-0"
    )


def _save_config(
    cidr, interface,
    smtp_user, smtp_password, groq_key, abuseipdb_key,
    tier="household", public_url=None,
    ntfy_topic=None, telegram_token=None, telegram_chat=None,
    discord_webhook=None, webhook_url=None,
    ai_privacy_choice=None,
    auto_block=None, alert_sensitivity=None,
    firewall_enable=None, firewall_router_ip=None,
    firewall_router_user=None, firewall_key_path=None,
    capture_mode=None, ap_ssid=None, ap_password=None, ap_interface=None, ap_band=None,
) -> bool:
    """Write .env, update default_config.json. Admin account is created in Step 1."""
    if config.get("system", "is_configured", default=False):
        logger.warning("_save_config called on already-configured system — blocked.")
        return False
    try:
        # Network config (stored in JSON, not .env)
        config.update("network", "local_networks", [cidr or "192.168.1.0/24"])
        config.update("network", "interface", interface or "wlan0")

        # Capture mode (Phase 1 persists the choice; the AP is brought up in Phase 2).
        # Only switch to gateway when the user supplied an AP password, so an accidental
        # selection can never leave Zeek pointed at a not-yet-present USB Wi-Fi adapter.
        if capture_mode == "gateway" and ap_password:
            config.update("network", "capture_mode", "gateway")
            config.update("network", "ap_ssid", ap_ssid or "IoTSentinel")
            config.update("network", "ap_password", ap_password)
            if ap_interface:
                config.update("network", "ap_interface", ap_interface)
            # IoT AP band: 2.4GHz ("bg", default — widest device support) or 5GHz ("a").
            # Pick a valid default channel for the band so configure_ap.sh starts cleanly.
            if ap_band in ("bg", "a"):
                config.update("network", "ap_band", ap_band)
                config.update("network", "ap_channel", 36 if ap_band == "a" else 6)
        else:
            config.update("network", "capture_mode", "passive")

        # The backend points Zeek at network.interface on startup, so a changed
        # interface needs a backend restart to take effect. Only attempt this on a
        # provisioned Pi (systemd unit present); elsewhere it's a no-op and applies
        # on the next orchestrator start. `sudo -n` never blocks on a password prompt.
        try:
            _unit = "/etc/systemd/system/iotsentinel-backend.service"
            if interface and os.path.exists(_unit):
                subprocess.run(["sudo", "-n", "systemctl", "restart", "iotsentinel-backend"],
                               check=False, capture_output=True, timeout=15)
        except Exception as e:
            logger.warning(f"Could not restart backend to apply interface change: {e}")

        # Deployment tier
        config.update("system", "deployment_tier", tier or "household")

        # Dashboard template based on tier
        template = "advanced" if tier == "business" else "simple"
        try:
            cursor = db_manager.conn.cursor()
            cursor.execute(
                "INSERT OR REPLACE INTO user_preferences (user_id, preference_key, preference_value) "
                "SELECT id, 'dashboard_template', ? FROM users WHERE role = 'admin'",
                (template,)
            )
            db_manager.conn.commit()
        except Exception as e:
            logger.warning(f"Could not set dashboard template: {e}")

        env_vars = {}

        # Persist a stable Flask secret key so sessions survive dashboard restarts
        if not os.getenv('FLASK_SECRET_KEY'):
            env_vars['FLASK_SECRET_KEY'] = secrets.token_hex(32)

        # NOTE: Admin password is no longer written to .env.
        # The bcrypt hash was stored in the DB at Step 1 (create_admin).
        # The DB is the single source of truth for credentials.

        # Email
        if smtp_user and smtp_password:
            env_vars["EMAIL_SMTP_HOST"] = "smtp.gmail.com"
            env_vars["EMAIL_SMTP_PORT"] = "587"
            env_vars["EMAIL_SMTP_USER"] = smtp_user
            env_vars["EMAIL_SMTP_PASSWORD"] = smtp_password
            env_vars["EMAIL_SENDER_EMAIL"] = smtp_user
            env_vars["EMAIL_RECIPIENT_EMAIL"] = smtp_user

        # Push notifications — ntfy.sh
        if ntfy_topic:
            env_vars["NOTIFICATIONS_NTFY_ENABLED"] = "true"
            env_vars["NOTIFICATIONS_NTFY_SERVER"]  = "https://ntfy.sh"
            env_vars["NOTIFICATIONS_NTFY_TOPIC"]   = ntfy_topic

        # Push notifications — Telegram
        if telegram_token and telegram_chat:
            env_vars["NOTIFICATIONS_TELEGRAM_ENABLED"]   = "true"
            env_vars["NOTIFICATIONS_TELEGRAM_BOT_TOKEN"] = telegram_token
            env_vars["NOTIFICATIONS_TELEGRAM_CHAT_ID"]   = telegram_chat

        # Push notifications — Discord
        if discord_webhook:
            env_vars["NOTIFICATIONS_DISCORD_ENABLED"]      = "true"
            env_vars["NOTIFICATIONS_DISCORD_WEBHOOK_URL"]  = discord_webhook

        # Push notifications — Generic webhook
        if webhook_url:
            env_vars["NOTIFICATIONS_WEBHOOK_ENABLED"] = "true"
            env_vars["NOTIFICATIONS_WEBHOOK_URL"]     = webhook_url

        # AI assistant
        if groq_key:
            env_vars["GROQ_API_KEY"] = groq_key

        # AI privacy preference — same setting the Admin toggle writes; read
        # by dashboard/shared.py at boot to set HybridAIAssistant.privacy_mode.
        try:
            db_manager.set_setting('ai_privacy_mode',
                                   '1' if ai_privacy_choice == 'local' else '0')
        except Exception as e:
            logger.warning(f"Could not save AI privacy preference: {e}")

        # Threat intel
        if abuseipdb_key:
            env_vars["THREAT_INTELLIGENCE_ABUSEIPDB_API_KEY"] = abuseipdb_key

        # Autonomous blocking consent — preserve confidence_threshold/note, flip enabled.
        if auto_block is not None:
            agent_cfg = config.get("agent", "auto_block", default={}) or {}
            agent_cfg = dict(agent_cfg)
            agent_cfg["enabled"] = bool(auto_block)
            config.update("agent", "auto_block", agent_cfg)

        # Alert sensitivity → notification rate-limit thresholds.
        if alert_sensitivity:
            _levels = {
                "low":    {"max_per_device_per_hour": 3,  "max_global_per_hour": 12, "cooldown_minutes": 30},
                "medium": {"max_per_device_per_hour": 5,  "max_global_per_hour": 20, "cooldown_minutes": 15},
                "high":   {"max_per_device_per_hour": 10, "max_global_per_hour": 40, "cooldown_minutes": 5},
            }
            for k, v in _levels.get(alert_sensitivity, _levels["medium"]).items():
                config.update("alerting", k, v)

        # Firewall enforcement (advanced) — only written when explicitly enabled.
        if firewall_enable:
            config.update("firewall", "enabled", True)
            config.update("firewall", "router_ip", firewall_router_ip or "192.168.1.1")
            config.update("firewall", "router_user", firewall_router_user or "root")
            config.update("firewall", "router_private_key_path", firewall_key_path or "~/.ssh/id_rsa")

        # Remote access: store public URL and configure for proxy
        if public_url:
            env_vars["IOTSENTINEL_PUBLIC_URL"] = public_url
            env_vars["IOTSENTINEL_HOST"] = "0.0.0.0"
            env_vars["IOTSENTINEL_BEHIND_PROXY"] = "true"
            env_vars["IOTSENTINEL_HTTPS"] = "true"

        # Always write .env (even empty sentinel) so display_page exits the wizard
        config.write_env(env_vars)

        config.update("system", "is_configured", True)
        return True

    except Exception as e:
        logger.error(f"Setup save failed: {e}")
        return False
