"""
WiFi / reachability helpers
===========================
Single source of truth for the nmcli operations the setup wizard, the post-setup
"Change WiFi" control, and the connectivity-recovery watchdog all share.

Every function is best-effort and never raises: on a non-NetworkManager host (e.g.
a dev laptop or a Linux VM without nmcli) they degrade to empty/None results so the
dashboard keeps working.
"""
from __future__ import annotations

import logging
import shutil
import socket
import subprocess

logger = logging.getLogger(__name__)

# The provisioning hotspot SSID. Excluded from "current network" detection so the
# Pi hosting its own setup AP is never mistaken for being on home WiFi.
HOTSPOT_SSID = "IoTSentinel-Setup"

# mDNS hostname the image publishes via avahi (TARGET_HOSTNAME in the pi-gen build).
DEFAULT_MDNS_HOST = "iotsentinel.local"

# Dashboard port (kept in sync with dashboard/app.py).
DASHBOARD_PORT = 8050


def nmcli_available() -> bool:
    """True when NetworkManager's CLI is present (i.e. we can manage WiFi)."""
    return shutil.which("nmcli") is not None


def scan_wifi_networks() -> list[dict]:
    """Return a list of {label, value} dicts for visible SSIDs (value == SSID)."""
    if not nmcli_available():
        return []
    try:
        result = subprocess.run(
            ["nmcli", "-t", "-f", "SSID,SIGNAL,SECURITY", "dev", "wifi", "list", "--rescan", "yes"],
            capture_output=True, text=True, timeout=15,
        )
        options, seen = [], set()
        for line in result.stdout.splitlines():
            parts = line.split(":")
            ssid = parts[0].strip() if parts else ""
            if not ssid or ssid in seen or ssid == HOTSPOT_SSID:
                continue
            seen.add(ssid)
            signal = parts[1].strip() if len(parts) > 1 else "?"
            secured = "\U0001f512 " if len(parts) > 2 and parts[2].strip() else ""
            options.append({"label": f"{secured}{ssid}  ({signal}%)", "value": ssid})
        return options
    except Exception:
        return []


def current_wifi() -> str | None:
    """Return the SSID the Pi is currently connected to, or None.

    The setup hotspot is never reported as the current network.
    """
    if not nmcli_available():
        return None
    try:
        result = subprocess.run(
            ["nmcli", "-t", "-f", "ACTIVE,SSID", "dev", "wifi"],
            capture_output=True, text=True, timeout=10,
        )
        for line in result.stdout.splitlines():
            active, _, ssid = line.partition(":")
            ssid = ssid.strip()
            if active.strip() == "yes" and ssid and ssid != HOTSPOT_SSID:
                return ssid
        return None
    except Exception:
        return None


def connect_wifi(ssid: str, password: str, iface: str = "wlan0") -> tuple[bool, str]:
    """Switch the Pi to a WiFi network using nmcli. Returns (success, message).

    A timeout is treated as a soft success: nmcli often does connect the Pi to the
    new network but the response is lost because switching networks drops the very
    connection this request came in on.
    """
    if not ssid:
        return False, "Please select a WiFi network first."
    if not nmcli_available():
        return False, "nmcli not available on this device."
    try:
        cmd = ["sudo", "nmcli", "dev", "wifi", "connect", ssid]
        if password:
            cmd += ["password", password]
        cmd += ["ifname", iface]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=25)
        if result.returncode == 0:
            return True, (
                f"Connected to “{ssid}”. Your Pi is now on this network. "
                f"Reconnect this device to the same WiFi, then reopen "
                f"http://{DEFAULT_MDNS_HOST}:{DASHBOARD_PORT}."
            )
        err = result.stderr.strip() or result.stdout.strip()
        return False, err or "Connection failed. Check your WiFi password and try again."
    except subprocess.TimeoutExpired:
        return True, (
            f"Switching to “{ssid}”… Rejoin that network on this device and "
            f"reopen http://{DEFAULT_MDNS_HOST}:{DASHBOARD_PORT} to continue."
        )
    except Exception as e:
        return False, str(e)


def get_local_ip() -> str | None:
    """Best-effort primary LAN IPv4 of this host (the address other devices reach).

    Uses a connectionless UDP socket so no traffic is actually sent; falls back to
    the hostname resolution. Returns None if neither yields a routable address.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
        finally:
            s.close()
        if ip and not ip.startswith("127."):
            return ip
    except Exception:
        pass
    try:
        ip = socket.gethostbyname(socket.gethostname())
        if ip and not ip.startswith("127."):
            return ip
    except Exception:
        pass
    return None


def get_reachable_addresses() -> dict:
    """Return {mdns, ip, port} describing how to reach the dashboard.

    'mdns' is the iotsentinel.local hostname (always offered as the primary,
    router-independent address); 'ip' is the live LAN IP if one is detectable.
    """
    host = socket.gethostname() or "iotsentinel"
    mdns = host if host.endswith(".local") else f"{host}.local"
    # The pi-gen image sets the hostname to "iotsentinel"; keep that friendly name
    # even on hosts where gethostname() returns something else is NOT desired, so we
    # trust the real hostname here and fall back to the documented default.
    if host in ("", "localhost"):
        mdns = DEFAULT_MDNS_HOST
    return {"mdns": mdns, "ip": get_local_ip(), "port": DASHBOARD_PORT}
