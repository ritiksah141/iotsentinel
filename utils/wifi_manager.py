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
import os
import shutil
import socket
import subprocess
import time
from pathlib import Path

logger = logging.getLogger(__name__)

# The provisioning hotspot SSID. Excluded from "current network" detection so the
# Pi hosting its own setup AP is never mistaken for being on home WiFi.
HOTSPOT_SSID = "IoTSentinel-Setup"

# mDNS hostname the image publishes via avahi (TARGET_HOSTNAME in the pi-gen build).
DEFAULT_MDNS_HOST = "iotsentinel.local"

# Dashboard port (kept in sync with dashboard/app.py).
DASHBOARD_PORT = 8050

# Wi-Fi regulatory countries for the wizard picker (ISO 3166-1 alpha-2), kept
# globally representative and sorted by country name. Not every ISO country is
# listed, but the field accepts any valid 2-letter code. There is no built-in
# bias to any one country — the user picks their own; the radio just needs *some*
# valid code to start the first setup hotspot before the wizard runs.
COUNTRY_OPTIONS = sorted([
    ("AR", "Argentina"), ("AU", "Australia"), ("AT", "Austria"), ("BD", "Bangladesh"),
    ("BE", "Belgium"), ("BR", "Brazil"), ("CA", "Canada"), ("CL", "Chile"),
    ("CN", "China"), ("CO", "Colombia"), ("DK", "Denmark"), ("EG", "Egypt"),
    ("FI", "Finland"), ("FR", "France"), ("DE", "Germany"), ("HK", "Hong Kong"),
    ("IN", "India"), ("ID", "Indonesia"), ("IE", "Ireland"), ("IL", "Israel"),
    ("IT", "Italy"), ("JP", "Japan"), ("KE", "Kenya"), ("MY", "Malaysia"),
    ("MX", "Mexico"), ("NP", "Nepal"), ("NL", "Netherlands"), ("NZ", "New Zealand"),
    ("NG", "Nigeria"), ("NO", "Norway"), ("PK", "Pakistan"), ("PH", "Philippines"),
    ("PL", "Poland"), ("PT", "Portugal"), ("SA", "Saudi Arabia"), ("SG", "Singapore"),
    ("ZA", "South Africa"), ("KR", "South Korea"), ("ES", "Spain"), ("LK", "Sri Lanka"),
    ("SE", "Sweden"), ("CH", "Switzerland"), ("TW", "Taiwan"), ("TH", "Thailand"),
    ("TR", "Turkey"), ("AE", "United Arab Emirates"), ("GB", "United Kingdom"),
    ("US", "United States"), ("VN", "Vietnam"),
], key=lambda x: x[1])


def nmcli_available() -> bool:
    """True when NetworkManager's CLI is present (i.e. we can manage WiFi)."""
    return shutil.which("nmcli") is not None


def _parse_wifi_list(stdout: str) -> list[dict]:
    options, seen = [], set()
    for line in stdout.splitlines():
        parts = line.split(":")
        ssid = parts[0].strip() if parts else ""
        if not ssid or ssid in seen or ssid == HOTSPOT_SSID:
            continue
        seen.add(ssid)
        signal = parts[1].strip() if len(parts) > 1 else "?"
        secured = "\U0001f512 " if len(parts) > 2 and parts[2].strip() else ""
        options.append({"label": f"{secured}{ssid}  ({signal}%)", "value": ssid})
    return options


def scan_wifi_networks() -> list[dict]:
    """Return a list of {label, value} dicts for visible SSIDs (value == SSID).

    Tries an active rescan first; if that yields nothing (common when the radio
    is busy — e.g. wlan0 still hosting the setup AP — or the rescan errors), it
    falls back to NetworkManager's cached list so the dropdown isn't empty.
    """
    if not nmcli_available():
        return []
    base = ["nmcli", "-t", "-f", "SSID,SIGNAL,SECURITY", "dev", "wifi", "list"]
    for rescan in ("yes", "no"):
        try:
            result = subprocess.run(
                base + ["--rescan", rescan],
                capture_output=True, text=True, timeout=15,
            )
            options = _parse_wifi_list(result.stdout)
            if options:
                return options
        except Exception:
            continue
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


def teardown_setup_hotspot(iface: str = "wlan0") -> None:
    """Bring down + delete the provisioning hotspot so wlan0 returns to client mode.

    Called once the Pi has joined home Wi-Fi. The setup AP and the home-Wi-Fi
    client share wlan0, so a lingering AP profile blocks/confuses the client
    connection and keeps the dashboard reachable only on 10.42.0.1. Best-effort
    and never raises — failure here must not break a successful Wi-Fi switch.

    Prefers the shared setup_hotspot.sh (it also clears the captive iptables
    redirect); falls back to a direct nmcli delete if the script isn't available.
    """
    if not nmcli_available():
        return
    script = Path(__file__).resolve().parents[1] / "scripts" / "setup_hotspot.sh"
    try:
        # Invoke by absolute path (not `sudo bash <script>`): sudoers grants the exact
        # script path, and granting `bash` would be a root-equivalent hole. Only treat
        # it as done when it actually succeeded — a non-zero exit (e.g. sudoers denial)
        # must fall through to the direct nmcli teardown below, not silently return.
        if script.exists():
            r = subprocess.run(["sudo", "-n", str(script), "disarm"],
                               capture_output=True, text=True, timeout=20)
            if r.returncode == 0:
                return
            logger.warning("setup_hotspot.sh disarm exited %s (%s) — falling back to nmcli",
                           r.returncode, (r.stderr or r.stdout or "").strip())
    except Exception as e:
        logger.warning("setup_hotspot.sh disarm failed, falling back to nmcli: %s", e)
    # Fallback: at least remove the NetworkManager AP profile directly.
    try:
        subprocess.run(["sudo", "-n", "nmcli", "connection", "down", HOTSPOT_SSID],
                       capture_output=True, text=True, timeout=10)
        subprocess.run(["sudo", "-n", "nmcli", "connection", "delete", HOTSPOT_SSID],
                       capture_output=True, text=True, timeout=10)
    except Exception as e:
        logger.warning("Direct hotspot teardown failed: %s", e)


# How many times to (re)activate the saved home profile before giving up on a live
# confirmation. Each attempt allows the radio to finish leaving AP mode; the saved
# autoconnect profile keeps NetworkManager trying afterwards regardless.
_CONNECT_ATTEMPTS = 4


def _iface_state(iface: str) -> str | None:
    """Return NetworkManager's state for *iface* (e.g. 'connected', 'disconnected',
    'connecting', 'unavailable'), or None if it can't be read."""
    try:
        r = subprocess.run(["nmcli", "-t", "-f", "DEVICE,STATE", "device", "status"],
                           capture_output=True, text=True, timeout=10)
        for line in r.stdout.splitlines():
            dev, _, state = line.partition(":")
            if dev.strip() == iface:
                return state.strip()
    except Exception:
        pass
    return None


def _create_home_profile(ssid: str, password: str, iface: str) -> bool:
    """Persist a NetworkManager client profile for the home network with autoconnect
    ON, BEFORE the setup hotspot comes down. Writing a profile needs no radio (it is
    safe while wlan0 is still hosting the AP), so the credentials survive even if the
    live activation below is slow or the request is cut off when wlan0 leaves the AP —
    NM keeps retrying while the radio is free, and the join survives a reboot.

    The same-named profile is deleted first so repeated setups never stack duplicates.
    Returns True if the add succeeded.
    """
    # Drop any stale profile of the same name (best-effort).
    subprocess.run(["sudo", "-n", "nmcli", "connection", "delete", ssid],
                   capture_output=True, text=True, timeout=10)
    add = ["sudo", "-n", "nmcli", "connection", "add", "type", "wifi",
           "con-name", ssid, "ifname", iface, "ssid", ssid,
           "connection.autoconnect", "yes", "connection.autoconnect-priority", "10"]
    if password:
        add += ["wifi-sec.key-mgmt", "wpa-psk", "wifi-sec.psk", password]
    try:
        r = subprocess.run(add, capture_output=True, text=True, timeout=15)
        if r.returncode != 0:
            logger.warning("home Wi-Fi profile add exited %s (%s)",
                           r.returncode, (r.stderr or r.stdout or "").strip())
        return r.returncode == 0
    except Exception as e:
        logger.warning("could not pre-create home Wi-Fi profile: %s", e)
        return False


def connect_wifi(ssid: str, password: str, iface: str = "wlan0") -> tuple[bool, str]:
    """Switch the Pi to a WiFi network using nmcli. Returns (success, message).

    Profile-first / autoconnect model (the rc6 deferred join left the Pi stranded —
    it deleted the setup AP and then ran a one-shot `nmcli dev wifi connect`; if that
    single attempt failed, wlan0 was on neither the hotspot nor home Wi-Fi, and no
    home profile had been saved). Instead we:

      1. PERSIST the home profile first (autoconnect yes) — no radio needed, so the
         credentials are safe even before the AP comes down and survive a reboot.
      2. Tear the setup AP down so wlan0 returns to managed/client mode (a radio in
         AP mode can't associate). No-op when no hotspot is up (post-setup Change WiFi).
      3. Wait for wlan0 to leave AP mode, then bring the profile up and VERIFY a real
         connection, retrying across a short window — the first activation often races
         the radio finishing its switch out of AP mode.

    A timeout is treated as a soft success: `nmcli connection up` often does connect
    the Pi but the reply is lost when wlan0 switches networks. The saved autoconnect
    profile means NM completes/retries the join on its own.
    """
    if not ssid:
        return False, "Please select a WiFi network first."
    if not nmcli_available():
        return False, "nmcli not available on this device."

    success_msg = (
        f"Connected to “{ssid}”. Your Pi is now on this network. "
        f"Reconnect this device to the same WiFi, then reopen "
        f"http://{DEFAULT_MDNS_HOST}:{DASHBOARD_PORT}."
    )
    soft_msg = (
        f"Switching to “{ssid}”… Rejoin that network on this device and "
        f"reopen http://{DEFAULT_MDNS_HOST}:{DASHBOARD_PORT} to continue."
    )

    # 1) Save the home profile while we still have the radio in a known state.
    _create_home_profile(ssid, password, iface)

    # 2) Drop the setup AP so wlan0 leaves AP mode (no-op if no hotspot is up).
    teardown_setup_hotspot(iface)

    # 3) Wait (best-effort) for wlan0 to come back to a managed state before activating.
    for _ in range(10):
        if _iface_state(iface) in ("disconnected", "connecting", "connected"):
            break
        time.sleep(1)

    # 4) Bring the saved profile up and confirm we actually landed on the home network,
    #    retrying a few times to ride out the AP→client transition.
    up_cmd = ["sudo", "-n", "nmcli", "connection", "up", ssid, "ifname", iface]
    last_err = ""
    for _ in range(_CONNECT_ATTEMPTS):
        try:
            result = subprocess.run(up_cmd, capture_output=True, text=True, timeout=30)
        except subprocess.TimeoutExpired:
            # Reply lost as wlan0 switched networks; the autoconnect profile finishes it.
            return True, soft_msg
        except Exception as e:
            return False, str(e)
        if result.returncode == 0 and current_wifi() == ssid:
            return True, success_msg
        last_err = (result.stderr or result.stdout or "").strip()
        el = last_err.lower()
        # A wrong password / missing secret will never fix itself with retries.
        if "secrets were required" in el or "no secrets" in el:
            return False, "Connection failed - check your WiFi password and try again."
        time.sleep(4)

    # Out of attempts. If we are in fact on the network now, call it a success;
    # otherwise surface the error (or a soft "still switching" if NM is mid-activation).
    if current_wifi() == ssid:
        return True, success_msg
    if last_err:
        return False, last_err
    return True, soft_msg


def set_country(country: str) -> tuple[bool, str]:
    """Set + persist the Wi-Fi regulatory country (ISO 3166-1 alpha-2).

    On a Raspberry Pi the radio is rfkill-blocked and won't do AP mode until a
    country is set, and the code also governs legal TX power / channels. This applies
    it live (`iw reg set`), persists it for reboots (`raspi-config do_wifi_country`),
    and records it in .env so the provisioning/recovery hotspot scripts reuse it.
    Best-effort and non-fatal — degrades cleanly on a non-Pi host.
    """
    cc = (country or "").strip().upper()
    if len(cc) != 2 or not cc.isalpha():
        return False, "Please choose a valid country."
    applied = False
    try:
        if shutil.which("iw"):
            subprocess.run(["sudo", "iw", "reg", "set", cc],
                           capture_output=True, text=True, timeout=10)
            applied = True
        if shutil.which("raspi-config"):
            subprocess.run(["sudo", "raspi-config", "nonint", "do_wifi_country", cc],
                           capture_output=True, text=True, timeout=20)
            applied = True
    except Exception as e:  # never break setup over the regulatory apply
        logger.warning("set_country apply failed: %s", e)
    _persist_country_env(cc)
    if applied:
        return True, f"Wi-Fi region set to {cc}."
    return True, f"Saved region {cc} (will apply on this device's Wi-Fi)."


def _persist_country_env(cc: str) -> None:
    """Record IOTSENTINEL_WIFI_COUNTRY in .env so the root hotspot scripts reuse it."""
    try:
        env = Path(__file__).resolve().parent.parent / ".env"
        lines, found = [], False
        if env.exists():
            for line in env.read_text().splitlines():
                if line.startswith("IOTSENTINEL_WIFI_COUNTRY="):
                    lines.append(f"IOTSENTINEL_WIFI_COUNTRY={cc}"); found = True
                else:
                    lines.append(line)
        if not found:
            lines.append(f"IOTSENTINEL_WIFI_COUNTRY={cc}")
        env.write_text("\n".join(lines) + "\n")
    except Exception as e:
        logger.warning("could not persist Wi-Fi country to .env: %s", e)


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
    """Return {mdns, ip, port, remote} describing how to reach the dashboard.

    'mdns' is the iotsentinel.local hostname (always offered as the primary,
    router-independent address); 'ip' is the live LAN IP if one is detectable;
    'remote' is the public remote-access URL (Tailscale Funnel) if configured, so
    the Quick Settings → Network tab can show the from-anywhere link too.
    """
    host = socket.gethostname() or "iotsentinel"
    mdns = host if host.endswith(".local") else f"{host}.local"
    # The pi-gen image sets the hostname to "iotsentinel"; keep that friendly name
    # even on hosts where gethostname() returns something else is NOT desired, so we
    # trust the real hostname here and fall back to the documented default.
    if host in ("", "localhost"):
        mdns = DEFAULT_MDNS_HOST
    remote = (os.getenv("IOTSENTINEL_PUBLIC_URL") or "").strip() or None
    return {"mdns": mdns, "ip": get_local_ip(), "port": DASHBOARD_PORT, "remote": remote}
