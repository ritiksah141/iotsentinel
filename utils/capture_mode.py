"""
Capture-mode awareness
======================
Small helper used by the dashboard to give HONEST empty-states. When IoTSentinel runs
passively on a Wi-Fi *client*, it can discover devices (ARP/L2) but cannot capture other
devices' unicast traffic — a wireless client never receives frames addressed to other
clients. So traffic-derived charts (timeline, protocol mix, anomaly, forecast) are
inherently sparse until the Pi is the gateway (AP mode). The UI should SAY this instead of
showing a blank "no data".
"""
from __future__ import annotations


def is_passive_wifi() -> bool:
    """True when monitoring passively on a Wi-Fi interface (the sparse-traffic mode)."""
    try:
        from config.config_manager import config
        mode = config.get('network', 'capture_mode', default='passive')
        iface = (config.get('network', 'interface', default='') or '').lower()
        return mode != 'gateway' and iface.startswith(('wlan', 'wl', 'wifi', 'wlp'))
    except Exception:
        return False


def passive_traffic_note() -> str:
    """One-line explanation for why traffic charts are sparse on a Wi-Fi client."""
    return ("Passive Wi-Fi mode: device discovery is live, but per-device traffic "
            "analytics need Gateway (AP) mode — enable it in Settings → Network.")


def empty_title(base: str) -> str:
    """Annotate a chart's 'no data' title with the passive-Wi-Fi reason when applicable,
    so a sparse chart reads as expected (not broken). Returns *base* unchanged otherwise."""
    if is_passive_wifi():
        return base + " - passive Wi-Fi sees little device traffic (enable Gateway mode for full capture)"
    return base


def capture_mode_name() -> str:
    """The configured capture mode ('passive' or 'gateway'), for UI badges/labels.

    Reads the config directly (not the is_passive_wifi() interface heuristic) so the
    label is correct on dev machines and demo installs too."""
    try:
        from config.config_manager import config
        return (config.get('network', 'capture_mode', default='passive') or 'passive').lower()
    except Exception:
        return 'passive'
