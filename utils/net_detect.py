"""
Network self-detection helpers
==============================
Shared, dependency-light helpers for working out which IPv4 subnet the Pi is
actually on. Used by the orchestrator to self-heal ``network.local_networks``
after the device joins home Wi-Fi (the setup wizard can only guess the subnet
while still on the 10.42.0.1 hotspot, which is the wrong network to monitor).

Every function is best-effort and never raises.
"""
from __future__ import annotations

import ipaddress
import socket

import psutil

# Subnets that mean "we haven't detected the real LAN yet": the shipped default
# and the provisioning hotspot range. If local_networks still holds one of these
# we overwrite it with whatever the live interface reports.
PLACEHOLDER_CIDRS = {"192.168.1.0/24", "10.42.0.0/24"}


def guess_cidr(iface: str) -> str | None:
    """Return the CIDR for the first non-loopback IPv4 address on *iface*, or None."""
    try:
        for addr in psutil.net_if_addrs().get(iface, []):
            if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                if addr.address.startswith("169.254."):
                    continue  # link-local / no DHCP lease yet
                net = ipaddress.IPv4Network(
                    f"{addr.address}/{addr.netmask}", strict=False
                )
                return str(net)
    except Exception:
        pass
    return None


def detect_active_cidr(preferred_iface: str | None = None) -> str | None:
    """Best-effort detection of the LAN CIDR the Pi is currently on.

    Tries *preferred_iface* first (e.g. ``network.interface``), then any other
    interface that carries a routable private IPv4 address, skipping loopback,
    link-local and the hotspot range.
    """
    if preferred_iface:
        cidr = guess_cidr(preferred_iface)
        if cidr and cidr not in PLACEHOLDER_CIDRS:
            return cidr
    try:
        for iface in psutil.net_if_addrs().keys():
            if iface.lower().startswith(("lo", "loop")):
                continue
            cidr = guess_cidr(iface)
            if cidr and cidr not in PLACEHOLDER_CIDRS:
                return cidr
    except Exception:
        pass
    return None
