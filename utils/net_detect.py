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


def get_local_ip() -> str | None:
    """Best-effort primary outbound IPv4 address of this host (the Pi itself).

    Uses the standard UDP-connect trick: opening a datagram socket toward a
    public address makes the kernel pick the source IP for the default route
    without actually sending anything. Never raises; returns None on failure.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
        finally:
            s.close()
        if ip and not ip.startswith(("127.", "169.254.")):
            return ip
    except Exception:
        pass
    return None


def get_default_gateway() -> str | None:
    """Best-effort IPv4 default gateway (the home router) from /proc/net/route.

    Linux-only (the Pi); returns None on platforms without /proc (e.g. macOS dev
    machines) or any parse error. Never raises.
    """
    try:
        with open("/proc/net/route") as fh:
            for line in fh.readlines()[1:]:
                fields = line.strip().split()
                # Destination 00000000 == default route; field[2] is the gateway
                # as a little-endian hex IPv4.
                if len(fields) >= 3 and fields[1] == "00000000":
                    gw_hex = fields[2]
                    octets = [str(int(gw_hex[i:i + 2], 16)) for i in (6, 4, 2, 0)]
                    return ".".join(octets)
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
