#!/usr/bin/env python3
"""
Tests for the home-subnet self-detection path that fixes the "Pi monitors the
empty 10.42.0.1 hotspot net instead of the home LAN" bug:

  - utils.net_detect    — interface -> CIDR helpers
  - utils.arp_scanner   — reads network.local_networks (not the dead local_subnet)

Run: pytest tests/test_net_autodetect.py -v
"""

import socket
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from utils import net_detect


def _addr(ip, mask):
    return SimpleNamespace(family=socket.AF_INET, address=ip, netmask=mask)


# ---------------------------------------------------------------------------
# net_detect.guess_cidr
# ---------------------------------------------------------------------------
def test_guess_cidr_returns_network_for_iface():
    with patch("utils.net_detect.psutil.net_if_addrs",
               return_value={"wlan0": [_addr("192.168.4.37", "255.255.255.0")]}):
        assert net_detect.guess_cidr("wlan0") == "192.168.4.0/24"


def test_guess_cidr_skips_loopback_and_linklocal():
    with patch("utils.net_detect.psutil.net_if_addrs",
               return_value={"wlan0": [_addr("127.0.0.1", "255.0.0.0"),
                                       _addr("169.254.1.5", "255.255.0.0")]}):
        assert net_detect.guess_cidr("wlan0") is None


# ---------------------------------------------------------------------------
# net_detect.detect_active_cidr
# ---------------------------------------------------------------------------
def test_detect_prefers_real_subnet_over_hotspot():
    addrs = {
        "wlan0": [_addr("10.42.0.1", "255.255.255.0")],      # the hotspot — ignore
        "eth0":  [_addr("192.168.8.12", "255.255.255.0")],   # the real LAN
    }
    with patch("utils.net_detect.psutil.net_if_addrs", return_value=addrs):
        # preferred iface only has the hotspot CIDR -> fall through to eth0
        assert net_detect.detect_active_cidr("wlan0") == "192.168.8.0/24"


def test_detect_returns_none_when_only_placeholders():
    addrs = {"wlan0": [_addr("10.42.0.1", "255.255.255.0")]}
    with patch("utils.net_detect.psutil.net_if_addrs", return_value=addrs):
        assert net_detect.detect_active_cidr("wlan0") is None


# ---------------------------------------------------------------------------
# arp_scanner reads local_networks[0]
# ---------------------------------------------------------------------------
def _make_scanner(config_values):
    def fake_get(section, key, default=None):
        return config_values.get((section, key), default)

    with patch("utils.arp_scanner.DatabaseManager", return_value=MagicMock()), \
         patch("utils.arp_scanner.config.get", side_effect=fake_get):
        from utils.arp_scanner import ARPScanner
        return ARPScanner()


def test_arp_scanner_uses_local_networks_first_entry():
    scanner = _make_scanner({
        ("network", "capture_mode"): "passive",
        ("network", "local_networks"): ["192.168.9.0/24"],
        ("database", "path"): ":memory:",
    })
    assert scanner.network_range == "192.168.9.0/24"


def test_arp_scanner_gateway_mode_uses_ap_subnet():
    scanner = _make_scanner({
        ("network", "capture_mode"): "gateway",
        ("network", "ap_subnet"): "10.42.0.0/24",
        ("database", "path"): ":memory:",
    })
    assert scanner.network_range == "10.42.0.0/24"


def test_scan_excludes_setup_hotspot_clients():
    """Connected Devices must reflect the home network, not the setup AP: a 10.42.0.x
    hotspot client (the wizard phone/laptop) in the kernel ARP table must be filtered
    out, while home-subnet devices (incl. the router) are kept."""
    scanner = _make_scanner({
        ("network", "capture_mode"): "passive",
        ("network", "local_networks"): ["192.168.0.0/24"],
        ("database", "path"): ":memory:",
    })
    neigh = [
        {"ip": "192.168.0.1", "mac": "aa:aa:aa:aa:aa:aa", "manufacturer": "Router"},
        {"ip": "192.168.0.50", "mac": "bb:bb:bb:bb:bb:bb", "manufacturer": "Phone"},
        {"ip": "10.42.0.213", "mac": "cc:cc:cc:cc:cc:cc", "manufacturer": "SetupLaptop"},
    ]
    with patch.object(scanner, "_ping_sweep"), \
         patch.object(scanner, "_read_ip_neigh", return_value=neigh):
        ips = {d["ip"] for d in scanner.scan_network()}
    assert ips == {"192.168.0.1", "192.168.0.50"}, "hotspot client must be excluded"


def test_scan_fails_open_on_bad_range():
    """A mis-detected/blank subnet must not hide every device (fail open, don't filter)."""
    scanner = _make_scanner({
        ("network", "capture_mode"): "passive",
        ("network", "local_networks"): ["not-a-cidr"],
        ("database", "path"): ":memory:",
    })
    neigh = [{"ip": "192.168.0.1", "mac": "aa:aa:aa:aa:aa:aa", "manufacturer": "Router"}]
    with patch.object(scanner, "_ping_sweep"), \
         patch.object(scanner, "_read_ip_neigh", return_value=neigh):
        ips = {d["ip"] for d in scanner.scan_network()}
    assert ips == {"192.168.0.1"}
