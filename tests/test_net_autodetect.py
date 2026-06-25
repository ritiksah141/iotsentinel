#!/usr/bin/env python3
"""
Tests for the home-subnet self-detection path that fixes the "Pi monitors the
empty 10.42.0.1 hotspot net instead of the home LAN" bug, plus the ConfigManager.get
contract the orchestrator depends on:

  - utils.net_detect    — interface -> CIDR helpers
  - utils.arp_scanner   — reads network.local_networks (not the dead local_subnet)
  - orchestrator        — _autodetect_local_network self-heals the placeholder subnet,
                          and must use config.get_section('x') (NOT config.get('x', {}),
                          which passes {} as an unhashable KEY -> TypeError and silently
                          broke discovery + subnet self-heal on hardware)

Run: pytest tests/test_net_autodetect.py -v
"""

import re
import socket
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

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


def test_ping_sweep_skips_oversized_subnet():
    """A large home LAN (/16 etc.) must NOT trigger a tens-of-thousands ping sweep that
    hangs discovery — fall back to the passive neighbour table instead."""
    scanner = _make_scanner({
        ("network", "capture_mode"): "passive",
        ("network", "local_networks"): ["10.0.0.0/16"],   # 65k hosts
        ("database", "path"): ":memory:",
    })
    with patch.object(scanner, "_ping_host") as ping:
        scanner._ping_sweep()
    ping.assert_not_called()


def test_ping_sweep_runs_on_normal_subnet():
    scanner = _make_scanner({
        ("network", "capture_mode"): "passive",
        ("network", "local_networks"): ["192.168.0.0/24"],   # 254 hosts
        ("database", "path"): ":memory:",
    })
    with patch.object(scanner, "_ping_host") as ping:
        scanner._ping_sweep()
    assert ping.call_count > 0, "a normal /24 must be actively swept"


def test_scan_fails_open_on_placeholder_subnet():
    """Before the self-heal locks the real LAN, network_range is a placeholder. The filter
    must NOT scope to it — otherwise a home that isn't 192.168.1.0/24 (e.g. Virgin Media's
    192.168.0.x) would have EVERY device dropped → 0/0. Fail open until a real subnet locks."""
    scanner = _make_scanner({
        ("network", "capture_mode"): "passive",
        ("network", "local_networks"): ["192.168.1.0/24"],   # the shipped placeholder
        ("database", "path"): ":memory:",
    })
    neigh = [
        {"ip": "192.168.0.1", "mac": "aa:aa:aa:aa:aa:aa", "manufacturer": "Router"},
        {"ip": "192.168.0.50", "mac": "bb:bb:bb:bb:bb:bb", "manufacturer": "Phone"},
    ]
    with patch.object(scanner, "_ping_sweep"), \
         patch.object(scanner, "_read_ip_neigh", return_value=neigh):
        ips = {d["ip"] for d in scanner.scan_network()}
    assert ips == {"192.168.0.1", "192.168.0.50"}, "placeholder range must not hide devices"


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


# ---------------------------------------------------------------------------
# ConfigManager.get contract + orchestrator subnet self-heal
#
# config.get('section', {}) passed {} as the KEY (get(section, key, default)), so it
# ran dict.get({}, ...) -> TypeError: unhashable type: 'dict'. That threw inside the
# orchestrator's innovation-feature init and _autodetect_local_network every cycle,
# silently disabling mDNS/UPnP/nmap discovery and pinning the subnet to the placeholder.
# ---------------------------------------------------------------------------
class _RealishConfig:
    """Mirrors config.config_manager.ConfigManager.get / get_section / update exactly,
    so the OLD buggy `config.get('x', {})` raises here just as it would in production."""

    def __init__(self, data):
        self._config = data

    def get(self, section, key, default=None):
        return self._config.get(section, {}).get(key, default)

    def get_section(self, section):
        return self._config.get(section, {})

    def update(self, section, key, value):
        self._config.setdefault(section, {})[key] = value
        return True


_BAD_CONFIG_GET = re.compile(r"""config\.get\(['"][a-z_]+['"]\s*,\s*\{\}\)""")


def test_orchestrator_has_no_unhashable_config_get_pattern():
    src = (Path(__file__).parent.parent / "orchestrator.py").read_text()
    hits = _BAD_CONFIG_GET.findall(src)
    assert not hits, f"orchestrator still uses config.get('x', {{}}) (unhashable key): {hits}"


def test_realish_config_reproduces_the_old_bug():
    cfg = _RealishConfig({"discovery": {"mode": "passive"}})
    with pytest.raises(TypeError):
        cfg.get("discovery", {})                       # the bug
    assert cfg.get_section("discovery") == {"mode": "passive"}  # the fix


def test_autodetect_local_network_heals_placeholder_subnet():
    """Self-heal must replace the placeholder CIDR with the detected home subnet
    without raising (the config.get bug used to throw every cycle)."""
    from orchestrator import IoTSentinelOrchestrator

    cfg = _RealishConfig({"network": {
        "capture_mode": "passive", "interface": "wlan0",
        "local_networks": ["192.168.1.0/24"]}})  # the shipped placeholder
    fake_self = SimpleNamespace(arp_scanner=SimpleNamespace(network_range="192.168.1.0/24"))
    with patch("orchestrator.config", cfg), \
         patch("utils.net_detect.detect_active_cidr", return_value="192.168.8.0/24"):
        IoTSentinelOrchestrator._autodetect_local_network(fake_self)
    assert cfg.get_section("network")["local_networks"] == ["192.168.8.0/24"]
    assert fake_self.arp_scanner.network_range == "192.168.8.0/24"


def test_autodetect_keeps_user_set_real_subnet():
    """A non-placeholder subnet the user set must never be clobbered."""
    from orchestrator import IoTSentinelOrchestrator

    cfg = _RealishConfig({"network": {
        "capture_mode": "passive", "interface": "wlan0",
        "local_networks": ["10.0.5.0/24"]}})
    fake_self = SimpleNamespace(arp_scanner=None)
    with patch("orchestrator.config", cfg), \
         patch("utils.net_detect.detect_active_cidr", return_value="192.168.8.0/24"):
        IoTSentinelOrchestrator._autodetect_local_network(fake_self)
    assert cfg.get_section("network")["local_networks"] == ["10.0.5.0/24"]


def test_discovery_settings_save_restarts_backend():
    """Saving discovery/scan toggles must bounce the backend so the orchestrator
    re-reads discovery config (it only reads at startup)."""
    src = (Path(__file__).parent.parent / "dashboard" / "callbacks"
           / "callbacks_global.py").read_text()
    assert "iotsentinel-backend" in src
    assert "systemctl" in src and "restart" in src


def test_active_discovery_enabled_by_default():
    """v1 passive mode ships with active (nmap) discovery ON so the device list is
    complete out of the box, not just the always-on ARP sweep."""
    import json
    cfg = json.loads((Path(__file__).parent.parent / "config"
                      / "default_config.json").read_text())
    disc = cfg["discovery"]
    assert disc["active_scan_enabled"] is True
    assert disc["nmap_enabled"] is True
    assert disc["mode"] == "passive"  # capture mode unchanged; only discovery is active


def test_active_scan_loop_follows_subnet_heal_and_skips_placeholder():
    """The nmap active-scan loop must re-read the subnet every cycle (so it follows the
    self-heal) and skip the placeholder, mirroring the ARP scanner — otherwise it pins to
    the wrong subnet captured at startup, the same bug that under-counted devices."""
    import inspect
    from orchestrator import IoTSentinelOrchestrator
    src = inspect.getsource(IoTSentinelOrchestrator._active_scan_loop)
    assert "PLACEHOLDER_CIDRS" in src, "active scan must skip the placeholder subnet"
    # the subnet read must be INSIDE the while loop, not captured once before it
    body = src.split("while self.running", 1)[1]
    assert "local_networks" in body, "subnet must be re-read each cycle, not once at start"
