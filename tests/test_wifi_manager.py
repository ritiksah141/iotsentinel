#!/usr/bin/env python3
"""
Unit tests for utils.wifi_manager — the shared nmcli/reachability helpers used by
the setup wizard, the post-setup "Change WiFi" control, and the connectivity
recovery watchdog.

Run: pytest tests/test_wifi_manager.py -v
"""

import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from utils import wifi_manager


# ---------------------------------------------------------------------------
# nmcli_available
# ---------------------------------------------------------------------------
def test_nmcli_available_true_when_on_path():
    with patch("utils.wifi_manager.shutil.which", return_value="/usr/bin/nmcli"):
        assert wifi_manager.nmcli_available() is True


def test_nmcli_available_false_when_missing():
    with patch("utils.wifi_manager.shutil.which", return_value=None):
        assert wifi_manager.nmcli_available() is False


# ---------------------------------------------------------------------------
# scan_wifi_networks
# ---------------------------------------------------------------------------
def test_scan_returns_empty_without_nmcli():
    with patch("utils.wifi_manager.nmcli_available", return_value=False):
        assert wifi_manager.scan_wifi_networks() == []


def test_scan_parses_ssids_dedupes_and_hides_hotspot():
    out = "\n".join([
        "HomeNet:82:WPA2",
        "HomeNet:60:WPA2",          # duplicate -> collapsed
        "OpenCafe:40:",             # open network -> no lock glyph
        f"{wifi_manager.HOTSPOT_SSID}:99:",   # our own setup AP -> excluded
        ":50:WPA2",                 # blank SSID -> skipped
    ])
    proc = MagicMock(stdout=out)
    with patch("utils.wifi_manager.nmcli_available", return_value=True), \
         patch("utils.wifi_manager.subprocess.run", return_value=proc):
        opts = wifi_manager.scan_wifi_networks()
    values = [o["value"] for o in opts]
    assert values == ["HomeNet", "OpenCafe"]
    # secured network gets a lock glyph; open one does not
    home = next(o for o in opts if o["value"] == "HomeNet")
    cafe = next(o for o in opts if o["value"] == "OpenCafe")
    assert "\U0001f512" in home["label"]
    assert "\U0001f512" not in cafe["label"]


def test_scan_swallows_errors():
    with patch("utils.wifi_manager.nmcli_available", return_value=True), \
         patch("utils.wifi_manager.subprocess.run", side_effect=OSError("boom")):
        assert wifi_manager.scan_wifi_networks() == []


# ---------------------------------------------------------------------------
# current_wifi
# ---------------------------------------------------------------------------
def test_current_wifi_returns_active_ssid():
    proc = MagicMock(stdout="no:OtherNet\nyes:HomeNet\n")
    with patch("utils.wifi_manager.nmcli_available", return_value=True), \
         patch("utils.wifi_manager.subprocess.run", return_value=proc):
        assert wifi_manager.current_wifi() == "HomeNet"


def test_current_wifi_ignores_setup_hotspot():
    proc = MagicMock(stdout=f"yes:{wifi_manager.HOTSPOT_SSID}\n")
    with patch("utils.wifi_manager.nmcli_available", return_value=True), \
         patch("utils.wifi_manager.subprocess.run", return_value=proc):
        assert wifi_manager.current_wifi() is None


def test_current_wifi_none_without_nmcli():
    with patch("utils.wifi_manager.nmcli_available", return_value=False):
        assert wifi_manager.current_wifi() is None


# ---------------------------------------------------------------------------
# connect_wifi
# ---------------------------------------------------------------------------
def test_connect_requires_ssid():
    ok, msg = wifi_manager.connect_wifi("", "pw")
    assert ok is False and "select" in msg.lower()


def test_connect_success_builds_password_command():
    proc = MagicMock(returncode=0, stdout="", stderr="")
    with patch("utils.wifi_manager.nmcli_available", return_value=True), \
         patch("utils.wifi_manager.subprocess.run", return_value=proc) as run:
        ok, msg = wifi_manager.connect_wifi("HomeNet", "secret")
    assert ok is True
    cmd = run.call_args[0][0]
    assert cmd[:5] == ["sudo", "nmcli", "dev", "wifi", "connect"]
    assert "password" in cmd and "secret" in cmd
    assert "HomeNet" in msg


def test_connect_failure_surfaces_stderr():
    proc = MagicMock(returncode=4, stdout="", stderr="Secrets were required but not provided")
    with patch("utils.wifi_manager.nmcli_available", return_value=True), \
         patch("utils.wifi_manager.subprocess.run", return_value=proc):
        ok, msg = wifi_manager.connect_wifi("HomeNet", "wrong")
    assert ok is False and "Secrets" in msg


def test_connect_timeout_is_soft_success():
    with patch("utils.wifi_manager.nmcli_available", return_value=True), \
         patch("utils.wifi_manager.subprocess.run",
               side_effect=subprocess.TimeoutExpired(cmd="nmcli", timeout=25)):
        ok, msg = wifi_manager.connect_wifi("HomeNet", "secret")
    assert ok is True and "HomeNet" in msg


# ---------------------------------------------------------------------------
# reachability
# ---------------------------------------------------------------------------
def test_get_reachable_addresses_shape():
    addr = wifi_manager.get_reachable_addresses()
    assert set(addr) == {"mdns", "ip", "port"}
    assert addr["mdns"].endswith(".local")
    assert addr["port"] == wifi_manager.DASHBOARD_PORT


def test_get_local_ip_skips_loopback():
    with patch("utils.wifi_manager.socket.socket") as sock:
        inst = sock.return_value
        inst.getsockname.return_value = ("127.0.0.1", 0)
        with patch("utils.wifi_manager.socket.gethostbyname", return_value="127.0.0.1"):
            assert wifi_manager.get_local_ip() is None
