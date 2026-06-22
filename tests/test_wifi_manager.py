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
         patch("utils.wifi_manager.teardown_setup_hotspot") as teardown, \
         patch("utils.wifi_manager.subprocess.run", return_value=proc) as run:
        ok, msg = wifi_manager.connect_wifi("HomeNet", "secret")
    assert ok is True
    cmd = run.call_args_list[0][0][0]   # the connect call (teardown is mocked out)
    assert cmd[:5] == ["sudo", "nmcli", "dev", "wifi", "connect"]
    assert "password" in cmd and "secret" in cmd
    assert "HomeNet" in msg
    teardown.assert_called_once()        # hotspot is torn down on success


def test_connect_timeout_tears_down_hotspot():
    with patch("utils.wifi_manager.nmcli_available", return_value=True), \
         patch("utils.wifi_manager.teardown_setup_hotspot") as teardown, \
         patch("utils.wifi_manager.subprocess.run",
               side_effect=subprocess.TimeoutExpired(cmd="nmcli", timeout=25)):
        ok, _ = wifi_manager.connect_wifi("HomeNet", "secret")
    assert ok is True
    teardown.assert_called_once()


def test_connect_failure_surfaces_stderr():
    proc = MagicMock(returncode=4, stdout="", stderr="Secrets were required but not provided")
    with patch("utils.wifi_manager.nmcli_available", return_value=True), \
         patch("utils.wifi_manager.subprocess.run", return_value=proc):
        ok, msg = wifi_manager.connect_wifi("HomeNet", "wrong")
    assert ok is False and "Secrets" in msg


def test_connect_timeout_is_soft_success():
    with patch("utils.wifi_manager.nmcli_available", return_value=True), \
         patch("utils.wifi_manager.teardown_setup_hotspot"), \
         patch("utils.wifi_manager.subprocess.run",
               side_effect=subprocess.TimeoutExpired(cmd="nmcli", timeout=25)):
        ok, msg = wifi_manager.connect_wifi("HomeNet", "secret")
    assert ok is True and "HomeNet" in msg


# ---------------------------------------------------------------------------
# teardown_setup_hotspot
# ---------------------------------------------------------------------------
def test_teardown_noop_without_nmcli():
    with patch("utils.wifi_manager.nmcli_available", return_value=False), \
         patch("utils.wifi_manager.subprocess.run") as run:
        wifi_manager.teardown_setup_hotspot()
    run.assert_not_called()


def test_teardown_invokes_disarm_script():
    proc = MagicMock(returncode=0, stdout="", stderr="")
    with patch("utils.wifi_manager.nmcli_available", return_value=True), \
         patch("utils.wifi_manager.subprocess.run", return_value=proc) as run:
        wifi_manager.teardown_setup_hotspot()
    cmd = run.call_args_list[0][0][0]
    assert "setup_hotspot.sh" in " ".join(cmd) and cmd[-1] == "disarm"


# ---------------------------------------------------------------------------
# set_country (Wi-Fi regulatory region)
# ---------------------------------------------------------------------------
def test_set_country_rejects_invalid_code():
    ok, msg = wifi_manager.set_country("USA")   # not 2-letter
    assert ok is False and "country" in msg.lower()
    ok, msg = wifi_manager.set_country("")
    assert ok is False


def test_set_country_applies_and_persists(tmp_path):
    calls = []
    fake_env = tmp_path / ".env"

    def fake_run(cmd, **kw):
        calls.append(cmd)
        return MagicMock(returncode=0, stdout="", stderr="")

    with patch("utils.wifi_manager.shutil.which", return_value="/usr/sbin/iw"), \
         patch("utils.wifi_manager.subprocess.run", side_effect=fake_run), \
         patch("utils.wifi_manager.Path") as PathMock:
        PathMock.return_value.resolve.return_value.parent.parent = tmp_path
        ok, msg = wifi_manager.set_country("us")   # lowercase -> normalised
    assert ok is True
    # applied via iw reg set with the upper-cased code
    assert any("iw" in c and "US" in c for c in calls)
    assert fake_env.read_text().strip() == "IOTSENTINEL_WIFI_COUNTRY=US"


def test_country_options_are_valid_codes():
    assert ("GB", "United Kingdom") in wifi_manager.COUNTRY_OPTIONS
    for code, name in wifi_manager.COUNTRY_OPTIONS:
        assert len(code) == 2 and code.isupper() and name


# ---------------------------------------------------------------------------
# reachability
# ---------------------------------------------------------------------------
def test_get_reachable_addresses_shape():
    addr = wifi_manager.get_reachable_addresses()
    assert set(addr) == {"mdns", "ip", "port", "remote"}
    assert addr["mdns"].endswith(".local")
    assert addr["port"] == wifi_manager.DASHBOARD_PORT


def test_get_reachable_addresses_includes_remote_url():
    with patch.dict("os.environ", {"IOTSENTINEL_PUBLIC_URL": "https://demo.ts.net"}):
        addr = wifi_manager.get_reachable_addresses()
    assert addr["remote"] == "https://demo.ts.net"


def test_scan_falls_back_to_cached_when_rescan_empty():
    cached = "HomeNet:80:WPA2\n"

    def fake_run(cmd, **kw):
        # First call (rescan yes) returns nothing; second (rescan no) returns cache.
        rescan = cmd[cmd.index("--rescan") + 1]
        return MagicMock(stdout=cached if rescan == "no" else "")

    with patch("utils.wifi_manager.nmcli_available", return_value=True), \
         patch("utils.wifi_manager.subprocess.run", side_effect=fake_run):
        opts = wifi_manager.scan_wifi_networks()
    assert [o["value"] for o in opts] == ["HomeNet"]


def test_get_local_ip_skips_loopback():
    with patch("utils.wifi_manager.socket.socket") as sock:
        inst = sock.return_value
        inst.getsockname.return_value = ("127.0.0.1", 0)
        with patch("utils.wifi_manager.socket.gethostbyname", return_value="127.0.0.1"):
            assert wifi_manager.get_local_ip() is None
