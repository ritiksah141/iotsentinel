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


def _is_add(cmd):
    """True if a subprocess.run argv creates the home-Wi-Fi profile."""
    return cmd[:5] == ["sudo", "-n", "nmcli", "connection", "add"]


def _is_up(cmd):
    """True if a subprocess.run argv activates the home-Wi-Fi profile."""
    return cmd[:5] == ["sudo", "-n", "nmcli", "connection", "up"]


def test_connect_creates_autoconnect_profile_with_password():
    """The home profile is persisted (autoconnect yes) so the join survives a slow
    activation or a reboot — the fix for the rc6 'stranded after teardown' bug."""
    proc = MagicMock(returncode=0, stdout="", stderr="")
    with patch("utils.wifi_manager.nmcli_available", return_value=True), \
         patch("utils.wifi_manager.time.sleep"), \
         patch("utils.wifi_manager._iface_state", return_value="connected"), \
         patch("utils.wifi_manager.current_wifi", return_value="HomeNet"), \
         patch("utils.wifi_manager.teardown_setup_hotspot"), \
         patch("utils.wifi_manager.subprocess.run", return_value=proc) as run:
        ok, msg = wifi_manager.connect_wifi("HomeNet", "secret")
    assert ok is True and "HomeNet" in msg
    add = next((c[0][0] for c in run.call_args_list if _is_add(c[0][0])), None)
    assert add, "home profile was never created"
    assert "HomeNet" in add and "secret" in add
    assert "connection.autoconnect" in add and "yes" in add
    assert "wpa-psk" in add and "wifi-sec.psk" in add


def test_connect_open_network_omits_wifi_security():
    proc = MagicMock(returncode=0, stdout="", stderr="")
    with patch("utils.wifi_manager.nmcli_available", return_value=True), \
         patch("utils.wifi_manager.time.sleep"), \
         patch("utils.wifi_manager._iface_state", return_value="connected"), \
         patch("utils.wifi_manager.current_wifi", return_value="OpenCafe"), \
         patch("utils.wifi_manager.teardown_setup_hotspot"), \
         patch("utils.wifi_manager.subprocess.run", return_value=proc) as run:
        ok, _ = wifi_manager.connect_wifi("OpenCafe", "")
    assert ok is True
    add = next(c[0][0] for c in run.call_args_list if _is_add(c[0][0]))
    assert "wifi-sec.psk" not in add and "wpa-psk" not in add


def test_connect_saves_profile_before_tearing_down_hotspot():
    """The profile MUST be written BEFORE the AP comes down: writing it needs no radio,
    and saving it first means the credentials survive even if activation is cut off when
    wlan0 leaves the AP (so NM + a reboot can still complete the join)."""
    order = []
    proc = MagicMock(returncode=0, stdout="", stderr="")

    def fake_run(cmd, **kw):
        if _is_add(cmd):
            order.append("profile")
        elif _is_up(cmd):
            order.append("up")
        return proc

    with patch("utils.wifi_manager.nmcli_available", return_value=True), \
         patch("utils.wifi_manager.time.sleep"), \
         patch("utils.wifi_manager._iface_state", return_value="connected"), \
         patch("utils.wifi_manager.current_wifi", return_value="HomeNet"), \
         patch("utils.wifi_manager.teardown_setup_hotspot",
               side_effect=lambda *a, **k: order.append("teardown")), \
         patch("utils.wifi_manager.subprocess.run", side_effect=fake_run):
        ok, _ = wifi_manager.connect_wifi("HomeNet", "secret")
    assert ok is True
    assert order.index("profile") < order.index("teardown") < order.index("up")


def test_connect_retries_activation_until_connected():
    """The first activation often races the radio finishing its switch out of AP mode;
    a later attempt that confirms current_wifi == ssid must succeed."""
    up_results = [MagicMock(returncode=4, stdout="", stderr="Activation failed"),
                  MagicMock(returncode=0, stdout="", stderr="")]

    def fake_run(cmd, **kw):
        if _is_up(cmd):
            return up_results.pop(0)
        return MagicMock(returncode=0, stdout="", stderr="")

    with patch("utils.wifi_manager.nmcli_available", return_value=True), \
         patch("utils.wifi_manager.time.sleep"), \
         patch("utils.wifi_manager._iface_state", return_value="connected"), \
         patch("utils.wifi_manager.current_wifi", return_value="HomeNet"), \
         patch("utils.wifi_manager.teardown_setup_hotspot"), \
         patch("utils.wifi_manager.subprocess.run", side_effect=fake_run):
        ok, msg = wifi_manager.connect_wifi("HomeNet", "secret")
    assert ok is True and "HomeNet" in msg
    assert up_results == []          # both activation attempts were consumed


def test_connect_wrong_password_fails_fast():
    """A missing-secret error won't fix itself with retries — fail immediately with a
    password hint rather than spinning the whole retry window."""
    proc = MagicMock(returncode=4, stdout="",
                     stderr="Error: Secrets were required, but not provided.")
    with patch("utils.wifi_manager.nmcli_available", return_value=True), \
         patch("utils.wifi_manager.time.sleep"), \
         patch("utils.wifi_manager._iface_state", return_value="connected"), \
         patch("utils.wifi_manager.current_wifi", return_value=None), \
         patch("utils.wifi_manager.teardown_setup_hotspot"), \
         patch("utils.wifi_manager.subprocess.run", return_value=proc):
        ok, msg = wifi_manager.connect_wifi("HomeNet", "wrong")
    assert ok is False and "password" in msg.lower()


def test_connect_timeout_is_soft_success():
    def fake_run(cmd, **kw):
        if _is_up(cmd):
            raise subprocess.TimeoutExpired(cmd="nmcli", timeout=30)
        return MagicMock(returncode=0, stdout="", stderr="")

    with patch("utils.wifi_manager.nmcli_available", return_value=True), \
         patch("utils.wifi_manager.time.sleep"), \
         patch("utils.wifi_manager._iface_state", return_value="connected"), \
         patch("utils.wifi_manager.current_wifi", return_value=None), \
         patch("utils.wifi_manager.teardown_setup_hotspot"), \
         patch("utils.wifi_manager.subprocess.run", side_effect=fake_run):
        ok, msg = wifi_manager.connect_wifi("HomeNet", "secret")
    assert ok is True and "HomeNet" in msg


def test_connect_profile_not_deleted_on_failed_activation():
    """On activation failure the autoconnect profile must be LEFT in place so NM keeps
    retrying and a reboot recovers — only a stale same-named profile is removed up front."""
    deletes = []

    def fake_run(cmd, **kw):
        if cmd[:5] == ["sudo", "-n", "nmcli", "connection", "delete"]:
            deletes.append(cmd[-1])
        if _is_up(cmd):
            return MagicMock(returncode=4, stdout="", stderr="Activation failed")
        return MagicMock(returncode=0, stdout="", stderr="")

    with patch("utils.wifi_manager.nmcli_available", return_value=True), \
         patch("utils.wifi_manager.time.sleep"), \
         patch("utils.wifi_manager._iface_state", return_value="connected"), \
         patch("utils.wifi_manager.current_wifi", return_value=None), \
         patch("utils.wifi_manager.teardown_setup_hotspot"), \
         patch("utils.wifi_manager.subprocess.run", side_effect=fake_run):
        ok, msg = wifi_manager.connect_wifi("HomeNet", "secret")
    assert ok is False
    # The only delete is the pre-create cleanup of a stale same-named profile, never a
    # delete of the just-saved credentials after the join failed.
    assert deletes == ["HomeNet"]


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


def test_teardown_invokes_script_by_path_not_bash():
    """sudoers grants the exact script path; `sudo bash <script>` would be denied (and
    is a root hole). On success we must NOT also run the nmcli fallback."""
    proc = MagicMock(returncode=0, stdout="", stderr="")
    with patch("utils.wifi_manager.nmcli_available", return_value=True), \
         patch("utils.wifi_manager.Path.exists", return_value=True), \
         patch("utils.wifi_manager.subprocess.run", return_value=proc) as run:
        wifi_manager.teardown_setup_hotspot("wlan0")
    cmds = [c[0][0] for c in run.call_args_list]
    assert len(cmds) == 1, "successful disarm must not fall through to nmcli"
    assert cmds[0][:2] == ["sudo", "-n"] and "bash" not in cmds[0]
    assert cmds[0][-1] == "disarm" and cmds[0][2].endswith("setup_hotspot.sh")


def test_teardown_falls_back_to_nmcli_when_script_denied():
    """A non-zero exit (e.g. sudoers denial) must fall through to the direct nmcli
    delete — not silently return as if the hotspot were gone (the rc5 teardown bug)."""
    denied = MagicMock(returncode=1, stdout="", stderr="sudo: a password is required")
    ok = MagicMock(returncode=0, stdout="", stderr="")
    calls = []

    def fake_run(cmd, **kw):
        calls.append(cmd)
        return denied if cmd[2].endswith("setup_hotspot.sh") else ok

    with patch("utils.wifi_manager.nmcli_available", return_value=True), \
         patch("utils.wifi_manager.Path.exists", return_value=True), \
         patch("utils.wifi_manager.subprocess.run", side_effect=fake_run):
        wifi_manager.teardown_setup_hotspot("wlan0")
    # script attempt + nmcli down + nmcli delete
    assert any("connection" in c and "down" in c for c in calls)
    assert any("connection" in c and "delete" in c for c in calls)
