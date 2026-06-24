"""Tests for the Raspberry Pi ops scripts in config/.

Why this exists: scripts/setup_pi.sh wires three scripts into the shipped image
(Pi tuning, a Zeek watchdog, and Zeek log rotation) behind `[ -f ]` guards. When
those files were missing the guards silently skipped them, so the image lost real
functionality with no error. These tests pin that the files exist, are runnable,
and that every path setup_pi.sh references actually resolves.
"""

import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
CONFIG = ROOT / "config"

SCRIPTS = ["optimize_pi.sh", "zeek_monitor.sh", "zeek_cleanup.sh", "configure_zeek.sh"]


class TestPiScriptsPresent:
    def test_all_three_exist(self):
        for name in SCRIPTS:
            assert (CONFIG / name).is_file(), f"missing config/{name}"

    def test_all_executable(self):
        for name in SCRIPTS:
            assert os.access(CONFIG / name, os.X_OK), f"config/{name} not executable"

    def test_all_have_shebang(self):
        for name in SCRIPTS:
            first = (CONFIG / name).read_text().splitlines()[0]
            assert first.startswith("#!"), f"config/{name} missing shebang"

    def test_all_pass_bash_syntax_check(self):
        for name in SCRIPTS:
            r = subprocess.run(
                ["bash", "-n", str(CONFIG / name)],
                capture_output=True, text=True,
            )
            assert r.returncode == 0, f"config/{name} syntax error: {r.stderr}"


class TestSetupPiReferencesResolve:
    def test_every_guarded_path_exists(self):
        # Pull each `[ -f "$PROJECT_DIR/config/<x>.sh" ]` reference out of setup_pi.sh
        # and confirm the file is really there (no more silent skips).
        text = (ROOT / "scripts" / "setup_pi.sh").read_text()
        refs = re.findall(r'\$PROJECT_DIR/(config/[\w./-]+\.sh)', text)
        assert refs, "expected setup_pi.sh to reference config/*.sh scripts"
        for rel in set(refs):
            assert (ROOT / rel).is_file(), f"setup_pi.sh references missing {rel}"


class TestCleanupRetention:
    def test_cleanup_defines_retention_constant(self):
        assert "RETENTION_DAYS=" in (CONFIG / "zeek_cleanup.sh").read_text()

    def test_cleanup_never_touches_current_logs(self):
        # The live "current/" Zeek dir must be pruned from deletion.
        assert "current" in (CONFIG / "zeek_cleanup.sh").read_text()


class TestSetupHotspotScript:
    """setup_hotspot.sh arms/recovers the provisioning AP and (now) disarms it
    once the Pi joins home Wi-Fi, so wlan0 returns to client mode."""

    PATH = Path(__file__).parent.parent / "scripts" / "setup_hotspot.sh"

    def test_exists_and_syntax_ok(self):
        assert self.PATH.is_file(), "missing scripts/setup_hotspot.sh"
        r = subprocess.run(["bash", "-n", str(self.PATH)], capture_output=True, text=True)
        assert r.returncode == 0, f"setup_hotspot.sh syntax error: {r.stderr}"

    def test_supports_disarm_mode(self):
        text = self.PATH.read_text()
        assert "disarm)" in text, "setup_hotspot.sh must handle the 'disarm' mode"
        assert 'usage: setup_hotspot.sh [boot|recover|disarm]' in text

    def test_disarm_deletes_the_hotspot_connection(self):
        text = self.PATH.read_text()
        assert 'nmcli connection delete "$HOTSPOT"' in text
        assert 'nmcli connection down "$HOTSPOT"' in text

    def test_recover_disarms_lingering_hotspot_on_home_wifi(self):
        """Root-side backstop: when home Wi-Fi is up the recover timer must disarm a
        still-active setup hotspot (else wlan0 stays AP+client and the dashboard is
        reachable only on 10.42.0.1). Guards against a missed dashboard disarm."""
        text = self.PATH.read_text()
        recover = text.split("recover)", 1)[1].split("disarm)", 1)[0]
        # Inside the home-Wi-Fi branch we must call disarm_hotspot when one is active.
        assert "disarm_hotspot" in recover, \
            "recover) must tear down a lingering hotspot once on home Wi-Fi"

    def test_active_home_wifi_uses_valid_device_fields(self):
        """'nmcli device status' has NO 'NAME' field (that belongs to 'connection show').
        Querying NAME makes nmcli error and print nothing, so active_home_wifi ALWAYS
        reported 'offline' and the recovery timer re-armed the hotspot ~6 min after the
        Pi joined home Wi-Fi. Must use the real DEVICE/TYPE/STATE/CONNECTION fields."""
        text = self.PATH.read_text()
        fn = text.split("active_home_wifi()", 1)[1].split("\n}", 1)[0]
        assert "device status" in fn
        assert "NAME,TYPE,STATE device status" not in fn, \
            "NAME is not a valid 'device status' field — nmcli would error to empty"
        assert "DEVICE,TYPE,STATE,CONNECTION" in fn

    def test_boot_caches_wifi_scan_before_arming_ap(self):
        """A radio in AP mode can't scan, so boot must cache a Wi-Fi scan BEFORE arming
        the hotspot — that file is the wizard's only source of SSID suggestions."""
        text = self.PATH.read_text()
        assert "cache_wifi_scan()" in text, "cache_wifi_scan function not defined"
        # The boot-case arm-retry loop ("for attempt in 1 2 3") is unique to boot mode;
        # the scan must be cached before it runs.
        arm = text.index("for attempt in 1 2 3")
        assert text[:arm].rfind("cache_wifi_scan") != -1, \
            "boot must call cache_wifi_scan before arming the AP"

    def test_recover_nudges_saved_home_profile_before_arming(self):
        """Single-radio trap: once the AP is re-armed NM can never autoconnect, so while
        offline AND the radio is free, recover must first try to activate the wizard's
        saved home profile — and only arm the hotspot if that join fails."""
        text = self.PATH.read_text()
        assert "saved_home_profile" in text and "try_home_profile" in text
        recover = text.split("recover)", 1)[1].split("disarm)", 1)[0]
        # The nudge must run before the threshold counter / arm path.
        assert recover.index("try_home_profile") < recover.index("arm_hotspot"), \
            "must attempt the saved home profile before arming the setup hotspot"
