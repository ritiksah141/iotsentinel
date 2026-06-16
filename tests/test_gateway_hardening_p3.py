"""Phase 3 tests: gateway-mode hardening.

Covers the wizard AP-interface picker, the on-Pi validation script, the privileged
nft/iptables wrapper (so inline enforcement works as a non-root service), the
sudoers grants, and systemd ordering. The live AP/NAT path is validated on the Pi 4
by scripts/validate_gateway.sh.
"""

import os
import subprocess
from pathlib import Path
from unittest.mock import MagicMock

ROOT = Path(__file__).parent.parent
VALIDATE_SH = ROOT / "scripts" / "validate_gateway.sh"
SETUP_SH = ROOT / "scripts" / "setup_pi.sh"
BACKEND_SVC = ROOT / "services" / "iotsentinel-backend.service"
WIZARD = ROOT / "dashboard" / "layouts" / "setup_wizard.py"


# ── wizard AP-interface picker ──────────────────────────────────────────────────
class TestApInterfacePicker:
    def test_layout_has_ap_interface_select(self):
        assert 'id="setup-ap-interface"' in WIZARD.read_text()

    def test_save_config_persists_ap_interface(self, tmp_path, monkeypatch):
        # _save_config writes network.ap_interface only when gateway + password given.
        import dashboard.callbacks.callbacks_setup as cs
        writes = {}
        fake_cfg = MagicMock()
        fake_cfg.get.return_value = False  # is_configured -> not blocked
        fake_cfg.update.side_effect = lambda sec, key, val: writes.__setitem__((sec, key), val)
        monkeypatch.setattr(cs, "config", fake_cfg)
        monkeypatch.setattr(cs, "db_manager", MagicMock())
        monkeypatch.setattr(cs, "os", MagicMock(getenv=lambda *a, **k: "x", path=MagicMock(exists=lambda p: False)))
        ap_pw = "Wpa2Pass123"  # pragma: allowlist secret
        cs._save_config(
            "10.42.0.0/24", "wlan0", None, None, None, None, "household", None,
            capture_mode="gateway", ap_ssid="IoT", ap_password=ap_pw,
            ap_interface="wlan1")
        assert writes.get(("network", "capture_mode")) == "gateway"
        assert writes.get(("network", "ap_interface")) == "wlan1"


# ── validate_gateway.sh ─────────────────────────────────────────────────────────
class TestValidateGatewayScript:
    def test_present_executable_shebang_syntax(self):
        assert VALIDATE_SH.is_file()
        assert os.access(VALIDATE_SH, os.X_OK)
        assert VALIDATE_SH.read_text().splitlines()[0].startswith("#!")
        r = subprocess.run(["bash", "-n", str(VALIDATE_SH)], capture_output=True, text=True)
        assert r.returncode == 0, r.stderr

    def test_checks_the_critical_path(self):
        body = VALIDATE_SH.read_text()
        for token in ("iotsentinel-ap", "ip_forward", "masquerade",
                      "node.cfg", "capture_mode"):
            assert token in body, f"validate_gateway.sh missing check for '{token}'"


# ── privileged nft/iptables wrapper ─────────────────────────────────────────────
class TestPrivWrapper:
    def test_prefixes_sudo_when_non_root(self, monkeypatch):
        from utils import firewall_enforcer as fw
        monkeypatch.setattr(fw.os, "geteuid", lambda: 1000)
        assert fw._priv(["nft", "list", "ruleset"])[:2] == ["sudo", "-n"]

    def test_no_sudo_when_root(self, monkeypatch):
        from utils import firewall_enforcer as fw
        monkeypatch.setattr(fw.os, "geteuid", lambda: 0)
        assert fw._priv(["nft", "list"]) == ["nft", "list"]

    def test_block_issues_privileged_nft(self, monkeypatch):
        from utils import firewall_enforcer as fw
        monkeypatch.setattr(fw.os, "geteuid", lambda: 1000)
        monkeypatch.setattr(fw._LocalBackend, "_detect_nft", staticmethod(lambda: True))
        captured = []

        def fake_run(cmd, *a, **k):
            captured.append(cmd)
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        monkeypatch.setattr(fw.subprocess, "run", fake_run)
        backend = fw._LocalBackend()
        backend.block_ip("10.42.0.55")
        # at least one nft invocation must be elevated with sudo -n
        assert any(c[:2] == ["sudo", "-n"] and "nft" in c for c in captured), captured


# ── provisioning / sudoers / service ordering ───────────────────────────────────
class TestProvisioningHardening:
    def test_sudoers_grants_nft_iptables_zeekctl(self):
        body = SETUP_SH.read_text()
        for token in ("/usr/sbin/nft *", "/usr/sbin/iptables *", "/opt/zeek/bin/zeekctl deploy"):
            assert token in body, f"setup_pi.sh sudoers missing '{token}'"

    def test_dnsmasq_base_installed(self):
        assert "dnsmasq-base" in SETUP_SH.read_text()

    def test_backend_orders_after_networkmanager(self):
        assert "NetworkManager.service" in BACKEND_SVC.read_text()
