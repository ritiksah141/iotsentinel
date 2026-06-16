"""Phase 2 tests for gateway / access-point mode.

Covers the AP bring-up script, the ap_manager wrapper, the orchestrator wiring, and
the gateway-aware firewall failsafe. The live AP/NAT/Zeek path is hardware-bound and
validated on the Pi 4 (Phase 3); here we verify the logic, safety, and config.
"""

import os
import subprocess
from pathlib import Path
from unittest.mock import MagicMock

ROOT = Path(__file__).parent.parent
AP_SH = ROOT / "config" / "configure_ap.sh"


# ── configure_ap.sh ─────────────────────────────────────────────────────────────
class TestConfigureApScript:
    def test_present_executable_shebang(self):
        assert AP_SH.is_file()
        assert os.access(AP_SH, os.X_OK)
        assert AP_SH.read_text().splitlines()[0].startswith("#!")

    def test_bash_syntax(self):
        r = subprocess.run(["bash", "-n", str(AP_SH)], capture_output=True, text=True)
        assert r.returncode == 0, r.stderr

    def test_uses_nm_shared_mode_and_down_path(self):
        body = AP_SH.read_text()
        for token in ("ipv4.method shared", "wifi-sec.key-mgmt wpa-psk",
                      "802-11-wireless.mode ap", "--down", "iotsentinel-ap"):
            assert token in body, f"configure_ap.sh missing '{token}'"

    def test_only_starts_in_gateway_mode(self):
        # Guard: the script must refuse to start unless capture_mode == gateway.
        assert '!= "gateway"' in AP_SH.read_text()

    def test_refuses_weak_password(self):
        assert "-lt 8" in AP_SH.read_text()


# ── ap_manager ──────────────────────────────────────────────────────────────────
class TestApManager:
    def test_passive_is_disabled_and_start_noops(self, monkeypatch):
        from utils import ap_manager
        ap = ap_manager.AccessPointManager()
        monkeypatch.setattr(ap, "is_enabled", lambda: False)
        ap._run = MagicMock()
        assert ap.start() is False
        ap._run.assert_not_called()

    def test_gateway_start_invokes_script(self, monkeypatch):
        from utils import ap_manager
        ap = ap_manager.AccessPointManager()
        monkeypatch.setattr(ap, "is_enabled", lambda: True)
        ap._run = MagicMock(return_value=True)
        assert ap.start() is True
        ap._run.assert_called_once_with()

    def test_stop_calls_down(self):
        from utils import ap_manager
        ap = ap_manager.AccessPointManager()
        ap._run = MagicMock(return_value=True)
        assert ap.stop() is True
        ap._run.assert_called_once_with("--down")

    def test_run_success_and_failure(self, monkeypatch):
        from utils import ap_manager
        ap = ap_manager.AccessPointManager()

        ok = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        monkeypatch.setattr(ap_manager.subprocess, "run", lambda *a, **k: ok)
        assert ap._run() is True

        bad = subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="boom")
        monkeypatch.setattr(ap_manager.subprocess, "run", lambda *a, **k: bad)
        assert ap._run() is False

    def test_run_never_raises(self, monkeypatch):
        from utils import ap_manager
        ap = ap_manager.AccessPointManager()
        monkeypatch.setattr(ap_manager.subprocess, "run",
                            lambda *a, **k: (_ for _ in ()).throw(OSError("nope")))
        assert ap._run() is False  # swallowed, not raised


# ── orchestrator AP wiring ──────────────────────────────────────────────────────
def _bare_orchestrator():
    from orchestrator import IoTSentinelOrchestrator
    return IoTSentinelOrchestrator.__new__(IoTSentinelOrchestrator)


class TestOrchestratorApWiring:
    def test_passive_skips_ap(self, monkeypatch):
        import orchestrator as orch
        monkeypatch.setattr(orch.config, "get", lambda *a, **k: "passive")
        o = _bare_orchestrator()
        # Should return without importing/starting the AP — no exception either.
        o._ensure_ap_configured()

    def test_gateway_starts_ap_and_checks_uplink(self, monkeypatch):
        import orchestrator as orch
        import utils.ap_manager as apm
        import utils.network_monitor as nm
        monkeypatch.setattr(orch.config, "get", lambda *a, **k: "gateway")
        fake_ap = MagicMock()
        fake_ap.start.return_value = True
        monkeypatch.setattr(apm, "AccessPointManager", lambda: fake_ap)
        monkeypatch.setattr(nm, "uplink_ok", lambda *a, **k: True)
        o = _bare_orchestrator()
        o._rollback_gateway = MagicMock()
        o._ensure_ap_configured()
        fake_ap.start.assert_called_once()
        o._rollback_gateway.assert_not_called()  # uplink healthy → no rollback

    def test_gateway_rolls_back_when_uplink_dies(self, monkeypatch):
        import orchestrator as orch
        import utils.ap_manager as apm
        import utils.network_monitor as nm
        monkeypatch.setattr(orch.config, "get", lambda *a, **k: "gateway")
        fake_ap = MagicMock()
        fake_ap.start.return_value = True
        monkeypatch.setattr(apm, "AccessPointManager", lambda: fake_ap)
        monkeypatch.setattr(nm, "uplink_ok", lambda *a, **k: False)
        o = _bare_orchestrator()
        o._rollback_gateway = MagicMock()
        o._ensure_ap_configured()
        o._rollback_gateway.assert_called_once()  # AP broke uplink → rolled back


# ── gateway-aware firewall failsafe ─────────────────────────────────────────────
class TestFirewallGatewayFailsafe:
    def test_ap_gateway_ip_default(self):
        from utils import firewall_enforcer as fw
        assert fw._ap_gateway_ip() == "10.42.0.1"

    def test_passive_whitelist_keeps_rfc1918_blanket(self, monkeypatch):
        from utils import firewall_enforcer as fw
        monkeypatch.setattr(fw, "_capture_mode", lambda: "passive")
        nets = fw._failsafe_accept_nets()
        assert "10.0.0.0/8" in nets
        assert "10.42.0.1/32" not in nets

    def test_gateway_whitelist_makes_iot_subnet_blockable(self, monkeypatch):
        from utils import firewall_enforcer as fw
        monkeypatch.setattr(fw, "_capture_mode", lambda: "gateway")
        nets = fw._failsafe_accept_nets()
        # The IoT segment must NOT be blanket-accepted, or devices can't be blocked.
        assert "10.0.0.0/8" not in nets
        # ...but the Pi's own AP gateway must stay protected.
        assert "10.42.0.1/32" in nets

    def test_ap_gateway_is_protected_but_devices_are_not(self):
        from utils import firewall_enforcer as fw
        assert fw._is_protected_ip("10.42.0.1") is True       # the Pi/AP gateway
        assert fw._is_protected_ip("10.42.0.55") is False     # an IoT device → blockable
