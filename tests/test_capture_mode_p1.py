"""Phase 1 tests for the gateway-capture foundation.

Covers the safe, no-traffic-rerouting groundwork: the capture_mode config, the Zeek
interface-resolution precedence, the uplink_ok() probe, and the orchestrator
connectivity watchdog that auto-rolls-back gateway mode if the home Wi-Fi uplink drops.
"""

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

ROOT = Path(__file__).parent.parent
CFG_JSON = ROOT / "config" / "default_config.json"
ZEEK_SH = ROOT / "config" / "configure_zeek.sh"


# ── capture_mode config plumbing ────────────────────────────────────────────────
class TestCaptureModeConfig:
    def test_default_config_has_capture_mode_keys(self):
        net = json.loads(CFG_JSON.read_text())["network"]
        assert net["capture_mode"] == "passive"
        for key in ("ap_interface", "ap_ssid", "ap_subnet"):
            assert key in net, f"network.{key} missing from default_config.json"

    def test_configmanager_reads_capture_mode(self):
        from config.config_manager import ConfigManager
        cfg = ConfigManager(CFG_JSON)
        assert cfg.get("network", "capture_mode", default="passive") == "passive"

    def test_env_override_capture_mode(self, monkeypatch):
        # _override_with_env maps SECTION_KEY → value at construction time.
        monkeypatch.setenv("NETWORK_CAPTURE_MODE", "gateway")
        from config.config_manager import ConfigManager
        cfg = ConfigManager(CFG_JSON)
        assert cfg.get("network", "capture_mode") == "gateway"


# ── Zeek interface-resolution precedence ────────────────────────────────────────
def _resolve(net: dict) -> str:
    """Pure-Python mirror of the precedence embedded in configure_zeek.sh:
    monitor_interface > ap_interface (gateway) > interface."""
    mode = net.get("capture_mode") or "passive"
    iface = net.get("monitor_interface") or ""
    if not iface and mode == "gateway":
        iface = net.get("ap_interface") or ""
    if not iface:
        iface = net.get("interface") or ""
    return iface


class TestZeekInterfaceResolution:
    def test_passive_uses_interface(self):
        assert _resolve({"capture_mode": "passive", "interface": "wlan0",
                         "ap_interface": "wlan1", "monitor_interface": None}) == "wlan0"

    def test_gateway_uses_ap_interface(self):
        assert _resolve({"capture_mode": "gateway", "interface": "wlan0",
                         "ap_interface": "wlan1", "monitor_interface": None}) == "wlan1"

    def test_monitor_interface_wins(self):
        assert _resolve({"capture_mode": "gateway", "interface": "wlan0",
                         "ap_interface": "wlan1", "monitor_interface": "eth1"}) == "eth1"

    def test_script_encodes_precedence_and_existence_fallback(self):
        body = ZEEK_SH.read_text()
        for token in ("capture_mode", "ap_interface", "monitor_interface", "/sys/class/net/"):
            assert token in body, f"configure_zeek.sh no longer references {token}"


# ── uplink_ok() ─────────────────────────────────────────────────────────────────
class TestUplinkOk:
    def test_zero_loss_is_up(self, monkeypatch):
        # Regression: 0.0% loss is the BEST case and must read as "up" (the `or`
        # idiom previously misread 0.0 as missing → false "down").
        import utils.network_monitor as nm
        monkeypatch.setattr(nm, "ping_device",
                            lambda *a, **k: {"avg_latency_ms": 10.0, "packet_loss_percent": 0.0})
        assert nm.uplink_ok() is True

    def test_all_hosts_unreachable_is_down(self, monkeypatch):
        import utils.network_monitor as nm
        monkeypatch.setattr(nm, "ping_device",
                            lambda *a, **k: {"avg_latency_ms": None, "packet_loss_percent": 100.0})
        assert nm.uplink_ok() is False

    def test_none_result_is_down(self, monkeypatch):
        import utils.network_monitor as nm
        monkeypatch.setattr(nm, "ping_device", lambda *a, **k: None)
        assert nm.uplink_ok() is False

    def test_second_host_recovers(self, monkeypatch):
        import utils.network_monitor as nm
        calls = {"n": 0}

        def fake(host, *a, **k):
            calls["n"] += 1
            return None if calls["n"] == 1 else {"packet_loss_percent": 0.0}

        monkeypatch.setattr(nm, "ping_device", fake)
        assert nm.uplink_ok(("1.1.1.1", "8.8.8.8")) is True


# ── orchestrator connectivity watchdog ──────────────────────────────────────────
def _bare_orchestrator():
    """Build an orchestrator without running its heavy __init__."""
    from orchestrator import IoTSentinelOrchestrator
    return IoTSentinelOrchestrator.__new__(IoTSentinelOrchestrator)


class TestUplinkWatchdog:
    def test_passive_mode_is_noop(self, monkeypatch):
        import orchestrator as orch
        monkeypatch.setattr(orch.config, "get", lambda *a, **k: "passive")
        o = _bare_orchestrator()
        o._rollback_gateway = MagicMock()
        o._check_uplink_watchdog()
        o._rollback_gateway.assert_not_called()
        assert o._uplink_fail_count == 0

    def test_gateway_down_rolls_back(self, monkeypatch):
        import orchestrator as orch
        import utils.network_monitor as nm
        monkeypatch.setattr(orch.config, "get", lambda *a, **k: "gateway")
        monkeypatch.setattr(nm, "uplink_ok", lambda *a, **k: False)
        monkeypatch.setattr(orch.time, "sleep", lambda *_a, **_k: None)
        o = _bare_orchestrator()
        o._rollback_gateway = MagicMock()
        o._check_uplink_watchdog()
        o._rollback_gateway.assert_called_once()
        assert o._uplink_fail_count == 1

    def test_gateway_up_no_rollback(self, monkeypatch):
        import orchestrator as orch
        import utils.network_monitor as nm
        monkeypatch.setattr(orch.config, "get", lambda *a, **k: "gateway")
        monkeypatch.setattr(nm, "uplink_ok", lambda *a, **k: True)
        monkeypatch.setattr(orch.time, "sleep", lambda *_a, **_k: None)
        o = _bare_orchestrator()
        o._rollback_gateway = MagicMock()
        o._uplink_fail_count = 2
        o._check_uplink_watchdog()
        o._rollback_gateway.assert_not_called()
        assert o._uplink_fail_count == 0

    def test_sleep_returns_immediately_once_shutdown_signalled(self):
        import threading
        import time as _t
        o = _bare_orchestrator()
        o._shutdown_event = threading.Event()
        o._shutdown_event.set()
        t0 = _t.time()
        assert o._sleep(5) is True          # event already set → no real sleep
        assert _t.time() - t0 < 1.0

    def test_sleep_falls_back_when_event_missing(self, monkeypatch):
        import orchestrator as orch
        o = _bare_orchestrator()            # __new__ → no _shutdown_event
        recorded = {}
        monkeypatch.setattr(orch.time, "sleep", lambda s: recorded.__setitem__("s", s))
        assert o._sleep(2) is False
        assert recorded["s"] == 2

    def test_rollback_is_safe_without_ap_manager(self):
        # ap_manager doesn't exist yet (Phase 2); rollback must not raise and should
        # still raise a best-effort system alert.
        o = _bare_orchestrator()
        o.alerting = MagicMock()
        o._rollback_gateway("test reason")  # must not raise
        o.alerting.create_alert.assert_called_once()
