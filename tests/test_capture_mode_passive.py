"""utils.capture_mode.is_passive_wifi — drives the honest 'passive Wi-Fi' empty-states.
True only when monitoring passively on a Wi-Fi interface (the sparse-traffic mode)."""
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from utils import capture_mode


def _cfg(mode, iface):
    def fake_get(section, key, default=None):
        return {("network", "capture_mode"): mode,
                ("network", "interface"): iface}.get((section, key), default)
    return fake_get


def test_passive_wifi_true_on_wlan():
    with patch("config.config_manager.config.get", side_effect=_cfg("passive", "wlan0")):
        assert capture_mode.is_passive_wifi() is True


def test_gateway_mode_is_not_passive():
    with patch("config.config_manager.config.get", side_effect=_cfg("gateway", "wlan0")):
        assert capture_mode.is_passive_wifi() is False


def test_wired_passive_is_not_flagged():
    with patch("config.config_manager.config.get", side_effect=_cfg("passive", "eth0")):
        assert capture_mode.is_passive_wifi() is False


def test_note_text_mentions_gateway():
    assert "Gateway" in capture_mode.passive_traffic_note()
