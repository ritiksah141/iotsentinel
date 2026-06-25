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


def test_capture_mode_name_reads_config():
    with patch("config.config_manager.config.get", side_effect=_cfg("gateway", "wlan0")):
        assert capture_mode.capture_mode_name() == "gateway"
    with patch("config.config_manager.config.get", side_effect=_cfg("passive", "wlan0")):
        assert capture_mode.capture_mode_name() == "passive"


def test_readme_marks_gateway_only_features():
    """Honesty guard: the README comparison must flag the traffic-derived features as
    Gateway-mode (the 'G' marker) and carry the per-mode capability matrix, so passive
    mode is never presented as delivering per-device traffic analysis/ML/IPS."""
    readme = (Path(__file__).parent.parent / "README.md").read_text(encoding="utf-8")
    assert "Gateway mode" in readme
    assert "What each mode delivers" in readme  # the capability matrix
    # The traffic/ML/IPS rows must carry the Gateway marker, not read as flat "Yes".
    for feature in ("Traffic analysis", "Unsupervised ML", "Autonomous IDS/IPS"):
        # marker char appears on the same line as the feature label
        line = next(l for l in readme.splitlines() if feature in l and l.strip().startswith("|"))
        assert "ᴳ" in line, f"{feature} row must be tagged Gateway-mode"
