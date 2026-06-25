#!/usr/bin/env python3
"""
Tests for utils.network_security_scorer.

Focus: the device-health "online" window. A hard 24h cutoff was too aggressive for a
passive Wi-Fi client (devices re-announce via ARP/mDNS only every few hours), so on a
quiet network every device flipped to offline and the Network Security card read 0/N.
The window is now a configurable, more forgiving default (72h via
network.online_window_hours).

Run: pytest tests/test_network_security_scorer.py -v
"""

import sys
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.network_security_scorer import NetworkSecurityScorer


def _add_device(db, ip, hours_ago, firmware="1.0"):
    last_seen = (datetime.now() - timedelta(hours=hours_ago)).isoformat()
    db.conn.execute(
        "INSERT INTO devices (device_ip, device_name, firmware_version, last_seen) "
        "VALUES (?, ?, ?, ?)",
        (ip, f"Device {ip}", firmware, last_seen),
    )
    db.conn.commit()


def test_device_seen_48h_ago_is_online_under_default_window(db):
    """48h-old device counts as online (24h would have wrongly marked it offline)."""
    _add_device(db, "192.168.8.10", hours_ago=48)
    health = NetworkSecurityScorer(db_manager=db)._calculate_device_health_score()
    assert health["total_devices"] == 1
    assert health["devices_online"] == 1


def test_long_absent_device_is_offline(db):
    """A device unseen for longer than the window is still counted offline."""
    _add_device(db, "192.168.8.11", hours_ago=200)  # ~8 days
    health = NetworkSecurityScorer(db_manager=db)._calculate_device_health_score()
    assert health["total_devices"] == 1
    assert health["devices_online"] == 0


def test_no_devices_scores_full_health(db):
    health = NetworkSecurityScorer(db_manager=db)._calculate_device_health_score()
    assert health["score"] == 100
