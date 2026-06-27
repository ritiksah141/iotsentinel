#!/usr/bin/env python3
"""
Tests for utils.network_security_scorer.

Two windows are now maintained in device health:
  - SCORING window (72h default via network.online_window_hours): used for connectivity_score
    so a passive Wi-Fi client that only re-announces every few hours doesn't score as "offline".
  - DISPLAY window (30 min default via network.online_window_minutes): returned as
    devices_online for the "X/Y online" display label, reflecting devices active right now.

A device seen 48h ago should contribute to the connectivity SCORE (72h window) but NOT
appear in devices_online (30-min window) -- 22/22 online when devices are idle was misleading.
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


def test_device_seen_48h_ago_contributes_to_score_not_display(db):
    """48h-old device counts toward the connectivity SCORE (72h window) but is NOT
    shown as 'online' in the display label (30-min window).  This prevents the
    '22/22 online' mislead when all devices are idle but recently discovered."""
    _add_device(db, "192.168.8.10", hours_ago=48)
    health = NetworkSecurityScorer(db_manager=db)._calculate_device_health_score()
    assert health["total_devices"] == 1
    # Display count uses 30-min window: a 48h-old device should NOT show as online
    assert health["devices_online"] == 0
    # But the connectivity score should be healthy (72h scoring window sees it)
    assert health["connectivity_score"] > 0


def test_device_seen_recently_shows_online(db):
    """A device seen in the last few minutes shows up in devices_online (display label)."""
    _add_device(db, "192.168.8.12", hours_ago=0.1)  # 6 minutes ago
    health = NetworkSecurityScorer(db_manager=db)._calculate_device_health_score()
    assert health["total_devices"] == 1
    assert health["devices_online"] == 1


def test_long_absent_device_is_offline(db):
    """A device unseen for longer than the scoring window scores as offline."""
    _add_device(db, "192.168.8.11", hours_ago=200)  # ~8 days
    health = NetworkSecurityScorer(db_manager=db)._calculate_device_health_score()
    assert health["total_devices"] == 1
    assert health["devices_online"] == 0
    assert health["connectivity_score"] == 0


def test_no_devices_scores_full_health(db):
    health = NetworkSecurityScorer(db_manager=db)._calculate_device_health_score()
    assert health["score"] == 100
