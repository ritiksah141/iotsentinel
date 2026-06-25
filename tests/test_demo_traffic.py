#!/usr/bin/env python3
"""Tests for scripts/demo_traffic.py — the demo traffic generator that injects normal +
anomalous connections (processed=0) so the live inference engine raises real anomaly alerts
on the dashboard during a demonstration (no real attack traffic needed).

Run: pytest tests/test_demo_traffic.py -v
"""
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

_spec = importlib.util.spec_from_file_location("demo_traffic", ROOT / "scripts" / "demo_traffic.py")
dt = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dt)


def test_seed_injects_normal_and_anomalies(db):
    summary = dt.seed(db, devices=4, normal=30)
    assert summary["normal"] > 0
    assert summary["exfil"] > 0 and summary["scan"] > 0 and summary["beacon"] > 0

    cur = db.conn.cursor()
    total = cur.execute("SELECT COUNT(*) FROM connections").fetchone()[0]
    assert total == summary["normal"] + summary["exfil"] + summary["scan"] + summary["beacon"]


def test_injected_connections_are_unprocessed(db):
    """The inference engine only scores rows with processed=0 — verify the seed leaves them so."""
    dt.seed(db, devices=3, normal=10)
    unprocessed = db.get_unprocessed_connections(limit=1000)
    assert len(unprocessed) > 0


def test_exfil_rows_are_clearly_anomalous(db):
    """Exfil flows must be orders of magnitude above the baseline so River scores them high."""
    dt.seed(db, devices=3, normal=20)
    cur = db.conn.cursor()
    max_sent = cur.execute("SELECT MAX(bytes_sent) FROM connections").fetchone()[0]
    assert max_sent > 10_000_000  # tens of MB — far above normal browsing


def test_home_hosts_are_valid_ips():
    hosts = dt._home_hosts(5)
    assert len(hosts) == 5
    import ipaddress
    for h in hosts:
        ipaddress.ip_address(h)  # raises if invalid


def test_demo_seed_enabled_in_this_build():
    """This (demo) build seeds anomaly traffic at first boot with zero manual steps;
    the first-boot wrapper reads the same flag. (Set false for the public release.)"""
    import json
    cfg = json.loads((ROOT / "config" / "default_config.json").read_text())
    assert cfg.get("demo", {}).get("seed_traffic") is True
    wrapper = (ROOT / "scripts" / "run_model_eval.sh").read_text()
    assert "seed_traffic" in wrapper and "demo_traffic.py" in wrapper
