"""Tests for scripts/seed_demo_alerts.py — the demo/showcase alert seeder.

Guards that the seed data is well-formed (valid severities, valid JSON top_features,
a MITRE tactic and a plain-English line on every alert) and that the seeder is
idempotent, so running it before a recording can never duplicate or corrupt data.
"""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scripts.seed_demo_alerts import seed, DEMO_ALERTS, DEMO_DEVICES, _demo_alerts_present

VALID_SEVERITIES = {"low", "medium", "high", "critical"}


def _all_demo(db):
    cur = db.conn.cursor()
    cur.execute("SELECT device_ip, severity, anomaly_score, top_features, plain_explanation, "
                "mitre_tactic FROM alerts WHERE top_features LIKE '%\"_demo\": true%'")
    return cur.fetchall()


def test_seed_inserts_all_demo_alerts(db):
    result = seed(db)
    assert result["skipped"] is False
    assert result["alerts"] == len(DEMO_ALERTS) == 6
    rows = _all_demo(db)
    assert len(rows) == 6


def test_seeded_alerts_are_wellformed(db):
    seed(db)
    for ip, severity, score, feats, plain, mitre in _all_demo(db):
        assert severity in VALID_SEVERITIES
        assert 0.0 <= score <= 1.0
        parsed = json.loads(feats)          # top_features must be valid JSON
        assert parsed.get("_demo") is True   # hidden marker for --reset
        assert plain and plain.strip()       # a plain-English safety-net line
        assert mitre                          # a MITRE tactic for the Attack-Path Sankey


def test_seed_covers_an_unknown_device_for_the_private_glyph(db):
    seed(db)
    types = {d[2] for d in DEMO_DEVICES}
    assert "unknown" in types, "keep one unknown device so the private glyph is shown"


def test_seed_is_idempotent_and_resettable(db):
    first = seed(db)
    assert first["alerts"] == 6
    # Second run without reset must not duplicate.
    second = seed(db)
    assert second["skipped"] is True
    assert len(_all_demo(db)) == 6
    # Reset removes the old ones and reinserts exactly the same count.
    third = seed(db, reset=True)
    assert third["skipped"] is False and third["removed"] == 6
    assert len(_all_demo(db)) == 6


def test_reset_only_touches_demo_alerts(db):
    # A real (non-demo) alert must survive a demo reset.
    db.add_device("10.0.0.9", device_name="Real Device")
    db.create_alert("10.0.0.9", "high", 0.9, "real technical explanation",
                    json.dumps({"real": 1}), plain_explanation="real plain")
    seed(db, reset=True)
    cur = db.conn.cursor()
    cur.execute("SELECT COUNT(*) FROM alerts WHERE device_ip = '10.0.0.9'")
    assert cur.fetchone()[0] == 1, "reset must not delete real alerts"
