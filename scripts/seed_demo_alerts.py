#!/usr/bin/env python3
"""Seed realistic security alerts for demos / the showcase video.

Real IoT devices rarely misbehave on cue, and you cannot wait for a genuine attack
while recording. This inserts a small set of believable alerts (varied severity +
MITRE tactic + device type) so the dashboard has data to show — the Alerts feed, the
Attack-Path Sankey, incident correlation, and especially the AI *plain-English*
explanation feature.

How the AI plain-English showcase works with this seed:
  * Each alert is inserted with a technical `explanation` and a hand-written plain
    safety-net line, with plain_explanation_ai = 0.
  * The running app's background worker (orchestrator._plain_english_loop) selects
    alerts WHERE plain_explanation_ai = 0 and rewrites each with the real LLM
    (Groq / Ollama), so within a minute the plain text becomes genuine AI output and
    the source badge flips to "Groq AI".
  * The alert-detail "Explain in plain English" button regenerates on demand for a
    live, on-camera AI call.

Idempotent: every seeded alert carries a hidden ``"_demo": true`` marker in its
top_features JSON, so ``--reset`` removes only the demo data, never real alerts.

Usage:
  python scripts/seed_demo_alerts.py            # insert (skips if demo alerts exist)
  python scripts/seed_demo_alerts.py --reset    # remove previous demo data, reinsert
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from database.db_manager import DatabaseManager

# Demo devices live in the high end of the DHCP range so they are easy to spot and
# unlikely to collide with a real lease. One is deliberately an 'unknown' type so the
# private-device (padlock) glyph is shown too.
DEMO_DEVICES = [
    ("192.168.1.201", "Living Room Camera", "security camera", "Wyze"),
    ("192.168.1.202", "Kitchen Smart Plug", "smart plug", "TP-Link"),
    ("192.168.1.203", "Bedroom Smart TV", "smart tv", "Samsung"),
    ("192.168.1.204", None, "unknown", None),
    ("192.168.1.205", "Hallway Thermostat", "thermostat", "Nest"),
    ("192.168.1.206", "Front Door Doorbell", "doorbell", "Ring"),
]

# (ip, severity, anomaly_score, mitre_tactic, top_features(dict), technical, plain, hours_ago)
DEMO_ALERTS = [
    ("192.168.1.201", "high", 0.88, "Exfiltration",
     {"outbound_bytes": 0.84, "new_destination_asn": 0.77, "off_hours_activity": 0.63},
     "Outbound volume 41x 7-day baseline (238 MB) to a first-seen destination ASN in a "
     "country this device has never contacted; transfer occurred 02:40-03:10 local.",
     "Your Living Room Camera sent an unusually large amount of video to an unfamiliar "
     "server overseas in the middle of the night. This can mean the camera feed is being "
     "copied off your network.",
     2),
    ("192.168.1.202", "medium", 0.71, "Discovery",
     {"internal_fanout": 0.79, "port_sweep": 0.7, "conn_rate": 0.61},
     "Contacted 38 distinct internal hosts on tcp/80 and tcp/443 within 60s "
     "(horizontal scan); no prior internal fan-out in baseline.",
     "Your Kitchen Smart Plug suddenly tried to reach dozens of other devices in your "
     "home very fast, as if it was mapping your network. A plug should never do this.",
     6),
    ("192.168.1.203", "low", 0.55, "Collection",
     {"tracker_domain_rate": 0.58, "dns_entropy": 0.44},
     "Connection rate to advertising and telemetry domains rose 6x versus baseline over "
     "the last hour.",
     "Your Bedroom Smart TV is contacting far more tracking and advertising servers than "
     "usual. It is not dangerous, but the TV is sharing more about what you watch.",
     10),
    ("192.168.1.204", "critical", 0.97, "Credential Access",
     {"failed_auth_rate": 0.95, "target_admin_iface": 0.9, "brute_force_pattern": 0.88},
     "142 failed authentications against the router admin interface (192.168.1.1) in 5 "
     "minutes from an unclassified device; consistent with a password brute-force.",
     "An unrecognized device is rapidly guessing your router's password. If it succeeds "
     "it could take control of your entire home network.",
     1),
    ("192.168.1.205", "high", 0.85, "Command and Control",
     {"beacon_regularity": 0.86, "low_rep_destination": 0.8, "stale_firmware": 0.66},
     "Regular 30s beacon to a low-reputation host (jitter < 3%); device firmware is 3 "
     "years out of date with known CVEs.",
     "Your Hallway Thermostat is checking in with a suspicious server on a fixed timer. "
     "That steady heartbeat is a pattern hijacked devices use while waiting for orders.",
     14),
    ("192.168.1.206", "medium", 0.68, "Impact",
     {"outbound_spike": 0.74, "lan_unreachable": 0.6},
     "Outbound traffic 12x normal while the device stopped answering LAN pings for 4 "
     "minutes; possible resource abuse or takeover.",
     "Your Front Door Doorbell suddenly sent far more data than normal and stopped "
     "responding on your local network, which can mean it is overloaded or misused.",
     22),
]

_DEMO_MARKER = '"_demo": true'


def _reset(db: DatabaseManager) -> int:
    """Delete previously seeded demo alerts (identified by the hidden marker)."""
    with db._write_lock:
        cur = db.conn.cursor()
        cur.execute("DELETE FROM alerts WHERE top_features LIKE ?", (f"%{_DEMO_MARKER}%",))
        removed = cur.rowcount
        db.conn.commit()
    return removed


def _demo_alerts_present(db: DatabaseManager) -> int:
    cur = db.conn.cursor()
    cur.execute("SELECT COUNT(*) FROM alerts WHERE top_features LIKE ?", (f"%{_DEMO_MARKER}%",))
    return cur.fetchone()[0]


def seed(db: DatabaseManager, reset: bool = False) -> dict:
    """Insert the demo devices + alerts. Returns a small summary dict."""
    removed = _reset(db) if reset else 0
    if not reset and _demo_alerts_present(db):
        return {"skipped": True, "reason": "demo alerts already present (use --reset)"}

    for ip, name, dtype, maker in DEMO_DEVICES:
        db.add_device(ip, device_name=name, device_type=dtype, manufacturer=maker)

    now = datetime.now()
    created = []
    for ip, severity, score, tactic, feats, tech, plain, hours_ago in DEMO_ALERTS:
        feats = {**feats, "_demo": True}
        alert_id = db.create_alert(
            device_ip=ip, severity=severity, anomaly_score=score,
            explanation=tech, top_features=json.dumps(feats),
            plain_explanation=plain, mitre_tactic=tactic,
        )
        if alert_id:
            # Spread timestamps so the "alerts by day" chart and recency sort look real.
            ts = (now - timedelta(hours=hours_ago)).strftime("%Y-%m-%d %H:%M:%S")
            with db._write_lock:
                db.conn.execute("UPDATE alerts SET timestamp = ? WHERE id = ?", (ts, alert_id))
                db.conn.commit()
            created.append(alert_id)

    return {"skipped": False, "removed": removed, "devices": len(DEMO_DEVICES),
            "alerts": len(created), "ids": created}


def main() -> int:
    ap = argparse.ArgumentParser(description="Seed demo security alerts for the video/showcase.")
    ap.add_argument("--reset", action="store_true",
                    help="Remove previously seeded demo alerts before inserting.")
    ap.add_argument("--db", default=str(Path(__file__).resolve().parent.parent
                                        / "data" / "database" / "iotsentinel.db"),
                    help="Path to the IoTSentinel SQLite database.")
    args = ap.parse_args()

    db = DatabaseManager(args.db)
    result = seed(db, reset=args.reset)
    if result.get("skipped"):
        print(f"Nothing to do: {result['reason']}.")
        return 0
    print(f"Seeded {result['alerts']} demo alerts across {result['devices']} devices "
          f"(removed {result['removed']} old). The app's background worker will rewrite "
          f"each plain-English line with the real LLM shortly after startup.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
