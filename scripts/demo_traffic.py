#!/usr/bin/env python3
"""
Demo traffic generator — inject realistic connections so the live anomaly pipeline fires.

For a demonstration where the Pi runs as a passive Wi-Fi client (and therefore sees little
real device traffic), this seeds the `connections` table with a believable mix of normal
flows plus deliberate anomalies (data exfiltration, a port scan, C2 beaconing). The
running inference engine picks up the unprocessed rows, scores them with River ML, and
raises anomaly alerts — so the dashboard shows live activity, anomaly index movement, and
alerts on camera without any real attack traffic.

Connections are inserted via the normal `DatabaseManager.add_connection` path (processed=0),
exactly as the Zeek parser would, so nothing about the detection path is faked.

Usage:
  python scripts/demo_traffic.py [--seed] [--continuous] [--interval 20]
                                 [--devices 6] [--normal 200] [--db PATH]
"""
from __future__ import annotations

import argparse
import ipaddress
import random
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

# Public TEST-NET ranges (RFC 5737) — safe, non-routable example destinations.
_EXT_IPS = [f"203.0.113.{i}" for i in range(2, 60)] + [f"198.51.100.{i}" for i in range(2, 60)]
_COMMON_PORTS = [443, 443, 443, 80, 53, 123, 993]


def _home_hosts(n: int) -> list[str]:
    """Pick n host IPs from the monitored home subnet (falls back to 192.168.1.0/24)."""
    cidr = "192.168.1.0/24"
    try:
        from config.config_manager import config
        nets = config.get_section("network").get("local_networks") or []
        if nets and "/" in str(nets[0]):
            ipaddress.ip_network(nets[0], strict=False)  # validate
            cidr = nets[0]
    except Exception:
        pass
    net = ipaddress.ip_network(cidr, strict=False)
    hosts = [str(h) for h in list(net.hosts())[10:10 + max(n, 1) * 4]]
    return hosts[:n] if hosts else ["192.168.1.50"]


def _normal(db, devices: list[str], count: int) -> int:
    """Baseline browsing/IoT chatter so River learns 'normal' before the anomalies."""
    added = 0
    for _ in range(count):
        dev = random.choice(devices)
        port = random.choice(_COMMON_PORTS)
        sent = random.randint(200, 6000)
        recv = random.randint(500, 40000)
        try:
            db.add_connection(dev, random.choice(_EXT_IPS), port, "tcp" if port != 53 else "udp",
                              bytes_sent=sent, bytes_received=recv,
                              duration=random.randint(0, 8),
                              packets_sent=random.randint(2, 30),
                              packets_received=random.randint(2, 40),
                              conn_state="SF")
            added += 1
        except Exception:
            pass
    return added


def _anomalies(db, devices: list[str]) -> dict:
    """Three classic IoT attack signatures, deliberately far from the baseline."""
    counts = {"exfil": 0, "scan": 0, "beacon": 0}
    exfil_dev, scan_dev, beacon_dev = (devices + devices)[:3]
    sink = random.choice(_EXT_IPS)

    # Data exfiltration: sustained, very large outbound transfers.
    for _ in range(5):
        try:
            db.add_connection(exfil_dev, sink, 443, "tcp",
                              bytes_sent=random.randint(40_000_000, 120_000_000),
                              bytes_received=random.randint(2000, 9000),
                              duration=random.randint(60, 240),
                              packets_sent=random.randint(4000, 12000),
                              packets_received=random.randint(40, 120),
                              conn_state="SF")
            counts["exfil"] += 1
        except Exception:
            pass

    # Port scan: many tiny one-shot connections across sequential ports.
    for port in range(20, 20 + 40):
        try:
            db.add_connection(scan_dev, random.choice(_EXT_IPS), port, "tcp",
                              bytes_sent=random.randint(0, 60), bytes_received=0,
                              duration=0, packets_sent=1, packets_received=0,
                              conn_state="S0")
            counts["scan"] += 1
        except Exception:
            pass

    # C2 beaconing: regular, identical small callbacks to one host on a high port.
    for _ in range(12):
        try:
            db.add_connection(beacon_dev, sink, 8443, "tcp",
                              bytes_sent=512, bytes_received=256, duration=1,
                              packets_sent=4, packets_received=3, conn_state="SF")
            counts["beacon"] += 1
        except Exception:
            pass
    return counts


def seed(db, devices: int = 6, normal: int = 200) -> dict:
    """Inject one batch: a normal baseline followed by the three anomaly types.
    Returns a summary dict. The running inference engine scores the rows next cycle."""
    hosts = _home_hosts(devices)
    n_added = _normal(db, hosts, normal)
    anom = _anomalies(db, hosts)
    return {"devices": len(hosts), "normal": n_added, **anom}


def main() -> int:
    ap = argparse.ArgumentParser(description="Inject demo traffic so live anomalies fire.")
    ap.add_argument("--seed", action="store_true", help="Inject one batch and exit")
    ap.add_argument("--continuous", action="store_true", help="Keep injecting batches")
    ap.add_argument("--interval", type=int, default=20, help="Seconds between batches (continuous)")
    ap.add_argument("--devices", type=int, default=6)
    ap.add_argument("--normal", type=int, default=200)
    ap.add_argument("--db", default=str(REPO / "data" / "database" / "iotsentinel.db"))
    args = ap.parse_args()

    from database.db_manager import DatabaseManager
    db = DatabaseManager(args.db)

    def _run():
        s = seed(db, devices=args.devices, normal=args.normal)
        print(f"Injected: {s['normal']} normal, {s['exfil']} exfil, {s['scan']} scan, "
              f"{s['beacon']} beacon across {s['devices']} devices "
              f"(the inference engine scores them on its next cycle).")

    if args.continuous:
        print("Continuous demo traffic — Ctrl-C to stop.")
        try:
            while True:
                _run()
                time.sleep(max(2, args.interval))
        except KeyboardInterrupt:
            print("\nStopped.")
    else:
        _run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
