#!/usr/bin/env python3
"""
ARP Scanner for IoTSentinel

Discovers devices on the local network using only privilege-free OS calls:
  1. Parallel ping sweep (populates the kernel ARP cache — no sudo needed)
  2. 'ip neigh show' (reads the kernel ARP/NDP table — no raw sockets)
  3. /proc/net/arp fallback (pure file read, Linux only)
  4. 'arp -a' fallback (macOS / BSD dev environments)

No scapy, no nmap, no sudo, no CAP_NET_RAW required.
"""

import logging
import re
import subprocess
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

from config.config_manager import config
from database.db_manager import DatabaseManager
from utils.mac_lookup import get_manufacturer
from utils.name_resolver import resolve_name, is_synthetic

logger = logging.getLogger(__name__)

# Cap for the active ping sweep. /24=254, /23=510, /22=1022 hosts are swept fully;
# anything larger (a misconfigured or unusually large home LAN) falls back to the
# passive kernel neighbour table so discovery never hangs for minutes.
_MAX_SWEEP_HOSTS = 1024

# Always available — no privilege flag needed
SCAPY_AVAILABLE = False  # kept for orchestrator import compatibility


class ARPScanner:
    """
    Network device scanner.

    Uses a two-phase privilege-free strategy:
      Phase 1 — parallel ping sweep to populate the kernel ARP cache.
      Phase 2 — read the ARP table via 'ip neigh show' (or fallbacks).

    No raw sockets, no scapy, no nmap, no sudo required.
    """

    def __init__(self):
        self.db = DatabaseManager(config.get('database', 'path'))
        # In gateway mode the monitored devices live on the Pi's AP subnet, so scan
        # that range; otherwise scan the configured home subnet.
        if config.get('network', 'capture_mode', default='passive') == 'gateway':
            self.network_range = config.get('network', 'ap_subnet', default='10.42.0.0/24')
        else:
            # The wizard / orchestrator store the home LAN as the list
            # network.local_networks (see callbacks_setup._save_config and
            # orchestrator). Read the first entry — the legacy 'local_subnet'
            # key was never written, so scanning always fell back to the
            # hardcoded default and discovered nothing on the real LAN.
            local_networks = config.get('network', 'local_networks', default=['192.168.1.0/24'])
            self.network_range = (local_networks[0] if local_networks else '192.168.1.0/24')
        self.timeout = int(config.get('network', 'arp_timeout', default=2))
        # Optional shutdown signal: the orchestrator sets this to its shutdown event so a
        # long ping sweep aborts promptly instead of blocking graceful shutdown.
        self.stop_event = None
        logger.info(f"ARP scanner initialised for {self.network_range} (no-sudo mode)")

    def _stopping(self) -> bool:
        """True once a shutdown has been signalled via stop_event."""
        return self.stop_event is not None and self.stop_event.is_set()

    # ── Phase 1: populate ARP cache ─────────────────────────────────────────

    def _ping_host(self, ip: str) -> None:
        """Send a single fast ping to populate the kernel ARP cache."""
        try:
            subprocess.run(
                ['ping', '-c', '1', '-W', '1', ip],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=3,
            )
        except Exception:
            pass

    def _ping_sweep(self) -> None:
        """
        Ping every host in the configured subnet in parallel.
        Pings are fire-and-forget — we only care that the kernel sees the
        replies and updates its ARP cache.  No sudo required.
        """
        try:
            net = ipaddress.ip_network(self.network_range, strict=False)
        except ValueError:
            logger.warning(f"Invalid subnet '{self.network_range}', skipping ping sweep")
            return

        hosts = list(net.hosts())
        # Most home LANs are /24 (254 hosts). Some routers hand out a larger range
        # (/22, /20, /16); actively pinging tens of thousands of addresses would hang
        # discovery for minutes. Cap the ACTIVE sweep — the passive 'ip neigh' read still
        # surfaces everything the kernel already knows, so big subnets degrade gracefully.
        if len(hosts) > _MAX_SWEEP_HOSTS:
            logger.warning(
                f"Subnet {self.network_range} is large ({len(hosts)} hosts) — skipping the "
                f"active ping sweep and relying on the kernel neighbour table for discovery.")
            return
        logger.info(f"Ping sweep: {len(hosts)} hosts in {self.network_range}")

        # Not a `with` block: on shutdown we break out and cancel the queued pings
        # without waiting (wait=False), so the scan thread joins within the timeout.
        pool = ThreadPoolExecutor(max_workers=64)
        try:
            futures = {pool.submit(self._ping_host, str(ip)): str(ip) for ip in hosts}
            for _ in as_completed(futures):
                if self._stopping():
                    logger.info("Ping sweep aborted — shutdown signalled")
                    break  # fire-and-forget; result irrelevant
        finally:
            pool.shutdown(wait=False, cancel_futures=True)

    # ── Phase 2: read ARP table ──────────────────────────────────────────────

    def _read_ip_neigh(self) -> List[Dict[str, str]]:
        """
        Read kernel ARP/NDP table via 'ip neigh show'.
        Returns entries with status REACHABLE, STALE, DELAY, or PROBE
        (all indicate a recently-seen host).
        No privileges required.
        """
        devices: List[Dict[str, str]] = []
        try:
            result = subprocess.run(
                ['ip', 'neigh', 'show'],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode != 0:
                return devices

            for line in result.stdout.splitlines():
                # Format: 192.168.1.10 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
                m = re.match(
                    r'^(\d+\.\d+\.\d+\.\d+)\s+dev\s+\S+\s+lladdr\s+([0-9a-f:]{17})\s+(\S+)',
                    line, re.IGNORECASE
                )
                if not m:
                    continue
                ip, mac, state = m.group(1), m.group(2).lower(), m.group(3).upper()
                if state in ('REACHABLE', 'STALE', 'DELAY', 'PROBE'):
                    devices.append({
                        'ip': ip,
                        'mac': mac,
                        'manufacturer': get_manufacturer(mac),
                    })
        except FileNotFoundError:
            pass  # 'ip' command not available — fall through to next method
        except Exception as e:
            logger.debug(f"ip neigh show failed: {e}")

        return devices

    def _read_proc_arp(self) -> List[Dict[str, str]]:
        """
        Parse /proc/net/arp — available on all Linux kernels, no privileges.
        Fallback when 'ip neigh' is unavailable.
        """
        devices: List[Dict[str, str]] = []
        try:
            with open('/proc/net/arp', 'r') as f:
                for line in f.readlines()[1:]:  # skip header
                    parts = line.split()
                    if len(parts) < 4:
                        continue
                    ip, _, flags, mac = parts[0], parts[1], parts[2], parts[3]
                    # flags 0x2 = ARP_COMPLETE (entry is valid)
                    if int(flags, 16) & 0x2 and mac != '00:00:00:00:00:00':
                        devices.append({
                            'ip': ip,
                            'mac': mac.lower(),
                            'manufacturer': get_manufacturer(mac),
                        })
        except FileNotFoundError:
            pass  # Not Linux — fall through
        except Exception as e:
            logger.debug(f"/proc/net/arp read failed: {e}")

        return devices

    def _read_arp_a(self) -> List[Dict[str, str]]:
        """
        Parse 'arp -a' output — macOS / BSD fallback for dev environments.
        """
        devices: List[Dict[str, str]] = []
        try:
            result = subprocess.run(
                ['arp', '-a'], capture_output=True, text=True, timeout=10
            )
            for line in result.stdout.splitlines():
                # Format: hostname (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ...
                m = re.search(
                    r'\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-f:]{17})',
                    line, re.IGNORECASE
                )
                if m:
                    ip, mac = m.group(1), m.group(2).lower()
                    devices.append({
                        'ip': ip,
                        'mac': mac,
                        'manufacturer': get_manufacturer(mac),
                    })
        except Exception as e:
            logger.debug(f"arp -a failed: {e}")

        return devices

    def _in_monitored_subnet(self, ip: str) -> bool:
        """True if *ip* belongs to the subnet we are monitoring.

        The kernel ARP table ('ip neigh') lists neighbours on EVERY interface, so while
        the Pi hosts the setup hotspot it also sees the phone/laptop used for the wizard
        at 10.42.0.x. Those are provisioning artifacts, not home-network devices, and must
        never enter the inventory — the Connected Devices list should reflect the home
        Wi-Fi (the monitored subnet), not the setup AP. Scoping to network_range also
        naturally drops anything on another interface.

        CRITICAL: fail OPEN while the range is still a PLACEHOLDER (the shipped default or
        the hotspot range) — i.e. before the orchestrator's subnet self-heal has locked
        the real LAN. Otherwise, on a home network that isn't 192.168.1.0/24 (e.g. Virgin
        Media's 192.168.0.x), filtering against the stale placeholder would drop EVERY real
        device and the dashboard would show 0/0. Only scope once a real subnet is locked.
        """
        try:
            from utils.net_detect import PLACEHOLDER_CIDRS
            if self.network_range in PLACEHOLDER_CIDRS:
                return True  # subnet not confirmed yet — never hide real devices
            return ipaddress.ip_address(ip) in ipaddress.ip_network(
                self.network_range, strict=False)
        except Exception:
            return True

    # ── Public API ───────────────────────────────────────────────────────────

    def get_network_interface(self) -> Optional[str]:
        """Detect the primary network interface from the default route."""
        try:
            result = subprocess.run(
                ['ip', 'route', 'show', 'default'],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                m = re.search(r'dev\s+(\S+)', result.stdout)
                if m:
                    iface = m.group(1)
                    logger.info(f"Detected interface: {iface}")
                    return iface
        except Exception as e:
            logger.debug(f"Interface detection failed: {e}")
        return None

    def scan_network(self) -> List[Dict[str, str]]:
        """
        Discover devices on the local network without any elevated privileges.

        Strategy:
          1. Ping sweep — forces the kernel to ARP-resolve every live host.
          2. Read the kernel ARP table (ip neigh → /proc/net/arp → arp -a).

        Returns:
            List of dicts: [{ip, mac, manufacturer}, ...]
        """
        # Phase 1 — populate ARP cache
        self._ping_sweep()

        # If shutdown was signalled during the sweep, return early without the
        # follow-up table reads so the worker thread exits promptly.
        if self._stopping():
            return []

        # Phase 2 — read ARP table (try methods in order)
        devices = self._read_ip_neigh()

        if not devices:
            logger.debug("ip neigh empty/unavailable, trying /proc/net/arp")
            devices = self._read_proc_arp()

        if not devices:
            logger.debug("/proc/net/arp empty/unavailable, trying arp -a")
            devices = self._read_arp_a()

        # Deduplicate by IP (keep first occurrence) and scope to the monitored subnet so
        # setup-hotspot clients (10.42.0.x) and other-interface neighbours never enter the
        # home-network inventory.
        seen: set = set()
        unique: List[Dict[str, str]] = []
        for d in devices:
            if d['ip'] in seen or not self._in_monitored_subnet(d['ip']):
                continue
            seen.add(d['ip'])
            unique.append(d)

        logger.info(f"ARP scan complete: {len(unique)} devices found in {self.network_range}")
        return unique

    def scan_and_update_database(self) -> int:
        """
        Scan the network and upsert discovered devices into the database.

        Returns:
            Number of devices updated.
        """
        devices = self.scan_network()

        if not devices:
            logger.warning("No devices found in ARP scan")
            return 0

        updated_count = 0
        existing_by_ip = {d['device_ip']: d for d in self.db.get_all_devices()}

        for device in devices:
            existing = existing_by_ip.get(device['ip'])
            existing_name = existing.get('device_name') if existing else None

            if is_synthetic(existing_name):
                resolved = resolve_name(
                    device['ip'],
                    mac=device.get('mac'),
                    manufacturer=device.get('manufacturer'),
                )
                device_name = resolved or f"Device-{device['mac'][-8:].replace(':', '').upper()}"
            else:
                device_name = None  # preserve existing real name via COALESCE

            success = self.db.add_device(
                device_ip=device['ip'],
                mac_address=device['mac'],
                device_name=device_name,
                manufacturer=device['manufacturer'],
            )

            if success:
                updated_count += 1
                label = device_name or existing_name or device['ip']
                logger.info(f"Updated: {device['ip']} → {device['mac']} ({label})")

        logger.info(f"Database updated with {updated_count} devices")
        return updated_count

    def close(self):
        """Close database connection."""
        if self.db:
            self.db.close()


def main():
    """Command-line interface for the ARP scanner."""
    import argparse

    parser = argparse.ArgumentParser(description='IoTSentinel network scanner (no sudo)')
    parser.add_argument('--scan', action='store_true', help='Scan network once')
    parser.add_argument('--network', type=str, help='Override subnet (e.g. 192.168.1.0/24)')
    args = parser.parse_args()

    log_dir = Path(config.get('logging', 'log_dir'))
    log_dir.mkdir(parents=True, exist_ok=True)

    from logging.handlers import RotatingFileHandler
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            RotatingFileHandler(
                log_dir / 'arp_scanner.log',
                maxBytes=2 * 1024 * 1024, backupCount=3),
            logging.StreamHandler(),
        ]
    )

    scanner = ARPScanner()

    if args.network:
        scanner.network_range = args.network

    if args.scan:
        devices = scanner.scan_network()
        if devices:
            print(f"\n{'IP Address':<15} {'MAC Address':<18} {'Manufacturer'}")
            print('-' * 65)
            for d in devices:
                print(f"{d['ip']:<15} {d['mac'] or 'N/A':<18} {d['manufacturer']}")
            print(f"\nTotal: {len(devices)} devices")
            updated = scanner.scan_and_update_database()
            print(f"Database updated: {updated} devices")
        else:
            print("No devices found")
    else:
        print("Use --scan to perform a network scan")

    scanner.close()


if __name__ == '__main__':
    main()
