#!/usr/bin/env python3
"""
ARP Scanner for IoTSentinel

Discovers devices on the local network using ARP scanning.
This provides device discovery when DHCP logs are unavailable.

Uses scapy for ARP requests and stores results in the database.
"""

import logging
import subprocess
import re
from typing import List, Dict, Optional
from pathlib import Path
import sys

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from config.config_manager import config
from database.db_manager import DatabaseManager
from utils.mac_lookup import get_manufacturer

logger = logging.getLogger(__name__)

# Try to import scapy
try:
    from scapy.all import ARP, Ether, srp, conf
    SCAPY_AVAILABLE = True
    # Disable scapy verbose output
    conf.verb = 0
except ImportError:
    SCAPY_AVAILABLE = False
    logger.warning("Scapy not available. ARP scanning disabled.")


class ARPScanner:
    """
    Network device scanner using ARP protocol.

    This discovers devices by sending ARP requests and analyzing responses.
    More reliable than DHCP logging for device discovery.
    """

    def __init__(self):
        self.db = DatabaseManager(config.get('database', 'path'))
        self.network_range = config.get('network', 'local_subnet', default='192.168.1.0/24')
        self.timeout = config.get('network', 'arp_timeout', default=2)

        if not SCAPY_AVAILABLE:
            logger.error("Scapy is not installed. ARP scanning will not work.")
            logger.info("Install with: pip install scapy")

        logger.info(f"ARP scanner initialized for network: {self.network_range}")

    def scan_network(self) -> List[Dict[str, str]]:
        """
        Perform ARP scan of the local network.

        Returns:
            List of dictionaries with device info (ip, mac, manufacturer)
        """
        if not SCAPY_AVAILABLE:
            logger.error("Cannot scan: Scapy not available")
            return []

        logger.info(f"Starting ARP scan of {self.network_range}...")
        devices = []

        try:
            # Create ARP request packet
            arp_request = ARP(pdst=self.network_range)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request

            # Send packet and receive responses
            answered_list = srp(arp_request_broadcast, timeout=self.timeout, verbose=False)[0]

            # Parse responses
            for sent, received in answered_list:
                device_info = {
                    'ip': received.psrc,
                    'mac': received.hwsrc,
                    'manufacturer': get_manufacturer(received.hwsrc)
                }
                devices.append(device_info)
                logger.debug(f"Found device: {device_info['ip']} ({device_info['mac']})")

            logger.info(f"✓ ARP scan complete: found {len(devices)} devices")
            return devices

        except PermissionError:
            logger.error("Permission denied. ARP scanning requires root/sudo privileges.")
            logger.info("Run with: sudo python3 -m utils.arp_scanner")
            return []
        except Exception as e:
            logger.error(f"Error during ARP scan: {e}")
            return []

    def scan_and_update_database(self) -> int:
        """
        Scan network and update database with discovered devices.

        Returns:
            Number of devices found and updated
        """
        devices = self.scan_network()

        if not devices:
            logger.warning("No devices found in ARP scan")
            return 0

        updated_count = 0
        for device in devices:
            # Generate a friendly name
            mac_suffix = device['mac'][-8:].replace(':', '').upper()
            device_name = f"Device-{mac_suffix}"

            # Check if we already have a custom name for this device
            existing_devices = self.db.get_all_devices()
            for existing in existing_devices:
                if existing['device_ip'] == device['ip'] and existing['device_name']:
                    # Keep existing custom name
                    device_name = existing['device_name']
                    break

            # Update database
            success = self.db.add_device(
                device_ip=device['ip'],
                mac_address=device['mac'],
                device_name=device_name,
                manufacturer=device['manufacturer']
            )

            if success:
                updated_count += 1
                logger.info(f"Updated: {device['ip']} → {device['mac']} ({device['manufacturer']})")

        logger.info(f"Database updated with {updated_count} devices")
        return updated_count

    def get_network_interface(self) -> Optional[str]:
        """
        Try to detect the primary network interface.

        Returns:
            Interface name (e.g., 'eth0', 'wlan0') or None
        """
        try:
            # Try to get default route interface
            result = subprocess.run(
                ['ip', 'route', 'show', 'default'],
                capture_output=True,
                text=True,
                timeout=5
            )

            if result.returncode == 0:
                # Parse output: "default via 192.168.1.1 dev eth0 ..."
                match = re.search(r'dev\s+(\S+)', result.stdout)
                if match:
                    interface = match.group(1)
                    logger.info(f"Detected network interface: {interface}")
                    return interface
        except Exception as e:
            logger.error(f"Error detecting network interface: {e}")

        return None

    def scan_with_nmap(self) -> List[Dict[str, str]]:
        """
        Alternative scanning method using nmap (if available).
        This is a fallback when scapy doesn't work.

        Returns:
            List of dictionaries with device info
        """
        logger.info("Attempting scan with nmap...")
        devices = []

        try:
            # Check if nmap is installed
            result = subprocess.run(
                ['which', 'nmap'],
                capture_output=True,
                timeout=5
            )

            if result.returncode != 0:
                logger.warning("nmap not installed. Install with: sudo apt install nmap")
                return []

            # Run nmap scan
            result = subprocess.run(
                ['sudo', 'nmap', '-sn', '-oG', '-', self.network_range],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode != 0:
                logger.error("nmap scan failed")
                return []

            # Parse nmap output
            for line in result.stdout.split('\n'):
                if 'Host:' in line and 'Status: Up' in line:
                    # Extract IP address
                    ip_match = re.search(r'Host:\s+(\d+\.\d+\.\d+\.\d+)', line)
                    if ip_match:
                        ip = ip_match.group(1)

                        # Try to get MAC address with another nmap scan
                        mac_result = subprocess.run(
                            ['sudo', 'nmap', '-sn', ip],
                            capture_output=True,
                            text=True,
                            timeout=5
                        )

                        mac = None
                        mac_match = re.search(r'MAC Address:\s+([0-9A-F:]+)', mac_result.stdout, re.IGNORECASE)
                        if mac_match:
                            mac = mac_match.group(1).lower()

                        devices.append({
                            'ip': ip,
                            'mac': mac,
                            'manufacturer': get_manufacturer(mac) if mac else 'Unknown'
                        })

            logger.info(f"✓ nmap scan complete: found {len(devices)} devices")
            return devices

        except subprocess.TimeoutExpired:
            logger.error("nmap scan timed out")
            return []
        except Exception as e:
            logger.error(f"Error during nmap scan: {e}")
            return []

    def close(self):
        """Close database connection."""
        if self.db:
            self.db.close()


def main():
    """Command-line interface for ARP scanner."""
    import argparse

    parser = argparse.ArgumentParser(description='IoTSentinel ARP Network Scanner')
    parser.add_argument('--scan', action='store_true', help='Scan network once')
    parser.add_argument('--nmap', action='store_true', help='Use nmap instead of scapy')
    parser.add_argument('--network', type=str, help='Network range (e.g., 192.168.1.0/24)')

    args = parser.parse_args()

    # Setup logging
    log_dir = Path(config.get('logging', 'log_dir'))
    log_dir.mkdir(parents=True, exist_ok=True)

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_dir / 'arp_scanner.log'),
            logging.StreamHandler()
        ]
    )

    # Initialize scanner
    scanner = ARPScanner()

    # Override network range if provided
    if args.network:
        scanner.network_range = args.network
        logger.info(f"Using custom network range: {args.network}")

    # Perform scan
    if args.scan:
        if args.nmap:
            devices = scanner.scan_with_nmap()
        else:
            devices = scanner.scan_network()

        if devices:
            print("\n" + "=" * 70)
            print("DISCOVERED DEVICES")
            print("=" * 70)
            print(f"{'IP Address':<15} {'MAC Address':<18} {'Manufacturer':<30}")
            print("-" * 70)
            for device in devices:
                print(f"{device['ip']:<15} {device['mac'] or 'N/A':<18} {device['manufacturer']:<30}")
            print("=" * 70)
            print(f"\nTotal devices found: {len(devices)}")

            # Update database
            updated = scanner.scan_and_update_database()
            print(f"Database updated with {updated} devices")
        else:
            print("No devices found or scan failed")
            print("\nTroubleshooting:")
            print("1. Make sure you're running with sudo/root privileges")
            print("2. Check your network range in config.yaml")
            print("3. Try with --nmap flag if scapy fails")
    else:
        print("Use --scan to perform a network scan")
        print("Example: sudo python3 -m utils.arp_scanner --scan")

    scanner.close()


if __name__ == '__main__':
    main()
