#!/usr/bin/env python3
"""
Professional Zeek Log Parser for IoTSentinel

Reads Zeek's JSON logs and feeds them into the database.
This leverages Zeek's C++ engine for protocol analysis.

Architecture: Zeek (C++) → JSON logs → Parser (Python) → Database
"""

import json
import logging
import sys
import time
import gzip
from pathlib import Path
from datetime import datetime
from typing import Optional

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from config.config_manager import config
from database.db_manager import DatabaseManager
from utils.mac_lookup import get_manufacturer

logger = logging.getLogger(__name__)


class ZeekLogParser:
    """Parse Zeek logs and insert into database."""

    def __init__(self):
        self.zeek_log_path = Path(config.get('network', 'zeek_log_path'))
        self.db = DatabaseManager(config.get('database', 'path'))
        self.status_file_path = Path(config.get('system', 'status_file_path', default='config/monitoring_status.json'))

        # Track file positions for resuming
        self.file_positions = {}

        # Statistics
        self.stats = {
            'conn_records': 0,
            'http_records': 0,
            'dns_records': 0,
            'dhcp_records': 0,
            'total_records': 0,
            'start_time': time.time()
        }

        logger.info(f"Zeek parser initialized: {self.zeek_log_path}")

    def parse_conn_log(self, log_path: Path) -> int:
        """
        Parse Zeek conn.log (all network connections).

        Zeek conn.log JSON fields:
        - ts: timestamp
        - uid: unique connection ID
        - id.orig_h: source IP
        - id.orig_p: source port
        - id.resp_h: destination IP
        - id.resp_p: destination port
        - proto: protocol (tcp/udp/icmp)
        - service: identified service
        - duration: connection duration
        - orig_bytes, resp_bytes: data transferred
        - conn_state: connection state
        """
        records_parsed = 0

        try:
            # Handle gzipped logs
            if log_path.suffix == '.gz':
                f = gzip.open(log_path, 'rt')
            else:
                f = open(log_path, 'r')

            # Resume from last position
            file_key = str(log_path)
            if file_key in self.file_positions:
                f.seek(self.file_positions[file_key])

            with f:
                for line in f:
                    # Skip Zeek comments
                    if line.startswith('#'):
                        continue

                    try:
                        record = json.loads(line)

                        # Extract connection data
                        device_ip = record.get('id.orig_h')

                        # Ensure device exists (will be updated with MAC/name from DHCP later)
                        if device_ip:
                            self.db.add_device(device_ip)

                        conn_id = self.db.add_connection(
                            device_ip=device_ip,
                            dest_ip=record.get('id.resp_h'),
                            dest_port=record.get('id.resp_p', 0),
                            protocol=record.get('proto', 'unknown'),
                            service=record.get('service'),
                            duration=record.get('duration', 0),
                            bytes_sent=record.get('orig_bytes', 0),
                            bytes_received=record.get('resp_bytes', 0),
                            packets_sent=record.get('orig_pkts', 0),
                            packets_received=record.get('resp_pkts', 0),
                            conn_state=record.get('conn_state')
                        )

                        if conn_id:
                            records_parsed += 1
                            self.stats['conn_records'] += 1
                            self.stats['total_records'] += 1

                        if records_parsed % 1000 == 0:
                            logger.debug(f"Parsed {records_parsed:,} conn records...")

                    except json.JSONDecodeError:
                        continue
                    except Exception as e:
                        logger.error(f"Error parsing conn record: {e}")
                        continue

                # Save position
                self.file_positions[file_key] = f.tell()

            if records_parsed > 0:
                logger.info(f"✓ Parsed {records_parsed} records from {log_path.name}")

            return records_parsed

        except FileNotFoundError:
            logger.debug(f"Log file not found: {log_path}")
            return 0
        except Exception as e:
            logger.error(f"Error reading conn.log: {e}")
            return 0

    def parse_dhcp_log(self, log_path: Path) -> int:
        """Parse Zeek dhcp.log to get MAC addresses and hostnames."""
        records_parsed = 0
        try:
            # Handle gzipped logs
            if log_path.suffix == '.gz':
                f = gzip.open(log_path, 'rt')
            else:
                f = open(log_path, 'r')

            file_key = str(log_path)
            if file_key in self.file_positions:
                f.seek(self.file_positions[file_key])

            with f:
                for line in f:
                    if line.startswith('#'):
                        continue
                    try:
                        record = json.loads(line)

                        # Zeek DHCP log fields
                        mac = record.get('mac')
                        ip = record.get('assigned_addr') or record.get('assigned_ip')
                        hostname = record.get('host_name') or record.get('client_fqdn')

                        if mac and ip:
                            # Get manufacturer from MAC
                            manufacturer = get_manufacturer(mac)

                            # Generate friendly name
                            device_name = hostname if hostname else f"Device-{mac[-8:].replace(':', '')}"

                            # Update device with MAC and hostname
                            success = self.db.add_device(
                                device_ip=ip,
                                mac_address=mac,
                                device_name=device_name,
                                manufacturer=manufacturer
                            )

                            if success:
                                records_parsed += 1
                                self.stats['dhcp_records'] += 1
                                self.stats['total_records'] += 1
                                logger.debug(f"DHCP: {ip} → {mac} ({device_name})")

                    except json.JSONDecodeError:
                        continue
                    except Exception as e:
                        logger.error(f"Error parsing DHCP record: {e}")
                        continue

                self.file_positions[file_key] = f.tell()

            if records_parsed > 0:
                logger.info(f"✓ Parsed {records_parsed} DHCP records")

            return records_parsed

        except FileNotFoundError:
            logger.warning("dhcp.log not found")
            return 0
        except Exception as e:
            logger.error(f"Error reading dhcp.log: {e}")
            return 0

    def parse_http_log(self, log_path: Path) -> int:
        """Parse Zeek http.log (HTTP traffic)."""
        records_parsed = 0

        try:
            if log_path.suffix == '.gz':
                f = gzip.open(log_path, 'rt')
            else:
                f = open(log_path, 'r')

            file_key = str(log_path)
            if file_key in self.file_positions:
                f.seek(self.file_positions[file_key])

            with f:
                for line in f:
                    if line.startswith('#'):
                        continue

                    try:
                        record = json.loads(line)
                        logger.debug(
                            f"HTTP: {record.get('method')} "
                            f"{record.get('host')}{record.get('uri')}"
                        )
                        records_parsed += 1
                        self.stats['http_records'] += 1
                        self.stats['total_records'] += 1
                    except json.JSONDecodeError:
                        continue

                self.file_positions[file_key] = f.tell()

            if records_parsed > 0:
                logger.info(f"✓ Parsed {records_parsed} HTTP records")

            return records_parsed

        except FileNotFoundError:
            return 0
        except Exception as e:
            logger.error(f"Error reading http.log: {e}")
            return 0

    def parse_dns_log(self, log_path: Path) -> int:
        """Parse Zeek dns.log (DNS queries)."""
        records_parsed = 0

        try:
            if log_path.suffix == '.gz':
                f = gzip.open(log_path, 'rt')
            else:
                f = open(log_path, 'r')

            file_key = str(log_path)
            if file_key in self.file_positions:
                f.seek(self.file_positions[file_key])

            with f:
                for line in f:
                    if line.startswith('#'):
                        continue

                    try:
                        record = json.loads(line)
                        logger.debug(f"DNS: {record.get('query')}")
                        records_parsed += 1
                        self.stats['dns_records'] += 1
                        self.stats['total_records'] += 1
                    except json.JSONDecodeError:
                        continue

                self.file_positions[file_key] = f.tell()

            if records_parsed > 0:
                logger.info(f"✓ Parsed {records_parsed} DNS records")

            return records_parsed

        except FileNotFoundError:
            return 0
        except Exception as e:
            logger.error(f"Error reading dns.log: {e}")
            return 0

    def _is_monitoring_paused(self) -> bool:
        """Check if monitoring is paused."""
        try:
            if not self.status_file_path.exists():
                return False
            with open(self.status_file_path, 'r') as f:
                status = json.load(f)
                return status.get('status') == 'paused'
        except (FileNotFoundError, json.JSONDecodeError):
            return False

    def watch_and_parse(self, interval: int = 60):
        """
        Continuously monitor and parse Zeek logs.
        Runs as a service, checking every interval seconds.
        """
        logger.info("=" * 60)
        logger.info("Starting Zeek log monitoring")
        logger.info(f"Log path: {self.zeek_log_path}")
        logger.info(f"Interval: {interval} seconds")
        logger.info("=" * 60)

        try:
            while True:
                if self._is_monitoring_paused():
                    logger.info("Monitoring is paused. Checking again in 60 seconds...")
                    time.sleep(60)
                    continue

                current_log_dir = self.zeek_log_path / 'current'

                if not current_log_dir.exists():
                    logger.warning(f"Zeek log directory not found: {current_log_dir}")
                    time.sleep(interval)
                    continue

                # Parse dhcp.log FIRST to get device info
                dhcp_log = current_log_dir / 'dhcp.log'
                if dhcp_log.exists():
                    self.parse_dhcp_log(dhcp_log)

                # Parse conn.log (most important)
                conn_log = current_log_dir / 'conn.log'
                if conn_log.exists():
                    self.parse_conn_log(conn_log)

                # Parse http.log
                http_log = current_log_dir / 'http.log'
                if http_log.exists():
                    self.parse_http_log(http_log)

                # Parse dns.log
                dns_log = current_log_dir / 'dns.log'
                if dns_log.exists():
                    self.parse_dns_log(dns_log)

                # Log statistics
                elapsed = time.time() - self.stats['start_time']
                rps = self.stats['total_records'] / elapsed if elapsed > 0 else 0

                logger.info(
                    f"Stats: {self.stats['total_records']:,} total "
                    f"({self.stats['conn_records']:,} conn, "
                    f"{self.stats['http_records']:,} http, "
                    f"{self.stats['dns_records']:,} dns, "
                    f"{self.stats['dhcp_records']:,} dhcp) "
                    f"| {rps:.1f} records/sec"
                )

                time.sleep(interval)

        except KeyboardInterrupt:
            logger.info("Stopping log monitoring...")
        finally:
            self.db.close()
            logger.info("Zeek parser stopped")

    def parse_once(self):
        """Parse current logs once (for testing)."""
        logger.info("Parsing Zeek logs (one-time)...")

        current_log_dir = self.zeek_log_path / 'current'

        if not current_log_dir.exists():
            logger.error(f"Zeek log directory not found: {current_log_dir}")
            logger.info("Make sure Zeek is running: sudo /opt/zeek/bin/zeekctl status")
            return

        # Parse DHCP FIRST to get device names/MAC addresses
        dhcp_log = current_log_dir / 'dhcp.log'
        if dhcp_log.exists():
            self.parse_dhcp_log(dhcp_log)
        else:
            logger.warning("dhcp.log not found - device names and MAC addresses won't be available")

        # Parse conn.log
        conn_log = current_log_dir / 'conn.log'
        if conn_log.exists():
            self.parse_conn_log(conn_log)
        else:
            logger.warning("conn.log not found")

        # Parse http.log
        http_log = current_log_dir / 'http.log'
        if http_log.exists():
            self.parse_http_log(http_log)

        # Parse dns.log
        dns_log = current_log_dir / 'dns.log'
        if dns_log.exists():
            self.parse_dns_log(dns_log)

        # Summary
        logger.info("=" * 60)
        logger.info("PARSE SUMMARY")
        logger.info("=" * 60)
        logger.info(f"Connection records: {self.stats['conn_records']:,}")
        logger.info(f"DHCP records: {self.stats['dhcp_records']:,}")
        logger.info(f"HTTP records: {self.stats['http_records']:,}")
        logger.info(f"DNS records: {self.stats['dns_records']:,}")
        logger.info(f"Total records: {self.stats['total_records']:,}")
        logger.info("=" * 60)


def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(description='IoTSentinel Zeek Log Parser')
    parser.add_argument('--watch', action='store_true', help='Continuously monitor logs')
    parser.add_argument('--interval', type=int, default=60, help='Watch interval (seconds)')
    parser.add_argument('--once', action='store_true', help='Parse once and exit')

    args = parser.parse_args()

    # Setup logging
    log_dir = Path(config.get('logging', 'log_dir'))
    log_dir.mkdir(parents=True, exist_ok=True)

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_dir / 'zeek_parser.log'),
            logging.StreamHandler()
        ]
    )

    # Initialize parser
    zeek_parser = ZeekLogParser()

    if args.once:
        zeek_parser.parse_once()
    elif args.watch:
        zeek_parser.watch_and_parse(interval=args.interval)
    else:
        print("Use --watch to continuously monitor or --once to parse current logs")


if __name__ == "__main__":
    main()
