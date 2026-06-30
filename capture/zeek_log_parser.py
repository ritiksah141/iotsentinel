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

    # Flush a batch to the DB every this many rows — keeps memory bounded on
    # very large conn.log files while still giving a massive commit reduction.
    _BATCH_SIZE = 5_000

    # RFC-1918 + loopback + link-local prefixes — never screen these as external
    _PRIVATE_PREFIXES = ('10.', '192.168.', '127.', '169.254.',
                         '172.16.', '172.17.', '172.18.', '172.19.',
                         '172.20.', '172.21.', '172.22.', '172.23.',
                         '172.24.', '172.25.', '172.26.', '172.27.',
                         '172.28.', '172.29.', '172.30.', '172.31.')

    def _screen_malicious_ips(self, batch: list) -> None:
        """
        Check dest_ips in the batch against the local malicious_ips table.

        Creates a critical alert immediately for any match, rate-limited to one
        alert per (device_ip, dest_ip) pair per hour to avoid flooding.  This
        makes detection happen at ingestion time (not waiting for the agent's
        60-second poll cycle).
        """
        if not batch:
            return

        # Collect unique external dest_ips
        external = {
            c['dest_ip'] for c in batch
            if c.get('dest_ip') and
            not any(c['dest_ip'].startswith(p) for p in self._PRIVATE_PREFIXES)
        }
        if not external:
            return

        try:
            cursor = self.db.conn.cursor()
            placeholders = ','.join('?' * len(external))
            cursor.execute(
                f"SELECT ip, source FROM malicious_ips WHERE ip IN ({placeholders})",
                list(external),
            )
            rows = cursor.fetchall()
            if not rows:
                return

            hit_map = {row[0]: row[1] for row in rows}

            alerted_pairs: set = set()
            for conn in batch:
                dest_ip = conn.get('dest_ip', '')
                device_ip = conn.get('device_ip', '')
                if dest_ip not in hit_map or not device_ip:
                    continue

                pair = (device_ip, dest_ip)
                if pair in alerted_pairs:
                    continue
                alerted_pairs.add(pair)

                # Rate-limit: one alert per pair per hour
                cursor.execute(
                    """SELECT COUNT(*) FROM alerts
                       WHERE device_ip = ?
                         AND explanation LIKE ?
                         AND timestamp >= datetime('now', '-1 hour')""",
                    (device_ip, f'%{dest_ip}%'),
                )
                if cursor.fetchone()[0] > 0:
                    continue

                source = hit_map[dest_ip]
                cursor.execute(
                    """INSERT INTO alerts
                       (timestamp, device_ip, severity, anomaly_score,
                        explanation, top_features, acknowledged, plain_explanation, mitre_tactic)
                       VALUES (datetime('now'), ?, 'critical', 1.0, ?, '{}', 0, ?, ?)""",
                    (
                        device_ip,
                        (f"MALICIOUS_IP_CONTACT: {device_ip} contacted known-malicious "
                         f"IP {dest_ip} (source: {source}) — flagged at ingestion time."),
                        (f"A device on your network ({device_ip}) sent traffic to a "
                         f"known malicious IP address ({dest_ip}). This threat was "
                         f"detected as soon as the connection was logged."),
                        "Command and Control (TA0011)",
                    ),
                )

            if alerted_pairs:
                self.db.conn.commit()
                logger.warning(
                    "[zeek] Malicious IP contact: %d alert(s) created — %s",
                    len(alerted_pairs),
                    ', '.join(f'{d}->{ip}' for d, ip in alerted_pairs),
                )

        except Exception as e:
            logger.error("[zeek] Malicious IP screen error: %s", e)

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

        Batching strategy
        -----------------
        Rows are accumulated in memory and flushed via ``add_connections_batch``
        (executemany) every _BATCH_SIZE lines and once at end-of-file.  This
        reduces the number of commits from O(N) to O(N / _BATCH_SIZE) which is
        orders of magnitude faster on a Pi and eliminates per-row fsync storms.
        """
        records_parsed = 0
        pending: list = []

        def _flush(batch: list) -> int:
            if not batch:
                return 0
            return self.db.add_connections_batch(batch)

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

                        device_ip = record.get('id.orig_h')
                        dest_ip   = record.get('id.resp_h')

                        # Skip records without the key IPs (malformed)
                        if not device_ip or not dest_ip:
                            continue

                        pending.append({
                            'device_ip':       device_ip,
                            'dest_ip':         dest_ip,
                            'dest_port':       record.get('id.resp_p', 0),
                            'protocol':        record.get('proto', 'unknown'),
                            'service':         record.get('service') or '',
                            'duration':        record.get('duration', 0),
                            'bytes_sent':      record.get('orig_bytes', 0),
                            'bytes_received':  record.get('resp_bytes', 0),
                            'packets_sent':    record.get('orig_pkts', 0),
                            'packets_received': record.get('resp_pkts', 0),
                            'conn_state':      record.get('conn_state') or '',
                        })

                        # Flush when batch is full
                        if len(pending) >= self._BATCH_SIZE:
                            self._screen_malicious_ips(pending)
                            inserted = _flush(pending)
                            records_parsed += inserted
                            self.stats['conn_records'] += inserted
                            self.stats['total_records'] += inserted
                            logger.debug(f"Flushed batch: {inserted} conn records (total {records_parsed:,})")
                            pending = []

                    except json.JSONDecodeError:
                        continue
                    except Exception as e:
                        logger.error(f"Error parsing conn record: {e}")
                        continue

                # Flush remaining rows
                if pending:
                    self._screen_malicious_ips(pending)
                    inserted = _flush(pending)
                    records_parsed += inserted
                    self.stats['conn_records'] += inserted
                    self.stats['total_records'] += inserted

                # Save file position
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

                            # Use the real DHCP hostname when present; otherwise pass
                            # None so add_device's COALESCE preserves any already-resolved
                            # name (vendor/mDNS/reverse-DNS) instead of clobbering it with
                            # a synthetic Device-XXXX placeholder.
                            device_name = hostname or None

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

    @staticmethod
    def _domain_suffixes(domain: str) -> list:
        """Return the domain and each of its parent labels (up to 4 levels)."""
        parts = domain.split('.')
        return ['.'.join(parts[i:]) for i in range(max(0, len(parts) - 4), len(parts))]

    def _screen_malicious_domains(self, batch: list) -> None:
        """
        Check DNS query batch against the malicious_domains table.

        Uses a single batch SQL query (one IN clause for all unique queries in the
        batch + their parent domains) rather than a per-record LIKE full-table scan.
        This keeps the hot path O(log n) via the PRIMARY KEY index even with 50K+
        domains in the blocklist.

        Creates a critical alert per (device_ip, matched_domain), rate-limited to
        one per hour to avoid flooding.
        """
        if not batch:
            return
        try:
            cursor = self.db.conn.cursor()

            # Build the candidate lookup set: for each queried domain, include
            # itself and up to 4 parent-label suffixes (so 'a.b.evil.com' also
            # checks 'b.evil.com' and 'evil.com').
            query_map: dict = {}  # candidate → [(device_ip, original_query)]
            for record in batch:
                device_ip = record.get('device_ip', '')
                query = record.get('query', '')
                if not device_ip or not query:
                    continue
                for candidate in self._domain_suffixes(query.rstrip('.').lower()):
                    query_map.setdefault(candidate, []).append((device_ip, query))

            if not query_map:
                return

            # Single indexed lookup: domain IN (...) — uses PRIMARY KEY index
            candidates = list(query_map.keys())
            placeholders = ','.join('?' * len(candidates))
            cursor.execute(
                f"SELECT domain, source FROM malicious_domains WHERE domain IN ({placeholders})",
                candidates,
            )
            hits = {row[0]: row[1] for row in cursor.fetchall()}

            if not hits:
                return

            alerted_pairs: set = set()
            for matched_domain, source in hits.items():
                for device_ip, original_query in query_map.get(matched_domain, []):
                    pair = (device_ip, matched_domain)
                    if pair in alerted_pairs:
                        continue

                    # Rate-limit: one alert per pair per hour
                    cursor.execute(
                        """SELECT COUNT(*) FROM alerts
                           WHERE device_ip = ? AND explanation LIKE ?
                             AND timestamp >= datetime('now', '-1 hour')""",
                        (device_ip, f'%{matched_domain}%'),
                    )
                    if cursor.fetchone()[0] > 0:
                        continue

                    alerted_pairs.add(pair)

                    cursor.execute(
                        "UPDATE dns_queries SET flagged = 1, threat_source = ? "
                        "WHERE device_ip = ? AND query = ? AND flagged = 0",
                        (source, device_ip, original_query),
                    )
                    cursor.execute(
                        """INSERT INTO alerts
                           (timestamp, device_ip, severity, anomaly_score,
                            explanation, top_features, acknowledged, plain_explanation, mitre_tactic)
                           VALUES (datetime('now'), ?, 'critical', 1.0, ?, '{}', 0, ?, ?)""",
                        (
                            device_ip,
                            (f"MALICIOUS_DOMAIN_QUERY: {device_ip} queried known-malicious "
                             f"domain {matched_domain} (source: {source}) — "
                             f"query: {original_query}"),
                            (f"A device ({device_ip}) on your network looked up a known malicious "
                             f"domain ({matched_domain}). Detected at DNS ingestion time. "
                             f"The device may be infected or contacting a command-and-control server."),
                            "Command and Control (TA0011)",
                        ),
                    )

            if alerted_pairs:
                self.db.conn.commit()
                logger.warning(
                    "[zeek] Malicious domain query: %d alert(s) created — %s",
                    len(alerted_pairs),
                    ', '.join(f'{d}->{m}' for d, m in alerted_pairs),
                )

        except Exception as e:
            logger.error("[zeek] Malicious domain screen error: %s", e)

    def parse_dns_log(self, log_path: Path) -> int:
        """
        Parse Zeek dns.log — write queries to dns_queries table and screen
        against the malicious_domains blocklist for real-time DNS threat detection.
        """
        records_parsed = 0
        pending: list = []

        def _flush_dns(batch: list) -> int:
            if not batch:
                return 0
            try:
                cursor = self.db.conn.cursor()
                cursor.executemany(
                    '''INSERT OR IGNORE INTO dns_queries
                       (timestamp, device_ip, query, query_type, answers, flagged)
                       VALUES (?, ?, ?, ?, ?, 0)''',
                    [
                        (
                            r.get('timestamp', ''),
                            r['device_ip'],
                            r['query'],
                            r.get('query_type', ''),
                            r.get('answers', ''),
                        )
                        for r in batch
                    ],
                )
                self.db.conn.commit()
                return len(batch)
            except Exception as e:
                logger.error("[zeek] DNS batch insert failed: %s", e)
                return 0

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
                        query = record.get('query', '')
                        if not query:
                            continue

                        device_ip = record.get('id.orig_h', '')
                        answers = record.get('answers', [])
                        answers_str = ', '.join(answers) if isinstance(answers, list) else str(answers or '')
                        ts_raw = record.get('ts')
                        try:
                            ts_str = datetime.utcfromtimestamp(float(ts_raw)).strftime('%Y-%m-%d %H:%M:%S') if ts_raw else ''
                        except (ValueError, TypeError):
                            ts_str = ''

                        # Count every valid query record in stats
                        records_parsed += 1
                        self.stats['dns_records'] += 1
                        self.stats['total_records'] += 1

                        # Only enqueue for DB write + threat screen when we have a device IP
                        if device_ip:
                            pending.append({
                                'device_ip': device_ip,
                                'query': query,
                                'query_type': record.get('qtype_name', ''),
                                'answers': answers_str,
                                'timestamp': ts_str,
                            })
                            if len(pending) >= self._BATCH_SIZE:
                                self._screen_malicious_domains(pending)
                                _flush_dns(pending)
                                pending = []

                    except json.JSONDecodeError:
                        continue
                    except Exception as e:
                        logger.error(f"Error parsing DNS record: {e}")
                        continue

                if pending:
                    self._screen_malicious_domains(pending)
                    _flush_dns(pending)

                self.file_positions[file_key] = f.tell()

            if records_parsed > 0:
                logger.info(f"[zeek] Parsed {records_parsed} DNS records")

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

    from logging.handlers import RotatingFileHandler
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            RotatingFileHandler(
                log_dir / 'zeek_parser.log',
                maxBytes=2 * 1024 * 1024, backupCount=3),
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
