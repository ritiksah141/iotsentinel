#!/usr/bin/env python3
"""
Domain Blocklist Sync for IoTSentinel

Downloads and maintains a local database of known-malicious domains using:
- abuse.ch URLhaus (free, no key, updated every 5 minutes by abuse.ch)
- Built-in IoT-focused seed list

Synced daily into the `malicious_domains` table, which is then checked at DNS
ingestion time (ZeekLogParser) for real-time threat detection.
"""

import logging
from datetime import datetime
from typing import Optional
from urllib.parse import urlparse

import requests

logger = logging.getLogger(__name__)

# URLhaus domain/URL blocklist (plain text, no auth required)
_URLHAUS_RECENT_URLS = "https://urlhaus.abuse.ch/downloads/text_recent_urls/"

# Sync at most once every 6 hours
_MIN_SYNC_INTERVAL_HOURS = 6

# Request timeout
_TIMEOUT = 15

# Maximum domains to import per sync (caps memory and DB writes on a Pi)
_MAX_DOMAINS = 50_000


class DomainBlocklistSync:
    """
    Manages the malicious_domains table used for DNS-level threat detection.

    Imports URLhaus entries into the local DB so ZeekLogParser can flag DNS
    queries without any network calls at ingestion time.
    """

    def __init__(self, db_manager):
        self.db = db_manager
        self._ensure_table()

    def _ensure_table(self):
        try:
            cursor = self.db.conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS malicious_domains (
                    domain TEXT PRIMARY KEY,
                    source TEXT,
                    category TEXT,
                    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            cursor.execute(
                'CREATE INDEX IF NOT EXISTS idx_malicious_domains_domain '
                'ON malicious_domains(domain)'
            )
            self.db.conn.commit()
        except Exception as e:
            logger.warning("[blocklist] Table init failed: %s", e)

    def _last_sync_age_hours(self) -> float:
        """Return hours since the last URLhaus sync, or infinity if never synced."""
        try:
            cursor = self.db.conn.cursor()
            cursor.execute(
                "SELECT last_updated FROM malicious_domains WHERE source = 'urlhaus' "
                "ORDER BY last_updated DESC LIMIT 1"
            )
            row = cursor.fetchone()
            if not row:
                return float('inf')
            last = datetime.fromisoformat(str(row[0]))
            return (datetime.utcnow() - last).total_seconds() / 3600
        except Exception:
            return float('inf')

    def _download_urlhaus(self) -> list:
        """
        Download the URLhaus recent-URLs text file and extract unique domains.
        Returns a list of (domain, 'urlhaus', 'malware') tuples.
        """
        try:
            logger.info("[blocklist] Downloading URLhaus domain list...")
            resp = requests.get(_URLHAUS_RECENT_URLS, timeout=_TIMEOUT)
            resp.raise_for_status()
        except requests.RequestException as e:
            logger.warning("[blocklist] URLhaus download failed: %s", e)
            return []

        domains = set()
        for line in resp.text.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            try:
                parsed = urlparse(line)
                host = parsed.hostname
                if host and '.' in host and len(host) <= 253:
                    domains.add(host.lower())
            except Exception:
                continue

        result = [(d, 'urlhaus', 'malware') for d in list(domains)[:_MAX_DOMAINS]]
        logger.info("[blocklist] URLhaus: %d unique domains extracted", len(result))
        return result

    def sync_blocklist(self, force: bool = False) -> dict:
        """
        Sync the malicious_domains table from URLhaus.

        Args:
            force: Skip the minimum interval check and sync immediately.

        Returns:
            dict with 'added', 'total', 'skipped' counts.
        """
        stats = {'added': 0, 'total': 0, 'skipped': 0, 'source': 'urlhaus'}

        age = self._last_sync_age_hours()
        if not force and age < _MIN_SYNC_INTERVAL_HOURS:
            logger.info(
                "[blocklist] Skipping sync — last sync %.1f hours ago (min %d hours)",
                age, _MIN_SYNC_INTERVAL_HOURS,
            )
            stats['skipped'] = 1
            return stats

        entries = self._download_urlhaus()
        if not entries:
            return stats

        try:
            cursor = self.db.conn.cursor()
            now = datetime.utcnow().isoformat()

            # Bulk insert — executemany is orders of magnitude faster than per-row
            # execute() and writes the SD card in a single WAL transaction.
            cursor.executemany(
                '''INSERT OR REPLACE INTO malicious_domains
                   (domain, source, category, last_updated)
                   VALUES (?, ?, ?, ?)''',
                [(domain, source, category, now) for domain, source, category in entries],
            )
            stats['added'] = cursor.rowcount if cursor.rowcount >= 0 else len(entries)

            self.db.conn.commit()

            cursor.execute("SELECT COUNT(*) FROM malicious_domains")
            stats['total'] = cursor.fetchone()[0]

            logger.info(
                "[blocklist] Sync complete: +%d domains (%d total in DB)",
                stats['added'], stats['total'],
            )

        except Exception as e:
            logger.error("[blocklist] DB write failed: %s", e)

        return stats

    def is_domain_malicious(self, domain: str) -> Optional[str]:
        """
        Check if a domain (or its parent) is in the blocklist.

        Returns the matched malicious domain string, or None if clean.
        Handles subdomain matching: querying 'sub.evil.com' matches 'evil.com'.
        """
        if not domain:
            return None
        domain = domain.rstrip('.').lower()
        try:
            cursor = self.db.conn.cursor()
            # Exact match or subdomain match
            cursor.execute(
                "SELECT domain FROM malicious_domains "
                "WHERE domain = ? OR ? LIKE '%.' || domain "
                "LIMIT 1",
                (domain, domain),
            )
            row = cursor.fetchone()
            return row[0] if row else None
        except Exception:
            return None

    def get_stats(self) -> dict:
        """Return basic stats about the current blocklist."""
        try:
            cursor = self.db.conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM malicious_domains")
            total = cursor.fetchone()[0]
            cursor.execute(
                "SELECT last_updated FROM malicious_domains ORDER BY last_updated DESC LIMIT 1"
            )
            row = cursor.fetchone()
            last_sync = str(row[0]) if row else 'never'
            return {'total_domains': total, 'last_sync': last_sync}
        except Exception:
            return {'total_domains': 0, 'last_sync': 'unknown'}


_domain_sync: Optional[DomainBlocklistSync] = None


def get_domain_blocklist_sync(db_manager=None) -> Optional[DomainBlocklistSync]:
    """Return or create the global DomainBlocklistSync singleton."""
    global _domain_sync
    if _domain_sync is None and db_manager is not None:
        _domain_sync = DomainBlocklistSync(db_manager)
    return _domain_sync
