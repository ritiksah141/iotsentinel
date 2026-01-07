#!/usr/bin/env python3
"""
NVD (National Vulnerability Database) API Client for IoTSentinel

Integrates with NVD API 2.0 to fetch CVE data for IoT devices.
Implements rate limiting and SQLite caching for efficient operation.
"""

import logging
import time
import sqlite3
import json
import requests
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
from pathlib import Path
import threading

logger = logging.getLogger(__name__)


# NVD API 2.0 endpoints
NVD_API_BASE = 'https://services.nvd.nist.gov/rest/json/cves/2.0'

# Rate limits (NVD API 2.0)
# Without API key: 5 requests per 30 seconds, 10,000 requests per day
# With API key: 50 requests per 30 seconds, 100,000 requests per day
RATE_LIMIT_NO_KEY = 5
RATE_LIMIT_WITH_KEY = 50
RATE_WINDOW_SECONDS = 30


class TokenBucketRateLimiter:
    """
    Token bucket algorithm for rate limiting.

    Ensures we don't exceed NVD API rate limits.
    """

    def __init__(self, rate: int, window: int):
        """
        Initialize rate limiter.

        Args:
            rate: Number of requests allowed per window
            window: Time window in seconds
        """
        self.rate = rate
        self.window = window
        self.tokens = rate
        self.last_refill = time.time()
        self.lock = threading.Lock()

    def acquire(self) -> bool:
        """
        Acquire a token for making a request.

        Blocks until a token is available.

        Returns:
            True when token acquired
        """
        with self.lock:
            now = time.time()

            # Refill tokens based on time passed
            elapsed = now - self.last_refill
            if elapsed >= self.window:
                self.tokens = self.rate
                self.last_refill = now

            # Wait if no tokens available
            while self.tokens <= 0:
                sleep_time = self.window - (time.time() - self.last_refill)
                if sleep_time > 0:
                    logger.debug(f"Rate limit reached, sleeping for {sleep_time:.2f}s")
                    time.sleep(sleep_time)

                # Refill after sleep
                self.tokens = self.rate
                self.last_refill = time.time()

            # Consume token
            self.tokens -= 1
            return True


class NVDAPIClient:
    """
    Client for NVD API 2.0 with rate limiting and caching.

    Provides methods to search for CVEs by vendor, product, and keywords.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        cache_db_path: str = 'data/cache/nvd_cache.db',
        cache_ttl_hours: int = 24
    ):
        """
        Initialize NVD API client.

        Args:
            api_key: NVD API key (optional, increases rate limit)
            cache_db_path: Path to SQLite cache database
            cache_ttl_hours: Cache time-to-live in hours
        """
        self.api_key = api_key
        self.cache_db_path = cache_db_path
        self.cache_ttl_hours = cache_ttl_hours

        # Setup rate limiter
        rate_limit = RATE_LIMIT_WITH_KEY if api_key else RATE_LIMIT_NO_KEY
        self.rate_limiter = TokenBucketRateLimiter(rate_limit, RATE_WINDOW_SECONDS)

        # Initialize cache database
        self._init_cache_db()

        logger.info(f"NVD API client initialized (rate limit: {rate_limit} req/{RATE_WINDOW_SECONDS}s)")

    def _init_cache_db(self):
        """Initialize SQLite cache database."""
        try:
            # Create directory if needed
            cache_dir = Path(self.cache_db_path).parent
            cache_dir.mkdir(parents=True, exist_ok=True)

            # Create table
            conn = sqlite3.connect(self.cache_db_path)
            cursor = conn.cursor()

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS nvd_cache (
                    cache_key TEXT PRIMARY KEY,
                    data TEXT NOT NULL,
                    cached_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_cached_at
                ON nvd_cache(cached_at)
            ''')

            conn.commit()
            conn.close()

            logger.debug(f"NVD cache database initialized: {self.cache_db_path}")

        except Exception as e:
            logger.error(f"Error initializing cache database: {e}")

    def _get_from_cache(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """
        Get data from cache if not expired.

        Args:
            cache_key: Cache key

        Returns:
            Cached data or None
        """
        try:
            conn = sqlite3.connect(self.cache_db_path)
            cursor = conn.cursor()

            # Calculate expiry time
            expiry_time = datetime.now() - timedelta(hours=self.cache_ttl_hours)

            cursor.execute(
                "SELECT data FROM nvd_cache WHERE cache_key = ? AND cached_at > ?",
                (cache_key, expiry_time.isoformat())
            )

            row = cursor.fetchone()
            conn.close()

            if row:
                logger.debug(f"Cache hit: {cache_key}")
                return json.loads(row[0])
            else:
                logger.debug(f"Cache miss: {cache_key}")
                return None

        except Exception as e:
            logger.error(f"Error reading from cache: {e}")
            return None

    def _save_to_cache(self, cache_key: str, data: Dict[str, Any]):
        """
        Save data to cache.

        Args:
            cache_key: Cache key
            data: Data to cache
        """
        try:
            conn = sqlite3.connect(self.cache_db_path)
            cursor = conn.cursor()

            cursor.execute('''
                INSERT OR REPLACE INTO nvd_cache (cache_key, data, cached_at)
                VALUES (?, ?, ?)
            ''', (cache_key, json.dumps(data), datetime.now().isoformat()))

            conn.commit()
            conn.close()

            logger.debug(f"Saved to cache: {cache_key}")

        except Exception as e:
            logger.error(f"Error saving to cache: {e}")

    def _make_request(
        self,
        params: Dict[str, Any],
        use_cache: bool = True
    ) -> Optional[Dict[str, Any]]:
        """
        Make API request with rate limiting and caching.

        Args:
            params: Query parameters
            use_cache: Whether to use cache

        Returns:
            API response data or None
        """
        # Generate cache key
        cache_key = json.dumps(params, sort_keys=True)

        # Try cache first
        if use_cache:
            cached_data = self._get_from_cache(cache_key)
            if cached_data:
                return cached_data

        # Acquire rate limit token
        self.rate_limiter.acquire()

        try:
            # Build headers
            headers = {
                'User-Agent': 'IoTSentinel/1.0'
            }

            if self.api_key:
                headers['apiKey'] = self.api_key

            # Make request
            logger.debug(f"Making NVD API request: {params}")
            response = requests.get(
                NVD_API_BASE,
                params=params,
                headers=headers,
                timeout=30
            )

            response.raise_for_status()
            data = response.json()

            # Cache response
            if use_cache:
                self._save_to_cache(cache_key, data)

            return data

        except requests.RequestException as e:
            logger.error(f"NVD API request failed: {e}")
            return None
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse NVD API response: {e}")
            return None

    def fetch_cves_for_vendor(
        self,
        vendor: str,
        product: Optional[str] = None,
        results_per_page: int = 100,
        max_results: int = 500
    ) -> List[Dict[str, Any]]:
        """
        Fetch CVEs for a vendor/product.

        Args:
            vendor: Vendor name (e.g., "google", "amazon")
            product: Product name (optional, e.g., "nest_cam")
            results_per_page: Results per page (max 2000)
            max_results: Maximum total results to fetch

        Returns:
            List of CVE dictionaries
        """
        logger.info(f"Fetching CVEs for vendor={vendor}, product={product}")

        all_cves = []
        start_index = 0

        while len(all_cves) < max_results:
            # Build query params
            params = {
                'resultsPerPage': min(results_per_page, 2000),
                'startIndex': start_index
            }

            # Add CPE match string
            if product:
                # CPE format: cpe:2.3:h:vendor:product:*:*:*:*:*:*:*:*
                params['cpeName'] = f'cpe:2.3:*:{vendor.lower()}:{product.lower()}:*:*:*:*:*:*:*:*'
            else:
                # Search by keyword
                params['keywordSearch'] = vendor

            # Make request
            data = self._make_request(params)

            if not data or 'vulnerabilities' not in data:
                break

            # Extract CVEs
            vulnerabilities = data['vulnerabilities']
            if not vulnerabilities:
                break

            # Process CVEs
            for vuln in vulnerabilities:
                cve_data = self._process_cve(vuln)
                if cve_data:
                    all_cves.append(cve_data)

            # Check if more results available
            total_results = data.get('totalResults', 0)
            if start_index + len(vulnerabilities) >= total_results:
                break

            start_index += len(vulnerabilities)

            # Respect max_results
            if len(all_cves) >= max_results:
                all_cves = all_cves[:max_results]
                break

        logger.info(f"Found {len(all_cves)} CVEs for {vendor}")
        return all_cves

    def search_iot_cves(
        self,
        keywords: Optional[List[str]] = None,
        results_per_page: int = 100,
        max_results: int = 500
    ) -> List[Dict[str, Any]]:
        """
        Search for IoT-related CVEs.

        Args:
            keywords: List of keywords (default: IoT-related keywords)
            results_per_page: Results per page
            max_results: Maximum results to fetch

        Returns:
            List of CVE dictionaries
        """
        if keywords is None:
            keywords = ['IoT', 'router', 'camera', 'smart', 'embedded']

        logger.info(f"Searching for IoT CVEs with keywords: {keywords}")

        all_cves = []

        for keyword in keywords:
            params = {
                'keywordSearch': keyword,
                'resultsPerPage': min(results_per_page, 2000),
                'startIndex': 0
            }

            data = self._make_request(params)

            if data and 'vulnerabilities' in data:
                for vuln in data['vulnerabilities']:
                    cve_data = self._process_cve(vuln)
                    if cve_data:
                        # Avoid duplicates
                        if not any(c['cve_id'] == cve_data['cve_id'] for c in all_cves):
                            all_cves.append(cve_data)

            if len(all_cves) >= max_results:
                all_cves = all_cves[:max_results]
                break

        logger.info(f"Found {len(all_cves)} IoT-related CVEs")
        return all_cves

    def _process_cve(self, vulnerability: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Process and extract relevant CVE information.

        Args:
            vulnerability: Raw vulnerability data from NVD

        Returns:
            Processed CVE dictionary or None
        """
        try:
            cve_info = vulnerability.get('cve', {})

            cve_id = cve_info.get('id', '')

            # Extract description
            descriptions = cve_info.get('descriptions', [])
            description = ''
            for desc in descriptions:
                if desc.get('lang') == 'en':
                    description = desc.get('value', '')
                    break

            # Extract CVSS scores
            metrics = cve_info.get('metrics', {})
            cvss_v3 = None
            cvss_score = 0.0
            severity = 'unknown'

            if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                cvss_v3 = metrics['cvssMetricV31'][0]['cvssData']
                cvss_score = cvss_v3.get('baseScore', 0.0)
                severity = cvss_v3.get('baseSeverity', 'unknown').lower()
            elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
                cvss_v3 = metrics['cvssMetricV30'][0]['cvssData']
                cvss_score = cvss_v3.get('baseScore', 0.0)
                severity = cvss_v3.get('baseSeverity', 'unknown').lower()
            elif 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
                cvss_v2 = metrics['cvssMetricV2'][0]['cvssData']
                cvss_score = cvss_v2.get('baseScore', 0.0)
                severity = 'medium'  # Default for v2

            # Extract published and modified dates
            published = cve_info.get('published', '')
            last_modified = cve_info.get('lastModified', '')

            # Extract CPE configurations
            cpe_list = []
            configurations = cve_info.get('configurations', [])
            for config in configurations:
                nodes = config.get('nodes', [])
                for node in nodes:
                    cpe_match = node.get('cpeMatch', [])
                    for cpe in cpe_match:
                        if cpe.get('vulnerable', False):
                            cpe_list.append(cpe.get('criteria', ''))

            return {
                'cve_id': cve_id,
                'description': description,
                'cvss_score': cvss_score,
                'severity': severity,
                'published': published,
                'last_modified': last_modified,
                'cpe_list': cpe_list
            }

        except Exception as e:
            logger.error(f"Error processing CVE: {e}")
            return None

    def cleanup_old_cache(self, days: int = 7):
        """
        Remove cache entries older than specified days.

        Args:
            days: Number of days to keep
        """
        try:
            conn = sqlite3.connect(self.cache_db_path)
            cursor = conn.cursor()

            cutoff_time = datetime.now() - timedelta(days=days)

            cursor.execute(
                "DELETE FROM nvd_cache WHERE cached_at < ?",
                (cutoff_time.isoformat(),)
            )

            deleted = cursor.rowcount
            conn.commit()
            conn.close()

            if deleted > 0:
                logger.info(f"Cleaned up {deleted} old cache entries")

        except Exception as e:
            logger.error(f"Error cleaning up cache: {e}")


# Global NVD client instance
_nvd_client = None


def get_nvd_client(api_key: Optional[str] = None) -> NVDAPIClient:
    """
    Get global NVD API client instance.

    Args:
        api_key: NVD API key (optional)

    Returns:
        NVDAPIClient instance
    """
    global _nvd_client
    if _nvd_client is None:
        _nvd_client = NVDAPIClient(api_key=api_key)
    return _nvd_client
