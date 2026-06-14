"""Batched IP geolocation with caching (ip-api.com free tier).

Why this exists: the threat-map and country-stats callbacks each looped up to
20 IPs making sequential blocking requests — up to 40 per refresh against
ip-api.com's 45 req/min free-tier cap, so requests were throttled into read
timeouts and every refresh re-queried the same addresses. This module makes
ONE batch POST (up to 100 IPs) and caches results: 24 h for successes (geo
data is effectively static) and 10 min for failures, so an offline LAN-only
Pi logs one debug line instead of a warning per IP per refresh.
"""

import logging
import threading
import time
from typing import Dict, Iterable, Optional

import requests

logger = logging.getLogger(__name__)

BATCH_URL = 'http://ip-api.com/batch?fields=status,country,countryCode,lat,lon,isp,query'
BATCH_LIMIT = 100      # ip-api batch maximum
REQUEST_TIMEOUT = 5    # one batched call may take longer than the old per-IP 2 s
SUCCESS_TTL = 24 * 3600
FAILURE_TTL = 600
MAX_CACHE_ENTRIES = 5000

_cache: Dict[str, tuple] = {}   # ip -> (expires_at, geo_dict_or_None)
_lock = threading.Lock()


def geolocate_ips(ips: Iterable[str]) -> Dict[str, dict]:
    """Resolve IPs to geo info. Returns {ip: geo} for IPs that resolved;
    unresolvable IPs are omitted. geo keys: country, country_code, lat,
    lon, isp."""
    now = time.time()
    result: Dict[str, dict] = {}
    missing = []
    with _lock:
        for ip in dict.fromkeys(ips):  # de-dupe, keep order
            hit = _cache.get(ip)
            if hit and hit[0] > now:
                if hit[1] is not None:
                    result[ip] = hit[1]
            else:
                missing.append(ip)

    if missing:
        fetched = _fetch_batch(missing[:BATCH_LIMIT])
        with _lock:
            if len(_cache) > MAX_CACHE_ENTRIES:
                _evict_expired(now)
            for ip in missing[:BATCH_LIMIT]:
                geo = fetched.get(ip)
                ttl = SUCCESS_TTL if geo else FAILURE_TTL
                _cache[ip] = (now + ttl, geo)
                if geo:
                    result[ip] = geo
    return result


def geolocate_ip(ip: str) -> Optional[dict]:
    """Single-IP convenience wrapper."""
    return geolocate_ips([ip]).get(ip)


def _fetch_batch(ips) -> Dict[str, dict]:
    try:
        resp = requests.post(BATCH_URL, json=list(ips), timeout=REQUEST_TIMEOUT)
        if resp.status_code != 200:
            logger.debug("ip-api batch returned HTTP %s", resp.status_code)
            return {}
        out = {}
        for entry in resp.json():
            if entry.get('status') == 'success' and entry.get('query'):
                out[entry['query']] = {
                    'country': entry.get('country', 'Unknown'),
                    'country_code': entry.get('countryCode', '??'),
                    'lat': entry.get('lat', 0),
                    'lon': entry.get('lon', 0),
                    'isp': entry.get('isp', 'Unknown'),
                }
        return out
    except (requests.RequestException, ValueError) as exc:
        # Expected on offline / LAN-only installs — not warning-worthy.
        logger.debug("ip-api batch lookup failed (%d IPs): %s", len(list(ips)), exc)
        return {}


def _evict_expired(now: float) -> None:
    expired = [ip for ip, (exp, _) in _cache.items() if exp <= now]
    for ip in expired:
        del _cache[ip]
    if len(_cache) > MAX_CACHE_ENTRIES:
        _cache.clear()  # pathological case: full reset is cheaper than LRU


def clear_cache() -> None:
    """Test helper."""
    with _lock:
        _cache.clear()
