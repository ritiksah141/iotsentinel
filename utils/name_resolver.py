#!/usr/bin/env python3
"""
Device Name Resolver for IoTSentinel

Enriches ARP-discovered devices with human-readable names using:
  1. Reverse DNS (PTR lookup) — stdlib socket, no sudo, no deps
  2. NetBIOS/NBNS node-status request — pure UDP socket, no sudo, no deps
  3. Manufacturer friendly fallback — vendor + device type (e.g. "Samsung TV")

All methods are dependency-free (stdlib only) and require no elevated privileges.

Public API
----------
    resolve_name(ip, mac=None, manufacturer=None, device_type=None) -> Optional[str]
    is_synthetic(name) -> bool
"""

import logging
import socket
import struct
import threading
import time
from typing import Dict, Optional, Tuple

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from config.config_manager import config

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Config (with safe fallbacks so the resolver works even without the key)
# ---------------------------------------------------------------------------
_nr_cfg = config.get('discovery', 'name_resolution', default={})

_DNS_ENABLED:          bool  = _nr_cfg.get('reverse_dns',          True)
_NETBIOS_ENABLED:      bool  = _nr_cfg.get('netbios',              True)
_MFR_FALLBACK_ENABLED: bool  = _nr_cfg.get('manufacturer_fallback', True)
_DNS_TIMEOUT:          float = float(_nr_cfg.get('dns_timeout',    1.0))
_NETBIOS_TIMEOUT:      float = 0.8   # fixed — UDP reply is fast or not at all
_CACHE_TTL:            float = float(_nr_cfg.get('cache_ttl_seconds', 3600))

# ---------------------------------------------------------------------------
# In-process result cache  {ip: (resolved_name_or_None, expiry_monotonic)}
# ---------------------------------------------------------------------------
_cache: Dict[str, Tuple[Optional[str], float]] = {}
_cache_lock = threading.Lock()


def _cache_get(ip: str) -> Tuple[bool, Optional[str]]:
    with _cache_lock:
        entry = _cache.get(ip)
    if entry and time.monotonic() < entry[1]:
        return True, entry[0]
    return False, None


def _cache_set(ip: str, name: Optional[str]) -> None:
    with _cache_lock:
        _cache[ip] = (name, time.monotonic() + _CACHE_TTL)


# ---------------------------------------------------------------------------
# Tier 1 — Reverse DNS (PTR)
# ---------------------------------------------------------------------------

def _clean_dns_hostname(raw: str) -> str:
    """Strip domain suffixes and return a clean short hostname."""
    for suffix in ('.local', '.lan', '.home', '.localdomain', '.internal',
                   '.gateway', '.router', '.broadband', '.bthomehub'):
        if raw.lower().endswith(suffix):
            raw = raw[:-len(suffix)]
            break
    # Take only the first label (leftmost component)
    label = raw.split('.')[0]
    # Title-case if it looks like all-lowercase (e.g. "living-room-tv")
    if label and label == label.lower():
        label = label.replace('-', ' ').replace('_', ' ').title().replace(' ', '-')
    return label


def _resolve_reverse_dns(ip: str) -> Optional[str]:
    """
    Attempt a PTR reverse-DNS lookup with a hard timeout using a daemon thread.
    Returns a cleaned hostname or None.
    """
    result_holder: list = [None]

    def _lookup() -> None:
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            result_holder[0] = hostname
        except (socket.herror, socket.gaierror, OSError):
            pass

    t = threading.Thread(target=_lookup, daemon=True)
    t.start()
    t.join(_DNS_TIMEOUT)

    raw = result_holder[0]
    if not raw or raw == ip:
        return None

    cleaned = _clean_dns_hostname(raw)
    if not cleaned:
        return None

    logger.debug(f"Reverse DNS {ip} → {cleaned}")
    return cleaned


# ---------------------------------------------------------------------------
# Tier 2 — NetBIOS/NBNS Node Status Request (pure-socket, no sudo)
# ---------------------------------------------------------------------------

# Pre-built NBNS Node Status Request packet
# Name: wildcard '*' padded to 16 bytes, NetBIOS-encoded → 32 chars
# QTYPE: 0x0021 (NBSTAT)   QCLASS: 0x0001 (IN)
_NBNS_TXN_ID = b'\xAB\xCD'
_NBNS_ENCODED_WILDCARD = b'\x43\x4B' + b'\x41\x41' * 15   # 'CK' + 'AA'*15
_NBNS_PACKET = (
    _NBNS_TXN_ID           # transaction ID
    + b'\x00\x00'          # flags: standard query
    + b'\x00\x01'          # QDCOUNT = 1
    + b'\x00\x00'          # ANCOUNT = 0
    + b'\x00\x00'          # NSCOUNT = 0
    + b'\x00\x00'          # ARCOUNT = 0
    + b'\x20'              # label length = 32
    + _NBNS_ENCODED_WILDCARD
    + b'\x00'              # end of name
    + b'\x00\x21'          # QTYPE  = NBSTAT
    + b'\x00\x01'          # QCLASS = IN
)


def _skip_nbns_name(data: bytes, offset: int) -> int:
    """Advance offset past a DNS/NBNS encoded name (handles pointers)."""
    while offset < len(data):
        length = data[offset]
        if length == 0:
            return offset + 1
        if length >= 0xC0:      # compression pointer
            return offset + 2
        offset += 1 + length
    return offset


def _parse_nbns_response(data: bytes) -> Optional[str]:
    """
    Parse an NBNS node-status response and return the best device name.
    Returns None on any parse error or if no useful name found.
    """
    if len(data) < 12:
        return None
    if data[0:2] != _NBNS_TXN_ID:
        return None
    flags = struct.unpack('!H', data[2:4])[0]
    if not (flags & 0x8000):    # must be a response (QR bit)
        return None
    qdcount = struct.unpack('!H', data[4:6])[0]
    ancount = struct.unpack('!H', data[6:8])[0]
    if ancount == 0:
        return None

    offset = 12
    # Skip questions
    for _ in range(qdcount):
        offset = _skip_nbns_name(data, offset)
        offset += 4             # QTYPE + QCLASS

    # Parse first answer RR
    offset = _skip_nbns_name(data, offset)
    if offset + 10 > len(data):
        return None

    rtype = struct.unpack('!H', data[offset:offset + 2])[0]
    offset += 8                 # type(2) + class(2) + ttl(4)
    if offset + 2 > len(data):
        return None
    # rdlength — not used; we read forward manually
    offset += 2                 # rdlength

    if rtype != 0x0021:         # not NBSTAT
        return None
    if offset >= len(data):
        return None

    num_names = data[offset]
    offset += 1

    workstation_names: list = []
    fileserver_names: list  = []

    for _ in range(num_names):
        if offset + 18 > len(data):
            break
        raw_name   = data[offset: offset + 15]
        suffix     = data[offset + 15]
        name_flags = struct.unpack('!H', data[offset + 16: offset + 18])[0]
        offset += 18

        # Skip group names (bit 15 of flags)
        if name_flags & 0x8000:
            continue

        try:
            name = raw_name.decode('ascii', errors='replace').rstrip()
        except Exception:
            continue

        if not name or name == '*':
            continue

        if suffix == 0x00:
            workstation_names.append(name)
        elif suffix == 0x20:
            fileserver_names.append(name)

    for name in workstation_names:
        return name
    for name in fileserver_names:
        return name
    return None


def _resolve_netbios(ip: str) -> Optional[str]:
    """
    Send an NBNS node-status request to port 137 and parse the reply.
    Pure stdlib UDP — no sudo, no external binary.
    Returns a name string or None.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(_NETBIOS_TIMEOUT)
        sock.sendto(_NBNS_PACKET, (ip, 137))
        response, _ = sock.recvfrom(1024)
        sock.close()
        name = _parse_nbns_response(response)
        if name:
            logger.debug(f"NetBIOS {ip} → {name}")
        return name
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Tier 3 — Manufacturer friendly fallback
# ---------------------------------------------------------------------------

# Map device_type → human-friendly suffix word
_TYPE_DISPLAY: Dict[str, str] = {
    'router':          'Router',
    'switch':          'Switch',
    'access_point':    'Access Point',
    'smartphone':      'Phone',
    'mobile':          'Phone',
    'laptop':          'Laptop',
    'desktop':         'Computer',
    'workstation':     'Computer',
    'smart_tv':        'TV',
    'television':      'TV',
    'tv':              'TV',
    'camera':          'Camera',
    'ip_camera':       'Camera',
    'printer':         'Printer',
    'nas':             'NAS',
    'game_console':    'Game Console',
    'smart_speaker':   'Speaker',
    'speaker':         'Speaker',
    'thermostat':      'Thermostat',
    'light':           'Smart Light',
    'smart_light':     'Smart Light',
    'smart_plug':      'Smart Plug',
    'plug':            'Smart Plug',
    'hub':             'Hub',
    'tablet':          'Tablet',
    'raspberry_pi':    'Raspberry Pi',
    'iot_device':      'IoT Device',
    'sensor':          'Sensor',
    'gateway':         'Gateway',
    'voip':            'VoIP Device',
    'media_player':    'Media Player',
}

# Words that are noisy prefixes in vendor strings (strip them)
_VENDOR_NOISE = {
    'inc', 'inc.', 'ltd', 'ltd.', 'co.', 'corp', 'corp.',
    'llc', 'gmbh', 'ag', 's.a', 'b.v.', 'technologies',
    'technology', 'electronics', 'systems', 'solutions',
    'networks', 'semiconductor', 'computer',
}

# Well-known brand names as they appear in OUI strings → friendly display name
_BRAND_MAP: Dict[str, str] = {
    'apple':        'Apple',
    'samsung':      'Samsung',
    'google':       'Google',
    'amazon':       'Amazon',
    'microsoft':    'Microsoft',
    'sony':         'Sony',
    'lg':           'LG',
    'huawei':       'Huawei',
    'xiaomi':       'Xiaomi',
    'tp-link':      'TP-Link',
    'tplink':       'TP-Link',
    'asus':         'ASUS',
    'netgear':      'Netgear',
    'cisco':        'Cisco',
    'linksys':      'Linksys',
    'd-link':       'D-Link',
    'dlink':        'D-Link',
    'ubiquiti':     'Ubiquiti',
    'philips':      'Philips',
    'ring':         'Ring',
    'nest':         'Nest',
    'wyze':         'Wyze',
    'roku':         'Roku',
    'sonos':        'Sonos',
    'bose':         'Bose',
    'logitech':     'Logitech',
    'intel':        'Intel',
    'broadcom':     'Broadcom',
    'raspberry':    'Raspberry Pi',
    'espressif':    'ESP Device',
    'nordic':       'Nordic',
    'bosch':        'Bosch',
    'siemens':      'Siemens',
    'hikvision':    'Hikvision',
    'dahua':        'Dahua',
    'synology':     'Synology',
    'qnap':         'QNAP',
    'western':      'WD',
    'seagate':      'Seagate',
    'hp':           'HP',
    'hewlett':      'HP',
    'dell':         'Dell',
    'lenovo':       'Lenovo',
    'asus':         'ASUS',
    'acer':         'Acer',
    'toshiba':      'Toshiba',
    'panasonic':    'Panasonic',
    'sharp':        'Sharp',
    'hisense':      'Hisense',
    'tcl':          'TCL',
    'vizio':        'VIZIO',
    'amazon':       'Amazon',
    'belkin':       'Belkin',
    'wemo':         'Wemo',
}


def _extract_brand(manufacturer: str) -> Optional[str]:
    """Extract a clean brand name from an OUI manufacturer string."""
    if not manufacturer or manufacturer.lower() in ('unknown', ''):
        return None
    # A randomized/locally-administered MAC has no real vendor — don't mangle the
    # sentinel string into a fake brand ("Private/Random Device"). _build_manufacturer
    # _fallback handles these separately into a clean "Private device".
    if 'private' in manufacturer.lower() or 'random' in manufacturer.lower():
        return None
    low = manufacturer.lower()
    # Check known brand map first (longest match wins)
    for key, brand in _BRAND_MAP.items():
        if key in low:
            return brand
    # Generic: take first word, skip noise words
    words = manufacturer.split()
    for word in words:
        stripped = word.strip('.,()').lower()
        if stripped not in _VENDOR_NOISE and len(stripped) >= 2:
            return word.strip('.,()').title()
    return None


def _build_manufacturer_fallback(
    manufacturer: Optional[str],
    device_type:  Optional[str],
) -> Optional[str]:
    """
    Build a friendly label like 'Samsung TV' or 'TP-Link Router'.
    Returns None if neither vendor nor type is known.
    """
    # Privacy MAC randomization (common on modern phones/laptops) reports no real
    # vendor. Give it a clean, honest label rather than a raw MAC or mangled string.
    mfr_low = (manufacturer or '').lower()
    if 'private' in mfr_low or 'random' in mfr_low:
        tw = _TYPE_DISPLAY.get((device_type or '').lower())
        return f"Private {tw}" if tw and tw not in ('Unknown', 'IoT Device') else "Private device"

    brand      = _extract_brand(manufacturer or '')
    type_word  = _TYPE_DISPLAY.get((device_type or '').lower())

    if brand and type_word:
        # Avoid redundant "Raspberry Pi Raspberry Pi" case
        if type_word.lower() in brand.lower():
            return brand
        return f"{brand} {type_word}"
    if brand:
        return f"{brand} Device"
    if type_word and type_word not in ('Unknown', 'IoT Device'):
        return type_word
    return None


# ---------------------------------------------------------------------------
# Synthetic-name detector
# ---------------------------------------------------------------------------

def is_synthetic(name: Optional[str]) -> bool:
    """
    Return True if *name* is empty, an IP address, or a machine-generated
    placeholder that carries no human-readable information.

    Examples that return True:
        None, '', 'unknown', 'Device-A1B2C3', '192.168.1.42'
    Examples that return False:
        'living-room-tv', 'DESKTOP-ABC123', 'Samsung TV'
    """
    if not name:
        return True
    if name.lower() in ('unknown', 'none'):
        return True
    if name.startswith('Device-') and len(name) == 13:
        return True
    # MAC-derived placeholders (e.g. 'MAC-C3D40B' from older builds / seed data) carry
    # no human-readable info — treat as synthetic so they get re-resolved to a friendly
    # vendor/hostname name instead of lingering in the device list and topology.
    if name.upper().startswith('MAC-'):
        return True
    # Looks like a raw IP address
    parts = name.split('.')
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return True
    return False


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def resolve_name(
    ip:           str,
    mac:          Optional[str] = None,
    manufacturer: Optional[str] = None,
    device_type:  Optional[str] = None,
) -> Optional[str]:
    """
    Return the best human-readable name for a device, or None if only a
    synthetic placeholder would result.

    Resolution order (first non-None result wins):
      1. Reverse DNS (PTR)
      2. NetBIOS node-status (NBNS)
      3. Manufacturer + device-type friendly label

    Results are cached for *cache_ttl_seconds* (default 1 h) to avoid
    re-querying DNS/NetBIOS on every 60-second scan cycle.

    No sudo required. No external binaries. No pip dependencies beyond stdlib.
    """
    # Check cache first
    hit, cached = _cache_get(ip)
    if hit:
        return cached

    name: Optional[str] = None

    # --- Tier 1: Reverse DNS ---
    if _DNS_ENABLED:
        try:
            name = _resolve_reverse_dns(ip)
        except Exception as exc:
            logger.debug(f"Reverse DNS error for {ip}: {exc}")

    # --- Tier 2: NetBIOS ---
    if not name and _NETBIOS_ENABLED:
        try:
            name = _resolve_netbios(ip)
        except Exception as exc:
            logger.debug(f"NetBIOS error for {ip}: {exc}")

    # --- Tier 3: Manufacturer fallback ---
    if not name and _MFR_FALLBACK_ENABLED:
        try:
            name = _build_manufacturer_fallback(manufacturer, device_type)
        except Exception as exc:
            logger.debug(f"Manufacturer fallback error for {ip}: {exc}")

    _cache_set(ip, name)
    if name:
        logger.info(f"Resolved {ip} → {name!r}")
    return name


def clear_cache() -> None:
    """Flush the in-process name cache (useful for testing)."""
    with _cache_lock:
        _cache.clear()
