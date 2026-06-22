"""
Tests for utils/name_resolver.py

Covers: reverse-DNS, NetBIOS parse, manufacturer fallback,
is_synthetic, priority preservation, and cache behaviour.
"""

import socket
import struct
from unittest.mock import MagicMock, patch, call

import pytest


# ---------------------------------------------------------------------------
# Patch config so the module loads cleanly without a real config file path
# ---------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def _patch_config(monkeypatch):
    """Provide a minimal config so name_resolver imports without error."""
    mock_cfg = MagicMock()
    mock_cfg.get.return_value = {
        'reverse_dns':          True,
        'netbios':              True,
        'manufacturer_fallback': True,
        'dns_timeout':          1.0,
        'cache_ttl_seconds':    3600,
    }
    import sys
    fake_cm = MagicMock()
    fake_cm.config = mock_cfg
    sys.modules.setdefault('config.config_manager', fake_cm)
    # Reload the resolver so _nr_cfg picks up the mock
    import importlib
    import utils.name_resolver as nr
    importlib.reload(nr)
    # Ensure each test starts with an empty cache
    nr.clear_cache()
    yield nr
    nr.clear_cache()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_nbns_response(names):
    """
    Build a minimal NBNS node-status response byte-string.
    names: list of (name_str_15, suffix, is_group)
    """
    TXN_ID    = b'\xAB\xCD'
    FLAGS     = struct.pack('!H', 0x8500)   # response, authoritative
    QDCOUNT   = struct.pack('!H', 0)        # no question echoed
    ANCOUNT   = struct.pack('!H', 1)
    NSCOUNT   = struct.pack('!H', 0)
    ARCOUNT   = struct.pack('!H', 0)
    header    = TXN_ID + FLAGS + QDCOUNT + ANCOUNT + NSCOUNT + ARCOUNT

    # Answer RR — name as pointer (0xC00C would normally point somewhere;
    # we skip question so the parser just reads from offset 12 directly).
    # Use a 0x00 terminated single-char label as a simple stub.
    rr_name   = b'\x00'                    # root label (empty name)
    rr_type   = struct.pack('!H', 0x0021)  # NBSTAT
    rr_class  = struct.pack('!H', 0x0001)  # IN
    rr_ttl    = struct.pack('!I', 0)

    num_names = len(names)
    name_bytes = bytes([num_names])
    for (nm, suffix, is_group) in names:
        nm_padded = nm.ljust(15)[:15].encode('ascii')
        flags_val  = 0x8000 if is_group else 0x0000
        name_bytes += nm_padded + bytes([suffix]) + struct.pack('!H', flags_val)
    # 6-byte stats (MAC + padding)
    name_bytes += b'\x00' * 6

    rr_rdlen  = struct.pack('!H', len(name_bytes))
    answer    = rr_name + rr_type + rr_class + rr_ttl + rr_rdlen + name_bytes
    return header + answer


# ---------------------------------------------------------------------------
# is_synthetic
# ---------------------------------------------------------------------------

class TestIsSynthetic:
    def test_none_is_synthetic(self, _patch_config):
        assert _patch_config.is_synthetic(None) is True

    def test_empty_string(self, _patch_config):
        assert _patch_config.is_synthetic('') is True

    def test_unknown_string(self, _patch_config):
        assert _patch_config.is_synthetic('unknown') is True

    def test_device_prefix(self, _patch_config):
        assert _patch_config.is_synthetic('Device-A1B2C3') is True

    def test_raw_ip(self, _patch_config):
        assert _patch_config.is_synthetic('192.168.1.42') is True

    def test_real_hostname(self, _patch_config):
        assert _patch_config.is_synthetic('living-room-tv') is False

    def test_real_netbios_name(self, _patch_config):
        assert _patch_config.is_synthetic('DESKTOP-ABC123') is False

    def test_manufacturer_label(self, _patch_config):
        assert _patch_config.is_synthetic('Samsung TV') is False

    def test_mac_prefixed_placeholder_is_synthetic(self, _patch_config):
        # Legacy/seed 'MAC-XXXXXX' labels (seen in the topology) must be treated as
        # synthetic so they get re-resolved to a friendly name.
        assert _patch_config.is_synthetic('MAC-C3D40B') is True
        assert _patch_config.is_synthetic('mac-abc123') is True


# ---------------------------------------------------------------------------
# Reverse DNS
# ---------------------------------------------------------------------------

class TestReverseDns:
    def test_resolves_and_cleans(self, _patch_config):
        with patch('socket.gethostbyaddr',
                   return_value=('living-room-tv.local', [], ['192.168.1.5'])):
            result = _patch_config._resolve_reverse_dns('192.168.1.5')
        assert result == 'Living-Room-Tv'

    def test_strips_lan_suffix(self, _patch_config):
        with patch('socket.gethostbyaddr',
                   return_value=('MyNAS.lan', [], ['192.168.1.10'])):
            result = _patch_config._resolve_reverse_dns('192.168.1.10')
        assert result == 'MyNAS'

    def test_herror_returns_none(self, _patch_config):
        with patch('socket.gethostbyaddr', side_effect=socket.herror):
            result = _patch_config._resolve_reverse_dns('192.168.1.99')
        assert result is None

    def test_result_same_as_ip_returns_none(self, _patch_config):
        with patch('socket.gethostbyaddr',
                   return_value=('192.168.1.5', [], ['192.168.1.5'])):
            result = _patch_config._resolve_reverse_dns('192.168.1.5')
        assert result is None


# ---------------------------------------------------------------------------
# NetBIOS parse
# ---------------------------------------------------------------------------

class TestNetBiosResolve:
    def test_parses_workstation_name(self, _patch_config):
        payload   = _make_nbns_response([('MYPC          ', 0x00, False)])
        mock_sock = MagicMock()
        mock_sock.recvfrom.return_value = (payload, ('192.168.1.20', 137))
        with patch('socket.socket', return_value=mock_sock):
            result = _patch_config._resolve_netbios('192.168.1.20')
        assert result == 'MYPC'

    def test_skips_group_names(self, _patch_config):
        payload = _make_nbns_response([
            ('WORKGROUP      ', 0x00, True),   # group — skip
            ('MYDESKTOP      ', 0x00, False),  # unique — use this
        ])
        mock_sock = MagicMock()
        mock_sock.recvfrom.return_value = (payload, ('192.168.1.21', 137))
        with patch('socket.socket', return_value=mock_sock):
            result = _patch_config._resolve_netbios('192.168.1.21')
        assert result == 'MYDESKTOP'

    def test_socket_error_returns_none(self, _patch_config):
        mock_sock = MagicMock()
        mock_sock.recvfrom.side_effect = socket.timeout
        with patch('socket.socket', return_value=mock_sock):
            result = _patch_config._resolve_netbios('192.168.1.30')
        assert result is None

    def test_wrong_txn_id_returns_none(self, _patch_config):
        # Build response with wrong TXN_ID
        payload = b'\xFF\xFF' + b'\x85\x00\x00\x00\x00\x01' + b'\x00' * 50
        mock_sock = MagicMock()
        mock_sock.recvfrom.return_value = (payload, ('192.168.1.31', 137))
        with patch('socket.socket', return_value=mock_sock):
            result = _patch_config._resolve_netbios('192.168.1.31')
        assert result is None


# ---------------------------------------------------------------------------
# Manufacturer fallback
# ---------------------------------------------------------------------------

class TestManufacturerFallback:
    def test_vendor_and_type(self, _patch_config):
        result = _patch_config._build_manufacturer_fallback('Samsung Electronics', 'smart_tv')
        assert result == 'Samsung TV'

    def test_apple_phone(self, _patch_config):
        result = _patch_config._build_manufacturer_fallback('Apple, Inc.', 'smartphone')
        assert result == 'Apple Phone'

    def test_vendor_only(self, _patch_config):
        result = _patch_config._build_manufacturer_fallback('TP-Link Technologies', None)
        assert result == 'TP-Link Device'

    def test_type_only_no_vendor(self, _patch_config):
        result = _patch_config._build_manufacturer_fallback(None, 'router')
        assert result == 'Router'

    def test_nothing_known(self, _patch_config):
        result = _patch_config._build_manufacturer_fallback(None, None)
        assert result is None

    def test_unknown_vendor_string(self, _patch_config):
        result = _patch_config._build_manufacturer_fallback('Unknown', 'camera')
        assert result == 'Camera'

    def test_randomized_mac_gets_clean_private_label(self, _patch_config):
        # get_manufacturer() returns "Private/Random MAC" for privacy-randomized MACs
        # (modern phones/laptops). It must become a clean "Private device", NOT a
        # mangled "Private/Random Device".
        result = _patch_config._build_manufacturer_fallback('Private/Random MAC', None)
        assert result == 'Private device'

    def test_randomized_mac_with_type(self, _patch_config):
        result = _patch_config._build_manufacturer_fallback('Private/Random MAC', 'smartphone')
        assert result == 'Private Phone'

    def test_randomized_mac_not_treated_as_brand(self, _patch_config):
        assert _patch_config._extract_brand('Private/Random MAC') is None

    def test_raspberry_pi(self, _patch_config):
        result = _patch_config._build_manufacturer_fallback('Raspberry Pi Foundation', 'raspberry_pi')
        assert 'Raspberry Pi' in result


# ---------------------------------------------------------------------------
# resolve_name — tier ordering and fallthrough
# ---------------------------------------------------------------------------

class TestResolveName:
    def test_dns_wins_over_netbios(self, _patch_config):
        with patch.object(_patch_config, '_resolve_reverse_dns', return_value='dns-host'), \
             patch.object(_patch_config, '_resolve_netbios',     return_value='NB-HOST'):
            result = _patch_config.resolve_name('192.168.1.50')
        assert result == 'dns-host'

    def test_falls_through_to_netbios(self, _patch_config):
        with patch.object(_patch_config, '_resolve_reverse_dns', return_value=None), \
             patch.object(_patch_config, '_resolve_netbios',     return_value='NB-HOST'):
            result = _patch_config.resolve_name('192.168.1.51')
        assert result == 'NB-HOST'

    def test_falls_through_to_manufacturer(self, _patch_config):
        with patch.object(_patch_config, '_resolve_reverse_dns', return_value=None), \
             patch.object(_patch_config, '_resolve_netbios',     return_value=None):
            result = _patch_config.resolve_name(
                '192.168.1.52',
                manufacturer='Samsung Electronics',
                device_type='smart_tv',
            )
        assert result == 'Samsung TV'

    def test_returns_none_when_all_fail(self, _patch_config):
        with patch.object(_patch_config, '_resolve_reverse_dns', return_value=None), \
             patch.object(_patch_config, '_resolve_netbios',     return_value=None):
            result = _patch_config.resolve_name('192.168.1.53')
        assert result is None


# ---------------------------------------------------------------------------
# Cache behaviour
# ---------------------------------------------------------------------------

class TestCache:
    def test_second_call_uses_cache(self, _patch_config):
        _patch_config.clear_cache()
        with patch.object(_patch_config, '_resolve_reverse_dns', return_value='cached-host') as mock_dns, \
             patch.object(_patch_config, '_resolve_netbios',     return_value=None):
            _patch_config.resolve_name('192.168.1.60')
            _patch_config.resolve_name('192.168.1.60')
        # DNS should only be called once (second call hits cache)
        assert mock_dns.call_count == 1

    def test_different_ips_not_shared(self, _patch_config):
        _patch_config.clear_cache()
        with patch.object(_patch_config, '_resolve_reverse_dns', side_effect=['host-a', 'host-b']), \
             patch.object(_patch_config, '_resolve_netbios', return_value=None):
            r1 = _patch_config.resolve_name('192.168.1.70')
            r2 = _patch_config.resolve_name('192.168.1.71')
        assert r1 == 'host-a'
        assert r2 == 'host-b'

    def test_clear_cache_forces_re_lookup(self, _patch_config):
        _patch_config.clear_cache()
        with patch.object(_patch_config, '_resolve_reverse_dns', return_value='first') as mock_dns, \
             patch.object(_patch_config, '_resolve_netbios', return_value=None):
            _patch_config.resolve_name('192.168.1.80')
            _patch_config.clear_cache()
            _patch_config.resolve_name('192.168.1.80')
        assert mock_dns.call_count == 2
