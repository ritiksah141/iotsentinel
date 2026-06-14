"""Tests for utils/ip_geolocator.py — batched, cached IP geolocation.

Why this exists: the threat map and country-stats cards depend on this module
replacing 40 sequential ip-api.com requests per refresh with one cached batch
call. A caching bug would either re-introduce the rate-limit timeouts the old
code hit, or serve stale/missing geo data silently.
"""

import time
from unittest.mock import MagicMock, patch

import pytest
import requests

from utils import ip_geolocator
from utils.ip_geolocator import geolocate_ip, geolocate_ips


def _api_entry(ip, country='Germany', code='DE', lat=52.5, lon=13.4, isp='Hetzner'):
    return {'status': 'success', 'query': ip, 'country': country,
            'countryCode': code, 'lat': lat, 'lon': lon, 'isp': isp}


def _mock_response(entries, status_code=200):
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = entries
    return resp


@pytest.fixture(autouse=True)
def fresh_cache():
    ip_geolocator.clear_cache()
    yield
    ip_geolocator.clear_cache()


class TestGeolocateIps:
    def test_batch_success(self):
        with patch.object(requests, 'post',
                          return_value=_mock_response([_api_entry('1.2.3.4')])) as post:
            result = geolocate_ips(['1.2.3.4'])
        assert result['1.2.3.4']['country'] == 'Germany'
        assert result['1.2.3.4']['country_code'] == 'DE'
        assert result['1.2.3.4']['lat'] == 52.5
        assert post.call_count == 1

    def test_single_post_for_many_ips(self):
        ips = [f'8.8.8.{i}' for i in range(20)]
        entries = [_api_entry(ip) for ip in ips]
        with patch.object(requests, 'post', return_value=_mock_response(entries)) as post:
            result = geolocate_ips(ips)
        assert len(result) == 20
        assert post.call_count == 1  # ONE batch call, not 20

    def test_success_cached_no_second_request(self):
        with patch.object(requests, 'post',
                          return_value=_mock_response([_api_entry('1.2.3.4')])) as post:
            geolocate_ips(['1.2.3.4'])
            geolocate_ips(['1.2.3.4'])
        assert post.call_count == 1

    def test_failure_negative_cached(self):
        with patch.object(requests, 'post',
                          side_effect=requests.ConnectionError('offline')) as post:
            assert geolocate_ips(['1.2.3.4']) == {}
            assert geolocate_ips(['1.2.3.4']) == {}  # cached failure, no retry
        assert post.call_count == 1

    def test_timeout_returns_empty_not_raises(self):
        with patch.object(requests, 'post',
                          side_effect=requests.Timeout('read timeout')):
            assert geolocate_ips(['1.2.3.4']) == {}

    def test_failed_status_entries_omitted(self):
        entries = [_api_entry('1.1.1.1'),
                   {'status': 'fail', 'query': '192.168.1.5'}]
        with patch.object(requests, 'post', return_value=_mock_response(entries)):
            result = geolocate_ips(['1.1.1.1', '192.168.1.5'])
        assert '1.1.1.1' in result
        assert '192.168.1.5' not in result

    def test_http_error_returns_empty(self):
        with patch.object(requests, 'post', return_value=_mock_response([], status_code=429)):
            assert geolocate_ips(['1.2.3.4']) == {}

    def test_bad_json_returns_empty(self):
        resp = MagicMock()
        resp.status_code = 200
        resp.json.side_effect = ValueError('not json')
        with patch.object(requests, 'post', return_value=resp):
            assert geolocate_ips(['1.2.3.4']) == {}

    def test_deduplicates_input(self):
        with patch.object(requests, 'post',
                          return_value=_mock_response([_api_entry('1.2.3.4')])) as post:
            geolocate_ips(['1.2.3.4', '1.2.3.4', '1.2.3.4'])
        sent = post.call_args.kwargs.get('json') or post.call_args[1].get('json')
        assert sent == ['1.2.3.4']

    def test_batch_capped_at_limit(self):
        ips = [f'9.9.{i // 256}.{i % 256}' for i in range(150)]
        with patch.object(requests, 'post', return_value=_mock_response([])) as post:
            geolocate_ips(ips)
        sent = post.call_args.kwargs.get('json') or post.call_args[1].get('json')
        assert len(sent) == ip_geolocator.BATCH_LIMIT

    def test_expired_entry_refetched(self):
        with patch.object(requests, 'post',
                          return_value=_mock_response([_api_entry('1.2.3.4')])) as post:
            geolocate_ips(['1.2.3.4'])
            # force-expire the entry
            with ip_geolocator._lock:
                ip, (_, geo) = next(iter(ip_geolocator._cache.items()))
                ip_geolocator._cache[ip] = (time.time() - 1, geo)
            geolocate_ips(['1.2.3.4'])
        assert post.call_count == 2

    def test_mixed_cache_hit_and_miss(self):
        with patch.object(requests, 'post',
                          return_value=_mock_response([_api_entry('1.1.1.1')])):
            geolocate_ips(['1.1.1.1'])
        with patch.object(requests, 'post',
                          return_value=_mock_response([_api_entry('2.2.2.2', country='France', code='FR')])) as post:
            result = geolocate_ips(['1.1.1.1', '2.2.2.2'])
        sent = post.call_args.kwargs.get('json') or post.call_args[1].get('json')
        assert sent == ['2.2.2.2']  # only the miss is fetched
        assert result['1.1.1.1']['country'] == 'Germany'
        assert result['2.2.2.2']['country'] == 'France'


class TestGeolocateIp:
    def test_single_ip_wrapper(self):
        with patch.object(requests, 'post',
                          return_value=_mock_response([_api_entry('1.2.3.4')])):
            geo = geolocate_ip('1.2.3.4')
        assert geo['isp'] == 'Hetzner'

    def test_single_ip_failure_returns_none(self):
        with patch.object(requests, 'post', side_effect=requests.Timeout('t')):
            assert geolocate_ip('1.2.3.4') is None
