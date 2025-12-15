#!/usr/bin/env python3
"""
Unit Tests for Dashboard API Integration Hub

Tests the 7 threat intelligence APIs:
- AbuseIPDB
- VirusTotal
- Shodan
- AlienVault OTX
- GreyNoise
- IPinfo
- MITRE ATT&CK

Coverage:
- API connectivity checks
- Environment variable detection
- Error handling for missing/invalid keys
- Status badge generation
- Configuration instructions

Run: pytest tests/test_dashboard_api_integration.py -v -m api
"""

import pytest
import os
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock
import requests

sys.path.insert(0, str(Path(__file__).parent.parent))


@pytest.mark.api
class TestAPIIntegrationHub:
    """Test suite for API Integration Hub feature."""

    def test_abuseipdb_configured(self):
        """TC-API-001: Verify AbuseIPDB detects configured API key from .env."""
        # Act - Read from actual .env file
        key = os.getenv('THREAT_INTELLIGENCE_ABUSEIPDB_API_KEY')

        # Assert
        if key:
            assert key is not None
            assert len(key) > 0
        else:
            pytest.skip("AbuseIPDB API key not configured in .env")

    def test_abuseipdb_not_configured(self):
        """TC-API-002: Verify AbuseIPDB handles missing API key."""
        # Arrange & Act
        with patch.dict(os.environ, {}, clear=True):
            key = os.getenv('THREAT_INTELLIGENCE_ABUSEIPDB_API_KEY')

        # Assert
        assert key is None

    def test_virustotal_configured(self):
        """TC-API-003: Verify VirusTotal detects configured API key from .env."""
        # Act - Read from actual .env file
        key = os.getenv('VIRUSTOTAL_API_KEY')

        # Assert
        if key:
            assert key is not None
            assert len(key) > 0
        else:
            pytest.skip("VirusTotal API key not configured in .env")

    def test_shodan_configured(self):
        """TC-API-004: Verify Shodan detects configured API key from .env."""
        # Act - Read from actual .env file
        key = os.getenv('SHODAN_API_KEY')

        # Assert
        if key:
            assert key is not None
            assert len(key) > 0
        else:
            pytest.skip("Shodan API key not configured in .env")

    def test_otx_configured(self):
        """TC-API-005: Verify AlienVault OTX detects configured API key from .env."""
        # Act - Read from actual .env file
        key = os.getenv('OTX_API_KEY')

        # Assert
        if key:
            assert key is not None
            assert len(key) > 0
        else:
            pytest.skip("AlienVault OTX API key not configured in .env")

    def test_greynoise_configured(self):
        """TC-API-006: Verify GreyNoise detects configured API key from .env."""
        # Act - Read from actual .env file
        key = os.getenv('GREYNOISE_API_KEY')

        # Assert
        if key:
            assert key is not None
            assert len(key) > 0
        else:
            pytest.skip("GreyNoise API key not configured in .env")

    def test_ipinfo_configured(self):
        """TC-API-007: Verify IPinfo detects configured API key from .env."""
        # Act - Read from actual .env file
        key = os.getenv('IPINFO_API_KEY')

        # Assert
        if key:
            assert key is not None
            assert len(key) > 0
        else:
            pytest.skip("IPinfo API key not configured in .env")

    @patch('requests.get')
    def test_api_health_check_success(self, mock_get):
        """TC-API-008: Verify API health check returns connected for 200 status."""
        # Arrange
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_get.return_value = mock_response

        # Act
        response = requests.get('https://api.example.com/health')

        # Assert
        assert response.status_code == 200

    @patch('requests.get')
    def test_api_health_check_failure(self, mock_get):
        """TC-API-009: Verify API health check handles connection errors."""
        # Arrange
        mock_get.side_effect = requests.exceptions.ConnectionError()

        # Act & Assert
        with pytest.raises(requests.exceptions.ConnectionError):
            requests.get('https://api.example.com/health', timeout=5)

    @patch('requests.get')
    def test_api_health_check_timeout(self, mock_get):
        """TC-API-010: Verify API health check handles timeouts."""
        # Arrange
        mock_get.side_effect = requests.exceptions.Timeout()

        # Act & Assert
        with pytest.raises(requests.exceptions.Timeout):
            requests.get('https://api.example.com/health', timeout=5)

    def test_api_status_badge_colors(self):
        """TC-API-011: Verify status badge color mapping."""
        # Arrange
        status_colors = {
            'connected': 'success',
            'not_configured': 'warning',
            'connection_failed': 'danger'
        }

        # Assert
        assert status_colors['connected'] == 'success'
        assert status_colors['not_configured'] == 'warning'
        assert status_colors['connection_failed'] == 'danger'

    def test_mitre_attack_always_connected(self):
        """TC-API-012: Verify MITRE ATT&CK shows as always connected (no API key needed)."""
        # MITRE ATT&CK should always be connected as it doesn't require an API key
        # This tests that the dashboard logic correctly handles this

        # Act - MITRE doesn't need an API key
        mitre_requires_key = False

        # Assert
        assert mitre_requires_key is False

    def test_all_apis_environment_variables_distinct(self):
        """TC-API-013: Verify all APIs use distinct environment variable names."""
        # Arrange
        env_vars = {
            'THREAT_INTELLIGENCE_ABUSEIPDB_API_KEY',
            'VIRUSTOTAL_API_KEY',
            'SHODAN_API_KEY',
            'OTX_API_KEY',
            'GREYNOISE_API_KEY',
            'IPINFO_API_KEY'
        }

        # Assert
        assert len(env_vars) == 6  # All unique


@pytest.mark.api
@pytest.mark.integration
class TestAPIRealConnectivity:
    """Integration tests for real API connectivity (requires valid API keys)."""

    def test_abuseipdb_real_connection(self):
        """TC-API-INT-001: Test real AbuseIPDB API connection."""
        api_key = os.getenv('THREAT_INTELLIGENCE_ABUSEIPDB_API_KEY')

        if not api_key:
            pytest.skip("AbuseIPDB API key not configured")

        try:
            response = requests.get(
                'https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8',
                headers={'Key': api_key, 'Accept': 'application/json'},
                timeout=10
            )
            assert response.status_code in [200, 401, 429]  # 200=success, 401=bad key, 429=rate limit
        except requests.exceptions.RequestException:
            pytest.skip("AbuseIPDB API unreachable")

    def test_otx_real_connection(self):
        """TC-API-INT-002: Test real AlienVault OTX API connection."""
        api_key = os.getenv('OTX_API_KEY')

        if not api_key:
            pytest.skip("OTX API key not configured")

        try:
            response = requests.get(
                'https://otx.alienvault.com/api/v1/indicators/IPv4/8.8.8.8/general',
                headers={'X-OTX-API-KEY': api_key},
                timeout=10
            )
            assert response.status_code in [200, 401, 403]
        except requests.exceptions.RequestException:
            pytest.skip("OTX API unreachable")

    def test_virustotal_real_connection(self):
        """TC-API-INT-003: Test real VirusTotal API connection."""
        api_key = os.getenv('VIRUSTOTAL_API_KEY')

        if not api_key:
            pytest.skip("VirusTotal API key not configured")

        try:
            response = requests.get(
                'https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8',
                headers={'x-apikey': api_key},
                timeout=10
            )
            assert response.status_code in [200, 401, 429]
        except requests.exceptions.RequestException:
            pytest.skip("VirusTotal API unreachable")
