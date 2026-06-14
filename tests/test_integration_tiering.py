#!/usr/bin/env python3
"""
Tests for Phase 1 — API hub integration tiering (essential / advanced / enterprise).

Covers:
- All 17 integrations carry a 'tier' field with a valid value
- Tier counts are exactly 3 essential, 9 advanced, 5 enterprise
- The tier-based filtering logic produces the correct counts per persona
- Setup wizard still only requests essential-tier credentials

Run: pytest tests/test_integration_tiering.py -v
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


from alerts.integration_system import INTEGRATIONS

VALID_TIERS = {'essential', 'advanced', 'enterprise'}

# Expected tier membership (locked in plan)
EXPECTED_ESSENTIAL = {'email_smtp', 'abuseipdb', 'ip_api'}
EXPECTED_ADVANCED = {
    'virustotal', 'alienvault_otx', 'greynoise',
    'ipinfo',
    'ntfy', 'slack', 'discord', 'telegram', 'pushover',
}
EXPECTED_ENTERPRISE = {
    'github_issues', 'gitlab_issues', 'trello',
    'zapier', 'ifttt',
}


class TestIntegrationTierField:

    def test_all_integrations_have_tier(self):
        missing = [k for k, v in INTEGRATIONS.items() if 'tier' not in v]
        assert missing == [], f"Missing 'tier' key: {missing}"

    def test_all_tiers_are_valid_values(self):
        invalid = {k: v['tier'] for k, v in INTEGRATIONS.items() if v['tier'] not in VALID_TIERS}
        assert invalid == {}, f"Invalid tier values: {invalid}"

    def test_total_integration_count_is_17(self):
        assert len(INTEGRATIONS) == 17

    def test_essential_count_is_3(self):
        essential = {k for k, v in INTEGRATIONS.items() if v['tier'] == 'essential'}
        assert len(essential) == 3, f"Expected 3 essential, got {len(essential)}: {essential}"

    def test_advanced_count_is_9(self):
        advanced = {k for k, v in INTEGRATIONS.items() if v['tier'] == 'advanced'}
        assert len(advanced) == 9, f"Expected 9 advanced, got {len(advanced)}: {advanced}"

    def test_enterprise_count_is_5(self):
        enterprise = {k for k, v in INTEGRATIONS.items() if v['tier'] == 'enterprise'}
        assert len(enterprise) == 5, f"Expected 5 enterprise, got {len(enterprise)}: {enterprise}"


class TestTierMembership:

    def test_essential_integrations_are_correct(self):
        essential = {k for k, v in INTEGRATIONS.items() if v['tier'] == 'essential'}
        assert essential == EXPECTED_ESSENTIAL

    def test_advanced_integrations_are_correct(self):
        advanced = {k for k, v in INTEGRATIONS.items() if v['tier'] == 'advanced'}
        assert advanced == EXPECTED_ADVANCED

    def test_enterprise_integrations_are_correct(self):
        enterprise = {k for k, v in INTEGRATIONS.items() if v['tier'] == 'enterprise'}
        assert enterprise == EXPECTED_ENTERPRISE

    def test_no_key_required_for_essential_no_key_integrations(self):
        """ip_api must have empty setup_fields (zero-friction, no API key required)."""
        assert INTEGRATIONS['ip_api']['setup_fields'] == [], \
            f"ip_api expected no setup_fields but got {INTEGRATIONS['ip_api']['setup_fields']}"


class TestTierFilteringLogic:
    """
    Verifies the filtering logic that update_api_integration_hub applies.
    Simple mode: essential only (4). Advanced mode: all tiers (25).
    Tests use the INTEGRATIONS dict directly — no Dash callback needed.
    """

    def _filter(self, visible_tiers):
        return [k for k, v in INTEGRATIONS.items() if v['tier'] in visible_tiers]

    def test_simple_sees_only_essential(self):
        visible = self._filter({'essential'})
        assert len(visible) == 3

    def test_advanced_sees_all(self):
        visible = self._filter({'essential', 'advanced', 'enterprise'})
        assert len(visible) == 17

    def test_simple_cannot_see_enterprise(self):
        visible = set(self._filter({'essential'}))
        for k in EXPECTED_ENTERPRISE:
            assert k not in visible

    def test_simple_cannot_see_advanced_tier(self):
        visible = set(self._filter({'essential'}))
        for k in EXPECTED_ADVANCED:
            assert k not in visible


class TestSetupWizardEssentialsOnly:
    """
    Confirms the setup wizard only asks about essential-tier integrations.
    It should never surface advanced or enterprise credentials at first boot.
    """

    def test_wizard_step2_fields_are_subset_of_essential(self):
        """The wizard collects email_smtp + abuseipdb (+ Groq which is not a registered integration)."""
        from dashboard.layouts import setup_wizard
        import inspect
        src = inspect.getsource(setup_wizard)
        # The wizard must reference essential integrations
        assert 'setup-smtp-user' in src or 'email' in src.lower(), \
            "Wizard should have an email/SMTP step"
        assert 'abuseipdb' in src.lower(), \
            "Wizard should have an AbuseIPDB step"
        # The wizard must NOT reference enterprise integrations at first boot
        for enterprise_key in ('github_issues', 'gitlab_issues', 'trello', 'zapier', 'ifttt'):
            assert enterprise_key not in src.lower(), \
                f"Wizard should not reference enterprise integration '{enterprise_key}'"
