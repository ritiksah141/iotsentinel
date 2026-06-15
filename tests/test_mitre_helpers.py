"""Unit tests for the MITRE tactic helpers used by the Attack Path Sankey.

These back the Bug-3 fix: alerts persist a mitre_tactic string and the Sankey
reduces it to a clean kill-chain stage, with a fallback that recovers the tactic
from legacy free-text explanations.
"""

from dashboard.shared import mitre_stage_from_tactic, mitre_tactic_from_explanation


class TestMitreStageFromTactic:
    def test_strips_id_and_description(self):
        assert mitre_stage_from_tactic(
            "Exfiltration (TA0010) - Large outbound data transfer"
        ) == "Exfiltration"

    def test_strips_id_only(self):
        assert mitre_stage_from_tactic("Command and Control (TA0011)") == "Command and Control"

    def test_plain_name_passes_through(self):
        assert mitre_stage_from_tactic("Discovery") == "Discovery"

    def test_none_is_unknown(self):
        assert mitre_stage_from_tactic(None) == "Unknown"

    def test_empty_is_unknown(self):
        assert mitre_stage_from_tactic("") == "Unknown"

    def test_unknown_tactic_string(self):
        assert mitre_stage_from_tactic("Unknown - Further investigation recommended") == "Unknown"


class TestMitreTacticFromExplanation:
    def test_recovers_embedded_tactic(self):
        explanation = (
            "Anomalous activity detected. Connection: TCP to 1.2.3.4:443 (HTTPS). "
            "MITRE ATT&CK: Lateral Movement (TA0008) - Remote access protocol. "
            "Note: River continuously learns."
        )
        assert mitre_tactic_from_explanation(explanation) == \
            "Lateral Movement (TA0008) - Remote access protocol"

    def test_returns_none_without_marker(self):
        assert mitre_tactic_from_explanation("Just a plain explanation with no tactic.") is None

    def test_none_input(self):
        assert mitre_tactic_from_explanation(None) is None

    def test_chains_into_stage(self):
        """The two helpers compose: explanation -> tactic -> stage."""
        explanation = "Stuff happened. MITRE ATT&CK: Exfiltration (TA0010) - big upload."
        tactic = mitre_tactic_from_explanation(explanation)
        assert mitre_stage_from_tactic(tactic) == "Exfiltration"
