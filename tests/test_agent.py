import unittest
from unittest.mock import MagicMock
from src.cti_agent.agent import calculate_risk_score
from src.cti_agent.models import Vulnerability, EnrichedVulnerability

class TestAgent(unittest.TestCase):

    def test_calculate_risk_score(self):
        vulnerability = Vulnerability(
            cve_id="CVE-2021-44228",
            description="Log4j remote code execution vulnerability",
            cvss_score=10.0,
            weaknesses=["CWE-502"]
        )
        enriched_vulnerability = EnrichedVulnerability(
            vulnerability=vulnerability,
            is_in_kev=True,
            kev_details={'cveID': 'CVE-2021-44228', 'vulnerabilityName': 'Log4Shell'},
            attack_mappings=[{'tactic': 'TA0002', 'technique_id': 'T1059'}],
            defensive_measures={'sigma': ['rule1']},
            epss_score=0.9
        )
        risk_score = calculate_risk_score(enriched_vulnerability)
        self.assertIsInstance(risk_score, float)
        self.assertGreater(risk_score, 0.0)

    def test_calculate_risk_score_no_kev(self):
        vulnerability = Vulnerability(
            cve_id="CVE-2022-12345",
            description="A less critical vulnerability",
            cvss_score=5.0,
            weaknesses=["CWE-200"]
        )
        enriched_vulnerability = EnrichedVulnerability(
            vulnerability=vulnerability,
            is_in_kev=False,
            kev_details={},
            attack_mappings=[],
            defensive_measures={},
            epss_score=0.1
        )
        risk_score = calculate_risk_score(enriched_vulnerability)
        self.assertIsInstance(risk_score, float)
        # Expected calculation: (0.3 * 5.0) + (0.4 * 0.0) + (0.1 * 0.0) + (0.2 * 0.1 * 10) = 1.5 + 0 + 0 + 0.2 = 1.7
        self.assertAlmostEqual(risk_score, 1.7)

if __name__ == "__main__":
    unittest.main()