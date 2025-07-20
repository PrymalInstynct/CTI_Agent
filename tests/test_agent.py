import unittest
from unittest.mock import MagicMock
from src.cti_agent.agent import calculate_risk_score
from src.cti_agent.models import Vulnerability

class TestAgent(unittest.TestCase):

    def test_calculate_risk_score(self):
        vulnerability = Vulnerability(
            cve_id="CVE-2021-44228",
            description="Log4j remote code execution vulnerability",
            cvss_score=10.0,
            weaknesses=["CWE-502"]
        )
        kev_info = {"CVE-2021-44228": {"description": "Log4Shell"}}
        attack_mappings = [{"tactic": "TA0002", "technique_id": "T1059"}]

        risk_score = calculate_risk_score(vulnerability, kev_info, attack_mappings)
        self.assertIsInstance(risk_score, float)
        self.assertGreater(risk_score, 0.0)

    def test_calculate_risk_score_no_kev(self):
        vulnerability = Vulnerability(
            cve_id="CVE-2022-12345",
            description="A less critical vulnerability",
            cvss_score=5.0,
            weaknesses=["CWE-200"]
        )
        kev_info = {}
        attack_mappings = []

        risk_score = calculate_risk_score(vulnerability, kev_info, attack_mappings)
        self.assertIsInstance(risk_score, float)
        self.assertEqual(risk_score, 2.0) # 0.4 * 5.0

if __name__ == "__main__":
    unittest.main()