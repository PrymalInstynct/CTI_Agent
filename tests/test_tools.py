
import os
import json
import unittest
from unittest.mock import patch, MagicMock
from src.cti_agent.tools import query_nvd_for_cves, correlate_with_cisa_kev, get_cpe_for_component, map_cve_to_attack, find_defensive_measures
from src.cti_agent.models import Component

class TestTools(unittest.TestCase):
    def setUp(self):
        self.sbom_json_path = "sbom.json"
        self.sbom_xml_path = "sbom.xml"

    

    @patch("requests.get")
    def test_query_nvd_for_cves(self, mock_get):
        mock_response = unittest.mock.Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2021-44228",
                        "descriptions": [{"value": "Log4j remote code execution vulnerability"}],
                        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 10.0}}]},
                        "weaknesses": [{"description": [{"value": "CWE-502"}]}]
                    }
                }
            ]
        }
        mock_get.return_value = mock_response

        vulnerabilities = query_nvd_for_cves("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*")
        self.assertIsInstance(vulnerabilities, list)
        self.assertGreater(len(vulnerabilities), 0)
        self.assertEqual(vulnerabilities[0].cve_id, "CVE-2021-44228")

    def test_correlate_with_cisa_kev(self):
        cve_ids = ["CVE-2021-44228", "CVE-2022-12345"]
        kev_info = correlate_with_cisa_kev(cve_ids)
        self.assertIsInstance(kev_info, dict)
        self.assertIn("CVE-2021-44228", kev_info)

    def test_get_cpe_for_component(self):
        cpe_string = get_cpe_for_component("Apache Log4j", "2.14.1")
        self.assertEqual(cpe_string, "cpe:2.3:a:apache_log4j:apache_log4j:2.14.1:*:*:*:*:*:*:*")

    def test_map_cve_to_attack(self):
        attack_mappings = map_cve_to_attack("CVE-2021-44228", "Log4j remote code execution vulnerability")
        self.assertIsInstance(attack_mappings, list)
        self.assertGreater(len(attack_mappings), 0)

    async def test_find_defensive_measures(self):
        defensive_measures = await find_defensive_measures("CVE-2021-44228")
        self.assertIsInstance(defensive_measures, dict)
        self.assertIn("sigma", defensive_measures)

if __name__ == "__main__":
    import asyncio
    asyncio.run(unittest.main())
