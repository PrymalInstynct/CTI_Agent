
import os
import json
import unittest
from unittest.mock import patch, MagicMock
from src.cti_agent.tools import parse_sbom, query_nvd_for_cves, correlate_with_cisa_kev, get_cpe_for_component, map_cve_to_attack, find_defensive_measures
from src.cti_agent.models import Component

class TestTools(unittest.TestCase):
    def setUp(self):
        self.sbom_json_path = "sbom.json"
        self.sbom_xml_path = "sbom.xml"

    @patch("src.cti_agent.tools.get_db")
    def test_parse_sbom_json(self, mock_get_db):
        mock_db = MagicMock()
        mock_get_db.return_value = mock_db
        
        components = parse_sbom(self.sbom_json_path)
        self.assertIsInstance(components, list)
        self.assertGreater(len(components), 0)
        self.assertIsInstance(components[0], Component)
        mock_db.__getitem__.assert_called_with("sboms")

    @patch("src.cti_agent.tools.get_db")
    def test_parse_sbom_xml(self, mock_get_db):
        mock_db = MagicMock()
        mock_get_db.return_value = mock_db
        
        components = parse_sbom(self.sbom_xml_path)
        self.assertIsInstance(components, list)
        self.assertGreater(len(components), 0)
        self.assertIsInstance(components[0], Component)
        mock_db.__getitem__.assert_called_with("sboms")

    @patch("src.cti_agent.tools.get_db")
    @patch("builtins.open", new_callable=unittest.mock.mock_open, read_data="data")
    def test_parse_sbom_unsupported(self, mock_open, mock_get_db):
        mock_get_db.return_value = MagicMock()
        with self.assertRaises(ValueError):
            parse_sbom("unsupported.txt")

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

    def test_find_defensive_measures(self):
        defensive_measures = find_defensive_measures("CVE-2021-44228")
        self.assertIsInstance(defensive_measures, dict)
        self.assertIn("sigma", defensive_measures)

if __name__ == "__main__":
    unittest.main()
