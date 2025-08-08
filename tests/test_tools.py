
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

    @patch('src.cti_agent.tools.VectorStoreManager')
    @patch('src.cti_agent.tools.Agent')
    async def test_find_defensive_measures(self, MockAgent, MockVectorStoreManager):
        mock_vector_store_instance = MockVectorStoreManager.return_value
        mock_agent_instance = MockAgent.return_value

        # Mock search results from VectorStoreManager
        mock_vector_store_instance.search.side_effect = [
            # Snort results
            {'documents': [["snort rule content 1", "snort rule content 2"]], 'metadatas': [[{}, {}]], 'ids': [["id1", "id2"]], 'distances': [[0.1, 0.2]]},
            # Sigma results
            {'documents': [["sigma rule content 1"]], 'metadatas': [[{}]], 'ids': [["id3"]], 'distances': [[0.3]]},
            # Yara results
            {'documents': [["yara rule content 1", "yara rule content 2", "yara rule content 3"]], 'metadatas': [[{}, {}, {}]], 'ids': [["id4", "id5", "id6"]], 'distances': [[0.4, 0.5, 0.6]]},
        ]

        # Mock LLM response for formatting
        mock_agent_instance.run.return_value.output = "Formatted rules from LLM: Snort: ..., Sigma: ..., Yara: ..."

        cve_id = "CVE-2023-1234"
        defensive_measures = await find_defensive_measures(cve_id)

        self.assertIsInstance(defensive_measures, dict)
        self.assertIn("snort", defensive_measures)
        self.assertIn("sigma", defensive_measures)
        self.assertIn("yara", defensive_measures)
        self.assertIn("formatted_output", defensive_measures)

        self.assertEqual(defensive_measures["snort"], ["snort rule content 1", "snort rule content 2"])
        self.assertEqual(defensive_measures["sigma"], ["sigma rule content 1"])
        self.assertEqual(defensive_measures["yara"], ["yara rule content 1", "yara rule content 2", "yara rule content 3"])
        self.assertEqual(defensive_measures["formatted_output"], "Formatted rules from LLM: Snort: ..., Sigma: ..., Yara: ...")

        # Verify VectorStoreManager.search calls
        mock_vector_store_instance.search.assert_any_call(query=f"Snort rules for {cve_id}", where={"rule_type": "snort", "cve_id": cve_id})
        mock_vector_store_instance.search.assert_any_call(query=f"Sigma rules for {cve_id}", where={"rule_type": "sigma", "cve_id": cve_id})
        mock_vector_store_instance.search.assert_any_call(query=f"Yara rules for {cve_id}", where={"rule_type": "yara", "cve_id": cve_id})

        # Verify Agent.run call
        MockAgent.assert_called_once_with(
            'google-gla:gemini-2.5-flash',
            system_prompt=unittest.mock.ANY # We don't need to assert the exact system prompt here
        )
        mock_agent_instance.run.assert_called_once()
