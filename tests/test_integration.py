
import unittest
import asyncio
from unittest.mock import patch, AsyncMock, MagicMock
from src.cti_agent.agent import run_analysis
from src.cti_agent.models import Component, Vulnerability

class TestIntegration(unittest.TestCase):

    @patch("src.cti_agent.agent.generate_markdown_report")
    @patch("src.cti_agent.tools.find_defensive_measures")
    @patch("src.cti_agent.tools.map_cve_to_attack")
    @patch("src.cti_agent.tools.correlate_with_cisa_kev")
    @patch("src.cti_agent.tools.query_nvd_for_cves")
    @patch("src.cti_agent.data_manager.load_and_store_sbom")
    @patch("src.cti_agent.agent.analysis_agent.run") # Patch the analysis_agent.run method
    def test_run_analysis_integration(
        self,
        mock_analysis_agent_run,
        mock_load_and_store_sbom,
        mock_query_nvd_for_cves,
        mock_correlate_with_cisa_kev,
        mock_map_cve_to_attack,
        mock_find_defensive_measures,
        mock_generate_report,
    ):
        # 1. Setup Mocks
        mock_load_and_store_sbom.return_value = ({
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
            "version": 1,
            "components": [
                {
                    "type": "library",
                    "name": "test-component",
                    "version": "1.0.0",
                }
            ],
        }, True)

        # Mock the primary entry point `analysis_agent.run` for CPE generation
        mock_analysis_agent_run.return_value = MagicMock(output="cpe:2.3:a:test:test-component:1.0.0:*:*:*:*:*:*:*")

        # Mock the subsequent tool calls within run_analysis
        mock_query_nvd_for_cves.return_value = [
            Vulnerability(cve_id="CVE-2022-12345", description="A test vulnerability", cvss_score=7.5, weaknesses=["CWE-123"])
        ]
        mock_correlate_with_cisa_kev.return_value = {}
        mock_map_cve_to_attack.return_value = []
        mock_find_defensive_measures.return_value = {}
        mock_generate_report.return_value = "Mock Report" # Prevent printing to console

        # 2. Run the analysis
        asyncio.run(run_analysis("sbom.json"))

        # 3. Assertions
        # Verify that load_and_store_sbom was called
        mock_load_and_store_sbom.assert_called_once_with("sbom.json")

        # Verify that the analysis_agent was called for CPE generation
        mock_analysis_agent_run.assert_any_call(f"Generate a CPE 2.3 string for the following software component. Return ONLY the CPE string and nothing else. Do NOT include any other text, explanation, or formatting. Component Name: test-component, Version: 1.0.0. Example: For 'Apache Log4j', version '2.14.1', the CPE is cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*")
        # Assert that the summary generation call was made
        mock_analysis_agent_run.assert_any_call(unittest.mock.ANY)
        self.assertEqual(mock_analysis_agent_run.call_count, 2)

        # Verify that the enrichment tools were called with the correct data
        mock_query_nvd_for_cves.assert_called_once_with("cpe:2.3:a:test:test-component:1.0.0:*:*:*:*:*:*:*")
        mock_correlate_with_cisa_kev.assert_called_once_with(["CVE-2022-12345"])
        mock_map_cve_to_attack.assert_called_once_with("CVE-2022-12345", "A test vulnerability")
        mock_find_defensive_measures.assert_called_once_with("CVE-2022-12345")
        mock_generate_report.assert_called_once()

if __name__ == "__main__":
    unittest.main()
