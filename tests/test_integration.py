
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
    @patch("src.cti_agent.tools.parse_sbom") # Mock parse_sbom directly
    @patch("src.cti_agent.agent.agent") # Patch the agent instance itself
    def test_run_analysis_integration(
        self,
        mock_agent,
        mock_parse_sbom,
        mock_query_nvd_for_cves,
        mock_correlate_with_cisa_kev,
        mock_map_cve_to_attack,
        mock_find_defensive_measures,
        mock_generate_report,
    ):
        # 1. Setup Mocks
        mock_parse_sbom.return_value = [Component(name="test-component", version="1.0.0", purl=None, cpe=None)]

        # Mock the primary entry point `agent.run` for CPE generation
        mock_agent.run.return_value = AsyncMock(return_value=MagicMock(output="cpe:2.3:a:test:test-component:1.0.0:*:*:*:*:*:*:*"))

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
        # Verify that parse_sbom was called
        mock_parse_sbom.assert_called_once_with("sbom.json")

        # Verify that the agent was called for CPE generation
        mock_agent.run.assert_called_once_with(f"Generate a CPE 2.3 string for the following software component. Provide only the CPE string and nothing else. Component Name: test-component, Version: 1.0.0. Example: For 'Apache Log4j', version '2.14.1', the CPE is cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*")

        # Verify that the enrichment tools were called with the correct data
        mock_query_nvd_for_cves.assert_called_once_with("cpe:2.3:a:test:test-component:1.0.0:*:*:*:*:*:*:*")
        mock_correlate_with_cisa_kev.assert_called_once_with(["CVE-2022-12345"])
        mock_map_cve_to_attack.assert_called_once_with("CVE-2022-12345", "A test vulnerability")
        mock_find_defensive_measures.assert_called_once_with("CVE-2022-12345")
        mock_generate_report.assert_called_once()

if __name__ == "__main__":
    unittest.main()
