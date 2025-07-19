import pytest
from src.cti_agent.agent import agent
from src.cti_agent.models import EnrichedVulnerability
import os

@pytest.fixture
def mock_sbom_file_integration(tmp_path):
    sbom_content = '''
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.4",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "log4j",
      "version": "2.14.1",
      "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
      "cpe": "cpe:/a:apache:log4j:2.14.1"
    }
  ]
}
    '''
    f = tmp_path / "bom_integration.json"
    f.write_text(sbom_content)
    return str(f)

def test_full_analysis_run(mock_sbom_file_integration):
    # This test will run the full agent, so it requires live API keys and network access.
    # In a real CI/CD pipeline, you might mock external API calls for faster, more reliable tests.
    # For this integration test, we'll assume the environment variables are set.
    
    # Ensure API keys are set for the test environment
    if "GEMINI_API_KEY" not in os.environ:
        os.environ["GEMINI_API_KEY"] = os.getenv("GEMINI_API_KEY", "YOUR_GEMINI_API_KEY")
    if "NVD_API_KEY" not in os.environ:
        os.environ["NVD_API_KEY"] = os.getenv("NVD_API_KEY", "YOUR_NVD_API_KEY")

    report = agent.run(sbom_file_path=mock_sbom_file_integration)
    
    assert isinstance(report, str) # Expecting a markdown string
    assert "Cyber Threat Intelligence Analysis Report" in report
    assert "log4j" in report
    assert "CVE" in report
    assert "Actively Exploited" in report or "Not Listed" in report
