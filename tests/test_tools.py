import pytest
from src.cti_agent.tools import parse_sbom, query_nvd_for_cves, correlate_with_cisa_kev, get_cpe_for_component, map_cve_to_attack, find_defensive_measures
from src.cti_agent.models import Component, Vulnerability
import os
import json

# Mock data for testing
@pytest.fixture
def mock_sbom_file(tmp_path):
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
    },
    {
      "type": "library",
      "name": "spring-core",
      "version": "5.3.10",
      "purl": "pkg:maven/org.springframework/spring-core@5.3.10"
    }
  ]
}
    '''
    f = tmp_path / "bom.json"
    f.write_text(sbom_content)
    return str(f)

@pytest.fixture
def mock_cisa_kev_file(tmp_path):
    kev_content = '''
{
  "vulnerabilities": [
    {
      "cveID": "CVE-2021-44228",
      "vendorProject": "Apache",
      "product": "Log4j",
      "vulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability",
      "dateAdded": "2021-12-10",
      "shortDescription": "Apache Log4j2 2.14.1 and below are vulnerable to remote code execution.",
      "requiredAction": "Apply updates per vendor instructions.",
      "dueDate": "2021-12-24",
      "knownRansomwareCampaignUse": "Multiple",
      "notes": ""
    }
  ]
}
    '''
    f = tmp_path / "cisa_kev.json"
    f.write_text(kev_content)
    # Ensure the frameworks directory exists and the file is placed there
    frameworks_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'frameworks')
    os.makedirs(frameworks_dir, exist_ok=True)
    target_path = os.path.join(frameworks_dir, "cisa_kev.json")
    with open(target_path, 'w') as dest_f:
        dest_f.write(kev_content)
    return target_path


def test_parse_sbom(mock_sbom_file):
    components = parse_sbom(mock_sbom_file)
    assert len(components) == 2
    assert components[0].name == "log4j"
    assert components[0].version == "2.14.1"
    assert components[0].cpe == "cpe:/a:apache:log4j:2.14.1"
    assert components[1].name == "spring-core"

def test_query_nvd_for_cves():
    # This test requires a live NVD API key and network access.
    # For automated testing, consider mocking the requests.get call.
    # For now, we'll use a known CPE that should return results.
    os.environ["NVD_API_KEY"] = os.getenv("NVD_API_KEY", "YOUR_NVD_API_KEY") # Ensure API key is set
    cves = query_nvd_for_cves("cpe:/a:apache:log4j:2.14.1")
    assert len(cves) > 0
    assert isinstance(cves[0], Vulnerability)

def test_correlate_with_cisa_kev(mock_cisa_kev_file):
    # Temporarily change the working directory to ensure the test finds the mock KEV file
    original_cwd = os.getcwd()
    os.chdir(os.path.dirname(mock_cisa_kev_file))
    
    kev_info = correlate_with_cisa_kev(["CVE-2021-44228", "CVE-2020-12345"])
    assert "CVE-2021-44228" in kev_info
    assert "CVE-2020-12345" not in kev_info
    assert kev_info["CVE-2021-44228"]["product"] == "Log4j"
    
    os.chdir(original_cwd)

def test_get_cpe_for_component():
    cpe = get_cpe_for_component("Apache Log4j", "2.17.1")
    assert cpe == "cpe:2.3:a:apache log4j:apache log4j:2.17.1:*:*:*:*:*:*:*"

def test_map_cve_to_attack():
    mappings = map_cve_to_attack("CVE-2021-44228", "Remote code execution in Log4j")
    assert len(mappings) > 0
    assert "tactic" in mappings[0]

def test_find_defensive_measures():
    measures = find_defensive_measures("CVE-2021-44228")
    assert "sigma" in measures
    assert len(measures["sigma"]) > 0
