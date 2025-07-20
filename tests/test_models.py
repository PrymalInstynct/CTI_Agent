
import pytest
import os
from unittest.mock import patch, MagicMock
from src.cti_agent.models import get_db, Component, Vulnerability, EnrichedVulnerability, AnalysisReport, SBOM
from pymongo import MongoClient

@patch('src.cti_agent.models.MongoClient')
@patch.dict(os.environ, {
    'MONGO_DB_HOST': 'test_host',
    'MONGO_DB_PORT': '12345',
    'MONGO_DB_NAME': 'test_db'
})
def test_get_db_connection(mock_mongo_client):
    db = get_db()
    mock_mongo_client.assert_called_once_with('test_host', 12345)
    mock_mongo_client.return_value.__getitem__.assert_called_once_with('test_db')
    assert db == mock_mongo_client.return_value.__getitem__.return_value

def test_component_model():
    component = Component(name="test_component", version="1.0.0", purl="pkg:test/test_component@1.0.0", cpe="cpe:/a:test:test_component:1.0.0")
    assert component.name == "test_component"
    assert component.version == "1.0.0"
    assert component.purl == "pkg:test/test_component@1.0.0"
    assert component.cpe == "cpe:/a:test:test_component:1.0.0"

def test_vulnerability_model():
    vulnerability = Vulnerability(cve_id="CVE-2023-0001", description="Test vulnerability", cvss_score=7.5, weaknesses=["CWE-123"])
    assert vulnerability.cve_id == "CVE-2023-0001"
    assert vulnerability.description == "Test vulnerability"
    assert vulnerability.cvss_score == 7.5
    assert vulnerability.weaknesses == ["CWE-123"]

def test_enriched_vulnerability_model():
    vulnerability = Vulnerability(cve_id="CVE-2023-0001", description="Test vulnerability", cvss_score=7.5, weaknesses=["CWE-123"])
    enriched_vulnerability = EnrichedVulnerability(
        vulnerability=vulnerability,
        is_in_kev=True,
        kev_details={"details": "KEV details"},
        attack_mappings=[{"tactic": "TA0001"}],
        defensive_measures={"sigma": ["rule1"]}
    )
    assert enriched_vulnerability.vulnerability == vulnerability
    assert enriched_vulnerability.is_in_kev == True
    assert enriched_vulnerability.kev_details == {"details": "KEV details"}
    assert enriched_vulnerability.attack_mappings == [{"tactic": "TA0001"}]
    assert enriched_vulnerability.defensive_measures == {"sigma": ["rule1"]}

def test_analysis_report_model():
    vulnerability = Vulnerability(cve_id="CVE-2023-0001", description="Test vulnerability", cvss_score=7.5, weaknesses=["CWE-123"])
    enriched_vulnerability = EnrichedVulnerability(
        vulnerability=vulnerability,
        is_in_kev=True,
        kev_details={"details": "KEV details"},
        attack_mappings=[{"tactic": "TA0001"}],
        defensive_measures={"sigma": ["rule1"]}
    )
    analysis_report = AnalysisReport(
        analysis_metadata={'timestamp': '2025-07-19'},
        prioritized_vulnerabilities=[enriched_vulnerability]
    )
    assert analysis_report.analysis_metadata == {'timestamp': '2025-07-19'}
    assert analysis_report.prioritized_vulnerabilities == [enriched_vulnerability]

def test_sbom_model():
    sbom = SBOM(
        filename="test.json",
        timestamp="2025-07-19T10:00:00Z",
        sbom_format="json",
        raw_content={'key': 'value'},
        components_count=10
    )
    assert sbom.filename == "test.json"
    assert sbom.timestamp == "2025-07-19T10:00:00Z"
    assert sbom.sbom_format == "json"
    assert sbom.raw_content == {'key': 'value'}
    assert sbom.components_count == 10
    assert SBOM.Config.collection_name == "sboms"
