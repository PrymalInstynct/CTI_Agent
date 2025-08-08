import pytest
from src.cti_agent.rule_parsers import parse_snort_rule_metadata, parse_sigma_rule_metadata, parse_yara_rule_metadata
from src.cti_agent.models import SnortRuleMetadata, SigmaRuleMetadata, YaraRuleMetadata

def test_parse_snort_rule_metadata():
    rule_content = 'alert tcp any any -> any any (msg:"ET POLICY Outbound FTP"; flow:established; content:"USER "; nocase; pcre:"/USER\s+\S+/i"; classtype:policy-violation; sid:2000001; rev:1;)'
    metadata = parse_snort_rule_metadata(rule_content, cve_id="CVE-2023-1234", source_url="http://example.com/snort")
    assert isinstance(metadata, SnortRuleMetadata)
    assert metadata.rule_type == "snort"
    assert metadata.cve_id == "CVE-2023-1234"
    assert metadata.source_url == "http://example.com/snort"
    assert metadata.description == "ET POLICY Outbound FTP"

def test_parse_snort_rule_metadata_no_msg():
    rule_content = 'alert tcp any any -> any any (flow:established; sid:2000002; rev:1;)'
    metadata = parse_snort_rule_metadata(rule_content)
    assert isinstance(metadata, SnortRuleMetadata)
    assert metadata.description == "Snort rule"

def test_parse_sigma_rule_metadata():
    rule_content = """
    title: Suspicious PowerShell Activity
    id: 12345
    description: Detects suspicious PowerShell command line arguments.
    logsource:
        product: windows
        service: powershell
    detection:
        selection:
            CommandLine|contains:
                - 'Invoke-Mimikatz'
        condition: selection
    """
    metadata = parse_sigma_rule_metadata(rule_content, component_name="powershell")
    assert isinstance(metadata, SigmaRuleMetadata)
    assert metadata.rule_type == "sigma"
    assert metadata.component_name == "powershell"
    assert metadata.description == "Suspicious PowerShell Activity"

def test_parse_sigma_rule_metadata_no_title():
    rule_content = """
    id: 12345
    description: Detects suspicious PowerShell command line arguments.
    """
    metadata = parse_sigma_rule_metadata(rule_content)
    assert isinstance(metadata, SigmaRuleMetadata)
    assert metadata.description == "Sigma rule"

def test_parse_yara_rule_metadata():
    rule_content = """
    rule evil_malware_sample
    {
      meta:
        author = "John Doe"
        description = "Detects a specific malware sample"
      strings:
        $a = "MZ"
        $b = "This program cannot be run in DOS mode."
      condition:
        $a and $b
    }
    """
    metadata = parse_yara_rule_metadata(rule_content, cve_id="CVE-2023-5678")
    assert isinstance(metadata, YaraRuleMetadata)
    assert metadata.rule_type == "yara"
    assert metadata.cve_id == "CVE-2023-5678"
    assert metadata.description == "Yara rule: evil_malware_sample"

def test_parse_yara_rule_metadata_no_rule_name():
    rule_content = """
    rule
    {
      meta:
        author = "John Doe"
      strings:
        $a = "test"
      condition:
        $a
    }
    """
    metadata = parse_yara_rule_metadata(rule_content)
    assert isinstance(metadata, YaraRuleMetadata)
    assert metadata.description == "Yara rule"
