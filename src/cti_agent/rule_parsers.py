from typing import Optional, Dict, Any
from .models import SnortRuleMetadata, SigmaRuleMetadata, YaraRuleMetadata

import re

def parse_snort_rule_metadata(rule_content: str, cve_id: Optional[str] = None, component_name: Optional[str] = None, source_url: Optional[str] = None) -> SnortRuleMetadata:
    """
    Parses Snort rule content to extract metadata.
    This is a placeholder and can be enhanced with more sophisticated parsing.
    """
    description = "Snort rule"
    # Basic attempt to extract msg from Snort rule
    match = re.search(r'msg:"([^"]+)"', rule_content)
    if match:
        description = match.group(1)
    
    return SnortRuleMetadata(
        rule_type="snort",
        cve_id=cve_id,
        component_name=component_name,
        source_url=source_url,
        description=description
    )

def parse_sigma_rule_metadata(rule_content: str, cve_id: Optional[str] = None, component_name: Optional[str] = None, source_url: Optional[str] = None) -> SigmaRuleMetadata:
    """
    Parses Sigma rule content to extract metadata.
    This is a placeholder and can be enhanced with more sophisticated parsing.
    """
    description = "Sigma rule"
    # Basic attempt to extract title from Sigma rule (assuming YAML format)
    match = re.search(r'title:\s*(.*)', rule_content)
    if match:
        description = match.group(1).strip()
    
    return SigmaRuleMetadata(
        rule_type="sigma",
        cve_id=cve_id,
        component_name=component_name,
        source_url=source_url,
        description=description
    )

def parse_yara_rule_metadata(rule_content: str, cve_id: Optional[str] = None, component_name: Optional[str] = None, source_url: Optional[str] = None) -> YaraRuleMetadata:
    """
    Parses Yara rule content to extract metadata.
    This is a placeholder and can be enhanced with more sophisticated parsing.
    """
    description = "Yara rule"
    # Basic attempt to extract rule name from Yara rule
    match = re.search(r'rule\s+([^\s]+)', rule_content)
    if match:
        description = f"Yara rule: {match.group(1).strip()}"
    
    return YaraRuleMetadata(
        rule_type="yara",
        cve_id=cve_id,
        component_name=component_name,
        source_url=source_url,
        description=description
    )
