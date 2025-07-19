from pydantic import BaseModel, Field
from typing import List, Optional

class Component(BaseModel):
    """Represents a single software component from the SBOM."""
    name: str
    version: str
    purl: Optional[str] = None
    cpe: Optional[str] = None

class Vulnerability(BaseModel):
    """Represents a single CVE record retrieved from NVD."""
    cve_id: str
    description: str
    cvss_score: float
    weaknesses: List[str]

class EnrichedVulnerability(BaseModel):
    """A composite model that represents a fully analyzed vulnerability."""
    vulnerability: Vulnerability
    is_in_kev: bool = False
    kev_details: Optional[dict] = None
    attack_mappings: List[dict] = Field(default_factory=list)
    defensive_measures: dict = Field(default_factory=dict)

class AnalysisReport(BaseModel):
    """The top-level model that structures the final report."""
    analysis_metadata: dict
    prioritized_vulnerabilities: List[EnrichedVulnerability]
