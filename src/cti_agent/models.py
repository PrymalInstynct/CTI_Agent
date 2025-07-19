"""Pydantic models for the CTI Agent."""
from typing import List, Optional
from pydantic import BaseModel, Field
import os
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv()

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
    is_in_kev: bool
    kev_details: Optional[dict] = None
    attack_mappings: List[dict]
    defensive_measures: dict

class AnalysisReport(BaseModel):
    """The top-level model that structures the final report."""
    analysis_metadata: dict
    prioritized_vulnerabilities: List[EnrichedVulnerability]

class SBOM(BaseModel):
    """Represents an SBOM document in MongoDB."""
    filename: str
    timestamp: str
    sbom_format: str
    raw_content: dict
    components_count: int

    class Config:
        collection_name = "sboms"

def get_db():
    """Returns a MongoDB client instance."""
    mongo_host = os.getenv("MONGO_DB_HOST", "localhost")
    mongo_port = int(os.getenv("MONGO_DB_PORT", 27017))
    mongo_db_name = os.getenv("MONGO_DB_NAME", "cti_agent_db")
    client = MongoClient(mongo_host, mongo_port)
    return client[mongo_db_name]
