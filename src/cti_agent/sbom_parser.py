"""
This module provides functions for parsing SBOM files and extracting entities.
"""


"""
This module provides functions for parsing SBOM files and extracting entities.
"""
import json
import re
from pydantic_ai import Agent
from .models import SbomEntities, Component
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component as CycloneDxComponent
from xml.etree import ElementTree

async def extract_entities_from_sbom(sbom_content: str) -> SbomEntities:
    """
    Extracts component entities from an SBOM file using the cyclonedx-python library.
    This function no longer extracts CVEs directly, as CVE lookup should be a 
    separate, deterministic step in the analysis pipeline.

    Args:
        sbom_content: The raw content of the SBOM file (JSON or XML).

    Returns:
        An SbomEntities object containing the extracted package components.
    """
    packages = []

    bom = None
    try:
        # Attempt to parse as JSON
        bom = Bom.from_json(data=json.loads(sbom_content))
    except Exception:
        try:
            # Attempt to parse as XML
            bom = Bom.from_xml(data=ElementTree.fromstring(sbom_content))
        except Exception as e:
            raise ValueError(f"Could not parse SBOM content as JSON or XML: {e}")

    for component in bom.components:
        packages.append(Component(name=component.name, version=component.version))

    # Deduplicate packages to ensure each component is processed only once.
    packages_unique = []
    seen_packages = set()
    for p in packages:
        if (p.name, p.version) not in seen_packages:
            packages_unique.append(p)
            seen_packages.add((p.name, p.version))

    return SbomEntities(packages=packages_unique, cpes=[], cves=[])

def generate_search_queries(entities: SbomEntities) -> list[str]:
    """
    Generates a list of precise search queries from the extracted SBOM entities.

    Args:
        entities: An SbomEntities object containing the extracted entities.

    Returns:
        A list of search queries.
    """
    queries = set()
    for package in entities.packages:
        queries.add(f"{package.name} {package.version} vulnerability")
        queries.add(f"exploit for {package.name} {package.version}")
    for cve in entities.cves:
        queries.add(cve)
    for cpe in entities.cpes:
        queries.add(cpe)
    return list(queries)

