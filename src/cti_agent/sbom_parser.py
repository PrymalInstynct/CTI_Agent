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
    Extracts entities from an SBOM file using cyclonedx-python library.

    Args:
        sbom_content: The raw content of the SBOM file (JSON or XML).

    Returns:
        An SbomEntities object containing the extracted entities.
    """
    packages = []
    cpes = []
    cves = []

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
        if component.cpe:
            cpes.append(str(component.cpe))
        # Extract CVEs if present in component properties or external references
        for prop in component.properties:
            if prop.name == "cve" or prop.name == "vulnerability":
                cves.append(prop.value)
        for ext_ref in component.external_references:
            if ext_ref.type == "vulnerability" and ext_ref.url:
                # Attempt to extract CVE ID from URL
                match = re.search(r"(CVE-\d{4}-\d{4,7})", str(ext_ref.url))
                if match:
                    cves.append(match.group(1))

    # Deduplicate lists
    packages_unique = []
    seen_packages = set()
    for p in packages:
        if (p.name, p.version) not in seen_packages:
            packages_unique.append(p)
            seen_packages.add((p.name, p.version))

    cpes_unique = list(set(cpes))
    cves_unique = list(set(cves))

    return SbomEntities(packages=packages_unique, cpes=cpes_unique, cves=cves_unique)

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

