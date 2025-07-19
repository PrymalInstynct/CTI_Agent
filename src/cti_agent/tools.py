"""Agent tools for the CTI Agent."""
import os
import json
import datetime
import time
import requests
from cyclonedx.model.bom import Bom
from cyclonedx.io import BomIO
from .models import get_db, Component, SBOM, Vulnerability


def parse_sbom(sbom_file_path: str) -> list[Component]:
    """Parses the input SBOM file to extract a list of software components.

    Args:
        sbom_file_path: The path to the SBOM file.

    Returns:
        A list of software components.
    """
    db = get_db()
    with open(sbom_file_path, 'r') as f:
        raw_content = f.read()

    if sbom_file_path.endswith('.json'):
        sbom_format = 'json'
        bom = Bom.from_json(raw_content)
        raw_dict = json.loads(raw_content)
    elif sbom_file_path.endswith('.xml'):
        sbom_format = 'xml'
        bom = Bom.from_xml(raw_content)
        # Converting XML to JSON for storing in MongoDB
        raw_dict = json.loads(bom.to_json())
    else:
        raise ValueError("Unsupported SBOM file format. Please use JSON or XML.")

    components = []
    for component in bom.components:
        components.append(
            Component(
                name=component.name,
                version=component.version,
                purl=str(component.purl) if component.purl else None,
                cpe=component.cpe if component.cpe else None,
            )
        )

    sbom_doc = SBOM(
        filename=os.path.basename(sbom_file_path),
        timestamp=datetime.datetime.utcnow().isoformat(),
        sbom_format=sbom_format,
        raw_content=raw_dict,
        components_count=len(components),
    )
    db[SBOM.Config.collection_name].insert_one(sbom_doc.dict())

    return components

def query_nvd_for_cves(cpe_string: str) -> list[Vulnerability]:
    """Queries the NVD API using a CPE string to find all associated CVEs.

    Args:
        cpe_string: The CPE string to query for.

    Returns:
        A list of vulnerabilities.
    """
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {"apiKey": os.getenv("NVD_API_KEY")}
    params = {"cpeName": cpe_string}

    for attempt in range(3):
        try:
            response = requests.get(base_url, headers=headers, params=params)
            response.raise_for_status()
            data = response.json()
            vulnerabilities = []
            for vuln in data.get("vulnerabilities", []):
                cve = vuln.get("cve", {})
                vulnerabilities.append(
                    Vulnerability(
                        cve_id=cve.get("id"),
                        description=cve.get("descriptions", [{}])[0].get("value"),
                        cvss_score=cve.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseScore"),
                        weaknesses=[w.get("description", [{}])[0].get("value") for w in cve.get("weaknesses", [])],
                    )
                )
            return vulnerabilities
        except requests.exceptions.RequestException as e:
            if e.response.status_code == 403:
                print(f"Rate limit exceeded. Retrying in {2 ** attempt} seconds...")
                time.sleep(2 ** attempt)
            else:
                raise e
    return []

def correlate_with_cisa_kev(cve_ids: list[str]) -> dict:
    """Checks a list of CVE IDs against the CISA KEV catalog.

    Args:
        cve_ids: A list of CVE IDs to check.

    Returns:
        A dictionary mapping CVE IDs to their KEV details.
    """
    with open(os.path.join(os.path.dirname(__file__), "..", "frameworks", "cisa_kev.json"), 'r') as f:
        kev_data = json.load(f)

    kev_info = {}
    for cve_id in cve_ids:
        for vuln in kev_data.get("vulnerabilities", []):
            if vuln.get("cveID") == cve_id:
                kev_info[cve_id] = vuln
                break

    return kev_info
