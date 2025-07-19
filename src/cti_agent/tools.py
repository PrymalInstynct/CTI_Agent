from pydantic_ai import Tool
from cyclonedx.model.bom import Bom
from typing import List, Dict
from .models import Component, Vulnerability
import os
import requests
import json

@Tool
def parse_sbom(sbom_file_path: str) -> List[Component]:
    """Parses the input SBOM file to extract a list of software components.

    Args:
        sbom_file_path (str): The path to the CycloneDX SBOM file.

    Returns:
        List[Component]: A list of software components.
    """
    with open(sbom_file_path, 'r') as f:
        bom = Bom.from_json(f.read())
        return [
            Component(
                name=component.name,
                version=component.version,
                purl=str(component.purl),
                cpe=component.cpe,
            )
            for component in bom.components
        ]

@Tool
def query_nvd_for_cves(cpe_string: str) -> List[Vulnerability]:
    """
    Queries the NVD API using a CPE string to find all associated CVEs.

    Args:
        cpe_string (str): The CPE string to query for.

    Returns:
        List[Vulnerability]: A list of vulnerabilities.
    """
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    api_key = os.getenv("NVD_API_KEY")
    headers = {"apiKey": api_key} if api_key else {}
    params = {"cpeName": cpe_string}

    try:
        response = requests.get(base_url, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()
        vulnerabilities = []
        for vuln in data.get("vulnerabilities", []):
            cve = vuln.get("cve", {})
            cve_id = cve.get("id")
            description = ""
            for desc in cve.get("descriptions", []):
                if desc.get("lang") == "en":
                    description = desc.get("value")
                    break
            
            cvss_v3 = None
            if "cvssMetricV31" in cve.get("metrics", {}):
                cvss_v3 = cve["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"]
            elif "cvssMetricV30" in cve.get("metrics", {}):
                cvss_v3 = cve["metrics"]["cvssMetricV30"][0]["cvssData"]["baseScore"]


            weaknesses = []
            for weakness in cve.get("weaknesses", []):
                for desc in weakness.get("description", []):
                    if desc.get("lang") == "en":
                        weaknesses.append(desc.get("value"))

            vulnerabilities.append(
                Vulnerability(
                    cve_id=cve_id,
                    description=description,
                    cvss_score=cvss_v3,
                    weaknesses=weaknesses,
                )
            )
        return vulnerabilities
    except requests.exceptions.RequestException as e:
        print(f"Error querying NVD API: {e}")
        return []

@Tool
def correlate_with_cisa_kev(cve_ids: List[str]) -> Dict[str, dict]:
    """
    Checks a list of CVE IDs against the CISA KEV catalog.

    Args:
        cve_ids (List[str]): A list of CVE IDs to check.

    Returns:
        Dict[str, dict]: A dictionary of KEV details for the found CVEs.
    """
    try:
        with open("frameworks/cisa_kev.json", "r") as f:
            kev_data = json.load(f)
        
        kev_vulnerabilities = {
            vuln["cveID"]: vuln for vuln in kev_data.get("vulnerabilities", [])
        }

        found_kevs = {}
        for cve_id in cve_ids:
            if cve_id in kev_vulnerabilities:
                found_kevs[cve_id] = kev_vulnerabilities[cve_id]
        return found_kevs
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Error reading CISA KEV data: {e}")
        return {}

@Tool
def get_cpe_for_component(component_name: str, component_version: str) -> str:
    """
    Generates a CPE 2.3 string for a component.

    Args:
        component_name (str): The name of the component.
        component_version (str): The version of the component.

    Returns:
        str: The generated CPE string.
    """
    # This will be implemented by the AI agent.
    # For now, we can return a placeholder.
    return f"cpe:2.3:a:{component_name.lower()}:{component_name.lower()}:{component_version}:*:*:*:*:*:*:*"

@Tool
def map_cve_to_attack(cve_id: str, cve_description: str) -> List[Dict[str, str]]:
    """
    Maps a CVE to MITRE ATT&CK tactics and techniques.

    Args:
        cve_id (str): The CVE ID.
        cve_description (str): The CVE description.

    Returns:
        List[Dict[str, str]]: A list of ATT&CK mappings.
    """
    # This will be implemented by the AI agent.
    # For now, we can return a placeholder.
    return [
        {
            "tactic": "Execution",
            "technique_id": "T1059",
            "technique_name": "Command and Scripting Interpreter",
        }
    ]

@Tool
def find_defensive_measures(cve_id: str) -> Dict[str, List[str]]:
    """
    Finds defensive measures for a given CVE ID.

    Args:
        cve_id (str): The CVE ID.

    Returns:
        Dict[str, List[str]]: A dictionary of defensive measures.
    """
    # This will be implemented by the AI agent.
    # For now, we can return a placeholder.
    return {
        "sigma": [
            "title: Suspicious PowerShell Execution",
            "logsource:",
            "  product: windows",
            "  service: powershell",
            "detection:",
            "  selection:",
            "    EventID: 4104",
            "  condition: selection",
        ],
        "snort": [],
        "yara": [],
    }
