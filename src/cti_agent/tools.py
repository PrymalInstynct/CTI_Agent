"""Agent tools for the CTI Agent."""
import os
import json
import time
import requests
from .models import get_db, Component, Vulnerability




def query_nvd_for_cves(cpe_string: str) -> list[Vulnerability]:
    """Queries the NVD API using a CPE string to find all associated CVEs.

    Args:
        cpe_string: The CPE string to query for.

    Returns:
        A list of vulnerabilities.
    """
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {"apiKey": os.getenv("NVD_API_KEY"), "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"}
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
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                # No vulnerabilities found for this CPE, which is a valid scenario
                return []
            elif e.response.status_code == 403:
                print(f"Rate limit exceeded. Retrying in {2 ** attempt} seconds...")
                time.sleep(2 ** attempt)
            else:
                raise e
        except requests.exceptions.RequestException as e:
            # Catch any other request-related errors
            raise e
    return []

def correlate_with_cisa_kev(cve_ids: list[str]) -> dict:
    """Checks a list of CVE IDs against the CISA KEV catalog.

    Args:
        cve_ids: A list of CVE IDs to check.

    Returns:
        A dictionary mapping CVE IDs to their KEV details.
    """
    kev_file_path = os.path.join(os.path.dirname(__file__), "..", "frameworks", "cisa_kev.json")
    try:
        with open(kev_file_path, 'r') as f:
            kev_data = json.load(f)
    except FileNotFoundError:
        print(f"Error: CISA KEV data file not found at {kev_file_path}. Please run 'cti-agent --update-data' to download it.")
        return {}
    except json.JSONDecodeError:
        print(f"Error: Could not decode CISA KEV data from {kev_file_path}. The file might be corrupted.")
        return {}

    kev_info = {}
    for cve_id in cve_ids:
        for vuln in kev_data.get("vulnerabilities", []):
            if vuln.get("cveID") == cve_id:
                kev_info[cve_id] = vuln
                break

    return kev_info


def get_cpe_for_component(component_name: str, component_version: str) -> str:
    """Generates a CPE 2.3 string for a component.

    Args:
        component_name: The name of the component.
        component_version: The version of the component.

    Returns:
        A CPE 2.3 string.
    """
    # This is a simplified implementation. A real implementation would use a more
    # sophisticated method to generate the CPE string.
    return f"cpe:2.3:a:{component_name.lower().replace(' ', '_')}:{component_name.lower().replace(' ', '_')}:{component_version}:*:*:*:*:*:*:*"


def map_cve_to_attack(cve_id: str, cve_description: str) -> list[dict]:
    """Maps a CVE to MITRE ATT&CK tactics and techniques.

    Args:
        cve_id: The CVE ID.
        cve_description: The CVE description.

    Returns:
        A list of ATT&CK mappings.
    """
    # This is a placeholder. A real implementation would use an LLM to map the
    # CVE to ATT&CK techniques.
    return [
        {
            "tactic": "TA0002",
            "technique_id": "T1059",
            "technique_name": "Command and Scripting Interpreter",
        }
    ]


async def find_defensive_measures(cve_id: str) -> dict:
    """Finds defensive measures for a CVE using an LLM.

    Args:
        cve_id: The CVE ID.

    Returns:
        A dictionary of defensive measures (e.g., {"sigma": ["rule1", "rule2"]}).
    """
    # Temporarily hardcoding return value to isolate error
    return {"sigma": ["hardcoded_sigma_rule"], "snort": [], "yara": []}

def summarize_findings(enriched_vulnerabilities: list[dict]) -> str:
    """Generates a high-level executive summary of the analysis findings.

    Args:
        enriched_vulnerabilities: A list of dictionaries, where each dictionary contains
                                  details about an enriched vulnerability, including
                                  its CVE ID, CVSS score, KEV status, EPSS score,
                                  and other relevant information.

    Returns:
        A 1-2 paragraph executive summary of the findings.
    """
    # This function will be called by the agent with the full vulnerability data.
    # The agent's prompt will then guide the LLM to generate the summary.
    # This is a placeholder for the tool definition. The actual LLM call
    # for summarization happens in agent.py.
    return "Summary generation handled by the agent's prompt."

async def answer_user_query(collection_name: str, query: dict, projection: dict = None) -> str:
    """Executes a MongoDB query and returns the raw results as a JSON string.

    Args:
        collection_name: The name of the MongoDB collection to query.
        query: The MongoDB query filter.
        projection: An optional MongoDB projection to include/exclude fields.

    Returns:
        A JSON string representing the query results.
    """
    db = get_db()
    try:
        collection = db[collection_name]

        # Default projection for sboms to avoid large token counts
        if collection_name == "sboms" and projection is None:
            projection = {"raw_content": 0}

        results = list(collection.find(query, projection))
        if results:
            return json.dumps(results, default=str)
        else:
            return f"No results found in the '{collection_name}' collection for the given query."
    except Exception as e:
        return f"An error occurred while querying the database: {e}"

def query_epss(cve_ids: list[str]) -> dict[str, float]:
    """Queries the EPSS API for the exploit probability scores of a list of CVEs.

    Args:
        cve_ids: A list of CVE IDs to query for.

    Returns:
        A dictionary mapping CVE IDs to their EPSS scores.
    """
    if not cve_ids:
        return {}

    url = f"https://api.first.org/data/v1/epss?cve={','.join(cve_ids)}"
    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        if data.get("status") == "OK" and data.get("data"):
            return {item["cve"]: float(item["epss"]) for item in data["data"]}
    except requests.exceptions.RequestException as e:
        print(f"Error querying EPSS API: {e}")
    return {}