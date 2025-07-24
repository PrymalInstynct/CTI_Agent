"""Agent tools for the CTI Agent."""
import os
import json
import time
import requests
import re
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from .models import get_db, Component, Vulnerability
from pydantic_ai import Agent
from .vector_store_manager import VectorStoreManager



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

def scrape_nvd_cve_info(cve_id: str) -> bool:
    """Scrapes detailed information for a given CVE from NVD, follows relevant links,
    and stores the aggregated content in the RAG vector store.

    Args:
        cve_id: The CVE ID to scrape.

    Returns:
        True if successful, False otherwise.
    """
    initial_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
    visited_urls = set()
    vector_store = VectorStoreManager()

    try:
        _crawl_links_recursively(initial_url, cve_id, vector_store, visited_urls, max_depth=2)
        print(f"Successfully scraped and stored info for {cve_id} and its links.")
        return True
    except Exception as e:
        print(f"An error occurred during the scraping process for {cve_id}: {e}")
        return False

def _crawl_links_recursively(url: str, cve_id: str, vector_store: VectorStoreManager, visited_urls: set, depth: int = 0, max_depth: int = 2):
    """Recursively crawls links from a starting URL, scrapes content, and stores it.

    Args:
        url: The URL to crawl.
        cve_id: The parent CVE ID for metadata.
        vector_store: The VectorStoreManager instance.
        visited_urls: A set of already visited URLs to avoid loops.
        depth: The current crawling depth.
        max_depth: The maximum allowed crawling depth.
    """
    if depth > max_depth or url in visited_urls:
        return

    visited_urls.add(url)
    print(f"Crawling (Depth {depth}): {url}")

    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        }
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, 'html.parser')

        # Extract and store the text content of the current page
        # Use the body tag to avoid including head content like scripts and styles
        body_content = soup.body
        if body_content:
            document_text = ' '.join(body_content.get_text().split())
            doc_id = f"{cve_id}_{url}"
            vector_store.add_document(
                document=document_text,
                metadata={'source': url, 'cve_id': cve_id},
                doc_id=doc_id
            )

        # Find all relevant links and crawl them
        if depth < max_depth:
            # This selector targets the "Hyperlinks" and "Additional Information" sections
            # which are common places for external references.
            reference_links = soup.find_all('a', href=True)
            for link in reference_links:
                href = link.get('href')
                if href and href.startswith('http'):
                    # Ensure the link is absolute
                    absolute_url = urljoin(url, href)
                    _crawl_links_recursively(absolute_url, cve_id, vector_store, visited_urls, depth + 1, max_depth)

    except requests.exceptions.RequestException as e:
        print(f"Could not retrieve or parse {url}: {e}")

async def search_defensive_measures(cve_id: str):
    """Searches the RAG vector store for defensive measures related to a CVE,
    then uses an LLM to extract actionable advice.

    Args:
        cve_id: The CVE ID to search for.

    Returns:
        A list of defensive measures.
    """
    vector_store = VectorStoreManager()
    # Search for the raw NVD content we stored earlier
    results = vector_store.search(query=cve_id, n_results=1)
    documents = results.get('documents', [])

    if not documents or not documents[0]:
        return ["No information found in the vector store for this CVE."]

    # The document is the raw text scraped from the NVD page
    nvd_text_content = documents[0][0]

    # Create a dedicated agent to parse the NVD content
    extraction_agent = Agent(
      'google-gla:gemini-2.5-flash',
      system_prompt="""You are an expert security analyst. Your task is to extract actionable defensive measures from the provided text, which is from an NVD vulnerability page.
Focus on mitigation, remediation, and patching instructions. Present the information as a clear, concise list of single-sentence recommendations.
Do NOT use any markdown formatting (e.g., no asterisks, dashes, or bullet points). Start each recommendation on a new line.
If no specific measures are mentioned, state that clearly."""
    )

    prompt = f"""
    Based on the following text from the NVD page for {cve_id}, please extract the key defensive measures.

    NVD Content:
    ---
    {nvd_text_content}
    ---

    Extracted Defensive Measures:
    """

    response = await extraction_agent.run(prompt)

    if response and response.output:
        # Sanitize the output to remove any markdown and split into a list
        lines = response.output.strip().split('\n')
        # Remove any leading/trailing whitespace and list markers
        sanitized_lines = [re.sub(r'^\s*[-*\s]*', '', line).strip() for line in lines]
        # Filter out any empty lines that might result from the sanitization
        return [line for line in sanitized_lines if line]
    else:
        return ["Could not extract defensive measures from the NVD content."]
