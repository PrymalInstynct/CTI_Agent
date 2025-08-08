
"""Agent tools for the CTI Agent."""
import os
import json
import time
import requests
import re
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from PyPDF2 import PdfReader
from io import BytesIO
from .models import get_db, Component, Vulnerability, SnortRule, SigmaRule, YaraRule, SnortRuleMetadata, SigmaRuleMetadata, YaraRuleMetadata
from . import rule_parsers
from pydantic_ai import Agent
from googlesearch import search
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
    vector_store = VectorStoreManager()
    
    # Search for Snort rules
    snort_results = vector_store.search(query=f"Snort rules for {cve_id}", where={"rule_type": "snort", "cve_id": cve_id})
    snort_rules = [doc for doc in snort_results.get('documents', [])]

    # Search for Sigma rules
    sigma_results = vector_store.search(query=f"Sigma rules for {cve_id}", where={"rule_type": "sigma", "cve_id": cve_id})
    sigma_rules = [doc for doc in sigma_results.get('documents', [])]

    # Search for Yara rules
    yara_results = vector_store.search(query=f"Yara rules for {cve_id}", where={"rule_type": "yara", "cve_id": cve_id})
    yara_rules = [doc for doc in yara_results.get('documents', [])]

    # Use an LLM to extract and format the rules consistently
    extraction_agent = Agent(
        'google-gla:gemini-2.5-flash',
        system_prompt="""You are an expert in cybersecurity rules (Snort, Sigma, Yara).
        Your task is to extract and format the provided rule content consistently.
        For each rule type, present the rules clearly. If no rules are found for a type, state that.
        """
    )

    prompt = f"""Extract and format the following defensive measures for CVE ID {cve_id}:

Snort Rules:
{snort_rules if snort_rules else "No Snort rules found."}

Sigma Rules:
{sigma_rules if sigma_rules else "No Sigma rules found."}

Yara Rules:
{yara_rules if yara_rules else "No Yara rules found."}

Provide the output in a structured format, clearly separating each rule type.
"""
    
    response = await extraction_agent.run(prompt)
    
    # The response from the LLM is an AgentRunResult object. We need its .output attribute.
    formatted_rules = response.output

    return {
        "snort": snort_rules,
        "sigma": sigma_rules,
        "yara": yara_rules,
        "formatted_output": formatted_rules
    }

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

def scrape_nvd_cve_info(cve_id: str, crawl_depth: int = 2) -> bool:
    """Scrapes detailed information for a given CVE from NVD, follows relevant links,
    and stores the aggregated content in the RAG vector store.

    Args:
        cve_id: The CVE ID to scrape.
        crawl_depth: The maximum recursion depth for the web scraper.

    Returns:
        True if successful, False otherwise.
    """
    initial_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
    visited_urls = set()
    vector_store = VectorStoreManager()

    try:
        _crawl_links_recursively(initial_url, cve_id, vector_store, visited_urls, max_depth=crawl_depth)
        _scrape_rules_from_github(cve_id, vector_store) # New call to scrape rules from GitHub
        print(f"Successfully processed {cve_id} and its links and rules.")
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

    # --- Start of new logic ---
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        }
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        content_type = response.headers.get('content-type', '').lower()

        # Always parse HTML to find links, even if the document is already ingested.
        if 'text/html' not in content_type:
            # If not HTML, we can't find more links, so respect the old logic.
            # Check for existence and add if new.
            doc_id = f"{cve_id}_{url}"
            if not vector_store.document_exists(doc_id=doc_id):
                print(f"Crawling non-HTML (Depth {depth}): {url}")
                document_text = ''
                if 'application/pdf' in content_type:
                    with BytesIO(response.content) as pdf_file:
                        reader = PdfReader(pdf_file)
                        for page in reader.pages:
                            document_text += page.extract_text() or ''
                elif 'text/markdown' in content_type or 'application/json' in content_type or 'application/xml' in content_type or 'text/xml' in content_type:
                    document_text = response.text
                if document_text:
                    vector_store.add_document(document=document_text, metadata={'source': url, 'cve_id': cve_id, 'content_type': content_type}, doc_id=doc_id)
            else:
                print(f"Skipping already ingested non-HTML: {url}")
            return # Stop crawling this branch

        # For HTML, parse it for links
        soup = BeautifulSoup(response.content, 'html.parser')

        # Check if the HTML document itself needs to be ingested
        doc_id = f"{cve_id}_{url}"
        if not vector_store.document_exists(doc_id=doc_id):
            print(f"Crawling (Depth {depth}): {url}")
            if soup.header:
                soup.header.decompose()
            if soup.footer:
                soup.footer.decompose()
            if soup.body:
                document_text = ' '.join(soup.body.get_text().split())
                if document_text:
                    vector_store.add_document(document=document_text, metadata={'source': url, 'cve_id': cve_id}, doc_id=doc_id)
            else:
                print(f"Skipping already ingested URL: {url}")

        # Regardless of ingestion, if depth allows, find and crawl links.
        if depth < max_depth:
            # Exclude links from header and footer
            if soup.header:
                soup.header.decompose()
            if soup.footer:
                soup.footer.decompose()

            reference_links = soup.find_all('a', href=True)
            for link in reference_links:
                href = link.get('href')
                if href and href.startswith('http'):
                    absolute_url = urljoin(url, href)
                    _crawl_links_recursively(absolute_url, cve_id, vector_store, visited_urls, depth + 1, max_depth)

    except requests.exceptions.RequestException as e:
        print(f"Could not retrieve or parse {url}: {e}")
    except Exception as e:
        print(f"An unexpected error occurred while processing {url}: {e}")

def _scrape_rules_from_github(cve_id: str, vector_store: VectorStoreManager):
    """Scrapes Snort, Sigma, and Yara rules from GitHub repositories and stores them.
    """
    search_queries = {
        "sigma": f"{cve_id} Sigma rules github",
        "yara": f"{cve_id} Yara rules github",
        "snort": f"{cve_id} Snort rules"
    }

    for rule_type, query in search_queries.items():
        print(f"Searching for {rule_type} rules for {cve_id} with query: {query}")
        search_results = search(query, num=5, stop=5, pause=2)
        if search_results:
            for result in search_results:
                url = result
                if url and ("github.com" in url or "snort.org" in url): # Basic filtering
                    doc_id = f"{cve_id}_{rule_type}_{url}"
                    if not vector_store.document_exists(doc_id=doc_id):
                        try:
                            response = requests.get(url, timeout=5)
                            response.raise_for_status()
                            rule_content = response.text
                            metadata = {'source': url, 'cve_id': cve_id, 'rule_type': rule_type}
                            if rule_type == "snort":
                                rule_metadata = rule_parsers.parse_snort_rule_metadata(rule_content, cve_id=cve_id, source_url=url)
                            elif rule_type == "sigma":
                                rule_metadata = rule_parsers.parse_sigma_rule_metadata(rule_content, cve_id=cve_id, source_url=url)
                            elif rule_type == "yara":
                                rule_metadata = rule_parsers.parse_yara_rule_metadata(rule_content, cve_id=cve_id, source_url=url)
                            else:
                                rule_metadata = None

                            if rule_metadata:
                                metadata.update(rule_metadata.model_dump()) # Use model_dump() for Pydantic v2+
                            
                            vector_store.add_document(
                                document=rule_content,
                                metadata=metadata,
                                doc_id=doc_id
                            )
                            print(f"Successfully scraped {rule_type} rule for {cve_id} from {url}")
                        except requests.exceptions.RequestException as e:
                            print(f"Could not retrieve {rule_type} rule from {url}: {e}")
                    else:
                        print(f"Skipping already ingested {rule_type} rule: {url}")
        
        


async def search_vector_store(query: str) -> str:
    """Searches the vector store for a given query.

    Args:
        query: The query to search for.

    Returns:
        A string containing the search results.
    """
    vector_store = VectorStoreManager()
    results = vector_store.search(query, k=15)
    return "\n".join([res['document'] for res in results])
