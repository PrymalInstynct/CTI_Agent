
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
from .models import get_db, Component, Vulnerability, SnortRule, SigmaRule, YaraRule
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
        print(f"Successfully processed {cve_id} and its links.")
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
                if document_text:
                    vector_store.add_document(document=document_text, metadata={'source': url, 'cve_id': cve_id}, doc_id=doc_id)
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

async def search_defensive_measures(cve_id: str) -> dict:
    """Searches the RAG vector store for defensive measures related to a CVE,
    then uses an LLM to extract actionable advice, including Snort, Sigma, and Yara rules.

    Args:
        cve_id: The CVE ID to search for.

    Returns:
        A dictionary containing lists of enhanced_defensive_measures, snort_rules, sigma_rules, and yara_rules.
    """
    vector_store = VectorStoreManager()
    results = vector_store.search(
        query=f"defensive measures for {cve_id}",
        n_results=10,
        where={"cve_id": cve_id}
    )
    documents = results.get("documents", [])

    if not documents or not documents[0]:
        return {
            "enhanced_defensive_measures": ["No information found in the vector store for this CVE."],
            "snort_rules": [],
            "sigma_rules": [],
            "yara_rules": []
        }

    full_text_content = "\n\n---\n\n".join(documents[0])

    extraction_agent = Agent(
      'google-gla:gemini-2.5-flash',
      system_prompt="""You are a specialized AI Cybersecurity Analyst Agent. Your primary function is to assist in threat detection by finding relevant security rules for a given Common Vulnerability and Exposures (CVE) identifier. The CVE you receive has been identified from a Software Bill of Materials (SBOM), indicating a potential vulnerability within the user's software supply chain.

Your Mission:

For the provided CVE, you must search for and retrieve existing, publicly available detection logic. Specifically, you must find:

    Snort Signatures: For network-based detection.
    Sigma Rules: For log-based detection in SIEMs.
    YARA Rules: For file-based or memory-based threat hunting.

Instructions & Constraints:

    Accuracy is critical. Prioritize rules from official repositories (e.g., Snort.org, SigmaHQ on GitHub, community Yara-Rules projects) and well-known security research blogs or threat intelligence providers.
    Do NOT generate or create new rules. Your task is to find existing, published rules.
    For each rule you find, you MUST provide the rule content itself, a brief, one-sentence description of the rule's purpose, and a direct URL to its source for verification.
    If you cannot find any rules for a specific category, you must explicitly state that none were found.

Output Format:

You must structure your response as a JSON object with the following keys:
- `enhanced_defensive_measures`: A list of general defensive measures (mitigation, remediation, patching, vendor advisories, best practices).
- `snort_rules`: A list of objects, where each object represents a Snort rule and has the following keys:
    - `rule_content`: The full Snort rule content as a string.
    - `description`: A brief, one-sentence description of the rule's purpose.
    - `source_url`: A direct URL to the rule's source.
- `sigma_rules`: A list of objects, where each object represents a Sigma rule and has the following keys:
    - `rule_content`: The full Sigma rule content as a string.
    - `description`: A brief, one-sentence description of the rule's purpose.
    - `source_url`: A direct URL to the rule's source.
- `yara_rules`: A list of objects, where each object represents a Yara rule and has the following keys:
    - `rule_content`: The full Yara rule content as a string.
    - `description`: A brief, one-sentence description of the rule's purpose.
    - `source_url`: A direct URL to the rule's source.

If no specific measures or rules are found for a category, provide an empty list for that key.

Example JSON output:
```json
{
  "enhanced_defensive_measures": [
    "Apply the latest security patches from the vendor.",
    "Implement a web application firewall (WAF) to protect against common web-based attacks."
  ],
  "snort_rules": [
    {
      "rule_content": "alert tcp any any -> any any (msg:\"ET EXPLOIT Apache Struts2 S2-045 Remote Code Execution\"; flow:to_server,established; content:\"Content-Type|3a| %{\"; fast_pattern; classtype:web-application-attack; sid:2023900; rev:1;)",
      "description": "Detects Apache Struts2 S2-045 remote code execution attempts.",
      "source_url": "https://www.snort.org/rules/2023900"
    }
  ],
  "sigma_rules": [
    {
      "rule_content": "title: Apache Struts2 S2-045 Remote Code Execution\nlogsource:\n  product: web\n  service: apache_struts2\ndetection:\n  selection:\n    c-type|contains: \"%{\n  condition: selection",
      "description": "Detects Apache Struts2 S2-045 remote code execution attempts via web logs.",
      "source_url": "https://github.com/SigmaHQ/sigma/blob/master/rules/web/web_apache_struts2_s2_045.yml"
    }
  ],
  "yara_rules": [
    {
      "rule_content": "rule Apache_Struts2_S2_045 {\n  strings:\n    $s1 = \"Content-Type: %{\" ascii wide\n  condition:\n    $s1\n}",
      "description": "Detects Apache Struts2 S2-045 payloads in files or memory.",
      "source_url": "https://github.com/Yara-Rules/rules/blob/master/malware/apache_struts2_s2_045.yar"
    }
  ]
}
```"""
    )

    prompt = f"""
    Based on the following text scraped for {cve_id}, please extract the key defensive measures, Snort rules, Sigma rules, and Yara rules.

    Scraped Content:
    ---
    {full_text_content}
    ---

    Extracted Defensive Measures and Rules (JSON format):
    """

    response = await extraction_agent.run(prompt)

    if response and response.output:
        try:
            # Extract JSON string from the response, handling potential markdown code blocks
            json_match = re.search(r"```json\n([\s\S]*?)\n```", response.output)
            if json_match:
                json_str = json_match.group(1)
            else:
                json_str = response.output # Assume it's just the JSON if no code block

            extracted_data = json.loads(json_str)
            return {
                "enhanced_defensive_measures": extracted_data.get("enhanced_defensive_measures", []),
                "snort_rules": [SnortRule(**rule) for rule in extracted_data.get("snort_rules", [])],
                "sigma_rules": [SigmaRule(**rule) for rule in extracted_data.get("sigma_rules", [])],
                "yara_rules": [YaraRule(**rule) for rule in extracted_data.get("yara_rules", [])]
            }
        except json.JSONDecodeError as e:
            print(f"Error decoding JSON from LLM response: {e}")
            print(f"LLM response: {response.output}")
            return {
                "enhanced_defensive_measures": ["Could not extract defensive measures from the provided content due to JSON parsing error."],
                "snort_rules": [],
                "sigma_rules": [],
                "yara_rules": []
            }
    else:
        return {
            "enhanced_defensive_measures": ["Could not extract defensive measures from the provided content."],
            "snort_rules": [],
            "sigma_rules": [],
            "yara_rules": []
        }
