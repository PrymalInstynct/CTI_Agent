import os
import json
from pydantic_ai import Agent
from pydantic_ai.providers.google_gla import GoogleGLAProvider
from . import tools
from . import data_manager
from .models import Component, EnrichedVulnerability, get_db
from .sbom_parser import extract_entities_from_sbom, generate_search_queries
from cyclonedx.model.bom import Bom
import json

# --- Constants ---
CHUNK_SIZE = 20

# Configure the LLM
# Define the master system prompt
system_prompt = """You are an expert Cyber Threat Intelligence Analyst.
Your mission is to analyze a list of software components from a Software Bill of Materials (SBOM).
For each component, you will use the provided tools to find associated vulnerabilities (CVEs), enrich them with data from NVD, CISA KEV, CWE, and MITRE ATT&CK, and find defensive measures.
Your final output will be a structured, prioritized vulnerability report.
You must be precise, factual, and follow the instructions of each tool call exactly."""

# Create the chat agent
chat_agent = Agent(
  'google-gla:gemini-2.5-flash',
  tools=[
    tools.answer_user_query,
  ],
  system_prompt="""You are a helpful assistant that can answer questions about SBOM and vulnerability data stored in a MongoDB database.
You have access to a tool called `answer_user_query` that can query the database based on natural language questions.
To use the tool, you must provide the collection name and a query filter.
The available collections are 'sboms' and 'enriched_vulnerabilities'.
When querying the 'sboms' collection, you should exclude the 'raw_content' field by default to avoid excessive token usage.
When the user asks a question, first determine which collection to query and what filter to use.
Then, call the `answer_user_query` tool with the collection and filter.
Finally, use the results from the tool to formulate a user-friendly answer.
"""
)


def calculate_risk_score(enriched_vulnerability: EnrichedVulnerability) -> float:
    """Calculates a risk score for an enriched vulnerability."""
    # Weights for each factor
    w_cvss = 0.5
    w_kev = 0.3
    w_epss = 0.2

    # CVSS Score (0-10), scaled to 100 for impact
    cvss_score = (enriched_vulnerability.vulnerability.cvss_score or 0.0) * 10

    # KEV Flag (0 or 1), scaled to 100 for impact
    kev_flag = 100.0 if enriched_vulnerability.is_in_kev else 0.0

    # EPSS Score (0-1), scaled to 100 for impact
    epss_score = (enriched_vulnerability.epss_score or 0.0) * 100

    # Weighted average
    risk_score = (w_cvss * cvss_score) + (w_kev * kev_flag) + (w_epss * epss_score)
    return round(risk_score, 2)

async def run_analysis(sbom_file_path: str, crawl_depth: int = 2):
    """Runs the full analysis on an SBOM file."""
    print("--- Starting Analysis ---")
    sbom_data, is_new_sbom = data_manager.load_and_store_sbom(sbom_file_path)
    
    # 1. Extract components from SBOM
    sbom_entities = await extract_entities_from_sbom(sbom_data)
    print(f"Found {len(sbom_entities.packages)} components in SBOM.")

    # 2. Deterministic CVE Lookup and Enrichment
    all_vulnerabilities = {}
    for component in sbom_entities.packages:
        print(f"Processing component: {component.name} v{component.version}")
        cpe_string = await tools.get_cpe_for_component(component.name, component.version)
        print(f"  Generated CPE: {cpe_string}")
        cves = tools.query_nvd_for_cves(cpe_string)
        print(f"  Found {len(cves)} CVEs for this CPE.")
        for cve in cves:
            if cve.cve_id not in all_vulnerabilities:
                all_vulnerabilities[cve.cve_id] = cve

    cve_ids = list(all_vulnerabilities.keys())
    print(f"Total unique CVEs found: {len(cve_ids)}")
    kev_info = tools.correlate_with_cisa_kev(cve_ids)
    epss_scores = tools.query_epss(cve_ids)
    print(f"Found {len(epss_scores)} EPSS scores.")

    # 3. Build Enriched Data Structure and Calculate Risk Score
    enriched_vulnerabilities = []
    for cve_id, cve in all_vulnerabilities.items():
        is_in_kev = cve_id in kev_info
        epss_score = epss_scores.get(cve_id)

        attack_mappings = tools.map_cve_to_attack(cve_id, cve.description)
        defensive_measures = await tools.find_defensive_measures(cve_id)

        enriched_vuln = EnrichedVulnerability(
            vulnerability=cve,
            is_in_kev=is_in_kev,
            kev_details=kev_info.get(cve_id),
            epss_score=epss_score,
            attack_mappings=attack_mappings,
            defensive_measures=defensive_measures
        )
        enriched_vuln.risk_score = calculate_risk_score(enriched_vuln)
        enriched_vulnerabilities.append(enriched_vuln)

    # Sort vulnerabilities by the calculated risk score
    enriched_vulnerabilities.sort(key=lambda x: x.risk_score, reverse=True)
    print("--- Finished Analysis, Generating Report ---")

    # 4. Final Report Synthesis (LLM as a renderer)
    final_prompt = f"""Based on the following structured vulnerability data, generate a comprehensive threat intelligence report. Do not perform any analysis; simply render the provided data into the specified Markdown format.

Enriched Vulnerabilities:
{json.dumps([v.model_dump() for v in enriched_vulnerabilities], indent=2, default=str)}

SBOM Filename: {os.path.basename(sbom_file_path)}
"""


    # Create the synthesis agent with a detailed system prompt for formatting
    synthesis_agent = Agent(
        'google-gla:gemini-2.5-flash',
        tools=[],
        system_prompt="""You are an expert Cyber Threat Intelligence Analyst that generates comprehensive, well-formatted Markdown reports.

Your output MUST follow this structure EXACTLY:

# Cyber Threat Intelligence Analysis Report

**SBOM File:** `<sbom_filename>`

## Executive Summary

(A 1-2 paragraph summary of the key findings, including the total number of vulnerabilities and the number of actively exploited vulnerabilities.)

## Prioritized Vulnerabilities

| CVE ID | CVSS v3.1 Score | CISA KEV | EPSS Score | Risk Score |
| --- | --- | --- | --- | --- |
(Table rows for each vulnerability, sorted by Risk Score in descending order. KEV status is 'Yes' or 'No'. If the EPSS score is null or 0.0, display 'N/A'.)

## Detailed Vulnerability Analysis

(For each vulnerability, create a section like this, sorted by Risk Score in descending order.)

<details>
<summary><strong>`<CVE_ID>`</strong></summary>

**CVSS v3.1 Base Score:** <score>

**CISA KEV Status:** <Actively Exploited or Not Listed>

**EPSS Score:** <score>

**CWE:** [<CWE-ID>](<cwe_url>)

**Description:** <description_text>

### Mitigations & Remediations

(The list MUST be a bulleted list using `-` and a single space. DO NOT use `*`.

CORRECT FORMAT:
- Upgrade to version 2.17.1 or later. *[Link to source](https://logging.apache.org/log4j/2.x/security.html)*
- Disable JNDI lookups. *[Link to source](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-348a)*

INCORRECT FORMAT:
*   Upgrade to version 2.17.1 or later. *[Link to source](https://logging.apache.org/log4j/2.x/security.html)*

)


### Detection Rules

(For Detection Rules, prioritize including rules in the report that can be referenced with a source URL found through the research. Only generate a Custom rule if a rule cannot be found for a specific CVE with a source URL, then attempt to generate a relevant rule and label its source as "Custom-generated".)

#### MITRE ATT&CK Mapping

- **Tactic:** [<Tactic_ID>](<tactic_url>)
- **Technique:** [<Technique_ID>: <Technique_Name>](<technique_url>)

##### `<Rule_Type>` Rules

```<rule_language>
<rule_content>
```

**Description:** <rule_description>

**Source URL:** [<rule_source_url>](<rule_source_url>)

(Repeat for all rule types and rules.)

</details>


- Ensure all sections and headers are present and correctly formatted.
- Use a single newline to separate list items and other elements.
- Ensure every list only contains a single space after the initial `-` at the beginning of the line.
- Use two newlines to separate major sections.
- Ensure there is a blank line before and after every code block (```).
- Ensure that there is exact one newline at the end of the document.
- Do not include any extra text or commentary outside of this structure.

Use the provided `Enriched Vulnerabilities` data to populate the report sections.
"""
    )

    report = await synthesis_agent.run(final_prompt)

    return report.output