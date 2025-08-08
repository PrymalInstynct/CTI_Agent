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
    w_cvss = 0.3
    w_kev = 0.4
    w_attack = 0.1
    w_epss = 0.2

    # CVSS Score
    cvss_score = enriched_vulnerability.vulnerability.cvss_score or 0.0

    # KEV Flag
    kev_flag = 10.0 if enriched_vulnerability.is_in_kev else 0.0

    # ATT&CK Impact
    attack_impact = 0.0
    if enriched_vulnerability.attack_mappings:
        # This is a simplified impact score. A real implementation would have a
        # more sophisticated mapping of tactics to impact.
        attack_impact = 5.0

    # EPSS Score
    epss_score_value = enriched_vulnerability.epss_score or 0.0

    risk_score = (w_cvss * cvss_score) + (w_kev * kev_flag) + (w_attack * attack_impact) + (w_epss * epss_score_value * 10)
    return risk_score

async def run_analysis(sbom_file_path: str, crawl_depth: int = 2):
    """Runs the full analysis on an SBOM file."""
    sbom_data, is_new_sbom = data_manager.load_and_store_sbom(sbom_file_path)

    # 1. Extract entities from SBOM
    entities = await extract_entities_from_sbom(sbom_data)

    # 2. Generate search queries
    queries = generate_search_queries(entities)

    # 3. Search vector store
    context = ""
    for query in queries:
        context += await tools.search_vector_store(query)

    # 4. Final report synthesis
    final_prompt = f"""Based on the following security intelligence context and the provided SBOM, generate a comprehensive threat intelligence report. List all relevant Snort, Sigma, and Yara rules that apply to the components and vulnerabilities identified.

Context: {context}

SBOM: {sbom_data}"""

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
(Table rows for each vulnerability, sorted by Risk Score in descending order. KEV status is 'Yes' or 'No'.)

## Detailed Vulnerability Analysis

(For each vulnerability, create a section like this, sorted by Risk Score in descending order.)

### `<CVE_ID>`

**CVSS v3.1 Base Score:** <score>

**CISA KEV Status:** <Actively Exploited or Not Listed>

**EPSS Score:** <score>

**CWE:** [<CWE-ID>](<cwe_url>)

**Description:** <description_text>

**MITRE ATT&CK Mapping:**

- **Tactic:** [<Tactic_ID>](<tactic_url>)
- **Technique:** [<Technique_ID>: <Technique_Name>](<technique_url>)

**Defensive Measures:**

**<Rule_Type> Rules:**

```<rule_language>
<rule_content>
```

Description: <rule_description>

Source URL: <<rule_source_url>>

(Repeat for all rule types and rules.)

- Ensure all sections and headers are present and correctly formatted.
- Use a single newline to separate list items and other elements.
- Use two newlines to separate major sections.
- Ensure there is a blank line before and after every code block (```).
- Do not add any extra text or commentary outside of this structure.
"""
    )

    report = await synthesis_agent.run(final_prompt)

    return report.output