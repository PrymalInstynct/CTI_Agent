# Pydantic AI Agent for the CTI Agent.
import os
import json
from pydantic_ai import Agent
from pydantic_ai.providers.google_gla import GoogleGLAProvider
from . import tools
from . import data_manager
from .models import Component, EnrichedVulnerability, get_db
from cyclonedx.model.bom import Bom
import json

# Configure the LLM
# Define the master system prompt
system_prompt = """You are an expert Cyber Threat Intelligence Analyst.
Your mission is to analyze a list of software components from a Software Bill of Materials (SBOM).
For each component, you will use the provided tools to find associated vulnerabilities (CVEs), enrich them with data from NVD, CISA KEV, CWE, and MITRE ATT&CK, and find defensive measures.
Your final output will be a structured, prioritized vulnerability report.
You must be precise, factual, and follow the instructions of each tool call exactly."""

# Create the analysis agent
analysis_agent = Agent(
  'google-gla:gemini-2.5-flash',
  tools=[
    tools.query_nvd_for_cves,
    tools.correlate_with_cisa_kev,
    tools.get_cpe_for_component,
    tools.map_cve_to_attack,
    tools.query_epss,
    tools.scrape_nvd_cve_info,
    tools.search_defensive_measures,
  ],
  system_prompt=system_prompt
)

# Create the summary agent
summary_agent = Agent(
  'google-gla:gemini-2.5-flash',
  tools=[],
  system_prompt="""You are a helpful assistant that generates a high-level executive summary of a cybersecurity report based on the provided vulnerability data."""
)

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

async def run_analysis(sbom_file_path: str):
    """Runs the full analysis on an SBOM file."""
    sbom_data, is_new_sbom = data_manager.load_and_store_sbom(sbom_file_path)

    # Re-parse the SBOM content into a Bom object to extract components
    if sbom_file_path.endswith('.json'):
        bom = Bom.from_json(sbom_data)
    elif sbom_file_path.endswith('.xml'):
        import xmltodict
        bom = Bom.from_xml(sbom_data)
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

    all_vulnerabilities = []
    for component in components:
        if not component.cpe:
            cpe_prompt = (
                f"Generate a CPE 2.3 string for the following software component. "
                f"Return ONLY the CPE string and nothing else. Do NOT include any other text, explanation, or formatting. "
                f"Component Name: {component.name}, Version: {component.version}. "
                f"Example: For 'Apache Log4j', version '2.14.1', the CPE is cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"
            )

            cpe_result = None # Initialize cpe_result
            try:
                cpe_result = await analysis_agent.run(cpe_prompt)
                if cpe_result and cpe_result.output:
                    component.cpe = cpe_result.output.strip()
                else:
                    print(f"Warning: LLM returned no output for CPE generation for component {component.name}.")
            except Exception as e:
                print(f"Error generating CPE for {component.name}: {e}")
                print(f"LLM response: {cpe_result}")
                component.cpe = None # Ensure CPE is None on error

        vulnerabilities = tools.query_nvd_for_cves(component.cpe)
        all_vulnerabilities.extend(vulnerabilities)

    cve_ids = [v.cve_id for v in all_vulnerabilities]
    kev_info = tools.correlate_with_cisa_kev(cve_ids)
    epss_scores = tools.query_epss(cve_ids)

    enriched_vulnerabilities = []
    for vulnerability in all_vulnerabilities:
        try:
            # Scrape NVD for more details and populate the vector store
            tools.scrape_nvd_cve_info(vulnerability.cve_id)

            attack_mappings = tools.map_cve_to_attack(vulnerability.cve_id, vulnerability.description)
            defensive_measures = await tools.find_defensive_measures(vulnerability.cve_id)
            enhanced_defensive_measures = await tools.search_defensive_measures(vulnerability.cve_id)
            epss_score = epss_scores.get(vulnerability.cve_id)

            enriched_vulnerability = EnrichedVulnerability(
                vulnerability=vulnerability,
                is_in_kev=True if kev_info.get(vulnerability.cve_id) else False,
                kev_details=kev_info.get(vulnerability.cve_id),
                attack_mappings=attack_mappings,
                defensive_measures=defensive_measures,
                enhanced_defensive_measures=enhanced_defensive_measures,
                epss_score=epss_score,
            )
            enriched_vulnerability.risk_score = calculate_risk_score(enriched_vulnerability)
            enriched_vulnerabilities.append(enriched_vulnerability)
        except AttributeError as e:
            print(f"Caught AttributeError: {e}")
            print(f"vulnerability: {vulnerability.cve_id}")
            print(f"defensive_measures type: {type(defensive_measures)}")
            print(f"defensive_measures value: {defensive_measures}")
            raise e

    db = get_db()
    # Convert Pydantic models to dictionaries for MongoDB insertion
    vulnerabilities_to_insert = [v.model_dump(by_alias=True) for v in enriched_vulnerabilities]
    db[EnrichedVulnerability.Config.collection_name].insert_many(vulnerabilities_to_insert)
    if is_new_sbom:
        print(f"Inserted {len(vulnerabilities_to_insert)} enriched vulnerabilities into MongoDB.")

    # Sort vulnerabilities by risk score
    enriched_vulnerabilities.sort(key=lambda x: x.risk_score, reverse=True)

    # Generate the summary with the LLM
    summary_data = [
        {
            "cve_id": v.vulnerability.cve_id,
            "cvss_score": v.vulnerability.cvss_score,
            "is_in_kev": v.is_in_kev,
            "epss_score": v.epss_score,
            "risk_score": v.risk_score,
        }
        for v in enriched_vulnerabilities
    ]

    summary_prompt = (
        f"Based on the following vulnerability data, generate a 1-2 paragraph executive summary for a cybersecurity report. "
        f"Highlight the total number of vulnerabilities, the number of actively exploited vulnerabilities (KEV), and the number of high-risk vulnerabilities. "
        f"Conclude with a recommendation for prioritizing remediation efforts.\n\n"
        f"Vulnerability Data: {json.dumps(summary_data, indent=2, default=str)}"
    )
    summary_result = await summary_agent.run(summary_prompt)
    summary = summary_result.output

    # Generate the report
    report = generate_markdown_report(enriched_vulnerabilities, sbom_file_path, len(components), summary)
    return report


def generate_markdown_report(enriched_vulnerabilities, sbom_file_path, total_components, summary):
    """Generates a Markdown report from the analysis results."""
    report = """# Cyber Threat Intelligence Analysis Report

**SBOM File:** `{sbom_file_path}`

## Executive Summary

{summary}

- **Total Components Scanned:** {total_components}
- **Total Vulnerabilities Found:** {total_vulnerabilities}
- **Actively Exploited Vulnerabilities (CISA KEV):** {kev_count}

## Prioritized Vulnerabilities

| CVE ID | CVSS v3.1 Score | CISA KEV | EPSS Score | Risk Score |
| --- | --- | --- | --- | --- |
{vulnerability_table}
## Detailed Vulnerability Analysis

{detailed_analysis}
"""

    total_vulnerabilities = len(enriched_vulnerabilities)
    kev_count = sum(1 for item in enriched_vulnerabilities if item.is_in_kev)

    vulnerability_table = ""
    for item in enriched_vulnerabilities:
        kev_status = "Yes" if item.is_in_kev else "No"
        epss_score = f"{item.epss_score:.2f}" if item.epss_score is not None else "N/A"
        risk_score = calculate_risk_score(item)
        vulnerability_table += f"| {item.vulnerability.cve_id} | {item.vulnerability.cvss_score} | {kev_status} | {epss_score} | {risk_score:.2f} |\n"

    detailed_analysis = ""
    for item in enriched_vulnerabilities:
        epss_score_str = f"{item.epss_score:.2f}" if item.epss_score is not None else "N/A"
        detailed_analysis += f"### {item.vulnerability.cve_id}\n\n"
        detailed_analysis += f"**CVSS v3.1 Base Score:** {item.vulnerability.cvss_score}\n\n"
        detailed_analysis += f"**CISA KEV Status:** {'Actively Exploited' if item.is_in_kev else 'Not Listed'}\n\n"
        detailed_analysis += f"**EPSS Score:** {epss_score_str}\n\n"
        detailed_analysis += f"**CWE:** [{item.vulnerability.weaknesses[0] if item.vulnerability.weaknesses else 'N/A'}](https://cwe.mitre.org/data/definitions/{item.vulnerability.weaknesses[0].split('-')[1]}.html)\n\n"
        detailed_analysis += f"**Description:** {item.vulnerability.description}\n"

        if item.attack_mappings:
            detailed_analysis += "\n**MITRE ATT&CK Mapping:**\n\n"
            for mapping in item.attack_mappings:
                detailed_analysis += f"- **Tactic:** [{mapping['tactic']}](https://attack.mitre.org/tactics/{mapping['tactic']})\n"
                detailed_analysis += f"- **Technique:** [{mapping['technique_id']}: {mapping['technique_name']}](https://attack.mitre.org/techniques/{mapping['technique_id']})\n"
            detailed_analysis += "\n"

        if item.defensive_measures:
            detailed_analysis += "**Defensive Measures:**\n\n"
            for measure_type, rules in item.defensive_measures.items():
                detailed_analysis += f"**{measure_type.upper()} Rules:**\n\n```yaml\n"
                for rule in rules:
                    detailed_analysis += f"{rule}\n"
                detailed_analysis += "```\n\n"

        if item.enhanced_defensive_measures:
            detailed_analysis += "**Enhanced Defensive Measures (from RAG):**\n\n"
            for measure in item.enhanced_defensive_measures:
                detailed_analysis += f"- {measure}\n"
            detailed_analysis += "\n"

    formatted_report = report.format(
        sbom_file_path=sbom_file_path,
        summary=summary,
        total_components=total_components,
        total_vulnerabilities=total_vulnerabilities,
        kev_count=kev_count,
        vulnerability_table=vulnerability_table,
        detailed_analysis=detailed_analysis,
    )
    return formatted_report.strip() + "\n"