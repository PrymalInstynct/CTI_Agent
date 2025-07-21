# Pydantic AI Agent for the CTI Agent.
import os
import json
from pydantic_ai import Agent
from pydantic_ai.providers.google_gla import GoogleGLAProvider
from . import tools
from .models import Component

# Configure the LLM
# Define the master system prompt
system_prompt = """You are an expert Cyber Threat Intelligence Analyst. 
Your mission is to analyze a list of software components from a Software Bill of Materials (SBOM). 
For each component, you will use the provided tools to find associated vulnerabilities (CVEs), enrich them with data from NVD, CISA KEV, CWE, and MITRE ATT&CK, and find defensive measures. 
Your final output will be a structured, prioritized vulnerability report. 
You must be precise, factual, and follow the instructions of each tool call exactly."""

# Create the agent
agent = Agent(
  'google-gla:gemini-2.5-flash',
  tools=[
    tools.parse_sbom,
    tools.query_nvd_for_cves,
    tools.correlate_with_cisa_kev,
    tools.get_cpe_for_component,
    tools.map_cve_to_attack,
    tools.find_defensive_measures,
  ],
  system_prompt=system_prompt
)


def calculate_risk_score(vulnerability, kev_info, attack_mappings, epss_score):
    """Calculates a risk score for a vulnerability."""
    # Weights for each factor
    w_cvss = 0.3
    w_kev = 0.4
    w_attack = 0.1
    w_epss = 0.2

    # CVSS Score
    cvss_score = vulnerability.cvss_score or 0.0

    # KEV Flag
    kev_flag = 10.0 if vulnerability.cve_id in kev_info else 0.0

    # ATT&CK Impact
    attack_impact = 0.0
    if attack_mappings:
        # This is a simplified impact score. A real implementation would have a
        # more sophisticated mapping of tactics to impact.
        attack_impact = 5.0

    # EPSS Score
    epss_score_value = epss_score or 0.0

    risk_score = (w_cvss * cvss_score) + (w_kev * kev_flag) + (w_attack * attack_impact) + (w_epss * epss_score_value * 10)
    return risk_score


async def run_analysis(sbom_file_path: str):
    """Runs the full analysis on an SBOM file."""
    components = tools.parse_sbom(sbom_file_path)
    
    all_vulnerabilities = []
    for component in components:
        if not component.cpe:
            cpe_prompt = (
                f"Generate a CPE 2.3 string for the following software component. "
                f"Provide only the CPE string and nothing else. "
                f"Component Name: {component.name}, Version: {component.version}. "
                f"Example: For 'Apache Log4j', version '2.14.1', the CPE is cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"
            )
            cpe_result = await agent.run(cpe_prompt)
            component.cpe = cpe_result.output.strip()

        vulnerabilities = tools.query_nvd_for_cves(component.cpe)
        all_vulnerabilities.extend(vulnerabilities)

    cve_ids = [v.cve_id for v in all_vulnerabilities]
    kev_info = tools.correlate_with_cisa_kev(cve_ids)
    epss_scores = tools.query_epss(cve_ids)

    enriched_vulnerabilities = []
    for vulnerability in all_vulnerabilities:
        attack_mappings = tools.map_cve_to_attack(vulnerability.cve_id, vulnerability.description)
        defensive_measures = tools.find_defensive_measures(vulnerability.cve_id)
        epss_score = epss_scores.get(vulnerability.cve_id)
        risk_score = calculate_risk_score(vulnerability, kev_info, attack_mappings, epss_score)

        enriched_vulnerabilities.append(
            {
                "vulnerability": vulnerability,
                "kev_info": kev_info.get(vulnerability.cve_id),
                "attack_mappings": attack_mappings,
                "defensive_measures": defensive_measures,
                "epss_score": epss_score,
                "risk_score": risk_score,
            }
        )

    # Sort vulnerabilities by risk score
    enriched_vulnerabilities.sort(key=lambda x: x["risk_score"], reverse=True)

    # Generate the summary with the LLM
    summary_prompt = (
        f"Based on the following vulnerability data, generate a 1-2 paragraph executive summary for a cybersecurity report. "
        f"Highlight the total number of vulnerabilities, the number of actively exploited vulnerabilities (KEV), and the number of high-risk vulnerabilities. "
        f"Conclude with a recommendation for prioritizing remediation efforts.\n\n"
        f"Vulnerability Data: {json.dumps(enriched_vulnerabilities, indent=2, default=str)}"
    )
    summary_result = await agent.run(summary_prompt)
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
    kev_count = sum(1 for item in enriched_vulnerabilities if item["kev_info"])

    vulnerability_table = ""
    for item in enriched_vulnerabilities:
        vulnerability = item["vulnerability"]
        kev_status = "Yes" if item["kev_info"] else "No"
        epss_score = f"{item['epss_score']:.2f}" if item['epss_score'] is not None else "N/A"
        vulnerability_table += f"| {vulnerability.cve_id} | {vulnerability.cvss_score} | {kev_status} | {epss_score} | {item['risk_score']:.2f} |\n"

    detailed_analysis = ""
    for item in enriched_vulnerabilities:
        vulnerability = item["vulnerability"]
        epss_score_str = f"{item['epss_score']:.2f}" if item['epss_score'] is not None else "N/A"
        detailed_analysis += f"### {vulnerability.cve_id}\n\n"
        detailed_analysis += f"**CVSS v3.1 Base Score:** {vulnerability.cvss_score}\n\n"
        detailed_analysis += f"**CISA KEV Status:** {'Actively Exploited' if item['kev_info'] else 'Not Listed'}\n\n"
        detailed_analysis += f"**EPSS Score:** {epss_score_str}\n\n"
        detailed_analysis += f"**CWE:** [{vulnerability.weaknesses[0] if vulnerability.weaknesses else 'N/A'}](https://cwe.mitre.org/data/definitions/{vulnerability.weaknesses[0].split('-')[1]}.html)\n\n"
        detailed_analysis += f"**Description:** {vulnerability.description}\n"

        if item["attack_mappings"]:
            detailed_analysis += "\n**MITRE ATT&CK Mapping:**\n\n"
            for mapping in item["attack_mappings"]:
                detailed_analysis += f"- **Tactic:** [{mapping['tactic']}](https://attack.mitre.org/tactics/{mapping['tactic']})\n"
                detailed_analysis += f"- **Technique:** [{mapping['technique_id']}: {mapping['technique_name']}](https://attack.mitre.org/techniques/{mapping['technique_id']})\n"
            detailed_analysis += "\n"

        if item["defensive_measures"]:
            detailed_analysis += "**Defensive Measures:**\n\n"
            for measure_type, rules in item["defensive_measures"].items():
                detailed_analysis += f"**{measure_type.upper()} Rules:**\n\n```yaml\n"
                for rule in rules:
                    detailed_analysis += f"{rule}\n"
                detailed_analysis += "```\n\n"

    return report.format(
        sbom_file_path=sbom_file_path,
        summary=summary,
        total_components=total_components,
        total_vulnerabilities=total_vulnerabilities,
        kev_count=kev_count,
        vulnerability_table=vulnerability_table,
        detailed_analysis=detailed_analysis,
    )

