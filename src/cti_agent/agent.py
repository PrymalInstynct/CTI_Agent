"""Pydantic AI Agent for the CTI Agent."""
import os
from pydantic_ai import Agent
from pydantic_ai.llm.google import Google
from . import tools

# Configure the LLM
llm = Google(
  api_key=os.getenv("GEMINI_API_KEY"),
  model_name='google-gla:gemini-2.5-flash'
)

# Define the master system prompt
system_prompt = """You are an expert Cyber Threat Intelligence Analyst. 
Your mission is to analyze a list of software components from a Software Bill of Materials (SBOM). 
For each component, you will use the provided tools to find associated vulnerabilities (CVEs), enrich them with data from NVD, CISA KEV, CWE, and MITRE ATT&CK, and find defensive measures. 
Your final output will be a structured, prioritized vulnerability report. 
You must be precise, factual, and follow the instructions of each tool call exactly."""

# Create the agent
agent = Agent(
  [
    tools.parse_sbom,
    tools.query_nvd_for_cves,
    tools.correlate_with_cisa_kev,
    tools.get_cpe_for_component,
    tools.map_cve_to_attack,
    tools.find_defensive_measures
  ],
  llm=llm,
  system_prompt=system_prompt
)

def calculate_risk_score(vulnerability, kev_info, attack_mappings):
    """Calculates a risk score for a vulnerability."""
    # Weights for each factor
    w_cvss = 0.4
    w_kev = 0.4
    w_attack = 0.2

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

    risk_score = (w_cvss * cvss_score) + (w_kev * kev_flag) + (w_attack * attack_impact)
    return risk_score

def run_analysis(sbom_file_path: str):
    """Runs the full analysis on an SBOM file."""
    components = agent.run(f"Parse the SBOM file at {sbom_file_path}")
    
    enriched_vulnerabilities = []
    for component in components:
        if not component.cpe:
            component.cpe = agent.run(f"Generate a CPE for {component.name} version {component.version}")

        vulnerabilities = agent.run(f"Query NVD for CVEs using CPE: {component.cpe}")
        cve_ids = [v.cve_id for v in vulnerabilities]
        kev_info = agent.run(f"Correlate CVEs with CISA KEV: {cve_ids}")

        for vulnerability in vulnerabilities:
            attack_mappings = agent.run(f"Map CVE to ATT&CK: {vulnerability.cve_id} - {vulnerability.description}")
            defensive_measures = agent.run(f"Find defensive measures for {vulnerability.cve_id}")
            risk_score = calculate_risk_score(vulnerability, kev_info, attack_mappings)

            enriched_vulnerabilities.append(
                {
                    "vulnerability": vulnerability,
                    "kev_info": kev_info.get(vulnerability.cve_id),
                    "attack_mappings": attack_mappings,
                    "defensive_measures": defensive_measures,
                    "risk_score": risk_score,
                }
            )

    # Sort vulnerabilities by risk score
    enriched_vulnerabilities.sort(key=lambda x: x["risk_score"], reverse=True)

    # Generate the report (for now, just print the results)
    for item in enriched_vulnerabilities:
        print(f"CVE: {item['vulnerability'].cve_id}, Risk Score: {item['risk_score']}")