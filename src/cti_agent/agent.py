from pydantic_ai import Agent
from . import tools
from .models import EnrichedVulnerability, AnalysisReport
from typing import List
from datetime import datetime

class CTI_Agent(Agent):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def _calculate_risk_score(self, vulnerability: EnrichedVulnerability) -> float:
        """
        Calculates a proprietary risk score for a given vulnerability.
        This is a placeholder implementation.
        """
        score = vulnerability.vulnerability.cvss_score if vulnerability.vulnerability.cvss_score else 0.0
        if vulnerability.is_in_kev:
            score += 5.0  # High impact for KEV vulnerabilities
        
        # Add more sophisticated logic for ATT&CK mapping and EPSS here later.
        
        return score

    def _generate_markdown_report(self, sbom_file_path: str, total_components: int, enriched_vulnerabilities: List[EnrichedVulnerability]) -> str:
        report_content = []

        # Executive Summary
        total_vulnerabilities = len(enriched_vulnerabilities)
        critical_high_vulnerabilities = [
            v for v in enriched_vulnerabilities if v.vulnerability.cvss_score and v.vulnerability.cvss_score >= 7.0
        ]
        kev_vulnerabilities = [v for v in enriched_vulnerabilities if v.is_in_kev]

        report_content.append("# Cyber Threat Intelligence Analysis Report")
        report_content.append(f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report_content.append(f"**SBOM File:** `{sbom_file_path}`")
        report_content.append("\n## Executive Summary")
        report_content.append(f"- **Total Components Scanned:** {total_components}")
        report_content.append(f"- **Total Vulnerabilities Found:** {total_vulnerabilities}")
        report_content.append(f"- **Critical/High Priority Vulnerabilities:** {len(critical_high_vulnerabilities)}")
        report_content.append(f"- **Actively Exploited (CISA KEV) Vulnerabilities:** {len(kev_vulnerabilities)}")
        if kev_vulnerabilities:
            report_content.append("\n### Actively Exploited Vulnerabilities (CISA KEV)")
            for kev_vuln in kev_vulnerabilities:
                report_content.append(f"- [{kev_vuln.vulnerability.cve_id}](https://nvd.nist.gov/vuln/detail/{kev_vuln.vulnerability.cve_id})")

        # Prioritized Vulnerabilities
        report_content.append("\n## Prioritized Vulnerabilities")
        report_content.append("| CVE ID | CVSS Score | KEV | ATT&CK Tactic | ATT&CK Technique |\n|---|---|---|---|---|")
        for vuln in enriched_vulnerabilities:
            kev_status = "Yes" if vuln.is_in_kev else "No"
            attack_tactic = vuln.attack_mappings[0]['tactic'] if vuln.attack_mappings else "N/A"
            attack_technique = vuln.attack_mappings[0]['technique_name'] if vuln.attack_mappings else "N/A"
            report_content.append(f"| [{vuln.vulnerability.cve_id}](https://nvd.nist.gov/vuln/detail/{vuln.vulnerability.cve_id}) | {vuln.vulnerability.cvss_score:.1f} | {kev_status} | {attack_tactic} | {attack_technique} |")

        # Detailed Vulnerability Analysis
        report_content.append("\n## Detailed Vulnerability Analysis")
        for vuln in enriched_vulnerabilities:
            report_content.append(f"\n### {vuln.vulnerability.cve_id}")
            report_content.append(f"- **Description:** {vuln.vulnerability.description}")
            report_content.append(f"- **CVSS v3.1 Base Score:** {vuln.vulnerability.cvss_score:.1f}")
            report_content.append(f"- **CISA KEV Status:** {'Actively Exploited' if vuln.is_in_kev else 'Not Listed'}")
            
            if vuln.vulnerability.weaknesses:
                report_content.append("- **CWEs:**")
                for cwe in vuln.vulnerability.weaknesses:
                    report_content.append(f"  - {cwe}")

            if vuln.attack_mappings:
                report_content.append("- **MITRE ATT&CK Mappings:**")
                for mapping in vuln.attack_mappings:
                    report_content.append(f"  - **Tactic:** {mapping['tactic']}")
                    report_content.append(f"  - **Technique:** {mapping['technique_id']} - {mapping['technique_name']}")

            if vuln.defensive_measures:
                report_content.append("- **Defensive Measures:**")
                for measure_type, rules in vuln.defensive_measures.items():
                    if rules:
                        report_content.append(f"  - **{measure_type.upper()} Rules:**")
                        report_content.append("```")
                        report_content.append("\n".join(rules))
                        report_content.append("```")
        
        return "\n".join(report_content)

    def run(self, sbom_file_path: str) -> str:
        parsed_sbom_data = tools.parse_sbom.func(sbom_file_path=sbom_file_path)
        
        components = parsed_sbom_data['components']
        enriched_vulnerabilities = []

        for component in components:
            cpe_string = component.cpe
            if not cpe_string:
                cpe_string = tools.get_cpe_for_component.func(
                    component_name=component.name,
                    component_version=component.version,
                )

            if cpe_string:
                vulnerabilities = tools.query_nvd_for_cves.func(
                    cpe_string=cpe_string
                )
                
                cve_ids = [v.cve_id for v in vulnerabilities]
                kev_info = tools.correlate_with_cisa_kev.func(cve_ids=cve_ids)

                for vuln in vulnerabilities:
                    attack_mappings = tools.map_cve_to_attack.func(
                        cve_id=vuln.cve_id,
                        cve_description=vuln.description,
                    )
                    defensive_measures = self.run_tool(
                        "find_defensive_measures", cve_id=vuln.cve_id
                    )

                    enriched_vulnerabilities.append(
                        EnrichedVulnerability(
                            vulnerability=vuln,
                            is_in_kev=vuln.cve_id in kev_info,
                            kev_details=kev_info.get(vuln.cve_id),
                            attack_mappings=attack_mappings,
                            defensive_measures=defensive_measures,
                        )
                    )
        
        # Prioritize vulnerabilities
        enriched_vulnerabilities.sort(key=self._calculate_risk_score, reverse=True)
        
        return self._generate_markdown_report(sbom_file_path, len(components), enriched_vulnerabilities)

def create_agent():
    return CTI_Agent(
        model="google-gla:gemini-2.5-flash",
        tools=[
            tools.parse_sbom,
            tools.query_nvd_for_cves,
            tools.correlate_with_cisa_kev,
            tools.get_cpe_for_component,
            tools.map_cve_to_attack,
            tools.find_defensive_measures,
        ],
        system_prompt="""You are an expert Cyber Threat Intelligence Analyst. Your mission is to analyze a list of software components from a Software Bill of Materials (SBOM). For each component, you will use the provided tools to find associated vulnerabilities (CVEs), enrich them with data from NVD, CISA KEV, CWE, and MITRE ATT&CK, and find defensive measures. Your final output will be a structured, prioritized vulnerability report. You must be precise, factual, and follow the instructions of each tool call exactly.""",
    )