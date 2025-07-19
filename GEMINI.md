# Product Requirements Document: Cyber Threat Intelligence Agent

Version: 1.0

Date: July 8, 2025

Status: DRAFT

## 1.0 Product Vision & Overview

### 1.1 Vision Statement

To create a state-of-the-art, AI-driven command-line utility that empowers DevSecOps engineers and security analysts to rapidly and intelligently assess the security posture of software applications. By ingesting a standard Software Bill of Materials (SBOM), the Cyber Threat Intelligence Agent will automate the complex, multi-source correlation of vulnerabilities, providing deep contextualization and a risk-prioritized, actionable remediation plan.

### 1.2 Project Goals & Objectives

The primary goal of the Cyber Threat Intelligence Agent is to transform the process of vulnerability management from a reactive, manual, and often overwhelming task into a proactive, automated, and intelligent workflow. This will be achieved through the following key objectives:

- Automate Vulnerability Discovery: The agent will eliminate the laborious and error-prone manual process of cross-referencing software components listed in an SBOM against disparate vulnerability databases. It will programmatically parse dependencies and initiate a comprehensive security analysis.

- Enhance Intelligence with AI: The project will leverage the advanced reasoning capabilities of Large Language Models (LLMs) to perform nuanced analysis tasks that are challenging for traditional, deterministic tools. This includes dynamically generating Common Platform Enumeration (CPE) strings from incomplete component data and mapping complex vulnerability descriptions to adversary tactics, techniques, and procedures (TTPs).::q!

- Provide Actionable Context: The agent will move beyond simple vulnerability scanning to provide rich, actionable context. By correlating vulnerabilities with frameworks like MITRE ATT&CK and Common Weakness Enumeration (CWE), it will explain how a vulnerability might be exploited and what underlying software weakness it represents. Furthermore, it will furnish concrete defensive measures, such as detection rules in Sigma, Snort, or Yara formats, enabling immediate action.  

- Implement Risk-Based Prioritization: A core objective is to generate a remediation plan that reflects true business risk. The agent will implement a sophisticated prioritization algorithm that looks beyond static severity scores (like CVSS) to incorporate a holistic view of risk. This includes factoring in confirmed, real-world exploits from the CISA Known Exploited Vulnerabilities (KEV) catalog and the potential impact derived from adversary tactics.  

- Developer-Centric Workflow: The entire experience is designed for the modern developer and security professional. By providing a seamless, powerful command-line interface (CLI), the agent integrates smoothly into existing development, security, and CI/CD workflows, delivering results directly in the terminal where users work most effectively.

### 1.3 Target Audience

The Cyber Threat Intelligence Agent is designed for technical users who operate at the intersection of software development and cybersecurity.

- Primary Audience:

  - DevSecOps Engineers: Professionals responsible for embedding security practices and automated checks into the CI/CD pipeline. They require fast, reliable, and scriptable tools to assess application security without slowing down development cycles.

  - Application Security (AppSec) Specialists: Analysts who perform in-depth security reviews of applications. They will use the agent to accelerate their initial triage process, quickly identifying high-risk components and understanding potential attack paths.

  - Security Analysts (SOC/Threat Intelligence): Analysts who may receive SBOMs from internal development teams or third-party vendors. They will use the agent to rapidly assess the threat landscape associated with a given piece of software.

- Secondary Audience:

  - Security-Conscious Software Developers: Developers who want to take a more proactive role in securing their code. The agent provides them with a simple way to check their dependencies for critical issues before committing code.

  - Product Security Managers: Managers who need high-level summaries of the risk posture of different applications. The agent's clear, Markdown-based reports can be easily shared and archived to track risk over time.

## 2.0 User Personas and Stories

### 2.1 Primary Persona: "Alex," the DevSecOps Engineer

- Profile: Alex is responsible for building and maintaining the secure software development lifecycle (SDLC) at a mid-sized technology company. They are highly technical, fluent in Python and shell scripting, and live in the command line. Alex's primary challenge is to balance the speed of development with the need for robust security. They are often inundated with a high volume of alerts from various security scanners and struggle to distinguish real, urgent threats from theoretical or low-risk findings.

- Goals:

  - To quickly and accurately assess the security risk of new dependencies introduced into a project during a pull request review.

  - To understand the real-world impact of a vulnerability—is it being actively exploited by threat actors?—rather than relying solely on its theoretical CVSS severity score.

  - To provide development teams with clear, unambiguous, and actionable guidance on which vulnerabilities to fix first and how to configure detection systems to monitor for potential exploitation attempts.

  - To automate security analysis as a gate within the CI/CD pipeline, failing a build if a high-risk, actively exploited vulnerability is detected.

### 2.2 User Stories

The following user stories describe the key tasks Alex needs to accomplish using the Cyber Threat Intelligence Agent:

- US-01: SBOM Analysis Initiation

  - "As Alex, I want to run the agent from my command line, passing the path to a CycloneDX SBOM file, so that I can initiate a security analysis of my application's dependencies."

- US-02: Prioritized Vulnerability Reporting

  - "As Alex, I want to receive a clear, prioritized list of vulnerabilities in my terminal, so I can immediately focus my team's efforts on the highest-risk issues and not get lost in a sea of low-priority alerts."

- US-03: AI-Driven CPE Identification

  - "As Alex, I want the agent to automatically identify the correct Common Platform Enumeration (CPE) for each software component, even if the SBOM does not contain it, so that it can accurately query the National Vulnerability Database for associated CVEs."

- US-04: Threat Contextualization

  - "As Alex, I want to see how each critical vulnerability maps to specific MITRE ATT&CK techniques and Common Weakness Enumerations (CWEs), so I can understand the potential attack vectors and the fundamental types of weaknesses being exploited."

- US-05: Actionable Defensive Measures

  - "As Alex, I want the agent to provide me with any available Sigma, Snort, or Yara rules for high-priority vulnerabilities, so I can immediately provide them to our Security Operations team to configure our SIEM and EDR systems for proactive detection."

- US-06: CISA KEV Correlation

  - "As Alex, I want the agent to clearly flag any vulnerabilities that are listed in the CISA KEV catalog, so I can give them the highest possible priority for remediation, in alignment with our organizational policy and federal guidance."

- US-07: Secure Configuration

  - "As Alex, I want to configure the agent with my necessary API keys using a standard .env file, so that my sensitive credentials are not exposed in my shell history, committed to version control, or visible in process lists."

## 3.0 Functional Requirements: Core Features

This section details the specific functional capabilities that the Cyber Threat Intelligence Agent must provide.

### 3.1 Command-Line Interface (CLI)

The primary user interaction with the agent will be through a command-line interface, designed for simplicity, power, and ease of integration into automated workflows.

- FR-3.1.1: SBOM Input: The CLI MUST accept a mandatory argument to specify the path to the CycloneDX SBOM file for analysis. The suggested argument format is `--sbom-file <path>`. The application must validate that the provided path points to an existing file and return a clear error if it does not.

- FR-3.1.2: Pydantic AI Integration: The CLI will be implemented leveraging the Pydantic AI framework's built-in capabilities, specifically the to_cli() or to_cli_sync() methods. This approach is selected for its rapid development cycle and tight integration with the core agent logic. It automatically generates a functional CLI from the agent's tool definitions, minimizing boilerplate code and ensuring that the CLI's interface is always synchronized with the agent's capabilities.

- FR-3.1.3: Output Rendering: The CLI MUST render its final analysis report in well-formatted Markdown directly to the standard output (stdout). This design choice ensures maximum flexibility, allowing the user to view the report directly in the terminal, pipe it to a pager like less, or redirect it to a file (e.g., agent --sbom-file bom.json > report.md). The rendering logic must correctly handle newlines, code block formatting for detection rules, and proper URL encoding for links to external resources like NVD.

- FR-3.1.4: Error Handling: The application must implement robust error handling and provide clear, user-friendly error messages for common failure scenarios. This is critical for a tool intended for use in automated scripts. Scenarios to handle include:

  - An invalid or non-existent path is provided for the SBOM file.

  - Required environment variables for API keys (GEMINI_API_KEY, NVD_API_KEY) are missing or invalid.

  - The SBOM file is malformed and cannot be parsed by the CycloneDX library.

  - An external API (e.g., NVD) returns an error, such as a rate-limiting status code.

- FR-3.1.5: Best Practices: While Pydantic AI provides the core interface, the CLI should adhere to established conventions to enhance usability. This includes providing a standard --help flag that details all available commands and options, and a --version flag to display the current version of the application. These features are standard in professional-grade CLI tools built with frameworks like Click or argparse and are expected by technical users.  

### 3.2 CycloneDX SBOM Parsing

The agent's first task is to ingest and understand the provided Software Bill of Materials.

- FR-3.2.1: File Format Support: The system MUST be capable of parsing CycloneDX SBOMs provided in both JSON and XML formats, as both are common in the industry. The parser should ideally auto-detect the format based on file content or extension.

- FR-3.2.2: Component Extraction: The agent must parse the input SBOM and extract a canonical list of all software components defined within the components array. For each component, it MUST extract the following key attributes if they are present in the SBOM data: name, version, purl (Package URL), and cpe (Common Platform Enumeration). This information forms the basis for all subsequent analysis.  

- FR-3.2.3: Library Implementation: The parsing logic will be implemented using the cyclonedx-python-lib library, which is the reference Python implementation for the CycloneDX standard. Specifically, the implementation will utilize the library's robust deserialization methods, such as `Bom.from_json()` for JSON files and `Bom.from_xml()` for XML files. This approach loads the SBOM data into the library's Pydantic-based object model, providing a structured, type-safe, and reliable way to access the BOM's contents.  

The architecture will enforce a clear separation of concerns. The cyclonedx-python-lib will serve exclusively as the data ingestion and modeling layer. Its purpose is to translate the raw SBOM file into a structured Python object representation, leveraging its  

Bom and Component classes. The library itself does not perform vulnerability enrichment; it explicitly notes that sourcing vulnerability information is the responsibility of the consuming application. This design choice is beneficial, as it decouples the core analysis logic of the Cyber Threat Intelligence Agent from the specifics of the parsing library. Internal Pydantic models will be defined within the agent's application logic. These models will be populated with data from the  

cyclonedx.model.component.Component objects. The agent's tools will then operate on these internal models, ensuring the application's core logic is modular, easier to maintain, and not tightly coupled to an external library's data structures.

### 3.3 Multi-Source Vulnerability Correlation

Once components are identified, the agent must correlate them against leading vulnerability intelligence sources.

- FR-3.3.1: NVD API Integration: The agent MUST query the National Vulnerability Database (NVD) 2.0 CVE API to retrieve vulnerability information for each software component.

  - Queries will be constructed using the CPE string associated with a component. The request format will be `https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={cpe_string}`.

  - The system must handle API rate limiting gracefully. The NVD API enforces request limits, and the agent should implement a retry mechanism with exponential backoff to manage this.

  - To achieve higher rate limits and ensure reliable operation, the agent MUST use an NVD_API_KEY, which will be provided via an environment variable.

- FR-3.3.2: CISA KEV Catalog Integration: The agent MUST correlate all identified CVEs against the CISA Known Exploited Vulnerabilities (KEV) catalog to identify threats that are being actively used by adversaries.

  - The KEV catalog will be acquired from the official CISA JSON feed, which is the authoritative source. To optimize performance and reduce external dependencies during runtime, this catalog will be downloaded and stored locally within the frameworks/ directory.  

  - The system will include a mechanism to refresh this local data file to ensure the intelligence is current. This can be achieved using a dedicated library like cisa-kev, which simplifies the process of downloading and querying the KEV data.  

  - Any CVE that is found in the KEV catalog MUST be clearly flagged as "Actively Exploited" in the final report, as this is a primary indicator for prioritization.  

### 3.4 AI-Powered Analysis & Contextualization

A key differentiator for this agent is its use of an LLM to provide deep, contextual analysis that goes beyond simple data retrieval.

- FR-3.4.1: AI-Driven CPE Construction: For software components where a CPE string is not provided in the SBOM, the agent MUST use the LLM to dynamically construct a valid CPE 2.3 string. This is a critical function, as an accurate CPE is essential for reliable NVD lookups. The LLM will be provided with the component's name, version, and purl (if available) as context. The prompt engineering for this task will be highly structured, incorporating few-shot examples to guide the model toward generating a syntactically correct and accurate CPE string.

- FR-3.4.2: Threat Contextualization (CWE & MITRE ATT&CK): For each high-priority CVE identified, the agent MUST use the LLM to provide deeper threat context.

  - CWE Mapping: The agent will analyze the CVE description to identify the corresponding Common Weakness Enumeration (CWE) ID. While the NVD API response often includes CWE data, the LLM can serve as a powerful fallback or provide supplementary analysis for CVEs from other sources. To facilitate this, the comprehensive CWE data will be downloaded from the official MITRE source and stored locally for reference.

  - MITRE ATT&CK Mapping: The agent will analyze the CVE description and its associated weakness to map the vulnerability to one or more MITRE ATT&CK tactics and techniques. This is a complex semantic mapping task where LLMs have shown significant promise over deterministic methods. The complete ATT&CK framework data, in STIX format, will be downloaded from the official MITRE/CTI repository and stored locally to serve as a knowledge base for the agent.  

- FR-3.4.3: Defensive Measure Analysis: For each high-priority CVE, the agent MUST use the LLM to search for and identify relevant defensive measures that can be used to mitigate, remediate, or detect exploitation.

  - The LLM will be prompted to search public sources (simulated through its vast training data) for detection rules specifically associated with a given CVE ID.

  - Any identified rules MUST be formatted and presented in their native syntax (e.g., Sigma YAML, Snort rule syntax, or Yara rule syntax) within a code block in the final report for easy copy-pasting into security tools.

### 3.5 Comprehensive Reporting

The final output of the agent is a single, actionable report delivered to the user.

- FR-3.5.1: Report Format: The final output MUST be a single, comprehensive report generated in Markdown format. This format is chosen for its readability, portability, and ease of integration with other developer tools and documentation systems.

- FR-3.5.2: Report Structure: The report will be organized hierarchically to allow for both quick scanning and in-depth analysis:

    1. Executive Summary: A high-level overview of the analysis, including key metrics like the total number of components scanned, total vulnerabilities found, and a count of critical/high-priority issues, with a special mention of any actively exploited vulnerabilities from the KEV catalog.

    2. Prioritized Vulnerabilities: A summary table listing all identified vulnerabilities, ordered by the AI-driven risk score (detailed in Section 4.4). This table will provide a quick, at-a-glance view of the most pressing issues.

    3. Detailed Vulnerability Analysis: A dedicated section for each high-priority vulnerability. This section will provide a complete, contextualized breakdown, including:

       - CVE ID (with a hyperlink to the NVD entry).

       - CVSS v3.1 Base Score and Severity Rating.

       - CISA KEV Status (e.g., "Actively Exploited" or "Not Listed").

       - CWE ID and Name (e.g., "CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')").

       - MITRE ATT&CK Mapping (Tactic and Technique, e.g., "Tactic: Execution, Technique: T1059 - Command and Scripting Interpreter").

       - Defensive Measures (any identified Sigma, Snort, or Yara rules, presented in formatted code blocks).

- FR-3.5.3: AI-Powered Prioritization: The report MUST present vulnerabilities in a prioritized order determined by the agent's internal risk-scoring algorithm. This prioritization will be a synthesis of multiple risk factors, not a simple sort by CVSS score, reflecting a more intelligent and context-aware assessment of the threats.

## 4.0 AI Agent Architecture

This section defines the internal architecture of the Pydantic AI Agent, which serves as the orchestrating intelligence of the application. The design emphasizes modularity, maintainability, and the strategic application of LLM capabilities.

### 4.1 Pydantic AI Agent Definition

- FR-4.1.1: Agent Initialization: The core of the application will be an instance of the pydantic_ai.Agent class. It will be configured to use the Gemini 2.5 Flash model as its primary reasoning engine, accessed via a secure API key.

- FR-4.1.2: Model Pluggability: The choice of LLM will be designed for flexibility. The model identifier (e.g., 'google-gla:gemini-1.5-flash') will be sourced from a configuration setting or environment variable. This ensures that the application is not locked into a single provider and can easily be adapted to use other models supported by Pydantic AI, such as those from OpenAI, Mistral, or Anthropic, as the technology landscape evolves.  

- FR-4.1.3: System Prompt: The agent will be initialized with a carefully crafted master system prompt that establishes its persona, defines its high-level objective, and sets the tone for its operation.

  - System Prompt Text: "You are an expert Cyber Threat Intelligence Analyst. Your mission is to analyze a list of software components from a Software Bill of Materials (SBOM). For each component, you will use the provided tools to find associated vulnerabilities (CVEs), enrich them with data from NVD, CISA KEV, CWE, and MITRE ATT&CK, and find defensive measures. Your final output will be a structured, prioritized vulnerability report. You must be precise, factual, and follow the instructions of each tool call exactly."

### 4.2 Agent Tool Definitions

The agent's functional capabilities will be implemented as a suite of discrete, single-purpose Python functions, each decorated with agent.tool. This modular, tool-based architecture is a best practice for building complex AI agents, as it makes the system more maintainable, testable, and allows the LLM to reason about which function to call to accomplish a specific sub-task. The table below specifies the contract between the LLM and the Python code for each tool.  

| Tool Name  | Function                                                                                                                | Inputs              | Outputs                                                              | Example LLM Thought Process                                                                                                                                                                                              |
| ---------- | ----------------------------------------------------------------------------------------------------------------------- | ------------------- | -------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| parse_sbom | Parses the input SBOM file to extract a list of software components. This is the initial step in the analysis workflow. | sbom_file_path: str | components: List[dict] (each dict contains name, version, purl, cpe) | "The user has provided an SBOM file at a specific path. My first step is to understand its contents. I must call the parse_sbom tool with this file path to get the list of software components that I need to analyze." |
| get_cpe_for_component | Uses the LLM's reasoning to generate a valid CPE 2.3 string for a component that lacks one in the input data. | component_name: str, component_version: str | cpe_string: str | "The component 'apache-log4j' version '2.17.1' is missing a CPE. To query the NVD, I need to construct one. The vendor is 'apache', product is 'log4j'. I will formulate this into the standard format: cpe:2.3:a:apache:log4j:2.17.1:*:*:*:*:*:*:* and use the get_cpe_for_component tool to validate and return this string." |
| query_nvd_for_cves | Queries the NVD API using a CPE string to find all associated CVEs and their basic details. | cpe_string: str | cves: List[dict] (each dict has cve_id, description, cvss_v3_score, cwe_ids) | "I now have a valid CPE for the log4j component. The next logical step is to discover its vulnerabilities. I will call the query_nvd_for_cves tool with the CPE string to retrieve a list of all associated CVEs from the National Vulnerability Database." |
| correlate_with_cisa_kev | Checks a list of CVE IDs against the locally stored CISA KEV catalog to identify actively exploited vulnerabilities. | cve_ids: List[str] | kev_info: dict (a mapping of cve_id to its KEV details, if found) | "I have a list of CVEs for this component. To assess the real-world risk, I must determine if any are being actively exploited. I will call the correlate_with_cisa_kev tool with this list of CVE IDs to check against the CISA KEV catalog." |
| map_cve_to_attack | Uses the LLM to analyze a CVE's description and map it to relevant MITRE ATT&CK tactics and techniques. | cve_id: str, cve_description: str | attack_mappings: List[dict] (each dict has tactic, technique_id, technique_name) | "For CVE-2021-44228, the description mentions 'remote code execution'. This is a clear indicator of the 'Execution' tactic. I will call the map_cve_to_attack tool with the CVE ID and its description to identify the specific technique, which is likely T1059 (Command and Scripting Interpreter)." |
| find_defensive_measures | Uses the LLM to search for publicly known detection rules (Sigma, Snort, Yara) for a given CVE ID. | cve_id: str | detection_rules: dict (keys: 'sigma', 'snort', 'yara'; values are lists of rule strings) | "This is a critical, actively exploited vulnerability. The user needs to know how to detect it. I will call the find_defensive_measures tool with 'CVE-2021-44228' to search for any available Sigma, Snort, or Yara rules that can be deployed." |

### 4.3 Orchestration Logic

- FR-4.3.1: Workflow Definition: The agent is responsible for orchestrating the execution of its tools in a logical sequence to perform the end-to-end analysis for each component identified in the SBOM. The standard workflow is as follows:

    1. The process begins by calling parse_sbom a single time to ingest the entire list of components.

    2. The agent then iterates through each component.

    3. For a given component, if the cpe field is missing or invalid, the agent will first call get_cpe_for_component to generate it.

    4. With a valid CPE, the agent calls query_nvd_for_cves.

    5. If vulnerabilities are returned, the agent proceeds with enrichment, calling correlate_with_cisa_kev, map_cve_to_attack, and find_defensive_measures for each high-priority vulnerability.

    6. After all components have been processed, the agent aggregates the enriched vulnerability data.

    7. The agent applies the prioritization algorithm (defined in Section 4.4) to the aggregated data to calculate a RiskScore for each vulnerability.

    8. Finally, the agent synthesizes all information into the final, structured Markdown report.

The process of generating structured data, such as a CPE string or a mapping to an ATT&CK technique, is highly sensitive to the quality of the prompt. Research indicates that prompt style (e.g., JSON vs. simple prefixes), structure, and the inclusion of examples (few-shot prompting) significantly influence the accuracy, reliability, and cost of LLM outputs. Advanced techniques like meta-prompting, where an LLM helps refine prompts, further highlight the importance of this step.  

Therefore, to ensure the agent's intelligence is robust and reproducible, the prompt templates for the key AI-driven tools (get_cpe_for_component, map_cve_to_attack, find_defensive_measures) are considered core product requirements, not mere implementation details. These prompts must be engineered with the following principles:

- Role-Playing: The prompt should instruct the LLM to act as an expert in the relevant domain (e.g., "You are a cybersecurity expert specializing in vulnerability classification").

- Clear Instructions: The task must be defined unambiguously.

- Context Provision: All necessary input data (e.g., component name, version, CVE description) must be clearly delineated within the prompt.

- Few-Shot Examples: The prompt must include several high-quality examples of the desired input-to-output transformation. For CPE generation, this would include examples of component names being correctly mapped to CPE strings. This guides the model's reasoning process and dramatically improves the quality of the output.

### 4.4 AI-Driven Vulnerability Prioritization Algorithm

To move beyond simplistic and often misleading prioritization based solely on CVSS scores, the agent will implement a more holistic, multi-factor risk-scoring algorithm.  

- FR-4.4.1: Multi-Factor Risk Scoring: The agent MUST calculate a proprietary RiskScore for each identified vulnerability. This score will be used to rank vulnerabilities in the final report, ensuring that the user's attention is directed to the threats that pose the most immediate and significant risk.

- FR-4.4.2: Scoring Factors: The algorithm will be a weighted formula that incorporates the following key risk indicators:

  - Severity (CVSS): The numeric CVSS v3.1 Base Score (ranging from 0.0 to 10.0) serves as the baseline measure of a vulnerability's theoretical severity.

  - Exploitation Status (CISA KEV): This is a high-impact, binary factor. A vulnerability's presence in the CISA KEV catalog is a definitive signal of real-world exploitation and must heavily influence its priority.  

  - Threat Context (ATT&CK): This factor provides context on the impact of a successful exploit. Vulnerabilities that map to ATT&CK tactics associated with high-impact outcomes (e.g., TA0002 - Execution, TA0008 - Lateral Movement) will receive a higher weight than those mapped to preparatory tactics (e.g., TA0043 - Reconnaissance).

  - Predicted Exploitability (EPSS): The architecture MUST be designed to easily incorporate the Exploit Prediction Scoring System (EPSS) score. EPSS provides a predictive, forward-looking probability of exploitation, which would complement the retrospective data from CISA KEV.  

The synthesis of these frameworks into a single, transparent score is a core feature. A vulnerability's priority is not just about its severity but is a function of its severity, confirmed exploitation, and potential impact. The RiskScore can be conceptualized with a formula such as:

```bash
RiskScore=(Wcvss​×CVSSScore​)+(Wkev​×KEVFlag​)+(Wattack​×ATTACKImpact​)
```

Where:

- Wcvss​, Wkev​, and Wattack​ are the weights assigned to each factor.

- CVSSScore​ is the numerical CVSS base score.

- KEVFlag​ is a large constant if the CVE is in the KEV catalog, and 0 otherwise.

- ATTACKImpact​ is a score assigned based on the mapped ATT&CK tactic's impact.

The LLM's role in this process is to gather and structure the inputs for this algorithm. The final calculation is performed by deterministic Python code, making the prioritization logic transparent, auditable, and testable.

## 5.0 Data Management & Integration

### 5.1 External Data Sources

The agent relies on several external threat intelligence and vulnerability data sources. The management of this data is critical for performance, reliability, and accuracy. A hybrid approach of live API calls for dynamic data and local caching for static data is required.

- FR-5.1.1: Local Framework Storage: The application MUST download and store data from relatively static frameworks—specifically CISA KEV, MITRE ATT&CK, and CWE—into a local frameworks/ directory. This strategy minimizes external API calls during runtime, improves performance, allows for offline analysis capabilities, and reduces dependency on the availability of external services.

- FR-5.1.2: Data Update Strategy: The application MUST include a mechanism to refresh the locally stored data to prevent the intelligence from becoming stale. This can be implemented as a dedicated CLI command (e.g., agent --update-data) or an automatic check that triggers a download if the local files are older than a predefined threshold (e.g., 24 hours for KEV, 90 days for ATT&CK).

The following table centralizes all external data dependencies, defining the acquisition method, format, and update strategy for each.

| Data Source  | Format          | Acquisition Method | URL / Endpoint                                                                        | Local Path (frameworks/) | Update Strategy   |
| ------------ | --------------- | ------------------ | ------------------------------------------------------------------------------------- | ------------------------ | ----------------- |
| NVD          | JSON            | Live API Call      | `https://services.nvd.nist.gov/rest/json/cves/2.0`                                    | N/A                      | Real-time per run |
| CISA KEV     | JSON            | Download           | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | cisa_kev.json            | Daily             |
| MITRE ATT&CK | STIX 2.1 (JSON) | Download           | `https://github.com/mitre/cti/raw/master/enterprise-attack/enterprise-attack.json`    | enterprise-attack.json   | Quarterly         |
| CWE          | XML             | Download (ZIP)     | `https://cwe.mitre.org/data/xml/cwec_v4.14.xml.zip`                                   | cwe_database.xml         | Annually          |

### 5.2 Internal Data Models (Pydantic)

To ensure type safety, data validation, and clear data contracts throughout the application, the system MUST use Pydantic models to represent all key data entities. This is especially important for structuring the data passed to and from the Pydantic AI agent's tools.  

- FR-5.2.1: Structured Data Handling: Pydantic models will serve as the canonical data structures for the entire analysis pipeline. This approach prevents common data-related bugs and makes the codebase easier to understand and debug.

- FR-5.2.2: Core Models: At a minimum, the following Pydantic models shall be defined in the application's source code:

  - Component: Represents a single software component from the SBOM. Fields will include name: str, version: str, purl: Optional[str], and cpe: Optional[str].

  - Vulnerability: Represents a single CVE record retrieved from NVD. Fields will include cve_id: str, description: str, cvss_score: float, and weaknesses: List[str].

  - EnrichedVulnerability: A composite model that represents a fully analyzed vulnerability. It will contain a Vulnerability object along with its associated enrichment data: is_in_kev: bool, kev_details: Optional[dict], attack_mappings: List[dict], and defensive_measures: dict.

  - AnalysisReport: The top-level model that structures the final report. It will contain analysis metadata (e.g., timestamp, SBOM file name) and a prioritized list of EnrichedVulnerability objects.

## 6.0 Non-Functional Requirements

### 6.1 Security

- NFR-6.1.1: API Key Management: API keys for external services (Gemini, NVD) MUST NOT be hardcoded into the source code. They must be loaded securely from environment variables. The application will use the python-dotenv library to automatically load these variables from a .env file in the project's root directory. A .env.example file MUST be provided in the repository to serve as a template for users.

- NFR-6.1.2: Data Handling: The application must handle the download and storage of threat intelligence data securely. While the data itself is public, mechanisms to verify file integrity (e.g., checksum validation if provided by the source) should be considered for future enhancements.

## 6.2 Performance

- NFR-6.2.1: Analysis Time: For a typical SBOM containing up to 100 components, the end-to-end analysis should complete within a reasonable timeframe, targeted at under 5 minutes. This performance is subject to the latency of external API calls. Caching strategies for NVD API results could be implemented in future versions to improve performance for repeated analyses of the same components.

- NFR-6.2.2: Resource Usage: As a command-line utility, the application should be lightweight and have a minimal memory and CPU footprint during operation, consistent with tools in its class.

### 6.3 Usability

- NFR-6.3.1: CLI Clarity: The command-line interface, including its commands, arguments, and help text, must be clear, concise, and intuitive for a technical user audience.

- NFR-6.3.2: Report Readability: The final Markdown report must be well-structured and highly readable. It should make effective use of Markdown features such as tables for summary data, code blocks for detection rules, and hyperlinks for references to CVEs and other external resources.

### 6.4 Maintainability & Coding Style

- NFR-6.4.1: Indentation: All Python source code MUST use 2 spaces for indentation for consistency and readability.

- NFR-6.4.2: Linting: All Markdown files produced by or included in the project, including the final report and the README.md, MUST be able to pass a standard markdownlint test to ensure high-quality, consistent formatting.

- NFR-6.4.3: Modularity: The codebase must be organized into logical modules with a clear separation of concerns. Distinct modules should exist for data acquisition (data_manager.py), core analysis logic (agent.py, tools.py), data modeling (models.py), and the CLI entry point (main.py).

## 7.0 Project Deliverables & Setup

### 7.1 Project Directory Structure

- FR-7.1.1: The project repository MUST adhere to a standard and intuitive Python project structure to facilitate development, packaging, and maintenance.

```bash
\ cyber-threat-agent
|--.env.example
|--.gitignore
|-- README.md
|-- pyproject.toml
|-- frameworks/
| |--.gitkeep
|-- src/
| |-- cti_agent/
| | |-- init.py
| | |-- main.py         # CLI entry point and Pydantic AI to_cli() call
| | |-- agent.py        # Pydantic AI agent definition and orchestration
| | |-- tools.py        # Implementations of the agent's tools
| | |-- models.py       # Internal Pydantic data models
| | |-- data_manager.py # Logic for downloading and loading framework data
|-- tests/
|-- (Unit and integration tests)
```

### 7.2 README.md Content Requirements

- FR-7.2.1: The README.md file is the primary entry point for new users and contributors and MUST contain the following sections:

  - Project Title and Description: A clear title and a concise paragraph explaining what the agent does.

  - Features: A bulleted list of the agent's key capabilities.

  - Prerequisites: A list of required software, such as Python 3.10+ and uv.

  - Installation: Step-by-step instructions on how to set up a virtual environment and install the project dependencies using uv.

  - Configuration: Clear instructions on how to create a .env file from the .env.example template and where to obtain the necessary API keys.

  - Usage: Command-line examples demonstrating how to run the agent with an SBOM file and how to update the local threat intelligence data.

  - Project Directory Structure: A visual representation of the project's folder structure.

  - Data Sources: An explanation of the external data frameworks used (NVD, KEV, ATT&CK, CWE) and their role in the analysis.

### 7.3.env.example Specification

- FR-7.3.1: A .env.example file MUST be included in the root of the repository to provide a clear template for users to configure their environment variables. It must contain the following content:

```toml
# Google Gemini API Key for LLM-powered analysis and contextualization
GEMINI_API_KEY="YOUR_GEMINI_API_KEY"

# NVD API Key for vulnerability lookups. Optional but highly recommended for higher rate limits.
# Obtain a key from: https://nvd.nist.gov/developers/request-an-api-key
NVD_API_KEY="YOUR_NVD_API_KEY"
```

### 7.4 Dependency Management with uv

- FR-7.4.1: The project MUST exclusively use uv for virtual environment creation and dependency management. uv is chosen for its high performance and modern approach to Python packaging, combining the functionalities of tools like pip and virtualenv into a single, fast binary.

- FR-7.4.2: All project dependencies MUST be declared in the [project.dependencies] section of the pyproject.toml file, in accordance with modern Python packaging standards.

- FR-7.4.3: The README.md file will provide users with the specific uv commands required for a complete setup, such as uv venv to create the environment and uv pip install. to install the project and its dependencies.

## 8.0 Assumptions and Out of Scope

### 8.1 Assumptions

- The user of the agent has a stable internet connection required for making live API calls and downloading framework data.

- The user is capable of obtaining the necessary API keys for the Google Gemini and NVD services.

- All input SBOM files are well-formed and valid according to the CycloneDX specification.

### 8.2 Out of Scope for Version 1.0

To ensure a focused and achievable initial release, the following features and capabilities are explicitly out of scope for version 1.0:

- Graphical User Interface (GUI): This is a CLI-first and CLI-only tool.

- Automated Remediation: The agent will provide intelligence and recommendations but will not perform any automated actions such as patching vulnerabilities or modifying code.

- Real-time Application Monitoring: The agent operates on static SBOM files and does not monitor running applications or infrastructure.

- Support for Other SBOM Formats: Initial support is limited to CycloneDX. Support for other formats like SPDX may be considered in future releases.

- Integrated Search for Defensive Measures: The find_defensive_measures tool will rely on the LLM's intrinsic knowledge for v1.0. Future versions may integrate a tool that actively searches public repositories or threat intelligence feeds.

- Persistent Storage: The agent is stateless. Each analysis run is independent, and results are not stored in a persistent database for historical tracking or trend analysis.
