# PLANNING.md

## 1.0 Project Goal

To develop a command-line Cyber Threat Intelligence Agent that analyzes a Software Bill of Materials (SBOM), correlates component vulnerabilities against multiple threat intelligence sources, and generates a prioritized, actionable report. The agent will leverage AI for advanced analysis and contextualization.

## 2.0 Architecture & Design

The application will be a Python-based CLI tool, architected for modularity and maintainability. The core logic will be orchestrated by an AI agent built with the `pydantic-ai` library.

### 2.1 Core Components

- **CLI Entrypoint (`src/cti_agent/main.py`):** The user interface of the application. It will be generated directly from the agent's definition using `pydantic-ai`'s `to_cli()` method, ensuring the CLI is always in sync with the agent's capabilities.
- **AI Agent (`src/cti_agent/agent.py`):** The central orchestrator. An instance of `pydantic_ai.Agent` configured with the Gemini 2.5 Flash model. It will manage the workflow by calling a series of specialized tools in a logical sequence to analyze each software component.
- **Tools (`src/cti_agent/tools.py`):** A collection of discrete Python functions, each decorated with `@tool`. These functions will perform the specific, single-responsibility tasks outlined in the PRD, such as parsing the SBOM, querying the NVD, or mapping a CVE to an ATT&CK technique.
- **Data Models (`src/cti_agent/models.py`):** A set of Pydantic models (`Component`, `Vulnerability`, `EnrichedVulnerability`, etc.) that define the data structures used throughout the application. This ensures type safety, validation, and clear data contracts between different parts of the system.
- **Data Manager (`src/cti_agent/data_manager.py`):** A module responsible for managing external threat intelligence data. It will handle the downloading, storing, and refreshing of local copies of the CISA KEV catalog, MITRE ATT&CK framework, and CWE database.

### 2.2 Data Flow

1. The user executes the agent via the CLI, providing the path to a CycloneDX SBOM file.
2. The `main.py` script invokes the AI agent.
3. The agent's first step is to call the `parse_sbom` tool to extract the list of software components.
4. The agent iterates through each component:
    a. If a CPE is missing, it calls the `get_cpe_for_component` tool.
    b. It calls `query_nvd_for_cves` to find vulnerabilities.
    c. For each significant CVE, it calls enrichment tools: `correlate_with_cisa_kev`, `map_cve_to_attack`, and `find_defensive_measures`.
5. After processing all components, the agent aggregates the collected `EnrichedVulnerability` data.
6. It applies the internal `RiskScore` algorithm to prioritize the vulnerabilities.
7. Finally, the agent synthesizes all the information into a single, well-formatted Markdown report, which is printed to standard output.

## 3.0 Key Technologies & Libraries

- **Programming Language:** Python 3.10+
- **AI Agent Framework:** `pydantic-ai`
- **Dependency Management:** `uv`
- **SBOM Parsing:** `cyclonedx-python-lib`
- **Environment Variables:** `python-dotenv`
- **Testing:** `pytest`

## 4.0 Testing Strategy

- Unit tests will be written using the `pytest` framework.
- Tests will be located in the `/tests` directory, mirroring the `src` directory structure.
- The primary focus of unit tests will be on the individual functions in `tools.py` and `data_manager.py` to ensure their correctness in isolation.
- Integration tests will be developed to verify the end-to-end data flow for a sample SBOM.

## 5.0 Style & Conventions

- **Code Formatting:** `black` with 2-space indentation.
- **Linting:** Adherence to PEP8 standards.
- **Docstrings:** Google-style docstrings for all functions and methods.
- **Markdown:** All Markdown files will be linted with `markdownlint`.
