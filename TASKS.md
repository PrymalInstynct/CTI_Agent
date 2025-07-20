# CTI Agent v2.0 Task Checklist

This checklist is generated from the Product Requirements Document (v2.0).

## Phase 1: Project Setup & Foundation

- [x] **Project Scaffolding**
  - [x] Initialize project structure (`src/cti_agent`, `frameworks`, `tests`).
  - [x] Create `pyproject.toml` with project metadata and dependencies (`pydantic`, `pydantic-ai`, `cyclonedx-python-lib`, `pymongo`, `python-dotenv`, `uv`).
  - [x] Create `.gitignore` file.
- [x] **Documentation**
  - [x] Create `README.md` and populate all sections as per FR-7.2.1.
  - [x] Create `.env.example` with fields for `GEMINI_API_KEY`, `NVD_API_KEY`, and MongoDB connection details as per FR-7.3.1.
- [x] **Initial CLI Setup**
  - [x] Implement the basic CLI entry point in `src/cti_agent/main.py` using Pydantic AI's `to_cli()`.
  - [x] Add `--help` and `--version` flags.

## Phase 2: Data Integration & Management

- [x] **Local Data Frameworks**
  - [x] Create `src/cti_agent/data_manager.py`.
  - [x] Implement function to download and store the CISA KEV JSON feed.
  - [x] Implement function to download and store the MITRE ATT&CK STIX JSON.
  - [x] Implement function to download and unpack the CWE XML data.
  - [x] Create a CLI command (`--update-data`) to trigger the refresh of all local data.
- [x] **Database Integration**
  - [x] Add `pymongo` to `pyproject.toml`.
  - [x] Implement MongoDB connection logic, configured via environment variables.
  - [x] Add instructions to `README.md` for setting up a local MongoDB instance with Docker.
  - [x] Define the MongoDB document structure for SBOMs in `src/cti_agent/models.py` as per FR-3.7.

## Phase 3: Core SBOM Analysis Logic

- [x] **SBOM Parsing**
  - [x] Implement the `parse_sbom` agent tool in `src/cti_agent/tools.py`.
  - [x] Ensure the tool handles both JSON and XML CycloneDX formats.
  - [x] Define the internal `Component` Pydantic model in `src/cti_agent/models.py`.
  - [x] Implement logic to store the parsed SBOM in MongoDB.
- [x] **Vulnerability Correlation**
  - [x] Implement the `query_nvd_for_cves` agent tool, using a component's CPE.
    - [x] Handle NVD API rate limiting with exponential backoff.
    - [x] Ensure the tool uses the `NVD_API_KEY` from environment variables.
  - [x] Implement the `correlate_with_cisa_kev` agent tool, checking against the local KEV data.

## Phase 4: AI-Powered Enrichment & Analysis

- [x] **AI Agent Definition**
  - [x] Create `src/cti_agent/agent.py` and define the main Pydantic AI Agent.
  - [x] Implement the master system prompt as defined in FR-4.1.3.
  - [x] Configure the agent to use the specified Gemini model `gemini-2.5-flash`.
- [x] **AI-Driven Tools**
  - [x] Implement the `get_cpe_for_component` tool with robust few-shot prompting.
  - [x] Implement the `map_cve_to_attack` tool to link CVEs to MITRE ATT&CK techniques.
  - [x] Implement the `find_defensive_measures` tool to find Sigma, Snort, or Yara rules.
- [x] **Orchestration & Prioritization**
  - [x] Implement the primary orchestration logic in `agent.py` to follow the workflow from FR-4.3.1.
  - [x] Implement the multi-factor `RiskScore` algorithm (FR-4.4) to prioritize vulnerabilities.

## Phase 5: Reporting & Finalization

- [x] **Data Modeling**
  - [x] Define all required Pydantic models (`Vulnerability`, `EnrichedVulnerability`, `AnalysisReport`) in `src/cti_agent/models.py`.
- [x] **Report Generation**
  - [x] Implement the final Markdown report generation logic.
  - [x] Ensure the report structure is hierarchical and matches the specification in FR-3.5.2.
  - [x] Ensure the report correctly flags actively exploited vulnerabilities and includes all enrichment data.
- [x] **Error Handling & Usability**
  - [x] Implement comprehensive error handling for all failure scenarios listed in FR-3.1.4.
  - [x] Review and refine all CLI output for clarity and readability.

## Phase 6: Testing & Quality Assurance

- [x] **Unit Testing**
  - [x] Write unit tests for the `parse_sbom` tool with sample JSON and XML files (using `sbom.json` and `sbom.xml`).
  - [x] Write unit tests for the `data_manager.py` functions.
  - [x] Write unit tests for the `RiskScore` calculation logic.
  - [x] Write unit tests for each of the agent's tools, mocking external APIs and LLM responses.
- [x] **Integration Testing**
  - [x] Write an end-to-end integration test that runs a sample SBOM through the entire analysis pipeline (using `sbom.json` and `sbom.xml`).
- [x] **Code Quality**
  - [x] Set up `markdownlint` and ensure all project Markdown files pass.
  - [x] Enforce 2-space indentation across the Python codebase.
  - [x] Run a final review of the code against all non-functional requirements.

## Phase 7: Feature Enhancements

- [ ] Include [EPSS](https://www.first.org/epss/) in calculation of vulnerability priority
- [ ] Have the LLM create a 1 to 2 paragraph summary of the analysis about the specific vulnerabilites found after all of the SBOM analysis is complete
- [ ] Enable "Chatbot" functionality that will enable to user to quary for vulnerability information based on the SBOM input stored in the MongoDBand have the LLM provide reports and results back
- [ ] Write the Markdown report to a file in a folder rather then directly to standard output

## Discovered During Work

- [x] Migrate the docker implementation of MongoDB to docker-compose.
- Add new sub-tasks or TODOs discovered during development here.
