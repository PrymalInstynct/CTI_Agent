# TASKS.md

This file tracks the development tasks for the Cyber Threat Intelligence Agent. New tasks discovered during development should be added to the 'Discovered During Work' section.

## Phase 1: Project Setup & Core Infrastructure (Date: 2025-07-07)

- [x] **TASK-01:** Initialize the project structure as defined in `PLANNING.md`.
- [x] **TASK-02:** Create the `pyproject.toml` file and define initial dependencies (`pydantic-ai`, `cyclonedx-python-lib`, `python-dotenv`, `pytest`, `uv`).
- [x] **TASK-03:** Create the `.env.example` file with placeholders for `GEMINI_API_KEY` and `NVD_API_KEY`.
- [x] **TASK-04:** Develop the `data_manager.py` module to download and store CISA KEV, MITRE ATT&CK, and CWE data into the `frameworks/` directory.
- [x] **TASK-05:** Create initial Pydantic models in `models.py` for `Component`, `Vulnerability`, and `AnalysisReport`.

## Phase 2: Core Tooling & Agent Implementation (Date: 2025-07-07)

- [x] **TASK-06:** Implement the `parse_sbom` tool in `tools.py` using `cyclonedx-python-lib`.
- [x] **TASK-07:** Implement the `query_nvd_for_cves` tool in `tools.py` to query the NVD API.
- [x] **TASK-08:** Implement the `correlate_with_cisa_kev` tool in `tools.py` to check against the local KEV JSON file.
- [x] **TASK-09:** Implement the AI-driven `get_cpe_for_component` tool in `tools.py` with robust few-shot prompting.
- [x] **TASK-10:** Implement the AI-driven `map_cve_to_attack` tool in `tools.py`.
- [x] **TASK-11:** Implement the AI-driven `find_defensive_measures` tool in `tools.py`.
- [x] **TASK-12:** Define the main `Agent` in `agent.py`, including the system prompt and tool definitions.

## Phase 3: CLI, Orchestration & Reporting (Date: 2025-07-07)

- [x] **TASK-13:** Implement the CLI entrypoint in `main.py` using `pydantic-ai`'s `to_cli()`.
- [x] **TASK-14:** Implement the main orchestration logic within the `Agent` to manage the analysis workflow.
- [x] **TASK-15:** Implement the `RiskScore` prioritization algorithm.
- [x] **TASK-16:** Implement the final Markdown report generation.

## Phase 4: Testing & Documentation (Date: 2025-07-07)

- [x] **TASK-17:** Write unit tests for all functions in `tools.py`.
- [x] **TASK-18:** Write unit tests for the `data_manager.py`.
- [x] **TASK-19:** Write an integration test for a full analysis run.
- [x] **TASK-20:** Write the `README.md` file with comprehensive setup and usage instructions.

## Phase 5: Database Integration (v2.0) (Date: 2025-07-19)

- [ ] **TASK-21:** Update `pyproject.toml` to include `pymongo` dependency.
- [ ] **TASK-22:** Update `.env.example` with MongoDB connection details (`MONGO_DB_HOST`, `MONGO_DB_PORT`, `MONGO_DB_NAME`, `MONGO_DB_USERNAME`, `MONGO_DB_PASSWORD`).
- [ ] **TASK-23:** Create `docker-compose.yml` for local MongoDB deployment with persistent storage.
- [ ] **TASK-24:** Implement `src/cti_agent/database.py` with `MongoDBManager` class for connection, health checks, and SBOM persistence.
- [ ] **TASK-25:** Integrate database connection and SBOM saving logic into the main application workflow (e.g., `main.py` or `agent.py`).
- [ ] **TASK-26:** Implement database health check and auto-deployment logic using `docker-compose up -d` within `MongoDBManager.connect()`.
- [ ] **TASK-27:** Update `README.md` with instructions for MongoDB setup via Docker and `.env` configuration.
- [ ] **TASK-28:** Write unit tests for `src/cti_agent/database.py` (connection, save_sbom, error handling).
- [ ] **TASK-29:** Update integration tests to ensure SBOMs are correctly persisted after analysis.

## Discovered During Work

- *(No tasks yet)*
