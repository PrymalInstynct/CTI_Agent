# CTI Agent v3.0 Task Checklist

This checklist is generated from the Product Requirements Document (v3.0).

## Phase 1: Core Feature Enhancements

- [x] **EPSS Integration**
  - [x] Add a new function/tool (`query_epss`) to fetch EPSS scores for CVEs from the FIRST.org API.
  - [x] Update the `EnrichedVulnerability` Pydantic model in `src/cti_agent/models.py` to include an `epss_score` field.
  - [x] Modify the `RiskScore` algorithm in `src/cti_agent/agent.py` to incorporate the EPSS score as a weighting factor.
  - [x] Update the detailed vulnerability section of the Markdown report to display the EPSS score.

- [x] **AI-Generated Summaries**
  - [x] Implement a new agent tool (`summarize_findings`) that uses the LLM to generate a 1-2 paragraph executive summary of the analysis results.
  - [x] Update the orchestration logic in `agent.py` to call this tool after all vulnerabilities have been analyzed.
  - [x] Add the generated summary to the top of the Markdown report.

- [x] **File-Based Reporting**
  - [x] Create a `reports/` directory in the project root.
  - [x] Modify the main CLI logic in `src/cti_agent/main.py` to save the Markdown report to a file in the `reports/` directory instead of printing to stdout.
  - [x] Implement a file naming convention (e.g., `report-<sbom_name>-<timestamp>.md`).
  - [x] Ensure the application prints the path to the generated report file upon completion.
  - [x] Ensure hyperlinks to the correct CWE and MITRE ATT&CK TTPs are included in the report.

## Phase 2: Interactive Chatbot Functionality

- [x] **CLI Command for Chat Mode**
  - [x] Add a new CLI command (e.g., `agent chat`) in `src/cti_agent/main.py` to initiate an interactive chat session.

- [x] **Chatbot Agent & Tools**
  - [x] Define a new agent or modify the existing one to handle conversational queries.
  - [x] Implement a tool (`answer_user_query`) that takes a natural language question from the user.
  - [x] Inside the `answer_user_query` tool, implement the logic to:
    - [x] Use the LLM to parse the user's question and determine the query to be performed against the MongoDB database.
    - [x] Execute the query against the stored SBOM data.
    - [x] Use the LLM again to formulate a natural language response based on the query results.

- [x] **Database Query Logic**
  - [x] Enhance the database connection logic in `src/cti_agent/data_manager.py` to support the types of queries needed for the chatbot (e.g., finding components by name, listing vulnerabilities by severity).

## Phase 3: Advanced Querying & De-duplication

- [ ] If there were a need to perform complex, dynamic queries or aggregations across these datasets (e.g., "find all MITRE ATT&CK techniques associated with CVEs that are also in CISA KEV and have a high EPSS score"), MongoDB's querying capabilities would be more powerful than flat file lookups.
- [x] Ensure that the user cannot upload the exact same SBOM with the exact same content more then once to MongoDB.
  - [x] If an attempt is made to upload a duplicate SBOM print that information to standard out along with pull the SBOM out of MongoDB for Cyber Threat Intel Analysis.

## Phase 4: Documentation & Testing

- [ ] **Update Documentation**
  - [ ] Update `README.md` to describe the new EPSS integration, the AI summaries, the file-based reporting, and the new `chat` mode.
  - [ ] Update `CTI_Agent_PRD.md` to reflect the final implementation details of v3.0.

- [ ] **Unit & Integration Testing**
  - [ ] Write unit tests for the `query_epss` tool (mocking the API call).
  - [ ] Write unit tests for the `summarize_findings` tool (mocking the LLM call).
  - [ ] Write unit tests for the `answer_user_query` tool and the database query logic it depends on.
  - [ ] Write integration tests for the end-to-end chatbot functionality.

## Previously Completed (v2.0)

- [x] **Project Scaffolding**
- [x] **Documentation (v2.0)**
- [x] **Initial CLI Setup**
- [x] **Local Data Frameworks**
- [x] **Database Integration**
- [x] **SBOM Parsing**
- [x] **Vulnerability Correlation**
- [x] **AI Agent Definition**
- [x] **AI-Driven Tools (v2.0)**
- [x] **Orchestration & Prioritization (v2.0)**
- [x] **Data Modeling (v2.0)**
- [x] **Report Generation (v2.0)**
- [x] **Error Handling & Usability**
- [x] **Unit & Integration Testing (v2.0)**
- [x] **Code Quality**
