# CTI Agent v4.0 Task Checklist

This checklist is generated from the Product Requirements Document (v4.0).

## Phase 1: Core Feature Enhancements (v3.0 - Completed)

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

## Phase 2: Interactive Chatbot Functionality (v3.0 - Completed)

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

## Phase 3: SBOM De-duplication (v3.0 - Completed)

- [x] Ensure that the user cannot upload the exact same SBOM with the exact same content more then once to MongoDB.
  - [x] If an attempt is made to upload a duplicate SBOM print that information to standard out along with pull the SBOM out of MongoDB for Cyber Threat Intel Analysis.

## Phase 4: Documentation & Testing (v3.0 - Completed)

- [x] **Update Documentation**
  - [x] Update `README.md` to describe the new EPSS integration, the AI summaries, the file-based reporting, and the new `chat` mode.
  - [x] Update `CTI_Agent_PRD.md` to reflect the final implementation details of v3.0.

- [x] **Unit & Integration Testing**
  - [x] Write unit tests for the `query_epss` tool (mocking the API call).
  - [x] Write unit tests for the `summarize_findings` tool (mocking the LLM call).
  - [x] Write unit tests for the `answer_user_query` tool and the database query logic it depends on.
  - [x] Write integration tests for the end-to-end chatbot functionality.

## Phase 5: RAG and Enhanced Context (v4.0 - In Progress)

- [x] **Vector Store Setup**
  - [x] Choose a local vector store (e.g., ChromaDB, FAISS, supabase, Pinecone).
  - [x] Implement local deployment instructions for the chosen vector store including it into the existing docker-compose.yml.
  - [x] Integrate vector store connection management into the application.
  - [x] Update `CTI_Agent_PRD_v4.0.md`, `README.md`, & `TASKS.md` with details on the chosen vector store and its integration.

- [x] **NVD Web Scraping & Ingestion**
  - [x] Develop a tool (`scrape_nvd_cve_info`) to scrape detailed CVE information from NVD website.
    - [x] include the capability to follow and scrape the contents of those sites that are found assoicated with the CVE being researched.
      - [x] Never crawl more then 2 hops away from the NVD website.
  - [x] **Scraper Enhancements**
    - [x] Add a `--crawl-depth` command-line argument to control the recursion depth of the web scraper.
    - [x] Implement logic to ignore hyperlinks found in the `<header>` and `<footer>` sections of scraped webpages.
    - [x] Reduce the web request timeout to 3 seconds to avoid long waits.
    - [x] Implement a check to prevent re-scraping and re-ingesting URLs that already exist in the vector store for a given CVE.
  - [x] Implement logic to ingest scraped NVD data into the vector store.
  - [x] Update `EnrichedVulnerability` model to reference vector store for detailed CVE context.
  - [x] Update `CTI_Agent_PRD_v4.0.md`, `README.md`, & `TASKS.md` with details on the web scraping capabiltiy and its integration.

- [x] **Enhanced Defensive Measures**
  - [x] Develop a tool (`search_defensive_measures`) to search the RAG vector store for defensive measures (Sigma, Snort, Yara, Mitigation/Remediation/Patching Instructions).
  - [x] Update `EnrichedVulnerability` model to store comprehensive defensive measures from RAG.
  - [x] Modify report generation to include these enhanced defensive measures.

## Phase 6: Large SBOM Handling & LLM Optimization (v4.0 - Completed)

- [x] **SBOM Chunking/Summarization**
  - [x] Implement logic to chunk large SBOMs to avoid LLM token limits.
  - [ ] Develop strategies for summarizing SBOM components if chunking is insufficient.
  - [x] Update SBOM parsing and analysis orchestration to handle chunked/summarized SBOMs.

- [x] **LLM Integration with RAG**
  - [x] Modify existing LLM calls (e.g., CPE generation, summary generation) to leverage the RAG vector store for improved context.

## Phase 7: Snort, Sigma, Yara

- [x] Leverage the Vector Store and LLM to search the internet and identify and propose any Snort signatures that may be capable of detecting the vulnerability being exploited
  - [x] Ensure any identified signatures are documented within the final report, and if none were found be clear about that in the report
- [x] Leverage the Vector Store and LLM to search the internet and identify and propose any Sigma rules that may be capable of detecting the vulnerability being exploited
  - [x] Ensure any identified rules are documented within the final report, and if none were found be clear about that in the report
- [x] Leverage the Vector Store and LLM to search the internet and  identify and propose any Yara signatures that may be capable of detecting the vulnerability being exploited
  - [x] Ensure any identified signatures are documented within the final report, and if none were found be clear about that in the report

## Phase 8: Documentation & Testing (v4.0 - Ongoing)

- [ ] **Update Documentation**
  - [ ] Update `README.md` with new v4.0 features and vector store setup instructions.
  - [ ] Update `CTI_Agent_PRD_v4.0.md` (already done, but ensure consistency).

- [ ] **Unit & Integration Testing**
  - [ ] Write unit tests for all new v4.0 features (vector store, scraping, enhanced defensive measures, SBOM chunking).
  - [ ] Write integration tests for end-to-end RAG and large SBOM handling workflows.

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
