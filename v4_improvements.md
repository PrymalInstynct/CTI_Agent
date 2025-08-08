# CTI-Agent Improvement Plan: Tasks for AI Code Assistant

This document outlines the tasks required to refactor the cti-agent application. The goal is to move from a probabilistic autonomous agent to a deterministic, structured workflow to improve the accuracy and consistency of identifying Snort, Sigma, and Yara rules from Software Bill of Materials (SBOMs).
Task 1: Transition from Autonomous Agent to a Structured Workflow

Objective: Replace the single, large agent prompt with a multi-step, deterministic process for analyzing SBOMs.

    Sub-task 1.1: Implement a Dedicated SBOM Parser for Entity Extraction.

        Location: Create a new file src/cti_agent/sbom_parser.py.

        Action:

            Define a Pydantic model, SbomEntities, in src/cti_agent/models.py to hold structured data like packages, cpes, and cves.

            In sbom_parser.py, create a function extract_entities_from_sbom(sbom_content: str) -> SbomEntities.

            This function should take the raw SBOM content (JSON or XML) and parse it to identify all component names, versions, CPEs, and any explicitly mentioned CVEs.

            Use a focused LLM call with a specific prompt only for this extraction task to ensure high accuracy. The prompt should instruct the model to return a JSON object matching the SbomEntities model.

    Sub-task 1.2: Create a Deterministic Query Generation Function.

        Location: src/cti_agent/sbom_parser.py.

        Action:

            Create a function generate_search_queries(entities: SbomEntities) -> list[str].

            This function will take the SbomEntities object and programmatically generate a list of precise search queries.

            Examples:

                For each package: f"{package_name} vulnerability", f"exploit for {package_name} {version}".

                For each CVE: f"{cve_id}".

                For each CPE: f"{cpe_string}".

            Ensure the function de-duplicates queries to avoid redundant searches.

    Sub-task 1.3: Refactor the Main Agent Logic in agent.py.

        Location: src/cti_agent/agent.py.

        Action:

            Modify the run method in the CTIAgent class.

            Remove the existing single-prompt, tool-using agent logic.

            Implement the new four-step workflow:

                Call sbom_parser.extract_entities_from_sbom() with the input SBOM.

                Pass the resulting entities to sbom_parser.generate_search_queries().

                Iterate through the generated list of queries, calling the search_vector_store tool for each one.

                Aggregate all the search results into a single, comprehensive context string.

    Sub-task 1.4: Update the Final Prompt for Synthesis.

        Location: src/cti_agent/agent.py.

        Action:

            Create a new, simpler prompt for the final LLM call.

            This prompt's primary role is to synthesize and format a report. It should take the aggregated search results (the context) and the original SBOM as input.

            Example Prompt: "Based on the following security intelligence context and the provided SBOM, generate a comprehensive threat intelligence report. List all relevant Snort, Sigma, and Yara rules that apply to the components and vulnerabilities identified. Context: {context}\n\nSBOM: {sbom_content}"

Task 2: Enhance Data Ingestion with Chunking and Metadata

Objective: Improve the quality of documents in the vector store by breaking them into smaller chunks and enriching them with structured metadata for better searchability.

    Sub-task 2.1: Implement Rule-Specific Metadata Parsers.

        Location: src/cti_agent/data_manager.py.

        Action:

            Create helper functions to parse metadata from rule files:

                parse_yara_metadata(content: str) -> dict: Use regex or simple string matching to extract the rule_name, and fields from the meta section like description, author, hash, and cve.

                parse_sigma_metadata(content: str) -> dict: Use the PyYAML library to parse the rule and extract title, id, status, description, and tags.

                parse_snort_metadata(content: str) -> dict: Use regex to parse the rule header and extract msg, sid, rev, and any cve or reference fields.

    Sub-task 2.2: Integrate Text Chunking into the Data Loading Process.

        Location: src/cti_agent/data_manager.py.

        Action:

            In the load_rules_from_directory function, add the langchain.text_splitter.RecursiveCharacterTextSplitter.

            After reading a rule file's content, use the text splitter to divide it into smaller, overlapping chunks (e.g., chunk_size=1000, chunk_overlap=150).

    Sub-task 2.3: Add Rich Metadata to Each Document Chunk.

        Location: src/cti_agent/data_manager.py.

        Action:

            Within the load_rules_from_directory function, as you process each rule file:

                Call the appropriate metadata parser (from sub-task 2.1) on the full content of the rule file once.

                When you create the Document object for each chunk of that rule, add the extracted metadata to it.

                The final metadata for each document should include source, rule_type, and the specific fields like rule_name, cve, sid, etc.

Task 3: Optimize Vector Search and LLM Configuration

Objective: Improve the retrieval process to get more diverse and relevant results, and configure the LLM for more deterministic output.

    Sub-task 3.1: Switch to Max Marginal Relevance (MMR) Search.

        Location: src/cti_agent/tools.py.

        Action:

            In the search_vector_store function, change the retrieval method from the default similarity search to max_marginal_relevance_search.

    Sub-task 3.2: Adjust Search Parameters.

        Location: src/cti_agent/tools.py.

        Action:

            Update the call to max_marginal_relevance_search with new parameters:

                Set k=15 to retrieve more documents for the final context.

                Set fetch_k=50 to give the MMR algorithm a larger pool of documents to select from, improving diversity.

    Sub-task 3.3: Configure LLM for Deterministic Output.

        Location: src/cti_agent/agent.py.

        Action:

            When initializing the ChatGoogleGenerativeAI model for the final report synthesis step, explicitly set temperature=0. This will make the LLM's output highly consistent and based more directly on the provided context.
