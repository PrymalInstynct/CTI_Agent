# v4.0 Features

- [ ] If there were a need to perform complex, dynamic queries or aggregations across these datasets (e.g., "find all MITRE ATT&CK techniques associated with CVEs that are also in CISA KEV and have a high EPSS score"), MongoDB's querying capabilities, or the use of a RAG vector store would be more powerful than flat file lookups.
- [ ] Leverage LLM to scrape NVD for website containing information about CVEs into a RAG vector store in order to provide better query context
- [ ] Leverage LLM to search for Defensive Measures available on the internet for detecting and preventing the exploitation of the CVE's found in the SBOM
  - [ ] Sigma Rules
  - [ ] Snort Rules
  - [ ] Yara Rules
  - [ ] Mitigation/Remediation/Patching Instructions
- [ ] Handle analysis of Large SBOMs that might cause token limits to be reached when running queries via LLM
- [ ] Explore deployment of local vector store for RAG to support LLM analysis
