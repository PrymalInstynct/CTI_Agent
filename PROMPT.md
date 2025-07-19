# Prompt History

## Generate Product Requirements Document (PRD) using Gemini 2.5 Pro Deep Research

```markdown
Help me to create a Product Requirements Document (PRD) for the following software application, Ensure that the output of this PRD is provided to me in Markdown syntax: 

# Project: Cyber Threat Intelligence Agent

## Feature

I want to build a Pydantic AI Agent:

- **CLI for User Interaction:** A user-friendly command-line interface that uses command-line arguments to accept SBOM files and initiate the analysis.
- **LLM:** Leverage `Gemini 2.5 Flash` via an API key for the initial development, but allow for other models to be integrated in the future.
- **CycloneDX SBOM Parsing:** The ability to parse and understand software components listed in a CycloneDX SBOM.
- **Multi-Source Vulnerability Correlation:** Integration with the National Vulnerability Database (NVD), CISA's Known Exploited Vulnerabilities (KEV) catalog.
- **AI-Driven CPE Construction:** Dynamically determine CPE 'part' and 'vendor' using the AI Agent for accurate NVD API queries.
- **Threat Contextualization:** Mapping of identified vulnerabilities to the MITRE ATT&CK framework and Common Weakness Enumeration (CWE) for better understanding of attack vectors and weaknesses, using the AI Agent for identification.
- **Defensive Measure Analysis:** Identify any known defensive measures that can be used to mitigate, remediate, or detect the exploitation of the vulnerability.
  - **Detection Rules:** Any detection rules identified should be in Sigma, Snort, or Yara format.
- **AI-Powered Analysis:** Utilization of the Pydantic AI library to orchestrate the analysis process, manage data, and generate insights.
- **Comprehensive Reporting:** Generation of a clear and actionable vulnerability report that provides a prioritized list of vulnerabilites, include the order they should be addressed based on the AI-Powered Analysis, as well as any Defensive Measures discovered during analysis.
- **Human-Readable Report Output:** Ensure the generated report is easily human-readable by using Markdown syntax within the command line, including proper handling of newlines and URL-encoded characters.

## Coding Style

- Use 2 spaces for indentation
- Ensure all Markdown files will pass a markdownlint test

## Documentation References

- [Pydantic AI documentation](https://ai.pydantic.dev/)
- [NVD Documentation](https://nvd.nist.gov/developers/vulnerabilities)
- [CVE Documentation](https://cve.mitre.org/)
- [CISA KEV Documentation](https://www.cisa.gov/known-exploited-vulnerabilities)
- [CycloneDX Documentation](https://cyclonedx.org/)
- [MITRE ATT&CK Framework Documentation](https://attack.mitre.org/)
- [Common Weakness Enumerations Documentation](https://cwe.mitre.org/)
- [CPE 2.3 Scheme Format](https://en.wikipedia.org/wiki/Common_Platform_Enumeration)
- [URL Encoding Reference](https://www.w3schools.com/tags/ref_urlencode.asp)
- [Sigma Documentation](https://sigmahq.io/docs/guide/getting-started.html)
- [Snort Documentation](https://docs.snort.org/start/configuration)
- [Yara Documentation](https://virustotal.github.io/yara-x/docs/intro/getting-started/)

## Other Considerations

- Include a .env.example, README with instructions for setup including how to configure the AI Agent with a Gemini API Key
- Include the project structure in the README.
- Use `uv` for virtual environment management and dependency installation.
- If any of the frameworks (NVD, CISA, MITRE ATT&CK, CWE) provide a JSON or XML structured file of their most current content download it into the `frameworks` directory.
- Use `python-dotenv` and `load_dotenv()` for environment variables (`GEMINI_API_KEY` and `NVD_API_KEY`).
```

### Create PlANNING.md and TASKS.md from PRD

`Based on the Product Requirements Document inside of @GEMINI.md please create a PLANNING.md and TASKS.md file that will support the future creation of the the Cyber Threat Intelligence Agent.`

### Build Project

`Please build the first interation of the Cyber Threat Intelligence Agent, make sure to follow the PRD found in @GEMINI.md, while tracking your progress in @TASKS.md and @PLANNING.md.`
