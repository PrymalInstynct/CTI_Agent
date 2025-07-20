# Cyber Threat Intelligence Agent

A command-line tool for comprehensive threat intelligence analysis of software applications.

## Features

- **Automated SBOM Analysis**: Parses CycloneDX SBOMs (JSON/XML) to identify all software components.
- **AI-Powered Vulnerability Enrichment**: Leverages the Gemini 2.5 Flash model to:
  - Dynamically construct accurate Common Platform Enumeration (CPE) strings for components.
  - Map vulnerabilities to MITRE ATT&CK® tactics and techniques to understand adversary behavior.
  - Identify the underlying software weaknesses by linking to the Common Weakness Enumeration (CWE™).
  - Find and provide actionable defensive measures, including Sigma, Snort, and Yara rules.
- **Real-World Threat Correlation**: Flags vulnerabilities present in the CISA Known Exploited Vulnerabilities (KEV) catalog, highlighting immediate threats.
- **Intelligent Risk Prioritization**: Moves beyond simple CVSS scores by using a multi-factor algorithm to prioritize vulnerabilities based on severity, real-world exploitation, and potential impact.
- **Persistent Analysis**: Stores every analyzed SBOM in a local MongoDB database for historical tracking and future analysis.

## Prerequisites

- Python 3.10+
- uv
- Docker (for MongoDB)

## Installation

1. Clone the repository:

    ```bash
    git clone https://github.com/your-username/cyber-threat-agent.git
    cd cyber-threat-agent
    ```

2. Create a virtual environment and install dependencies:

    ```bash
    uv venv
    uv pip install -e . # or `pip install -e .`
    ```

## Configuration

1. Create a `.env` file from the example:

    ```bash
    cp .env.example .env
    ```

2. Obtain the necessary API keys and update the `.env` file:
    - `GEMINI_API_KEY`: Your Google Gemini API key.
    - `NVD_API_KEY`: Your NVD API key (from [NVD API Key Request](https://nvd.nist.gov/developers/request-an-api-key)). This is highly recommended to avoid rate limiting and ensure reliable vulnerability lookups.

## Database Setup (MongoDB)

1. Start a local MongoDB instance using Docker Compose:

    ```bash
    docker-compose up -d
    ```

2. Update the `.env` file with your MongoDB connection details if they differ from the defaults.

## Usage

- Analyze an SBOM:

    ```bash
    cti-agent --sbom-file <path-to-your-sbom.json>
    ```

- Update local threat intelligence data:

    ```bash
    cti-agent --update-data
    ```

## Report Output

The agent generates a comprehensive Markdown report directly to standard output. This report includes:

- An Executive Summary with key metrics.
- A Prioritized Vulnerabilities table, ordered by the calculated `RiskScore`.
- Detailed analysis for each high-priority vulnerability, including:
  - CVE ID, CVSS score, and CISA KEV status.
  - CWE and MITRE ATT&CK mappings.
  - Actionable defensive measures (Sigma, Snort, Yara rules).

You can redirect the output to a file for easy viewing and sharing:

```bash
cti-agent --sbom-file <path-to-your-sbom.json> > analysis_report.md
```

## Error Handling

The agent provides clear and user-friendly error messages for common issues, such as:

- Invalid or non-existent SBOM file paths.
- Missing or invalid API keys.
- Malformed SBOM files.
- External API errors (e.g., rate limiting).

## Intelligent Prioritization

This agent goes beyond standard CVSS-based scoring. It employs a multi-factor risk algorithm to provide a more realistic and actionable priority list. The `RiskScore` for each vulnerability is calculated based on:

- **Severity (CVSS)**: The baseline severity score.
- **Exploitation Status (CISA KEV)**: A high-impact factor that heavily weights vulnerabilities known to be actively exploited in the wild.
- **Threat Context (ATT&CK)**: The potential impact of an exploit, derived from its mapping to MITRE ATT&CK tactics.

This approach ensures that your team focuses on the vulnerabilities that pose the most significant and immediate threat to your organization.

## Testing

The project includes a suite of unit and integration tests to ensure code quality and correctness.

### Running All Tests

To run all tests, use the following command:

```bash
uv run python3 -m unittest discover tests
```

### Running Unit Tests

To run the unit tests for a specific module, use the following commands:

- **Agent Tests:**

    ```bash
    uv run python3 -m unittest tests/test_agent.py
    ```

- **Data Manager Tests:**

    ```bash
    uv run python3 -m unittest tests/test_data_manager.py
    ```

- **Tools Tests:**

    ```bash
    uv run python3 -m unittest tests/test_tools.py
    ```

### Running Integration Tests

To run the end-to-end integration tests, use the following command:

```bash
python3 -m unittest tests/test_integration.py
```

## Project Directory Structure

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
| | |-- __init__.py
| | |-- main.py
| | |-- agent.py
| | |-- tools.py
| | |-- models.py
| | |-- data_manager.py
|-- tests/
```

## Data Sources

- [National Vulnerability Database (NVD)](https://nvd.nist.gov/)
- [CISA Known Exploited Vulnerabilities (KEV) Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [MITRE ATT&CK®](https://attack.mitre.org/)
- [Common Weakness Enumeration (CWE™)](https://cwe.mitre.org/)
