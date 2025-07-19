# Cyber Threat Intelligence Agent

A command-line tool for comprehensive threat intelligence analysis of software applications.

## Features

- Automated vulnerability discovery from CycloneDX SBOMs.
- AI-driven CPE generation and vulnerability contextualization.
- Correlation with CISA KEV, MITRE ATT&CK, and CWE.
- Prioritized reporting and actionable defensive measures.
- SBOM persistence in a local MongoDB database.

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
