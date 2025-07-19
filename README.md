# Cyber Threat Intelligence Agent

## Project Title and Description

The Cyber Threat Intelligence Agent is a command-line utility designed to help DevSecOps engineers and security analysts assess the security posture of software applications. By ingesting a standard Software Bill of Materials (SBOM), it automates the correlation of vulnerabilities from multiple sources, providing deep contextualization and a risk-prioritized, actionable remediation plan.

## Features

- **SBOM Analysis:** Parses CycloneDX SBOMs (JSON format) to extract software components.
- **NVD Integration:** Queries the National Vulnerability Database (NVD) for CVE information.
- **CISA KEV Correlation:** Identifies actively exploited vulnerabilities using the CISA Known Exploited Vulnerabilities (KEV) catalog.
- **AI-Driven CPE Identification:** Dynamically constructs CPE strings for components lacking them.
- **Threat Contextualization:** Maps CVEs to MITRE ATT&CK tactics/techniques and Common Weakness Enumerations (CWEs).
- **Defensive Measures:** Suggests relevant detection rules (Sigma, Snort, Yara) for high-priority vulnerabilities.
- **Risk-Based Prioritization:** Prioritizes vulnerabilities based on a multi-factor risk score.
- **Comprehensive Reporting:** Generates a detailed Markdown report with executive summary and actionable insights.

## Prerequisites

- Python 3.10+
- `uv` (for dependency management)

## Installation

1. **Clone the repository:**

    ```bash
    git clone https://github.com/your-repo/cyber-threat-agent.git
    cd cyber-threat-agent
    ```

2. **Create a virtual environment and install dependencies using `uv`:**

    ```bash
    uv venv
    source .venv/bin/activate  # On Windows, use `.venv\Scripts\activate`
    uv pip install .
    ```

## Configuration

Create a `.env` file in the root directory of the project based on the `.env.example` template:

```bash
cp .env.example .env
```

Edit the `.env` file and provide your API keys and MongoDB connection details:

- `GEMINI_API_KEY`: Obtain this from Google AI Studio or Google Cloud.
- `NVD_API_KEY`: Obtain this from the NVD website: [https://nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key)
- `MONGO_DB_HOST`: Hostname for your MongoDB instance (default: `localhost`)
- `MONGO_DB_PORT`: Port for your MongoDB instance (default: `27017`)
- `MONGO_DB_NAME`: Name of the database to use (default: `cti_agent_db`)
- `MONGO_DB_USERNAME`: (Optional) Username if your MongoDB requires authentication.
- `MONGO_DB_PASSWORD`: (Optional) Password if your MongoDB requires authentication.

## Database Setup (v2.0)

This project uses MongoDB for persistent storage of SBOMs. A `docker-compose.yml` file is provided for easy local deployment.

1. **Ensure Docker is running:** Make sure Docker Desktop or Docker Engine is installed and running on your system.

2. **Start the MongoDB container:** From the project root directory, run:

    ```bash
    docker-compose up -d
    ```

    This command will:
    - Download the MongoDB image if not already present.
    - Create and start a MongoDB container named `cti_agent_mongodb`.
    - Map port `27017` (or your specified `MONGO_DB_PORT` from `.env`) to the container.
    - Create a Docker volume (`mongodb_data`) for persistent storage, so your data is not lost if the container is removed or restarted.

3. **Verify MongoDB is running:** You can check the container status with:

    ```bash
    docker ps
    ```

    You should see `cti_agent_mongodb` listed with a `Up` status.

    The application will automatically attempt to connect to this MongoDB instance on startup. If it's not running, it will try to deploy it using `docker-compose up -d`.

## Usage

1. **Activate your virtual environment:**

    ```bash
    source .venv/bin/activate
    ```

2. **Update local threat intelligence data (recommended before first use and periodically):**

    ```bash
    python -m src.cti_agent.data_manager download_framework_data cisa_kev
    python -m src.cti_agent.data_manager download_framework_data mitre_attack
    python -m src.cti_agent.data_manager download_framework_data cwe
    ```

3. **Run the agent with an SBOM file:**

    ```bash
    python -m src.cti_agent.main --sbom-file /path/to/your/sbom.json > analysis_report.md
    ```

    Replace `/path/to/your/sbom.json` with the actual path to your CycloneDX SBOM file.
    The report will be printed to standard output, which you can redirect to a Markdown file.

## Project Directory Structure

```bash
cyber-threat-agent/
├── .env.example
├── .gitignore
├── README.md
├── pyproject.toml
├── frameworks/
│   └── .gitkeep
├── src/
│   └── cti_agent/
│       ├── __init__.py
│       ├── main.py         # CLI entry point and Pydantic AI to_cli() call
│       ├── agent.py        # Pydantic AI agent definition and orchestration
│       ├── tools.py        # Implementations of the agent's tools
│       ├── models.py       # Internal Pydantic data models
│       └── data_manager.py # Logic for downloading and loading framework data
└── tests/
    ├── test_tools.py
    ├── test_data_manager.py
    └── test_integration.py
```

## Data Sources

The agent leverages the following external data sources for comprehensive threat intelligence:

- **National Vulnerability Database (NVD):** Primary source for CVE information.
- **CISA Known Exploited Vulnerabilities (KEV) Catalog:** Identifies vulnerabilities actively exploited in the wild.
- **MITRE ATT&CK Framework:** Provides a knowledge base of adversary tactics and techniques.
- **Common Weakness Enumeration (CWE):** A community-developed list of common software weaknesses.
