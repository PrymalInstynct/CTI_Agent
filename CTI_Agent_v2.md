# Product Requirements Document: Cyber Threat Intelligence Agent - v2.0 Database Integration

  Version: 2.0

  Date: July 19, 2025

  Status: DRAFT

## 1.0 Product Vision & Overview (v2.0 Extension)

### 1.1 Vision Statement (Extended)

To evolve the AI-driven command-line utility into a comprehensive threat intelligence platform that not only rapidly assesses the security posture of software applications but also persists and leverages historical SBOM data for deeper analysis, trend identification, and enhanced AI-driven insights. By storing ingested SBOMs, the agent will enable long-term security posture management and provide a rich dataset for future advanced AI capabilities.

### 1.2 Project Goals & Objectives (v2.0 Specific)

Building upon the v1.0 objectives, v2.0 aims to:

- Enable Persistent SBOM Storage: Allow users to store all processed SBOMs for future reference, re-analysis, and historical tracking.
- Facilitate Historical Analysis: Lay the groundwork for analyzing changes in SBOMs over time and identifying evolving vulnerability trends.
- Provide Data Foundation for Advanced AI: Create a structured, queryable dataset of SBOMs that can be leveraged by future AI agent enhancements for pattern recognition, predictive analysis, and more nuanced contextualization.
- Simplify Local Deployment: Provide a straightforward method for local database deployment using Docker.

## 2.0 User Personas and Stories (v2.0 Specific)

### 2.1 Primary Persona: "Alex," the DevSecOps Engineer (v2.0 Needs)

Alex now also needs to:

- Track the security posture of applications over time.
- Easily re-run analysis on previously submitted SBOMs without re-uploading.
- Provide historical context to development teams regarding dependency changes and vulnerability remediation efforts.

### 2.2 User Stories (v2.0 Specific)

- US-08: SBOM Persistence: "As Alex, I want the agent to automatically store each processed SBOM in a local database, so I can reference it later and track changes over time."
- US-09: Historical SBOM Retrieval: "As Alex, I want to be able to list and retrieve previously analyzed SBOMs from the database, so I can re-run analysis or review past reports."
- US-10: Local Database Setup: "As Alex, I want clear instructions and a simple command to set up the required database locally using Docker, so I can quickly get started with the persistence feature."

## 3.0 Functional Requirements: Core Features (v2.0)

### 3.1 Database Integration (MongoDB via Docker)

- FR-3.1.1: Database Choice: The agent MUST integrate with MongoDB as its primary data store for SBOMs.
- FR-3.1.2: Local Deployment: The project MUST provide clear instructions and configuration for deploying a local MongoDB instance using Docker.
  - The MongoDB instance MUST be accessible from the Python application.
  - The Docker setup MUST include persistent storage for the database data.
- FR-3.1.3: Connection Management: The Python application MUST establish a connection to the MongoDB instance using connection details provided via environment variables (.env file).
- FR-3.1.4: SBOM Ingestion: After successfully parsing an SBOM (FR-3.2.2), the agent MUST store the raw SBOM content (JSON or XML) as a document in a designated MongoDB collection.
  - Each stored SBOM document MUST include metadata such as:
    - filename (original filename of the SBOM)
    - timestamp (datetime of ingestion)
    - sbom_format (e.g., "json", "xml")
    - raw_content (the full raw SBOM content as a string or dictionary)
    - components_count (number of components identified in the SBOM)
- FR-3.1.5: SBOM Retrieval (Future): While not fully implemented in v2.0, the architecture MUST support future capabilities to:
  - List all stored SBOMs.
  - Retrieve a specific SBOM by ID or filename.

### 3.2 Data Model (MongoDB Document Structure)

The primary document structure for SBOMs in MongoDB will be as follows:

    1 {
    2   "_id": ObjectId("..."), // MongoDB's unique identifier
    3   "filename": "my_application_sbom.json",
    4   "timestamp": ISODate("2025-07-19T10:30:00Z"),
    5   "sbom_format": "json",
    6   "components_count": 123,
    7   "raw_content": {
    8     // The full parsed CycloneDX SBOM content as a dictionary/JSON object
    9     "bomFormat": "CycloneDX",
   10     "specVersion": "1.4",
   11     "serialNumber": "urn:uuid:...",
   12     "version": 1,
   13     "components": [
   14       // ... component details ...
   15     ]
   16   }
   17 }

## 4.0 Non-Functional Requirements (v2.0)

### 4.1 Security

- NFR-4.1.1: Database Credentials: MongoDB connection details (host, port, username, password if applicable) MUST be loaded securely from environment variables.
- NFR-4.1.2: Data Isolation: The Docker setup for MongoDB should ensure that the database data is isolated and persistent across container restarts.

### 4.2 Performance

- NFR-4.2.1: Ingestion Speed: Storing an SBOM in the database should not significantly impact the overall analysis time (target: < 500ms per SBOM ingestion).

### 4.3 Usability

- NFR-4.3.1: Docker Setup Simplicity: The instructions for setting up MongoDB via Docker MUST be clear, concise, and require minimal manual steps.

## 5.0 Project Deliverables & Setup (v2.0 Updates)

### 5.1 Project Directory Structure (v2.0 Additions)

No major changes to the src directory structure, but new files will be added.

### 5.2 README.md Content Requirements (v2.0 Updates)

The README.md file MUST be updated to include:

- A new section on "Database Setup (v2.0)" detailing the Docker commands for MongoDB.
- Instructions on configuring the new MongoDB environment variables in .env.

### 5.3 .env.example Specification (v2.0 Updates)

The .env.example file MUST be updated to include the following:

   1 # MongoDB Connection Details for SBOM Persistence (v2.0)
   2 MONGO_DB_HOST="localhost"
   3 MONGO_DB_PORT="27017"
   4 MONGO_DB_NAME="cti_agent_db"
   5 # MONGO_DB_USERNAME="your_username" # Uncomment and set if using authentication
   6 # MONGO_DB_PASSWORD="your_password" # Uncomment and set if using authentication

### 5.4 Dependency Management with uv (v2.0 Updates)

- The pyproject.toml file MUST be updated to include pymongo as a dependency.
