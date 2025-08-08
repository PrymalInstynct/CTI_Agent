"""
This module provides functions for parsing SBOM files and extracting entities.
"""


"""
This module provides functions for parsing SBOM files and extracting entities.
"""
import json
import re
from pydantic_ai import Agent
from .models import SbomEntities

async def extract_entities_from_sbom(sbom_content: str) -> SbomEntities:
    """
    Extracts entities from an SBOM file using a focused LLM call.

    Args:
        sbom_content: The raw content of the SBOM file (JSON or XML).

    Returns:
        An SbomEntities object containing the extracted entities.
    """
    # Use a focused LLM call to extract entities from the SBOM.
    entity_extractor = Agent(model='google-gla:gemini-2.5-flash')
    prompt = f"""Extract all component names and their versions from the following SBOM content. Also extract any explicitly mentioned CPEs and CVEs.
Return the result as a JSON object with the keys 'packages', 'cpes', and 'cves'.
For 'packages', provide a list of objects, each with 'name' and 'version' fields.

SBOM Content:
{sbom_content}
"""
    response = await entity_extractor.run(prompt)
    
    # The response from the LLM is an AgentRunResult object. We need its .output attribute.
    json_string = response.output

    # The LLM might wrap the JSON in markdown code fences. Let's strip them.
    match = re.search(r"```json\n([\s\S]*?)\n```", json_string)
    if match:
        json_string = match.group(1)
    
    # Now parse the cleaned JSON string.
    return SbomEntities.model_validate_json(json_string)

def generate_search_queries(entities: SbomEntities) -> list[str]:
    """
    Generates a list of precise search queries from the extracted SBOM entities.

    Args:
        entities: An SbomEntities object containing the extracted entities.

    Returns:
        A list of search queries.
    """
    queries = set()
    for package in entities.packages:
        queries.add(f"{package} vulnerability")
        queries.add(f"exploit for {package}")
    for cve in entities.cves:
        queries.add(cve)
    for cpe in entities.cpes:
        queries.add(cpe)
    return list(queries)

