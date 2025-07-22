"""Manages the download and storage of external threat intelligence data."""
import os
import zipfile
import json
import hashlib
from io import BytesIO
import requests
from pymongo import MongoClient

FRAMEWORKS_DIR = os.path.join(os.path.dirname(__file__), "..", "frameworks")


CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
MITRE_ATTACK_URL = "https://github.com/mitre/cti/raw/master/enterprise-attack/enterprise-attack.json"
CWE_URL = "https://cwe.mitre.org/data/xml/cwec_v4.14.xml.zip"

def download_file(url, path):
    """Downloads a file from a URL to a given path."""
    response = requests.get(url)
    response.raise_for_status()
    with open(path, "wb") as f:
        f.write(response.content)

def download_and_unzip(url, dir_path):
    """Downloads and unzips a file into a directory."""
    response = requests.get(url)
    response.raise_for_status()
    with zipfile.ZipFile(BytesIO(response.content)) as z:
        z.extractall(dir_path)

def update_local_data():
    """Updates all local threat intelligence data."""
    os.makedirs(FRAMEWORKS_DIR, exist_ok=True)
    download_file(CISA_KEV_URL, os.path.join(FRAMEWORKS_DIR, "cisa_kev.json"))
    download_file(MITRE_ATTACK_URL, os.path.join(FRAMEWORKS_DIR, "enterprise-attack.json"))
    download_and_unzip(CWE_URL, FRAMEWORKS_DIR)

def get_db_collection(collection_name="sboms"):
    """Establishes a connection to MongoDB and returns a collection object."""
    client = MongoClient("mongodb://localhost:27017/")
    db = client["cti_agent_db"]
    return db[collection_name]

def load_and_store_sbom(sbom_path):
    """Loads an SBOM, checks for duplicates, and stores it in MongoDB if new."""
    with open(sbom_path, 'r') as f:
        sbom_data = json.load(f)

    # Use a hash of the content to check for duplicates
    sbom_content_str = json.dumps(sbom_data.get("components", []), sort_keys=True)
    sbom_hash = hashlib.sha256(sbom_content_str.encode('utf-8')).hexdigest()

    collection = get_db_collection()
    existing_sbom = collection.find_one({"_id": sbom_hash})

    if existing_sbom:
        print("Duplicate SBOM detected. Using existing data for analysis.")
        return existing_sbom["content"], False
    else:
        collection.insert_one({
            "_id": sbom_hash,
            "content": sbom_data,
            "filename": os.path.basename(sbom_path)
        })
        return sbom_data, True
