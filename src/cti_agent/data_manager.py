"""Manages the download and storage of external threat intelligence data."""
import os
import zipfile
from io import BytesIO
import requests

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
