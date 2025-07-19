import requests
import os
import json
import zipfile

FRAMEWORKS_DIR = os.path.join(os.path.dirname(__file__), '..', '..', 'frameworks')
os.makedirs(FRAMEWORKS_DIR, exist_ok=True)

def download_framework_data(framework_name: str):
    """
    Downloads and stores threat intelligence framework data locally.

    Args:
        framework_name (str): The name of the framework to download (e.g., 'cisa_kev', 'mitre_attack', 'cwe').
    """
    if framework_name == "cisa_kev":
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        file_path = os.path.join(FRAMEWORKS_DIR, "cisa_kev.json")
        try:
            response = requests.get(url)
            response.raise_for_status()
            with open(file_path, 'w') as f:
                json.dump(response.json(), f, indent=2)
            print(f"Downloaded CISA KEV data to {file_path}")
        except requests.exceptions.RequestException as e:
            print(f"Error downloading CISA KEV data: {e}")
    elif framework_name == "mitre_attack":
        url = "https://github.com/mitre/cti/raw/master/enterprise-attack/enterprise-attack.json"
        file_path = os.path.join(FRAMEWORKS_DIR, "enterprise-attack.json")
        try:
            response = requests.get(url)
            response.raise_for_status()
            with open(file_path, 'w') as f:
                json.dump(response.json(), f, indent=2)
            print(f"Downloaded MITRE ATT&CK data to {file_path}")
        except requests.exceptions.RequestException as e:
            print(f"Error downloading MITRE ATT&CK data: {e}")
    elif framework_name == "cwe":
        url = "https://cwe.mitre.org/data/xml/cwec_v4.14.xml.zip"
        zip_path = os.path.join(FRAMEWORKS_DIR, "cwec_v4.14.xml.zip")
        extract_path = os.path.join(FRAMEWORKS_DIR, "cwe_database.xml")
        try:
            response = requests.get(url)
            response.raise_for_status()
            with open(zip_path, 'wb') as f:
                f.write(response.content)
            
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                # Assuming the XML file inside the zip is named cwec_v4.14.xml
                # This might need adjustment if the name changes in future versions
                zip_ref.extract("cwec_v4.14.xml", FRAMEWORKS_DIR)
                os.rename(os.path.join(frameworks_dir, "cwec_v4.14.xml"), extract_path)
            os.remove(zip_path) # Clean up the zip file
            print(f"Downloaded and extracted CWE data to {extract_path}")
        except requests.exceptions.RequestException as e:
            print(f"Error downloading CWE data: {e}")
        except zipfile.BadZipFile as e:
            print(f"Error extracting CWE zip file: {e}")
        except FileNotFoundError as e:
            print(f"Error: Expected XML file not found in CWE zip: {e}")
    else:
        print(f"Unknown framework: {framework_name}")
