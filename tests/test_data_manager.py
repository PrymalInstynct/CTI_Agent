import pytest
import os
from src.cti_agent.data_manager import download_framework_data, FRAMEWORKS_DIR

@pytest.fixture
def setup_frameworks_dir(tmp_path):
    # Create a temporary frameworks directory for testing
    frameworks_dir = tmp_path / "frameworks"
    frameworks_dir.mkdir()
    # Patch the FRAMEWORKS_DIR in data_manager to point to the temporary directory
    import src.cti_agent.data_manager
    original_frameworks_dir = src.cti_agent.data_manager.FRAMEWORKS_DIR
    src.cti_agent.data_manager.FRAMEWORKS_DIR = str(frameworks_dir)
    yield frameworks_dir
    src.cti_agent.data_manager.FRAMEWORKS_DIR = original_frameworks_dir

def test_download_framework_data_cisa_kev(setup_frameworks_dir):
    download_framework_data("cisa_kev")
    assert os.path.exists(os.path.join(str(setup_frameworks_dir), "cisa_kev.json"))

def test_download_framework_data_mitre_attack(setup_frameworks_dir):
    download_framework_data("mitre_attack")
    assert os.path.exists(os.path.join(FRAMEWORKS_DIR, "enterprise-attack.json"))

def test_download_framework_data_cwe(setup_frameworks_dir):
    download_framework_data("cwe")
    assert os.path.exists(os.path.join(str(setup_frameworks_dir), "cwe_database.xml"))
