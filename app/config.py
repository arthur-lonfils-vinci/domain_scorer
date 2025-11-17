import os
from dotenv import load_dotenv
import yaml
from pathlib import Path

CONFIG_FILE = Path(__file__).parent / "config.yaml"

def load_config():
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    return {}

CONFIG = load_config()

def get_weight(category: str, feature_name: str, default: float = 0.0):
    """Return weight from YAML or fallback to default."""
    return CONFIG.get(category, {}).get(feature_name, default)


# ENV variable
load_dotenv()

# External vendor API Keys
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY", "")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")

# General Settings
REQUEST_TIMEOUT = float(os.getenv("REQUEST_TIMEOUT", "0.4"))
CACHE_DIR = os.getenv("CACHE_DIR", ".cache")
