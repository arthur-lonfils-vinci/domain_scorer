import os
from dotenv import load_dotenv

load_dotenv()

# External vendor API Keys
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY", "")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")

# General Settings
REQUEST_TIMEOUT = float(os.getenv("REQUEST_TIMEOUT", "0.4"))
CACHE_DIR = os.getenv("CACHE_DIR", ".cache")
