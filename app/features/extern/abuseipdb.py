import socket
from typing import List
import requests
from app.features.base import Feature
from app.config import ABUSEIPDB_API_KEY, REQUEST_TIMEOUT, get_weight
from app.features.types import TargetType, RunScope, Category, ConfigCat


class AbuseIPDBFeature(Feature):
    name = "vendor_abuseipdb"
    target_type: List[TargetType] = [TargetType.DOMAIN]
    run_on: List[RunScope] = [RunScope.ROOT]
    category: Category = Category.VENDORS

    def __init__(self):
        self.max_score = get_weight(ConfigCat.VENDORS, self.name, 0.1)

    def run(self, target: str, context: dict):
        if not ABUSEIPDB_API_KEY:
            return self.disabled("abuseipdb - No API key provided")

        try:
            ips = socket.gethostbyname_ex(target)[2]
        except Exception:
            return self.disabled("abuseipdb - Domain not found")

        score = 0.0
        reasons = []
        for ip in ips:
            try:
                resp = requests.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    headers={
                        "Key": ABUSEIPDB_API_KEY,
                        "Accept": "application/json",
                    },
                    params={"ipAddress": ip, "maxAgeInDays": 90},
                    timeout=REQUEST_TIMEOUT,
                )
                if resp.status_code != 200:
                    reasons.append(f"AbuseIPDB {ip}: HTTP {resp.status_code}")
                    continue
                data = resp.json().get("data", {})
                abuse_conf = data.get("abuseConfidenceScore", 0)
                score = max(score, abuse_conf / 100 * self.max_score)
                reasons.append(f"AbuseIPDB {ip}: AbuseScore={abuse_conf}")
            except Exception as e:  # noqa: BLE001
                return self.disabled(f"AbuseIPDB {ip}: error {e}")

        return self.success(score, "; ".join(reasons))
