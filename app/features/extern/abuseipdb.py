import socket
import requests
from app.features.base import Feature
from app.config import ABUSEIPDB_API_KEY, REQUEST_TIMEOUT


class AbuseIPDBFeature(Feature):
    name = "vendor_abuseipdb"
    max_score = 0.1
    target_type = "domain"

    def run(self, domain: str):
        if not ABUSEIPDB_API_KEY:
            return {"score": 0.0, "reason": "AbuseIPDB disabled (no API key)"}

        try:
            ips = socket.gethostbyname_ex(domain)[2]
        except Exception:  # noqa: BLE001
            return {
                "score": self.error_score(),
                "reason": "AbuseIPDB: cannot resolve domain",
            }

        max_score = 0.0
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
                    reasons.append(f"{ip}: HTTP {resp.status_code}")
                    continue
                data = resp.json().get("data", {})
                abuse_conf = data.get("abuseConfidenceScore", 0)
                max_score = max(max_score, abuse_conf / 100 * self.max_score)
                reasons.append(f"{ip}: AbuseScore={abuse_conf}")
            except Exception as e:  # noqa: BLE001
                reasons.append(f"{ip}: error {e}")

        return {"score": round(max_score, 3), "reason": "; ".join(reasons)}
