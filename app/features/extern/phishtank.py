import requests
from app.features.base import Feature
from app.config import REQUEST_TIMEOUT


class PhishTankFeature(Feature):
    name = "vendor_phishtank"
    max_score = 0.1
    target_type = "domain"

    def run(self, domain: str):
        url = f"http://checkurl.staging.phishtank.com/checkurl//?url={domain}&format=json"
        try:
            resp = requests.get(url, timeout=REQUEST_TIMEOUT)
            if resp.status_code != 200:
                return {
                    "score": self.error_score(),
                    "reason": f"PhishTank HTTP {resp.status_code}",
                }

            data = resp.json()
            if data.get("results", {}).get("valid", False):
                return {"score": self.max_score, "reason": "Listed in PhishTank"}

            return {"score": 0.0, "reason": "Not in PhishTank DB"}

        except Exception as e:  # noqa: BLE001
            return {"score": self.error_score(), "reason": f"PhishTank error: {e}"}
