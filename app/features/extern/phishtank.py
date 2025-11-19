from typing import List
import requests
from app.features.base import Feature
from app.config import get_weight
from app.features.types import TargetType, RunScope, Category, ConfigCat


class PhishTankFeature(Feature):
    name = "vendor_phishtank"
    target_type: List[TargetType] = [TargetType.DOMAIN]
    run_on: List[RunScope] = [RunScope.ROOT]
    category: Category = Category.VENDORS

    def __init__(self):
        self.max_score = get_weight(ConfigCat.VENDORS, self.name, 0.1)

    def run(self, domain: str, context: dict):

        url_to_check = f"http://{domain}/"

        try:
            resp = requests.post(
                "https://checkurl.phishtank.com/checkurl/",
                data={"url": url_to_check, "format": "json"},
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=10
            )

            if resp.status_code == 403:
                return self.disabled("PhishTank - Authorization Required")

            if resp.status_code != 200:
                return self.error(f"PhishTank HTTP {resp.status_code}")

            data = resp.json().get("results", {})

            # Interpretation of PhishTank output:
            in_db = data.get("in_database", False)
            verified = data.get("verified", False)

            if verified:
                return self.success(self.max_score, "Verified phishing (PhishTank)")

            if in_db and not verified:
                return self.success(self.max_score * 0.5, "Listed but unverified in PhishTank")

            return self.success(0.0, "Not listed in PhishTank")

        except Exception as e:  # noqa: BLE001
            return self.disabled(f"PhishTank error: {e}")
