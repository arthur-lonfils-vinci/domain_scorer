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

    def run(self, domain: str):
        endpoint = "https://checkurl.phishtank.com/checkurl/"
        try:
            resp = requests.post(endpoint, data={"url": domain, "format": "json"})
            if resp.status_code != 200:
                if resp.status_code == 403:
                    return self.disabled("PhishTank - Authorization Required")
                return self.error(f"PhishTank HTTP {resp.status_code}")

            data = resp.json()
            if data.get("results", {}).get("valid", False):
                return self.success(self.max_score, "Listed in PhishTank")

            return self.success(0.0, "Not in listed PhishTank")

        except Exception as e:  # noqa: BLE001
            return self.disabled(f"PhishTank error: {e}")
