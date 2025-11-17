from typing import List

import requests
from app.features.base import Feature
from app.config import REQUEST_TIMEOUT, get_weight
from app.features.types import Category, TargetType, RunScope, ConfigCat


class RobotsTxtFeature(Feature):
    name = "robots_txt"
    target_type: List[TargetType] = [TargetType.WEB]
    run_on: List[RunScope] = [RunScope.FQDN]
    category: Category = Category.WEB

    def __init__(self):
        self.max_score = get_weight(ConfigCat.WEB, self.name, 0.05)

    def run(self, domain: str):
        try:
            resp = requests.get(f"https://{domain}/robots.txt", timeout=REQUEST_TIMEOUT)
            score = self.max_score if resp.status_code != 200 else 0.0
            reason = "robots.txt missing" if score else "robots.txt found"
            return self.success(score, reason)
        except Exception as e:  # noqa: BLE001
            return self.error(f"robots.txt error: {e}")
