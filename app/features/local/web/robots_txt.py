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

    # Try HTTPS → HTTP fallback
    def _fetch(self, fqdn: str):
        urls = [
            f"https://{fqdn}/robots.txt",
            f"http://{fqdn}/robots.txt",
        ]
        last_exc = None
        for url in urls:
            try:
                r = requests.get(url, timeout=REQUEST_TIMEOUT)
                return r, None
            except Exception as e:
                last_exc = e
        return None, last_exc

    def run(self, target: str, context: dict):
        fqdn = context.get("fqdn", target)

        resp, error = self._fetch(fqdn)

        # Network failure → do NOT mark as suspicious
        if resp is None:
            return self.disabled(f"robots.txt unreachable ({error})")

        # HTTP OK → file exists → low risk
        if resp.status_code == 200:
            return self.success(0.0, "robots.txt found")

        # robots.txt missing → tiny heuristic signal
        score = self.max_score * 0.3
        return self.success(score, f"robots.txt missing (HTTP {resp.status_code})")
