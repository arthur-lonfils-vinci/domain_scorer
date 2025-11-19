from typing import List

import requests
from app.features.base import Feature
from app.config import URLSCAN_API_KEY, REQUEST_TIMEOUT, get_weight
from app.features.types import TargetType, RunScope, Category, ConfigCat
from app.cache import get_cache, set_cache


class URLScanFeature(Feature):
    name = "vendor_urlscan"
    target_type: List[TargetType] = [TargetType.DOMAIN]
    run_on: List[RunScope] = [RunScope.ROOT]
    category: Category = Category.VENDORS

    def __init__(self):
        self.max_score = get_weight(ConfigCat.VENDORS, self.name, 0.1)

    # --------------------------------------------------------------

    def run(self, target: str, context: dict):
        if not URLSCAN_API_KEY:
            return self.disabled("URLScan - No API key provided")

        # Prefer fqdn for URLScan (better matching accuracy)
        domain = context.get("fqdn", target)

        cache_key = f"urlscan:{domain}"
        if cached := get_cache(cache_key):
            return cached

        headers = {
            "API-Key": URLSCAN_API_KEY,
            "Content-Type": "application/json",
            "User-Agent": "domain-scorer/1.0"
        }

        try:
            resp = requests.get(
                "https://urlscan.io/api/v1/search/",
                params={"q": f"domain:{domain}"},
                headers=headers,
                timeout=REQUEST_TIMEOUT
            )

            if resp.status_code == 403:
                return self.disabled("URLScan - Forbidden (API key issue)")

            if resp.status_code != 200:
                return self.error(f"URLScan HTTP {resp.status_code}")

            total = resp.json().get("total", 0)
            score = self.max_score if total > 0 else 0.0

            result = self.success(score, f"URLScan results={total}")
            set_cache(cache_key, result)
            return result

        except Exception as e:  # noqa: BLE001
            return self.disabled(f"URLScan error: {e}")
