from typing import List

import requests
from app.features.base import Feature
from app.config import VIRUSTOTAL_API_KEY, REQUEST_TIMEOUT, get_weight
from app.cache import get_cache, set_cache
from app.features.types import TargetType, RunScope, Category, ConfigCat


class VirusTotalFeature(Feature):
    name = "vendor_vt"
    target_type: List[TargetType] = [TargetType.DOMAIN]
    run_on: List[RunScope] = [RunScope.ROOT]
    category: Category = Category.VENDORS

    def __init__(self):
        self.max_score = get_weight(ConfigCat.VENDORS, self.name, 0.4)

    # ---------------------------------------------------------

    def run(self, target: str, context: dict):
        # Prefer the real root domain extracted by analyzers
        domain = context.get("root", target)

        cache_key = f"vt:{domain}"
        if cached := get_cache(cache_key):
            return cached

        if not VIRUSTOTAL_API_KEY:
            result = self.disabled("virustotal - No API key provided")
            set_cache(cache_key, result)
            return result

        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}

        try:
            resp = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)

            # --- Handle errors -----------------------------------
            if resp.status_code == 404:
                result = self.disabled("virustotal - Domain not found")
                set_cache(cache_key, result)
                return result

            if resp.status_code == 429:
                result = self.disabled("virustotal - Rate limit exceeded")
                set_cache(cache_key, result)
                return result

            if resp.status_code != 200:
                # Real errors count as suspicious
                result = self.error(f"VT HTTP {resp.status_code}")
                set_cache(cache_key, result)
                return result

            # --- Parse --------------------------------------------
            json_data = resp.json()

            stats = json_data.get("data", {}) \
                             .get("attributes", {}) \
                             .get("last_analysis_stats", {})

            if not stats:
                # VT reachable but returns no results → usually domain unknown
                result = self.success(0.0, "No VirusTotal stats available")
                set_cache(cache_key, result)
                return result

            total = sum(stats.values()) or 1
            malicious_ratio = stats.get("malicious", 0) / total

            score = round(malicious_ratio * self.max_score, 3)

            result = self.success(score, f"Stats={stats}")
            set_cache(cache_key, result)
            return result

        except Exception as e:  # noqa: BLE001
            result = self.disabled(f"VT error: {e}")
            set_cache(cache_key, result)
            return result
