import requests
from app.features.base import Feature
from app.config import VIRUSTOTAL_API_KEY, REQUEST_TIMEOUT
from app.cache import get_cache, set_cache


class VirusTotalFeature(Feature):
    name = "vendor_vt"
    max_score = 0.7
    target_type = "domain"
    run_on = "root"

    def run(self, domain: str):
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
            if resp.status_code != 200:
                result = self.error(f"HTTP {resp.status_code}")
                set_cache(cache_key, result)
                return result

            data = resp.json()["data"]["attributes"]["last_analysis_stats"]
            total = sum(data.values()) or 1
            malicious_ratio = data.get("malicious", 0) / total
            score = round(malicious_ratio * self.max_score, 3)

            result = self.success(score, f"Stats={data}")
            set_cache(cache_key, result)
            set_cache(cache_key, result)
            return result

        except Exception as e:  # noqa: BLE001
            result = self.disabled(f"VT error: {e}")
            set_cache(cache_key, result)
            return result
