import requests
from app.features.base import Feature
from app.config import URLSCAN_API_KEY, REQUEST_TIMEOUT


class URLScanFeature(Feature):
    name = "vendor_urlscan"
    max_score = 0.1
    target_type = "domain"
    run_on = "root"

    def run(self, domain: str):
        if not URLSCAN_API_KEY:
            return self.disabled("URLScan - No API key provided")
        headers = {"API-Key": URLSCAN_API_KEY, "Content-Type": "application/json"}
        try:
            resp = requests.get(
                "https://urlscan.io/api/v1/search/",
                params={"q": f"domain:{domain}"},
                headers=headers,
            )
            if resp.status_code != 200:
                return self.error(f"URLScan HTTP: {resp.status_code}")

            total = resp.json().get("total", 0)
            score = self.max_score if total > 0 else 0.0
            return self.success(score, f"URLScan results={total}")

        except Exception as e:  # noqa: BLE001
            return self.disabled(f"URLScan error: {e}")
