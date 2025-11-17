import requests
from app.features.base import Feature
from app.config import URLSCAN_API_KEY, REQUEST_TIMEOUT


class URLScanFeature(Feature):
    name = "vendor_urlscan"
    max_score = 0.1
    target_type = "domain"

    def run(self, domain: str):
        headers = {"API-Key": URLSCAN_API_KEY} if URLSCAN_API_KEY else {}
        try:
            resp = requests.get(
                "https://urlscan.io/api/v1/search/",
                params={"q": f"domain:{domain}"},
                headers=headers,
                timeout=REQUEST_TIMEOUT,
            )
            if resp.status_code != 200:
                return {
                    "score": self.error_score(),
                    "reason": f"URLScan HTTP {resp.status_code}",
                }

            total = resp.json().get("total", 0)
            score = self.max_score if total > 0 else 0.0
            return {"score": score, "reason": f"URLScan results={total}"}

        except Exception as e:  # noqa: BLE001
            return {"score": self.error_score(), "reason": f"URLScan error: {e}"}
