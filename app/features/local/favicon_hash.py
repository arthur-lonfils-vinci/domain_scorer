import hashlib
import requests
from app.features.base import Feature
from app.config import REQUEST_TIMEOUT


class FaviconHashFeature(Feature):
    name = "favicon_hash"
    max_score = 0.05
    target_type = "domain"

    def run(self, domain: str):
        try:
            resp = requests.get(f"https://{domain}/favicon.ico", timeout=REQUEST_TIMEOUT)
            if resp.status_code != 200:
                return {"score": self.max_score, "reason": "favicon missing"}
            h = hashlib.md5(resp.content).hexdigest()
            return {"score": 0.0, "reason": f"favicon hash={h}"}
        except Exception as e:  # noqa: BLE001
            return {"score": self.error_score(), "reason": f"favicon error: {e}"}
