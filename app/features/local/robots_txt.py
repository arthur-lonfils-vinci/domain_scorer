import requests
from app.features.base import Feature
from app.config import REQUEST_TIMEOUT


class RobotsTxtFeature(Feature):
    name = "robots_txt"
    max_score = 0.05
    target_type = "domain"

    def run(self, domain: str):
        try:
            resp = requests.get(f"https://{domain}/robots.txt", timeout=REQUEST_TIMEOUT)
            score = self.max_score if resp.status_code != 200 else 0.0
            reason = "robots.txt missing" if score else "robots.txt found"
            return {"score": score, "reason": reason}
        except Exception as e:  # noqa: BLE001
            return {"score": self.error_score(), "reason": f"robots error: {e}"}
