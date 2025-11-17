from app.features.base import Feature
from .dns_utils import resolve_dns


class DNSMXRecordFeature(Feature):
    name = "mx_record"
    max_score = 0.05
    target_type = "domain"

    def run(self, domain: str):
        try:
            answers = resolve_dns(domain, "MX")
            count = len(answers)
            score = self.max_score if count == 0 else 0.0
            return {"score": score, "reason": f"MX count={count}"}
        except Exception as e:  # noqa: BLE001
            return {"score": self.error_score(), "reason": f"MX error: {e}"}
