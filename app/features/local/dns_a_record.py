from app.features.base import Feature
from .dns_utils import resolve_dns


class DNSARecordFeature(Feature):
    name = "dns_a_record"
    max_score = 0.05
    target_type = "domain"

    def run(self, domain: str):
        try:
            answers = resolve_dns(domain, "A")
            count = len(answers)
            score = self.max_score if count <= 1 else 0.0
            return self.success(score, f"DNS A Record: {count}")
        except Exception as e:  # noqa: BLE001
            return self.error(f"DNS A error: {e}")
