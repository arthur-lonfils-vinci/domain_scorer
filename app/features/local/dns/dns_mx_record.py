from app.features.base import Feature
from app.features.utils.dns.dns_utils import resolve_dns


class DNSMXRecordFeature(Feature):
    name = "mx_record"
    max_score = 0.05
    target_type = "domain"
    run_on = "root"

    def run(self, domain: str):
        try:
            answers = resolve_dns(domain, "MX")
            count = len(answers)
            score = self.max_score if count == 0 else 0.0
            return self.success(score, f"DNS MX Record: {count}")
        except Exception as e:  # noqa: BLE001
            return self.error(f"DNS MX error: {e}")
