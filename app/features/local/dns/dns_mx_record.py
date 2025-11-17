import dns

from app.config import get_weight
from app.features.base import Feature
from app.features.utils.dns.dns_utils import resolve_dns, is_nxdomain_error


class DNSMXRecordFeature(Feature):
    name = "dns_mx_record"
    target_type = "domain"
    run_on = "root"

    def __init__(self):
        self.max_score = get_weight("domain", self.name, 0.05)

    def run(self, domain: str):
        try:
            answers = resolve_dns(domain, "MX")
            count = len(answers)
            score = self.max_score if count == 0 else 0.0
            return self.success(score, f"DNS MX Record: {count}")
        except Exception as e:  # noqa: BLE001
            if is_nxdomain_error(e):
                return self.error("No DNS found")
            return self.disabled(f"DNS MX error: {e}")
