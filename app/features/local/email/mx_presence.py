from app.features.base import Feature
from app.features.utils.dns.dns_utils import resolve_dns

class EmailMXPresenceFeature(Feature):
    name = "email_mx_presence"
    target_type = "email"
    run_on = "root"
    max_score = 0.2       

    def run(self, domain: str):
        try:
            answers = resolve_dns(domain, "MX")
            count = len(answers)
            if count == 0:
                return self.error("Domain has NO MX → possible spoofing")
            return self.success(0.0, f"MX count={count}")
        except Exception as e:
            return self.disabled(f"MX lookup error: {e}")
