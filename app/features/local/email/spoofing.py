import socket

import dns

from app.config import get_weight
from app.features.base import Feature
from app.features.utils.dns.dns_utils import is_nxdomain_error


class EmailSpoofingFeature(Feature):
    name = "email_spoofing"
    target_type = "email"
    run_on = "root"
    max_score = 0.3

    def __init__(self):
        self.max_score = get_weight("email", self.name, 0.3)

    def run(self, domain: str):
        reasons = []
        score = 0

        # MX missing? → suspicious
        try:
            import app.features.utils.dns.dns_utils as dns_utils
            mx = dns_utils.resolve_dns(domain, "MX")
            if len(mx) == 0:
                reasons.append("Domain has NO MX")
                score += 1
        except Exception as e:
            if is_nxdomain_error(e):
                return self.error("No DNS found")
            return self.disabled("DNS MX failed → can't evaluate spoofing")

        # Domain not resolving? → suspicious
        try:
            socket.gethostbyname(domain)
        except Exception:
            reasons.append("Domain does not resolve")
            score += 1

        if score == 0:
            return self.success(0.0, "No spoofing indicators")

        return self.error("; ".join(reasons))
