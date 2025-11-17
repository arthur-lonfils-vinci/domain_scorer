from app.config import get_weight
from app.features.base import Feature
from app.features.utils.dns.dns_utils import resolve_dns, is_nxdomain_error


class DNSSpfDkimFeature(Feature):
    name = "dns_spf_dkim"
    target_type = "domain"
    run_on = "root"

    def __init__(self):
        self.max_score = get_weight("domain", self.name, 0.05)

    def run(self, domain: str):
        try:
            answers = resolve_dns(domain, "TXT")
            txts = [r.to_text() for r in answers]
            spf = any("v=spf1" in t for t in txts)
            dkim = any("v=DKIM1" in t for t in txts)

            # Missing SPF is more suspicious than missing DKIM
            score = self.max_score if not spf else 0.0
            reason = f"SPF={'yes' if spf else 'no'}, DKIM={'yes' if dkim else 'no'}"
            return self.success(score, reason)
        except Exception as e:  # noqa: BLE001
            if is_nxdomain_error(e):
                return self.error("No DNS found")
            return self.disabled(f"DNS SPF/DKIM error: {e}")
