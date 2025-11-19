from typing import List

from app.config import get_weight
from app.features.base import Feature
from app.features.types import TargetType, RunScope, Category, ConfigCat
from app.features.utils.dns.dns_utils import resolve_dns, is_nxdomain_error


class DNSSpfDkimFeature(Feature):
    name = "dns_spf_dkim"
    target_type: List[TargetType] = [TargetType.DOMAIN]
    run_on: List[RunScope] = [RunScope.ROOT]
    category: Category = Category.DNS

    def __init__(self):
        self.max_score = get_weight(ConfigCat.DOMAIN, self.name, 0.05)

    def run(self, target: str, context: dict):
        """
        Check SPF / DKIM presence.
        Missing SPF = suspicious
        Missing DKIM = low noise (informational)
        """
        domain = context.get("root", target)

        try:
            answers = resolve_dns(domain, "TXT")
            txts = [r.to_text().strip('"') for r in answers]

            spf_present = any(t.lower().startswith("v=spf1") for t in txts)
            dkim_present = any("v=dkim1" in t.lower() for t in txts)

            # SPF missing → suspicious
            score = self.max_score if not spf_present else 0.0

            reason = f"SPF={'yes' if spf_present else 'no'}, DKIM={'yes' if dkim_present else 'no'}"
            return self.success(score, reason)

        except Exception as e:  # noqa: BLE001
            if is_nxdomain_error(e):
                return self.error("Domain does not exist (NXDOMAIN)")
            return self.disabled(f"SPF/DKIM error: {e}")
