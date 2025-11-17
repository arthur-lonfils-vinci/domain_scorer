from app.features.base import Feature
from .dns_utils import resolve_dns


class DNSSpfDkimFeature(Feature):
    name = "spf_dkim"
    max_score = 0.05
    target_type = "domain"

    def run(self, domain: str):
        try:
            answers = resolve_dns(domain, "TXT")
            txts = [r.to_text() for r in answers]
            spf = any("v=spf1" in t for t in txts)
            dkim = any("v=DKIM1" in t for t in txts)

            # Missing SPF is more suspicious than missing DKIM
            score = self.max_score if not spf else 0.0
            reason = f"SPF={'yes' if spf else 'no'}, DKIM={'yes' if dkim else 'no'}"
            return {"score": score, "reason": reason}
        except Exception as e:  # noqa: BLE001
            return {"score": self.error_score(), "reason": f"SPF/DKIM error: {e}"}
