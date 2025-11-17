import tldextract
from app.features.base import Feature

SUSPICIOUS_PSEUDO_TLDS = {
    "uk.com",
    "us.com",
    "eu.com",
    "gb.net",
    "in.net",
    "cn.com",
    "sa.com",
}


class TLDRiskFeature(Feature):
    name = "tld_risk"
    max_score = 0.2
    target_type = "domain"

    def run(self, domain: str):
        ext = tldextract.extract(domain)
        full_suffix = ext.suffix.lower()
        if full_suffix in SUSPICIOUS_PSEUDO_TLDS:
            return {
                "score": self.max_score,
                "reason": f"Suspicious pseudo-TLD: {full_suffix}",
            }
        return {"score": 0.0, "reason": "TLD normal"}
