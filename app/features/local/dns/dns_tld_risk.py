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
    run_on = "root"

    def run(self, domain: str):
        ext = tldextract.extract(domain)
        full_suffix = ext.suffix.lower()
        if full_suffix in SUSPICIOUS_PSEUDO_TLDS:
            return self.success(self.max_score, "Pseudo-TLD")
        return self.success(0.0, "Normal TLD")
