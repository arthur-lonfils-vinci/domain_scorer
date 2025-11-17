import tldextract

from app.config import get_weight
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
    name = "dns_tld_risk"
    target_type = "domain"
    run_on = "root"

    def __init__(self):
        self.max_score = get_weight("domain", self.name, 0.2)

    def run(self, domain: str):
        ext = tldextract.extract(domain)
        full_suffix = ext.suffix.lower()
        if full_suffix in SUSPICIOUS_PSEUDO_TLDS:
            return self.success(self.max_score, "Pseudo-TLD")
        return self.success(0.0, "Normal TLD")
