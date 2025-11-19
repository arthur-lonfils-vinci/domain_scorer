from typing import List

import tldextract

from app.config import get_weight
from app.features.base import Feature
from app.features.types import TargetType, RunScope, Category, ConfigCat

SUSPICIOUS_PSEUDO_TLDS = {
    "uk.com", "us.com", "eu.com", "gb.net",
    "in.net", "cn.com", "sa.com",
}

HIGH_RISK_TLDS = {
    "tk", "ml", "ga", "cf", "gq",      # Freenom TLDs
    "zip", "mov",                      # Recent Google abuse spike
    "quest", "click", "xyz",           # Historically abused
}


class TLDRiskFeature(Feature):
    name = "dns_tld_risk"
    target_type: List[TargetType] = [TargetType.DOMAIN]
    run_on: List[RunScope] = [RunScope.ROOT]
    category: Category = Category.DNS

    def __init__(self):
        self.max_score = get_weight(ConfigCat.DOMAIN, self.name, 0.2)

    def run(self, target: str, context: dict):
        root = context.get("root", target)

        ext = tldextract.extract(root)
        suffix = ext.suffix.lower() if ext.suffix else ""

        if not suffix:
            return self.success(self.max_score * 0.5, "No valid TLD detected")

        # Risk #1 – High-abuse TLDs (.tk, .ml, .zip, .xyz...)
        if suffix in HIGH_RISK_TLDS:
            return self.success(self.max_score, f"High-risk TLD: .{suffix}")

        # Risk #2 – “Pseudo-TLDs” (uk.com / eu.com etc.)
        if suffix in SUSPICIOUS_PSEUDO_TLDS:
            return self.success(self.max_score * 0.7, f"Suspicious pseudo-TLD: .{suffix}")

        # Normal case
        return self.success(0.0, f"Normal TLD: .{suffix}")
