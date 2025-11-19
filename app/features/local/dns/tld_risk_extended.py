from typing import List
import tldextract

from app.config import get_weight
from app.features.base import Feature
from app.features.types import TargetType, RunScope, Category, ConfigCat


class TLDRiskExtendedFeature(Feature):
    """
    Extended TLD risk scoring based on:
    - high-abuse ccTLDs
    - high-risk new gTLDs
    - cheap/promo TLDs commonly used by phishing kits
    - suspicious multi-label suffixes (like .zip.com)
    """

    name = "tld_risk_extended"
    target_type: List[TargetType] = [TargetType.DOMAIN]
    run_on: List[RunScope] = [RunScope.ROOT]
    category = Category.DNS

    # ------------------------------------------------------------------
    # High-abuse TLDs (source: Spamhaus / Phishtank / internal research)
    # ------------------------------------------------------------------
    ABUSED_CCTLDS = {
        "tk", "ml", "ga", "cf", "gq",            # Freenom legacy
        "cm",                                     # common typo for .com
        "su",                                     # historical malware distribution
    }

    # ------------------------------------------------------------------
    # High-risk new gTLDs used heavily in phishing waves
    # ------------------------------------------------------------------
    HIGH_RISK_GTLD = {
        "zip", "mov", "lol", "cam", "click", "xyz",
        "support", "help", "account", "download",
        "review", "country", "work",
    }

    # ------------------------------------------------------------------
    # Cheap “promo” TLDs that appear in phishing kits
    # ------------------------------------------------------------------
    CHEAP_MASS_REG_TLDS = {
        "shop", "online", "live", "top", "info", "site", "fun",
        "buzz", "monster", "cyou", "icu", "press"
    }

    # ------------------------------------------------------------------

    def __init__(self):
        self.max_score = get_weight(ConfigCat.DOMAIN, self.name, 0.2)

    # ------------------------------------------------------------------

    def run(self, domain: str, context: dict = None):
        ext = tldextract.extract(domain)
        tld = ext.suffix.lower()

        if not tld:
            return self.error(f"Invalid TLD for {domain}")

        # Risk scoring
        score = 0.0
        reasons = []

        # Single-label TLD (e.g., "zip")
        parts = tld.split(".")

        # If second-level pseudo-zone (e.g. "zip.com"), score higher
        if len(parts) > 1:
            reasons.append(f"Multi-label TLD ({tld}) → often used for deception")
            score += 0.05

        tld_base = parts[-1]

        # --------------------------
        # 1) High-abuse ccTLDs
        # --------------------------
        if tld_base in self.ABUSED_CCTLDS:
            score += 0.15
            reasons.append(f"High-abuse ccTLD: .{tld_base}")

        # --------------------------
        # 2) High-risk new gTLDs
        # --------------------------
        if tld_base in self.HIGH_RISK_GTLD:
            score += 0.10
            reasons.append(f"High-risk gTLD: .{tld_base}")

        # --------------------------
        # 3) Cheap/promo TLDs
        # --------------------------
        if tld_base in self.CHEAP_MASS_REG_TLDS:
            score += 0.05
            reasons.append(f"Cheap / mass-registration TLD: .{tld_base}")

        # Final normalize
        score = min(score, self.max_score)

        if reasons:
            return self.success(score, "; ".join(reasons))

        return self.success(0.0, f"TLD {tld} appears normal")
