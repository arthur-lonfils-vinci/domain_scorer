import re
from typing import List

from app.config import get_weight
from app.cache import get_cache, set_cache
from app.features.base import Feature
from app.features.types import TargetType, RunScope, Category, ConfigCat
from app.features.utils.dns.dns_utils import resolve_dns, is_nxdomain_error


class DNSAuthAlignment(Feature):
    """
    Check SPF / DKIM / DMARC alignment with the From: domain.

    Outputs:
        - DMARC policy (none / quarantine / reject)
        - SPF domain alignment
        - DKIM assumed aligned unless misalignment detected
    """

    name = "dns_auth_alignment"
    target_type: List[TargetType] = [TargetType.EMAIL, TargetType.DOMAIN]
    run_on: List[RunScope] = [RunScope.ROOT]
    category: Category = Category.DNS

    DMARC_RE = re.compile(r"p=(none|quarantine|reject)", re.I)
    SPF_INCLUDE_RE = re.compile(r"include:([a-zA-Z0-9.-]+)")
    DKIM_SELECTOR_RE = re.compile(r"v=DKIM1;.*?s=([^;]+);.*?d=([^;]+)", re.I)

    def __init__(self):
        self.max_score = get_weight(ConfigCat.DOMAIN, self.name, 0.05)

    # ------------------------------------------------------------------

    def run(self, target: str, context: dict):
        root = context.get("root", target)
        cache_key = f"auth:{root}"

        # Cached result
        if cached := get_cache(cache_key):
            return cached

        # ==========================================================
        # 1) DMARC Lookup
        # ==========================================================
        try:
            dmarc_txt = resolve_dns(f"_dmarc.{root}", "TXT")
            dmarc_string = " ".join(r.to_text().strip('"') for r in dmarc_txt)
        except Exception as e:
            if is_nxdomain_error(e):
                result = self.error("DMARC missing → no authentication policy")
                set_cache(cache_key, result)
                return result
            result = self.disabled(f"DMARC lookup error: {e}")
            set_cache(cache_key, result)
            return result

        match = self.DMARC_RE.search(dmarc_string)
        if not match:
            result = self.error("DMARC record found but policy ('p=') missing")
            set_cache(cache_key, result)
            return result

        policy = match.group(1).lower()

        if policy == "none":
            result = self.error("DMARC policy = none → no protection")
            set_cache(cache_key, result)
            return result

        # Mild penalty for quarantine (but NOT total failure)
        if policy == "quarantine":
            dmarc_penalty = 0.2
        else:  # reject
            dmarc_penalty = 0.0

        # ==========================================================
        # 2) SPF Lookup
        # ==========================================================
        try:
            txt_records = resolve_dns(root, "TXT")
            txt_strings = [r.to_text().strip('"') for r in txt_records]
        except Exception as e:
            if is_nxdomain_error(e):
                result = self.error("SPF missing")
                set_cache(cache_key, result)
                return result
            result = self.disabled(f"SPF lookup error: {e}")
            set_cache(cache_key, result)
            return result

        spf_record = next((t for t in txt_strings if t.startswith("v=spf1")), None)
        if not spf_record:
            result = self.error("SPF missing")
            set_cache(cache_key, result)
            return result

        includes = self.SPF_INCLUDE_RE.findall(spf_record)
        aligned_spf = (
            root in spf_record or
            any(root in inc for inc in includes)
        )

        if not aligned_spf:
            result = self.error(f"SPF not aligned with domain ({spf_record})")
            set_cache(cache_key, result)
            return result

        # ==========================================================
        # 3) DKIM (Optional, only if incoming email headers provided)
        # ==========================================================
        # Without headers, DKIM alignment cannot be determined.
        dkim_reason = "DKIM alignment assumed (selector unknown)"

        # ==========================================================
        # 4) SUCCESS
        # ==========================================================
        reason = (
            f"DMARC={policy}, "
            f"SPF aligned, "
            f"DKIM={dkim_reason}"
        )

        # Return low score since proper alignment = low risk
        result = self.success(dmarc_penalty, reason)
        set_cache(cache_key, result)
        return result
