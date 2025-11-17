import re
from typing import List

from app.config import get_weight
from app.features.base import Feature
from app.features.types import TargetType, RunScope, Category, ConfigCat
from app.features.utils.dns.dns_utils import resolve_dns


class DNSAuthAlignment(Feature):
    """
    Check SPF / DKIM / DMARC alignment with the From: domain.

    Outputs:
        - DMARC policy (none/quarantine/reject)
        - SPF domain alignment
        - DKIM domain alignment (if selector resolved)
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

    def run(self, domain: str):
        # ---------------------------------------------------------
        # 1. DMARC Lookup
        # ---------------------------------------------------------
        try:
            dmarc_txt = resolve_dns(f"_dmarc.{domain}", "TXT")
            dmarc_string = " ".join(x.to_text().strip('"') for x in dmarc_txt)
        except Exception as e:
            dmarc_string = None

        if not dmarc_string:
            return self.error("DMARC missing → no authentication policy")

        m = self.DMARC_RE.search(dmarc_string)
        if not m:
            return self.error("DMARC record found but no 'p=' policy")

        policy = m.group(1).lower()

        if policy == "none":
            return self.error("DMARC policy = none → no protection")
        elif policy == "quarantine":
            dmarc_penalty = 0.2
        elif policy == "reject":
            dmarc_penalty = 0.0  # safest

        # ---------------------------------------------------------
        # 2. SPF Lookup
        # ---------------------------------------------------------
        try:
            txt_records = resolve_dns(domain, "TXT")
            txt_strings = [x.to_text().strip('"') for x in txt_records]
        except Exception:
            return self.error("SPF lookup failed")

        spf_record = next((t for t in txt_strings if t.startswith("v=spf1")), None)

        if not spf_record:
            return self.error("SPF missing")

        includes = self.SPF_INCLUDE_RE.findall(spf_record)
        aligned_spf = domain in spf_record or any(domain in inc for inc in includes)

        if not aligned_spf:
            return self.error(f"SPF not aligned with domain ({spf_record})")

        # ---------------------------------------------------------
        # 3. DKIM lookup (optional)
        # ---------------------------------------------------------
        # We cannot guess selector without headers → skip silently
        # DKIM alignment assumed OK unless explicit misalignment is known.
        dkim_align_reason = "DKIM alignment assumed (selector unknown)"

        # ---------------------------------------------------------
        # 4. SUCCESS → low risk
        # ---------------------------------------------------------
        return self.success(
            0.0, f"DMARC={policy}, SPF aligned, DKIM={dkim_align_reason}"
        )
