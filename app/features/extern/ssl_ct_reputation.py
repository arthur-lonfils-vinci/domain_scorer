import datetime
import requests
from typing import List, Optional

from app.config import get_weight
from app.cache import get_cache, set_cache
from app.features.base import Feature
from app.features.types import TargetType, RunScope, Category, ConfigCat


CRT_SH_URL = "https://crt.sh/?q={domain}&output=json"


class SSLCTReputationFeature(Feature):
    """
    Evaluate risk based on Certificate Transparency (CT) logs.

    Detects:
    - Certificates created <24h ago (common phishing indicator)
    - Too many certificate issuances (automation abuse)
    - Suspicious issuers on low-volume domains
    """

    name = "ssl_ct_reputation"
    target_type = [TargetType.DOMAIN]
    run_on = [RunScope.ROOT]
    category = Category.VENDORS

    def __init__(self):
        # Value pulled from config.yaml → domain.ssl_ct_reputation
        self.max_score = get_weight(ConfigCat.DOMAIN, self.name, 0.3)

    # -------------------------------------------------------------

    def _fetch_ct_logs(self, domain: str) -> Optional[List[dict]]:
        """Query crt.sh with caching."""
        cache_key = f"ct:{domain}"
        if cached := get_cache(cache_key):
            return cached

        try:
            resp = requests.get(
                CRT_SH_URL.format(domain=domain),
                timeout=6,
                headers={"User-Agent": "domain-scorer/1.0"}
            )

            if resp.status_code != 200:
                return None

            data = resp.json()
            set_cache(cache_key, data)
            return data

        except Exception:
            return None

    # -------------------------------------------------------------

    def _parse_issue_dates(self, entries: List[dict]) -> List[datetime.datetime]:
        """Convert crt.sh 'not_before' strings into datetime objects."""
        dates = []
        for e in entries:
            raw = e.get("not_before")
            if not raw:
                continue

            # Accept both:
            #  - "2025-01-01T12:00:00Z"
            #  - "2025-01-01T12:00:00"
            raw = raw.rstrip("Z")

            try:
                dt = datetime.datetime.strptime(raw, "%Y-%m-%dT%H:%M:%S")
                dates.append(dt)
            except Exception:
                continue

        return dates

    # -------------------------------------------------------------

    def _detect_suspicious_patterns(self, entries: List[dict]):
        if not entries:
            return 0.0, ["No CT entries found — likely new or unused domain"]

        reasons = []
        score = 0.0

        issue_dates = self._parse_issue_dates(entries)
        now = datetime.datetime.utcnow()

        # 1) Recent issuance (the strongest phishing signal)
        if issue_dates:
            latest = max(issue_dates)
            age_h = (now - latest).total_seconds() / 3600

            if age_h < 24:
                score += 0.15
                reasons.append(f"Certificate issued recently ({age_h:.1f} hours ago)")

            if age_h < 3:
                score += 0.2
                reasons.append(f"Very new certificate ({age_h:.1f} hours) — strong phishing indicator")

        # 2) Too many certificates
        if len(issue_dates) > 20:
            score += 0.15
            reasons.append(f"High certificate issuance count ({len(issue_dates)})")

        # 3) Suspicious issuers
        issuers = {e.get("issuer_name", "").lower() for e in entries}
        suspect = [i for i in issuers if "let's encrypt" in i or "zerossl" in i]

        if suspect and len(entries) <= 5:
            score += 0.15
            reasons.append(f"Low-volume certs issued by {', '.join(suspect)}")

        return min(score, self.max_score), reasons

    # -------------------------------------------------------------

    def run(self, root_domain: str, context: dict):
        # Use the correct domain from context when available
        domain = context.get("domain", root_domain)

        ct_entries = self._fetch_ct_logs(domain)
        if ct_entries is None:
            return self.disabled("CT log lookup failed")

        score, reasons = self._detect_suspicious_patterns(ct_entries)

        if reasons:
            return self.success(score, "; ".join(reasons))

        return self.success(0.0, "CT history looks normal")
