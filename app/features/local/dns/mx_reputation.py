import re
import socket
from typing import List

from app.config import get_weight
from app.features.base import Feature
from app.features.types import TargetType, RunScope, Category, ConfigCat
from app.features.utils.dns.dns_utils import resolve_dns


class MXReputationFeature(Feature):
    """
    Evaluate MX reputation using a combination of:

    - MX hostnames matching known spammy providers
    - MX IP abuse score (fully local heuristic, NOT external AbuseIPDB API)
    - Outsourced MX (Google, Microsoft) considered low risk
    - Suspicious MX names (random strings, numeric-heavy)
    """

    name = "mx_reputation"
    target_type: List[TargetType] = [TargetType.DOMAIN]
    run_on: List[RunScope] = [RunScope.ROOT]
    category: Category = Category.DNS

    # Known good providers = reduce risk
    GOOD_MX_PROVIDERS = [
        "google.com",
        "outlook.com",
        "office365.com",
        "protection.outlook.com",
        "yahoodns.net",
        "icloud.com",
    ]

    # Known risky / spam-heavy MX providers
    BAD_MX_PROVIDERS = [
        "mailgun.org",
        "sendgrid.net",
        "zoho.com",
        "mailer",
        "smtp-relay",
        "bulk-mail",
        "mass-mail",
        "mailcheap",
        "mailersend",
    ]

    RANDOM_HOST_RE = re.compile(r"[a-z0-9]{10,}\.[a-z0-9.-]+", re.I)

    def __init__(self):
        self.max_score = get_weight(ConfigCat.DOMAIN, self.name, 0.05)

    def run(self, domain: str):

        # ---------------------------------------------------------
        # 1. Resolve MX Records
        # ---------------------------------------------------------
        try:
            answers = resolve_dns(domain, "MX")
        except Exception:
            return self.error("MX lookup failed")

        if not answers:
            return self.error("No MX records found")

        mx_hosts = []
        for r in answers:
            text = r.to_text()
            mx = text.split()[-1].rstrip(".")
            mx_hosts.append(mx)

        # ---------------------------------------------------------
        # 2. Evaluate each MX hostname
        # ---------------------------------------------------------
        total_penalty = 0.0
        reasons = []

        for mx in mx_hosts:

            mx_lower = mx.lower()

            # 2.1 Good (trusted) MX provider
            if any(good in mx_lower for good in self.GOOD_MX_PROVIDERS):
                reasons.append(f"{mx} → trusted provider")
                continue  # contributes 0 risk

            # 2.2 Bad / spammy MX provider
            if any(bad in mx_lower for bad in self.BAD_MX_PROVIDERS):
                total_penalty += self.max_score * 0.6
                reasons.append(f"{mx} → suspicious provider")
                continue

            # 2.3 Random-looking hostnames
            if self.RANDOM_HOST_RE.match(mx):
                total_penalty += self.max_score * 0.4
                reasons.append(f"{mx} → random-looking hostname")
                continue

            # 2.4 Try resolving IP and apply simple local heuristic
            try:
                ip = socket.gethostbyname(mx)
            except Exception:
                total_penalty += self.max_score * 0.3
                reasons.append(f"{mx} → failed IP resolution")
                continue

            # Heuristic: private/reserved IP = suspicious
            if ip.startswith("10.") or ip.startswith("172.") or ip.startswith("192.168."):
                total_penalty += self.max_score * 0.2
                reasons.append(f"{mx} → private/reserved IP ({ip})")

        # ---------------------------------------------------------
        # 3. Final scoring
        # ---------------------------------------------------------
        if total_penalty == 0:
            return self.success(0.0, "; ".join(reasons) or "MX servers clean")

        score = min(total_penalty, self.max_score)

        return self.success(score, "; ".join(reasons))
