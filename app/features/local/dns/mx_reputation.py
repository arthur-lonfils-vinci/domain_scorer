import re
import socket
from typing import List

from app.config import get_weight
from app.features.base import Feature
from app.features.types import TargetType, RunScope, Category, ConfigCat
from app.features.utils.dns.dns_utils import resolve_dns


class MXReputationFeature(Feature):
    """
    Evaluate MX reputation using local heuristics:
    - Trusted providers → low risk
    - Known spammy providers → high risk
    - Random-looking hostnames (common in phishing infra)
    - Private/reserved MX IPs → suspicious
    """

    name = "mx_reputation"
    target_type: List[TargetType] = [TargetType.DOMAIN]
    run_on: List[RunScope] = [RunScope.ROOT]
    category: Category = Category.DNS

    GOOD_MX_PROVIDERS = [
        "google.com",
        "outlook.com",
        "office365.com",
        "protection.outlook.com",
        "yahoodns.net",
        "icloud.com",
    ]

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

    def __init__(self):
        self.max_score = get_weight(ConfigCat.DOMAIN, self.name, 0.05)

    # ---------------------------------------------------------
    # Helper: suspicious random hostname
    # ---------------------------------------------------------
    def _is_random_host(self, mx: str) -> bool:
        label = mx.split(".")[0]

        # Too short to be random
        if len(label) < 10:
            return False

        # Avoid matching legitimate words
        vowels = sum(1 for c in label if c in "aeiou")
        if vowels == 0 and label.isalnum():
            return True  # full consonant strings → often bot-generated

        # High digit/hex ratio
        digit_ratio = sum(c.isdigit() for c in label) / len(label)
        if digit_ratio > 0.6:
            return True

        hex_chars = sum(c in "0123456789abcdef" for c in label.lower())
        if hex_chars / len(label) > 0.8:
            return True

        return False

    # ---------------------------------------------------------

    def _is_suffix(self, mx: str, root: str) -> bool:
        """Return True if mx is exactly root or ends with .root"""
        return mx == root or mx.endswith("." + root)

    # ---------------------------------------------------------

    def run(self, domain: str, context: dict):
        # 1. Resolve MX records
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

        # 2. Evaluate
        total_penalty = 0.0
        reasons = []

        for mx in mx_hosts:
            mx_lower = mx.lower()

            # Trusted provider
            if any(self._is_suffix(mx_lower, g) for g in self.GOOD_MX_PROVIDERS):
                reasons.append(f"{mx} → trusted provider")
                continue

            # Suspicious provider
            if any(bad in mx_lower for bad in self.BAD_MX_PROVIDERS):
                total_penalty += self.max_score * 0.6
                reasons.append(f"{mx} → suspicious provider")
                continue

            # Random-looking MX
            if self._is_random_host(mx_lower):
                total_penalty += self.max_score * 0.4
                reasons.append(f"{mx} → random-looking hostname")
                continue

            # Resolve IP for heuristic analysis
            try:
                ip = socket.gethostbyname(mx)
            except Exception:
                total_penalty += self.max_score * 0.3
                reasons.append(f"{mx} → failed IP resolution")
                continue

            if ip.startswith(("10.", "192.168.", "172.")):
                total_penalty += self.max_score * 0.2
                reasons.append(f"{mx} → private/reserved IP ({ip})")

        # 3. Final scoring
        if total_penalty == 0:
            return self.success(0.0, "; ".join(reasons) or "MX servers clean")

        score = min(total_penalty, self.max_score)
        return self.success(score, "; ".join(reasons))
