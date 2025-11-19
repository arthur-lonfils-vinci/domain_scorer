import socket
from typing import List

from app.config import get_weight
from app.features.base import Feature
from app.features.types import TargetType, RunScope, Category, ConfigCat
from app.features.utils.dns.dns_utils import resolve_dns, is_nxdomain_error


class EmailSpoofingFeature(Feature):
    """
    Basic spoofing likelihood indicator.

    Signals:
    - Domain has NO MX → extremely common in spoofing attempts
    - Domain does not resolve → spoofing or abandoned domain
    """

    name = "email_spoofing"
    target_type: List[TargetType] = [TargetType.EMAIL]
    run_on: List[RunScope] = [RunScope.ROOT]
    category = Category.EMAIL

    def __init__(self):
        self.max_score = get_weight(ConfigCat.EMAIL, self.name, 0.3)

    def run(self, target: str, context: dict):
        domain = context.get("domain")
        if not domain:
            return self.disabled("Missing domain in context")

        reasons = []
        score = 0.0

        # ----------------------------------------------------
        # 1) MX presence (strongest spoofing indicator)
        # ----------------------------------------------------
        try:
            mx = resolve_dns(domain, "MX")
            if len(mx) == 0:
                reasons.append("Domain has NO MX (likely spoofing)")
                score += 0.7 * self.max_score
        except Exception as e:
            if is_nxdomain_error(e):
                return self.error("No DNS found → spoofing or fake domain")
            return self.disabled(f"MX lookup failed: {e}")

        # ----------------------------------------------------
        # 2) Domain resolves to IP?
        # ----------------------------------------------------
        try:
            socket.gethostbyname(domain)
        except Exception:
            reasons.append("Domain does not resolve to any IP")
            score += 0.5 * self.max_score

        # ----------------------------------------------------
        # If any indicators → suspicious
        # ----------------------------------------------------
        if score > 0:
            final_score = min(score, self.max_score)
            return self.success(final_score, "; ".join(reasons))

        return self.success(0.0, "No spoofing indicators detected")
