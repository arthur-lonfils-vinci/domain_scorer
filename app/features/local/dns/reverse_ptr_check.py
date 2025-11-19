from app.features.base import Feature
from app.features.types import TargetType, RunScope, Category, ConfigCat
from app.config import get_weight
from app.features.utils.dns.dns_utils import (
    resolve_ptr,
    forward_reverse_consistent,
    ptr_suspicious_patterns,
    resolve_a,
)
import tldextract


class ReversePTRCheckFeature(Feature):
    """
    Detect suspicious reverse DNS configurations.

    Checks:
    - Missing PTR
    - PTR → A → PTR mismatch
    - Suspicious PTR naming patterns
    - PTR not referencing the domain root
    """

    name = "reverse_ptr_check"
    target_type = [TargetType.DOMAIN]
    run_on = [RunScope.FQDN]
    category = Category.DNS

    def __init__(self):
        self.max_score = get_weight(ConfigCat.DOMAIN, self.name, 0.25)

    # --------------------------------------------------------------

    def run(self, fqdn: str, context: dict):
        # ----------------------------------------------------------
        # 1) Resolve IP for domain
        # ----------------------------------------------------------
        try:
            a_records = resolve_a(fqdn)
        except Exception as exc:  # noqa: BLE001
            return self.disabled(f"A lookup failed: {exc}")

        if not a_records:
            return self.success(0.0, "No A record → skipping PTR check")

        ip = a_records[0]  # Use first IP only

        # ----------------------------------------------------------
        # 2) PTR lookup
        # ----------------------------------------------------------
        try:
            ptr = resolve_ptr(ip)
        except Exception as exc:  # noqa: BLE001
            ptr = None

        if not ptr:
            return self.error(f"No PTR record for IP {ip}")

        ptr_lower = ptr.lower()
        reasons = []
        score = 0.0

        # ----------------------------------------------------------
        # 3) Forward <-> Reverse coherence
        # ----------------------------------------------------------
        try:
            if not forward_reverse_consistent(ip):
                score += 0.15
                reasons.append("PTR does not resolve back to original IP")
        except Exception:
            # If the check errors, treat as sensor failure, not risk
            reasons.append("Unable to verify A→PTR→A consistency")

        # ----------------------------------------------------------
        # 4) Suspicious PTR pattern detection
        # ----------------------------------------------------------
        pattern_reason = ptr_suspicious_patterns(ptr_lower)
        if pattern_reason:
            score += 0.15
            reasons.append(f"Suspicious PTR pattern: {pattern_reason}")

        # ----------------------------------------------------------
        # 5) PTR does not reference root domain (good heuristic)
        # ----------------------------------------------------------
        ext = tldextract.extract(fqdn)
        root_domain = f"{ext.domain}.{ext.suffix}".lower()

        # Check only the domain name (not full FQDN)
        if ext.domain not in ptr_lower:
            score += 0.10
            reasons.append(
                f"PTR hostname does not reference domain root ({ext.domain})"
            )

        # ----------------------------------------------------------
        # Final scoring
        # ----------------------------------------------------------
        score = min(score, self.max_score)

        if reasons:
            return self.success(score, f"PTR={ptr}; " + "; ".join(reasons))

        return self.success(0.0, f"PTR={ptr} looks normal")
