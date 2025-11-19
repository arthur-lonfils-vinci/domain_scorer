import ssl
import socket
import datetime
from typing import List, Optional

from app.config import get_weight
from app.features.base import Feature
from app.features.types import TargetType, RunScope, Category, ConfigCat


class TLSCertFeature(Feature):
    """
    TLS certificate analysis:
    - Detects certificates with unusually short validity (<90 days)
    - Detects certificates issued very recently (<24h)
    - Checks issuer reputation (self-signed or unknown CAs)
    - Safe against false positives (TLS unavailable ≠ suspicious)
    """

    name = "tls_cert"
    target_type: List[TargetType] = [TargetType.DOMAIN]
    run_on: List[RunScope] = [RunScope.FQDN]
    category: Category = Category.TLS

    def __init__(self):
        self.max_score = get_weight(ConfigCat.DOMAIN, self.name, 0.1)

    # ------------------------------------------------------------

    def _get_certificate(self, domain: str) -> Optional[dict]:
        """Low-level TLS handshake with safe fallback."""
        ctx = ssl.create_default_context()

        try:
            with socket.create_connection((domain, 443), timeout=4) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    return ssock.getpeercert()
        except Exception:
            # No TLS available → not suspicious by itself
            return None

    # ------------------------------------------------------------

    def run(self, fqdn: str, context: dict):
        cert = self._get_certificate(fqdn)

        if not cert:
            return self.disabled("TLS not available or handshake blocked")

        reasons = []
        score = 0.0

        # --------------------------------------------------------
        # 1. Parse certificate dates safely
        # --------------------------------------------------------
        try:
            nb = datetime.datetime.utcfromtimestamp(
                ssl.cert_time_to_seconds(cert["notBefore"])
            )
            na = datetime.datetime.utcfromtimestamp(
                ssl.cert_time_to_seconds(cert["notAfter"])
            )
        except Exception:
            return self.disabled("TLS cert date parsing failed")

        validity_days = (na - nb).days

        # Short validity is common for Let's Encrypt but still useful heuristic
        if validity_days < 90:
            score += self.max_score * 0.5
            reasons.append(f"Short certificate validity: {validity_days} days")

        # Very recent certificate = phishing indicator
        age_hours = (datetime.datetime.utcnow() - nb).total_seconds() / 3600
        if age_hours < 24:
            score += self.max_score * 0.5
            reasons.append(f"Certificate very recently issued ({age_hours:.1f}h ago)")

        # --------------------------------------------------------
        # 2. Check issuer
        # --------------------------------------------------------
        issuer = cert.get("issuer", ())
        issuer_str = " / ".join("=".join(x) for x in issuer)

        if "self-signed" in issuer_str.lower():
            score += self.max_score * 0.5
            reasons.append("Self-signed certificate")

        # Extremely unknown CA pattern
        if "Let's Encrypt" not in issuer_str and "Google Trust" not in issuer_str and "Cloudflare" not in issuer_str:
            if len(issuer_str) < 5:  # extremely malformed
                score += self.max_score * 0.3
                reasons.append(f"Suspicious issuer: {issuer_str}")

        # --------------------------------------------------------
        # Final scoring
        # --------------------------------------------------------
        score = min(score, self.max_score)

        if reasons:
            return self.success(score, "; ".join(reasons))

        return self.success(0.0, f"TLS OK ({issuer_str})")
