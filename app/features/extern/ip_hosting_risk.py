import re
import socket
from typing import List

import requests

from app.config import REQUEST_TIMEOUT, get_weight
from app.cache import get_cache, set_cache
from app.features.base import Feature
from app.features.types import TargetType, RunScope, Category, ConfigCat


class IPHostingRiskFeature(Feature):
    """
    Evaluate the risk of the IP hosting environment using:
    - ASN reputation (bulletproof hosts, spam-heavy networks)
    - Cloud/VPS provider detection
    - VPN hosting detection (NordVPN, Mullvad...)
    - Reverse-DNS naming patterns (generic VPS → suspicious)
    - Hosting classification (residential vs datacenter)

    **No external paid APIs** — this uses public BGPView.
    """

    name = "ip_hosting_risk"
    target_type: List[TargetType] = [TargetType.DOMAIN]
    run_on: List[RunScope] = [RunScope.ROOT]
    category = Category.ASN

    # =================================================================
    # Known risky hosting families
    # =================================================================
    BULLETPROOF_ASN = {
        "AS9009",    # M247
        "AS14061",   # DigitalOcean
        "AS20473",   # Choopa/Vultr
        "AS206092",  # Scaleway / Online SAS
        "AS8100",    # QuadraNet (historically abused)
        "AS26347",   # New Dream Network
    }

    VPN_HOSTING_KEYWORDS = [
        "vpn", "nordvpn", "mullvad", "surfshark", "expressvpn", "protonvpn",
    ]

    CLOUD_PROVIDERS = [
        "amazon", "aws", "google", "gcp", "azure", "digitalocean",
        "do-", "linode", "vultr", "scaleway", "ovh", "hetzner"
    ]

    VPS_PATTERNS = [
        r"vps", r"static-\d+", r"ip-\d+-\d+-\d+-\d+", r"dedibox", r"hosthatch",
        r"cloud", r"compute", r"node", r"server"
    ]

    # =================================================================

    def __init__(self):
        self.max_score = get_weight(ConfigCat.DOMAIN, self.name, 0.2)

    # =================================================================

    def run(self, domain: str, context: dict = None):
        # -------------------------------------------------------------
        # 1) Resolve A record
        # -------------------------------------------------------------
        try:
            ip = socket.gethostbyname(domain)
        except Exception as e:
            return self.error(f"Cannot resolve domain → {e}")

        cache_key = f"iprisk:{ip}"
        if cached := get_cache(cache_key):
            return cached

        reasons = []
        score = 0.0

        # -------------------------------------------------------------
        # 2) Query BGPView for ASN + reverse DNS
        # -------------------------------------------------------------
        try:
            resp = requests.get(f"https://api.bgpview.io/ip/{ip}", timeout=REQUEST_TIMEOUT)
            if resp.status_code != 200:
                result = self.disabled(f"BGPView HTTP {resp.status_code}")
                set_cache(cache_key, result)
                return result
            data = resp.json().get("data", {})
        except Exception as e:
            result = self.disabled(f"BGPView error: {e}")
            set_cache(cache_key, result)
            return result

        # -------------------------------------------------------------
        # Extract provider info
        # -------------------------------------------------------------
        asn_info = data.get("asn", {})
        asn = str(asn_info.get("asn", ""))
        asn_name = asn_info.get("name", "").lower()

        rdns = data.get("reverse_dns", {}).get("reverse_dns", "")
        rdns_lower = rdns.lower() if rdns else ""

        # =============================================================
        # 3) ASN risk
        # =============================================================
        if asn in self.BULLETPROOF_ASN:
            score += 0.15
            reasons.append(f"Hosted on known bulletproof ASN ({asn})")

        # =============================================================
        # 4) Cloud provider detection
        # =============================================================
        if any(cp in asn_name for cp in self.CLOUD_PROVIDERS):
            score += 0.05
            reasons.append(f"Cloud provider detected: {asn_name}")

        # =============================================================
        # 5) VPN hosting (evasion / malicious infra)
        # =============================================================
        if any(v in rdns_lower for v in self.VPN_HOSTING_KEYWORDS):
            score += 0.10
            reasons.append(f"VPN infra detected: {rdns_lower}")

        # =============================================================
        # 6) Suspicious PTR naming
        # =============================================================
        for pattern in self.VPS_PATTERNS:
            if re.search(pattern, rdns_lower):
                score += 0.10
                reasons.append(f"PTR suggests VPS hosting: {rdns}")
                break

        # =============================================================
        # Normalize + Return
        # =============================================================
        score = min(score, self.max_score)

        if reasons:
            result = self.success(score, f"IP={ip}; " + "; ".join(reasons))
        else:
            result = self.success(0.0, f"IP={ip}; hosting environment seems normal")

        set_cache(cache_key, result)
        return result
