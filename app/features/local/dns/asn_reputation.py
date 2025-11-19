import socket
from typing import List

import requests
from app.features.base import Feature
from app.config import REQUEST_TIMEOUT, get_weight
from app.cache import get_cache, set_cache
from app.features.types import TargetType, RunScope, Category, ConfigCat


BAD_ASNS = {"AS9009", "AS206092", "AS20473", "AS14061"}


class ASNReputationFeature(Feature):
    name = "asn_reputation"
    target_type: List[TargetType] = [TargetType.DOMAIN]
    run_on: List[RunScope] = [RunScope.ROOT]
    category: Category = Category.ASN

    def __init__(self):
        self.max_score = get_weight(ConfigCat.DOMAIN, self.name, 0.1)

    # ----------------------------------------------------------------------

    def run(self, target: str, context: dict):
        domain = context.get("root", target)

        cache_key = f"asn:{domain}"
        if cached := get_cache(cache_key):
            return cached

        # Resolve IP
        try:
            ip = socket.gethostbyname(domain)
        except Exception as e:
            result = self.disabled(f"ASN lookup failed: cannot resolve ({e})")
            set_cache(cache_key, result)
            return result

        # Request BGPView API
        try:
            resp = requests.get(f"https://api.bgpview.io/ip/{ip}", timeout=REQUEST_TIMEOUT)

            if resp.status_code != 200:
                result = self.disabled(f"ASN API error HTTP {resp.status_code}")
                set_cache(cache_key, result)
                return result

            data = resp.json().get("data", {})
            asn_info = data.get("asn", {}) or {}

            asn = asn_info.get("asn")
            name = asn_info.get("name", "")

            # No ASN = no risk
            if not asn:
                result = self.success(0.0, f"No ASN data for IP {ip}")
                set_cache(cache_key, result)
                return result

            # Known bad ASN?
            score = self.max_score if str(asn) in BAD_ASNS else 0.0

            result = self.success(score, f"ASN {asn} — {name}")
            set_cache(cache_key, result)
            return result

        except Exception as e:
            result = self.disabled(f"ASN API error: {e}")
            set_cache(cache_key, result)
            return result
