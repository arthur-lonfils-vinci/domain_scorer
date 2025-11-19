import datetime
from typing import List, Optional

import requests

from app.config import REQUEST_TIMEOUT, get_weight
from app.cache import get_cache, set_cache
from app.features.base import Feature
from app.features.types import TargetType, RunScope, Category, ConfigCat


# High-abuse registrars (Spamhaus + industry consensus)
ABUSED_REGISTRARS = {
    "namesilo", "alibabacloud", "hostinger", "gname",
    "ovh-sasl", "tucows", "namecheap", "publicdomainregistry",
}


class DomainPrivacyFeature(Feature):
    """
    Detect WHOIS privacy and registrar risk.

    What it checks:
    - Domain uses WHOIS privacy (GOOD for legit domains, BAD for NEW domains)
    - Newly registered + privacy → suspicious
    - High-risk registrars frequently used in phishing
    """

    name = "domain_privacy"
    target_type: List[TargetType] = [TargetType.DOMAIN]
    run_on: List[RunScope] = [RunScope.ROOT]
    category = Category.DNS

    def __init__(self):
        self.max_score = get_weight(ConfigCat.DOMAIN, self.name, 0.2)

    # -------------------------------------------------------------------------
    # RDAP LOOKUP
    # -------------------------------------------------------------------------

    def _rdap_lookup(self, domain: str):
        """
        Return dict with:
        {
            "registrar": "...",
            "privacy": bool,
            "created": datetime|None
        }
        """

        try:
            if domain.endswith(".be"):
                url = f"https://rdap.nic.brussels/domain/{domain}"
            else:
                url = f"https://www.rdap.net/domain/{domain}"

            resp = requests.get(url, timeout=REQUEST_TIMEOUT)

            if resp.status_code == 404:
                return None, "NXDOMAIN"
            if resp.status_code != 200:
                return None, f"RDAP HTTP {resp.status_code}"

            data = resp.json()

            # Registrar
            registrar = (data.get("registrar", {}) or {}).get("name", "")
            registrar_lower = registrar.lower()

            # Privacy detection
            # If no entities contain personal info, it's PRIVATE.
            entities = data.get("entities", [])
            privacy = True
            for ent in entities:
                roles = ent.get("roles", [])
                if "registrant" in roles:
                    emails = str(ent.get("email", "")).lower()
                    if emails and "privacy" not in emails and "redacted" not in emails:
                        privacy = False

            # Creation date
            created = None
            for event in data.get("events", []):
                if event.get("eventAction") == "registration":
                    ds = event.get("eventDate")
                    if ds:
                        created = datetime.datetime.fromisoformat(
                            ds.replace("Z", "")
                        )

            return {
                "registrar": registrar_lower,
                "privacy": privacy,
                "created": created,
            }, None

        except Exception as exc:
            return None, f"RDAP error: {exc}"

    # -------------------------------------------------------------------------
    # fallback WHOIS
    # -------------------------------------------------------------------------

    def _fallback_whois(self, domain: str):
        import whois

        try:
            w = whois.whois(domain)

            registrar = str(w.registrar or "").lower()

            privacy = False
            text = str(w.text or "").lower()
            if "privacy" in text or "redacted" in text:
                privacy = True

            created = w.creation_date
            if isinstance(created, list):
                created = created[0]

            return {
                "registrar": registrar,
                "privacy": privacy,
                "created": created,
            }, None

        except Exception as exc:
            return None, f"WHOIS error: {exc}"

    # -------------------------------------------------------------------------
    # Main run()
    # -------------------------------------------------------------------------

    def run(self, domain: str, context: dict = None):
        cache_key = f"privacy:{domain}"
        if cached := get_cache(cache_key):
            return cached

        # Prefer RDAP
        info, rdap_err = self._rdap_lookup(domain)

        if rdap_err == "NXDOMAIN":
            result = self.error("Domain does not exist (NXDOMAIN)")
            set_cache(cache_key, result)
            return result

        # fallback WHOIS
        if info is None:
            info, whois_err = self._fallback_whois(domain)
            if info is None:
                result = self.disabled(
                    f"WHOIS unavailable (RDAP error: {rdap_err}, WHOIS error: {whois_err})"
                )
                set_cache(cache_key, result)
                return result

        registrar = info["registrar"]
        privacy = info["privacy"]
        created = info["created"]

        reasons = []
        score = 0.0

        # ---------------------------------------------------------
        # 1) High-risk registrar
        # ---------------------------------------------------------
        if any(r in registrar for r in ABUSED_REGISTRARS):
            score += 0.1
            reasons.append(f"High-risk registrar: {registrar}")

        # ---------------------------------------------------------
        # 2) Newly registered + privacy = VERY suspicious
        # ---------------------------------------------------------
        if created:
            # Normalize timezone
            if created.tzinfo:
                created = created.astimezone(datetime.timezone.utc).replace(tzinfo=None)

            age_days = (datetime.datetime.utcnow() - created).days

            if age_days < 30 and privacy:
                score += 0.15
                reasons.append("Newly registered domain using WHOIS privacy")

            elif privacy and age_days < 120:
                score += 0.05
                reasons.append("Relatively new domain with WHOIS privacy")

            else:
                reasons.append(f"Domain age={age_days} days (privacy={privacy})")

        else:
            reasons.append("Creation date unavailable (privacy uncertain)")

        score = min(score, self.max_score)

        if reasons:
            result = self.success(score, "; ".join(reasons))
        else:
            result = self.success(0.0, "Registrar and privacy settings normal")

        set_cache(cache_key, result)
        return result
