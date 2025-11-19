import datetime
from typing import List, Tuple, Optional

import requests

from app.config import REQUEST_TIMEOUT, get_weight
from app.features.base import Feature
from app.cache import get_cache, set_cache
from app.features.types import TargetType, RunScope, Category, ConfigCat


class DomainAgeFeature(Feature):
    name = "domain_age"
    target_type: List[TargetType] = [TargetType.DOMAIN]
    run_on: List[RunScope] = [RunScope.ROOT]
    category: Category = Category.DNS   # or Category.WHOIS, if you introduce one

    def __init__(self):
        self.max_score = get_weight(ConfigCat.DOMAIN, self.name, 0.1)

    # ------------------------------------------------------------------
    # RDAP LOOKUP
    # ------------------------------------------------------------------
    def rdap_lookup(self, domain: str) -> Tuple[Optional[datetime.datetime], Optional[str]]:
        """
        Use RDAP when possible.
        Returns: (creation_date | None, error_message | None)
        """

        try:
            # .be → custom RDAP server
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
            events = data.get("events", [])

            for event in events:
                if event.get("eventAction") == "registration":
                    # Example format: "2015-03-26T10:44:09Z"
                    raw = event.get("eventDate")
                    if not raw:
                        continue

                    return datetime.datetime.fromisoformat(
                        raw.replace("Z", "")
                    ), None

            return None, "RDAP registration event missing"

        except Exception as e:  # noqa: BLE001
            return None, f"RDAP error: {e}"

    # ------------------------------------------------------------------
    # WHOIS FALLBACK
    # ------------------------------------------------------------------
    def fallback_whois(self, domain: str):
        """Fallback whois check using python-whois."""
        import whois

        try:
            data = whois.whois(domain)
            created = data.creation_date

            if isinstance(created, list):
                created = created[0]

            return created, None

        except Exception as e:  # noqa: BLE001
            return None, f"WHOIS error: {e}"

    # ------------------------------------------------------------------
    # MAIN RUN
    # ------------------------------------------------------------------
    def run(self, target: str, context: dict):
        # Always use the root domain for RDAP/WHOIS
        domain = context.get("root", target)

        cache_key = f"whois:{domain}"
        if cached := get_cache(cache_key):
            return cached

        # ------------------------------------------------------
        # 1. Try RDAP first
        # ------------------------------------------------------
        created, rdap_err = self.rdap_lookup(domain)

        if rdap_err == "NXDOMAIN":
            # This is a *real* security indicator
            result = self.error("Domain does not exist (NXDOMAIN)")
            set_cache(cache_key, result)
            return result

        # ------------------------------------------------------
        # 2. If RDAP failed → fallback WHOIS
        # ------------------------------------------------------
        if created is None:
            created, whois_err = self.fallback_whois(domain)

            if created is None:
                # SENSOR failure → not suspicious, don't penalize
                result = self.disabled(
                    f"WHOIS unavailable (RDAP: {rdap_err}, WHOIS: {whois_err})"
                )
                set_cache(cache_key, result)
                return result

        # ------------------------------------------------------
        # 3. Normalize timezone and compute age
        # ------------------------------------------------------
        if created.tzinfo:
            created = created.astimezone(datetime.timezone.utc).replace(tzinfo=None)

        age_days = (datetime.datetime.utcnow() - created).days

        # Very young domains (< 7 days) are extremely suspicious
        score = self.max_score if age_days < 7 else 0.0

        result = self.success(score, f"Domain age = {age_days} days")
        set_cache(cache_key, result)
        return result
