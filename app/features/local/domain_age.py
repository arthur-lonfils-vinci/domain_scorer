import datetime
import requests
from app.features.base import Feature
from app.cache import get_cache, set_cache


class DomainAgeFeature(Feature):
    name = "domain_age"
    max_score = 0.1
    target_type = "domain"

    RDAP_TIMEOUT = 4

    def rdap_lookup(self, domain: str):
        """
        RDAP lookup with automatic TLD-based routing.
        - .be domains → rdap.nic.brussels
        - other domains → rdap.net (auto RDAP delegation)
        """

        try:
            # Select endpoint depending on suffix
            if domain.endswith(".be"):
                url = f"https://rdap.nic.brussels/domain/{domain}"
            else:
                url = f"https://www.rdap.net/domain/{domain}"

            resp = requests.get(url, timeout=self.RDAP_TIMEOUT)

            if resp.status_code == 404:
                return None, "NXDOMAIN"

            if resp.status_code != 200:
                return None, f"RDAP HTTP {resp.status_code}"

            data = resp.json()

            # Find registration (creation) event
            events = data.get("events", [])
            for e in events:
                if e.get("eventAction") == "registration":
                    date_str = e.get("eventDate")
                    # Example: "2015-03-26T10:44:09Z"
                    return datetime.datetime.fromisoformat(date_str.replace("Z", "")), None

            return None, "RDAP: registration event missing"

        except Exception as e:  # noqa: BLE001
            return None, f"RDAP error: {e}"

    def fallback_whois(self, domain: str):
        """Fallback to python-whois (best effort)."""
        import whois

        try:
            w = whois.whois(domain)
            d = w.creation_date

            if isinstance(d, list):
                d = d[0]

            return d, None

        except Exception as e:  # noqa: BLE001
            return None, f"WHOIS error: {e}"

    def run(self, domain: str):
        cache_key = f"whois:{domain}"
        if cached := get_cache(cache_key):
            return cached

        # ===========================
        # 1) Try RDAP (preferred)
        # ===========================
        created, rdap_err = self.rdap_lookup(domain)

        # RDAP says domain does not exist → REAL security warning
        if rdap_err == "NXDOMAIN":
            result = self.error("Domain does not exist (NXDOMAIN)")
            set_cache(cache_key, result)
            return result

        # ===========================
        # 2) RDAP returned no creation date → try WHOIS
        # ===========================
        if created is None:
            created, whois_err = self.fallback_whois(domain)

            if created is None:
                # Both failed → this is a SENSOR FAILURE (not suspicious)
                result = self.disabled(
                    f"WHOIS unavailable (RDAP error: {rdap_err}, WHOIS error: {whois_err})"
                )
                set_cache(cache_key, result)
                return result

        # ===========================
        # 3) Compute score
        # ===========================

        # Normalize timezone
        if created.tzinfo:
            created = created.astimezone(datetime.timezone.utc).replace(tzinfo=None)

        age_days = (datetime.datetime.utcnow() - created).days

        score = self.max_score if age_days < 7 else 0.0
        result = self.success(score, f"Domain age={age_days} days")

        set_cache(cache_key, result)
        return result
