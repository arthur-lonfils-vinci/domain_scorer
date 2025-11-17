import datetime
import whois
from app.features.base import Feature
from app.cache import get_cache, set_cache


class DomainAgeFeature(Feature):
    name = "domain_age"
    max_score = 0.1
    target_type = "domain"

    def run(self, domain: str):
        cache_key = f"whois:{domain}"
        if cached := get_cache(cache_key):
            return cached

        try:
            w = whois.whois(domain)
            created = w.creation_date
            if isinstance(created, list):
                created = created[0]

            if not created:
                result = {
                    "score": self.error_score(),
                    "reason": "WHOIS: missing creation date",
                }
                set_cache(cache_key, result)
                return result

            if created.tzinfo:
                created = created.astimezone(datetime.timezone.utc).replace(
                    tzinfo=None
                )

            age_days = (datetime.datetime.utcnow() - created).days
            score = self.max_score if age_days < 7 else 0.0
            result = {
                "score": score,
                "reason": f"Domain age={age_days} days",
            }
            set_cache(cache_key, result)
            return result

        except Exception as e:  # noqa: BLE001
            result = {"score": self.error_score(), "reason": f"WHOIS error: {e}"}
            set_cache(cache_key, result)
            return result
