from typing import List

from app.config import get_weight
from app.features.base import Feature
from app.features.types import TargetType, RunScope, Category, ConfigCat
from app.features.utils.dns.dns_utils import resolve_dns, is_nxdomain_error
from app.cache import get_cache, set_cache


class DNSARecordFeature(Feature):
    name = "dns_a_record"
    target_type: List[TargetType] = [TargetType.DOMAIN]
    run_on: List[RunScope] = [RunScope.FQDN]
    category: Category = Category.DNS

    def __init__(self):
        self.max_score = get_weight(ConfigCat.DOMAIN, self.name, 0.05)

    # ------------------------------------------------------------------

    def run(self, target: str, context: dict):
        fqdn = context.get("fqdn", target)
        cache_key = f"a_record:{fqdn}"

        # Cached result
        if cached := get_cache(cache_key):
            return cached

        try:
            answers = resolve_dns(fqdn, "A")
            count = len(answers)

            #
            # Heuristic:
            # - 0 A records = suspicious (handled in exception)
            # - 1 A record = mildly suspicious
            # - >1 A records = normal
            #
            score = self.max_score if count <= 1 else 0.0

            result = self.success(score, f"A-record count={count}")
            set_cache(cache_key, result)
            return result

        except Exception as e:
            if is_nxdomain_error(e):
                result = self.error("No A records found (NXDOMAIN)")
                set_cache(cache_key, result)
                return result

            result = self.disabled(f"A-record lookup error: {e}")
            set_cache(cache_key, result)
            return result
