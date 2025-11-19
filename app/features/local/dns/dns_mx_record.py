from typing import List

from app.config import get_weight
from app.features.base import Feature
from app.features.types import TargetType, RunScope, Category, ConfigCat
from app.features.utils.dns.dns_utils import resolve_dns, is_nxdomain_error


class DNSMXRecordFeature(Feature):
    name = "dns_mx_record"
    target_type: List[TargetType] = [TargetType.DOMAIN]
    run_on: List[RunScope] = [RunScope.ROOT]
    category: Category = Category.DNS

    def __init__(self):
        self.max_score = get_weight(ConfigCat.DOMAIN, self.name, 0.05)

    def run(self, target: str, context: dict):
        """
        MX lookup on root domain.
        High risk if:
          - no MX records
          - NXDOMAIN
        """

        domain = context.get("root", target)

        try:
            answers = resolve_dns(domain, "MX")
            count = len(answers)

            if count == 0:
                return self.error("No MX records → domain cannot receive email")

            return self.success(0.0, f"MX records found ({count})")

        except Exception as e:  # noqa: BLE001
            if is_nxdomain_error(e):
                return self.error("Domain does not exist (NXDOMAIN)")
            return self.disabled(f"MX lookup error: {e}")
