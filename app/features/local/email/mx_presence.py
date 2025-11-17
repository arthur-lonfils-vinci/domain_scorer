from typing import List

import dns

from app.config import get_weight
from app.features.base import Feature
from app.features.types import TargetType, RunScope, Category
from app.features.utils.dns.dns_utils import resolve_dns, is_nxdomain_error


class EmailMXPresenceFeature(Feature):
    name = "email_mx_presence"
    target_type: List[TargetType] = [TargetType.EMAIL]
    run_on: List[RunScope] = [RunScope.ROOT]
    category: Category = Category.HEURISTICS

    def __init__(self):
        self.max_score = get_weight(Category.EMAIL, self.name, 0.2)

    def run(self, domain: str):
        try:
            answers = resolve_dns(domain, "MX")
            count = len(answers)
            if count == 0:
                return self.error("Domain has NO MX → possible spoofing")
            return self.success(0.0, f"MX count={count}")
        except Exception as e:
            if is_nxdomain_error(e):
                return self.error("No DNS found")
            return self.error(f"MX lookup error: {e}")
