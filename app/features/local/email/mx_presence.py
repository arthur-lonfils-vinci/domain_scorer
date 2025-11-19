from typing import List

from app.config import get_weight
from app.features.base import Feature
from app.features.types import TargetType, RunScope, Category, ConfigCat
from app.features.utils.dns.dns_utils import resolve_dns, is_nxdomain_error


class EmailMXPresenceFeature(Feature):
    """
    Basic MX presence check for emails.

    - If MX is missing → high spoofing probability
    - If NXDOMAIN → domain invalid
    - If MX exists → mailbox possibly valid
    """

    name = "email_mx_presence"
    target_type: List[TargetType] = [TargetType.EMAIL]
    run_on: List[RunScope] = [RunScope.ROOT]
    category = Category.HEURISTICS

    def __init__(self):
        # Email category weights come from ConfigCat.EMAIL
        self.max_score = get_weight(ConfigCat.EMAIL, self.name, 0.2)

    def run(self, target: str, context: dict):
        # Extract domain from context (always reliable)
        domain = context.get("domain")
        if not domain:
            return self.disabled("Missing domain in context")

        try:
            answers = resolve_dns(domain, "MX")
            count = len(answers)

            if count == 0:
                return self.error("Domain has NO MX → likely spoofing source")

            return self.success(0.0, f"MX count={count}")

        except Exception as e:
            if is_nxdomain_error(e):
                return self.error("No DNS found")
            return self.error(f"MX lookup error: {e}")
