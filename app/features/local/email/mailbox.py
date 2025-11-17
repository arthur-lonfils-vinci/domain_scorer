from typing import List

import dns.resolver

from app.config import get_weight
from app.features.base import Feature
from app.features.types import TargetType, RunScope, Category, ConfigCat
from app.features.utils.dns.dns_utils import resolve_dns, is_nxdomain_error

class EmailMailboxFeature(Feature):
    name = "email_mailbox"
    target_type: List[TargetType] = [TargetType.EMAIL]
    run_on: List[RunScope] = [RunScope.USER]
    category: Category = Category.EMAIL

    def __init__(self):
        self.max_score = get_weight(ConfigCat.EMAIL, self.name, 0.15)

    def run(self, email: str):
        try:
            local, domain = email.split("@", 1)
            answers = resolve_dns(domain, "MX")
            if len(answers) == 0:
                return self.error("Mailbox impossible — no MX records")
            return self.success(0.0, "Mailbox likely exists (MX found)")
        except Exception as e:
            if is_nxdomain_error(e) :
                return self.error("No DNS found")
            return self.disabled(f"Mailbox check failed: {e}")
