from typing import List

from app.config import get_weight
from app.features.base import Feature
from app.features.types import TargetType, RunScope, Category, ConfigCat


class CrossDomainMismatch(Feature):
    name = "email_cross_domain_mismatch"
    target_type: List[TargetType] = [TargetType.EMAIL]
    run_on: List[RunScope] = [RunScope.USER]
    category: Category = Category.HEURISTICS

    def __init__(self):
        self.max_score = get_weight(ConfigCat.EMAIL, self.name, 0.4)

    def run(self, email: str):
        local, domain = email.split("@", 1)
        local_parts = local.replace(".", " ").replace("_", " ").split()

        # If local part contains domain string (foo@bar.com vs bar.foo@mail.com)
        if any(part and part.lower() in domain.lower() for part in local_parts):
            return self.success(0.0, "Local part legitimately related to domain")

        if any(part.lower() not in domain.lower() for part in local_parts):
            return self.success(
                self.max_score,
                "Local part words do not match domain (possible impersonation)"
            )

        return self.success(0.0, "Domain/local-part match seems normal")
