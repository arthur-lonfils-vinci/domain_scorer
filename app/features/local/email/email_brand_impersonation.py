from typing import List

from app.config import get_weight
from app.features.base import Feature
import re

from app.features.types import RunScope, TargetType, Category, ConfigCat


class EmailImpersonationFeature(Feature):
    name = "email_brand_impersonation"
    target_type: List[TargetType] = [TargetType.EMAIL]
    run_on: List[RunScope] = [RunScope.USER]
    category: Category = Category.HEURISTICS

    BRANDS = [
        "paypal", "apple", "google", "microsoft", "dropbox",
        "netflix", "bank", "amazon", "dhl", "fedex"
    ]

    def __init__(self):
        self.max_score = get_weight(ConfigCat.EMAIL, self.name, 0.8)

    def run(self, email: str):
        local, domain = email.split("@", 1)
        local_lower = local.lower()
        domain_lower = domain.lower()

        for brand in self.BRANDS:
            if brand in local_lower and brand not in domain_lower:
                return self.success(
                    self.max_score,
                    f"Brand impersonation: '{brand}' appears in local part but domain is '{domain}'"
                )

        return self.success(0.0, "No impersonation indicators found")
