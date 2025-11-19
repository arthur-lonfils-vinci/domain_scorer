from typing import List
from app.config import get_weight
from app.features.base import Feature
from app.features.types import RunScope, TargetType, Category, ConfigCat


class EmailImpersonationFeature(Feature):
    name = "email_brand_impersonation"
    target_type: List[TargetType] = [TargetType.EMAIL]
    run_on: List[RunScope] = [RunScope.USER]
    category: Category = Category.HEURISTICS

    # Direct brand list
    BRANDS = [
        "paypal", "apple", "google", "microsoft", "dropbox",
        "netflix", "bank", "amazon", "dhl", "fedex"
    ]

    # Common obfuscations (leet → brand)
    LEET_MAP = {
        "0": "o",
        "1": "l",
        "3": "e",
        "5": "s",
        "7": "t",
        "@": "a",
    }

    def __init__(self):
        self.max_score = get_weight(ConfigCat.EMAIL, self.name, 0.8)

    def _normalize_leet(self, s: str) -> str:
        """Convert l33t-like characters to detect spoofed brands."""
        return "".join(self.LEET_MAP.get(ch, ch) for ch in s.lower())

    def run(self, target: str, context: dict):
        local = context.get("local_part")
        domain = context.get("domain")

        if not local or not domain:
            return self.disabled("Missing email context (local/domain)")

        local_norm = self._normalize_leet(local)
        domain_lower = domain.lower()

        # Check both raw and normalized local part
        candidates = {local.lower(), local_norm}

        for brand in self.BRANDS:
            for candidate in candidates:
                if brand in candidate and brand not in domain_lower:
                    return self.success(
                        self.max_score,
                        f"Brand impersonation: '{brand}' present in local-part '{local}', "
                        f"but domain is '{domain}'"
                    )

        return self.success(0.0, "No impersonation indicators found")
