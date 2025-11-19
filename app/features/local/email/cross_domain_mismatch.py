from typing import List

from app.config import get_weight
from app.features.base import Feature
from app.features.types import TargetType, RunScope, Category, ConfigCat


COMMON_NEUTRAL_WORDS = {
    "info", "contact", "help", "admin", "support", "service",
    "team", "office", "mail", "no-reply", "noreply"
}


class CrossDomainMismatch(Feature):
    """
    Detect local-part pretending to be a DIFFERENT domain.

    Examples flagged:
      paypal-security@random.fr
      apple-login@xyz.com
      microsoft-update@fake.org

    Legit cases NOT flagged:
      john@google.com
      marketing@apple.com
      contact@company.fr
    """

    name = "email_cross_domain_mismatch"
    target_type: List[TargetType] = [TargetType.EMAIL]
    run_on: List[RunScope] = [RunScope.USER]
    category = Category.HEURISTICS

    def __init__(self):
        self.max_score = get_weight(ConfigCat.EMAIL, self.name, 0.2)

    def run(self, email: str, context: dict):
        local = context["local_part"]
        domain = context["domain"]

        local_clean = (
            local.replace(".", " ")
                 .replace("_", " ")
                 .replace("-", " ")
                 .lower()
        )
        parts = [p for p in local_clean.split() if p]

        domain_root = domain.split(".")[0].lower()

        # ------------------------------------------------------------------
        # 1) If local-part includes the root-domain → legit (company name)
        # ------------------------------------------------------------------
        if domain_root in local_clean:
            return self.success(0.0, "Local-part relates to the domain")

        # ------------------------------------------------------------------
        # 2) Detect cross-domain impersonation
        # local-part contains another famous brand → suspicious
        # ------------------------------------------------------------------
        for p in parts:
            if p in COMMON_NEUTRAL_WORDS:
                continue  # do not flag common functional words

            if p in local_clean and p not in domain_root:
                return self.success(
                    self.max_score,
                    f"Local-part references unrelated brand/keyword: '{p}'"
                )

        # ------------------------------------------------------------------
        return self.success(0.0, "Local-part/domain alignment looks normal")
