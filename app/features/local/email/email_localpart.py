import re
from app.features.base import Feature


class EmailLocalPartFeature(Feature):
    """
    Score suspicious local-parts like:
    - many digits
    - impersonation / brand names
    """

    name = "email_localpart"
    max_score = 0.2
    target_type = "email"
    run_on = "user"

    SUSPICIOUS_PATTERNS = [
        r"\d{5,}",                     # many digits
        r"(support|verify|secure)",    # generic impersonation
        r"(paypal|microsoft|apple|google|dropbox)[-_]?\w+",
        r"(security|billing|update)",
    ]

    def run(self, email: str):
        local, domain = email.split("@", 1)
        for pattern in self.SUSPICIOUS_PATTERNS:
            if re.search(pattern, local, re.IGNORECASE):
                return self.success(self.max_score, f"Suspicious local-part pattern: {pattern}")

        return self.success(0.0, "Local-part looks normal")
