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

    SUSPICIOUS_PATTERNS = [
        r"\d{5,}",                     # many digits
        r"(support|verify|secure)",    # generic impersonation
        r"(paypal|microsoft|apple|google|dropbox)[-_]?\w+",
        r"(security|billing|update)",
    ]

    def run(self, email: str):
        if "@" not in email:
            return self.disabled("Not a valid email address - no @")

        local = email.split("@", 1)[0]

        for pattern in self.SUSPICIOUS_PATTERNS:
            if re.search(pattern, local, re.IGNORECASE):
                return self.success(self.max_score, f"Suspicious local-part pattern: {pattern}")

        return self.success(0.0, "Local-part looks normal")
