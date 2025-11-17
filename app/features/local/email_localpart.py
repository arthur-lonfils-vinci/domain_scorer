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
            return {"score": 0.0, "reason": "Not an email"}

        local = email.split("@", 1)[0]

        for pattern in self.SUSPICIOUS_PATTERNS:
            if re.search(pattern, local, re.IGNORECASE):
                return {
                    "score": self.max_score,
                    "reason": f"Suspicious local-part pattern: {pattern}",
                }

        return {"score": 0.0, "reason": "Local-part looks normal"}
