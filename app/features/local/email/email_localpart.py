from typing import List
import unicodedata
from app.config import get_weight
from app.features.base import Feature
from app.features.types import TargetType, RunScope, Category, ConfigCat


class EmailLocalPartFeature(Feature):
    """
    Advanced local-part analysis:
    - Impersonation patterns
    - Random/gibberish detection
    - Suspicious role accounts
    - Unicode homoglyphs / hidden chars
    - Numeric-heavy usernames
    """

    name = "email_localpart"
    target_type: List[TargetType] = [TargetType.EMAIL]
    run_on: List[RunScope] = [RunScope.USER]
    category: Category = Category.EMAIL

    # ---------------------------------------------------------
    # Pattern databases
    # ---------------------------------------------------------
    ROLE_ACCOUNTS = {
        "admin", "root", "support", "webmaster", "billing",
        "security", "noreply", "no-reply", "postmaster",
        "helpdesk", "service", "info", "contact"
    }

    IMPERSONATION_KEYWORDS = [
        "paypal", "apple", "google", "microsoft", "dropbox",
        "bank", "support", "secure", "login", "verify", "update"
    ]

    DISPOSABLE_HINTS = [
        "tmp", "temp", "trash", "burn", "spam", "testacc",
        "demo", "fake", "mailinator", "disposable"
    ]

    HOMOGLYPH_SUSPICIOUS_RANGES = [
        "CYRILLIC", "GREEK", "ARABIC"
    ]

    # ---------------------------------------------------------

    def __init__(self):
        self.max_score = get_weight(ConfigCat.EMAIL, self.name, 1.0)

    def _has_hidden_unicode(self, s: str) -> bool:
        """Detect invisible unicode characters."""
        for ch in s:
            if unicodedata.category(ch) in ("Cf",):  # formatting, zero-width
                return True
        return False

    def _has_homoglyphs(self, s: str) -> bool:
        """Detect foreign alphabet letters (Cyrillic/Greek for impersonation)."""
        for ch in s:
            name = unicodedata.name(ch, "")
            if any(r in name for r in self.HOMOGLYPH_SUSPICIOUS_RANGES):
                return True
        return False

    def _entropy(self, s: str) -> float:
        """Shannon entropy for randomness detection."""
        if len(s) == 0:
            return 0.0
        from math import log2
        freq = {c: s.count(c) for c in set(s)}
        return -sum((count / len(s)) * log2(count / len(s)) for count in freq.values())

    # ---------------------------------------------------------

    def run(self, email: str):
        local, _ = email.split("@", 1)
        local_lower = local.lower()

        score = 0.0
        reasons = []

        # 1) Hidden Unicode / homoglyph detection
        if self._has_hidden_unicode(local):
            score += 0.4
            reasons.append("Contains hidden unicode characters")

        if self._has_homoglyphs(local):
            score += 0.5
            reasons.append("Contains foreign-script homoglyph characters")

        # 2) Role-based accounts (common in phishing)
        if local_lower in self.ROLE_ACCOUNTS:
            score += 0.3
            reasons.append(f"Role-based account: {local}")

        # 3) Impersonation keywords
        for word in self.IMPERSONATION_KEYWORDS:
            if word in local_lower:
                score += 0.3
                reasons.append(f"Impersonation keyword: {word}")
                break

        # 4) Disposable / burner naming
        for hint in self.DISPOSABLE_HINTS:
            if hint in local_lower:
                score += 0.2
                reasons.append(f"Possible disposable pattern: {hint}")
                break

        # 5) Excessive digits
        digit_ratio = sum(ch.isdigit() for ch in local) / max(len(local), 1)
        if digit_ratio > 0.5:
            score += 0.5
            reasons.append("Digit-heavy username (>50%)")

        # 6) Random string entropy
        H = self._entropy(local)
        if H > 4.0 and len(local) > 10:
            score += 0.4
            reasons.append(f"High entropy local-part (H={H:.2f})")

        # Scale score safely
        score = min(score, self.max_score)

        if reasons:
            return self.success(score, "; ".join(reasons))

        return self.success(0.0, "Local-part looks normal")
