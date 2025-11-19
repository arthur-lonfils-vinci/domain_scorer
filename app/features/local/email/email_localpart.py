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
    - Weird uppercase patterns
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
        for ch in s:
            if unicodedata.category(ch) == "Cf":
                return True
        return False

    def _has_homoglyphs(self, s: str) -> bool:
        for ch in s:
            name = unicodedata.name(ch, "")
            if any(r in name for r in self.HOMOGLYPH_SUSPICIOUS_RANGES):
                return True
        return False

    def _entropy(self, s: str) -> float:
        if not s:
            return 0.0
        from math import log2
        freq = {c: s.count(c) for c in set(s)}
        return -sum((c / len(s)) * log2(c / len(s)) for c in freq.values())

    def _weird_casing(self, s: str) -> bool:
        if len(s) < 3:
            return False

        uppercase_ratio = sum(ch.isupper() for ch in s) / len(s)
        if uppercase_ratio > 0.3:
            return True

        alternating = sum(
            (s[i].isupper() != s[i + 1].isupper()) for i in range(len(s) - 1)
        )
        if alternating / len(s) > 0.5:
            return True

        return False

    def _looks_gibberish(self, s: str) -> bool:
        vowels = set("aeiouy")
        v_count = sum(ch in vowels for ch in s.lower())
        v_ratio = v_count / max(len(s), 1)

        if v_ratio < 0.25:
            return True

        import re
        if re.search(r"[bcdfghjklmnpqrstvwxyz]{4,}", s.lower()):
            return True

        return False

    # ---------------------------------------------------------

    def run(self, target: str, context: dict):
        """
        NEW SIGNATURE (mandatory for the engine):
        target = "MndNKFUg@jeyqh.fr"
        context["local_part"] = "MndNKFUg"
        """
        local = context.get("local_part")
        if not local:
            return self.disabled("Missing local_part in context")

        local_lower = local.lower()

        score = 0.0
        reasons = []

        # 1) Hidden Unicode
        if self._has_hidden_unicode(local):
            score += 0.4
            reasons.append("Contains hidden unicode characters")

        # 2) Homoglyphs
        if self._has_homoglyphs(local):
            score += 0.5
            reasons.append("Contains foreign-script homoglyph characters")

        # 3) Role accounts
        if local_lower in self.ROLE_ACCOUNTS:
            score += 0.3
            reasons.append(f"Role-based account: {local}")

        # 4) Impersonation keywords
        for word in self.IMPERSONATION_KEYWORDS:
            if word in local_lower:
                score += 0.3
                reasons.append(f"Impersonation keyword: {word}")
                break

        # 5) Disposable-style names
        for hint in self.DISPOSABLE_HINTS:
            if hint in local_lower:
                score += 0.2
                reasons.append(f"Possible disposable pattern: {hint}")
                break

        # 6) Digit-heavy
        digit_ratio = sum(ch.isdigit() for ch in local) / len(local)
        if digit_ratio > 0.5:
            score += 0.5
            reasons.append("Digit-heavy username (>50%)")

        # 7) Entropy
        H = self._entropy(local)
        if H > 4.0 and len(local) > 10:
            score += 0.4
            reasons.append(f"High entropy local-part (H={H:.2f})")

        # 8) Weird casing
        if self._weird_casing(local):
            score += 0.4
            reasons.append("Suspicious casing pattern (random capital letters)")

        # 9) Gibberish
        if self._looks_gibberish(local):
            score += 0.4
            reasons.append("Gibberish pattern detected (auto-generated username)")

        # Final score
        score = min(score, self.max_score)

        if reasons:
            return self.success(score, "; ".join(reasons))

        return self.success(0.0, "Local-part looks normal")
