import re
import unicodedata
from typing import List

import tldextract

from app.config import get_weight
from app.features.base import Feature
from app.features.types import TargetType, RunScope, Category, ConfigCat


# Common brand / high-value targets frequently impersonated
BRAND_KEYWORDS = [
    "google", "paypal", "apple", "microsoft", "amazon", "bank",
    "protonmail", "icloud", "facebook", "instagram", "linkedin",
    "dhl", "fedex", "dropbox", "netflix",
]

# Keyboard adjacency for swap-attack detection
KEYBOARD_ADJ = {
    "a": "qwsz",
    "b": "vghn",
    "c": "xdfv",
    "d": "erfcxs",
    "e": "wsdr",
    "f": "rtgvcd",
    "g": "tyhbvf",
    "h": "yujnbg",
    "i": "ujko",
    "j": "uikmnh",
    "k": "ijlm",
    "l": "kop",
    "m": "njk",
    "n": "bhjm",
    "o": "iklp",
    "p": "ol",
    "q": "wa",
    "r": "edft",
    "s": "wedxz",
    "t": "rfgy",
    "u": "yhji",
    "v": "cfgb",
    "w": "qase",
    "x": "zsdc",
    "y": "tghu",
    "z": "asx",
}


def levenshtein(a: str, b: str) -> int:
    """Fast Levenshtein implementation for typosquat detection."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)

    dp = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]

    for i in range(len(a) + 1):
        dp[i][0] = i

    for j in range(len(b) + 1):
        dp[0][j] = j

    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            dp[i][j] = min(
                dp[i - 1][j] + 1,       # deletion
                dp[i][j - 1] + 1,       # insertion
                dp[i - 1][j - 1] + cost # substitution
            )

    return dp[len(a)][len(b)]


def has_homoglyphs(s: str) -> bool:
    """Detect homograph attacks using Cyrillic/Greek lookalikes."""
    for ch in s:
        name = unicodedata.name(ch, "")
        if "CYRILLIC" in name or "GREEK" in name:
            return True
    return False


def keyboard_swap(a: str, b: str) -> bool:
    """Detect if b differs from a by swapping adjacent keyboard chars."""
    if len(a) != len(b):
        return False
    mismatches = [(i, a[i], b[i]) for i in range(len(a)) if a[i] != b[i]]
    if len(mismatches) != 1:
        return False
    _, c1, c2 = mismatches[0]
    return c2 in KEYBOARD_ADJ.get(c1, "")


# ==========================================================
#                      FEATURE CLASS
# ==========================================================

class DomainTyposquatFeature(Feature):
    name = "domain_typosquat"
    target_type: List[TargetType] = [TargetType.DOMAIN]
    run_on: List[RunScope] = [RunScope.ROOT]
    category: Category = Category.DNS

    def __init__(self):
        self.max_score = get_weight(ConfigCat.DOMAIN, self.name, 0.3)

    def run(self, domain: str, context: dict = None):

        ext = tldextract.extract(domain)
        root = ext.domain.lower()

        reasons = []
        score = 0.0

        # ==================================================
        # 1. Homoglyph attack
        # ==================================================
        if has_homoglyphs(root):
            reasons.append("Contains homoglyphs (Cyrillic/Greek lookalikes)")
            score += 0.2

        # ==================================================
        # 2. Numeric replacement (0↔o, 1↔l, 3↔e)
        # ==================================================
        replacement_patterns = [
            ("0", "o"), ("1", "l"), ("3", "e"), ("5", "s"),
        ]

        for a, b in replacement_patterns:
            if a in root or b in root:
                if root.replace(a, b) in BRAND_KEYWORDS:
                    reasons.append(f"Looks like digit-substitution of '{b}' → brand impersonation")
                    score += 0.2
                    break

        # ==================================================
        # 3. Keyboard adjacency swap
        # ==================================================
        for brand in BRAND_KEYWORDS:
            if keyboard_swap(root, brand):
                reasons.append(f"Keyboard-adjacent swap of brand '{brand}'")
                score += 0.2
                break

        # ==================================================
        # 4. Edit distance (Damerau–Levenshtein ~1 or 2)
        # ==================================================
        for brand in BRAND_KEYWORDS:
            dist = levenshtein(root, brand)
            if dist <= 2:
                reasons.append(f"Levenshtein distance {dist} from brand '{brand}'")
                score += 0.25
                break

        # ==================================================
        # 5. Gibberish root domain
        # ==================================================
        if re.search(r"[bcdfghjklmnpqrstvwxyz]{4,}", root):  # consonant-run
            reasons.append("Gibberish-like root (4+ consonants)")
            score += 0.15

        # Normalize
        score = min(score, self.max_score)

        if reasons:
            return self.success(score, "; ".join(reasons))

        return self.success(0.0, "No typosquatting indicators")
