import math
from collections import Counter
from typing import List

import tldextract

from app.config import get_weight
from app.features.base import Feature
from app.features.types import RunScope, TargetType, Category, ConfigCat


class LexicalEntropyFeature(Feature):
    name = "lexical_entropy"
    target_type: List[TargetType] = [TargetType.DOMAIN]
    run_on: List[RunScope] = [RunScope.FQDN]
    category: Category = Category.DNS

    def __init__(self):
        self.max_score = get_weight(ConfigCat.DOMAIN, self.name, 0.05)

    def run(self, target: str, context: dict):
        """
        Detect random-looking domain labels (common in phishing):
        - random letters
        - algorithmically generated subdomains
        - high entropy > 4.5 (but only meaningful if length ≥ 6)
        """
        ext = tldextract.extract(target)
        name = ext.domain or ""

        if not name:
            return self.error(f"No domain name extractable from: {target}")

        # Very short names naturally have higher entropy — do not flag them
        if len(name) < 6:
            entropy = 0.0
            return self.success(0.0, f"Entropy too small to evaluate (len={len(name)})")

        # Shannon entropy
        counts = Counter(name)
        probs = [c / len(name) for c in counts.values()]
        entropy = -sum(p * math.log2(p) for p in probs)

        score = self.max_score if entropy > 4.5 else 0.0

        return self.success(score, f"Entropy={entropy:.2f} (len={len(name)})")
