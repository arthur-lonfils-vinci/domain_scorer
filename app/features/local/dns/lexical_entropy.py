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

    def run(self, domain: str):
        ext = tldextract.extract(domain)
        name = ext.domain or ""
        if not name:
            return self.error(f"No domain name: {domain}")

        counts = Counter(name)
        probs = [c / len(name) for c in counts.values()]
        entropy = -sum(p * math.log2(p) for p in probs)
        score = self.max_score if entropy > 4.5 else 0.0
        return self.success(score, f"Entropy={entropy:.2f}")
