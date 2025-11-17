import math
from collections import Counter
import tldextract

from app.config import get_weight
from app.features.base import Feature


class LexicalEntropyFeature(Feature):
    name = "lexical_entropy"
    target_type = "domain"
    run_on = "fqdn"

    def __init__(self):
        self.max_score = get_weight("domain", self.name, 0.05)

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
