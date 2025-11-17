import math
from collections import Counter
import tldextract
from app.features.base import Feature


class LexicalEntropyFeature(Feature):
    name = "lexical_entropy"
    max_score = 0.05
    target_type = "domain"

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
