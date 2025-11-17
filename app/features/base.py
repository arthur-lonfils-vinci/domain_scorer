from typing import Dict, Any


class Feature:
    """
    Base class for scoring features.

    Attributes:
        name: unique identifier used in outputs
        max_score: maximum contribution to the global score
        target_type: "domain", "email", or "both"
    """

    name = "base"
    max_score = 0.0
    target_type = "domain"  # "domain" | "email" | "both"

    def run(self, target: str) -> Dict[str, Any]:
        """
        Execute the feature on the given target (domain or email).

        Must return a dict with:
          - score: float in [0, max_score]
          - reason: human-readable explanation
        """
        raise NotImplementedError()

    def error_score(self, factor: float = 0.8) -> float:
        """Default risk if feature fails."""
        return round(self.max_score * factor, 3)
