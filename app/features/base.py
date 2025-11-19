from typing import Dict, Any, List, Optional

from app.features.types import TargetType, RunScope, Category


class Feature:
    """
    Base class for scoring features.

    Attributes:
        name:        unique identifier for output
        max_score:   maximum contribution to global score
        target_type: "domain", "email", or "web"
        run_on:      "fqdn", "root" or "user" (scope of analysis)
        category:  "other", "DNS", "email", ...
    """

    name = "base"
    max_score = 0.0
    target_type: List[TargetType] = [TargetType.DOMAIN]
    run_on: List[RunScope] = [RunScope.FQDN]
    category: Category = Category.OTHER

    # -------------------------------------------------------
    # Output helpers — standardized scoring conventions
    # -------------------------------------------------------

    def success(self, score: float, reason: str) -> Dict[str, Any]:
        """Normal feature output. Fully trusted."""
        score = min(max(score, 0.0), self.max_score)
        return {"score": score, "reason": reason, "ok": True}

    def error(self, message: str) -> Dict[str, Any]:
        """
        Feature detected something *suspicious*.

        This SHOULD increase risk, so we return the MAX SCORE.
        """
        return {
            "score": self.max_score,
            "reason": f"[SUSPICIOUS] {message}",
            "ok": False,
        }

    def disabled(self, reason: str) -> Dict[str, Any]:
        """
        The feature cannot run (API issue, sensor unavailable, timeout, etc.)

        This must NOT contribute to risk.
        Return: score = None → excluded from normalization.
        """
        return {
            "score": None,
            "reason": f"[UNAVAILABLE] {reason}",
            "ok": False,
        }

    # -------------------------------------------------------

    def run(self, target: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        MUST be overridden by each feature.

        context = {
            "headers_path": "...",
            "raw_headers": "...",
            "raw_email": "...",
            "mode": "cli" | "api",
            "domain": ...,
            ...
        }
        """
        raise NotImplementedError()
