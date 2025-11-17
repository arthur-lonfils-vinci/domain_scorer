from typing import Dict, Any


class Feature:
    """
    Base class for scoring features.
    """

    name = "base"
    max_score = 0.0
    target_type = "domain"  # domain | email | both

    def run(self, target: str) -> Dict[str, Any]:
        raise NotImplementedError()

    # -------------------------
    # Standardized output API
    # -------------------------

    def success(self, score: float, reason: str) -> dict:
        return {
            "score": min(max(score, 0.0), self.max_score),
            "reason": reason,
            "ok": True,
        }

    def error(self, message: str) -> dict:
        return {
            "score": self.max_score,
            "reason": f"[SUSPICIOUS] {message}",
            "ok": False,
        }

    def disabled(self, reason: str) -> dict:
        return {
            "score": None,
            "reason": f"[UNAVAILABLE] {reason}",
            "ok": False,
        }
