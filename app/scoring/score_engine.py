from typing import Dict, Tuple
from app.features.registry import DOMAIN_FEATURES, EMAIL_FEATURES
from app.features.base import Feature


def _run_features(target: str, feature_set: Dict[str, Feature]):
    scores: Dict[str, float] = {}
    reasons: Dict[str, str] = {}

    for name, feature in feature_set.items():
        try:
            result = feature.run(target)
        except Exception as e:  # noqa: BLE001
            result = {
                "score": feature.error_score(),
                "reason": f"{name} crashed: {e}",
            }
        score = float(result.get("score", 0.0) or 0.0)
        reason = str(result.get("reason", ""))
        scores[name] = score
        reasons[name] = reason

    max_total = sum(f.max_score for f in feature_set.values()) or 1.0
    normalized = round(sum(scores.values()) / max_total, 3)
    return normalized, scores, reasons


def score_domain(domain: str) -> Tuple[float, Dict[str, float], Dict[str, str]]:
    return _run_features(domain, DOMAIN_FEATURES)


def score_email_only(email: str) -> Tuple[float, Dict[str, float], Dict[str, str]]:
    return _run_features(email, EMAIL_FEATURES)
