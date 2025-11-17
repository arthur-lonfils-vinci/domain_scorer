from typing import Dict, Any
from app.scoring.score_engine import score_domain
from app.scoring.threat_classifier import classify_domain_score


def analyze_domain(domain: str) -> Dict[str, Any]:
    normalized, scores, reasons = score_domain(domain)
    threat = classify_domain_score(normalized, scores)

    return {
        "target": domain,
        "type": "domain",
        "score": normalized,
        "threat": threat,
        "feature_scores": scores,
        "feature_reasons": reasons,
    }
