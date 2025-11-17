from typing import Dict
from app.features.registry import DOMAIN_FEATURES, EMAIL_FEATURES
from app.features.base import Feature


# ============================================================
# INTERNAL FUNCTION FOR ONE FEATURE SET
# ============================================================

def _run_feature_set(
        target_value: str,
        feature_set: Dict[str, Feature]
):
    """
    Run a list of features on one target.
    Returns: (normalized_score, scores_dict, reasons_dict)
    """
    scores: Dict[str, float] = {}
    reasons: Dict[str, str] = {}
    weights: Dict[str, float] = {}

    for name, feature in feature_set.items():
        try:
            result = feature.run(target_value)
        except Exception as e:
            # Use "disabled" → does NOT increase risk
            result = feature.disabled(f"{name} crashed: {e}")

        score = result.get("score")
        if score is None:
            scores[name] = 0.0
        else:
            scores[name] = float(score)

        reasons[name] = str(result.get("reason", ""))
        weights[name] = getattr(feature, "max_score", 0.0)

    max_total = sum(f.max_score for f in feature_set.values() if f.max_score) or 1.0
    normalized = round(sum(scores.values()) / max_total, 3)

    return normalized, scores, reasons, weights


# ============================================================
# DOMAIN: generate FQDN + ROOT layers
# ============================================================

def score_domain_layers(fqdn: str, root: str):
    fqdn_features = {
        name: f for name, f in DOMAIN_FEATURES.items()
        if getattr(f, "run_on") in ("fqdn", "both")
    }

    root_features = {
        name: f for name, f in DOMAIN_FEATURES.items()
        if getattr(f, "run_on") == "root"
    }

    fqdn_norm, fqdn_scores, fqdn_reasons, fqdn_weights = _run_feature_set(fqdn, fqdn_features)
    root_norm, root_scores, root_reasons, root_weights = _run_feature_set(root, root_features)

    return {
        "fqdn": {
            "target": fqdn,
            "score": fqdn_norm,
            "features": fqdn_scores,
            "reasons": fqdn_reasons,
            "weights": fqdn_weights,
        },
        "root": {
            "target": root,
            "score": root_norm,
            "features": root_scores,
            "reasons": root_reasons,
            "weights": root_weights,
        },
    }


# ============================================================
# EMAIL: 3-layer scoring
# ============================================================

def score_email_only(fqdn: str, root: str, user: str):
    """
    Email-only feature scoring.
    """

    feature_buckets = {
        "user": {},
        "fqdn": {},
        "root": {},
        "both": {},
    }

    # Classify features by run_on
    for name, feature in EMAIL_FEATURES.items():
        bucket = getattr(feature, "run_on", "user")
        feature_buckets.setdefault(bucket, {})
        feature_buckets[bucket][name] = feature

    # Run scoring
    user_norm, user_scores, user_reasons, user_weights = _run_feature_set(user, feature_buckets["user"])
    fqdn_norm, fqdn_scores, fqdn_reasons, fqdn_weights= _run_feature_set(fqdn, feature_buckets["fqdn"])
    root_norm, root_scores, root_reasons, root_weights = _run_feature_set(root, feature_buckets["root"])
    both_norm, both_scores, both_reasons, both_weights = _run_feature_set(fqdn, feature_buckets["both"])

    # Merge raw scores
    scores = {}
    scores.update(user_scores)
    scores.update(fqdn_scores)
    scores.update(root_scores)
    scores.update(both_scores)

    # Merge reasons
    reasons = {}
    reasons.update(user_reasons)
    reasons.update(fqdn_reasons)
    reasons.update(root_reasons)
    reasons.update(both_reasons)

    # Merge weights
    weights = {}
    weights.update(user_weights)
    weights.update(fqdn_weights)
    weights.update(root_weights)
    weights.update(both_weights)

    # FINAL NORMALIZED SCORE
    max_total = sum(f.max_score for f in EMAIL_FEATURES.values() if f.max_score) or 1.0
    total_score = sum(scores.values())
    normalized = round(total_score / max_total, 3)

    return normalized, scores, reasons, weights
